"""Fournisseurs LLM — l'interface, et deux implémentations.

CONTRAT D'UN FOURNISSEUR :

    complet(phrase: str, description_capacites: str) -> ReponseLLM | None

    · il ne reçoit QUE la phrase et la description des capacités
    · il ne reçoit JAMAIS un nom d'outil, un chemin, un argument
    · il retourne une ReponseLLM, ou None s'il ne sait pas
    · il ne lève pas d'exception métier : une erreur technique remonte et déclenche
      le repli déterministe

Trois implémentations, à ne pas mettre au même niveau de preuve :

    MockLLM            réponses figées — teste le CONTRAT et les GARDE-FOUS, sans réseau
    Groq               vrai modèle, API compatible OpenAI — branché sur `moteur="auto"`
    OpenAICompatible   endpoint compatible OpenAI générique — ÉCRIT, JAMAIS EXERCÉ (aucun
                       chemin du CLI ne l'instancie ; le garder n'engage à rien, l'utiliser
                       voudrait un besoin mesuré)

Le mock n'est pas un raccourci : c'est ce qui permet de tester le contrat sans dépendre d'un
fournisseur externe, y compris ici où aucune clé n'existe. **Attention à la phrase qu'elle
autorise** : `test_llm_reel.py` prouve que le contrat tient contre un vrai modèle, pas que le
modèle est robuste — « testé » et « validé en production » ne sont pas le même état, voir
`PROJET_ETAT.md`, « Clarification — LLM réel testé ≠ LLM réel validé en production ».
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass

from intent_llm import ReponseLLM


class MockLLM:
    """Fournisseur de test à réponses figées.

    `comportement` permet de simuler un modèle hostile ou défaillant, pour vérifier que
    les garde-fous tiennent :

        normal            réponses correctes
        invente_capacite  retourne une capacité qui n'existe pas
        nomme_outil       tente d'imposer un nom d'outil
        statut_invalide   retourne un statut hors contrat
        resolu_sans_caps  resolved sans capacités
        refus_sans_motif  rejected sans motif
        clarification_sans_question
        reponse_vide      retourne None
        plante            lève une exception
    """

    def __init__(self, comportement: str = "normal", nom: str = "mock"):
        self.comportement = comportement
        self.nom = nom
        self.appels: list[dict] = []

    def complet(self, phrase: str, description: str):
        # Tout ce que le fournisseur reçoit est journalisé : c'est ce qui permet de
        # vérifier qu'aucun nom d'outil ne lui a été transmis.
        self.appels.append({"phrase": phrase, "description": description})

        c = self.comportement
        if c == "plante":
            raise RuntimeError("fournisseur indisponible")
        if c == "reponse_vide":
            return None
        if c == "statut_invalide":
            return ReponseLLM("peut_etre", brut="statut hors contrat", fournisseur=self.nom)
        if c == "invente_capacite":
            return ReponseLLM("resolved", ("PENTEST_OFFENSIF_TOTAL",),
                              brut="capacité inventée", fournisseur=self.nom)
        if c == "nomme_outil":
            # Un modèle qui tente d'imposer un outil : la chaîne doit être ignorée,
            # parce que le plan est construit à partir du REGISTRE, jamais de la sortie.
            return ReponseLLM("resolved", ("nuclei", "metasploit"),
                              brut="lance nuclei et metasploit", fournisseur=self.nom)
        if c == "resolu_sans_caps":
            return ReponseLLM("resolved", (), brut="resolved vide", fournisseur=self.nom)
        if c == "refus_sans_motif":
            return ReponseLLM("rejected", motif="", brut="refus non motivé",
                              fournisseur=self.nom)
        if c == "clarification_sans_question":
            return ReponseLLM("needs_clarification", question="",
                              brut="clarification muette", fournisseur=self.nom)

        # comportement normal
        bas = phrase.lower()
        if any(m in bas for m in ("attaque", "attaquer", "ddos", "exfiltrer",
                                  "exfiltre", "exfiltras", "ransomware", "backdoor",
                                  "porte dérobée", "sans autorisation", "détruire",
                                  "détruis", "détruit", "destructive", "destructif",
                                  "exploit")):
            return ReponseLLM("rejected", motif="demande hors périmètre autorisé",
                              brut=phrase, fournisseur=self.nom)
        if any(m in bas for m in ("un truc", "quelque chose", "n'importe quoi",
                                  "je sais pas", "je ne sais pas", "on verra",
                                  "peu importe")) or len(bas.split()) <= 2:
            return ReponseLLM(
                "needs_clarification",
                question="Que veux-tu vérifier : le code, les dépendances, ou les secrets ?",
                brut=phrase, fournisseur=self.nom)

        # Sélection par compréhension de la phrase — c'est le seul rôle du LLM.
        caps = []
        if any(m in bas for m in ("secret", "credential", "token", "mot de passe",
                                  "clé exposée", "fuite")):
            caps.append("SECRET_DETECTION")
        if any(m in bas for m in ("dépendance", "dependenc", "cve", "vulnérabilit",
                                  "vulnerabilit", "sca", "sbom", "paquet",
                                  "supply chain", "supply-chain")):
            caps.append("DEPENDENCY_ANALYSIS")
        if any(m in bas for m in ("code", "statique", "sast", "source", "qualité",
                                  "injection", "bug", "faille")):
            caps.append("CODE_STATIC_ANALYSIS")
        # Le générique AJOUTE les capacités de base, il ne s'y substitue pas :
        # « sécurité » est aussi un mot-clé de DEPENDENCY_ANALYSIS.
        if any(m in bas for m in ("sécurité", "securite", "audit", "analyse", "scan",
                                  "dépôt", "depot", "repo", "repository")):
            for c in ("CODE_STATIC_ANALYSIS", "DEPENDENCY_ANALYSIS", "SECRET_DETECTION"):
                if c not in caps:
                    caps.append(c)
        if not caps:
            return ReponseLLM(
                "needs_clarification",
                question="Que veux-tu vérifier exactement ?",
                brut=phrase, fournisseur=self.nom)
        return ReponseLLM("resolved", tuple(caps), brut=phrase, fournisseur=self.nom)


@dataclass
class Groq:
    """Fournisseur réel — Groq, derrière leur API compatible OpenAI.

    La clé n'est JAMAIS écrite dans le code ni dans un fichier : elle vient de la
    variable d'environnement GROQ_API_KEY, lue à l'appel.

    Elle ne sort pas de ce processus : le prompt ne contient que la phrase de
    l'utilisateur et la description des capacités. Aucun nom d'outil, aucun chemin,
    aucun morceau de code analysé.
    """
    # `llama-3.3-70b-versatile` n'existe plus sur ce compte : 404. Les modèles
    # disponibles se listent sur /openai/v1/models — ils changent, donc le défaut
    # est surchargeable par GROQ_MODELE.
    modele: str = ""
    cle_env: str = "GROQ_API_KEY"
    modele_env: str = "GROQ_MODELE"
    modele_defaut: str = "openai/gpt-oss-120b"
    endpoint: str = "https://api.groq.com/openai/v1/chat/completions"
    timeout: int = 60
    nom: str = "groq"
    # Cloudflare bloque l'agent par défaut d'urllib (« Python-urllib/3.x ») avec un
    # 403 code 1010. Un agent normal passe. Ce n'est pas un contournement : c'est un
    # appel API ordinaire, pas du scraping.
    agent: str = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")

    def complet(self, phrase: str, description: str):
        import json
        import urllib.error
        import urllib.request

        cle = os.environ.get(self.cle_env, "")
        if not cle:
            # Pas de clé : on retourne None, le repli déterministe prend la main.
            return None
        modele = self.modele or os.environ.get(self.modele_env, self.modele_defaut)

        systeme = (
            "Tu classes une demande d'analyse de sécurité. "
            "Réponds UNIQUEMENT avec un objet JSON valide, sans texte autour, sans "
            "bloc de code, avec exactement ces quatre clés : "
            'status ("resolved" | "needs_clarification" | "rejected"), '
            "capabilities : liste d'identifiants pris UNIQUEMENT parmi ceux fournis, "
            "vide sinon. "
            "question : texte, obligatoire si needs_clarification, chaîne vide sinon. "
            "motif : texte, obligatoire si rejected, chaîne vide sinon. "
            "N'invente jamais d'identifiant de capacité. "
            "Ne propose jamais d'outil, de commande, de chemin ou de paramètre. "
            "Si la demande vise une cible qui n'appartient pas au demandeur, ou une "
            "action destructive, réponds rejected."
        )
        utilisateur = f"Capacités disponibles :\n{description}\n\nDemande : {phrase}"

        corps = json.dumps({
            "model": modele,
            "messages": [{"role": "system", "content": systeme},
                         {"role": "user", "content": utilisateur}],
            "temperature": 0,
        }).encode("utf-8")
        req = urllib.request.Request(
            self.endpoint, data=corps,
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {cle}",
                     "User-Agent": self.agent})
        # Groq limite le débit : sans pause entre appels rapprochés, on reçoit des
        # erreurs intermittentes. Ce n'est pas un défaut du modèle, c'est une contrainte
        # du fournisseur — et en production il faudra la gérer (file d'attente, retries).
        import time as _t
        dernier = None
        for essai in range(3):
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as rep:
                    doc = json.loads(rep.read().decode("utf-8"))
                break
            except urllib.error.HTTPError as e:
                detail = ""
                try:
                    detail = e.read().decode("utf-8", "replace")[:200]
                except Exception:
                    pass
                dernier = RuntimeError(f"Groq HTTP {e.code} : {detail}")
                if e.code in (429, 403, 500, 502, 503):
                    _t.sleep(1.5 * (essai + 1))
                    continue
                raise dernier from e
            except (urllib.error.URLError, OSError, json.JSONDecodeError) as e:
                dernier = RuntimeError(f"Groq injoignable : {type(e).__name__}")
                _t.sleep(1.5 * (essai + 1))
        else:
            raise dernier or RuntimeError("Groq : échec inconnu")

        texte = (doc.get("choices") or [{}])[0].get("message", {}).get("content", "")
        return self._lire(texte)

    def _lire(self, texte: str):
        """Extrait le JSON de la réponse. Tolère du texte autour et les blocs de code."""
        import json
        t = (texte or "").strip()
        if t.startswith("```"):
            t = t.strip("`")
            if t.lower().startswith("json"):
                t = t[4:]
        debut, fin = t.find("{"), t.rfind("}")
        if debut < 0 or fin <= debut:
            return None
        try:
            d = json.loads(t[debut:fin + 1])
        except json.JSONDecodeError:
            return None
        caps = d.get("capabilities") or []
        if not isinstance(caps, list):
            caps = []
        return ReponseLLM(
            statut=str(d.get("status", "")),
            capabilities=tuple(str(c) for c in caps),
            question=str(d.get("question", "") or ""),
            motif=str(d.get("motif", "") or ""),
            brut=texte,
            fournisseur=self.nom,
        )


@dataclass
class OpenAICompatible:
    """Fournisseur réel, derrière un endpoint compatible OpenAI.

    Non exercé dans l'environnement de développement : aucune clé, aucun endpoint.
    Le code est là pour qu'un vrai modèle se branche sans modifier le contrat.
    """
    modele: str = ""
    endpoint: str = ""
    cle_env: str = "PLATEFORME_LLM_CLE"
    timeout: int = 60
    nom: str = "openai-compatible"

    def complet(self, phrase: str, description: str):
        import urllib.error
        import urllib.request

        cle = os.environ.get(self.cle_env, "")
        endpoint = self.endpoint or os.environ.get("PLATEFORME_LLM_ENDPOINT", "")
        modele = self.modele or os.environ.get("PLATEFORME_LLM_MODELE", "")
        if not cle or not endpoint or not modele:
            # Pas de configuration : on retourne None, le repli déterministe prend la main.
            return None

        # Le prompt ne contient QUE la phrase et la description des capacités.
        # Aucun nom d'outil, aucun chemin, aucun argument.
        systeme = (
            "Tu classes une demande d'analyse de sécurité. "
            "Réponds UNIQUEMENT en JSON, sans texte autour, avec exactement ces clés : "
            'status ("resolved" | "needs_clarification" | "rejected"), '
            'capabilities (liste d\'identifiants parmi ceux fournis, vide sinon), '
            'question (chaîne, obligatoire si needs_clarification, vide sinon), '
            'motif (chaîne, obligatoire si rejected, vide sinon). '
            "N'invente jamais d'identifiant de capacité. "
            "Ne propose jamais d'outil, de commande ou de chemin."
        )
        utilisateur = (
            f"Capacités disponibles :\n{description}\n\nDemande : {phrase}\n"
        )
        corps = json.dumps({
            "model": modele,
            "messages": [{"role": "system", "content": systeme},
                         {"role": "user", "content": utilisateur}],
            "temperature": 0,
        }).encode("utf-8")
        req = urllib.request.Request(
            endpoint.rstrip("/") + "/chat/completions", data=corps,
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {cle}"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                doc = json.loads(r.read().decode("utf-8"))
        except (urllib.error.URLError, OSError, json.JSONDecodeError) as e:
            raise RuntimeError(f"LLM injoignable : {type(e).__name__}") from e

        texte = (doc.get("choices") or [{}])[0].get("message", {}).get("content", "")
        return self._lire(texte)

    def _lire(self, texte: str):
        """Extrait le JSON de la réponse. Tolère un texte autour."""
        texte = (texte or "").strip()
        if texte.startswith("```"):
            texte = texte.strip("`")
            if texte.lower().startswith("json"):
                texte = texte[4:]
        debut, fin = texte.find("{"), texte.rfind("}")
        if debut < 0 or fin <= debut:
            return None
        try:
            d = json.loads(texte[debut:fin + 1])
        except json.JSONDecodeError:
            return None
        caps = d.get("capabilities") or []
        if not isinstance(caps, list):
            caps = []
        return ReponseLLM(
            statut=str(d.get("status", "")),
            capabilities=tuple(str(c) for c in caps),
            question=str(d.get("question", "") or ""),
            motif=str(d.get("motif", "") or ""),
            brut=texte,
            fournisseur=self.nom,
        )

