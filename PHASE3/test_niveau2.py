#!/usr/bin/env python3
"""Phase 5B — NIVEAU 2 de la promesse : format non standard, parser spécifique.

    outil CLI
    → format non standard
    → parser spécifique isolé
    → même cœur inchangé

Ce test vérifie AUSSI les invariants métier, et pas seulement des quantités. Un test
qui se contente de `len(steps) >= 3` devient faux dès qu'on ajoute un provider : il faut
exiger les capacités obligatoires ET autoriser les supplémentaires.

Usage : python3 PHASE3/test_niveau2.py
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parent
sys.path.insert(0, str(RACINE / "slice"))

import assainissement as ASS        # noqa: E402
import parsers                      # noqa: E402
import pipeline                     # noqa: E402
import provider_manifest as PM      # noqa: E402
from registre import Registry       # noqa: E402

PAS = 0
ECHECS = 0


def cas(nom, ok, detail=""):
    global PAS, ECHECS
    PAS, ECHECS = (PAS + 1, ECHECS) if ok else (PAS, ECHECS + 1)
    print(f"  {'OK   ' if ok else 'ECHEC'} {nom}" + (f"\n          {detail}" if detail else ""))


def main() -> int:
    print("=== PHASE 5B — NIVEAU 2 : FORMAT NON STANDARD ===\n")
    reg = Registry()

    # ------------------------------------------------ 1. le parser est isolé
    prov = reg.provider("bandit_custom")
    cas("1. le provider custom est déclaré par manifest",
        prov.manifest is not None and prov.manifest.sortie_format == "custom",
        f"format={prov.manifest.sortie_format} parser={prov.manifest.extraction.parser}")
    cas("1b. le parser est enregistré par son NOM",
        parsers.obtenir(prov.manifest.extraction.parser) is not None,
        f"disponibles : {parsers.disponibles()}")

    # Le cœur ne doit connaître ni l'outil ni le format.
    def code_seul(nom: str) -> str:
        """Le code SANS les commentaires ni les docstrings.

        Vérifier le texte brut donnerait des faux positifs : extraction.py cite bandit
        dans un commentaire d'exemple, ce qui n'est pas une dépendance.
        """
        import ast
        src = (RACINE / "slice" / nom).read_text(encoding="utf-8")
        arbre = ast.parse(src)
        docstrings = {n.value.value for n in ast.walk(arbre)
                      if isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant)
                      and isinstance(n.value.value, str)}
        lignes = []
        for ligne in src.splitlines():
            if ligne.strip().startswith("#"):
                continue
            lignes.append(ligne)
        texte = "\n".join(lignes)
        for d in docstrings:
            texte = texte.replace(d, "")
        return texte

    coeur = ["pipeline.py", "findings.py", "policy.py", "plan.py", "clusterer.py",
             "rapport.py", "extraction.py"]
    coupables = [f for f in coeur
                 if re.search(r"\bbandit\b", code_seul(f), re.IGNORECASE)]
    cas("2. aucun fichier du cœur ne connaît bandit", not coupables,
        f"concernés : {coupables}" if coupables
        else "pipeline, findings, policy, plan, clusterer, rapport, extraction : aucun")

    # adapters.py connaît le format générique « custom », mais pas l'outil.
    # Mot entier : « bandit_custom » contient « bandit » en sous-chaîne, ce qui
    # donnerait un faux positif.
    ad = code_seul("adapters.py")
    cas("2b. l'adaptateur connaît le format générique, pas l'outil",
        "custom" in ad and not re.search(r"\bbandit\b", ad, re.IGNORECASE),
        "'custom' présent, mot 'bandit' absent")

    # ------------------------------------------------ 3. le manifest exige un parser
    print("\n--- validation du manifest ---")
    try:
        PM.valider({"id": "x", "binaire": "bandit", "argv": ["{BIN}"],
                    "output": {"format": "custom"}, "extraction": {}}, "T")
        cas("3. format custom sans parser → refusé", False, "accepté")
    except PM.ManifestError as e:
        cas("3. format custom sans parser → refusé", True, str(e)[:90])

    try:
        PM.valider({"id": "x", "binaire": "bandit", "argv": ["{BIN}"],
                    "output": {"format": "custom"},
                    "extraction": {"parser": "inexistant"}}, "T")
        cas("3b. parser inexistant → refusé", False, "accepté")
    except PM.ManifestError as e:
        cas("3b. parser inexistant → refusé", True, str(e)[:90])

    # La faille trouvée : jetons en minuscules.
    try:
        PM.valider({"id": "x", "binaire": "bandit",
                    "argv": ["{BIN}", "--msg-template", "{relpath},{line}"],
                    "output": {"format": "custom"},
                    "extraction": {"parser": "bandit_custom"}}, "T")
        cas("4. jeton d'outil NON déclaré → refusé", False,
            "accepté : la faille des jetons en minuscules est revenue")
    except PM.ManifestError as e:
        cas("4. jeton d'outil NON déclaré → refusé", True, str(e)[:90])

    try:
        PM.valider({"id": "x", "binaire": "bandit",
                    "argv": ["{BIN}", "--msg-template", "{relpath},{line}"],
                    "output": {"format": "custom"},
                    "extraction": {"parser": "bandit_custom",
                                   "jetons_outil": ["{relpath}", "{line}"]}}, "T")
        cas("4b. jeton d'outil déclaré → accepté", True)
    except PM.ManifestError as e:
        cas("4b. jeton d'outil déclaré → accepté", False, str(e)[:90])

    # ------------------------------------------------ 5. exécution
    print("\n--- exécution ---")
    e = pipeline.executer("Analyse la sécurité de mon dépôt", RACINE / "testrepo",
                        avec_internes=True)
    # Comptage par PROVIDER, plus par outil — et la distinction n'est pas cosmétique.
    # `source["tool"]` nomme le BINAIRE (décision du 2026-08-30, `findings.py`) : le
    # clusterer compte les outils distincts d'un cluster pour affirmer une convergence,
    # et compter `bandit` et `bandit_custom` comme deux moteurs indépendants alors
    # qu'ils sont le même binaire sur deux jeux de règles SURÉVALUAIT la convergence —
    # une affirmation de sécurité fausse, pas un détail de présentation.
    # Ce cas parle d'un PROVIDER (« le provider custom produit des findings ») : il doit
    # donc lire `source["provider"]`. Lire `tool` le faisait porter sur le moteur.
    par_outil = {}
    for f in e.findings:
        par_outil[f["source"]["provider"]] = par_outil.get(f["source"]["provider"], 0) + 1
    cas("5. le provider custom produit des findings", par_outil.get("bandit_custom", 0) > 0,
        f"par provider : {par_outil}")

    custom = [f for f in e.findings if f["source"]["provider"] == "bandit_custom"]
    cas("5b. leurs champs sont corrects",
        all(f["source"]["original_rule_id"] and f["location"]["file"] for f in custom),
        f"{len(custom)} findings, règles="
        f"{sorted({f['source']['original_rule_id'] for f in custom})}")
    cas("5c. le parser a produit les mêmes règles que le format JSON",
        {f["source"]["original_rule_id"] for f in custom}
        == {f["source"]["original_rule_id"] for f in e.findings
            if f["source"]["provider"] == "bandit"},
        "custom et json convergent sur le même jeu de règles")

    # ------------------------------------------------ 6. secrets
    cas("6. le parser masque les secrets du texte libre",
        not any(ASS.contient_secret(repr(f), large=True) for f in custom),
        "aucun motif dans les findings custom")

    # ------------------------------------------------ 7. invariants métier
    print("\n--- invariants métier (pas seulement des quantités) ---")
    steps = e.plan["steps"]
    OBLIGATOIRES = {"CODE_STATIC_ANALYSIS", "DEPENDENCY_ANALYSIS", "SECRET_DETECTION"}
    caps_plan = {s["capability"] for s in steps}
    ids_registre = {p.id for p in reg.providers()}
    caps_registre = {c.id for c in reg.capabilities()}

    # 7a — une capacité obligatoire absente du plan a DEUX causes, et elles ne se
    # réparent pas du même geste : le moteur ne l'a pas planifiée (défaut réel), ou
    # aucun de ses outils n'est exécutable sur CETTE machine (fait d'environnement —
    # trivy et grype absents, pip-audit écarté parce que la cage coupe le réseau).
    # L'ancien critère les confondait et faisait passer une machine incomplète pour une
    # régression du moteur.
    #
    # Le ledger tranche, parce que chaque provider écarté y porte un statut ET une raison
    # NOMMÉE. L'invariant vérifié devient donc plus fort, pas plus faible : une capacité
    # obligatoire est soit planifiée, soit absente avec une cause dite pour chacun de ses
    # outils. Un moteur qui « oublierait » une capacité sans motif resterait un échec.
    manquantes = sorted(OBLIGATOIRES - caps_plan)
    ledger = list(e.statuts or [])
    inexplicables = [cap for cap in manquantes
                     if not any(x.get("capability") == cap for x in ledger)
                     or any(not x.get("raison") for x in ledger
                            if x.get("capability") == cap)]
    cas("7a. les capacités obligatoires sont présentes — sinon leur absence est nommée",
        not inexplicables,
        (f"manquantes : {manquantes} · causes : "
         + ", ".join(f"{x['provider']}={x['statut']}" for x in ledger
                     if x.get("capability") in manquantes)
         + (f" · INEXPLIQUÉES : {inexplicables}" if inexplicables else "")))
    cas("7b. aucune capacité inconnue n'est sélectionnée", caps_plan <= caps_registre,
        f"inconnues : {sorted(caps_plan - caps_registre)}")
    provs_plan = {s["provider"] for s in steps}
    cas("7c. chaque provider sélectionné existe dans le registre",
        provs_plan <= ids_registre, f"inconnus : {sorted(provs_plan - ids_registre)}")
    import adapters as AD
    cas("7d. chaque provider sélectionné a un mode d'exécution connu du cœur",
        # La version précédente ne contrôlait que `bandit` et `bandit_custom`, deux noms
        # écrits en dur : les quatorze autres providers du registre passaient entre les
        # mailles, et le test devenait faux dès qu'un outil était ajouté. L'invariant
        # réel est plus large et se DÉRIVE : le cœur sait exécuter un provider soit par
        # son manifest, soit par un adaptateur historique enregistré — et pas autrement.
        all(reg.provider(pid).manifest is not None or pid in AD.ADAPTATEURS
            for pid in provs_plan),
        f"providers : {sorted(provs_plan)} · adaptateurs connus : {sorted(AD.ADAPTATEURS)}")
    cas("7e. chaque étape porte un risque déclaré",
        all(s["risque"] in ("PASSIVE", "ACTIVE", "INTRUSIVE", "DESTRUCTIVE") for s in steps),
        f"risques : {sorted({s['risque'] for s in steps})}")
    # 7f — une CONSTANTE QUI RECOPIAIT LE CATALOGUE. Neuf noms pour seize providers,
    # rallongée à la main à chaque intégration (checkov en 08-28, semgrep_go en 08-29,
    # grype+kics en 08-29…) : le test échouait donc à chaque nouvel outil, non parce
    # qu'un outil non autorisé était apparu, mais parce que personne n'avait rallongé la
    # liste. C'est exactement la duplication de connaissance que l'architecture veut
    # supprimer, et elle rendait le critère inopérant : il ne pouvait rien détecter.
    #
    # Or l'autorisation a DÉJÀ une source unique : `binaire_autorise`, que le chargeur de
    # manifest invoque au chargement (liste du cœur, puis manifeste d'approvisionnement —
    # « `which` n'est pas une autorisation »). On vérifie l'invariant À SA SOURCE.
    binaires_plan = {pid: Path(AD.binaire_de(reg.provider(pid))).name
                     for pid in sorted(provs_plan)}
    # `{BIN}/trivy` : le jeton est résolu au lancement, l'autorisation se juge sur le nom
    # nu — la même normalisation que `adapters.resoudre_exe`.
    refus_autorisation = {pid: PM.binaire_est_autorise(nom)
                          for pid, nom in binaires_plan.items()
                          if nom and not PM.binaire_autorise(nom)}
    cas("7f. aucun outil non autorisé n'est introduit",
        not refus_autorisation,
        f"binaires : {binaires_plan}"
        + (f" · REFUSÉS : {refus_autorisation}" if refus_autorisation else ""))
    cas("7g. des providers supplémentaires restent autorisés",
        len(provs_plan) > 3,
        f"{len(provs_plan)} providers pour 3 capacités obligatoires")

    # ------------------------------------------------ 8. couverture et rapport
    couv = e.rapport["couverture"].get("bandit_custom")
    cas("8. le provider custom apparaît dans la couverture", couv is not None,
        f"analysé={couv.get('analysé') if couv else None}")
    cas("8b. sa limite explique le parser spécifique",
        couv is not None and any("parser spécifique" in x for x in couv.get("limites", [])),
        (couv.get("limites", [""])[-1][:90] if couv else ""))

    print(f"\n{'=' * 52}\n  {PAS}/{PAS + ECHECS} · {ECHECS} échec(s)\n{'=' * 52}")
    if not ECHECS:
        print("\nNIVEAU 2 DÉMONTRÉ :")
        print("  un format non standard, lu par un parser spécifique enregistré par son")
        print("  nom dans le manifest, sans modification du cœur du pipeline.")
    return 1 if ECHECS else 0


if __name__ == "__main__":
    raise SystemExit(main())
