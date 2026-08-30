#!/usr/bin/env python3
"""Phase 5A — TEST DÉCISIF : le provider manifest déclaratif.

La preuve recherchée :

    j'ajoute un provider CLI dans un fichier YAML,
    sans modifier le cœur Python,
    et il apparaît correctement dans le plan,
    la policy, l'exécution, la couverture et le rapport.

Ce test vérifie AUSSI que le trusted core refuse ce qu'il doit refuser. Un manifest
permissif serait pire qu'absent : il donnerait l'illusion du déclaratif sans le contrôle.

Usage : python3 PHASE3/test_manifest.py
"""

from __future__ import annotations

import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parent
sys.path.insert(0, str(RACINE / "slice"))

import pipeline                        # noqa: E402
import provider_manifest as PM         # noqa: E402
from registre import Registry          # noqa: E402

PAS = 0
ECHECS = 0
NON_EVALUES: list = []


def cas(nom, ok, detail=""):
    global PAS, ECHECS
    PAS, ECHECS = (PAS + 1, ECHECS) if ok else (PAS, ECHECS + 1)
    print(f"  {'OK   ' if ok else 'ECHEC'} {nom}" + (f"\n          {detail}" if detail else ""))


def non_evalue(nom: str, raison: str) -> None:
    """Ce qui n'a PAS pu être mesuré, et qui ne doit pas compter comme un succès.

    Ajouté le 31/08/2026 : ce fichier ne savait dire que OK ou ECHEC. Une capacité sans
    aucun provider exécutable sur la machine ne produit ni plan ni plan_id, et le test
    plantait alors sur une clé absente — une impossibilité de mesure déguisée en panne,
    et surtout un crash qui masquait les neuf cas suivants.
    """
    NON_EVALUES.append(nom)
    print(f"  N/E   {nom}\n          {raison}")


def refuse(nom, doc, attendu_dans_erreur=""):
    """Vérifie qu'un manifest est REFUSÉ, et pour la bonne raison."""
    try:
        PM.valider(doc, "TEST")
        cas(nom, False, "le manifest a été ACCEPTÉ alors qu'il doit être refusé")
    except PM.ManifestError as e:
        ok = attendu_dans_erreur.lower() in str(e).lower() if attendu_dans_erreur else True
        cas(nom, ok, f"refusé : {str(e)[:110]}")


BON = {
    "id": "bandit",
    "binaire": "bandit",
    "argv": ["{BIN}", "-f", "json", "-r", "{TARGET}"],
    "output": {"format": "json"},
    "extraction": {"modele": "plat", "items_from": "results",
                   "champs": {"regle": "test_id", "fichier": "filename"}},
    "risk": "PASSIVE",
}


def main() -> int:
    print("=== PHASE 5A — PROVIDER MANIFEST DÉCLARATIF ===\n")
    reg = Registry()

    # ------------------------------------------------ 1. bandit existe, par YAML seul
    prov = reg.provider("bandit")
    cas("1. bandit est déclaré dans le registre", prov is not None and prov.manifest is not None,
        f"kind={prov.kind} · manifest={type(prov.manifest).__name__}")
    cas("1b. son argv est une LISTE, pas une chaîne shell",
        isinstance(prov.manifest.argv, tuple) and len(prov.manifest.argv) == 5
        and all(isinstance(a, str) for a in prov.manifest.argv),
        f"argv={list(prov.manifest.argv)}")

    # ------------------------------------------------ 2. le trusted core refuse
    print("\n--- le trusted core refuse ---")
    refuse("chaîne shell au lieu d'une liste",
           {**BON, "argv": "bandit -f json -r {TARGET}"}, "chaîne")
    refuse("binaire non autorisé",
           {**BON, "binaire": "curl"}, "non autorisé")
    refuse("placeholder inconnu",
           {**BON, "argv": ["{BIN}", "{CMD}"]}, "placeholder")
    refuse("injection de métacaractère",
           {**BON, "argv": ["{BIN}", "; rm -rf /"]}, "contient")
    refuse("injection par $()",
           {**BON, "argv": ["{BIN}", "$(id)"]}, "contient")
    refuse("format de sortie non supporté",
           {**BON, "output": {"format": "xml"}}, "format")
    refuse("json sans spécification d'extraction",
           {"id": "x", "binaire": "bandit", "argv": ["{BIN}"], "output": {"format": "json"}},
           "extraction")
    refuse("risque inconnu", {**BON, "risk": "DANGEREUX"}, "risque")

    # Un manifest correct doit passer.
    try:
        PM.valider(BON, "TEST")
        cas("un manifest conforme est accepté", True)
    except PM.ManifestError as e:
        cas("un manifest conforme est accepté", False, str(e)[:100])

    # ------------------------------------------------ 3. plan et policy
    print("\n--- plan et policy ---")
    e = pipeline.executer("Analyse la sécurité de mon dépôt", RACINE / "testrepo",
                        avec_internes=True)
    caps = [s["capability"] for s in e.plan["steps"]]
    provs = [s["provider"] for s in e.plan["steps"]]
    cas("3. bandit apparaît dans le plan", "bandit" in provs,
        f"providers={provs}")
    cas("3b. sa capacité apparaît dans le plan",
        "CODE_STATIC_ANALYSIS_SUITE" in caps, f"capacités={caps}")
    cas("3c. la policy a autorisé le plan", e.decision["allow"],
        f"motifs={e.decision['motifs']}")
    etape = next(s for s in e.plan["steps"] if s["provider"] == "bandit")
    cas("3d. le risque déclaré remonte au plan", etape["risque"] == "PASSIVE",
        f"risque={etape['risque']}")

    # ------------------------------------------------ 4. exécution et résultats
    print("\n--- exécution ---")
    bandit_findings = [f for f in e.findings if f["source"]["tool"] == "bandit"]
    cas("4. bandit a produit des findings", len(bandit_findings) > 0,
        f"{len(bandit_findings)} findings")
    cas("4b. ils portent l'identité source et canonique",
        all(f["source"]["original_rule_id"] and f["identity"]["canonical_rule_id"]
            for f in bandit_findings),
        f"ex. {bandit_findings[0]['identity']['canonical_rule_id']}" if bandit_findings else "")
    cas("4c. ils sont marqués comme issus du déclaratif",
        all(f["source"].get("declaratif") for f in bandit_findings),
        "declaratif=True partout")
    regles = sorted({f["source"]["original_rule_id"] for f in bandit_findings})
    cas("4d. les règles détectées sont plausibles",
        any(r.startswith("B") for r in regles), f"règles={regles[:6]}")

    # ------------------------------------------------ 5. couverture
    couv = e.rapport["couverture"].get("bandit")
    cas("5. bandit apparaît dans la couverture", couv is not None,
        f"analysé={couv.get('analysé') if couv else None}")
    cas("5b. sa limite déclarative est dite",
        couv is not None and any("déclaratif" in x for x in couv.get("limites", [])),
        (couv.get("limites", [""])[-1][:100] if couv else ""))

    # ------------------------------------------------ 6. secrets
    import re
    blob = repr(e.findings)
    cas("6. aucun secret n'a survécu", not re.search(
        r"ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|wJalrXUtnFEMI", blob),
        "les messages de bandit sont masqués à l'extraction")

    # ------------------------------------------------ 7. aucune modification du cœur
    print("\n--- indépendance vis-à-vis des outils ---")
    coeur = ["pipeline.py", "adapters.py", "findings.py", "policy.py",
             "plan.py", "registre.py", "clusterer.py", "rapport.py"]
    def _hors_commentaires(source: str) -> str:
        """Le code, sans les commentaires — et sans `#` pris dans une chaîne.

        Ce test cherchait « bandit » dans le TEXTE du fichier et se satisfaisait donc
        d'un commentaire : `findings.py` citant bandit pour expliquer un choix de
        normalisation faisait échouer une vérification d'architecture, alors qu'aucune
        ligne de code du cœur ne dépend de cet outil. Juger un mot dans un commentaire,
        c'est interdire d'expliquer ce qu'on fait — et laisser passer une vraie
        dépendance écrite en code.
        On utilise le tokenizer Python lui-même : `tokenize` sait où est un commentaire,
        là où une suppression de `#` à la main se trompe sur les chaînes.
        """
        import io
        import tokenize
        garde = []
        for tok in tokenize.generate_tokens(io.StringIO(source).readline):
            if tok.type != tokenize.COMMENT:
                garde.append(tok.string)
        return "\n".join(garde)

    mentions = []
    for f in coeur:
        t = (RACINE / "slice" / f).read_text(encoding="utf-8")
        # `adapters.py` cite bandit dans sa liste d'adaptateurs historiques : c'est
        # justement ce que le manifest doit rendre inutile. On vérifie qu'aucun AUTRE
        # fichier du cœur ne connaît bandit — DANS SON CODE, commentaires exclus.
        if f != "adapters.py" and "bandit" in _hors_commentaires(t).lower():
            mentions.append(f)
    cas("7. aucun fichier du cœur ne connaît bandit", not mentions,
        f"fichiers concernés : {mentions}" if mentions
        else "pipeline, findings, policy, plan, registre, clusterer, rapport : aucun")

    # ------------------------------------------------ 8. canonicalisation du plan
    print("\n--- canonicalisation ---")
    e1 = pipeline.executer("Analyse la sécurité de mon dépôt", RACINE / "testrepo",
                        avec_internes=True)
    e2 = pipeline.executer("analyse la sécurité de mon depot", RACINE / "testrepo",
                           avec_internes=True)
    e3 = pipeline.executer("  ANALYSE   la sécurité, de mon dépôt! ", RACINE / "testrepo",
                           avec_internes=True)
    cas("8. trois formulations d'une même intention → même plan_id",
        e1.plan["plan_id"] == e2.plan["plan_id"] == e3.plan["plan_id"],
        f"{e1.plan['plan_id']} == {e2.plan['plan_id']} == {e3.plan['plan_id']}")
    cas("8b. mais trois request_id distincts",
        len({e1.plan["request_id"], e2.plan["request_id"], e3.plan["request_id"]}) == 3,
        "la requête brute garde sa propre identité")
    cas("8c. même result_digest", e1.result_digest == e2.result_digest == e3.result_digest,
        f"{e1.result_digest}")
    e4 = pipeline.executer("Vérifie les dépendances", RACINE / "testrepo")
    # 8d compare deux plan_id : encore faut-il que la seconde intention PRODUISE un plan.
    # DEPENDENCY_ANALYSIS n'a ici aucun provider exécutable — trivy et grype sont absents
    # de la machine, pip-audit et npm-audit sont écartés par les conditions (la cage coupe
    # le réseau) — la mission s'arrête donc avant le plan et il n'y a rien à comparer.
    # Lire `e4.plan["plan_id"]` sans le garder transformait cette impossibilité en crash.
    if not e4.plan.get("plan_id"):
        non_evalue("8d. une autre intention → un autre plan_id",
                   f"aucun plan produit (arret={e4.arret!r}) : DEPENDENCY_ANALYSIS n'a "
                   "aucun provider exécutable sur cette machine — non mesurable, "
                   "et délibérément pas compté comme un succès")
    else:
        cas("8d. une autre intention → un autre plan_id",
            e4.plan["plan_id"] != e1.plan["plan_id"],
            f"{e4.plan['plan_id']} ≠ {e1.plan['plan_id']}")

    print(f"\n{'=' * 52}\n  {PAS}/{PAS + ECHECS} · {ECHECS} échec(s) · {len(NON_EVALUES)} non évalué(s)\n{'=' * 52}")
    if not ECHECS:
        print("\nPROMESSE TENUE :")
        print("  un provider CLI ajouté dans un fichier YAML, sans modifier le cœur,")
        print("  apparaît dans le plan, la policy, l'exécution, la couverture et le rapport.")
    return 1 if ECHECS else 0


if __name__ == "__main__":
    raise SystemExit(main())
