#!/usr/bin/env python3
"""
Batterie « extraction par blocs » — multi-framework CHECKOV.

Périmètre strict (consigne 2026-08-28) :
- AUCUN appel réseau, AUCUN outil exécuté : tout est lu depuis l'artefact
  capturé PHASE3/testrepo_iac/artefacts_captures/checkov_multiframework.json.
- Le clustering et le modèle de findings ne sont PAS touchés par ce chantier :
  seuls extraction.py (générique : jeton '$', nested_key pointé, racine dict
  ou liste) et la déclaration checkov (capabilities.yaml) ont évolué. Cette
  batterie le vérifie par ses régressions : les modèles existants (plat,
  imbriqué simple) doivent donner exactement le même résultat qu'avant.

Usage: python3 PHASE3/test_extraction_blocs.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

RACINE = Path(__file__).parent
sys.path.insert(0, str(RACINE / "slice"))

import extraction  # noqa: E402
from registre import Registry  # noqa: E402

ARTEFACT = RACINE / "testrepo_iac" / "artefacts_captures" / "checkov_multiframework.json"
ATTENDUS = RACINE / "testrepo_iac" / "ATTENDUS.yaml"

CAS = []
ECHECS = []


def cas(nom: str, cond: bool, detail: str = ""):
    CAS.append((nom, cond, detail))
    if not cond:
        ECHECS.append(nom)


def main() -> int:
    # 1. L'artefact capturé existe et a la forme attendue (racine = liste de blocs)
    if not ARTEFACT.is_file():
        print(f"MANQUANT : {ARTEFACT}")
        return 2
    brut = json.loads(ARTEFACT.read_text(encoding="utf-8"))
    cas("1. artefact capturé : racine = liste de blocs",
        isinstance(brut, list) and all("check_type" in b for b in brut),
        f"blocs={[b.get('check_type') for b in brut] if isinstance(brut, list) else type(brut).__name__}")

    # 2. La déclaration checkov est multi-framework et chargée par le registre
    prov = Registry().provider("checkov")
    m = prov.manifest
    cas("2a. plus de --framework dans argv (multi-framework)",
        not any(a == "--framework" for a in m.argv), f"argv={list(m.argv)}")
    cas("2b. modèle imbriqué avec racine '$'",
        m.extraction.modele == "imbriqué" and m.extraction.nested_from == "$",
        f"{m.extraction.modele}/{m.extraction.nested_from!r}")
    cas("2c. contexte cadre<-check_type",
        m.extraction.contexte.get("cadre") == "check_type")

    # 3. Extraction : tous les frameworks non vides remontent, comptes exacts
    items = extraction.extraire(brut, m.extraction)
    par_cadre = {}
    for it in items:
        par_cadre[it.get("cadre")] = par_cadre.get(it.get("cadre"), 0) + 1
    attendu_brut = {b["check_type"]: len(b["results"]["failed_checks"]) for b in brut}
    non_vides = {k: v for k, v in attendu_brut.items() if v}
    cas("3a. extraction : total = somme des blocs de l'artefact",
        len(items) == sum(attendu_brut.values()),
        f"{len(items)} extraits vs {sum(attendu_brut.values())} dans l'artefact")
    cas("3b. chaque bloc non vide est représenté (cadre injecté)",
        par_cadre == non_vides, f"{par_cadre} vs {non_vides}")
    cas("3c. terraform, kubernetes ET dockerfile couverts",
        {"terraform", "kubernetes", "dockerfile"} <= set(par_cadre), f"cadres={sorted(par_cadre)}")

    # 4. Le référentiel ATTENDUS.yaml est respecté bloc par bloc (cadre × fichier)
    att = yaml.safe_load(ATTENDUS.read_text(encoding="utf-8"))["attendus_provider"]
    obtenu: dict[tuple, set] = {}
    for n in (extraction.champs(it, m.extraction) for it in items):
        obtenu.setdefault((n["cadre"], n["fichier"]), set()).add(n["regle"])
    ecart = []
    for cadre, fichiers in att.items():
        for fichier, spec in fichiers.items():
            if obtenu.get((cadre, fichier)) != set(spec["checks"]):
                ecart.append(f"{cadre}:{fichier}")
    cas("4a. ATTENDUS respecté pour chaque (framework, fichier)",
        not ecart and len(obtenu) == sum(len(f) for f in att.values()), f"écarts={ecart}")
    cas("4b. mapping complet : regle/fichier/ligne/message non vides partout",
        all(n.get(k) not in (None, "", []) for n in
            (extraction.champs(it, m.extraction) for it in items)
            for k in ("regle", "fichier", "ligne", "message")))
    cas("4c. ligne = entier (file_line_range[0])",
        all(isinstance(n["ligne"], int) for n in
            (extraction.champs(it, m.extraction) for it in items)))

    # 5. Régression modèle imbriqué « simple » (forme trivy historique) : inchangé
    ex_trivy = extraction.Extraction(
        modele="imbriqué", items_from="Results",
        nested_from="Results", nested_key="Vulnerabilities",
        contexte={"cible": "Target"},
        champs={"paquet": "PkgName", "regle": "VulnerabilityID"},
    )
    doc_trivy = {"Results": [{"Target": "app:1", "Vulnerabilities": [{"PkgName": "x", "VulnerabilityID": "V-1"}]},
                             {"Target": "lock"}]}
    r = extraction.extraire(doc_trivy, ex_trivy)
    # NB : contexte injecte dans l'item brut ; champs() ne retourne que les champs
    # déclarés (comportement historique, inchangé) — d'où cible vérifié sur l'item.
    cas("5. imbriqué historique (trivy) inchangé",
        len(r) == 1 and r[0].get("cible") == "app:1"
        and extraction.champs(r[0], ex_trivy) == {"paquet": "x", "regle": "V-1"},
        str(r))

    # 6. Régression modèle plat (forme bandit historique) : inchangé
    ex_bandit = extraction.Extraction(modele="plat", items_from="results",
                                      champs={"regle": "test_id", "severite": "issue_severity"})
    doc_bandit = {"results": [{"test_id": "B101", "issue_severity": "LOW"}], "_totals": {"x": 1}}
    rb = extraction.extraire(doc_bandit, ex_bandit)
    cas("6. plat historique (bandit) inchangé",
        len(rb) == 1 and extraction.champs(rb[0], ex_bandit) == {"regle": "B101", "severite": "LOW"})

    # 7. Robustesse : blocs malformés ignorés, jamais de crash
    cassé = [{"check_type": "terraform", "results": {"failed_checks": [{"check_id": "CKV_OK"}]}},
             {"check_type": "cassé"},                      # pas de results
             "pas-un-bloc",                                 # pas un dict
             {"check_type": "vide", "results": {"failed_checks": None}}]
    rc = extraction.extraire(cassé, m.extraction)
    cas("7. blocs malformés ignorés sans crash",
        len(rc) == 1 and rc[0]["check_id"] == "CKV_OK", str(rc))

    # 8. Racine DICT (bloc isolé — forme que prend une sortie mono-sous-analyse)
    mono = brut[0] if brut else {}
    rm = extraction.extraire(mono, m.extraction)
    cas("8. racine dict + '$' : un bloc isolé est lu aussi",
        len(rm) == attendu_brut.get(mono.get("check_type"), -1), f"{len(rm)} items")

    for nom, cond, detail in CAS:
        print(("OK   " if cond else "ECHEC") + f" {nom}" + (f" — {detail}" if detail and not cond else ""))
    print(f"\n{len(CAS) - len(ECHECS)}/{len(CAS)} cas vérifiés")
    return 1 if ECHECS else 0


if __name__ == "__main__":
    sys.exit(main())
