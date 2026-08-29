#!/usr/bin/env python3
"""
Batterie « normalisation des chemins » — identité indépendante de la machine.

Décision 2026-08-28 (dogfooding, campagne 2). Défaut mesuré :
- 72 findings eslint portaient le chemin absolu du montage sandbox
  (/home/user/PHASE3/mt-scan/…) ; 7 clés de cluster l'embarquaient ;
- les fingerprints incluent le fichier : leur stabilité ne tient qu'à la
  constance du point de montage codé en dur — le jour où il devient dynamique
  (portabilité), toutes les identités changent d'un coup ;
- hors isolateur, la normalisation produit des chemins de la machine hôte.

Correctif : les chemins sont relativisés à la normalisation (avant calcul du
fingerprint), par rapport aux racines CONNUES (montage, cible). Clustering et
modèle de findings intacts — ils consomment des valeurs plus propres.

Aucun outil exécuté : artefacts capturés + documents synthétiques sur formes
réelles.

Usage: python3 PHASE3/test_chemins.py
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

RACINE = Path(__file__).parent
sys.path.insert(0, str(RACINE / "slice"))

import findings as F  # noqa: E402
from registre import Registry  # noqa: E402
from sandbox import Sandbox  # noqa: E402

CAS = []
ECHECS = []


def cas(nom: str, cond: bool, detail: str = ""):
    CAS.append((nom, cond, detail))
    if not cond:
        ECHECS.append(nom)


def raw_semgrep_eslint() -> dict:
    logs = RACINE / "dogfooding" / "logs"
    m = re.search(r"artefacts : (\S+)", (logs / "eslint2.log").read_text())
    d = RACINE / m.group(1)
    src = d / "raw_semgrep.json"
    if not src.is_file():                      # conservation : brut ou redacted
        src = d / "raw_semgrep.redacted.json"
    return json.loads(src.read_text())


def doc_checkov(fichier: str) -> dict:
    return [{"check_type": "terraform",
             "results": {"failed_checks": [{
                 "check_id": "CKV_AWS_3", "check_name": "EBS encryption",
                 "file_path": fichier, "file_line_range": [17, 22],
                 "severity": None, "guideline": None}]}},
            ]


def main() -> int:
    m_scan = Sandbox.M_SCAN

    # 1. Artefact réel : les chemins absolus du montage deviennent relatifs
    brut = raw_semgrep_eslint()
    fs = F.normaliser("semgrep", brut, racines=(m_scan,))
    absolus = [f.location["file"] for f in fs if str(f.location["file"]).startswith("/")]
    cas("1. artefact eslint : plus aucun chemin absolu", not absolus,
        f"{len(absolus)} absolus, ex: {absolus[0] if absolus else ''}")
    cas("1b. les chemins relatifs obtenus sont non vides",
        all(str(f.location["file"]) for f in fs) and len(fs) > 0, f"{len(fs)} findings")

    # 2. Indépendance machine : même dépôt, autre point de montage → mêmes identités
    autre = "/mnt/autre-machine/scan"
    brut2 = json.loads(json.dumps(brut).replace(m_scan, autre))
    fs2 = F.normaliser("semgrep", brut2, racines=(autre,))
    id1 = sorted(f.identity["fingerprint"] for f in fs)
    id2 = sorted(f.identity["fingerprint"] for f in fs2)
    cas("2. fingerprints identiques d'une machine à l'autre", id1 == id2 and len(id1) > 0,
        f"{len(id1)} vs {len(id2)}")

    # 3. Convention checkov : chemin à slash meneur → relatif au dépôt
    prov = Registry().provider("checkov")
    ck = F.normaliser("checkov", doc_checkov("/main.tf"), mani=prov.manifest,
                      racines=(m_scan,))
    cas("3. checkov '/main.tf' → 'main.tf'",
        len(ck) == 1 and ck[0].location["file"] == "main.tf",
        str(ck[0].location["file"]) if ck else "vide")
    ck2 = F.normaliser("checkov", doc_checkov(f"{m_scan}/k8s.yaml"), mani=prov.manifest,
                       racines=(m_scan,))
    cas("3b. checkov sous le montage → relatif",
        ck2[0].location["file"] == "k8s.yaml", ck2[0].location["file"])

    # 4. Régression : les chemins déjà relatifs ne bougent pas (formes trivy/gitleaks)
    doc_trivy = {"Results": [{"Target": "docs/package-lock.json", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-1", "PkgName": "vite", "InstalledVersion": "1.0",
         "Severity": "HIGH", "Title": "t"}]}]}
    tv = F.normaliser("trivy", doc_trivy, racines=(m_scan,))
    cas("4. trivy : chemin relatif inchangé",
        tv and tv[0].location["file"] == "docs/package-lock.json",
        tv[0].location["file"] if tv else "vide")

    # 5. Compatibilité : normaliser() sans racines fonctionne comme avant
    tv0 = F.normaliser("trivy", doc_trivy)
    cas("5. appel sans racines : comportement historique",
        tv0 and tv0[0].location["file"] == "docs/package-lock.json")
    ck0 = F.normaliser("checkov", doc_checkov("/main.tf"), mani=prov.manifest)
    cas("5b. sans racines, le slash meneur est retiré aussi",
        ck0[0].location["file"] == "main.tf", ck0[0].location["file"])

    # 6. Hypothèse documentée : dans l'isolateur, la cible est la seule arborescence
    #    visible — un chemin à slash meneur EST relatif à la cible. '/etc/x' devient
    #    donc 'etc/x' : assumé et testé tel quel, pas découvert en production.
    ck3 = F.normaliser("checkov", doc_checkov("/etc/x"), mani=prov.manifest, racines=())
    cas("6. slash meneur hors cible connu : relativisé (hypothèse isolateur)",
        ck3[0].location["file"] == "etc/x", ck3[0].location["file"])

    for nom, cond, detail in CAS:
        print(("OK   " if cond else "ECHEC") + f" {nom}" + (f" — {detail}" if detail and not cond else ""))
    print(f"\n{len(CAS) - len(ECHECS)}/{len(CAS)} cas vérifiés")
    return 1 if ECHECS else 0


if __name__ == "__main__":
    sys.exit(main())
