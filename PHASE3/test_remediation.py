#!/usr/bin/env python3
"""Phase 11 — Suite de tests autonomes pour le moteur de remédiation automatisée.

Vérifie 100 % des types de correctifs :
1. dependency_bump (SCA)
2. code_patch (Unified Diff format)
3. config_fix (IaC / Dockerfile / Shell)

Usage : PYTHONPATH=PHASE3/slice python3 PHASE3/test_remediation.py
"""

from __future__ import annotations

import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parent
sys.path.insert(0, str(RACINE / "slice"))

from findings import Finding, Remediation
import remediation as R

PAS = 0
ECHECS = 0


def cas(nom: str, ok: bool, detail: str = ""):
    global PAS, ECHECS
    if ok:
        PAS += 1
        print(f"  OK    {nom}")
    else:
        ECHECS += 1
        print(f"  ECHEC {nom}" + (f"\n          {detail}" if detail else ""))


def test_dependency_bump():
    print("=== Test 1: dependency_bump (SCA) ===")
    f_trivy = Finding(
        id="tv-0001",
        source={
            "tool": "trivy",
            "original_rule_id": "CVE-2020-14343",
            "canonical_rule_id": "trivy:CVE-2020-14343",
            "version_installee": "5.3.1",
            "version_corrigee": "5.4.1",
        },
        identity={"canonical_rule_id": "trivy:CVE-2020-14343", "fingerprint": "fp1"},
        location={"asset": "repository", "file": "requirements.txt", "package": "PyYAML"},
        severity={"value": "HIGH", "origine": "trivy"},
        evidence={"message": "PyYAML unsafe load vulnerability"},
    )

    rem = R.generer_remediation_finding(f_trivy)
    cas("1a. remédiation générée non nulle", rem is not None)
    cas("1b. type == dependency_bump", rem.type == "dependency_bump" if rem else False)
    cas("1c. confidence == high quand version_corrigee fournie", rem.confidence == "high" if rem else False)
    cas("1d. détails contiennent package_name et target_version",
        rem.details.get("package_name") == "PyYAML" and rem.details.get("target_version") == "5.4.1" if rem else False)


def test_code_patch():
    print("\n=== Test 2: code_patch (Unified Diff) ===")
    f_semgrep = Finding(
        id="sg-0001",
        source={
            "tool": "semgrep",
            "original_rule_id": "rules.python.lang.security.audit.avoid-pyyaml-load",
            "canonical_rule_id": "semgrep:avoid-pyyaml-load",
        },
        identity={"canonical_rule_id": "semgrep:avoid-pyyaml-load", "fingerprint": "fp2"},
        location={"asset": "repository", "file": "app.py", "line": 42},
        severity={"value": "MEDIUM", "origine": "semgrep"},
        evidence={"message": "Avoid yaml.load()", "extrait": "data = yaml.load(stream)\n"},
    )

    rem = R.generer_remediation_finding(f_semgrep)
    cas("2a. remédiation générée non nulle", rem is not None)
    cas("2b. type == code_patch", rem.type == "code_patch" if rem else False)
    cas("2c. format unified diff valide (--- a/ et +++ b/)",
        "--- a/app.py" in rem.details.get("patch", "") and "+++ b/app.py" in rem.details.get("patch", "") if rem else False)
    cas("2d. remplacement par safe_load présent dans le diff",
        "+data = yaml.safe_load(stream)" in rem.details.get("patch", "") if rem else False)


def test_config_fix():
    print("\n=== Test 3: config_fix (IaC / Dockerfile) ===")
    f_docker = Finding(
        id="hl-0001",
        source={
            "tool": "hadolint",
            "original_rule_id": "DL3002",
            "canonical_rule_id": "hadolint:DL3002",
        },
        identity={"canonical_rule_id": "hadolint:DL3002", "fingerprint": "fp3"},
        location={"asset": "repository", "file": "Dockerfile", "line": 10},
        severity={"value": "HIGH", "origine": "hadolint"},
        evidence={"message": "Last user should not be root"},
    )

    rem = R.generer_remediation_finding(f_docker)
    cas("3a. remédiation générée non nulle", rem is not None)
    cas("3b. type == config_fix", rem.type == "config_fix" if rem else False)
    cas("3c. suggestion USER 10001 présente",
        "USER 10001" in rem.details.get("suggested_directive", "") if rem else False)


def test_batch_remediations():
    print("\n=== Test 4: generer_remediations (batch findings + clusters) ===")
    f1 = Finding(
        id="f1",
        source={"tool": "trivy", "original_rule_id": "CVE-2020-14343", "version_corrigee": "5.4.1"},
        identity={"canonical_rule_id": "trivy:CVE-2020-14343", "fingerprint": "fp1"},
        location={"asset": "repository", "file": "requirements.txt", "package": "PyYAML"},
        severity={"value": "HIGH", "origine": "trivy"},
        evidence={},
    )
    clusters = [{
        "cluster_id": "CL-001",
        "members": ["f1"],
        "confidence": "high",
        "reason": ["same_package"],
    }]

    res = R.generer_remediations([f1], clusters)
    cas("4a. remédiations findings produites", "f1" in res["findings"])
    cas("4b. remédiation cluster associée", "CL-001" in res["clusters"])
    cas("4c. f1.remediation mis à jour directement sur l'instance Finding", f1.remediation is not None)


def main() -> int:
    test_dependency_bump()
    test_code_patch()
    test_config_fix()
    test_batch_remediations()

    print(f"\n==================================================")
    print(f"  {PAS}/{PAS + ECHECS} tests passés · {ECHECS} échec(s)")
    print(f"==================================================")
    return 1 if ECHECS else 0


if __name__ == "__main__":
    sys.exit(main())
