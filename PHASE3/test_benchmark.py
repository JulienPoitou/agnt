#!/usr/bin/env python3
"""Phase 8 — Suite de tests autonomes pour le harnais de benchmarking & scoring.

Vérifie le calcul correct des métriques TP, FP, FN, Précision, Rappel, F1-Score,
l'évaluation par cible et la génération des rapports (JSON et Markdown).

Usage : PYTHONPATH=PHASE3/slice:PHASE3/benchmark python3 PHASE3/test_benchmark.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parent
sys.path.insert(0, str(RACINE / "slice"))
sys.path.insert(0, str(RACINE / "benchmark"))

from findings import Finding
import harnais_benchmark as BM

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


def test_evaluer_target_parfait():
    print("=== Test 1: Évaluation cible idéale (100% Precision & Recall) ===")
    expected = [
        {"id": "EXP-1", "file": "requirements.txt", "package": "PyYAML", "cve": "CVE-2020-14343"},
        {"id": "EXP-2", "file": "app.py", "rule_id": "avoid-pyyaml-load"},
    ]
    actual = [
        Finding(
            id="f1",
            source={"tool": "trivy", "original_rule_id": "CVE-2020-14343"},
            identity={"canonical_rule_id": "trivy:CVE-2020-14343", "fingerprint": "fp1"},
            location={"asset": "repository", "file": "requirements.txt", "package": "PyYAML"},
            severity={"value": "HIGH", "origine": "trivy"},
            evidence={},
        ),
        Finding(
            id="f2",
            source={"tool": "semgrep", "original_rule_id": "avoid-pyyaml-load"},
            identity={"canonical_rule_id": "semgrep:avoid-pyyaml-load", "fingerprint": "fp2"},
            location={"asset": "repository", "file": "app.py", "line": 5},
            severity={"value": "MEDIUM", "origine": "semgrep"},
            evidence={},
        ),
    ]

    res = BM.evaluer_target("testrepo", expected, actual)
    cas("1a. TP == 2", res["tp"] == 2)
    cas("1b. FP == 0", res["fp"] == 0)
    cas("1c. FN == 0", res["fn"] == 0)
    cas("1d. Précision == 1.0", res["precision"] == 1.0)
    cas("1e. Recall == 1.0", res["recall"] == 1.0)
    cas("1f. F1 == 1.0", res["f1_score"] == 1.0)


def test_evaluer_target_mixte():
    print("\n=== Test 2: Évaluation avec FP et FN ===")
    expected = [
        {"id": "EXP-1", "file": "requirements.txt", "package": "PyYAML", "cve": "CVE-2020-14343"},
        {"id": "EXP-2", "file": "app.py", "rule_id": "avoid-pyyaml-load"}, # Non trouvé -> FN
    ]
    actual = [
        # Matche EXP-1
        Finding(
            id="f1",
            source={"tool": "trivy", "original_rule_id": "CVE-2020-14343"},
            identity={"canonical_rule_id": "trivy:CVE-2020-14343", "fingerprint": "fp1"},
            location={"asset": "repository", "file": "requirements.txt", "package": "PyYAML"},
            severity={"value": "HIGH", "origine": "trivy"},
            evidence={},
        ),
        # Faux positif (ne matche rien d'attendu)
        Finding(
            id="f3",
            source={"tool": "gitleaks", "original_rule_id": "generic-api-key"},
            identity={"canonical_rule_id": "gitleaks:generic-api-key", "fingerprint": "fp3"},
            location={"asset": "repository", "file": "other.py"},
            severity={"value": "HIGH", "origine": "gitleaks"},
            evidence={},
        ),
    ]

    res = BM.evaluer_target("testrepo_mixte", expected, actual)
    cas("2a. TP == 1", res["tp"] == 1)
    cas("2b. FP == 1", res["fp"] == 1)
    cas("2c. FN == 1", res["fn"] == 1)
    cas("2d. Précision == 0.5", res["precision"] == 0.5)
    cas("2e. Recall == 0.5", res["recall"] == 0.5)
    cas("2f. F1 == 0.5", res["f1_score"] == 0.5)


def test_benchmark_global():
    print("\n=== Test 3: Benchmark global & rapports ===")
    gt = {
        "targets": {
            "t1": {
                "expected_findings": [
                    {"id": "E1", "file": "req.txt", "package": "flask"}
                ]
            }
        }
    }
    results_by_target = {
        "t1": (
            [
                Finding(
                    id="f1",
                    source={"tool": "trivy", "original_rule_id": "CVE-2021-1234"},
                    identity={"canonical_rule_id": "trivy:CVE-2021-1234", "fingerprint": "fp1"},
                    location={"asset": "repository", "file": "req.txt", "package": "flask"},
                    severity={"value": "HIGH", "origine": "trivy"},
                    evidence={},
                )
            ],
            {"trivy": 0.45},
        )
    }

    b_data = BM.executer_benchmark_global(gt, results_by_target)
    cas("3a. Structure du benchmark globale valide", "global_metrics" in b_data)
    cas("3b. Métrique TP globale == 1", b_data["global_metrics"]["tp"] == 1)

    md = BM.generer_markdown_benchmark(b_data)
    cas("3c. Markdown contient le titre principal", "# BENCHMARK_RESULTS" in md)
    cas("3d. Markdown contient le tableau des cibles", "`t1`" in md)

    # Test d'enregistrement
    tmp_dir = RACINE / "artifacts" / "test_benchmark_tmp"
    j_path, md_path = BM.enregistrer_rapports_benchmark(b_data, output_dir=tmp_dir)
    cas("3e. Fichier JSON généré", j_path.exists())
    cas("3f. Fichier Markdown généré", md_path.exists())

    # Nettoyage
    if j_path.exists():
        j_path.unlink()
    if md_path.exists():
        md_path.unlink()
    if tmp_dir.exists():
        tmp_dir.rmdir()


def main() -> int:
    test_evaluer_target_parfait()
    test_evaluer_target_mixte()
    test_benchmark_global()

    print(f"\n==================================================")
    print(f"  {PAS}/{PAS + ECHECS} tests passés · {ECHECS} échec(s)")
    print(f"==================================================")
    return 1 if ECHECS else 0


if __name__ == "__main__":
    sys.exit(main())
