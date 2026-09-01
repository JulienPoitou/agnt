"""Harnais de Benchmarking & Scoring de Sécurité — Étape 8.

Mesure objectivement la précision, le rappel, le F1-Score, le taux de couverture
et la vitesse de détection de la plateforme AGNT sur des cibles référencées.

Formules :
- Précision = TP / (TP + FP)
- Rappel (Recall) = TP / (TP + FN)
- F1-Score = 2 * (Précision * Rappel) / (Précision + Rappel)

Génère les rapports synthétiques au format Markdown (BENCHMARK_RESULTS.md)
et JSON typé (benchmark_results.json).
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import yaml

BENCHMARK_DIR = Path(__file__).resolve().parent
GROUND_TRUTH_PATH = BENCHMARK_DIR / "ground_truth.yaml"


def charger_ground_truth(path: Path | str | None = None) -> dict[str, Any]:
    gt_file = Path(path) if path else GROUND_TRUTH_PATH
    if not gt_file.exists():
        return {"targets": {}}
    return yaml.safe_load(gt_file.read_text(encoding="utf-8")) or {"targets": {}}


def evaluer_target(
    target_name: str,
    expected_findings: list[dict[str, Any]],
    actual_findings: list[dict[str, Any]],
    execution_times: dict[str, float] | None = None,
) -> dict[str, Any]:
    """Évalue les métriques de sécurité (TP, FP, FN, Précision, Rappel, F1) pour une cible donnée."""
    matched_expected = set()
    matched_actual = set()

    for idx_act, actual in enumerate(actual_findings):
        d_act = actual.to_dict() if hasattr(actual, "to_dict") else dict(actual or {})
        src = d_act.get("source") or {}
        loc = d_act.get("location") or {}
        ev = d_act.get("evidence") or {}

        act_file = (loc.get("file") or "").lower()
        act_pkg = (loc.get("package") or "").lower()
        act_cve = (src.get("original_rule_id") or src.get("canonical_rule_id") or "").lower()
        act_rule = (src.get("original_rule_id") or src.get("canonical_rule_id") or "").lower()

        for idx_exp, exp in enumerate(expected_findings):
            exp_file = (exp.get("file") or "").lower()
            exp_pkg = (exp.get("package") or "").lower()
            exp_cve = (exp.get("cve") or "").lower()
            exp_rule = (exp.get("rule_id") or "").lower()

            match_file = not exp_file or exp_file in act_file or act_file in exp_file
            match_pkg = not exp_pkg or exp_pkg == act_pkg
            match_cve = not exp_cve or exp_cve in act_cve
            match_rule = not exp_rule or exp_rule in act_rule

            if match_file and match_pkg and match_cve and match_rule:
                matched_expected.add(idx_exp)
                matched_actual.add(idx_act)

    tp = len(matched_expected)
    fn = len(expected_findings) - tp
    fp = len(actual_findings) - len(matched_actual)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

    return {
        "target": target_name,
        "expected_count": len(expected_findings),
        "actual_count": len(actual_findings),
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "execution_times": execution_times or {},
    }


def executer_benchmark_global(
    ground_truth: dict[str, Any] | None = None,
    results_by_target: dict[str, tuple[list[dict], dict[str, float]]] | None = None,
) -> dict[str, Any]:
    """Exécute l'évaluation globale sur toutes les cibles et génère le rapport typé."""
    gt = ground_truth or charger_ground_truth()
    targets_gt = gt.get("targets") or {}

    evals = []
    total_tp = 0
    total_fp = 0
    total_fn = 0
    total_times: dict[str, float] = {}

    for target_name, gt_data in targets_gt.items():
        expected = gt_data.get("expected_findings") or []
        actual, times = results_by_target.get(target_name, ([], {})) if results_by_target else ([], {})

        res_eval = evaluer_target(target_name, expected, actual, times)
        evals.append(res_eval)

        total_tp += res_eval["tp"]
        total_fp += res_eval["fp"]
        total_fn += res_eval["fn"]

        for k, t_val in (times or {}).items():
            total_times[k] = total_times.get(k, 0.0) + t_val

    global_precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0
    global_recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0.0
    global_f1 = (2 * global_precision * global_recall) / (global_precision + global_recall) if (global_precision + global_recall) > 0 else 0.0

    benchmark_data = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "global_metrics": {
            "tp": total_tp,
            "fp": total_fp,
            "fn": total_fn,
            "precision": round(global_precision, 4),
            "recall": round(global_recall, 4),
            "f1_score": round(global_f1, 4),
        },
        "execution_times": {k: round(v, 4) for k, v in total_times.items()},
        "targets_evaluations": evals,
    }

    return benchmark_data


def generer_markdown_benchmark(data: dict[str, Any]) -> str:
    """Génère le contenu Markdown synthétique du benchmark (BENCHMARK_RESULTS.md)."""
    gm = data.get("global_metrics") or {}
    times = data.get("execution_times") or {}
    evals = data.get("targets_evaluations") or []

    lines = []
    lines.append("# BENCHMARK_RESULTS — Harnais de Scoring de Sécurité AGNT")
    lines.append("")
    lines.append(f"_Généré automatiquement le {data.get('timestamp', 'UTC')}_")
    lines.append("")
    lines.append("## 1. Métriques Globales de Sécurité")
    lines.append("")
    lines.append("| Métrique | Valeur | Description |")
    lines.append("|---|---|---|")
    lines.append(f"| **Vrais Positifs (TP)** | {gm.get('tp', 0)} | Vulnérabilités attendues correctement détectées |")
    lines.append(f"| **Faux Positifs (FP)** | {gm.get('fp', 0)} | Alertes surélevées hors Vérité Terrain |")
    lines.append(f"| **Faux Négatifs (FN)** | {gm.get('fn', 0)} | Vulnérabilités attendues non détectées |")
    lines.append(f"| **Précision** | **{gm.get('precision', 0.0):.2%}** | $TP / (TP + FP)$ |")
    lines.append(f"| **Rappel (Recall)** | **{gm.get('recall', 0.0):.2%}** | $TP / (TP + FN)$ |")
    lines.append(f"| **F1-Score** | **{gm.get('f1_score', 0.0):.4f}** | $2 \\cdot (P \\cdot R) / (P + R)$ |")
    lines.append("")

    lines.append("## 2. Résultats par Cible de Benchmark")
    lines.append("")
    lines.append("| Cible | Attendus | Trouvés | TP | FP | FN | Précision | Rappel | F1-Score |")
    lines.append("|---|---|---|---|---|---|---|---|---|")
    for ev in evals:
        lines.append(
            f"| `{ev.get('target')}` | {ev.get('expected_count')} | {ev.get('actual_count')} | "
            f"{ev.get('tp')} | {ev.get('fp')} | {ev.get('fn')} | "
            f"{ev.get('precision', 0.0):.2%} | {ev.get('recall', 0.0):.2%} | {ev.get('f1_score', 0.0):.4f} |"
        )
    lines.append("")

    if times:
        lines.append("## 3. Temps d'Exécution par Outil / Capacité")
        lines.append("")
        lines.append("| Outil / Capacité | Temps d'exécution (s) |")
        lines.append("|---|---|")
        for tool_name, t_val in times.items():
            lines.append(f"| `{tool_name}` | {t_val:.4f} s |")
        lines.append("")

    return "\n".join(lines)


def enregistrer_rapports_benchmark(
    data: dict[str, Any],
    output_dir: Path | str | None = None,
) -> tuple[Path, Path]:
    """Enregistre les résultats BENCHMARK_RESULTS.md et benchmark_results.json."""
    out_dir = Path(output_dir) if output_dir else BENCHMARK_DIR
    out_dir.mkdir(parents=True, exist_ok=True)

    json_path = out_dir / "benchmark_results.json"
    md_path = out_dir / "BENCHMARK_RESULTS.md"

    json_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    md_path.write_text(generer_markdown_benchmark(data), encoding="utf-8")

    return json_path, md_path
