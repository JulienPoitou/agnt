"""Parser dalfox — JSONL stdout (mode -S), findings seulement.

dalfox 3.2.2 (mode `url -f jsonl -S`) écrit sur stdout : une PREMIÈRE ligne
méta {findings_count, targets, total_requests…} puis UNE ligne JSON par
finding {type, param, payload, data, severity, confidence, cwe,
message_str…} (mesuré). La ligne méta ne doit jamais devenir un item : seules
les lignes portant type+param sont des findings. La sévérité (« High » mesuré
sur le constat V) et le CWE-79 sont DÉCLARÉS par l'outil : ils sont portés
tels quels, jamais traduits ni extrapolés. Les types R (reflet simple) / A
(AST DOM) / I (informationnel) existent dans l'outil — ils seraient portés
tels quels, un reflet simple n'étant pas une XSS prouvée.
"""
from __future__ import annotations

import json

from parsers import enregistrer


@enregistrer("dalfox")
def parser_dalfox(stdout: str) -> list[dict]:
    items: list[dict] = []
    for brut in (stdout or "").splitlines():
        ligne = brut.strip()
        if not ligne.startswith("{"):
            continue
        try:
            obj = json.loads(ligne)
        except ValueError:
            continue
        if not isinstance(obj, dict) or "type" not in obj or "param" not in obj:
            continue                                    # ligne méta ou inattendue
        items.append({
            "regle": str(obj.get("type") or ""),
            "nom_regle": str(obj.get("param") or ""),
            "message": str(obj.get("message_str") or ""),
            "url": str(obj.get("data") or ""),
            "severite": str(obj.get("severity") or ""),
            "confiance": str(obj.get("confidence") or ""),
            "cwe": str(obj.get("cwe") or ""),
            "preuve": str(obj.get("payload") or ""),
            "injection": str(obj.get("inject_type") or ""),
            "position": str(obj.get("location") or ""),
        })
    return items
