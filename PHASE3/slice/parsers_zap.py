"""Parser spécifique — document JSON « traditional » d'OWASP ZAP baseline scan.

SECOND NIVEAU de la promesse (voir `parsers_bandit.py`, `parsers_hadolint.py`) : le
rapport `-J` de zap-baseline est un format propriétaire de l'outil — un parser nommé le
lit, le cœur ne connaît ni ZAP ni son schéma.

Forme attendue (structure publiée du « ZAP traditional JSON report », celle que le script
`zap-baseline.py` rend par `-J report_json`, donc `zap.core.jsonreport()` ou le job
Automation Framework `traditional-json`) :

    {"@programName": "OWASP ZAP", "@version": "2.17.0",
     "site": [{"@name": "https://exemple/", "@host": "exemple",
               "alerts": [{"pluginid": "10202", "alert": "Absence de CSP…",
                           "riskcode": "2", "riskdesc": "Medium (High)",
                           "confidence": "3", "confidencedesc": "High",
                           "desc": "<p>…</p>", "solution": "…", "reference": "…",
                           "cweid": "693",
                           "instances": [{"uri": "https://…", "evidence": "…",
                                          "messageId": "7"}], …}]}]}

Trois règles de justesse, dans l'ordre d'importance :

  · UN item par INSTANCE, pas par alerte. Une alerte ZAP regroupe N URL touchées ; en
    faire un seul finding perdrait la localisation (quelle URL ?) et l'empreinte
    unique par URL que la corrélation inter-outils exige. Une alerte sans instance
    (constat global, ex. « Cloud metadata ») devient UN finding sur le site lui-même.
  · Les sévérités viennent des MOTS de l'outil (`riskdesc`, prefixé « Risque
    (Confiance) » par ZAP lui-même), et le repli sur les codes `riskcode` est la
    traduction PUBLIÉE de l'énumération de ZAP (0=Informationnel … 3=Élevé), pas une
    échelle inventée ici.
  · `parse` ne lève jamais : une entrée vide ou corrompue rend [] et le cœur écrira
    « sortie illisible », pas une mission interrompue sur un rapport tronqué.
"""

from __future__ import annotations

import json
import re

from parsers import enregistrer

# Traductions PUBLIÉES de l'énumération ZAP (documentation des champs du rapport et
# `zap-baseline.py`, vérifiées sur la version épinglée v2.17.0). Elles ne servent que
# quand `riskdesc`/`confidencedesc` sont absents du document — l'outil est toujours
# premier.
_RISQUES = {"0": "Information", "1": "Low", "2": "Medium", "3": "High"}
_CONFIANCES = {"0": "Tentative", "1": "Low", "2": "Medium", "3": "High",
               "4": "Confirmed"}

_TAG = re.compile(r"<[^>]+>")
_ESPACES = re.compile(r"\s+")


def _texte_brut(valeur, limite: int) -> str | None:
    """Le texte de l'outil, allégé de son balisage HTML et coupé — pas réécrit."""
    if not valeur:
        return None
    t = _TAG.sub(" ", str(valeur))
    t = _ESPACES.sub(" ", t).strip()
    if not t:
        return None
    return t[:limite] + "…" if len(t) > limite else t


def _liste(v):
    if v is None:
        return []
    return [v] if isinstance(v, dict) else (v if isinstance(v, list) else [])


@enregistrer("zap_baseline")
def parse(texte: str) -> list[dict]:
    if not texte or not texte.strip():
        return []
    try:
        doc = json.loads(texte)
    except Exception:
        return []
    if not isinstance(doc, dict):
        return []
    sites = _liste(doc.get("site"))
    if not sites:
        return []
    items: list[dict] = []
    for site in sites:
        if not isinstance(site, dict):
            continue
        site_url = str(site.get("@name") or site.get("@host") or "").strip()
        for a in _liste(site.get("alerts")):
            if not isinstance(a, dict):
                continue
            plugin = str(a.get("pluginid") or "").strip()
            titre = str(a.get("alert") or a.get("name") or "").strip()
            regle = (f"ZAP-{plugin}" if plugin
                     else (titre[:60] if titre else "ZAP-inconnu"))
            # Le mot de l'outil d'abord ; le code traduit ensuite. `riskdesc` est
            # formaté « Risque (Confiance) » par ZAP : le libellé est avant la parenthèse.
            sev = str(a.get("riskdesc") or "").split(" (")[0].strip()
            if not sev:
                sev = _RISQUES.get(str(a.get("riskcode") or "").strip(), "") or None
            conf = str(a.get("confidencedesc") or "").split(" (")[0].strip()
            if not conf:
                conf = _CONFIANCES.get(str(a.get("confidence") or "").strip(), "") or None
            cwe = str(a.get("cweid") or "").strip()
            cwe = f"CWE-{cwe}" if cwe and cwe not in ("0", "None") else None
            refs = [r.strip() for r in _TAG.sub(" ", str(a.get("reference") or "")).splitlines()
                    if r.strip()][:8] or None
            solution = _texte_brut(a.get("solution"), 400)
            message = _texte_brut(a.get("desc"), 600) or (titre or None)
            instances = _liste(a.get("instances")) or [None]
            for inst in instances:
                if inst is None:
                    url, preuve, msg_id = site_url or None, None, None
                elif isinstance(inst, dict):
                    url = str(inst.get("uri") or site_url or "").strip() or None
                    preuve = _texte_brut(inst.get("evidence"), 200)
                    msg_id = (str(inst.get("messageId") or inst.get("id") or "").strip()
                              or None)
                else:
                    continue
                item = {
                    "regle": regle,
                    "nom_regle": titre or None,
                    "url": url,
                    "severite": sev,
                    "confiance": conf,
                    "cwe": cwe,
                    "message": message,
                    "remediation": solution,
                    "reference": refs,
                    "preuve": preuve,
                    # L'identifiant du constat CHEZ L'OUTIL : numéro d'alerte (+ id du
                    # message d'instance s'il existe) — la trace pour retrouver la ligne
                    # exacte dans le rapport brut conservé.
                    "source_id": (f"{plugin}@{msg_id}" if plugin and msg_id
                                  else (plugin or None)),
                    "count": str(a.get("count") or "").strip() or None,
                }
                items.append({k: v for k, v in item.items() if v is not None})
    return items
