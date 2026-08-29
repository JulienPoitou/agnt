#!/usr/bin/env python3
"""
Applique à l'inventaire les corrections d'URL GitHub VÉRIFIÉES, et trace les non résolues.

Règle : aucune correction n'est écrite sans preuve. Deux méthodes de preuve acceptées,
enregistrées dans la colonne `url_corrigee_par` :
  - `HEAD/GET 200`  : le chemin renvoie HTTP 200 sur github.com
  - `github-search` : trouvé via l'API de recherche GitHub (full_name retourné)

Tout ce qui n'est pas prouvé reste marqué `404-non-resolu` ou `pas-d-url-github`.

Lit   : PHASE1/00_INVENTAIRE.csv
Écrit : PHASE1/00_INVENTAIRE.csv (en place) + PHASE1/04_URL_CORRIGEES.md
"""

from __future__ import annotations

import csv
import re
from pathlib import Path

SRC = Path("PHASE1/00_INVENTAIRE.csv")
REPORT = Path("PHASE1/04_URL_CORRIGEES.md")

# nom de la fiche -> (nouveau owner/repo, méthode de preuve)
CORRECTIONS: dict[str, tuple[str, str]] = {
    "PentestGPT": ("GreyDGL/PentestGPT", "HEAD/GET 200"),
    "TheHive": ("TheHive-Project/TheHive", "HEAD/GET 200"),
    "TypeDB CTI": ("typedb-osi/typedb-cti", "HEAD/GET 200"),
    "SpiderFoot": ("smicallef/spiderfoot", "HEAD/GET 200"),
    "Solo.io AgentGateway": ("agentgateway/agentgateway", "HEAD/GET 200"),
    "Kubernetes Agent Sandbox": ("kubernetes-sigs/agent-sandbox", "HEAD/GET 200"),
    "MCP DFIR identifiés": ("dfir-iris/iris-web", "HEAD/GET 200"),
    "Wazuh": ("wazuh/wazuh", "HEAD/GET 200"),
    "AI-Infra-Guard": ("Tencent/AI-Infra-Guard", "HEAD/GET 200"),
    "MCP Protocol (Anthropic)": ("modelcontextprotocol/modelcontextprotocol", "HEAD/GET 200"),
    "GitHub Security MCP": ("GitHub/github-mcp-server", "HEAD/GET 200"),
    "OpenSOAR": ("opensoar-hq/opensoar-core", "HEAD/GET 200 (redirection)"),
    "Abuse.ch (URLhaus, MalBazaar, ThreatFox)": ("abusech/URLhaus", "github-search"),
}

# Fiches sans URL GitHub, mais dont l'organisation existe : pas un repo unique.
ORG_ONLY = {
    "Burp Suite (Extensions)": "PortSwigger",
    "ProjectDiscovery (Suite)": "projectdiscovery",
    "Caido": "caido",
    "CACAO (OASIS)": "oasis-open",
    "OpenC2": "oasis-open",
}

# Ni repo, ni organisation vérifiable : hors périmètre Phase 1 (traçé, pas supprimé).
HORS_PERIMETRE = {
    "Maltego (CE)": "outil propriétaire, pas de repo public",
    "SOC Prime / Agentic SOC Platforms": "entrée générique, aucun repo nommé",
    "Awesome Cybersecurity Agentic AI": "entrée générique, aucun repo nommé",
    "SOC Knowledge Base": "entrée générique, aucun repo nommé",
    "AI Agent Runtime Security (from topic mcp-security)": "topic GitHub, pas un repo",
    "OWASP LLM Top 10 Vulnerable App": "entrée générique, aucun repo nommé",
    "Dastardly (PortSwigger)": "outil distribué hors GitHub",
    "Autres agents IA identifiés (2e cercle)": "agrégat, pas un repo",
    "MCP servers sécurité divers (petits)": "agrégat, pas un repo",
    "(croisé avec 🔵🟠🟡)": "artefact de mise en forme du fichier source",
    "GPT-Pentest": "chemin kyuupichan/gpt-pentest -> 404, alternative non prouvée",
    "GOSINT": "9b/gosint et variantes -> 404",
    "OSTrICa": "candidats testés -> 404",
    "OpenIOC": "candidats testés -> 404",
    "PickupSTIX": "candidats testés -> 404",
    "Fastfinder": "withsecurelabs/fastfinder -> 404",
    "rkhunter": "rkhunter/rkhunter -> 404 (paquet distribué par les distributions Linux)",
    "Shannon": "candidats testés -> 404",
    "Project CodeGuard": "anthropics/codeguard -> 404",
    "SecPipe / FuzzForge AI": "FuzzingLabs/secpipe -> 404",
    "BearClaw": "bearclaw-ai/bearclaw -> 404",
    "VoidAccess": "VoidAccess/VoidAccess -> 404",
    "SandboxAI": "sandboxai/sandboxai -> 404",
    "Immunity Agent": "immunity-agent/immunity-agent -> 404",
}


def main() -> int:
    if not SRC.exists():
        print(f"ERREUR: {SRC} introuvable")
        return 2

    rows = list(csv.DictReader(SRC.open(encoding="utf-8")))
    for r in rows:
        r.setdefault("url_initiale", r["github"])
        r.setdefault("url_corrigee_par", "")

    appliquees = []
    for r in rows:
        nom = r["nom"].strip()
        if nom in CORRECTIONS:
            new, methode = CORRECTIONS[nom]
            if r["owner_repo"] != new:
                appliquees.append((nom, r["owner_repo"] or r["github"] or "(vide)", new, methode))
            r["owner_repo"] = new
            r["github"] = f"https://github.com/{new}"
            r["url_corrigee_par"] = methode

    org = [r["nom"] for r in rows if r["nom"].strip() in ORG_ONLY]
    hors = [r["nom"] for r in rows if r["nom"].strip() in HORS_PERIMETRE]
    for r in rows:
        if r["nom"].strip() in ORG_ONLY:
            r["url_corrigee_par"] = "organisation GitHub, pas un repo unique"
        elif r["nom"].strip() in HORS_PERIMETRE and not r["owner_repo"]:
            r["url_corrigee_par"] = "hors périmètre Phase 1"

    # --- déduplication APRÈS correction : la première passe (parse_liste) tournait sur les
    # URL d'origine, donc une fiche « org » et sa fiche repo valide restaient séparées.
    def cle(r: dict) -> str:
        if r["owner_repo"]:
            return r["owner_repo"].lower()
        return "nom:" + re.sub(r"[^a-z0-9]", "", r["nom"].lower())

    vus: dict[str, dict] = {}
    dedup: list[str] = []
    for r in rows:
        k = cle(r)
        if k in vus:
            keep = vus[k]
            note = "; ".join(x for x in (keep.get("sections_multiples", ""), r["section"]) if x)
            keep["sections_multiples"] = note
            if (r.get("importance_niveau") or "0") > (keep.get("importance_niveau") or "0"):
                keep["importance"] = r["importance"]
                keep["importance_niveau"] = r["importance_niveau"]
            if r.get("url_corrigee_par") and not keep.get("url_corrigee_par"):
                keep["url_corrigee_par"] = r["url_corrigee_par"]
            dedup.append(f"{r['nom']} -> fusionné avec {keep['nom']} ({k})")
            continue
        vus[k] = r
    rows = list(vus.values())

    fields = list(rows[0].keys())
    if "url_initiale" not in fields:
        fields += ["url_initiale", "url_corrigee_par"]
    with SRC.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)

    lines = [
        "# PHASE 1 — Corrections d'URL GitHub",
        "",
        "Toute correction ci-dessous est **vérifiée**, pas déduite. Les fiches non prouvées",
        "sont laissées en l'état et listées comme telles.",
        "",
        "## Corrections appliquées",
        "",
        "| Fiche | URL d'origine | Corrigée en | Preuve |",
        "|---|---|---|---|",
    ]
    for nom, old, new, methode in appliquees:
        lines.append(f"| {nom} | `{old}` | `{new}` | {methode} |")

    lines += [
        "",
        "## Organisations GitHub (pas un repo unique)",
        "",
        "Ces fiches pointent vers une organisation. Elles ne peuvent pas être notées comme un",
        "repo : à décomposer en repos précis si on veut les utiliser en Phase 2.",
        "",
        "| Fiche | Organisation |",
        "|---|---|",
    ]
    for nom in org:
        lines.append(f"| {nom} | `github.com/{ORG_ONLY[nom]}` |")

    lines += [
        "",
        "## Hors périmètre Phase 1 (traçé, non supprimé)",
        "",
        "| Fiche | Motif |",
        "|---|---|",
    ]
    for nom in hors:
        lines.append(f"| {nom} | {HORS_PERIMETRE[nom]} |")

    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"Corrections appliquées   : {len(appliquees)}")
    print(f"Doublons fusionnés (2e passe) : {len(dedup)}")
    for d in dedup:
        print("   - " + d)
    print(f"Organisations (non repo) : {len(org)}")
    print(f"Hors périmètre           : {len(hors)}")
    print(f"Rapport                  : {REPORT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
