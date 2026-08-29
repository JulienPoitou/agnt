#!/usr/bin/env python3
"""Reconstruction du catalogue d'intégration.

Répond à : « parmi les 324 dépôts, lesquels sont réellement destinés à devenir des
providers exécutables ? »

RÔLES

    provider     outil exécutable qui produit des findings
    composant    brique de notre plateforme (policy, sandbox, gateway, registre)
    reference    architecture à imiter, rien à exécuter ni à importer
    concurrent   plateforme ou agent qui fait le même travail que nous
    lib          bibliothèque, pas un outil
    doc          liste, tutoriel, spécification : rien à exécuter
    inutile      hors périmètre

AVERTISSEMENT HONNÊTE

Classification AUTOMATIQUE par mots-clés. Elle n'est pas fiable à 100 %. Elle sert à
réduire 324 dépôts à un ensemble examinable, pas à décider. Chaque ligne marquée
`provider` doit être vérifiée à la main avant intégration.

Aucun code n'est écrit ici. Ce script produit un catalogue, rien d'autre.
"""

from __future__ import annotations

import csv
from collections import defaultdict
from pathlib import Path

RACINE = Path(__file__).resolve().parent
INVENTAIRE = RACINE / "00_INVENTAIRE_ENRICHI.csv"
GRILLE = RACINE / "01_GRILLE_TRI.csv"
SORTIE = RACINE / "07_CATALOGUE_INTEGRATION.csv"

CAPACITES = [
    ("CODE_STATIC_ANALYSIS", "analyse statique du code",
     ("sast", "static analysis", "code analysis", "semgrep", "bandit", "linter",
      "code scanning", "codeql", "sonar")),
    ("SECRET_DETECTION", "détection de secrets et credentials",
     ("secret", "credential", "gitleaks", "trufflehog", "detect-secrets", "api key")),
    ("DEPENDENCY_ANALYSIS", "vulnérabilités des dépendances",
     ("dependency", "dependencies", "sca", "sbom", "grype", "syft", "dependabot",
      "dependency-track", "supply chain")),
    ("CONTAINER_SCAN", "analyse d'images et de conteneurs",
     ("container", "docker image", "image scan", "trivy", "dockerfile")),
    ("CLOUD_POSTURE", "posture de sécurité cloud",
     ("cloud", "aws", "azure", "gcp", "kubernetes", "k8s", "prowler", "kubescape",
      "cis benchmark")),
    ("IAC_SCAN", "analyse d'infrastructure as code",
     ("terraform", "iac", "infrastructure as code", "checkov", "tfsec", "cloudformation")),
    ("NETWORK_DISCOVERY", "découverte réseau et de services",
     ("nmap", "port scan", "network scan", "network discovery", "masscan")),
    ("WEB_ENDPOINT_DISCOVERY", "découverte d'endpoints web",
     ("endpoint discovery", "crawler", "katana", "ffuf", "gau", "dirsearch", "spider")),
    ("WEB_VULN_SCAN", "scan de vulnérabilités web",
     ("dast", "web scan", "web vulnerability", "nuclei", "nikto", "zap")),
    ("EXPLOITATION", "exploitation et preuves de concept",
     ("exploit", "metasploit", "exploit framework", "payload")),
    ("ENDPOINT_COLLECTION", "collecte et visibilité sur les endpoints",
     ("endpoint", "osquery", "velociraptor", "host visibility", "edr")),
    ("LOG_ANALYSIS", "analyse de journaux",
     ("log analysis", "siem", "log management", "zeek", "suricata", "syslog")),
    ("THREAT_INTEL", "renseignement sur les menaces",
     ("threat intel", "osint", "misp", "opencti", "ioc", "threat feed", "intelowl")),
    ("MALWARE_ANALYSIS", "analyse de logiciels malveillants",
     ("malware", "cuckoo", "yara", "detonation", "cape")),
    ("DETECTION_RULES", "règles de détection",
     ("sigma", "detection rule", "yara rule", "detection engineering")),
    ("VULN_MANAGEMENT", "gestion du cycle de vie des vulnérabilités",
     ("vulnerability management", "defectdojo", "faraday", "vuln tracker")),
    ("INCIDENT_RESPONSE", "réponse à incident",
     ("incident response", "dfir", "case management", "thehive")),
    ("SECRETS_MANAGEMENT", "gestion des secrets d'exécution",
     ("vault", "secrets management", "secret store", "key management")),
    ("POLICY_ENFORCEMENT", "application de politiques",
     ("policy", "opa", "rego", "admission control", "kyverno")),
    ("SANDBOX_EXECUTION", "exécution isolée",
     ("sandbox", "isolation", "gvisor", "firecracker", "kata", "nsjail")),
]

MOTS_CONCURRENT = (
    "ai agent", "ai security agent", "autonomous", "ai pentest", "ai hacker",
    "agentic", "llm agent", "copilot", "assistant", "ai-powered", "ai powered",
    "multi-agent", "agent framework", "ai security platform",
)
MOTS_COMPOSANT = (
    "policy", "opa", "rego", "sandbox", "isolation", "gvisor", "firecracker",
    "gateway", "proxy", "registry", "broker", "queue", "workflow engine",
    "orchestration engine", "vault", "secret management", "key management",
    "mcp gateway", "mcp proxy", "mcp registry", "mcp aggregator", "runtime",
    "scheduler", "message queue", "observability", "tracing",
)
MOTS_REFERENCE = (
    "awesome", "list of", "curated", "tutorial", "guide", "cheatsheet",
    "cheat sheet", "best practices", "methodology", "framework documentation",
    "specification", "standard", "schema", "reference implementation",
    "benchmark", "dataset", "wordlist", "payload collection", "rules collection",
)
MOTS_PROVIDER = (
    "scanner", "scan", "detector", "detect", "analyzer", "analyse", "analyze",
    "crawler", "spider", "fuzzer", "fuzz", "exploit", "brute", "enumeration",
    "recon", "discovery", "monitor", "collector", "probe", "sensor",
    "checker", "auditor", "audit", "linter", "sast", "dast", "sca",
)
MOTS_LIB = (
    "library", "sdk", "client", "bindings", "wrapper", "package", "module",
    "toolkit", "utilities", "helpers",
)


def classifier(ligne: dict) -> tuple[str, str]:
    blob = " ".join([ligne.get("section", ""), ligne.get("categorie", ""),
                     ligne.get("description", ""), ligne.get("nom", "")]).lower()
    section = ligne.get("section", "").lower()

    if any(m in blob for m in MOTS_REFERENCE):
        return "doc", "liste, tutoriel ou spécification"
    if "ai security agent" in section or any(m in blob for m in MOTS_CONCURRENT):
        return "concurrent", "agent ou plateforme qui fait le même travail que nous"
    if any(m in blob for m in MOTS_COMPOSANT):
        return "composant", "brique de plateforme (policy, sandbox, gateway, registre)"
    if "mcp" in section or "mcp" in blob:
        return "provider", "serveur ou agrégateur MCP"
    if any(m in blob for m in MOTS_PROVIDER):
        return "provider", "outil qui produit des résultats exploitables"
    if any(m in blob for m in MOTS_LIB):
        return "lib", "bibliothèque, pas un outil exécutable"
    return "inutile", "aucun rôle identifié pour notre projet"


def capacites_de(ligne: dict) -> list[str]:
    blob = " ".join([ligne.get("categorie", ""), ligne.get("description", ""),
                     ligne.get("nom", "")]).lower()
    return [c for c, _l, mots in CAPACITES if any(m in blob for m in mots)]


def forme_execution(ligne: dict) -> str:
    blob = " ".join([ligne.get("categorie", ""), ligne.get("description", ""),
                     ligne.get("nom", "")]).lower()
    if "mcp" in blob:
        return "mcp_server"
    if any(m in blob for m in ("api", "rest", "server", "service", "daemon")):
        return "api"
    return "cli"


def main() -> int:
    if not INVENTAIRE.exists():
        print(f"inventaire absent : {INVENTAIRE}")
        return 1

    lignes = list(csv.DictReader(INVENTAIRE.open(encoding="utf-8")))
    grille = {}
    if GRILLE.exists():
        for g in csv.DictReader(GRILLE.open(encoding="utf-8")):
            grille[g["owner_repo"]] = g

    out, par_role, par_capacite = [], defaultdict(list), defaultdict(list)

    for ligne in lignes:
        role, pourquoi = classifier(ligne)
        caps = capacites_de(ligne) if role == "provider" else []
        forme = forme_execution(ligne) if role == "provider" else ""
        g = grille.get(ligne["owner_repo"], {})
        out.append({
            "owner_repo": ligne["owner_repo"],
            "nom": ligne["nom"],
            "role": role,
            "pourquoi": pourquoi,
            "capacites": " | ".join(caps),
            "forme_execution": forme,
            "etoiles": ligne.get("stars", ""),
            "dernier_commit": ligne.get("dernier_commit", ""),
            "licence": ligne.get("licence", ""),
            "archive": ligne.get("archived", ""),
            "verdict_phase1": g.get("verdict", ""),
            "verifiable": "oui" if ligne.get("etat") == "ok" else "non",
        })
        par_role[role].append(ligne["owner_repo"])
        for c in caps:
            par_capacite[c].append(ligne["owner_repo"])

    with SORTIE.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(out[0].keys()))
        w.writeheader()
        w.writerows(out)

    print(f"{len(lignes)} dépôts classés -> {SORTIE}\n")
    print("=== PAR RÔLE ===")
    for role in ("provider", "composant", "reference", "concurrent", "lib", "doc", "inutile"):
        print(f"  {len(par_role[role]):>4}  {role}")
    print(f"  {len(out):>4}  TOTAL")

    print("\n=== CAPACITÉS ET PROVIDERS CANDIDATS ===")
    for cap_id, libelle, _ in CAPACITES:
        n = len(par_capacite.get(cap_id, []))
        print(f"  {'  ' if n else '!!'} {n:>3}  {cap_id:<26} {libelle}")

    sans = [r for r in out if r["role"] == "provider" and not r["capacites"]]
    print(f"\n  {len(sans)} providers candidats sans capacité identifiée")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

