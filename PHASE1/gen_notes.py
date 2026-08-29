#!/usr/bin/env python3
"""
Génère PHASE1/NOTES.csv : le jugement (C1/C2/C3 + motif) sur les repos de la shortlist.

Les notes viennent de la lecture effective du README et de l'arborescence de chaque repo
(profils dans PHASE1/.profils/). Elles sont assumées comme un jugement d'architecture,
pas comme une mesure : c'est pour ça qu'elles vivent dans un fichier séparé de
l'inventaire enrichi, qui lui ne contient que des faits régénérables.

Barème : PHASE1/CRITERES.md  (C1 archi 50 %, C2 code 30 %, C3 couverture 20 %)
"""

from __future__ import annotations

import csv
import sys
from pathlib import Path

DEST = Path("PHASE1/NOTES.csv")

# usage prévu + mode d'intégration, par repo (CRITERES.md §4).
# Sans ces deux champs, un verdict INTEGRATE est ambigu : on ne sait pas si on exécute
# l'outil ou si on importe son code — et la gate G2 ne peut pas être appliquée à bon escient.
USAGE = {
    "aquasecurity/trivy": ("outil externe", "CLI"),
    "projectdiscovery/nuclei": ("outil externe", "CLI"),
    "stacklok/toolhive": ("composant d'infrastructure", "conteneur"),
    "DefectDojo/django-DefectDojo": ("référence architecturale", "lecture"),
    "usestrix/strix": ("référence architecturale", "lecture"),
    "open-policy-agent/opa": ("composant d'infrastructure", "HTTP sidecar"),
    "PurpleAILAB/Decepticon": ("référence architecturale", "lecture"),
    "secureCodeBox/secureCodeBox": ("référence architecturale", "lecture"),
    "Ed1s0nZ/CyberStrikeAI": ("référence architecturale", "lecture"),
    "vxcontrol/pentagi": ("référence architecturale", "lecture"),
    "StackStorm/st2": ("référence architecturale", "lecture"),
    "microsoft/agent-governance-toolkit": ("code réutilisable", "à confirmer"),
    "google/gvisor": ("composant d'infrastructure", "conteneur"),
    "jlowin/fastmcp": ("code réutilisable", "SDK"),
    "temporalio/temporal": ("composant d'infrastructure", "API"),
    "DependencyTrack/dependency-track": ("référence architecturale", "lecture"),
    "Tencent/AI-Infra-Guard": ("référence architecturale", "lecture"),
    "falcosecurity/falco": ("référence architecturale", "lecture"),
    "prowler-cloud/prowler": ("outil externe", "CLI"),
    "TracecatHQ/tracecat": ("référence architecturale", "lecture"),
    "velocidex/velociraptor": ("outil externe", "API"),
    "TheHive-Project/Cortex": ("outil externe", "API"),
    "semgrep/semgrep": ("outil externe", "CLI"),
    "aliasrobotics/cai": ("référence architecturale", "lecture"),
    "KeygraphHQ/shannon": ("référence architecturale", "lecture"),
    "infobyte/faraday": ("référence architecturale", "lecture"),
    "intelowlproject/IntelOwl": ("référence architecturale", "lecture"),
    "modelcontextprotocol/registry": ("code réutilisable", "API"),
    "TheHive-Project/TheHive": ("référence architecturale", "lecture"),
    "cuckoosandbox/cuckoo": ("référence architecturale", "lecture"),
    "IBM/mcp-context-forge": ("composant d'infrastructure", "API"),
    "agentgateway/agentgateway": ("composant d'infrastructure", "conteneur"),
    "agentic-community/mcp-gateway-registry": ("composant d'infrastructure", "API"),
    "cisco-ai-defense/mcp-scanner": ("outil externe", "CLI"),
    "samugit83/redamon": ("référence architecturale", "lecture"),
    "langchain-ai/langgraph": ("code réutilisable", "SDK"),
    "invariantlabs-ai/mcp-scan": ("outil externe", "CLI"),
    "mcpjungle/MCPJungle": ("composant d'infrastructure", "API"),
    "GH05TCREW/pentestagent": ("référence architecturale", "lecture"),
    "GreyDGL/PentestGPT": ("référence architecturale", "lecture"),
    "metatool-ai/metamcp": ("référence architecturale", "lecture"),
    "0x4m4/hexstrike-ai": ("référence architecturale", "lecture"),
    "nsacyber/WALKOFF": ("référence architecturale", "lecture"),
}

# owner_repo, C1, C2, C3, motif
NOTES = [
    # ---------------- Q5 + Q1 : agents IA cyber end-to-end ----------------
    ("usestrix/strix", 5, 4, 5,
     "Arbo propre (strix/ skills/ containers/ benchmarks/), orchestration multi-agents, "
     "validation d'exploit réelle. Le plus proche de notre cible côté agent."),
    ("vxcontrol/pentagi", 5, 3, 5,
     "Backend/frontend séparés, sandbox Docker, observabilité Langfuse, graphe Graphiti, "
     "multi-LLM, multi-tenant. Go + EULA à côté de la LICENSE : à lire avant ADAPT."),
    ("KeygraphHQ/shannon", 4, 3, 4,
     "Monorepo pnpm (apps/ repos/ workspaces/), llms.txt pour consommation par IA, section "
     "'Safety, Scope and Limitations'. AGPL-3.0 -> G2."),
    ("PurpleAILAB/Decepticon", 5, 4, 4,
     "SPEC.md + TELEMETRY.md + CONTRIBUTING_AGENT.md, LangGraph, LiteLLM, Neo4j, sandbox, "
     "spécialistes démarrés à la demande. La doc d'archi la plus aboutie du lot."),
    ("aliasrobotics/cai", 5, 2, 4,
     "ARCHIVÉ (août 2026) mais 18 papiers et 30+ CVE : artefact de recherche. À étudier pour "
     "l'architecture, jamais pour le code. G5."),
    ("GreyDGL/PentestGPT", 3, 3, 3,
     "Migration legacy -> unified_agent documentée par des rapports de migration. Intéressant "
     "pour la trajectoire, pas comme architecture de référence."),
    ("Ed1s0nZ/CyberStrikeAI", 5, 3, 5,
     "agents/ skills/ plugins/ mcp-servers/ knowledge_base/ roles/ : découpage par rôle et par "
     "capacité. Se revendique 'intent becomes governed execution' = notre fil conducteur."),
    ("Tencent/AI-Infra-Guard", 4, 4, 4,
     "agent-scan/ mcp-scan/ skill-scan/ skills/ : trois surfaces d'analyse distinctes. Bon modèle "
     "de séparation des scanners."),
    ("0x4m4/hexstrike-ai", 2, 3, 4,
     "Deux fichiers Python. Le 'decision engine' et les 12 agents sont dans un monolithe : aucune "
     "architecture à reprendre, mais le catalogue d'outils MCP est utile."),
    ("samugit83/redamon", 4, 3, 4,
     "recon_orchestrator/ + graph_db/ + skills/ + boucle triage -> fix -> PR. La boucle DETECT -> "
     "FIX -> VERIFY de notre Phase 11 existe déjà ici."),
    ("GH05TCREW/pentestagent", 3, 3, 3,
     "Petit, Docker/Kali, mcp_examples. Utile comme exemple minimal, pas comme référence."),

    # ---------------- Q5 : moteurs d'orchestration ----------------
    ("TracecatHQ/tracecat", 5, 4, 4,
     "Sandboxé par défaut via nsjail, exécution sur Temporal, automations code-native. La réponse "
     "la plus complète à 'comment exécuter du code tiers sans se tirer une balle'. AGPL -> G2."),
    ("StackStorm/st2", 5, 4, 3,
     "st2api/st2reactor/st2actions/st2auth/st2stream/st2common : séparation capteurs/règles/actions "
     "éprouvée depuis 10 ans. Le modèle 'pack' = notre capability registry, version mature."),
    ("TheHive-Project/Cortex", 5, 3, 3,
     "Le modèle analyzer/job est l'abstraction capability -> provider la plus littérale qui existe, "
     "avec flavors. Scala, AGPL -> G2. À lire pour le modèle, pas pour le code."),
    ("nsacyber/WALKOFF", 3, 2, 2,
     "ARCHIVÉ et dernier commit 2020. app_sdk/ montre un modèle d'app packagée ; le reste a vieilli. "
     "G1 + G5."),
    ("temporalio/temporal", 5, 4, 2,
     "Exécution durable, rejeu déterministe. Ne couvre rien en sécurité mais résout le problème "
     "d'orchestration longue durée mieux que tout le reste."),
    ("langchain-ai/langgraph", 4, 4, 2,
     "Graphe d'états pour agents. Infrastructure de planner possible, aucun contenu sécurité."),

    # ---------------- Q1 : registre / abstraction d'outils ----------------
    ("projectdiscovery/nuclei", 5, 5, 5,
     "DESIGN.md au dépôt, séparation cmd/internal/pkg/lib, template YAML = déclaration de capacité. "
     "Le meilleur exemple de 'l'outil est décrit par données, pas par code'."),
    ("jlowin/fastmcp", 4, 5, 3,
     "SDK Python MCP ergonomique, fastmcp_slim/ vs fastmcp_remote/, tâches. Bonne base pour écrire "
     "nos adaptateurs d'outils."),
    ("modelcontextprotocol/registry", 4, 4, 2,
     "Go, cmd/internal/pkg, API gelée en v0.1 + docs/design/ecosystem-vision.md. La référence pour "
     "la forme d'un registre, pas pour le contenu sécurité."),
    ("IBM/mcp-context-forge", 4, 4, 3,
     "Gateway MCP complète : plugins/, mcpgateway/, supply-chain/, charts/, ansible/. Très riche, "
     "mais la surface est énorme : risque de sur-ingénierie pour notre Phase 3."),
    ("agentic-community/mcp-gateway-registry", 4, 4, 3,
     "registry/ + gateway/ + auth_server/, et surtout docs/design/theory-of-the-system.md qui "
     "explique comment modifier le système sans casser sa théorie. Document rare et précieux."),
    ("metatool-ai/metamcp", 3, 3, 3,
     "Agrégateur/orchestrateur/gateway MCP tout-en-un. Utile comme contre-exemple de périmètre "
     "trop large."),
    ("MCPJungle/MCPJungle", 3, 4, 2,
     "Go, cmd/internal/pkg, un endpoint pour tous les MCP. Propre mais commodité."),

    # ---------------- Q2 : policy / gouvernance ----------------
    ("open-policy-agent/opa", 5, 5, 3,
     "Policy-as-code, CNCF graduated, sdk/ + server/ + topdown/ + bundle. La brique déterministe "
     "de notre POLICY ENGINE existe déjà : l'intégrer plutôt que l'écrire."),
    ("microsoft/agent-governance-toolkit", 5, 4, 3,
     "policy-engine/ + schemas/ + benchmarks/prompt-injection, porté sur 7 langages. Spécifications "
     "de gouvernance d'agent : exactement notre chapitre 'AI != security boundary'."),
    ("agentgateway/agentgateway", 4, 4, 3,
     "Rust + Go, dossiers architecture/ et design/, fuzz/. Gateway agent sous charter LF. Bon "
     "modèle de point de contrôle unique entre l'IA et les outils."),
    ("stacklok/toolhive", 5, 5, 4,
     "Chaque serveur MCP dans un conteneur isolé, containers/egress-proxy/, politique par requête, "
     "pkg/ + cmd/ Go propres. La réponse la plus directe à notre Phase 7."),
    ("invariantlabs-ai/mcp-scan", 3, 4, 2,
     "Scanner d'agents/MCP/skills pour prompt injection. Output CLI explicitement instable : "
     "à consommer avec précaution, pas à intégrer."),
    ("cisco-ai-defense/mcp-scanner", 4, 4, 3,
     "Trois moteurs (Yara, LLM, Cisco AI Defense) utilisables ensemble ou seuls, plus pip-audit. "
     "Le pattern 'plusieurs providers derrière une capacité', appliqué au scanning."),

    # ---------------- Q4 : findings / normalisation ----------------
    ("DefectDojo/django-DefectDojo", 5, 4, 5,
     "Des dizaines de parsers d'import, modèle produit/engagement/test/finding, BSD-3. La référence "
     "du modèle de findings unifié ; notre Phase 8 doit s'y aligner plutôt qu'inventer."),
    ("infobyte/faraday", 4, 3, 4,
     "architecture.md au dépôt, corrélation et travail collaboratif sur findings. GPL-3.0 -> G2."),
    ("aquasecurity/trivy", 5, 5, 5,
     "Scanners x cibles en matrice, sortie SARIF/CycloneDX native, pkg/ + rpc/. Le meilleur exemple "
     "de séparation 'ce qu'on cherche' / 'où on le cherche'."),
    ("secureCodeBox/secureCodeBox", 5, 4, 4,
     "operator/ + scanners/ + parser-sdk/ + hook-sdk/ + lurker/ : scanner comme CRD Kubernetes, "
     "parser et hooks comme SDK. L'architecture d'orchestration de scanners la plus aboutie."),
    ("DependencyTrack/dependency-track", 4, 4, 4,
     "vuln-analysis/ + vuln-data-source/ + package-metadata/ + notification/ : pipeline d'analyse "
     "modulaire, SBOM natif. Bon modèle de sources de données branchables."),
    ("TheHive-Project/TheHive", 4, 2, 4,
     "Fin de distribution publique, versions 3/4 non maintenues, repo archivé. Le modèle de cas "
     "d'incident reste lisible ; G5 interdit toute réutilisation."),

    # ---------------- Q3 : exécution / isolation ----------------
    ("google/gvisor", 5, 4, 2,
     "Noyau applicatif en userspace, runtime OCI runsc. Isolation forte pour exécuter du code "
     "hostile. Complexe à opérer : candidat pour plus tard, pas pour la Phase 3."),
    ("cuckoosandbox/cuckoo", 4, 2, 3,
     "Son propre README déclare 2.x non maintenu et une réécriture en cours. Modèle analyser/"
     "resultats historique ; G5 + G1."),

    # ---------------- Q4 : plateformes de détection ----------------
    ("falcosecurity/falco", 4, 4, 4,
     "Détection runtime par règles, et surtout une modularisation explicite en dépôts spécialisés "
     "(falcosecurity/evolution). Leçon d'architecture : séparer avant que ça grossisse."),
    ("intelowlproject/IntelOwl", 4, 3, 4,
     "api_app/ + async_tests/ + integrations/, analyseurs branchables. AGPL-3.0 -> G2."),
    ("velocidex/velociraptor", 5, 4, 4,
     "artifacts/ + flows/ + actions/ + accessors/ + acls/ : un artefact = une capacité déclarée, "
     "VQL comme langage de requête, ACL intégrées. Le modèle capability le plus complet du lot."),
    ("prowler-cloud/prowler", 4, 4, 4,
     "checks/ par provider cloud, sortie multi-format, mcp_server/ et claude_plugins/ déjà présents. "
     "Bon exemple d'outil qui expose déjà une surface MCP."),
    ("semgrep/semgrep", 4, 4, 4,
     "cli/ + libs/ + languages/ + interfaces/, règles déclaratives. LGPL-2.1 -> G2. À piloter en "
     "CLI, pas à importer."),
]


def main() -> int:
    DEST.parent.mkdir(parents=True, exist_ok=True)
    with DEST.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["owner_repo", "C1", "C2", "C3", "usage", "mode_integration",
                    "confiance", "preuve", "penalite", "motif"])
        USAGE_LC = {k.lower(): v for k, v in USAGE.items()}
        manquants = [r for r, *_ in NOTES if r.lower() not in USAGE_LC]
        if manquants:
            print("ERREUR: repos sans usage/mode défini:", manquants)
            return 1
        for repo, c1, c2, c3, motif in NOTES:
            usage, mode = USAGE_LC[repo.lower()]
            # confiance = moyenne partout : les notes reposent sur README + arborescence,
            # pas sur une lecture du code. Passer en "haute" est l'objet du P1.
            preuve = "README + arborescence de 1er niveau (profil .profils/)"
            w.writerow([repo, c1, c2, c3, usage, mode, "moyenne", preuve, "",
                        " ".join(motif.split())])
    print(f"{len(NOTES)} repos notés -> {DEST}")

    dupes = {r.lower() for r, *_ in NOTES if [x[0].lower() for x in NOTES].count(r.lower()) > 1}
    if dupes:
        print("ERREUR doublons dans NOTES:", dupes)
        return 1

    inv_path = Path("PHASE1/00_INVENTAIRE_ENRICHI.csv")
    if inv_path.exists():
        inv = {r["owner_repo"].strip().lower()
               for r in csv.DictReader(inv_path.open(encoding="utf-8")) if r["owner_repo"]}
        orphelins = sorted(r for r, *_ in NOTES if r.lower() not in inv)
        if orphelins:
            print("ERREUR: repos notés mais absents de l'inventaire:")
            for o in orphelins:
                print("   - " + o)
            return 1
    for repo, c1, c2, c3, _ in NOTES:
        for v in (c1, c2, c3):
            if not 0 <= v <= 5:
                print(f"note hors plage: {repo} = {v}")
                return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
