# Inventaire de plateforme — capacités, candidats, priorités

Généré par `python3 PHASE3/inventaire_plateforme.py`. **Ce fichier n'est pas une source de vérité d'exécution** : le registre (`slice/capabilities.yaml`) décide de ce qui tourne, ici on décide de ce qui *mérite* de l'être. Les empreintes des entrées sont écrites dans `inventaire/fiches.json` — une matrice qui diverge de ses sources se vérifie par `--verifier`.

| entrée | empreinte |
|---|---|
| catalogue | `aec6543c3e88` |
| fiches | `b647ef29b6ef` |
| notes | `a9f853547f2a` |
| matrice_phase1 | `d8819269b585` |
| registre | `cba82de50df8` |
| manifeste | `39c32e189f84` |

## Matrice des capacités

| Capacité | dans AGNT | providers (passifs) | entrée | sortie | parser | sandbox | candidats |
|---|---|---|---|---|---|---|---|
| CLOUD_POSTURE | absente | 0 | — | — | à écrire | idem | Kingfisher (0.6), PurplePanda (0.6), S3Scanner (0.6), axiom (0.5) |
| CODE_METRICS | **oui** | 1 (1) | repository | findings | déclaratif ou parser nommé | bwrap, réseau coupé, cible en lecture seule | — |
| CODE_STATIC_ANALYSIS | **oui** | 1 (1) | cible | finding | déclaratif ou parser nommé | bwrap, réseau coupé, cible en lecture seule | DefectDojo (0.8333), secureCodeBox (0.5), Bandit (0.375), Bearer (0.25) |
| CODE_STATIC_ANALYSIS_CUSTOM | **oui** | 1 (1) | cible | finding | déclaratif ou parser nommé | bwrap, réseau coupé, cible en lecture seule | — |
| CODE_STATIC_ANALYSIS_GO | **oui** | 1 (1) | cible | finding | déclaratif ou parser nommé | bwrap, réseau coupé, cible en lecture seule | — |
| CODE_STATIC_ANALYSIS_SUITE | **oui** | 1 (1) | cible | finding | déclaratif ou parser nommé | bwrap, réseau coupé, cible en lecture seule | — |
| CONTAINER_SCAN | absente | 0 | — | — | à écrire | idem | SecretScanner (0.6), Checkov (0.4167), Trivy (0.35), Grype (Anchore) (0.15) |
| DEPENDENCY_ANALYSIS | **oui** | 3 (3) | cible | finding | déclaratif ou parser nommé | bwrap, réseau coupé, cible en lecture seule | tfsec (1.5), Dependency-Track (1.0), DefectDojo (0.8333), Nuclei (0.6364) |
| DETECTION_RULES | absente | 0 | — | — | à écrire | idem | Elastic Security (Detection Rules) (0.5), Sigma (0.5), Splunk Security Content (0.5) |
| ENDPOINT_COLLECTION | absente | 0 | — | — | à écrire | idem | Velociraptor (0.5714), MCPHub (0.3333) |
| EXPLOITATION | absente | 0 | — | — | à écrire | idem | ThreatMapper (0.4286), AutoSploit (0.2857), MCP Servers Cybersecurity (neptune1212) (0.2857), Metasploit Framework (0.2857) |
| IAC_SCAN | **oui** | 2 (2) | cible | finding | déclaratif ou parser nommé | bwrap, réseau coupé, cible en lecture seule | tfsec (1.5), Checkov (0.4167), Trivy (0.35), KICS (Checkmarx) (0.0625) |
| INCIDENT_RESPONSE | absente | 0 | — | — | à écrire | idem | Cortex (0.5714), Velociraptor (0.5714), TheHive (0.4286), FlareVM (0.2857) |
| LOG_ANALYSIS | absente | 0 | — | — | à écrire | idem | Wazuh (0.5), Zeek (0.5) |
| MALWARE_ANALYSIS | absente | 0 | — | — | à écrire | idem | IntelOwl (0.5714), Kubescape (ARMO) (0.4286), Linux Malware Detect (0.4286), LOKI (0.4286) |
| NETWORK_DISCOVERY | absente | 0 | — | — | à écrire | idem | axiom (0.5), Fscan (0.5), MCP for Security (f1tz) (0.5), RustScan (0.5) |
| SECRET_DETECTION | **oui** | 2 (2) | cible | finding | déclaratif ou parser nommé | bwrap, réseau coupé, cible en lecture seule | Kingfisher (0.6), SecretScanner (0.6), ThreatMapper (0.4286), detect-secrets (0.375) |
| THREAT_INTEL | absente | 0 | — | — | à écrire | idem | IntelOwl (0.5714), LOKI (0.4286), TheHive (0.4286), Recon-ng (0.4) |
| VULN_MANAGEMENT | absente | 0 | — | — | à écrire | idem | Dependency-Track (1.0), DefectDojo (0.8333) |
| WEB_ENDPOINT_DISCOVERY | absente | 0 | — | — | à écrire | idem | axiom (0.5), MCP for Security (f1tz) (0.5), ffuf (0.4), SpiderFoot (0.3333) |
| WEB_VULN_SCAN | absente | 0 | — | — | à écrire | idem | DefectDojo (0.8333), Nuclei (0.6364), axiom (0.5), Nikto (0.3846) |

## Capacités absentes du registre

- **CLOUD_POSTURE** — 11 candidat(s) inventorié(s) en Phase 1 ; risque de capacité : 1.
- **CONTAINER_SCAN** — 4 candidat(s) inventorié(s) en Phase 1 ; risque de capacité : 1.
- **DETECTION_RULES** — 3 candidat(s) inventorié(s) en Phase 1 ; risque de capacité : 0.
- **ENDPOINT_COLLECTION** — 2 candidat(s) inventorié(s) en Phase 1 ; risque de capacité : 2.
- **EXPLOITATION** — 6 candidat(s) inventorié(s) en Phase 1 ; risque de capacité : 3.
- **INCIDENT_RESPONSE** — 4 candidat(s) inventorié(s) en Phase 1 ; risque de capacité : 3.
- **LOG_ANALYSIS** — 2 candidat(s) inventorié(s) en Phase 1 ; risque de capacité : 0.
- **MALWARE_ANALYSIS** — 7 candidat(s) inventorié(s) en Phase 1 ; risque de capacité : 3.
- **NETWORK_DISCOVERY** — 9 candidat(s) inventorié(s) en Phase 1 ; risque de capacité : 2.
- **THREAT_INTEL** — 8 candidat(s) inventorié(s) en Phase 1 ; risque de capacité : 1.
- **VULN_MANAGEMENT** — 2 candidat(s) inventorié(s) en Phase 1 ; risque de capacité : 0.
- **WEB_ENDPOINT_DISCOVERY** — 5 candidat(s) inventorié(s) en Phase 1 ; risque de capacité : 2.
- **WEB_VULN_SCAN** — 4 candidat(s) inventorié(s) en Phase 1 ; risque de capacité : 2.

## Capacités sous-équipées (un seul provider passif)

- **CODE_METRICS** : providers radon_cc ; mode `un_seul`
- **CODE_STATIC_ANALYSIS** : providers semgrep ; mode `un_seul`
- **CODE_STATIC_ANALYSIS_CUSTOM** : providers bandit_custom ; mode `un_seul`
- **CODE_STATIC_ANALYSIS_GO** : providers semgrep_go ; mode `un_seul`
- **CODE_STATIC_ANALYSIS_SUITE** : providers bandit ; mode `un_seul`

## Outils nommés dans la commande du 2026-08-30, état par rapport à l'inventaire


| outil | intégré à AGNT | dans l'inventaire Phase 1 | format | priorité |
|---|---|---|---|---|
| amass | non | Amass (OWASP) | json | 0.0 |
| assetfinder | non | **absent de l'inventaire Phase 1** — à sourcer avant d'intégrer | — | — |
| bandit | oui | Bandit | json | 1.5 |
| checkov | oui | Checkov | json | 1.6667 |
| detect-secrets | oui | detect-secrets | json (baseline) | 1.5 |
| dnsx | non | **absent de l'inventaire Phase 1** — à sourcer avant d'intégrer | — | — |
| eslint-plugin-security | non | **absent de l'inventaire Phase 1** — à sourcer avant d'intégrer | — | — |
| feroxbuster | non | **absent de l'inventaire Phase 1** — à sourcer avant d'intégrer | — | — |
| ffuf | non | ffuf | json | 0.4 |
| gitleaks | oui | Gitleaks | json | 0.75 |
| gosec | non | **absent de l'inventaire Phase 1** — à sourcer avant d'intégrer | — | — |
| grype | oui | Grype (Anchore) | json | 0.6 |
| httpx | non | **absent de l'inventaire Phase 1** — à sourcer avant d'intégrer | — | — |
| kics | oui | KICS (Checkmarx) | json | 0.25 |
| masscan | non | **absent de l'inventaire Phase 1** — à sourcer avant d'intégrer | — | — |
| naabu | non | **absent de l'inventaire Phase 1** — à sourcer avant d'intégrer | — | — |
| nikto | non | Nikto | texte structuré | 0.3846 |
| nmap | non | Nmap | xml | 0.3333 |
| nuclei | non | Nuclei | jsonl | 0.6364 |
| osv-scanner | non | **absent de l'inventaire Phase 1** — à sourcer avant d'intégrer | — | — |
| semgrep | oui | Semgrep | json | 1.0 |
| subfinder | non | **absent de l'inventaire Phase 1** — à sourcer avant d'intégrer | — | — |
| syft | non | **absent de l'inventaire Phase 1** — à sourcer avant d'intégrer | — | — |
| tfsec | non | tfsec | json | 1.5 |
| trivy | oui | Trivy | json | 1.4 |
| trufflehog | non | TruffleHog | json | 0.3333 |
| whatweb | non | **absent de l'inventaire Phase 1** — à sourcer avant d'intégrer | — | — |

> Un outil absent de l'inventaire n'est pas rejeté : il est **non sourcé**. La règle de la Phase 1 (« ne pas cloner tout Internet ») tient tant que sa licence, son activité et son format de sortie n'ont pas été lus quelque part.


## Recouvrements et doublons signalés par la Phase 1

- `aucun` : IntelOwl, Velociraptor, Sigma, Wazuh, Zeek, ffuf
- `partiel avec trivy` : Dependency-Track, Kubescape (ARMO), Checkov, ScoutSuite, Vuls
- `partiel avec zap` : Nuclei, Nikto
- `FORT avec gitleaks` : detect-secrets, TruffleHog
- `déjà intégré` : Semgrep, Gitleaks
- `FORT avec checkov` : tfsec
- `partiel avec nmap` : Fscan
- `partiel` : Recon-ng

## File d'intégration (priorité = valeur / (1 + complexité + risque))

| # | outil | capacité | format mesuré ? | réseau | privilèges | valeur | cx | risque | priorité |
|---|---|---|---|---|---|---|---|---|---|
| 1 | tfsec | DEPENDENCY_ANALYSIS, IAC_SCAN | connu | non | non | 3 | 1 | 0 | **1.5** |
| 2 | Dependency-Track | DEPENDENCY_ANALYSIS, VULN_MANAGEMENT | à lire | non | non | 4 | 3 | 0 | **1.0** |
| 3 | DefectDojo | CODE_STATIC_ANALYSIS, DEPENDENCY_ANALYSIS | à lire | non | non | 5 | 3 | 2 | **0.8333** |
| 4 | Nuclei | DEPENDENCY_ANALYSIS, WEB_VULN_SCAN | connu | oui | non | 7 | 5 | 5 | **0.6364** |
| 5 | Kingfisher | SECRET_DETECTION, DEPENDENCY_ANALYSIS | à lire | non | non | 3 | 3 | 1 | **0.6** |
| 6 | PurplePanda | DEPENDENCY_ANALYSIS, CLOUD_POSTURE | à lire | non | non | 3 | 3 | 1 | **0.6** |
| 7 | S3Scanner | DEPENDENCY_ANALYSIS, CLOUD_POSTURE | à lire | non | non | 3 | 3 | 1 | **0.6** |
| 8 | SecretScanner | SECRET_DETECTION, DEPENDENCY_ANALYSIS | à lire | non | non | 3 | 3 | 1 | **0.6** |
| 9 | Cortex | INCIDENT_RESPONSE | à lire | non | non | 4 | 3 | 3 | **0.5714** |
| 10 | IntelOwl | DEPENDENCY_ANALYSIS, THREAT_INTEL | à lire | non | non | 4 | 3 | 3 | **0.5714** |
| 11 | Velociraptor | ENDPOINT_COLLECTION, INCIDENT_RESPONSE | à lire | non | non | 4 | 3 | 3 | **0.5714** |
| 12 | axiom | DEPENDENCY_ANALYSIS, CLOUD_POSTURE | à lire | non | non | 3 | 3 | 2 | **0.5** |
| 13 | Elastic Security (Detection Rules) | DETECTION_RULES | à lire | non | non | 2 | 3 | 0 | **0.5** |
| 14 | FastMCP |  | à lire | non | non | 2 | 3 | 0 | **0.5** |
| 15 | Fscan | DEPENDENCY_ANALYSIS, NETWORK_DISCOVERY | à lire | non | non | 3 | 3 | 2 | **0.5** |
| 16 | MCP for Security (f1tz) | DEPENDENCY_ANALYSIS, NETWORK_DISCOVERY | à lire | non | non | 3 | 3 | 2 | **0.5** |
| 17 | MCP Scanner (Cisco) | DEPENDENCY_ANALYSIS | à lire | non | non | 2 | 3 | 0 | **0.5** |
| 18 | mcp-scan (Snyk/Invariant Labs) | DEPENDENCY_ANALYSIS | à lire | non | non | 2 | 3 | 0 | **0.5** |
| 19 | RustScan | DEPENDENCY_ANALYSIS, NETWORK_DISCOVERY | à lire | non | non | 3 | 3 | 2 | **0.5** |
| 20 | secureCodeBox | CODE_STATIC_ANALYSIS | à lire | non | non | 2 | 3 | 0 | **0.5** |
| 21 | Sigma | DETECTION_RULES | à lire | non | non | 2 | 3 | 0 | **0.5** |
| 22 | Splunk Security Content | DETECTION_RULES | à lire | non | non | 2 | 3 | 0 | **0.5** |
| 23 | ToolHive |  | à lire | non | non | 2 | 3 | 0 | **0.5** |
| 24 | Tracecat | DEPENDENCY_ANALYSIS | à lire | non | non | 2 | 3 | 0 | **0.5** |
| 25 | Wazuh | LOG_ANALYSIS | à lire | non | non | 2 | 3 | 0 | **0.5** |

## Ce que ce tableau ne dit pas

- Une priorité élevée n'autorise rien : l'outil doit être installé, épinglé par empreinte, passer la validation du manifeste, la policy, et le profil d'isolation. Un outil `reseau: true` reste **refusé** tant que l'export n'est pas autorisé explicitement pour la mission.
- `format = à lire` signifie : personne n'a vu la sortie de cet outil sur cette machine. C'est le champ qui ment le plus vite, il est gardé explicite.
- Les 112 autres entrées de la Phase 1 (rôles `inutile`, `doc`, `concurrent`) ne sont pas reprises : la Phase 1 a déjà tranché, et une matrice qui réhabilite les écartés sans argument n'est pas un inventaire, c'est un wish-list.
