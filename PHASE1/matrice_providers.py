#!/usr/bin/env python3
"""Fiches providers et matrice de couverture.

Répond à : « quel apport RÉEL de chaque outil ? » et non « combien d'outils ? ».

Le critère n'est pas le nombre d'outils mais la DIVERSITÉ FONCTIONNELLE : un outil qui
recouvre un provider déjà intégré apporte peu, même s'il est excellent.

AVERTISSEMENT HONNÊTE

Les champs « capacité », « cibles » et « chevauchement » viennent d'une base de
connaissances, PAS d'une vérification dépôt par dépôt. Ils sont marqués comme tels.
Les étoiles, dates et licences viennent de l'inventaire (données réelles).

Aucun code n'est écrit ici. Ce script produit une matrice de décision, rien d'autre.
"""

from __future__ import annotations

import csv
from collections import defaultdict
from pathlib import Path

RACINE = Path(__file__).resolve().parent
CATALOGUE = RACINE / "07_CATALOGUE_INTEGRATION.csv"
SORTIE_FICHES = RACINE / "08_FICHES_PROVIDERS.csv"
SORTIE_MATRICE = RACINE / "09_MATRICE_COUVERTURE_PROVIDERS.csv"

INTEGRES = {
    "semgrep": {"CODE_STATIC_ANALYSIS"},
    "trivy": {"DEPENDENCY_ANALYSIS", "CONTAINER_SCAN", "CLOUD_POSTURE"},
    "gitleaks": {"SECRET_DETECTION"},
}
COUVERT_ACTUEL = set().union(*INTEGRES.values())

# (capacité principale, capacités secondaires, cibles, chevauchement, intérêt)
CONNAISSANCE = {
    "nmap/nmap": ("NETWORK_DISCOVERY", "WEB_ENDPOINT_DISCOVERY",
                  "hôtes, ports, services", "aucun",
                  "découverte réseau, base de tout scan d'infrastructure"),
    "shadow1ng/fscan": ("NETWORK_DISCOVERY", "EXPLOITATION",
                        "hôtes, ports, services Windows", "partiel avec nmap",
                        "orienté Windows/AD, complémentaire de nmap"),
    "ffuf/ffuf": ("WEB_ENDPOINT_DISCOVERY", "", "URL, chemins, paramètres", "aucun",
                  "découverte de chemins cachés, simple et rapide"),
    "projectdiscovery/katana": ("WEB_ENDPOINT_DISCOVERY", "WEB_VULN_SCAN",
                                "URL, JavaScript, formulaires", "partiel avec ffuf",
                                "crawler moderne, meilleur que ffuf sur le JavaScript"),
    "zaproxy/zaproxy": ("WEB_VULN_SCAN", "WEB_ENDPOINT_DISCOVERY",
                        "applications web", "aucun", "scan web complet, très mature"),
    "projectdiscovery/nuclei": ("WEB_VULN_SCAN", "CLOUD_POSTURE",
                                "web, réseau, configurations", "partiel avec zap",
                                "scan par modèles, très large, mais ACTIF"),
    "sullo/nikto": ("WEB_VULN_SCAN", "", "serveurs web", "partiel avec zap",
                    "ancien mais utile sur les serveurs web"),
    "PyCQA/bandit": ("CODE_STATIC_ANALYSIS", "", "Python", "FORT avec semgrep",
                     "recouvre largement semgrep sur Python, apport faible"),
    "semgrep/semgrep": ("CODE_STATIC_ANALYSIS", "", "30+ langages", "déjà intégré",
                        "déjà intégré"),
    "returntocorp/semgrep": ("CODE_STATIC_ANALYSIS", "", "30+ langages", "déjà intégré",
                             "doublon de semgrep"),
    "SonarSource/sonarqube": ("CODE_STATIC_ANALYSIS", "", "30+ langages",
                              "FORT avec semgrep",
                              "qualité de code plus que sécurité, lourd"),
    "anchore/grype": ("DEPENDENCY_ANALYSIS", "CONTAINER_SCAN",
                      "SBOM, images, filesystem", "FORT avec trivy",
                      "recouvre trivy, meilleur sur les SBOM"),
    "anchore/syft": ("DEPENDENCY_ANALYSIS", "", "SBOM uniquement", "complément de trivy",
                     "génère des SBOM, ne détecte pas de vulnérabilité"),
    "future-architect/vuls": ("DEPENDENCY_ANALYSIS", "",
                              "serveurs Linux, paquets système", "partiel avec trivy",
                              "scan de serveurs, pas de conteneurs"),
    "DependencyTrack/dependency-track": ("DEPENDENCY_ANALYSIS", "VULN_MANAGEMENT",
                                         "SBOM, suivi dans le temps", "partiel avec trivy",
                                         "plateforme de suivi, pas un scanner"),
    "gitleaks/gitleaks": ("SECRET_DETECTION", "", "git, fichiers", "déjà intégré",
                          "déjà intégré"),
    "trufflesecurity/trufflehog": ("SECRET_DETECTION", "", "git, fichiers, API, S3",
                                   "FORT avec gitleaks",
                                   "vérifie si les secrets sont ACTIFS, pas juste présents"),
    "Yelp/detect-secrets": ("SECRET_DETECTION", "", "fichiers", "FORT avec gitleaks",
                            "apport faible face à gitleaks"),
    "bridgecrewio/checkov": ("IAC_SCAN", "CLOUD_POSTURE",
                             "Terraform, CloudFormation, Kubernetes, Dockerfile",
                             "partiel avec trivy", "IaC, capacité où on n'a RIEN"),
    "aquasecurity/tfsec": ("IAC_SCAN", "", "Terraform uniquement", "FORT avec checkov",
                           "Terraform seulement, checkov est plus large"),
    "kubescape/kubescape": ("CLOUD_POSTURE", "CONTAINER_SCAN", "Kubernetes",
                            "partiel avec trivy", "conformité Kubernetes"),
    "nccgroup/ScoutSuite": ("CLOUD_POSTURE", "", "AWS, Azure, GCP", "partiel avec trivy",
                            "audit de configuration cloud"),
    "prowler-cloud/prowler": ("CLOUD_POSTURE", "", "AWS, Azure, GCP, Kubernetes",
                              "partiel avec trivy", "conformité CIS, très complet"),
    "osquery/osquery": ("ENDPOINT_COLLECTION", "LOG_ANALYSIS",
                        "hôtes Linux/macOS/Windows, SQL", "aucun",
                        "visibilité sur les hôtes, requêtes SQL, très puissant"),
    "velocidex/velociraptor": ("ENDPOINT_COLLECTION", "INCIDENT_RESPONSE",
                               "hôtes, agents déployés", "aucun",
                               "puissant mais exige des agents déployés"),
    "zeek/zeek": ("LOG_ANALYSIS", "NETWORK_DISCOVERY", "trafic réseau", "aucun",
                  "analyse de trafic, riche mais lourd"),
    "OISF/suricata": ("LOG_ANALYSIS", "DETECTION_RULES", "trafic réseau",
                      "partiel avec zeek", "IDS/IPS, signatures"),
    "wazuh/wazuh": ("LOG_ANALYSIS", "ENDPOINT_COLLECTION", "hôtes, journaux", "aucun",
                    "plateforme complète, pas un simple scanner"),
    "laramies/theHarvester": ("THREAT_INTEL", "WEB_ENDPOINT_DISCOVERY",
                              "domaines, emails, sous-domaines", "aucun",
                              "OSINT passif, simple et utile"),
    "smicallef/spiderfoot": ("THREAT_INTEL", "WEB_ENDPOINT_DISCOVERY",
                             "domaines, IPs, emails", "partiel avec theHarvester",
                             "OSINT très large, mais lent"),
    "lanmaster53/recon-ng": ("THREAT_INTEL", "", "domaines, APIs", "partiel",
                             "OSINT modulaire"),
    "MISP/MISP": ("THREAT_INTEL", "", "partage d'indicateurs", "aucun",
                  "plateforme de partage, pas un scanner"),
    "OpenCTI-Platform/opencti": ("THREAT_INTEL", "", "connaissance des menaces",
                                 "partiel avec MISP", "plateforme, lourde"),
    "intelowlproject/IntelOwl": ("THREAT_INTEL", "MALWARE_ANALYSIS",
                                 "fichiers, domaines, URLs", "aucun",
                                 "agrège des analyses, dépend d'API tierces"),
    "SigmaHQ/sigma": ("DETECTION_RULES", "LOG_ANALYSIS", "règles de détection", "aucun",
                      "règles, pas un scanner : produit des requêtes"),
    "VirusTotal/yara": ("MALWARE_ANALYSIS", "DETECTION_RULES", "fichiers, mémoire",
                        "aucun", "règles de détection de malware"),
    "cuckoosandbox/cuckoo": ("MALWARE_ANALYSIS", "", "fichiers, exécution", "aucun",
                             "archivé, à éviter"),
    "kevoreilly/CAPEv2": ("MALWARE_ANALYSIS", "", "fichiers, exécution",
                          "successeur de cuckoo", "analyse de malware, lourd"),
    "rapid7/metasploit-framework": ("EXPLOITATION", "", "hôtes, services", "aucun",
                                    "exploitation, exige une autorisation explicite"),
    "sqlmapproject/sqlmap": ("EXPLOITATION", "WEB_VULN_SCAN",
                             "bases de données via web", "partiel avec zap",
                             "injection SQL, actif et intrusif"),
}


def marge(caps: set) -> tuple:
    nouvelles = sorted(caps - COUVERT_ACTUEL)
    return len(nouvelles), nouvelles


def main() -> int:
    if not CATALOGUE.exists():
        print(f"catalogue absent : {CATALOGUE}")
        return 1

    lignes = [r for r in csv.DictReader(CATALOGUE.open(encoding="utf-8"))
              if r["role"] == "provider" and r["capacites"]
              and r["verifiable"] == "oui" and r["archive"] != "yes"]

    fiches = []
    for r in lignes:
        repo = r["owner_repo"]
        caps = [c for c in r["capacites"].split(" | ") if c]
        connue = CONNAISSANCE.get(repo)
        if connue:
            cap_princ, cap_sec, cibles, chevauchement, interet = connue
            source = "connaissance (non vérifié dépôt par dépôt)"
        else:
            cap_princ = caps[0] if caps else ""
            cap_sec = " | ".join(caps[1:])
            cibles, interet = "", "à évaluer"
            chevauchement = "à évaluer"
            source = "non documenté"

        ensemble = set(filter(None, [cap_princ] + [c for c in cap_sec.split(" | ") if c]))
        n_new, nouvelles = marge(ensemble)
        etoiles = int(r["etoiles"] or 0)

        fiches.append({
            "owner_repo": repo,
            "etoiles": etoiles,
            "capacite_principale": cap_princ,
            "capacites_secondaires": cap_sec,
            "cibles_langages": cibles,
            "forme_execution": r["forme_execution"],
            "chevauchement": chevauchement,
            "nouvelles_capacites": n_new,
            "lesquelles": " | ".join(nouvelles),
            "interet_fonctionnel": interet,
            "licence": r["licence"],
            "dernier_commit": r["dernier_commit"],
            "maturite": ("élevée" if etoiles > 5000
                         else "moyenne" if etoiles > 1000 else "faible"),
            "source_appreciation": source,
        })

    fiches.sort(key=lambda f: (-f["nouvelles_capacites"], -f["etoiles"]))

    with SORTIE_FICHES.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(fiches[0].keys()))
        w.writeheader()
        w.writerows(fiches)

    print(f"{len(fiches)} fiches -> {SORTIE_FICHES}\n")
    print("=== APPORT RÉEL : nouvelles capacités par outil ===\n")
    for f in fiches[:22]:
        print(f"  +{f['nouvelles_capacites']}  {f['etoiles']:>6}*  {f['owner_repo']:<42} "
              f"{f['lesquelles'][:46] or '(recouvre l existant)'}")

    par_cap = defaultdict(list)
    for f in fiches:
        toutes = [f["capacite_principale"]] + [c for c in f["capacites_secondaires"].split(" | ") if c]
        for c in toutes:
            par_cap[c].append(f["owner_repo"])

    print("\n=== MATRICE DE COUVERTURE ===\n")
    with SORTIE_MATRICE.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["capacite", "deja_couverte", "nb_providers", "meilleurs_candidats"])
        for cap, provs in sorted(par_cap.items(), key=lambda x: -len(x[1])):
            deja = "OUI" if cap in COUVERT_ACTUEL else "NON"
            w.writerow([cap, deja, len(provs), ", ".join(provs[:5])])
            marque = "  " if deja == "OUI" else ">>"
            print(f"  {marque} {deja:<4} {len(provs):>3} prov.  {cap:<26} "
                  f"{', '.join(provs[:3])[:50]}")

    print(f"\n  >> = capacité NON couverte aujourd'hui")
    print(f"\nCouvert actuellement ({len(COUVERT_ACTUEL)}) : {sorted(COUVERT_ACTUEL)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

