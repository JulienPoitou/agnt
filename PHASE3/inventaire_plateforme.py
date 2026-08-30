#!/usr/bin/env python3
"""Inventaire de plateforme — l'entrée de l'extension, pas un catalogue de plus.

Ce que ce script fait, et surtout ce qu'il refuse de faire :

  IL JOINT    : l'inventaire déjà produit en Phase 1 (324 entrées triées, 69 fiches
                qualifiées, matrice de couverture, notes de scoring) avec le registre
                RÉEL d'AGNT (capacités, providers, manifeste des dépendances) et avec
                l'état de la machine (outil présent ? épinglé ?).
  IL CLASSE   : par (valeur / complexité / risque), formule écrite ci-dessous, appliquée
                de façon déterministe. La sélection n'est pas une opinion.
  IL PRODUIT  : une fiche par candidat, la matrice des capacités, et des MANIFESTES DE
                PLUGIN PRÊTS À POSER pour les candidats retenus — dans
                `plugins/propositions/`, qui n'est PAS le répertoire chargé par le runtime.
                Une proposition n'est donc jamais un outil « intégré » : c'est la
                différence entre un inventaire honnête et un registre décoré.
  IL NE PRÉTEND PAS : qu'un outil marche parce qu'il est populaire, ni qu'un format de
                sortie est connu parce qu'il est documenté. Tout champ qui n'a pas été lu
                dans la source ou mesuré porte la mention `déclaré (non mesuré ici)`.

Formule de priorité (reproduisible, ce n'est pas un score opaque) :

    valeur     = 2 si verdict Phase 1 = INTEGRATE ; 1 si ADAPT* ; 0 sinon
               + 2 si la capacité n'existe pas encore dans le registre
               + 1 si la capacité existe mais avec un seul provider (sous-équipée)
               + 1 si la capacité existe avec le mode fan_out (un second outil y est attendu)
    complexité = 1 si le format de sortie demande un parser nommé
               + 1 si la sortie est XML/CSV/texte (pas JSON/SARIF)
               + 2 si l'outil sort sur le réseau
               + 2 si l'outil demande des privilèges (root, pcap, containers)
               + 1 si une base ou un jeu de données doit être préparé (et épinglé)
               + 1 si l'installation n'est pas reproductible par empreinte
    risque     = 3 si la capacité touche à l'exploitation, au malware ou à l'active response
               + 2 si le réseau sortant est requis
               + 1 si l'outil lit au-delà du dépôt (hôte, conteneurs, filesystem)
               + 1 si la licence est copyleft (GPL/AGPL : régime de redistribution à trancher)

    priorité   = valeur / (1 + complexité + risque)

Usage :
    python3 PHASE3/inventaire_plateforme.py            # régénère les trois sorties
    python3 PHASE3/inventaire_plateforme.py --verifier # échoue si une sortie a dérivé
"""

from __future__ import annotations

import csv
import hashlib
import json
import sys
from pathlib import Path

RACINE_SLICE = Path(__file__).resolve().parent / "slice"
sys.path.insert(0, str(RACINE_SLICE))
RACINE_DEPOT = Path(__file__).resolve().parent.parent
P1 = RACINE_DEPOT / "PHASE1"
PHASE3 = RACINE_DEPOT / "PHASE3"

FICHES_JSON = PHASE3 / "inventaire" / "fiches.json"
MATRICE_MD = PHASE3 / "INVENTAIRE_PLATEFORME.md"
PROPOSITIONS = PHASE3 / "plugins" / "propositions"

# Les capacités que la Phase 1 ne couvrait pas sous ce nom : la table de correspondance
# est ÉCRITE parce qu'un rapprochement par chaîne (majuscules, tirets) ferait fusionner
# deux capacités différentes ou en perdrait une sans le dire.
EQUIVALENCES = {
    "WEB_VULN_SCAN": "DAST",
    "WEB_ENDPOINT_DISCOVERY": "WEB_FUZZING",
    "NETWORK_DISCOVERY": "NETWORK_DISCOVERY",
    "THREAT_INTEL": "OSINT",
    "LOG_ANALYSIS": "LOG_ANALYSIS",
    "VULN_MANAGEMENT": "VULN_MANAGEMENT",
}

# Ce qu'AGNT sait des formats de sortie des candidats nommés dans la commande du projet.
# `mesure` = un run réel a été fait sur CETTE machine (la date est dans le champ `preuve`),
# `declare` = lu dans la doc/Phase 1, pas revérifié ici. La distinction est le cœur du fichier.
CONTRATS: dict[str, dict] = {
    "semgrep": dict(sortie="json", parser="non requis (modèle plat)", reseau=False,
                    privilèges=False, base="règles (dépôt de règles épinglé)",
                    installation="pip", licence="LGPL-2.1 (cœur)",
                    preuve="déclaré · provider déjà au registre"),
    "bandit": dict(sortie="json", parser="non requis", reseau=False, privilèges=False,
                   base="aucune", installation="pip", licence="Apache-2.0",
                   preuve="déclaré · provider déjà au registre"),
    "gosec": dict(sortie="json", parser="non requis", reseau=False, privilèges=False,
                  base="aucune", installation="binaire Go (release GitHub)",
                  licence="Apache-2.0", preuve="déclaré (non mesuré ici)"),
    "eslint-plugin-security": dict(sortie="json", parser="requis (format eslint)",
                                   reseau=False, privilèges=False, base="node_modules",
                                   installation="npm", licence="MIT",
                                   preuve="déclaré (non mesuré ici)"),
    "detect-secrets": dict(sortie="json (baseline)", parser="requis (dictionnaire indexé par fichier)",
                           reseau=False, privilèges=False, base="aucune",
                           installation="pip", licence="Apache-2.0",
                           preuve="MESURÉ 2026-08-30 : 4 findings sur testrepo, empreintes stables"),
    "gitleaks": dict(sortie="json", parser="non requis", reseau=False, privilèges=False,
                     base="règles internes + .gitleaks.toml du dépôt", installation="binaire Go",
                     licence="MIT", preuve="déclaré · provider déjà au registre"),
    "trufflehog": dict(sortie="json", parser="requis (clé `DetectorName`)", reseau="partiel",
                       privilèges=False, base="vérification des secrets sort sur le réseau",
                       installation="binaire Go", licence="AGPL-3.0",
                       preuve="déclaré (non mesuré ici)"),
    "trivy": dict(sortie="json", parser="non requis", reseau=False, privilèges=False,
                  base="DB de vulnérabilités (à épingler, condition d'exécution)",
                  installation="binaire Go", licence="Apache-2.0",
                  preuve="déclaré · provider déjà au registre"),
    "grype": dict(sortie="json", parser="non requis", reseau=False, privilèges=False,
                  base="DB grype (marqueur instable : limite écrite au registre)",
                  installation="binaire Go", licence="Apache-2.0",
                  preuve="déclaré · provider déjà au registre"),
    "osv-scanner": dict(sortie="json", parser="requis (vulnerabilities[] + alias)",
                        reseau=True, privilèges=False,
                        base="API api.osv.dev SAUF mode `--offline` avec base locale",
                        installation="binaire Go", licence="Apache-2.0",
                        preuve="déclaré (non mesuré ici)"),
    "syft": dict(sortie="json", parser="requis (artifact[], ce n'est pas un finding)",
                 reseau=False, privilèges=False, base="aucune (produit un SBOM)",
                 installation="binaire Go", licence="Apache-2.0",
                 preuve="déclaré (non mesuré ici)"),
    "checkov": dict(sortie="json", parser="requis (inline_subset par bloc)", reseau=False,
                    privilèges=False, base="aucune", installation="pip",
                    licence="Apache-2.0", preuve="déclaré · provider déjà au registre"),
    "kics": dict(sortie="json", parser="non requis", reseau=False, privilèges=False,
                 base="bibliothèque de 1810 requêtes (asset séparé, sha256 épinglé)",
                 installation="binaire Go", licence="Apache-2.0",
                 preuve="déclaré · provider déjà au registre"),
    "tfsec": dict(sortie="json", parser="non requis", reseau=False, privilèges=False,
                  base="aucune", installation="binaire Go",
                  licence="MIT (projet déprécié au profit de Trivy) → à trancher",
                  preuve="déclaré (non mesuré ici)"),
    "nuclei": dict(sortie="jsonl", parser="requis (un objet par ligne)", reseau=True,
                   privilèges=False, base="templates (dépôt à part, à épingler)",
                   installation="binaire Go", licence="MIT",
                   preuve="déclaré (non mesuré ici)"),
    "httpx": dict(sortie="jsonl", parser="requis", reseau=True, privilèges=False,
                  base="aucune", installation="binaire Go", licence="MIT",
                  preuve="déclaré (non mesuré ici)"),
    "ffuf": dict(sortie="json", parser="requis", reseau=True, privilèges=False,
                 base="wordlist (fichier à fournir, non à télécharger)",
                 installation="binaire Go", licence="MIT", preuve="déclaré (non mesuré ici)"),
    "feroxbuster": dict(sortie="json", parser="requis", reseau=True, privilèges=False,
                        base="wordlist", installation="binaire Rust (cargo)",
                        licence="MIT", preuve="déclaré (non mesuré ici)"),
    "nikto": dict(sortie="texte structuré", parser="requis (XML partiel, CSV plat)",
                  reseau=True, privilèges=False, base="bases de signatures du paquet",
                  installation="paquet (perl)", licence="GPL-2.0",
                  preuve="déclaré (non mesuré ici)"),
    "whatweb": dict(sortie="json", parser="requis", reseau=True, privilèges=False,
                    base="signatures embarquées", installation="gem (ruby)",
                    licence="GPL-2.0", preuve="déclaré (non mesuré ici)"),
    "nmap": dict(sortie="xml", parser="requis (nmaprun/host)", reseau=True,
                 privilèges="root pour -sS/-O", base="nmap-service-probes (paquet)",
                 installation="paquet", licence="NPSL (licence non libre : à trancher)",
                 preuve="déclaré (non mesuré ici)"),
    "masscan": dict(sortie="json", parser="requis", reseau=True, privilèges=True,
                    base="aucune", installation="paquet/source", licence="AGPL-3.0",
                    preuve="déclaré (non mesuré ici)"),
    "naabu": dict(sortie="json", parser="requis", reseau=True, privilèges=False,
                  base="aucune", installation="binaire Go", licence="MIT",
                  preuve="déclaré (non mesuré ici)"),
    "amass": dict(sortie="json", parser="requis", reseau=True, privilèges=False,
                  base="sources publiques + clés d'API optionnelles", installation="binaire Go",
                  licence="Apache-2.0", preuve="déclaré (non mesuré ici)"),
    "subfinder": dict(sortie="json", parser="requis", reseau=True, privilèges=False,
                      base="résolveurs publics", installation="binaire Go", licence="BSD-3-Clause",
                      preuve="déclaré (non mesuré ici)"),
    "dnsx": dict(sortie="json", parser="requis", reseau=True, privilèges=False,
                 base="aucune", installation="binaire Go", licence="MIT",
                 preuve="déclaré (non mesuré ici)"),
    "assetfinder": dict(sortie="texte (une ligne par nom)", parser="requis", reseau=True,
                        privilèges=False, base="aucune", installation="binaire Go",
                        licence="GPL-3.0", preuve="déclaré (non mesuré ici)"),
}

# Risque par capacité. 3 = l'outil touche à l'exploitation / au malware / à l'action sur
# l'hôte : ce n'est pas une question de popularité, c'est la classe d'effets de bord.
RISQUE_CAPACITE = {
    "EXPLOITATION": 3, "MALWARE_ANALYSIS": 3, "INCIDENT_RESPONSE": 3,
    "ENDPOINT_COLLECTION": 2, "NETWORK_DISCOVERY": 2, "WEB_VULN_SCAN": 2,
    "DAST": 2, "WEB_FUZZING": 2, "FUZZING": 2, "THREAT_INTEL": 1, "OSINT": 1,
    "CLOUD_POSTURE": 1, "CONTAINER_SCAN": 1,
}
LICENCES_COPYLEFT = ("GPL", "AGPL", "NPSL")

# Outils nommés explicitement dans la commande du 2026-08-30. Le bonus est LÀ POUR ÊTRE
# VU : sans lui, la priorité sortirait uniquement des verdicts de la Phase 1, et la
# commande demanderait implicitement de trier à la main. +2 = une capacité manquante.
OUTILS_DEMANDES = {
    "semgrep", "bandit", "gosec", "eslint-plugin-security", "detect-secrets", "gitleaks",
    "trufflehog", "trivy", "grype", "osv-scanner", "checkov", "kics", "tfsec", "syft",
    "nuclei", "httpx", "ffuf", "feroxbuster", "nikto", "whatweb", "nmap", "masscan", "naabu",
    "amass", "subfinder", "dnsx", "assetfinder",
}
# Les 19 candidats que la Phase 1 a explicitement retenus : c'est la liste d'entrée
# prioritaire (consigne « ne pas cloner tout Internet »), pas la seule.
VERDICT_VALEUR = {"INTEGRATE": 2, "ADAPT": 1, "ADAPT (archi)": 1}


def _norm(s: str) -> str:
    return " ".join((s or "").replace("\r", " ").split())


def lire_csv(chemin: Path) -> list[dict]:
    with chemin.open(encoding="utf-8", newline="") as f:
        return [{k: _norm(v) for k, v in l.items()} for l in csv.DictReader(f)]


def registre_capacites() -> dict[str, dict]:
    from registre import Registry
    reg = Registry()
    out = {}
    for cap in reg.capabilities():
        passifs = [p for p in cap.providers if p.risque == "PASSIVE"]
        out[cap.id] = {
            "providers": [p.id for p in cap.providers],
            "passifs": len(passifs),
            "mode": getattr(cap, "mode_selection", "") or "",
            "max": getattr(cap, "max_providers", 0) or 0,
            "entree": list(getattr(cap, "entree", []) or []),
            "sortie": getattr(cap, "sortie", "") or "",
            "domaines": list(getattr(cap, "domaines", []) or []),
        }
    return out


def outils_epingles() -> dict[str, dict]:
    import outils as OUT
    return {k: {"version": t.version, "installation": t.installation, "licence": t.licence,
                "source": t.source} for k, t in OUT.registre().items()}


def noms_deja_integres() -> set:
    """Noms d'outils déjà portés par un provider du registre (binaire, id de provider,
    `tool_id` du manifest). Sert à NE PAS proposer d'intégrer ce qui tourne déjà — une
    matrice qui recommande d'intégrer semgrep pendant que semgrep est au registre perd son
    autorité, et le lecteur ne sait plus laquelle des deux lignes croire."""
    from registre import Registry
    out = set()
    for prov in Registry().providers():
        out.add(prov.id.lower().replace("-", "_"))
        if prov.commande:
            out.add(Path(str(prov.commande[0])).name.lower().replace("-", "_"))
        mani = getattr(prov, "manifest", None)
        for attribut in ("binaire", "tool_id"):
            v = getattr(mani, attribut, None)
            if v:
                out.add(Path(str(v)).name.lower().replace("-", "_"))
    return out


def outil_present(nom: str) -> bool:
    from shutil import which
    import adapters as A
    return A.resoudre_exe(nom) is not None or which(nom) is not None


def contracte(nom_brique: str) -> dict:
    """Le contrat de sortie d'un outil, par le nom du paquet (plus stable que le repo)."""
    # Comparaison EN MINUSCULES et sans séparateurs : le catalogue Phase 1 écrit
    # « Grype (Anchore) », « detect-secrets », « ESLint security plugin » — et un nom qui ne
    # se raccorde pas à un contrat connu n'est pas une absence de contrat, c'était une faute
    # de rapprochement (mesuré : 12 fiches sur 14 affichaient `format=inconnu` à tort).
    cible = nom_brique.lower().replace("-", "").replace("_", "").replace(" ", "")
    for cle, v in CONTRATS.items():
        if cle.lower().replace("-", "").replace("_", "").replace(" ", "") in cible:
            return dict(v, outil_cle=cle)
    return {}


def scorer(nom: str, verdict: str, capacites: list[str], contrat: dict,
           cap_reg: dict) -> tuple[float, dict]:
    valeur = VERDICT_VALEUR.get(verdict, 0)
    detail = {"verdict_phase1": verdict}
    absentes = 0
    sous_equipees = 0
    fan_out_attendus = 0
    for c in capacites:
        cid = EQUIVALENCES.get(c, c)
        info = cap_reg.get(cid)
        if info is None:
            absentes += 1
        elif info["passifs"] <= 1:
            sous_equipees += 1
        if info and info["mode"] == "fan_out":
            fan_out_attendus += 1
    if absentes:
        valeur += 2
    if sous_equipees:
        valeur += 1
    if fan_out_attendus:
        valeur += 1
    if nom.lower() in OUTILS_DEMANDES or nom.replace(" ", "-").lower() in OUTILS_DEMANDES:
        valeur += 2
        detail["demande_explicite"] = True
    detail.update(capabilites_absentes=absentes, capacites_sous_equipees=sous_equipees,
                  fan_out=sous_equipees and fan_out_attendus > 0)

    complexite = 0
    if not contrat:
        # Aucun contrat de sortie connu = le format reste à lire. Ce n'est PAS le cas le
        # plus simple : c'est celui où l'on découvre après coup que la sortie n'a aucune
        # structure stable. Pénalisé, sinon les composants d'infrastructure (aucun format
        # attendu, donc aucun travail) passeraient devant les scanners.
        complexite += 3
    if contrat:
        complexite += 1 if "requis" in contrat.get("parser", "") else 0
        if contrat.get("sortie") in ("xml", "jsonl", "texte structuré", "texte (une ligne par nom)"):
            complexite += 1
        if contrat.get("reseau"):
            complexite += 2
        if contrat.get("privilèges"):
            complexite += 2
        base = str(contrat.get("base") or "")
        if base and base not in ("aucune", "aucun"):
            complexite += 1
        if contrat.get("installation") in ("paquet/source", "gem (ruby)", "npm", "paquet (perl)"):
            complexite += 1

    risque = 0
    for c in capacites:
        risque = max(risque, RISQUE_CAPACITE.get(EQUIVALENCES.get(c, c), 0))
    if contrat.get("reseau"):
        risque += 2
    if contrat.get("privilèges"):
        risque += 1
    if contrat.get("base") not in (None, "aucune", "aucun"):
        risque += 1
    lic = str(contrat.get("licence") or "")
    if any(m in lic.upper() for m in LICENCES_COPYLEFT):
        risque += 1

    priorite = round(valeur / (1 + complexite + risque), 4)
    detail.update(valeur=valeur, complexite=complexite, risque=risque, priorite=priorite)
    return priorite, detail


def construis() -> dict:
    cat = {r["owner_repo"]: r for r in lire_csv(P1 / "07_CATALOGUE_INTEGRATION.csv")}
    fiches_p1 = {r["owner_repo"]: r for r in lire_csv(P1 / "08_FICHES_PROVIDERS.csv")}
    notes = {r["owner_repo"]: r for r in lire_csv(P1 / "NOTES.csv")}
    matrice_p1 = {r["capacite"]: r for r in lire_csv(P1 / "09_MATRICE_COUVERTURE_PROVIDERS.csv")}
    cap_reg = registre_capacites()
    epingles = outils_epingles()

    fiches = []
    for repo, l in cat.items():
        capacites = [c.strip() for c in (l.get("capacites") or "").split("|") if c.strip()]
        role = l.get("role") or ""
        if role in ("inutile", "doc", "concurrent"):
            continue                      # la Phase 1 a déjà tranché : on ne la contredit pas
        nom = (l.get("nom") or repo.split("/")[-1]).strip()
        contrat = contracte(nom)
        priorite, detail = scorer(nom, l.get("verdict_phase1", ""), capacites, contrat, cap_reg)
        f8 = fiches_p1.get(repo, {})
        n = notes.get(repo, {})
        deja = [c for c in capacites if c in cap_reg and repo.split("/")[-1].lower()
                in " ".join(cap_reg[c]["providers"]).lower()]
        entree = sorted({e for c in capacites if c in cap_reg for e in cap_reg[c]["entree"]}) or \
            (["cible"] if f8 else [])
        fiches.append({
            "nom": nom,
            "priorite_brute": priorite,
            "repository": f"https://github.com/{repo}",
            "owner_repo": repo,
            "langage_forme": l.get("forme_execution") or "inconnu",
            "licence": contrat.get("licence") or l.get("licence") or "inconnue",
            "activite": {"etoiles": l.get("etoiles") or "", "dernier_commit": l.get("dernier_commit") or "",
                         "archive": l.get("archive") or "?",
                         "maturite_phase1": f8.get("maturite") or ""},
            "fonction": l.get("pourquoi") or l.get("role") or "",
            "categories": capacites,
            "entree": entree,
            "sortie": contrat.get("sortie") or "inconnue",
            "format": contrat.get("sortie") or "inconnu",
            "parser_requis": ("requis" in str(contrat.get("parser") or "")
                             and "non requis" not in str(contrat.get("parser") or ""))
                            or not contrat,          # contrat inconnu = parser à écrire
            "installation": contrat.get("installation") or ("pip" if l.get("forme_execution") == "cli" else "à définir"),
            "dependances": contrat.get("base") or "inconnues",
            "reseau_requis": bool(contrat.get("reseau")),
            "privileges_requis": contrat.get("privilèges") or False,
            "risque": {"note": detail.get("risque", 0), "capacites": [c for c in capacites
                                                                      if RISQUE_CAPACITE.get(EQUIVALENCES.get(c, c), 0) >= 2]},
            "facilite_integration": {"score_inverse_complexite": 6 - detail.get("complexite", 0),
                                     "detail": detail},
            "valeur_pour_agnt": {"score": detail.get("valeur", 0), "priorite": priorite,
                                 "deja_au_registre": bool(deja), "epingle_au_manifeste": nom in epingles
                                 or (nom.replace("-", "_") in epingles)},
            "etat_machine": {"outil_present": outil_present(nom), "epingle": epingles.get(nom, {})},
            "preuve": contrat.get("preuve") or "aucun contrat de sortie connu : à lire avant intégration",
            "verdict_phase1": l.get("verdict_phase1") or "",
            "notes_phase1": {"C1": n.get("C1", ""), "C2": n.get("C2", ""), "C3": n.get("C3", ""),
                             "usage": n.get("usage", ""), "mode_integration": n.get("mode_integration", ""),
                             "confiance": n.get("confiance", ""), "penalite": n.get("penalite", "")},
            "chevauchement_phase1": f8.get("chevauchement") or "",
            "candidat_integration": role == "provider",
            "role_phase1": role,
        })
    deja_integres = noms_deja_integres()
    # Un outil peut être intégré sous un nom d'écran différent de celui du registre
    # (« KICS (Checkmarx) » vs le provider `kics`) : on compare aussi le dépôt amont, tel
    # qu'épinglé dans `manifeste_dependances.yaml`.
    depots_epingles = set()
    for entree_epinglee in epingles.values():
        src = str(entree_epinglee.get("source") or "").lower().rstrip("/")
        if "github.com/" in src:
            depots_epingles.add(src.split("github.com/")[-1])

    def normalise(nom: str) -> str:
        base = nom.lower().split("(")[0]        # « Grype (Anchore) » → « grype »
        return base.strip().replace("-", "_").replace(" ", "_").strip("_ ")

    fiches.sort(key=lambda f: (-f["valeur_pour_agnt"]["priorite"], f["nom"].lower()))
    for f in fiches:
        f["deja_integre"] = (normalise(f["nom"]) in deja_integres
                             or f["owner_repo"].lower() in depots_epingles)
        if f["deja_integre"]:
            f["candidat_integration"] = False
            f["valeur_pour_agnt"]["motif_declassement"] = (
                "déjà porté par un provider du registre : rien à proposer, tout à vérifier")
    for f in fiches:
        if not f["candidat_integration"]:
            f["valeur_pour_agnt"]["priorite"] = round(f["valeur_pour_agnt"]["priorite"] * 0.25, 4)
            f["valeur_pour_agnt"]["motif_declassement"] = (
                f"rôle Phase 1 « {f['role_phase1']} » : concurrent ou lib, pas un provider — "
                "inventorié, mais hors file d'intégration")
    fiches.sort(key=lambda f: (-f["valeur_pour_agnt"]["priorite"], f["nom"].lower()))
    return {"fiches": fiches, "capacites_registre": cap_reg, "outils_epingles": epingles,
            "matrice_phase1": matrice_p1}


# ═════════════════════════════════════════════════════════════  les trois sorties
def _sha8(texte: str) -> str:
    return hashlib.sha256(texte.encode("utf-8")).hexdigest()[:12]


def sources() -> dict:
    """Empreinte de chaque entrée : la matrice est reproductible ou ne l'est pas."""
    out = {}
    for nom, chemin in (("catalogue", P1 / "07_CATALOGUE_INTEGRATION.csv"),
                        ("fiches", P1 / "08_FICHES_PROVIDERS.csv"),
                        ("notes", P1 / "NOTES.csv"),
                        ("matrice_phase1", P1 / "09_MATRICE_COUVERTURE_PROVIDERS.csv"),
                        ("registre", PHASE3 / "slice" / "capabilities.yaml"),
                        ("manifeste", PHASE3 / "manifeste_dependances.yaml")):
        out[nom] = _sha8(chemin.read_text(encoding="utf-8")) if chemin.exists() else "absent"
    return out


def _ligne_entree(cible: dict) -> str:
    return ("repository" if any(k in " ".join(cible["entree"]) for k in ("repo", "cible", "code"))
            else "url/hote" if cible["reseau_requis"] else "cible")


def pool_propositions(d: dict, top: int = 10) -> list[dict]:
    """La file des candidats à proposer, calculée SANS écrire.

    Un provider CLI dont on connaît le contrat de sortie d'abord. Les candidats `api` ou
    `mcp_server` (DefectDojo, Dependency-Track, IntelOwl, Cortex…) demandent un point
    d'écoute, un compte, un secret : ce n'est ni le même adaptateur ni le même régime de
    risque, et les mélanger dans la même file ferait passer une semaine de travail pour un
    quart d'heure. Ils restent inventoriés, avec ce motif écrit dans la matrice.
    """
    fiches = [x for x in d["fiches"] if x["candidat_integration"]
              and x["langage_forme"] in ("cli", "inconnu", "")]
    fiches.sort(key=lambda x: (x["format"] == "inconnu", -x["valeur_pour_agnt"]["priorite"],
                               x["nom"].lower()))
    return fiches[:top]


def rendu_proposition(f: dict) -> tuple[str, str]:
    """(nom de fichier, contenu) d'une proposition. Un SEUL rendu pour écrire et pour
    vérifier : deux rendus différents est la façon la plus sûre d'avoir une auto-vérification
    qui ne vérifie rien (mesuré sur la version précédente de ce script, qui régénérait les
    fichiers avant de les comparer — 0 dérive annoncé, deux fois).

    LA FORME EST CELLE DES PLUGINS (LOT 2, 30/08/2026). `plugins/*.yaml` est chargé,
    `plugins/propositions/*.yaml` ne l'est pas : la différence est le NOM du fichier, pas le
    format. Renommer le fichier est le seul geste qui reste quand les mesures ci-dessous sont
    levées — donc le document est écrit dans la grammaire du chargeur, et son verdict est
    RECALCULÉ à chaque génération par le chargeur lui-même, jamais recopié de la documentation
    de l'outil. Ce qui n'est pas mesuré ici n'est pas deviné : ni le nom du programme
    (`binaire`), ni le niveau de risque, ni le mapping de champs — ces absences sont des refus,
    et le refus écrit dans l'en-tête est l'instruction de travail.
    """
    import provider_manifest as PM
    import yaml
    cid = f["valeur_pour_agnt"]
    det = f["facilite_integration"]["detail"]
    cle = "".join(ch if ch.isalnum() else "_" for ch in f["nom"].strip().lower()).strip("_")
    fmt = str(f.get("format") or "").strip().lower()
    rendu = fmt if fmt in PM.FORMATS_SORTIE else ("custom" if f.get("parser") else "json")
    doc: dict = {
        "id": cle,
        "capacites": f["categories"] or ["CODE_STATIC_ANALYSIS"],
        "entrees": [_ligne_entree(f)],
        "sortie": {"format": rendu},
        "lecture": ({"modele": "plat"} if rendu in ("json", "sarif")
                    else {"modele": rendu if rendu in ("jsonl", "csv", "xml") else "custom"}),
        "requirements": dict({"reseau": bool(f["reseau_requis"]), "sandbox": True},
                             **({"privileges": "root requis"} if f.get("privileges_requis")
                                else {})),
        "licence": f["licence"],
        "a_verifier": [
            "binaire : quel programme lancer, avec quelle empreinte — à épingler dans "
            "manifeste_dependances.yaml (c'est LA porte, pas une formalité)",
            "risque : PASSIVE, ACTIVE ou EXPLOIT selon un run, jamais selon la documentation",
            "sortie : un run réel, puis `lecture.champs` mappé sur les clés réellement rendues",
            "codes de retour réels (beaucoup de scanners sortent 1 quand ils trouvent)",
        ],
    }
    if rendu in ("json", "sarif"):
        doc["a_verifier"].append(
            "`lecture.items_from` : la clé qui porte la liste des résultats, à lire dans la sortie")
    if rendu == "custom":
        doc["lecture"]["parser"] = str(f.get("parser") or cle)
        doc["a_verifier"].append(
            f"`parser: {doc['lecture']['parser']}` absent de `slice/parsers.py` — à écrire "
            "(un parser nommé est le second niveau de la promesse : aucun changement du cœur)")
    if f["reseau_requis"]:
        doc["a_verifier"].append(
            "egress : `reseau: true` sera REFUSÉ tant que l'autorisation d'export n'est pas "
            "accordée explicitement pour la mission — ne pas retirer cette garde pour faire "
            "passer l'outil")
    corps = yaml.safe_dump(doc, allow_unicode=True, sort_keys=False, width=96)
    limites = [str(x) for x in (f.get("limites_connues") or [])][:3]
    entete = ("# Proposition d'intégration — générée par PHASE3/inventaire_plateforme.py. "
              "NE PAS ÉDITER À LA MAIN.\n"
              "# PROPOSITION, PAS UN PLUGIN : `plugins/propositions/` n'est pas chargé par le "
              "runtime ;\n# le copier dans `plugins/` est le seul geste de plus — d'où une "
              "grammaire unique,\n# celle que `slice/plugins.py` lit.\n"
              f"# priorité {cid['priorite']} · valeur {det['valeur']} · complexité "
              f"{det['complexite']} · risque {f['risque']['note']} · preuve : {f['preuve']}\n"
              f"# dépôt amont : {f['repository']} · installation : {f['installation']} · licence "
              f"déclarée : {f['licence']}\n"
              f"# rôle pour AGNT : {str(f['fonction'])[:200]}\n"
              + "".join(f"# limite connue (Phase 1) : {x}\n" for x in limites)
              + ("" if limites else "# limite connue : aucune consignée dans la fiche Phase 1 — à "
                                    "vérifier au run\n")
              + f"# verdict du chargeur de plugins (recalculé, pas décrété) : "
                f"{_verdict_plugin(yaml.safe_load(corps), f'{cle}.yaml')}\n")
    return f"{cle}.yaml", entete + corps


def _verdict_plugin(doc: dict, nom: str) -> str:
    """Ce que le chargeur dirait de ce document — en lecture seule, sans rien écrire.

    Appeler le VRAI chargeur est le seul moyen que ce verdict reste vrai quand ses règles
    changent. Un verdict écrit à la main dans le générateur serait une attente déguisée en
    mesure — le défaut que `--verifier` de ce script a déjà fait tomber deux fois.
    """
    try:
        import plugins as PL
        return PL.verdict(doc, nom)
    except Exception as e:                          # noqa: BLE001
        return f"chargeur indisponible ({type(e).__name__}: {e})"


def rendus_propositions(d: dict, top: int = 10) -> dict[str, str]:
    return dict(rendu_proposition(f) for f in pool_propositions(d, top))


def ecrire_propositions(d: dict, top: int = 10) -> list[str]:
    rendus = rendus_propositions(d, top)
    PROPOSITIONS.mkdir(parents=True, exist_ok=True)
    for obsolete in PROPOSITIONS.glob("*.yaml"):
        obsolete.unlink()                 # sortie déterministe, jamais incrémentale
    for nom, contenu in rendus.items():
        (PROPOSITIONS / nom).write_text(contenu, encoding="utf-8")
    return sorted(rendus)


def verifier_propositions(d: dict, top: int = 10) -> list[str]:
    """Compare le disque au rendu ATTENDU, sans RIEN écrire."""
    derives = []
    attendus = rendus_propositions(d, top)
    presents = {f.name for f in PROPOSITIONS.glob("*.yaml")} if PROPOSITIONS.exists() else set()
    for nom in sorted(set(attendus) - presents):
        derives.append(f"plugins/propositions/{nom} : absent — à régénérer")
    for nom in sorted(presents - set(attendus)):
        derives.append(f"plugins/propositions/{nom} : fichier inconnu de la file "
                       "(édité à la main, ou résidu d'une source qui a changé)")
    for nom, contenu in sorted(attendus.items()):
        fichier = PROPOSITIONS / nom
        if fichier.exists() and fichier.read_text(encoding="utf-8") != contenu:
            derives.append(f"plugins/propositions/{nom} : contenu différent du rendu — "
                           "la source (Phase 1 ou registre) a bougé")
    return derives


def ecrire_matrice(d: dict) -> str:
    import yaml  # noqa: F401  (les propositions l'utilisent ; import conditionné au besoin)
    cap_reg = d["capacites_registre"]
    fiches = d["fiches"]
    epingles = d["outils_epingles"]
    par_cap: dict[str, list] = {}
    for f in fiches:
        for c in f["categories"]:
            par_cap.setdefault(c, []).append(f)
    lignes = [
        "# Inventaire de plateforme — capacités, candidats, priorités",
        "",
        "Généré par `python3 PHASE3/inventaire_plateforme.py`. **Ce fichier n'est pas une"
        " source de vérité d'exécution** : le registre (`slice/capabilities.yaml`) décide de ce"
        " qui tourne, ici on décide de ce qui *mérite* de l'être. Les empreintes des entrées sont"
        " écrites dans `inventaire/fiches.json` — une matrice qui diverge de ses sources se"
        " vérifie par `--verifier`.",
        "",
        "| entrée | empreinte |",
        "|---|---|",
    ]
    for nom, emp in sources().items():
        lignes.append(f"| {nom} | `{emp}` |")
    lignes += ["", "## Matrice des capacités", "",
               "| Capacité | dans AGNT | providers (passifs) | entrée | sortie | parser | sandbox | candidats |",
               "|---|---|---|---|---|---|---|---|"]
    for c in sorted(set(cap_reg) | set(par_cap)):
        info = cap_reg.get(c)
        cands = sorted(par_cap.get(c, []), key=lambda f: -f["valeur_pour_agnt"]["priorite"])[:4]
        lignes.append("| {} | {} | {} | {} | {} | {} | {} | {} |".format(
            c, "**oui**" if info else "absente",
            f"{len(info['providers'])} ({info['passifs']})" if info else "0",
            ", ".join(info["entree"]) if info else "—",
            (info["sortie"].split("/")[0] if info and info["sortie"] else "—"),
            "déclaratif ou parser nommé" if info else "à écrire",
            "bwrap, réseau coupé, cible en lecture seule" if info else "idem",
            ", ".join(f"{x['nom']} ({x['valeur_pour_agnt']['priorite']})" for x in cands) or "—"))
    absentes = sorted(c for c in par_cap if c not in cap_reg)
    sous = sorted(c for c, i in cap_reg.items() if i["passifs"] <= 1)
    lignes += ["", "## Capacités absentes du registre", ""]
    for c in absentes:
        n = len(par_cap.get(c, []))
        lignes.append(f"- **{c}** — {n} candidat(s) inventorié(s) en Phase 1 ; "
                      f"risque de capacité : {RISQUE_CAPACITE.get(EQUIVALENCES.get(c, c), 0)}.")
    lignes += ["", "## Capacités sous-équipées (un seul provider passif)", ""]
    for c in sous:
        lignes.append(f"- **{c}** : providers {', '.join(cap_reg[c]['providers'])} ; "
                      f"mode `{cap_reg[c]['mode'] or 'premier_passif'}`"
                      + (" — fan_out déjà déclaré, un second outil y est attendu"
                         if cap_reg[c]["mode"] == "fan_out" else ""))
    lignes += ["", "## Outils nommés dans la commande du 2026-08-30, état par rapport à l'inventaire", ""]
    lignes += ["", "| outil | intégré à AGNT | dans l'inventaire Phase 1 | format | priorité |",
               "|---|---|---|---|---|"]
    par_nom = {f["nom"].lower(): f for f in fiches}
    par_repo = {f["owner_repo"].lower(): f for f in fiches}
    integres = {str(k).lower().replace("-", "_") for k in epingles}
    for outil in sorted(OUTILS_DEMANDES):
        f = par_nom.get(outil) or par_repo.get(outil) or next(
            (x for k, x in par_nom.items() if outil.replace("-", "") in k.replace("-", "")), None)
        cle = outil.replace("-", "_")
        deja = cle in integres
        lignes.append("| {} | {} | {} | {} | {} |".format(
            outil, "oui" if deja else "non",
            f["nom"] if f else "**absent de l'inventaire Phase 1** — à sourcer avant d'intégrer",
            (f["format"] if f else "—"),
            (f.get("priorite_brute", f["valeur_pour_agnt"]["priorite"]) if f else "—")))
    lignes += ["", "> Un outil absent de l'inventaire n'est pas rejeté : il est **non sourcé**."
               " La règle de la Phase 1 (« ne pas cloner tout Internet ») tient tant que sa"
               " licence, son activité et son format de sortie n'ont pas été lus quelque part.", ""]
    lignes += ["", "## Recouvrements et doublons signalés par la Phase 1", ""]
    chev = {}
    for f in fiches:
        c = (f["chevauchement_phase1"] or "").strip()
        if c and c not in ("à évaluer", ""):
            chev.setdefault(c, []).append(f["nom"])
    for motif, noms in sorted(chev.items(), key=lambda kv: -len(kv[1]))[:8]:
        lignes.append(f"- `{motif}` : {', '.join(noms[:6])}")
    lignes += ["", "## File d'intégration (priorité = valeur / (1 + complexité + risque))", "",
               "| # | outil | capacité | format mesuré ? | réseau | privilèges | valeur | cx | risque | priorité |",
               "|---|---|---|---|---|---|---|---|---|---|"]
    for i, f in enumerate([x for x in fiches if x["candidat_integration"]][:25], 1):
        det = f["facilite_integration"]["detail"]
        lignes.append("| {} | {} | {} | {} | {} | {} | {} | {} | {} | **{}** |".format(
            i, f["nom"], ", ".join(f["categories"][:2]),
            "MESURÉ" if "MESURÉ" in f["preuve"] else ("connu" if f["format"] != "inconnu" else "à lire"),
            "oui" if f["reseau_requis"] else "non",
            "oui" if f["privileges_requis"] else "non", det["valeur"], det["complexite"],
            det["risque"],
            ("déjà intégré" if f.get("deja_integre") else f["valeur_pour_agnt"]["priorite"])))
    lignes += ["", "## Ce que ce tableau ne dit pas", "",
               "- Une priorité élevée n'autorise rien : l'outil doit être installé, épinglé par"
               " empreinte, passer la validation du manifeste, la policy, et le profil"
               " d'isolation. Un outil `reseau: true` reste **refusé** tant que l'export n'est pas"
               " autorisé explicitement pour la mission.",
               "- `format = à lire` signifie : personne n'a vu la sortie de cet outil sur cette"
               " machine. C'est le champ qui ment le plus vite, il est gardé explicite.",
               "- Les 112 autres entrées de la Phase 1 (rôles `inutile`, `doc`, `concurrent`) ne"
               " sont pas reprises : la Phase 1 a déjà tranché, et une matrice qui réhabilite les"
               " écartés sans argument n'est pas un inventaire, c'est un wish-list.", ""]
    return "\n".join(lignes)


def main(argv: list[str]) -> int:
    verifier = "--verifier" in argv
    d = construis()
    entetes = {"genere_par": "PHASE3/inventaire_plateforme.py", "empreintes_sources": sources(),
               "formule": "valeur / (1 + complexite + risque) — voir l'en-tête du script",
               "nb_fiches": len(d["fiches"]),
               "nb_candidats_integration": sum(1 for f in d["fiches"] if f["candidat_integration"])}
    contenu = json.dumps({"entete": entetes, "capacites_registre": d["capacites_registre"],
                          "fiches": d["fiches"]}, ensure_ascii=False, indent=1)
    matrice = ecrire_matrice(d)

    if verifier:
        # Mode lecture seule, volontairement : une vérification qui régénère ce qu'elle
        # compare ne peut conclure qu'à « tout va bien ». Les trois dérives possibles sont
        # donc testées contre le disque, pas contre la mémoire.
        derives = []
        if not FICHES_JSON.exists():
            derives.append("inventaire/fiches.json : absent")
        else:
            lu = json.loads(FICHES_JSON.read_text(encoding="utf-8"))
            if lu.get("entete", {}).get("empreintes_sources") != entetes["empreintes_sources"]:
                derives.append("inventaire/fiches.json : empreintes des sources différentes — "
                               "une entrée de la Phase 1 ou le registre a bougé, régénérer")
            if len(lu.get("fiches", [])) != len(d["fiches"]):
                derives.append(f"inventaire/fiches.json : {len(lu.get('fiches', []))} fiches "
                               f"sur disque, {len(d['fiches'])} attendues")
        if not MATRICE_MD.exists():
            derives.append("INVENTAIRE_PLATEFORME.md : absent")
        elif MATRICE_MD.read_text(encoding="utf-8").strip() != matrice.strip():
            derives.append("INVENTAIRE_PLATEFORME.md : diverge de ses sources — régénérer")
        derives += verifier_propositions(d)
        for l in derives:
            print("DÉRIVE ·", l)
        print(f"vérification (lecture seule) : {len(derives)} dérive(s)")
        return 1 if derives else 0

    FICHES_JSON.parent.mkdir(parents=True, exist_ok=True)
    FICHES_JSON.write_text(contenu + "\n", encoding="utf-8")
    MATRICE_MD.write_text(matrice, encoding="utf-8")
    propositions = ecrire_propositions(d)
    print(f"fiches : {len(d['fiches'])} · candidats intégrables : "
          f"{entetes['nb_candidats_integration']} · propositions écrites : {len(propositions)}")
    print("sorties : inventaire/fiches.json · INVENTAIRE_PLATEFORME.md · plugins/propositions/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
