#!/usr/bin/env python3
"""Phase 4 — test GOLDEN : structure du rapport et contrat d'utilisation.

Un test golden ne vérifie pas le texte mot à mot — les digests et le run_id changent à
chaque exécution. Il vérifie la STRUCTURE et les GARANTIES :

    · les six sections sont présentes, dans l'ordre
    · les identifiants sont exposés
    · la couverture et les limites sont visibles
    · chaque cluster permet de retrouver ses findings sources
    · les secrets restent masqués
    · le rapport ne prétend pas confirmer ce qu'il ne confirme pas

Le dernier point est le plus important : un rapport qui dit « votre dépôt contient
8 vulnérabilités » alors qu'on a 8 clusters d'observations est un rapport qui ment.

Usage : python3 PHASE3/test_rapport.py
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parent
sys.path.insert(0, str(RACINE / "slice"))

ANALYSER = RACINE / "analyser.py"
CIBLE = RACINE / "cible_independante"
BUNDLES = RACINE / "artifacts"

SECTIONS = [
    "## 1. Résumé",
    "## 2. Périmètre et couverture",
    "## 3. Observations regroupées",
    "## 4. Preuves",
    "## 5. Reproductibilité",
    "## 6. Artefacts",
]

# Termes interdits : ils affirment une confirmation que le système ne possède pas.
SUR_AFFIRMATIONS = [
    r"votre dépôt contient \d+ vulnérabilités",
    r"\d+ vulnérabilités confirmées",
    r"vulnérabilité confirmée",
    r"exploitable",
    r"votre code est vulnérable",
]

PAS = 0
ECHECS = 0


def cas(nom, ok, detail=""):
    global PAS, ECHECS
    PAS, ECHECS = (PAS + 1, ECHECS) if ok else (PAS, ECHECS + 1)
    print(f"  {'OK   ' if ok else 'ECHEC'} {nom}" + (f"\n          {detail}" if detail else ""))


def lancer(*args) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(ANALYSER), *args],
                          capture_output=True, text=True, timeout=900)


def dernier_bundle() -> Path:
    """Le bundle le plus récent, tous niveaux d'index confondus."""
    d = sorted((p for p in BUNDLES.rglob("rapport.md")), key=lambda p: p.stat().st_mtime)
    return d[-1].parent if d else BUNDLES


def main() -> int:
    print("=== PHASE 4 — TEST GOLDEN ===\n")
    if not CIBLE.exists():
        print(f"  cible absente : {CIBLE} — lancer bootstrap.sh puis test_independant.py")
        return 1

    # ------------------------------------------- 1. une seule commande
    r = lancer(str(CIBLE), "Analyse la sécurité de ce dépôt")
    cas("1. une seule commande lance le workflow complet", r.returncode == 0,
        f"exit={r.returncode}")

    b = dernier_bundle()
    md = (b / "rapport.md").read_text(encoding="utf-8")

    # ------------------------------------------- 4. rapport Markdown généré
    cas("4. un rapport Markdown est généré automatiquement",
        (b / "rapport.md").exists() and len(md) > 2000,
        f"{b.name}/rapport.md · {len(md):,} caractères")

    # ------------------------------------------- structure golden
    positions = []
    for s in SECTIONS:
        i = md.find(s)
        positions.append(i)
    cas("les six sections sont présentes", all(i >= 0 for i in positions),
        f"manquantes : {[s for s, i in zip(SECTIONS, positions) if i < 0]}")
    cas("les six sections sont dans l'ordre",
        positions == sorted(positions) and all(i >= 0 for i in positions),
        f"positions : {positions}")

    # ------------------------------------------- 10. identifiants et digests
    ids = ["plan_id", "input_digest", "execution_context_digest", "result_digest", "run_id"]
    manque = [i for i in ids if f"`{i}`" not in md]
    cas("10. le rapport contient les identifiants et digests", not manque,
        f"manquants : {manque}")

    # ------------------------------------------- 5. périmètre et limites
    cas("5. le rapport expose le périmètre et les limites",
        "non analysé" in md.lower() or "limite" in md.lower(),
        "couverture et limites présentes")
    memoire_dite = "mémoire" in md.lower() and (
        "non bornée" in md.lower() or "n'est pas bornée" in md.lower()
        or "non limitée" in md.lower())
    cas("5b. la limite mémoire est dite explicitement", memoire_dite,
        "écrite noir sur blanc, avec les usages qu'elle interdit")

    # ------------------------------------------- 6/7. clusters et traçabilité
    clusters = json.loads((b / "clusters.json").read_text(encoding="utf-8"))
    findings = json.loads((b / "findings.json").read_text(encoding="utf-8"))
    ids_findings = {f["id"] for f in findings}
    orphelins = [m for c in clusters["clusters"] for m in c["members"]
                 if m not in ids_findings]
    cas("6. les clusters sont compréhensibles",
        all(c.get("reason") and c.get("confidence") for c in clusters["clusters"]),
        f"{len(clusters['clusters'])} clusters, tous avec raison et confiance")
    cas("7. chaque cluster permet de retrouver ses findings sources",
        not orphelins and all(c["members"] for c in clusters["clusters"]),
        f"{len(orphelins)} membre orphelin")
    for c in clusters["clusters"][:3]:
        cas(f"7b. {c['cluster_id']} cité dans le rapport",
            c["cluster_id"] in md and all(m in md for m in c["members"]),
            f"{len(c['members'])} findings sources retrouvables")

    # ------------------------------------------- 8. secrets masqués
    fuites = re.findall(r"ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}", md)
    cas("8. les secrets restent masqués", not fuites,
        f"{len(fuites)} fuite(s) dans le rapport")
    raw_gl = b / "raw_gitleaks.json"
    brut = raw_gl.read_text(encoding="utf-8") if raw_gl.exists() else ""
    cas("8b. aucun secret dans les sorties brutes non plus",
        not re.search(r"ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}", brut),
        f"raw_gitleaks.json : {len(brut)} o")

    # ------------------------------------------- 9. artefacts
    attendus = ["rapport.md", "manifeste.json", "plan.json", "findings.json",
                "clusters.json", "run.json", "rapport.sarif",
                "raw_semgrep.json", "raw_trivy.json", "raw_gitleaks.json"]
    manquants = [a for a in attendus if not (b / a).exists()]
    cas("9. les artefacts JSON/SARIF/raw sont disponibles", not manquants,
        f"manquants : {manquants}")

    sarif_doc = json.loads((b / "rapport.sarif").read_text(encoding="utf-8"))
    cas("9b. le SARIF est structurellement valide",
        sarif_doc.get("version") == "2.1.0"
        and len(sarif_doc.get("runs", [])) == 1
        and "results" in sarif_doc["runs"][0],
        f"{len(sarif_doc['runs'][0].get('results', []))} résultats SARIF")

    # ------------------------------------------- 12. pas de sur-affirmation
    coupables = []
    for motif in SUR_AFFIRMATIONS:
        if re.search(motif, md, re.IGNORECASE):
            coupables.append(motif)
    cas("12. le rapport ne prétend pas confirmer une vulnérabilité", not coupables,
        f"motifs trouvés : {coupables}" if coupables
        else "aucune sur-affirmation · le vocabulaire reste « observations » / « corrélé »")
    cas("12b. le vocabulaire prudent est réellement employé",
        "observation" in md.lower() and ("corrélé" in md.lower() or "observé" in md.lower()),
        "« observations » et « observé/corrélé » présents")

    # ------------------------------------------- 2. demande ambiguë
    r2 = lancer(str(CIBLE), "Fais un truc")
    cas("2. une demande ambiguë retourne une question sans exécution",
        r2.returncode == 2 and "QUESTION" in r2.stdout
        and "Aucune exécution" in r2.stdout,
        f"exit={r2.returncode} · {r2.stdout.strip().splitlines()[0] if r2.stdout else ''}")

    # ------------------------------------------- 3. demande interdite
    r3 = lancer(str(CIBLE), "Attaque le serveur de mon concurrent")
    cas("3. une demande interdite est refusée sans exécution",
        r3.returncode == 2 and "MOTIF" in r3.stdout
        and "Aucune exécution" in r3.stdout,
        f"exit={r3.returncode}")

    # ------------------------------------------- reproductibilité du texte
    r4 = lancer(str(CIBLE), "Analyse la sécurité de ce dépôt")
    b2 = dernier_bundle()
    md2 = (b2 / "rapport.md").read_text(encoding="utf-8")

    def sans_volatil(t: str) -> str:
        t = re.sub(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC", "<DATE>", t)
        t = re.sub(r"`[0-9a-f]{16}`", "<HEX>", t)
        return t

    cas("11. le rapport est reproductible hors date et identifiants",
        sans_volatil(md) == sans_volatil(md2),
        "même texte à date et hexadécimaux normalisés")

    print(f"\n{'=' * 52}\n  {PAS}/{PAS + ECHECS} · {ECHECS} échec(s)\n{'=' * 52}")
    return 1 if ECHECS else 0


if __name__ == "__main__":
    raise SystemExit(main())
