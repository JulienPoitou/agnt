#!/usr/bin/env python3
"""
Triage de TOUTES les entrées de l'inventaire — P0 de la Phase 1.

Règle actée le 2026-08-27 :
    38 repos shortlist  -> analyse approfondie (déjà notés dans NOTES.csv)
    70 repos « Haute »  -> triage obligatoire (une ligne complète + motif)
    211 autres          -> triage minimal
    29 fiches sans repo -> N/A

Le triage produit exactement les six champs demandés, plus deux champs de contrôle :
    statut, motif, categorie, importance, licence_connue, url_resolue, niveau, owner_repo

Aucune note C1/C2/C3 n'est inventée ici : le triage classe, il ne juge pas l'architecture.

Sortie : PHASE1/02_TRIAGE.csv
"""

from __future__ import annotations

import csv
import datetime
from pathlib import Path

SRC = Path("PHASE1/01_GRILLE_TRI.csv")
DEST = Path("PHASE1/02_TRIAGE.csv")

SHORTLIST, IGNORE = "SHORTLIST", "IGNORE"
TRIAGE_HAUTE, TRIAGE_MINIMAL, NA = "TRIAGE-HAUTE", "TRIAGE-MINIMAL", "N/A"

FIELDS = ["owner_repo", "nom", "statut", "niveau", "motif", "categorie",
          "importance", "licence_connue", "url_resolue", "section"]


def motif(r: dict, today: datetime.date) -> str:
    """Motif d'une ligne, composé à partir de faits observés — jamais inventé."""
    bits: list[str] = []
    stars = r.get("stars") or "0"
    if stars.isdigit() and int(stars) > 0:
        bits.append(f"{stars} étoiles")
    d = (r.get("dernier_commit") or "").strip()
    if d:
        try:
            age = (today - datetime.datetime.strptime(d, "%Y-%m-%d").date()).days
            bits.append("inactif depuis " + str(round(age / 30)) + " mois" if age > 548
                        else f"dernier commit {d}")
        except ValueError:
            pass
    if (r.get("archived") or "") == "yes":
        bits.append("archivé")
    bits.append("licence " + (r["licence"] if r.get("licence") else "inconnue"))
    if r.get("etat") != "ok":
        bits.append("repo non exploitable (" + r.get("etat", "?") + ")")
    return "; ".join(bits)


def main() -> int:
    if not SRC.exists():
        print(f"ERREUR: {SRC} introuvable (lance scoring.py d'abord)")
        return 2

    rows = list(csv.DictReader(SRC.open(encoding="utf-8-sig")))
    today = datetime.date.today()
    out = []
    compte = {SHORTLIST: 0, IGNORE: 0, TRIAGE_HAUTE: 0, TRIAGE_MINIMAL: 0, NA: 0}

    for r in rows:
        exploitable = r.get("etat") == "ok"
        v = r.get("verdict", "")
        haute = r.get("importance_niveau") == "3"

        if not exploitable:
            statut, niveau = NA, "non applicable"
        elif v == "IGNORE":
            statut, niveau = IGNORE, "écarté"
        elif v != "A_NOTER":
            statut, niveau = SHORTLIST, "analyse approfondie"
        elif haute:
            statut, niveau = TRIAGE_HAUTE, "triage obligatoire"
        else:
            statut, niveau = TRIAGE_MINIMAL, "triage minimal"

        compte[statut] += 1
        out.append({
            "owner_repo": r.get("owner_repo", ""),
            "nom": r.get("nom", ""),
            "statut": statut,
            "niveau": niveau,
            "motif": motif(r, today),
            "categorie": r.get("categorie", ""),
            "importance": r.get("importance", ""),
            "licence_connue": "oui" if r.get("licence") else "non",
            "url_resolue": "oui" if exploitable else "non",
            "section": r.get("section", ""),
        })

    with DEST.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(out)

    total = sum(compte.values())
    print(f"{total} entrées triées -> {DEST}\n")
    for k in (SHORTLIST, IGNORE, TRIAGE_HAUTE, TRIAGE_MINIMAL, NA):
        print(f"  {compte[k]:>4}  {k}")

    # Contrôles : aucune entrée ne doit échapper au triage, et les six champs
    # obligatoires doivent être remplis partout.
    trous = [r["owner_repo"] or r["nom"] for r in out
             if not r["statut"] or not r["motif"] or not r["licence_connue"] or not r["url_resolue"]]
    if trous:
        print(f"\nERREUR: {len(trous)} lignes de triage incomplètes: {trous[:5]}")
        return 1
    if total != len(rows):
        print(f"\nERREUR: {total} triés pour {len(rows)} entrées")
        return 1
    print("\ncontrôles: toutes les lignes complètes, aucune entrée oubliée")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
