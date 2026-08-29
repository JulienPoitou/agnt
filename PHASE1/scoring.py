#!/usr/bin/env python3
"""
Applique le barème de PHASE1/CRITERES.md à l'inventaire enrichi.

Séparation volontaire :
  - 00_INVENTAIRE_ENRICHI.csv  = les FAITS (stars, commit, licence, archived), régénérables
  - PHASE1/NOTES.csv           = le JUGEMENT (C1/C2/C3 + motif), saisi à la main

Ce script croise les deux. Il n'invente aucune note : un repo sans C1/C2/C3 sort en
verdict A_NOTER. Ce qu'il calcule, ce sont les règles mécaniques du barème :
les gates et le passage score -> verdict.

Usage :
    python3 PHASE1/scoring.py [-i 00_INVENTAIRE_ENRICHI.csv] [-n NOTES.csv] [-o 01_GRILLE_TRI.csv]
"""

from __future__ import annotations

import argparse
import csv
import sys
from datetime import date, datetime
from pathlib import Path

POIDS = {"C1": 0.50, "C2": 0.30, "C3": 0.20}
STALE_DAYS = 548  # ~18 mois -> gate G1

LICENSE_BLOCKING = {"", "none", "no license", "custom", "proprietary", "commercial", "other"}
LICENSE_COPYLEFT_FORT = {"agpl-3.0", "agpl3", "agpl-3.0-only", "agpl-3.0-or-later", "sspl",
                         "sspl-1.0", "busl-1.1", "busl"}
LICENSE_COPYLEFT = {"gpl-2.0", "gpl-3.0", "lgpl-2.1", "lgpl-3.0", "mpl-2.0"}


def parse_date(raw: str) -> date | None:
    raw = (raw or "").strip()
    if not raw:
        return None
    for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%Y-%m", "%Y"):
        try:
            return datetime.strptime(raw, fmt).date()
        except ValueError:
            continue
    return None


def score(c1, c2, c3, penalite: str | int = "") -> float | None:
    """Score pondéré sur 5. None si une note manque — jamais de note inventée.

    `penalite` implémente le signal G3 (supply chain) : -1 au score, et UNIQUEMENT
    lorsqu'un problème est confirmé par une lecture. Vide par défaut, donc aucun
    repo n'est pénalisé sans preuve — CRITERES.md §2.2.
    """
    try:
        vals = {"C1": float(c1), "C2": float(c2), "C3": float(c3)}
    except (TypeError, ValueError):
        return None
    for k, v in vals.items():
        if not 0 <= v <= 5:
            raise ValueError(f"{k}={v} hors plage 0..5")
    try:
        pen = float(penalite) if str(penalite).strip() != "" else 0.0
    except ValueError:
        raise ValueError(f"penalite invalide: {penalite!r}")
    return round(max(0.0, sum(POIDS[k] * vals[k] for k in POIDS) - pen), 2)


def gate_g1(dernier_commit: str, today: date) -> str:
    d = parse_date(dernier_commit)
    if d is None:
        return ""
    return "G1:inactif" if (today - d).days > STALE_DAYS else ""


def gate_g2(licence: str) -> str:
    lic = (licence or "").strip().lower()
    if not lic or lic in LICENSE_BLOCKING:
        return "G2:licence-inconnue"
    if lic in LICENSE_COPYLEFT_FORT:
        return "G2:copyleft-fort"
    if lic in LICENSE_COPYLEFT:
        return "G2:copyleft"
    return ""


def gate_g5(archived: str) -> str:
    """Repo archivé = lecture seule : ni INTEGRATE ni réutilisation de code.

    Distincte de G1 : un repo peut avoir été archivé hier. La date de commit seule
    ne suffit pas — 14 repos de l'inventaire sont archivés avec un commit récent.
    """
    return "G5:archive" if (archived or "").strip().lower() == "yes" else ""


# Usages pour lesquels une gate de licence (G2) s'applique réellement — CRITERES.md §2.1.
# Piloter un outil en CLI ne demande aucune licence compatible ; importer son code si.
USAGE_BLOQUE_PAR_G2 = {"code réutilisable", "composant d'infrastructure"}


def verdict(c1, total: float | None, gates: list[str], usage: str = "") -> str:
    """
    Passe le score au verdict. CRITERES.md §3 et §5.

    Ordre de décision :
      1. l'usage prévu prime — une "référence architecturale" n'est jamais INTEGRATE,
         puisqu'on ne l'exécute ni ne l'importe ;
      2. G1 (inactif) et G5 (archivé) bloquent INTEGRATE et ADAPT-code dans tous les cas ;
      3. G2 (licence) ne bloque que si l'usage touche au code — piloter un outil en CLI
         ne demande aucune licence compatible ;
      4. à usage et gates égaux, le score pondéré décide, C1 départage.
    """
    try:
        c1v = float(c1)
    except (TypeError, ValueError):
        return "A_NOTER"
    if total is None:
        return "A_NOTER"

    u = usage.strip()

    # 1. Écarté d'abord : un repo faible ne devient pas une référence d'architecture
    #    sous prétexte qu'on ne l'importe pas.
    if total <= 3.0 and c1v < 4:
        return "IGNORE"

    # 2. On ne fait que lire le repo : on ne l'intègre pas, on en reproduit l'architecture.
    if u == "référence architecturale":
        return "ADAPT (archi)"

    # 3. Gates. G1/G5 bloquent toujours ; G2 seulement si l'usage touche au code.
    dur = any(g.startswith(("G1", "G5")) for g in gates)
    lic = any(g.startswith("G2") for g in gates) and u in USAGE_BLOQUE_PAR_G2
    blocked = dur or lic

    # 4. Score.
    if total >= 4.0 and c1v >= 4:
        return "ADAPT (archi)" if blocked else "INTEGRATE"
    if total > 3.0:
        return "ADAPT (archi)" if (blocked and c1v >= 4) else "ADAPT"
    return "ADAPT (archi)" if c1v >= 4 else "IGNORE"


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-i", "--inventaire", default="PHASE1/00_INVENTAIRE_ENRICHI.csv")
    ap.add_argument("-n", "--notes", default="PHASE1/NOTES.csv")
    ap.add_argument("-o", "--output", default="PHASE1/01_GRILLE_TRI.csv")
    args = ap.parse_args(argv)

    inv_path, notes_path = Path(args.inventaire), Path(args.notes)
    if not inv_path.exists():
        print(f"ERREUR: inventaire introuvable: {inv_path}", file=sys.stderr)
        return 2

    rows = list(csv.DictReader(inv_path.open(encoding="utf-8-sig")))
    if not rows:
        print("ERREUR: inventaire vide.", file=sys.stderr)
        return 2

    notes: dict[str, dict] = {}
    if notes_path.exists():
        for n in csv.DictReader(notes_path.open(encoding="utf-8-sig")):
            key = n.get("owner_repo", "").strip().lower()
            if key:
                notes[key] = n
    else:
        print(f"(avertissement) {notes_path} absent : tout sortira en A_NOTER", file=sys.stderr)

    today = date.today()
    out = []
    for r in rows:
        n = notes.get((r["owner_repo"] or "").strip().lower(), {})
        # Les gates ne s'appliquent qu'à un vrai repo. Une fiche « outil propriétaire »,
        # « agrégat » ou « URL en 404 » n'a pas de code : lui coller G2:licence-inconnue
        # serait du bruit. 15 entrées étaient concernées.
        eligible = r.get("etat") == "ok"
        gates = [g for g in (gate_g1(r.get("dernier_commit", ""), today),
                             gate_g2(r.get("licence", "")),
                             gate_g5(r.get("archived", ""))) if g] if eligible else []
        c1, c2, c3 = n.get("C1", ""), n.get("C2", ""), n.get("C3", "")
        usage, mode = n.get("usage", ""), n.get("mode_integration", "")
        confiance, preuve, pen = n.get("confiance", ""), n.get("preuve", ""), n.get("penalite", "")
        total = score(c1, c2, c3, pen)
        row = dict(r)
        row.update({
            "C1": c1, "C2": c2, "C3": c3, "usage": usage, "mode_integration": mode,
            "confiance": confiance, "preuve": preuve, "penalite": pen,
            "score": "" if total is None else total,
            "gate": ";".join(gates),
            "verdict": verdict(c1, total, gates, usage),
            "motif": n.get("motif", ""),
        })
        out.append(row)

    dest = Path(args.output)
    dest.parent.mkdir(parents=True, exist_ok=True)
    fields = list(out[0].keys())
    with dest.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows(out)

    # Une note qui ne correspond à aucune ligne de l'inventaire est une erreur : elle ne
    # serait jamais lue. On échoue bruyamment plutôt que de la laisser dormir dans NOTES.csv.
    apparies = {(r["owner_repo"] or "").strip().lower() for r in rows}
    orphelins = sorted(k for k in notes if k not in apparies)
    if orphelins:
        print("ERREUR: notes orphelines (owner_repo absent de l'inventaire) :", file=sys.stderr)
        for o in orphelins:
            print(f"   - {o}", file=sys.stderr)
        return 1

    notees = [r for r in out if r["verdict"] != "A_NOTER"]
    from collections import Counter
    print(f"{len(out)} entrées | notées : {len(notees)} | en attente : {len(out) - len(notees)}")
    if notees:
        print("--- verdicts ---")
        for k, v in Counter(r["verdict"] for r in notees).most_common():
            print(f"  {v:>4}  {k}")
        print("--- gates ---")
        for k, v in Counter(g for r in out for g in (r["gate"].split(";") if r["gate"] else [])).most_common():
            print(f"  {v:>4}  {k}")
    print(f"Grille : {dest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
