#!/usr/bin/env python3
"""
Parse `uploads/liste complete.txt` en inventaire CSV exploitable.

Le fichier source est un empilement de fiches de la forme :

    Nom de l'outil
    Catégorie : ...
    (ligne vide)
    Description :
    ...texte...
    (ligne vide)
    GitHub : https://github.com/owner/repo
    (ligne vide)
    Importance : ⭐ Haute

précédé par des en-têtes de section (`🔵 Defensive / Blue Team`).
Le fichier contient plusieurs passes successives : les mêmes sections reviennent,
donc des doublons existent. Ce script les détecte au lieu de les masquer.

Sortie : PHASE1/00_INVENTAIRE.csv
"""

from __future__ import annotations

import csv
import re
import sys
from collections import Counter, OrderedDict
from pathlib import Path

SRC = Path("uploads/liste complete.txt")
DEST = Path("PHASE1/00_INVENTAIRE.csv")

SECTION_RE = re.compile(
    r"^(?:\[[^\]]+\]\s*)?"                       # préfixes type [1] éventuels
    r"((?:🔵|🟢|🟠|🟣|🔴|🟡|🟤|⚪|⚫|🟥|🟦)\s+.+)$"  # en-tête de section avec pastille
)
CAT_RE = re.compile(r"^Catégorie\s*:\s*(.+?)\s*$")
GH_RE = re.compile(r"^GitHub\s*:\s*(\S+)")
IMP_RE = re.compile(r"^Importance\s*:\s*(.+?)\s*$")
DESC_RE = re.compile(r"^Description\s*:")

# Normalise une URL GitHub en owner/repo
GH_URL_RE = re.compile(r"github\.com[:/]([^/\s]+)/([^/\s#?]+)", re.I)

IMP_LEVEL = {"haute": 3, "moyenne": 2, "faible": 1}


def importance_level(raw: str) -> int:
    low = raw.lower()
    for key, val in IMP_LEVEL.items():
        if key in low:
            return val
    return 2  # non reconnu -> neutre, signalé


def norm_name(name: str) -> str:
    n = re.sub(r"[\s\-\u2013_]+", "", name.lower())
    n = re.sub(r"[^a-z0-9]", "", n)
    return n


def main() -> int:
    if not SRC.exists():
        print(f"ERREUR: {SRC} introuvable", file=sys.stderr)
        return 2

    lines = [l.rstrip("\r\n") for l in SRC.read_text(encoding="utf-8", errors="replace").splitlines()]

    entries: list[dict] = []
    section = "(sans section)"
    cur: dict | None = None
    pending_desc = False

    def flush() -> None:
        nonlocal cur
        if cur is None:
            return
        cur["description"] = re.sub(r"\s+", " ", cur["description"]).strip()
        entries.append(cur)
        cur = None

    for i, raw in enumerate(lines):
        line = raw.strip()

        m = SECTION_RE.match(line)
        if m and not line.startswith(("Catégorie", "GitHub", "Importance")):
            flush()
            section = re.sub(r"\s+", " ", m.group(1)).strip()
            continue

        m = CAT_RE.match(line)
        if m:
            # une fiche démarre toujours par "Catégorie :" ; le nom est la ligne précédente
            name = ""
            for back in range(i - 1, max(i - 4, -1), -1):
                cand = lines[back].strip()
                if cand and not SECTION_RE.match(cand) and not DESC_RE.match(cand):
                    name = cand
                    break
            flush()
            cur = {
                "nom": re.sub(r"\s+", " ", name).strip(),
                "section": section,
                "categorie": m.group(1),
                "github": "",
                "owner_repo": "",
                "importance": "",
                "importance_niveau": "",
                "description": "",
                "statut": "",
            }
            pending_desc = False
            continue

        if cur is None:
            continue

        m = GH_RE.match(line)
        if m:
            cur["github"] = m.group(1)
            mu = GH_URL_RE.search(m.group(1))
            if mu:
                repo = mu.group(2)
                if repo.endswith(".git"):
                    repo = repo[:-4]
                cur["owner_repo"] = f"{mu.group(1)}/{repo}".rstrip("/")
            pending_desc = False
            continue

        m = IMP_RE.match(line)
        if m:
            cur["importance"] = m.group(1)
            cur["importance_niveau"] = importance_level(m.group(1))
            pending_desc = False
            continue

        if DESC_RE.match(line):
            pending_desc = True
            continue

        if pending_desc and line:
            cur["description"] += " " + line

    flush()

    # --- dédoublonnage : même owner/repo, ou à défaut même nom normalisé ---
    seen: "OrderedDict[str, dict]" = OrderedDict()
    dupes: list[str] = []
    no_gh: list[dict] = []

    for e in entries:
        key = e["owner_repo"] or "name:" + norm_name(e["nom"])
        if not e["owner_repo"]:
            no_gh.append(e)
        if key in seen:
            dupes.append(f"{e['nom']} ({e['section']}) -> déjà présent via {seen[key]['section']}")
            # on garde l'importance la plus élevée et on accumule les sections
            prev = seen[key]
            prev["sections_multiples"] = prev.get("sections_multiples", "")
            if prev["section"] not in prev["sections_multiples"]:
                prev["sections_multiples"] = prev["section"]
            prev["sections_multiples"] += " | " + e["section"]
            if int(e["importance_niveau"] or 0) > int(prev["importance_niveau"] or 0):
                prev["importance"] = e["importance"]
                prev["importance_niveau"] = e["importance_niveau"]
            continue
        seen[key] = e

    fields = [
        "nom", "owner_repo", "github", "section", "sections_multiples", "categorie",
        "importance", "importance_niveau", "statut", "description",
    ]
    DEST.parent.mkdir(parents=True, exist_ok=True)
    with DEST.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        for e in seen.values():
            e.setdefault("sections_multiples", "")
            w.writerow(e)

    print(f"Fiches brutes lues      : {len(entries)}")
    print(f"Doublons fusionnés      : {len(dupes)}")
    print(f"Entrées uniques         : {len(seen)}")
    print(f"Sans URL GitHub valide  : {len(no_gh)}")
    print(f"Sortie                  : {DEST}")

    print("\n--- répartition par section (après dédoublonnage) ---")
    for sec, n in Counter(e["section"] for e in seen.values()).most_common():
        print(f"  {n:>4}  {sec}")

    print("\n--- répartition par importance ---")
    for lvl, n in sorted(Counter(int(e["importance_niveau"] or 0) for e in seen.values()).items(), reverse=True):
        print(f"  {n:>4}  niveau {lvl}")

    if no_gh:
        print("\n--- entrées sans URL GitHub (à traiter à la main) ---")
        for e in no_gh[:25]:
            print(f"  {e['nom']}  [{e['section']}]  github='{e['github']}'")
        if len(no_gh) > 25:
            print(f"  ... et {len(no_gh) - 25} autres")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
