#!/usr/bin/env python3
"""
Constitue un profil compact par repo de la shortlist, pour permettre de noter C1
(qualité d'architecture) sur pièces plutôt que sur réputation.

Pour chaque repo : README (tronqué) + arborescence de premier niveau extraite du
payload JSON de la page GitHub. Sortie : PHASE1/.profils/{owner__repo}.txt
"""

from __future__ import annotations

import asyncio
import json
import re
import sys
import time
from pathlib import Path

try:
    import httpx
except ImportError:
    raise SystemExit("pip install httpx")

OUT = Path("PHASE1/.profils")
CONCURRENCY = 5
UA = "Mozilla/5.0 (X11; Linux x86_64) phase1-profiling"
README_MAX = 3400

# Fichier embarqué dans la page repo : contient defaultBranch + arbre de fichiers
EMBEDDED_RE = re.compile(r'"defaultBranch"\s*:\s*"([^"]+)"')
PATHS_RE = re.compile(r'"path"\s*:\s*"([^"]{1,120})"')


async def get(c: httpx.AsyncClient, url: str, sem: asyncio.Semaphore, raw: bool = False):
    async with sem:
        for attempt in range(3):
            try:
                r = await c.get(url, timeout=30)
                if r.status_code == 200:
                    return r.text if raw else r.text
                if r.status_code in (403, 429):
                    await asyncio.sleep(3 * (attempt + 1))
                    continue
                return None
            except httpx.HTTPError:
                await asyncio.sleep(2 * (attempt + 1))
    return None


async def profile(c: httpx.AsyncClient, repo: str, sem: asyncio.Semaphore) -> None:
    dest = OUT / f"{repo.replace('/', '__')}.txt"
    if dest.exists():
        return
    page = await get(c, f"https://github.com/{repo}", sem)
    if not page:
        dest.write_text(f"# {repo}\n\n(page inaccessible)\n", encoding="utf-8")
        return

    m = EMBEDDED_RE.search(page)
    branch = m.group(1) if m else "main"

    readme = None
    for b in (branch, "main", "master"):
        for name in ("README.md", "readme.md", "README.rst", "README"):
            readme = await get(c, f"https://raw.githubusercontent.com/{repo}/{b}/{name}", sem, raw=True)
            if readme and len(readme) > 80:
                break
        if readme:
            break

    paths = []
    seen = set()
    for p in PATHS_RE.findall(page):
        top = p.split("/")[0]
        if top not in seen and not top.startswith("."):
            seen.add(top)
            paths.append(p)
        if len(paths) > 70:
            break

    readme = (readme or "(README introuvable)")[:README_MAX]
    readme = re.sub(r"!\[[^\]]*\]\([^)]*\)", "", readme)          # images
    readme = re.sub(r"<[^>]{1,120}>", "", readme)                  # html
    readme = re.sub(r"\n{3,}", "\n\n", readme)

    dest.write_text(
        f"# {repo}  (branche {branch})\n\n## ARBORESCENCE (1er niveau)\n"
        + "\n".join(paths[:70])
        + f"\n\n## README (tronqué à {README_MAX} car.)\n\n{readme}\n",
        encoding="utf-8",
    )


async def main(repos: list[str]) -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    sem = asyncio.Semaphore(CONCURRENCY)
    t0 = time.time()
    async with httpx.AsyncClient(headers={"User-Agent": UA}, follow_redirects=True) as c:
        await asyncio.gather(*(profile(c, r, sem) for r in repos))
    n = len(list(OUT.glob("*.txt")))
    print(f"{n} profils écrits dans {OUT} en {time.time() - t0:.0f}s")
    return 0


if __name__ == "__main__":
    src = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("PHASE1/SHORTLIST_REPOS.txt")
    if not src.exists():
        raise SystemExit(f"liste introuvable: {src}")
    repos = [l.strip() for l in src.read_text(encoding="utf-8").splitlines()
             if l.strip() and not l.startswith("#")]
    raise SystemExit(asyncio.run(main(repos)))
