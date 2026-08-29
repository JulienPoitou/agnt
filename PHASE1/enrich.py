#!/usr/bin/env python3
"""
Enrichit PHASE1/00_INVENTAIRE.csv avec les métadonnées GitHub réelles.

Pourquoi pas l'API : api.github.com est limité à 60 req/h en non authentifié, et il y a
333 repos. Les pages github.com et les flux Atom ne renvoient aucun header de quota
(vérifié le 2026-08-27 : HTTP 200, aucun x-ratelimit, 0,13-0,64 s/page).

Deux requêtes par repo :
  1. GET github.com/{repo}             -> stargazerCount, licence SPDX, archived, 404
  2. GET github.com/{repo}/commits/HEAD.atom -> date exacte du dernier commit

Parallélisme volontairement bas (6) + cache local : le script est rejouable sans
re-requêter ce qui est déjà connu.

Sortie : PHASE1/00_INVENTAIRE_ENRICHI.csv
"""

from __future__ import annotations

import asyncio
import csv
import html as html_mod
import json
import re
import sys
import time
from datetime import date, datetime
from pathlib import Path

try:
    import httpx
except ImportError:
    print("httpx manquant -> pip install httpx", file=sys.stderr)
    raise SystemExit(3)

SRC = Path("PHASE1/00_INVENTAIRE.csv")
DEST = Path("PHASE1/00_INVENTAIRE_ENRICHI.csv")
CACHE = Path("PHASE1/.cache_meta.json")

# Version du parseur : le cache stocke des VALEURS extraites, donc toute modification de
# parse_page() doit incrémenter ce nombre, sinon le cache ressert les anciennes valeurs.
PARSER_VERSION = 3
CONCURRENCY = 6
TIMEOUT = 30.0
UA = "Mozilla/5.0 (X11; Linux x86_64) phase1-inventory-analysis/1.0"

STARS_RE = re.compile(r'"stargazerCount"\s*:\s*(\d+)')
SPDX_RE = re.compile(r'"spdxId"\s*:\s*"([A-Za-z0-9.\-]+)"')
LICENSE_NAME_RE = re.compile(r'"license"\s*:\s*\{[^{}]*?"name"\s*:\s*"([^"]{2,60})"')
# Identifiants de licence réellement présents sur GitHub. Hors de cette liste, on ne
# devine rien : une mauvaise licence ferait basculer la gate G2 à tort.
KNOWN_LICENSES = {
    "mit", "apache", "agpl", "gpl", "lgpl", "bsd", "mpl", "cc0", "unlicense",
    "epl", "isc", "artistic", "zlib", "boost", "osl", "eupl", "sspl", "busl",
    "npl", "postgresql", "python", "wtfpl", "ncsa", "ofl", "lgpl-2.1", "lgpl-3.0",
}
LIC_TEXT_RE = re.compile(r"\b([A-Za-z0-9][A-Za-z0-9.\-]{1,29})\s+license\b", re.I)


STOPWORDS = {"actual", "current", "the", "a", "an", "this", "new", "full", "official",
             "same", "our", "its", "original", "complete", "entire", "following",
             "free", "other", "unknown", "custom", "proprietary", "commercial", "startup"}


def _looks_like_license(tok: str) -> bool:
    t = tok.lower()
    if t in STOPWORDS:
        return False
    return any(t.startswith(k) for k in KNOWN_LICENSES)


ARCHIVED_RE = re.compile(r"Public archive|This repository has been archived", re.I)
UPDATED_RE = re.compile(r"<updated>([^<]+)</updated>")


def load_cache() -> dict:
    if CACHE.exists():
        try:
            data = json.loads(CACHE.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}
        if data.get("__version__") != PARSER_VERSION:
            print(f"  cache invalide (parser v{data.get('__version__')} != v{PARSER_VERSION}) -> régénéré")
            return {"__version__": PARSER_VERSION}
        return data
    return {"__version__": PARSER_VERSION}


def save_cache(cache: dict) -> None:
    CACHE.write_text(json.dumps(cache, ensure_ascii=False), encoding="utf-8")


async def get(client: httpx.AsyncClient, url: str, sem: asyncio.Semaphore) -> tuple[int, str]:
    async with sem:
        for attempt in range(4):
            try:
                r = await client.get(url, timeout=TIMEOUT)
                if r.status_code in (403, 429) or r.status_code >= 500:
                    wait = float(r.headers.get("Retry-After", 2 ** attempt))
                    await asyncio.sleep(min(wait, 30))
                    continue
                return r.status_code, r.text
            except httpx.HTTPError:
                await asyncio.sleep(2 ** attempt)
        return 0, ""


def parse_page(html: str) -> dict:
    html = html_mod.unescape(html)  # &gt; &amp; &quot; cassent les regex sinon
    stars = STARS_RE.search(html)
    spdx = [s for s in SPDX_RE.findall(html) if s != "NOASSERTION"]
    lic = spdx[0] if spdx else ""
    if not lic:
        ln = LICENSE_NAME_RE.search(html)
        if ln and _looks_like_license(ln.group(1).split()[0]):
            lic = ln.group(1).split()[0]
    if not lic:
        for t in LIC_TEXT_RE.finditer(html):
            if _looks_like_license(t.group(1)):
                lic = t.group(1)
                break
    return {
        "stars": int(stars.group(1)) if stars else "",
        "licence": "" if lic == "NOASSERTION" else lic,
        "archived": "yes" if ARCHIVED_RE.search(html) else "",
    }


def parse_atom(xml: str) -> str:
    ups = UPDATED_RE.findall(xml)
    if len(ups) < 2:
        return ""
    try:
        return datetime.fromisoformat(ups[1].replace("Z", "+00:00")).strftime("%Y-%m-%d")
    except ValueError:
        return ""


async def enrich(repos: list[str], cache: dict) -> dict:
    sem = asyncio.Semaphore(CONCURRENCY)
    async with httpx.AsyncClient(headers={"User-Agent": UA}, follow_redirects=True) as client:
        todo = [r for r in repos if r not in cache]
        if not todo:
            print("  tout est déjà en cache")
            return cache
        print(f"  {len(todo)} repos à requêter ({len(todo) * 2} requêtes, parallélisme {CONCURRENCY})...")
        t0 = time.time()
        done = 0

        async def one(repo: str) -> None:
            nonlocal done
            code, html = await get(client, f"https://github.com/{repo}", sem)
            rec: dict = {"http": code}
            if code == 200 and html:
                rec.update(parse_page(html))
                _, xml = await get(client, f"https://github.com/{repo}/commits/HEAD.atom", sem)
                rec["dernier_commit"] = parse_atom(xml)
            elif code == 404:
                rec.update({"stars": "", "licence": "", "archived": "", "dernier_commit": "", "erreur": "repo introuvable"})
            else:
                rec["erreur"] = f"http {code}"
            cache[repo] = rec
            done += 1
            if done % 25 == 0 or done == len(todo):
                print(f"    {done}/{len(todo)}  ({time.time() - t0:.0f}s)")
                save_cache(cache)

        await asyncio.gather(*(one(r) for r in todo))
        save_cache(cache)
        print(f"  terminé en {time.time() - t0:.1f}s")
    return cache


def main() -> int:
    if not SRC.exists():
        print(f"ERREUR: {SRC} introuvable (lance parse_liste.py d'abord)", file=sys.stderr)
        return 2

    rows = list(csv.DictReader(SRC.open(encoding="utf-8")))
    repos = sorted({r["owner_repo"] for r in rows if r["owner_repo"]})
    print(f"{len(rows)} entrées, {len(repos)} owner/repo uniques")

    cache = load_cache()
    asyncio.run(enrich(repos, cache))
    cache = load_cache()

    out, n_ok, n_404, n_err, n_nourl, n_hors, n_org = [], 0, [], [], [], [], []
    for r in rows:
        repo = r["owner_repo"]
        m = cache.get(repo, {})
        r2 = dict(r)
        note = (r.get("url_corrigee_par") or "")
        if not repo:
            if note == "hors périmètre Phase 1":
                n_hors.append(r["nom"])
                etat = "hors-perimetre"
            elif note == "organisation GitHub, pas un repo unique":
                n_org.append(r["nom"])
                etat = "organisation-pas-un-repo"
            else:
                n_nourl.append(r["nom"])
                etat = "pas-d-url-github"
            r2.update({"stars": "", "dernier_commit": "", "licence": "", "archived": "", "etat": etat})
        elif note == "organisation GitHub, pas un repo unique":
            n_org.append(r["nom"])
            r2.update({"stars": m.get("stars", ""), "dernier_commit": m.get("dernier_commit", ""),
                       "licence": m.get("licence", ""), "archived": m.get("archived", ""),
                       "etat": "organisation-pas-un-repo"})
        elif (m.get("erreur") == "repo introuvable" or m.get("http") == 404):
            if note == "hors périmètre Phase 1":
                n_hors.append(r["nom"])
                r2.update({"stars": "", "dernier_commit": "", "licence": "", "archived": "", "etat": "hors-perimetre"})
            else:
                n_404.append(f"{r['nom']} -> {repo}")
                r2.update({"stars": "", "dernier_commit": "", "licence": "", "archived": "", "etat": "404-introuvable"})
        elif m.get("erreur"):
            n_err.append(f"{r['nom']} -> {repo} ({m['erreur']})")
            r2.update({"stars": "", "dernier_commit": "", "licence": "", "archived": "", "etat": m["erreur"]})
        else:
            n_ok += 1
            r2.update({
                "stars": m.get("stars", ""),
                "dernier_commit": m.get("dernier_commit", ""),
                "licence": m.get("licence", ""),
                "archived": m.get("archived", ""),
                "etat": "ok",
            })
        out.append(r2)

    fields = list(rows[0].keys()) + ["stars", "dernier_commit", "licence", "archived", "etat"]
    with DEST.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows(out)

    today = date.today()
    stale = [r for r in out if r["dernier_commit"] and (today - datetime.strptime(r["dernier_commit"], "%Y-%m-%d").date()).days > 548]

    print(f"\nOK                    : {n_ok}")
    print(f"404 introuvable       : {len(n_404)}")
    print(f"autres erreurs        : {len(n_err)}")
    print(f"sans URL GitHub       : {len(n_nourl)}")
    print(f"hors périmètre Phase 1: {len(n_hors)}")
    print(f"organisations (non repo): {len(n_org)}")
    print(f"dernier commit > 18 mois (gate G1) : {len(stale)}")
    print(f"Sortie                : {DEST}")

    if n_404:
        print("\n--- URL GitHub invalides (à corriger) ---")
        for x in n_404:
            print("  404  " + x)
    if n_err:
        print("\n--- erreurs de récupération ---")
        for x in n_err:
            print("  ERR  " + x)
    if n_nourl:
        print("\n--- sans URL GitHub, non encore classées ---")
        for x in n_nourl:
            print("  ???  " + x)
    if n_404:
        print("\n--- 404 restant à trancher ---")
        for x in n_404:
            print("  404  " + x)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
