#!/usr/bin/env python3
"""Control plane : engagements, providers, verification (contrats HTTP).

Usage : python PHASE3/test_pilotage.py
"""
from __future__ import annotations

import json
import sys
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

RACINE = Path(__file__).resolve().parent
sys.path.insert(0, str(RACINE / "slice"))
sys.path.insert(0, str(RACINE / "interface"))

import api                                                    # noqa: E402

CAS: list[tuple[str, bool, str]] = []
ECHECS: list[str] = []


def cas(nom: str, cond, detail: str = "") -> None:
    CAS.append((nom, None if cond is None else bool(cond), detail))
    if not cond and cond is not None:
        ECHECS.append(nom)


def http(base: str, chemin: str, corps: dict | None = None, methode: str | None = None):
    donnees = json.dumps(corps).encode() if corps is not None else None
    import urllib.request
    import urllib.error
    req = urllib.request.Request(base + chemin, data=donnees, method=methode or ("POST" if donnees else "GET"))
    if donnees:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            texte = r.read().decode("utf-8", "replace")
            return r.status, (json.loads(texte) if "json" in (r.headers.get("Content-Type") or "") else texte)
    except urllib.error.HTTPError as e:
        texte = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(texte)
        except json.JSONDecodeError:
            return e.code, texte
    except Exception as exc:
        return 0, f"{type(exc).__name__}: {exc}"


class Silencieux(api.Gestionnaire):
    def log_message(self, *a):
        pass


def main() -> int:
    serveur = ThreadingHTTPServer(("127.0.0.1", 0), Silencieux)
    base = f"http://127.0.0.1:{serveur.server_address[1]}"
    fil = threading.Thread(target=serveur.serve_forever, daemon=True)
    fil.start()
    try:
        code, vide = http(base, "/api/engagements")
        verifie_liste = (code == 200 and isinstance(vide, dict)
                         and isinstance(vide.get("engagements"), list))
        cas("GET /api/engagements → liste (vide au départ)",
            verifie_liste and vide["engagements"] == [], f"code={code}")
        code, eng = http(base, "/api/engagements/web",
                         {"url": "https://pilote.tld/a", "cible_autorisee": True})
        cas("engagement créé → 202", code == 202 and isinstance(eng, dict) and eng.get("id"),
            f"code={code}")
        code, liste = http(base, "/api/engagements")
        items = (liste or {}).get("engagements") if isinstance(liste, dict) else None
        cas("l'engagement apparaît, sans secret (pas de userinfo possible)",
            code == 200 and isinstance(items, list) and len(items) == 1
            and items[0].get("url_canonique") == "https://pilote.tld/a"
            and "@" not in json.dumps(items),
            f"code={code} n={len(items) if isinstance(items, list) else '?'}")
        code, provs = http(base, "/api/providers")
        presents = {p["id"] for p in (provs or {}).get("providers", [])} if isinstance(provs, dict) else set()
        cas("GET /api/providers → déclarés manifest, champs publics seuls",
            code == 200 and isinstance(provs, dict)
            and provs.get("compte") == len(provs.get("providers", []))
            and {"nuclei", "zap_baseline", "ffuf", "nmap"} <= presents
            and all(set(p) == {"id", "binaire", "risque", "cibles", "timeout_s"}
                    for p in provs.get("providers", [])),
            f"code={code} compte={(provs or {}).get('compte')}")
        # ------------------------------------------------------- verification
        obs = [{"status": 200, "body_digest": "a" * 64, "body_taille": 8,
                "contient_extrait": True}] * 3
        code, jug = http(base, "/api/verification",
                         {"url": "https://pilote.tld/a", "expect_status": 200,
                          "expect_body_contains": "admin",
                          "control_url": "https://pilote.tld/",
                          "temoin": {"status": 200, "body_digest": "b" * 64,
                                     "body_taille": 11},
                          "observations": obs})
        cas("verification 3/3 + témoin → confirmed + runtime_verified false",
            code == 200 and isinstance(jug, dict) and jug.get("verdict") == "confirmed"
            and jug.get("runtime_verified") is False
            and jug.get("cycle_evenement") == "verifier_ok",
            f"code={code} corps={json.dumps(jug, ensure_ascii=False)[:160]}")
        code, jug = http(base, "/api/verification",
                         {"url": "https://pilote.tld/a", "observations": []})
        cas("observations vides → 400", code == 400, f"code={code}")
        code, jug = http(base, "/api/verification",
                         {"url": "   ", "observations": obs})
        cas("url vide → 400", code == 400, f"code={code}")
        code, jug = http(base, "/api/verification",
                         {"url": "https://pilote.tld/a", "intensity": "turbo",
                          "observations": obs})
        cas("intensity inconnue → 400", code == 400, f"code={code}")
        code, jug = http(base, "/api/verification",
                         {"url": "https://pilote.tld/a",
                          "observations": [{"status": 200}]})
        cas("observation malformée (digest manquant ok → jugée, pas 400)",
            code == 200 and isinstance(jug, dict) and "verdict" in jug,
            f"code={code}")
        code, jug = http(base, "/api/verification",
                         {"url": "https://pilote.tld/a", "observations": [{"nope": 1}] * 3})
        cas("observations sans match → potential/refuted, jamais confirmé",
            code == 200 and jug.get("verdict") in ("potential", "refuted", "inconclusive"),
            f"code={code} verdict={(jug or {}).get('verdict')}")
    finally:
        serveur.shutdown()

    print(f"\n{'=' * 50}\n  {len(CAS) - len([c for c in CAS if c[1] is False])}/{len(CAS)} passent\n{'=' * 50}")
    for nom, cond, detail in CAS:
        if cond is False:
            print(f"  ÉCHEC · {nom}\n        {detail}")
    return 1 if ECHECS else 0


if __name__ == "__main__":
    sys.exit(main())
