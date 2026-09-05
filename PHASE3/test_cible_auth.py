#!/usr/bin/env python3
"""Batterie T-AUTH-001/002 : session factice + IDOR sur THAUMAS-WEB.

Lance son PROPRE serveur en subprocess (python3 serveur.py <port>, mode HTTP —
PAS --tls) sur 8809, repli 8819 si le port est occupé, attend qu'il écoute,
mesure puis tue le processus (terminate). Aucun framework externe : mini-framework
maison cas(nom, cond, detail), exit 0/1.

Le jeton SESSION est généré UNE FOIS au boot (global fixé dans main() du serveur,
jamais à la requête) : toute la batterie tourne contre le même processus.

Cas mesurés :
  1. sans cookie             GET /admin/secret-session                  → 302 + Location: /login
  2. POST /login             user=alice&pass=x                          → 200 + Set-Cookie: SESSION=
  3. avec cookie             GET /admin/secret-session                  → 200 + RAPPORT-INTERNE-SESSION
  4. IDOR (T-AUTH-002)       GET /admin/secret-session?user=oscar + ck  → 200 + DOSSIER-AUDIT-OSCAR-FACTICE
  5. user inconnu            GET /admin/secret-session?user=inconnu+ck  → 404
  6. cookie faux             SESSION=fauseinvalide                      → 302 (token du boot exigé)
  7. POST /login sans user   pass seul                                  → 400

Usage : python PHASE3/test_cible_auth.py   (exit 0/1)
"""
from __future__ import annotations

import socket
import subprocess
import sys
import time
from http import client as http_client  # http() ci-dessous masquerait le module
from pathlib import Path

RACINE = Path(__file__).resolve().parent
SERVEUR = RACINE / "cible_web" / "serveur.py"

CAS: list[tuple[str, bool, str]] = []
ECHECS: list[str] = []


def cas(nom: str, cond, detail: str = "") -> None:
    CAS.append((nom, bool(cond), detail))
    if not cond:
        ECHECS.append(nom)


def port_disponible(port: int) -> bool:
    with socket.socket() as s:
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def choisir_port() -> int:
    # 8809 par défaut ; 8819 en repli si un serveur refuse de mourir sur 8809.
    return 8809 if port_disponible(8809) else 8819


def http(methode: str, chemin: str, corps: str = "", cookie: str = "", port: int = 0):
    conn = http_client.HTTPConnection("127.0.0.1", port, timeout=5)
    entetes: dict[str, str] = {}
    if cookie:
        entetes["Cookie"] = cookie
    if corps:
        entetes["Content-Type"] = "application/x-www-form-urlencoded"
    conn.request(methode, chemin, body=corps.encode("utf-8") if corps else None,
                 headers=entetes)
    r = conn.getresponse()
    brut = r.read().decode("utf-8", "replace")
    set_cookie = r.getheader("Set-Cookie") or ""
    location = r.getheader("Location") or ""
    conn.close()
    return r.status, set_cookie, location, brut


def _bilan() -> int:
    ok = len(CAS) - len(ECHECS)
    print(f"{'=' * 50}\n  {ok}/{len(CAS)} cas vérifiés\n{'=' * 50}")
    for nom, cond, detail in CAS:
        if not cond:
            print(f"  ÉCHEC · {nom}\n        {detail}")
    return 1 if ECHECS else 0


def main() -> int:
    port = choisir_port()
    base = f"http://127.0.0.1:{port}"
    proc = subprocess.Popen(
        [sys.executable, str(SERVEUR), str(port)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        vivant = False
        for _ in range(50):
            if proc.poll() is not None:
                break
            try:
                code, _, _, _ = http("GET", "/", port=port)
                vivant = code == 200
                break
            except OSError:
                time.sleep(0.2)
        cas(f"cible éphémère vivante sur {base}", vivant, "le serveur n'a pas démarré")
        if not vivant:
            return _bilan()

        # 1. sans cookie → 302 vers /login
        code, _, loc, brut = http("GET", "/admin/secret-session", port=port)
        cas("sans cookie : /admin/secret-session → 302 + Location /login",
            code == 302 and loc == "/login",
            f"code={code} location={loc} corps={brut[:60]}")

        # 2. POST /login → 200 + Set-Cookie: SESSION=
        code, set_cookie, _, brut = http("POST", "/login", corps="user=alice&pass=x",
                                         port=port)
        jeton = ""
        if set_cookie:
            paire = set_cookie.split(";", 1)[0]  # SESSION=<hex>
            if paire.startswith("SESSION="):
                jeton = paire[len("SESSION="):]
        cas("POST /login user=alice&pass=x → 200 + Set-Cookie SESSION= + « connecté alice »",
            code == 200 and jeton != "" and "connecté" in brut and "alice" in brut,
            f"code={code} set-cookie={set_cookie!r} corps={brut[:80]}")

        # 3. avec le cookie du boot → 200 + secret factice
        code, _, _, brut = http("GET", "/admin/secret-session",
                                cookie=f"SESSION={jeton}", port=port)
        cas("avec cookie du boot : /admin/secret-session → 200 + RAPPORT-INTERNE-SESSION",
            code == 200 and "RAPPORT-INTERNE-SESSION-THAUMAS-2026" in brut,
            f"code={code} corps={brut[:80]}")

        # 4. IDOR : la fiche d'oscar servie avec la session d'alice, sans contrôle
        code, _, _, brut = http("GET", "/admin/secret-session?user=oscar",
                                cookie=f"SESSION={jeton}", port=port)
        cas("IDOR ?user=oscar (cookie d'alice) → 200 + DOSSIER-AUDIT-OSCAR-FACTICE",
            code == 200 and "DOSSIER-AUDIT-OSCAR-FACTICE" in brut,
            f"code={code} corps={brut[:80]}")

        # 5. user inconnu → 404 nommé
        code, _, _, brut = http("GET", "/admin/secret-session?user=inconnu",
                                cookie=f"SESSION={jeton}", port=port)
        cas("?user=inconnu (cookie valide) → 404",
            code == 404 and "inconnu" in brut,
            f"code={code} corps={brut[:80]}")

        # 6. cookie faux → 302 : le token du BOOT est exigé, pas n'importe quelle valeur
        code, _, loc, brut = http("GET", "/admin/secret-session",
                                  cookie="SESSION=fauseinvalide", port=port)
        cas("cookie SESSION=fauseinvalide → 302 (token du boot exigé)",
            code == 302 and loc == "/login",
            f"code={code} location={loc} corps={brut[:60]}")

        # 7. POST /login sans user → 400 (pas de Set-Cookie émis)
        code, set_cookie, _, brut = http("POST", "/login", corps="pass=x", port=port)
        cas("POST /login sans user → 400",
            code == 400 and set_cookie == "",
            f"code={code} set-cookie={set_cookie!r} corps={brut[:80]}")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
    return _bilan()


if __name__ == "__main__":
    sys.exit(main())
