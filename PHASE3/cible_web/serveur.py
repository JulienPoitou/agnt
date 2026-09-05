#!/usr/bin/env python3
"""Cible d'essai web vulnérable — THAUMAS-WEB (stdlib uniquement).

Ce que c'est : la cible d'épreuve PERMANENTE des providers web du registre.
Chaque faille est connue, documentée (README_ATTENDUS.md) et reproductible :
un provider n'est qualifié que si son parser retrouve les ATTENDUS ici.

Sécurité du procédé : écoute sur 127.0.0.1 UNIQUEMENT, aucune dépendance,
aucun contenu réel — tout est factice et versionné. ~20 Mo de RAM.

Failles plantées (IDs de test) :
    T-ENV-001       /.env            secrets factices exposés
    T-GIT-001       /.git/config     dépôt git exposé
    T-XSS-001       /search?q=       XSS réfléchie (non échappée)
    T-TRAVERSAL-001 /download?file=  path traversal sous la racine servie
    T-SQLI-001      /users?id=       SQLi SQLite par concaténation
    T-ADMIN-001     /admin           panneau d'admin sans authentification

Usage : python serveur.py [port]   (défaut 8807)
"""
from __future__ import annotations

import json
import sqlite3
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

RACINE = Path(__file__).resolve().parent
SECRET_HORS_RACINE = RACINE.parent / "cible_web_secret" / "sauvegarde.txt"
GIT_FIXTURE = RACINE / "_git_fixture"

MARQUEUR_GIT = "GIT-DUMP-OK-THAUMAS-2026"


def generer_git_fixture() -> None:
    """Génère un mini dépôt git avec un secret, servi sous /.git/ (T-GIT-002).

    Rejoué au démarrage si absent : le dépôt est l'épreuve de git-dumper — un dump
    réussi doit restaurer secret_app.txt avec MARQUEUR_GIT dedans.
    """
    if (GIT_FIXTURE / ".git" / "HEAD").exists():
        return
    import subprocess
    app = GIT_FIXTURE
    app.mkdir(parents=True, exist_ok=True)
    (app / "secret_app.txt").write_text(
        f"configuration applicative (FACTORICE)\n{MARQUEUR_GIT}\n", encoding="utf-8")
    env_git = {"GIT_AUTHOR_NAME": "cible", "GIT_AUTHOR_EMAIL": "cible@epreuve.test",
               "GIT_COMMITTER_NAME": "cible", "GIT_COMMITTER_EMAIL": "cible@epreuve.test",
               "HOME": str(app)}
    def git(*args: str) -> None:
        subprocess.run(["git", *args], cwd=app, env=env_git, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    git("init", "-b", "master")
    git("add", "secret_app.txt")
    git("commit", "-m", "config initiale (fixture de qualification)")

PAGE = """<!doctype html><html lang="fr"><head><title>THAUMAS-WEB — cible d'épreuve</title></head>
<body><h1>THAUMAS-WEB</h1><p>Cible d'épreuve pour la qualification des providers web.</p>
<ul><li><a href="/search?q=THAUMAS">Recherche</a></li><li><a href="/users?id=1">Annuaire</a></li>
<li><a href="/download?file=notes.txt">Téléchargement</a></li></ul></body></html>"""

SQL_SCHEMA = """
CREATE TABLE users (id INTEGER PRIMARY KEY, nom TEXT, role TEXT);
INSERT INTO users VALUES (1, 'alice', 'admin'), (2, 'bob', 'dev'), (3, 'oscar', 'auditeur');
"""


class Cible(BaseHTTPRequestHandler):
    server_version = "THAUMAS-WEB/1.0"  # T-SRV-001 : bannière de serveur explicite

    def _repondre(self, code: int, corps, type_mime: str = "text/html; charset=utf-8") -> None:
        donnees = corps.encode("utf-8") if isinstance(corps, str) else corps
        self.send_response(code)
        self.send_header("Content-Type", type_mime)
        self.send_header("Content-Length", str(len(donnees)))
        self.end_headers()
        self.wfile.write(donnees)

    def do_GET(self) -> None:  # noqa: N802 (API http.server)
        u = urlparse(self.path)
        q = parse_qs(u.query)
        chemin = u.path

        # T-GIT-002 — dépôt .git COMPLET servi : HEAD, objects, refs… (épreuve git-dumper)
        if chemin.startswith("/.git/"):
            rel = chemin[len("/.git/"):]
            cible_f = (GIT_FIXTURE / ".git" / rel).resolve()
            try:
                cible_f.relative_to((GIT_FIXTURE / ".git").resolve())
            except ValueError:
                self._repondre(403, "interdit", "text/plain")
                return
            if cible_f.is_file():
                self._repondre(200, cible_f.read_bytes(), "application/octet-stream")
            else:
                self._repondre(404, "introuvable", "text/plain")
            return

        # T-ENV-001 — secrets factices exposés
        if chemin == "/.env":
            self._repondre(200, (
                "DB_PASSWORD=faux-mot-de-passe-qualif-2026\n"
                "AWS_ACCESS_KEY_ID=AKIAFAUXQUALIFICATION\n"
                "JWT_SECRET=cible-epreuve-factice\n"), "text/plain")
            return

        # T-GIT-001 — dépôt git exposé
        if chemin == "/.git/config":
            self._repondre(200, (
                "[core]\n\trepositoryformatversion = 0\n"
                "[remote \"origin\"]\n\turl = https://exemple-factice.test/cible.git\n"), "text/plain")
            return

        # T-ADMIN-001 — panneau d'admin sans authentification
        if chemin == "/admin":
            self._repondre(200, "<h1>Administration</h1><p>Aucune authentification requise.</p>")
            return

        # T-XSS-001 — XSS réfléchie : la requête est renvoyée SANS échappement
        if chemin == "/search":
            terme = q.get("q", [""])[0]
            self._repondre(200, f"<h1>Résultats pour : {terme}</h1><p>Aucun résultat.</p>")
            return

        # T-TRAVERSAL-001 — path traversal : le fichier demandé est lu hors du dossier servi
        if chemin == "/download":
            nom = q.get("file", [""])[0]
            cible = (RACINE / nom).resolve()
            if cible.exists() and cible.is_file():
                self._repondre(200, cible.read_text(encoding="utf-8", errors="replace"), "text/plain")
            else:
                self._repondre(404, "fichier introuvable", "text/plain")
            return

        # T-SQLI-001 — SQLi : la requête est construite par CONCATÉNATION
        if chemin == "/users":
            uid = q.get("id", [""])[0]
            conn = sqlite3.connect(":memory:")
            conn.executescript(SQL_SCHEMA)
            try:
                lignes = conn.execute(f"SELECT id, nom, role FROM users WHERE id = {uid}").fetchall()
            except sqlite3.OperationalError as exc:
                self._repondre(500, f"erreur SQL : {exc}", "text/plain")
                return
            corps = "<ul>" + "".join(f"<li>{i} — {n} ({r})</li>" for i, n, r in lignes) + "</ul>"
            self._repondre(200, f"<h1>Annuaire</h1>{corps}")
            return

        if chemin == "/":
            self._repondre(200, PAGE)
            return

        self._repondre(404, "introuvable", "text/plain")

    def log_message(self, *args) -> None:
        pass  # silencieux : la qualification relit les artefacts, pas les logs


def main() -> None:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8807
    generer_git_fixture()
    SECRET_HORS_RACINE.parent.mkdir(parents=True, exist_ok=True)
    SECRET_HORS_RACINE.write_text(
        "SAUVEGARDE-CONFIDENTIELLE-QUALIF\nligne-hors-racine-servie\n", encoding="utf-8")
    serveur = ThreadingHTTPServer(("127.0.0.1", port), Cible)
    print(f"cible THAUMAS-WEB sur http://127.0.0.1:{port} (Ctrl+C pour arrêter)")
    serveur.serve_forever()


if __name__ == "__main__":
    main()
