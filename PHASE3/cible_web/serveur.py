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
    T-AUTH-001      /login + /admin/secret-session  zone protégée accessible avec session
    T-AUTH-002      /admin/secret-session?user=     IDOR sur ?user= (fiche d'autrui)

Usage : python serveur.py [port] [--tls]
        (défaut 8807 ; --tls = HTTPS, certificat auto-signé généré au boot)

    T-TLS-001       (mode --tls)  certificat auto-signé CN=thaumas-web-epreuve
                    (la même cible, servie en TLS : épreuve des outils TLS)
"""
from __future__ import annotations

import html
import json
import sqlite3
import ssl
import sys
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

RACINE = Path(__file__).resolve().parent
SECRET_HORS_RACINE = RACINE.parent / "cible_web_secret" / "sauvegarde.txt"
GIT_FIXTURE = RACINE / "_git_fixture"

MARQUEUR_GIT = "GIT-DUMP-OK-THAUMAS-2026"

# Mode --tls : le couple cert/clé est GÉNÉRÉ au boot (openssl req -x509) dans
# certs/ — gitignoré : committer une clé privée, même factice, ferait crier
# gitleaks. CN = CN_CIBLE, l'ATTENDU que les outils TLS relisent (T-TLS-001).
CERTS = RACINE / "certs"
CERT_PEM = CERTS / "cert.pem"
CLE_PEM = CERTS / "cle.pem"
CN_CIBLE = "thaumas-web-epreuve"

# T-AUTH-001 — jeton de session FACTICE, généré UNE FOIS au boot (dans main) et
# partagé par tout le processus : c'est lui que /login émet en Set-Cookie et que
# /admin/secret-session exige. Jamais régénéré à la requête.
JETON_SESSION = ""

# T-AUTH-002 — fiches FACTICES par utilisateur : l'IDOR sert celle de n'importe
# qui (?user=) sans vérifier que la session est propriétaire de la fiche.
FICHES_UTILISATEURS = {
    "alice": "PAIEMENT-ALICE-FACTICE",
    "bob": "CLE-DEPLOIEMENT-BOB-FACTICE",
    "oscar": "DOSSIER-AUDIT-OSCAR-FACTICE",
}


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


def generer_certificat() -> None:
    """Certificat auto-signé généré AU BOOT (mode --tls), rejoué si absent.

    Échec openssl = boot qui échoue (check=True) : jamais un serveur TLS sans
    cert. La clé n'est PAS versionnée (certs/ gitignoré) — voir la constante.
    """
    if CERT_PEM.exists() and CLE_PEM.exists():
        return
    import subprocess
    CERTS.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048",
         "-keyout", str(CLE_PEM), "-out", str(CERT_PEM),
         "-days", "365", "-nodes", "-subj", f"/CN={CN_CIBLE}",
         "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost"],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

PAGE = """<!doctype html><html lang="fr"><head><title>THAUMAS-WEB — cible d'épreuve</title></head>
<body><h1>THAUMAS-WEB</h1><p>Cible d'épreuve pour la qualification des providers web.</p>
<ul><li><a href="/search?q=THAUMAS">Recherche</a></li><li><a href="/users?id=1">Annuaire</a></li>
<li><a href="/download?file=notes.txt">Téléchargement</a></li><li><a href="/login">Connexion</a></li></ul></body></html>"""

LIEN_SESSION = ("<p><a href=" + chr(34) + "/admin/secret-session" + chr(34)
                 + chr(62) + "Sessions" + chr(60) + "/a></p>")

SQL_SCHEMA = """
CREATE TABLE users (id INTEGER PRIMARY KEY, nom TEXT, role TEXT);
INSERT INTO users VALUES (1, 'alice', 'admin'), (2, 'bob', 'dev'), (3, 'oscar', 'auditeur');
"""


class Cible(BaseHTTPRequestHandler):
    server_version = "THAUMAS-WEB/1.0"  # T-SRV-001 : bannière de serveur explicite

    def _repondre(self, code: int, corps, type_mime: str = "text/html; charset=utf-8",
                  entetes: dict[str, str] | None = None) -> None:
        donnees = corps.encode("utf-8") if isinstance(corps, str) else corps
        self.send_response(code)
        self.send_header("Content-Type", type_mime)
        self.send_header("Content-Length", str(len(donnees)))
        for nom, valeur in (entetes or {}).items():
            self.send_header(nom, valeur)
        self.end_headers()
        self.wfile.write(donnees)

    def _cookie_session(self) -> str:
        """Valeur du cookie SESSION (T-AUTH-001), chaîne vide si absent."""
        for morceau in self.headers.get("Cookie", "").split(";"):
            if "=" in morceau and morceau.split("=", 1)[0].strip() == "SESSION":
                return morceau.split("=", 1)[1].strip()
        return ""

    def do_GET(self) -> None:  # noqa: N802 (API http.server)
        u = urlparse(self.path)
        q = parse_qs(u.query)
        chemin = u.path
        # Normalisation des slashs répétés : les scanners émettent {canonique}/FUZZ
        # (double slash quand l'URL canonique finit par / — mesuré : ffuf demande
        # //admin/... après avoir constaté la forme simple) et les serveurs réels
        # normalisent. Sans elle, l'oracle rejouerait la FORME brute du constat
        # (double slash → 404) et réfuterait ce que l'outil a réellement vu.
        while "//" in chemin:
            chemin = chemin.replace("//", "/")

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
            self._repondre(200, "<h1>Administration</h1><p>Aucune authentification requise.</p>" + LIEN_SESSION)
            return

        # T-AUTH-001 / T-AUTH-002 — zone protégée : le cookie SESSION émis par
        # /login (jeton du boot) est exigé — absent ou faux → 302 vers /login.
        # Avec le bon cookie, ?user= sert la fiche de N'IMPORTE quel utilisateur
        # sans contrôle de propriétaire : l'IDOR que seul un scan authentifié
        # peut atteindre (sans cookie, la route est carrément invisible).
        if chemin == "/admin/secret-session":
            if self._cookie_session() != JETON_SESSION:
                self._repondre(302, "redirection vers /login", entetes={"Location": "/login"})
                return
            user = q.get("user", [""])[0]
            if user:
                fiche = FICHES_UTILISATEURS.get(user)
                if fiche is None:
                    self._repondre(
                        404, f"<h1>404 — utilisateur inconnu : {html.escape(user)}</h1>")
                    return
                self._repondre(200, (
                    "<h1>espace admin authentifié</h1>"
                    f"<p>fiche (FACTICE) de {html.escape(user)} : {fiche}</p>"))
                return
            self._repondre(200, (
                "<h1>espace admin authentifié</h1>"
                "<p>SECRET (FACTICE) : RAPPORT-INTERNE-SESSION-THAUMAS-2026</p>"))
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

    def do_POST(self) -> None:  # noqa: N802 (API http.server)
        # T-AUTH-001 — /login : identifiants FACTICES (user=/pass=), le jeton du
        # boot est émis en Set-Cookie — une seule session par processus. Le nom
        # d'utilisateur est renvoyé ÉCHAPPÉ : pas de XSS plantée ici (T-XSS-001
        # est ailleurs, sur /search).
        if urlparse(self.path).path == "/login":
            longueur = int(self.headers.get("Content-Length") or 0)
            corps = self.rfile.read(longueur).decode("utf-8", "replace") if longueur else ""
            champs = parse_qs(corps)
            user = champs.get("user", [""])[0]
            passe = champs.get("pass", [""])[0]
            if not user or not passe:
                self._repondre(400, "<h1>400 — identifiants requis</h1>"
                                    "<p>user= et pass= attendus (formulaire factice).</p>")
                return
            self._repondre(200, (
                f"<h1>connecté : {html.escape(user)}</h1>"
                "<p>session factice posée (cookie SESSION) — épreuve du scan authentifié.</p>"),
                entetes={"Set-Cookie": f"SESSION={JETON_SESSION}; Path=/"})
            return
        self._repondre(404, "introuvable", "text/plain")

    def log_message(self, *args) -> None:
        pass  # silencieux : la qualification relit les artefacts, pas les logs


class ServeurTLS(ThreadingHTTPServer):
    """ThreadingHTTPServer dont le handshake TLS est PAR CONNEXION (get_request),
    pas dans accept() : une sonde qui parle HTTP pur au port TLS tue SA connexion,
    pas le serveur (ssl.SSLError est une OSError — socketserver lavale (avale), mesuré).
    Le timeout borne le HANDSHAKE seul : une négociation qui traîne ne bloque pas
    la boucle d accept, et le socket repart sans timeout ensuite."""

    def __init__(self, adresse, handler, contexte: "ssl.SSLContext"):
        super().__init__(adresse, handler)
        self._contexte = contexte

    def get_request(self):
        sock, adresse = self.socket.accept()
        sock.settimeout(10.0)
        try:
            tls_sock = self._contexte.wrap_socket(sock, server_side=True)
        except (ssl.SSLError, OSError):
            sock.close()
            raise
        tls_sock.settimeout(None)
        return tls_sock, adresse


def main() -> None:
    global JETON_SESSION
    args = sys.argv[1:]
    tls = "--tls" in args
    port = 8807
    for a in args:
        if a != "--tls":
            port = int(a)
    generer_git_fixture()
    JETON_SESSION = uuid.uuid4().hex  # T-AUTH-001 : un seul jeton par boot, partagé
    SECRET_HORS_RACINE.parent.mkdir(parents=True, exist_ok=True)
    SECRET_HORS_RACINE.write_text(
        "SAUVEGARDE-CONFIDENTIELLE-QUALIF\nligne-hors-racine-servie\n", encoding="utf-8")
    if tls:
        generer_certificat()
        contexte = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        contexte.load_cert_chain(str(CERT_PEM), str(CLE_PEM))
        serveur = ServeurTLS(("127.0.0.1", port), Cible, contexte)
        print(f"cible THAUMAS-WEB sur https://127.0.0.1:{port} "
              f"(TLS, CN={CN_CIBLE} — Ctrl+C pour arrêter)")
    else:
        serveur = ThreadingHTTPServer(("127.0.0.1", port), Cible)
        print(f"cible THAUMAS-WEB sur http://127.0.0.1:{port} (Ctrl+C pour arrêter)")
    serveur.serve_forever()


if __name__ == "__main__":
    main()
