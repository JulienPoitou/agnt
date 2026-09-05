#!/usr/bin/env python3
"""Engagements web : contrat de `POST /api/engagements/web` (plan + exécution).

Ce que cette batterie prouve, par HTTP et rien d'autre :
    ADMIS     un engagement valide est PLANIFIÉ (202 + id + plan) ; sans
              `executer: true`, rien ne part : `execution: "non_demandee"`.
    CÂBLÉ     `executer: true` → 202 + `en_file` + `execution: "file"` ; le run
              atteint un état terminal et le rapport web est rendu — sur une
              machine SANS binaires, l'échec est NOMMÉ dans le rapport
              (`statut_run: arrete`), jamais un spinner ni un faux « 0 constat ».
    REFUSÉ    url vide / schéma non-http(s) / hôte manquant / providers,
              intensity, egress ou executer invalides → 400 nommé ;
              sans `cible_autorisee: true` explicite → 403 `cible_non_autorisee`
              (avec ou sans executer — le fail-closed ne se contourne pas).
    SÛR       userinfo masqué dans tout ce qui est persisté/rendu (`url_sure`).
    HONNÊTE   `GET /api/runs/<id>` d'un engagement rend `mission_id` null —
              aucune mission inventée ; le dédup ne s'applique qu'au PLAN SEUL.
    INTACT    les routes existantes (`/api/capacites`, `/api/runs`) répondent
              toujours (non-régression du dispatch).

L'exécution RÉELLE avec de vrais binaires est la batterie machine de référence
`test_web_cable.py` (hors CI) — ici, l'exécution est prouvée jusqu'à la
transcription honnête des échecs, pas jusqu'au finding.

Usage : python PHASE3/test_engagements_web.py   (aucun réseau extérieur requis)
"""
from __future__ import annotations

import json
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

RACINE = Path(__file__).resolve().parent
sys.path.insert(0, str(RACINE / "slice"))
sys.path.insert(0, str(RACINE / "interface"))

import api                                                    # noqa: E402

RESULTATS: list[tuple[str, bool | None, str]] = []


def verifie(nom: str, cond, detail: str = "") -> None:
    RESULTATS.append((nom, None if cond is None else bool(cond), detail))


def http(base: str, chemin: str, corps: dict | None = None, methode: str | None = None):
    donnees = json.dumps(corps).encode() if corps is not None else None
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
    # Le worker de file (`_travail`) n'est démarré que par `api.main()` : la
    # batterie le lance elle-même pour prouver le chemin exécution de bout en bout.
    travail = threading.Thread(target=api._travail, daemon=True)
    travail.start()
    try:
        # ---------------------------------------------------------- chemin nominal
        code, eng = http(base, "/api/engagements/web",
                         {"url": "https://target.tld", "cible_autorisee": True})
        verifie("engagement valide → 202 + plan",
                code == 202 and isinstance(eng, dict) and eng.get("statut") == "planifie"
                and eng.get("id") and eng.get("execution") == "non_demandee",
                f"code={code} corps={json.dumps(eng, ensure_ascii=False)[:160]}")
        if isinstance(eng, dict) and eng.get("id"):
            verifie("le plan liste la chaîne intégrée dans l'ordre des phases",
                    eng.get("providers_prevus") == list(api.WEB_PROVIDERS_ORDRE),
                    json.dumps(eng.get("providers_prevus")))
            verifie("vérification Oracle annoncée (replay 3 en normal)",
                    (eng.get("verification") or {}).get("oracle") == "http_response"
                    and (eng.get("verification") or {}).get("replay") == 3,
                    json.dumps(eng.get("verification")))
            verifie("limites honnêtes : le plan seul dit comment exécuter",
                    any("executer" in str(l) for l in (eng.get("limites_connues") or [])),
                    json.dumps(eng.get("limites_connues"), ensure_ascii=False)[:140])
            code, lu = http(base, f"/api/runs/{eng['id']}")
            verifie("GET de l'engagement → planifie, mission_id null (rien d'inventé)",
                    code == 200 and isinstance(lu, dict) and lu.get("statut") == "planifie"
                    and lu.get("mission_id") is None,
                    f"code={code} corps={json.dumps(lu, ensure_ascii=False)[:140]}")
            import preuve as PR
            preuve = (lu or {}).get("preuve") if isinstance(lu, dict) else None
            verifie("GET joint la preuve scellée et vérifiable",
                    isinstance(preuve, dict) and PR.verifier(preuve) == (True, "sceau_valide")
                    and (preuve.get("objet") or {}).get("url_canonique") == "https://target.tld/",
                    json.dumps(preuve, ensure_ascii=False)[:160] if preuve else "pas de preuve")
        # ---------------------------------------------------------- secrets
        code, eng = http(base, "/api/engagements/web",
                         {"url": "https://u:p@example.com/x", "cible_autorisee": True})
        verifie("userinfo masqué dans url_sure",
                code == 202 and isinstance(eng, dict)
                and "u:p@" not in json.dumps(eng) and "example.com" in json.dumps(eng),
                f"code={code} corps={json.dumps(eng, ensure_ascii=False)[:140]}")
        # ---------------------------------------------------------- refus 400
        for nom, corps, frag in [
            ("url vide → 400", {"url": "   ", "cible_autorisee": True}, "url vide"),
            ("file:// → 400 (schéma refusé)", {"url": "file:///etc/passwd", "cible_autorisee": True}, "refus"),
            ("hôte manquant → 400", {"url": "https://", "cible_autorisee": True}, "hôte"),
            ("providers inconnus → 400", {"url": "https://target.tld", "cible_autorisee": True,
                                          "providers": ["nmap"]}, "inconnus"),
            ("intensity inconnue → 400", {"url": "https://target.tld", "cible_autorisee": True,
                                          "intensity": "turbo"}, "intensity"),
            ("egress chaîne → 400", {"url": "https://target.tld", "cible_autorisee": True,
                                     "egress": "yes"}, "egress"),
            ("executer chaîne → 400", {"url": "https://target.tld", "cible_autorisee": True,
                                       "executer": "oui"}, "executer"),
        ]:
            c, refus = http(base, "/api/engagements/web", corps)
            verifie(nom, c == 400 and isinstance(refus, dict) and "erreur" in refus
                    and frag in json.dumps(refus, ensure_ascii=False),
                    f"code={c} corps={json.dumps(refus, ensure_ascii=False)[:120]}")
        # ---------------------------------------------------------- refus 403
        for nom, corps in [
            ("sans cible_autorisee → 403", {"url": "https://target.tld"}),
            ("cible_autorisee false → 403", {"url": "https://target.tld", "cible_autorisee": False}),
        ]:
            c, refus = http(base, "/api/engagements/web", corps)
            verifie(nom, c == 403 and isinstance(refus, dict)
                    and refus.get("erreur") == "cible_non_autorisee",
                    f"code={c} corps={json.dumps(refus, ensure_ascii=False)[:120]}")
        # ---------------------------------------------------------- canonique + dedup
        code, eng = http(base, "/api/engagements/web",
                         {"url": "HTTPS://DUP.TLD:443/a/", "cible_autorisee": True})
        verifie("forme canonique persistée",
                code == 202 and isinstance(eng, dict)
                and eng.get("url_canonique") == "https://dup.tld/a",
                f"code={code} corps={json.dumps(eng, ensure_ascii=False)[:160]}")
        code, bis = http(base, "/api/engagements/web",
                         {"url": "https://dup.tld/a", "cible_autorisee": True})
        verifie("deuxième écriture du même endpoint → 200 dédupliqué, même id",
                code == 200 and isinstance(bis, dict) and bis.get("deduplique") is True
                and bis.get("id") == (eng.get("id") if isinstance(eng, dict) else None),
                f"code={code} corps={json.dumps(bis, ensure_ascii=False)[:160]}")
        # ---------------------------------------------------------- sous-sélection
        code, eng = http(base, "/api/engagements/web",
                         {"url": "https://scope.tld/scan", "cible_autorisee": True,
                          "providers": ["httpx", "nuclei"], "intensity": "aggressive",
                          "egress": True})
        verifie("sous-sélection + aggressive → replay 5, egress conservé",
                code == 202 and isinstance(eng, dict)
                and eng.get("providers_prevus") == ["httpx", "nuclei"]
                and (eng.get("verification") or {}).get("replay") == 5
                and eng.get("egress") is True,
                f"code={code} corps={json.dumps(eng, ensure_ascii=False)[:160]}")
        # ---------------------------------------------------------- exécution demandée
        code, refus = http(base, "/api/engagements/web",
                           {"url": "https://target.tld", "executer": True})
        verifie("executer SANS autorisation → toujours 403 (fail-closed inchangé)",
                code == 403 and isinstance(refus, dict)
                and refus.get("erreur") == "cible_non_autorisee",
                f"code={code} corps={json.dumps(refus, ensure_ascii=False)[:140]}")
        # 127.0.0.1:9 (discard) : refus de connexion immédiat, zéro réseau sortant —
        # le test prouve la TRANSCRIPTION d'exécution, pas un finding.
        code, eng = http(base, "/api/engagements/web",
                         {"url": "http://127.0.0.1:9/", "cible_autorisee": True,
                          "executer": True})
        verifie("executer: true → 202 + en_file + execution file",
                code == 202 and isinstance(eng, dict) and eng.get("statut") == "en_file"
                and eng.get("execution") == "file" and eng.get("id"),
                f"code={code} corps={json.dumps(eng, ensure_ascii=False)[:160]}")
        if isinstance(eng, dict) and eng.get("id"):
            terminal, lu = None, None
            # 240 itérations : la chaîne par défaut compte désormais plusieurs
            # outils réels qui échouent chacun sur leur tour — le run peut
            # prendre plus de temps qu'un seul binaire absent.
            for _ in range(240):
                code, lu = http(base, f"/api/runs/{eng['id']}")
                if isinstance(lu, dict) and lu.get("statut") in ("termine", "refuse", "erreur"):
                    terminal = lu.get("statut")
                    break
                time.sleep(0.5)
            verifie("engagement exécuté atteint un état terminal (binaire absent ou "
                    "refusé → échec NOMMÉ dans le rapport, jamais un spinner)",
                    terminal in ("termine", "refuse", "erreur"),
                    f"terminal={terminal} dernier={json.dumps(lu, ensure_ascii=False)[:200]}")
            if isinstance(lu, dict) and lu.get("rapport"):
                verifie("rapport web rendu : type, statut_run honnête, détail par provider",
                        lu["rapport"].get("type") == "rapport_web"
                        and lu["rapport"].get("statut_run") in ("termine", "arrete", "refuse")
                        and isinstance(lu["rapport"].get("details"), list),
                        json.dumps(lu["rapport"], ensure_ascii=False)[:220])
            verifie("l'engagement exécuté n'est pas dédupliqué avec un plan antérieur : "
                    "un id de run de file est rendu",
                    isinstance(lu, dict) and lu.get("id") == eng.get("id")
                    and not lu.get("deduplique"),
                    json.dumps(lu, ensure_ascii=False)[:140] if isinstance(lu, dict) else "lu")
        # ---------------------------------------------------------- non-régression
        code, caps = http(base, "/api/capacites")
        verifie("GET /api/capacites intact après le nouveau dispatch",
                code == 200 and isinstance(caps, dict)
                and ("capacites" in caps or "registre_erreur" in caps),
                f"code={code} clés={sorted(caps) if isinstance(caps, dict) else caps}")
        code, inconnu = http(base, "/api/runs/pas-un-run")
        verifie("run inconnu → toujours 404 nommé",
                code == 404 and "pas-un-run" in json.dumps(inconnu), f"code={code}")
    finally:
        serveur.shutdown()

    ok = sum(1 for _, c, _ in RESULTATS if c is True)
    ko = [n for n, c, _ in RESULTATS if c is False]
    print(f"\n{'=' * 50}\n  {ok}/{len(RESULTATS)} cas passent\n{'=' * 50}")
    for nom, cond, detail in RESULTATS:
        if not cond:
            print(f"  ÉCHEC · {nom}\n        {detail}")
    return 1 if ko else 0


if __name__ == "__main__":
    sys.exit(main())
