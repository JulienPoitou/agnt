#!/usr/bin/env python3
"""Batterie du gate de sécurité des projections History / Timeline / Status.

Ce harnais juge le gate (`history_timeline_gate.py`) sur trois plans :

1. **Corpus hostile** — 81 fixtures `docs/coordination/fixtures/security-…` :
   secrets (13 emplacements), chemins et artefacts (14), journal hostile ou
   inconnu (16), provenance MCP (14), statuts et compteurs mensongers (18).
   Chaque fixture attend PASS ou un ensemble de codes de refus : le verdict
   doit correspondre, et les codes attendus doivent réellement apparaître
   (une fixture qui échoue « pour une autre raison » est un échec du harnais :
   on ne ferme pas une faille par accident).
2. **Propriétés du gate lui-même** : déterministe, aucun assainissement (le
   verdict ne contient aucune donnée de sortie), aucune fuite de la valeur
   fautive dans ses messages, aucun lecteur de Mission (le module ne lit rien
   du workspace — vérifié statiquement), stdlib seule (fonctionne avec le
   `python3` système comme avec `.venv/bin/python`).
3. **Runner** — les trois modes sont exercés : `--fixture-mode`,
   `--response-file` et `--base-url` (contre un mini-serveur local de test qui
   rejoue une fixture saine et une hostile : le mode API est ainsi éprouvé
   sans attendre l'API CORE réelle).

Usage : python3 PHASE3/test_history_timeline_security.py
"""

from __future__ import annotations

import copy
import http.server
import json
import re
import subprocess
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

RACINE = Path(__file__).resolve().parent
sys.path.insert(0, str(RACINE))

import history_timeline_gate as G  # noqa: E402

FIXTURES = RACINE.parent / "docs" / "coordination" / "fixtures"
MESSAGE_MARQUEUR = "TEST ONLY — NEVER SERVE AS PRODUCT DATA"

PASS = 0
FAIL = 0


def cas(nom: str, condition: bool, detail: str = "") -> None:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  OK    {nom}")
    else:
        FAIL += 1
        print(f"  ÉCHEC {nom}" + (f" — {detail}" if detail else ""))


def non_evalue(nom: str, cause: str) -> None:
    print(f"  NON ÉVALUÉ · {nom} — {cause}")


def horloge(texte: str) -> datetime:
    return datetime.fromisoformat(texte.replace("Z", "+00:00"))


# ══════════════════════════════════════════════════════════════════════════
# 1 · corpus de fixtures
# ══════════════════════════════════════════════════════════════════════════

def corpus() -> int:
    print("=== 1 · corpus hostile/fixtures (81 scénarios attendus)")
    if not FIXTURES.is_dir():
        non_evalue("corpus", f"{FIXTURES} absent — fixtures non livrées")
        return 1
    fichiers = sorted(FIXTURES.glob("security-history-timeline-*.json"))
    cas("les fixtures sont marquées TEST ONLY (aucune donnée produit)",
        all(f.read_text(encoding="utf-8").count(MESSAGE_MARQUEUR) >= 1
            for f in fichiers), f"{len(fichiers)} fichiers")
    for path in fichiers:
        enveloppe = json.loads(path.read_text(encoding="utf-8"))
        attendu = enveloppe.get("expect") or {}
        codes_attendus = set(attendu.get("codes") or [])
        v = G.valider_projection(enveloppe.get("response"),
                                 horloge=horloge(enveloppe["now"]))
        if attendu.get("verdict") == "PASS":
            cas(f"{path.name} doit passer", v.ok, str(v))
        else:
            cas(f"{path.name} doit échouer sur {sorted(codes_attendus)}",
                not v.ok and set(codes_attendus) <= v.codes,
                f"obtenu {sorted(v.codes)}")
    return 0


# ══════════════════════════════════════════════════════════════════════════
# 2 · propriétés du gate
# ══════════════════════════════════════════════════════════════════════════

def proprietes() -> int:
    print("=== 2 · propriétés du gate (déterminisme, non-assainissement, non-fuite)")
    source = (RACINE / "history_timeline_gate.py").read_text(encoding="utf-8")
    code_validateur = source.split("# Runner")[0]

    # stdlib seule : le gate (validateur) ne peut pas être un second lecteur.
    imports = re.findall(r"^\s*(?:from|import)\s+([a-zA-Z0-9_.]+)", code_validateur,
                         re.M)
    cas("le validateur n'importe que la bibliothèque standard (pas de slice, "
        "pas de lecture d'archives)", all(m.split(".")[0] in {
            "__future__", "argparse", "json", "re", "sys", "urllib",
            "dataclasses", "datetime", "pathlib", "typing"} for m in imports),
        str(sorted(set(imports))))
    cas("le validateur ne lit aucun fichier (pas de second lecteur de Mission)",
        "open(" not in code_validateur and "read_text" not in code_validateur
        and "Path(" not in code_validateur.replace("from pathlib import Path", ""),
        "Path n'apparaît que dans le runner")

    # aucune liste noire de mots-clés ne doit masquer une branche du code
    sain = json.loads((FIXTURES / "security-history-timeline-sain-detail.json")
                      .read_text(encoding="utf-8"))["response"]
    copie = copy.deepcopy(sain)
    v1 = G.valider_projection(sain, horloge=horloge("2026-08-30T12:00:00Z"))
    v2 = G.valider_projection(copie, horloge=horloge("2026-08-30T12:00:00Z"))
    cas("déterministe : même entrée + même horloge => même verdict",
        v1.ok == v2.ok and v1.codes == v2.codes and str(v1) == str(v2), str(v1))
    cas("le gate n'assainit pas : l'entrée n'est pas modifiée",
        sain == copie, "les données entrées/sorties ont divergé")
    cas("le verdict ne porte aucune donnée de sortie (refus, pas réécriture)",
        set(v1.__dataclass_fields__) == {"ok", "raisons"}, str(v1))

    # Non-fuite : aucune valeur qui déclenche une règle de CONTENU (secret,
    # chemin, stack, HTML…) ne peut apparaître dans le texte du verdict. Les
    # mots bénins du vocabulaire peuvent légitimement apparaître dans une
    # explication (« conflict ») : on ne juge que ce qui est fautif.
    fuites = []
    for path in FIXTURES.glob("security-history-timeline-*.json"):
        enveloppe = json.loads(path.read_text(encoding="utf-8"))
        if (enveloppe.get("expect") or {}).get("verdict") != "FAIL":
            continue
        v = G.valider_projection(enveloppe["response"],
                                 horloge=horloge(enveloppe["now"]))
        texte = str(v)

        def valeurs(o):
            if isinstance(o, str):
                yield o
            elif isinstance(o, list):
                for x in o:
                    yield from valeurs(x)
            elif isinstance(o, dict):
                for x in o.values():
                    yield from valeurs(x)

        for val in valeurs(enveloppe["response"]):
            if any(motif.search(val) for _, motif, _ in G._CONTENUS) and \
                    val in texte:
                fuites.append(f"{path.name}: {val[:12]}…")
                break
    cas("aucune valeur fautive n'est reflétée par le gate (messages génériques)",
        not fuites, "; ".join(fuites[:4]))

    return 0


# ══════════════════════════════════════════════════════════════════════════
# 3 · runner : trois modes, contre un mini-serveur local
# ══════════════════════════════════════════════════════════════════════════

class _Stub(http.server.BaseHTTPRequestHandler):
    """Mini API CORE de test : sert une projection saine et une hostile."""

    reponses: dict[str, dict] = {}

    def do_GET(self):  # noqa: N802
        corps = self.reponses.get(self.path)
        if corps is None:
            self.send_response(404)
            self.end_headers()
            return
        data = json.dumps(corps, ensure_ascii=False).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):  # silence
        return


def runner() -> int:
    print("=== 3 · modes du runner")
    py = sys.executable
    gate = str(RACINE / "history_timeline_gate.py")

    r = subprocess.run([py, gate, "--fixture-mode", str(FIXTURES)],
                       capture_output=True, text=True, timeout=300)
    cas("--fixture-mode : code 0 sur le corpus complet",
        r.returncode == 0, f"rc={r.returncode} · {r.stdout.strip().splitlines()[-1] if r.stdout else ''}")

    hostile = FIXTURES / "security-history-timeline-secret-bearer.json"
    enveloppe = json.loads(hostile.read_text(encoding="utf-8"))
    import tempfile
    with tempfile.TemporaryDirectory(prefix="gate-reponse-") as td:
        chemin = Path(td) / "reponse.json"
        chemin.write_text(json.dumps(enveloppe["response"]), encoding="utf-8")
        r = subprocess.run([py, gate, "--response-file", str(chemin), "--now",
                            enveloppe["now"]], capture_output=True, text=True,
                           timeout=120)
        cas("--response-file : une réponse hostile sort en FAIL (code 2)",
            r.returncode == 2 and "FAIL" in r.stdout,
            f"rc={r.returncode} · {r.stdout.strip()[:80]}")
        saine = FIXTURES / "security-history-timeline-sain-detail.json"
        enveloppe2 = json.loads(saine.read_text(encoding="utf-8"))
        chemin.write_text(json.dumps(enveloppe2["response"]), encoding="utf-8")
        r = subprocess.run([py, gate, "--response-file", str(chemin), "--now",
                            enveloppe2["now"]], capture_output=True, text=True,
                           timeout=120)
        cas("--response-file : une réponse saine sort en PASS (code 0)",
            r.returncode == 0 and "PASS" in r.stdout,
            f"rc={r.returncode} · {r.stdout.strip()[:80]}")

    _Stub.reponses = {}
    serveur = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Stub)
    port = serveur.server_address[1]
    saine = json.loads((FIXTURES / "security-history-timeline-sain-detail.json")
                       .read_text(encoding="utf-8"))
    hostile2 = json.loads((FIXTURES / "security-history-timeline-ts-futur.json")
                          .read_text(encoding="utf-8"))
    resume = {k: saine["response"]["data"][k] for k in
              ("mission_id", "statut", "created_at", "run_id", "findings_count")}
    _Stub.reponses = {
        "/api/missions": {"api": "agnt.history.v1", "endpoint": "/api/missions",
                          "data": [resume]},
        "/api/missions/m-20260830-0001": saine["response"],
    }
    fil = threading.Thread(target=serveur.serve_forever, daemon=True)
    fil.start()
    try:
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = G.mode_api(f"http://127.0.0.1:{port}", None,
                              horloge("2026-08-30T12:00:00Z"))
        cas("--base-url : liste + détail sains => PASS (code 0)", code == 0,
            buf.getvalue().strip().replace("\n", " ")[:100])
        _Stub.reponses["/api/missions/m-20260830-0001"] = hostile2["response"]
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = G.mode_api(f"http://127.0.0.1:{port}", None,
                              horloge("2026-08-30T12:00:00Z"))
        cas("--base-url : un détail hostile fait échouer le mode API (code 2)",
            code == 2, buf.getvalue().strip().replace("\n", " ")[:100])
    finally:
        serveur.shutdown()
    return 0


# ══════════════════════════════════════════════════════════════════════════
# 4 · compatibilité avec les contrats Product (à re-lier quand ils arrivent)
# ══════════════════════════════════════════════════════════════════════════

def compatibilite_contrats() -> int:
    print("=== 4 · compatibilité avec les contrats Product")
    contrats = [
        RACINE.parent / "docs" / "coordination" / "test_mission_history_contract.py",
        RACINE.parent / "docs" / "coordination" / "test_mission_timeline_contract.py",
        RACINE.parent / "docs" / "coordination" / "test_execution_status_contract.py",
    ]
    absents = [p.name for p in contrats if not p.exists()]
    if absents:
        for nom in absents:
            non_evalue(nom, "fichier absent de ce workspace (Product/CORE ne "
                            "l'ont pas encore livré)")
    else:
        cas("les trois tests de contrat Product sont disponibles dans le workspace", True)
    non_evalue("re-lien du schéma du gate aux contrats Product",
               "les contrats agnt.history.v1 / agnt.timeline.v1 / "
               "agnt.execution-status.v1 ne sont pas dans ce workspace "
               "(vérifié : aucune branche, aucun commit) — quand ils sont "
               "livrés, le re-lien se fait ici et les codes attendus des "
               "fixtures sont ré-examinés")
    return 0


# ══════════════════════════════════════════════════════════════════════════
def main() -> int:
    print("=== GATE security history / timeline / status")
    corpus()
    proprietes()
    runner()
    compatibilite_contrats()
    print(f"\n{PASS} vérifications passées · {FAIL} en échec")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
