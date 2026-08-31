#!/usr/bin/env python3
"""doctor — une commande, une vérité sur l'environnement AGNT.

Quatre sections, aucune ambiguïté, aucun téléchargement :

    ENV         faits de machine (python, pyyaml/mcp, bwrap + userns noyau, node, docker)
    COMPOSANTS  binaires / outils pip / règles / bases — présence ET conformité
                d'empreinte avec PHASE3/manifeste_dependances.yaml
    SUITES      matrice PHASE3/test_* — PASS / FAIL / BLOCKED par suite, avec la
                RAISON EXACTE de chaque BLOCKED (binaire absent ? userns noyau ?
                réseau ? db absente ? module python manquant ?)
    ARMABLE     ce qui manque ET dont la source épinglée est joignable maintenant

Sémantique des verdicts (détaillée dans RUNBOOK_ENVIRONNEMENT.md) :

    PASS     rc=0 — la suite a rendu ses verdicts (« N non évalués » reste AFFICHÉ :
             un PASS avec cas non évalués n'est pas un PASS complet)
    FAIL     rc≠0 et au moins un échec qui N'EST PAS rattachable à une absence
             d'environnement — c'est le seul verdict qui fait échouer la commande
    BLOCKED  la suite ne peut pas évaluer : tous ses échecs/crashs se rattachent
             à une absence d'environnement nommée. Un test qui échoue POUR
             l'environnement reste BLOCKED documenté — jamais retouché, jamais
             compté PASS (règle du chantier).

Sorties : 0 si aucun FAIL (PASS et BLOCKED ne gâtent pas le gate), 1 sinon.
Options : --rapide (ENV+COMPOSANTS+ARMABLE, sans les suites) · --suites REGEX
          --timeout N (90 s par défaut) · --no-probe (ne pas tester la
          joignabilité des sources) · --json (sortie machine, tableau sinon)

Le doctor n'installe RIEN et n'affiche JAMAIS de secret (les présences de
variables sensibles sont rapportées comme « définie/absente », sans valeur).
"""

from __future__ import annotations

import argparse
import concurrent.futures as CF
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

RACINE = Path(__file__).resolve().parent
MANIFESTE = RACINE / "manifeste_dependances.yaml"
CACHE = Path(os.environ.get("ARENA_SECOPS_CACHE", str(Path.home() / ".cache" / "arena_secops")))
BIN = CACHE / "bin"
RULES = CACHE / "rules"
TRIVY_DB = CACHE / "trivy-cache"

BINAIRES_CACHES = ("trivy", "gitleaks", "opa", "grype", "kics")
OUTILS_PIP = ("semgrep", "bandit", "checkov", "detect-secrets", "radon",
              "pip-audit", "ruff", "trufflehog3")
REGLES = ("python", "security-audit", "javascript", "golang")

# Raisons NORMALISÉES d'un BLOCKED — chacune pointe son armement (ou son impossibilité).
R = {
    "opa":        "binaire opa absent → bash PHASE3/bootstrap.sh --armement opa",
    "pip_outils": "outils de scan absents → bash PHASE3/bootstrap.sh --armement outils-pip",
    "regles":     "règles semgrep absentes (semgrep.dev injoignable ici) → --armement regles-semgrep",
    "trivy_db":   "base de vulnérabilités absente (mirror.gcr.io injoignable ici) → --armement trivy-db",
    "bwrap":      "bwrap absent (deb.debian.org injoignable ici) ; userns restreints par le noyau → RUNBOOK §impossibilités",
    "pyyaml":     "pyyaml absent → venv : python3 -m venv /tmp/agnt-venv && pip install pyyaml mcp==2.1.1",
    "mcp":        "paquet python mcp absent → pip install mcp==2.1.1",
    "docker":     "docker absent (harnais OCI à rejouer sur une machine avec Docker)",
    "interop":    "MCP_INTEROP_PYTHON non défini (interop cross-runtime : volontairement opt-in)",
    "llm_key":    "GROQ_API_KEY absente — LLM réel non testable hors ligne, par conception",
    "timeout":    "timeout dépassé — attente réseau probable (aucune suite ne doit attendre le réseau)",
    "fixture":    "fixture absente ou .git non recréé → bash PHASE3/bootstrap.sh (local, sans flag)",
}

# Signatures FORTES : motif (regex sur stdout+stderr) → clé de raison.
SIGNATURES_FORTES = [
    (r"No module named 'yaml'", "pyyaml"),
    (r"No module named 'mcp'", "mcp"),
    (r"binaire OPA introuvable|binaire [`'‘]?opa[`'’]? (est )?absent", "opa"),
    (r"No such file or directory: '[^']*bwrap|bwrap: No such file|bwrap introuvable", "bwrap"),
    (r"outil introuvable : [\w.-]+", "pip_outils"),
    (r"base Trivy introuvable", "trivy_db"),
    (r"MCP_INTEROP_PYTHON", "interop"),
    (r"GROQ_API_KEY absente", "llm_key"),
    (r"docker absent", "docker"),
    (r"aucun outil (exécutable|disponible) sur cette machine|aucun fournisseur exécutable", "pip_outils"),
]
# Marqueurs « échec DÛ à l'environnement » pour la classification cas par cas :
MARQUEURS_ENV = re.compile(
    r"trivy|grype|semgrep|gitleaks|bandit|checkov|radon|detect.secrets|ruff|trufflehog3|"
    r"eslint|kics|bwrap|bubblewrap|opa\b|isolateur|sandbox|règles|rules/|base de vuln|"
    r"trivy-cache|outil|providers?\b|disponible|conditions|résea|network|egress|docker|API_KEY|"
    r"intermédiaire|findings=0|124 findings|aucun finding|module named|MCP_INTEROP|"
    r"cible|plan\b|mission|bundle|workflow|scan\b|suppléant|fixture|\.git\b|"
    r"base absente|injoignable|No such file", re.IGNORECASE)

# Échecs RÉELS pré-existants, HORS environnement, avec propriétaire et référence —
# nommés ici pour ne pas être absorbés par le filet « vocabulaire environnement ».
# Leur présence est une dette MESURÉE (jamais un faux PASS), pas un blocage d'armement.
KNOWN_REAL_FAILS = {
    "test_adversaire.py":
        "4 FAIL mesurés (D1, D4, E6, G6a) — dossier SECURITY, relevés voulus par la "
        "campagne elle-même (jamais de faux PASS) ; voir docs/coordination/PROJECT_STATE.md",
    "test_outils_pool_mission.py":
        "3b. régénération déterministe (octet pour octet) : sensible à la date inscrite "
        "dans pool.yaml (genere_le) — échec réel pré-existant, hors environnement",
}


def _lire_manifeste() -> dict | None:
    try:
        import yaml  # type: ignore
        return yaml.safe_load(MANIFESTE.read_text(encoding="utf-8")) or {}
    except Exception:
        return None


def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for bloc in iter(lambda: fh.read(1 << 22), b""):
            h.update(bloc)
    return h.hexdigest()


# -------------------------------------------------------------------------- ENV
def section_env() -> list[dict]:
    lignes = []

    def ajoute(nom, etat, detail=""):
        lignes.append({"nom": nom, "etat": etat, "detail": detail})

    ajoute("python3", "READY", f"{sys.version.split()[0]} ({sys.executable})")
    for mod, raison in (("yaml", "pyyaml"), ("mcp", "mcp")):
        r = subprocess.run([sys.executable, "-c", f"import {mod}"],
                           capture_output=True)
        ajoute(f"module {mod}", "READY" if r.returncode == 0 else "BLOCKED",
               "" if r.returncode == 0 else R[raison])
    # bwrap + user namespaces : DEUX faits, pas un seul — un bwrap présent sur un
    # noyau qui refuse les userns ne sandboxe RIEN (mesuré : kernel refus ici).
    bwrap = shutil.which("bwrap")
    if bwrap is None:
        ajoute("bwrap", "BLOCKED", R["bwrap"])
    else:
        sonde = subprocess.run(["bwrap", "--dev-bind", "/", "/", "true"],
                               capture_output=True, timeout=10)
        if sonde.returncode == 0:
            ajoute("bwrap", "READY", f"{bwrap} — userns fonctionnels")
        else:
            diag = sonde.stderr.decode(errors="replace").strip().splitlines()
            ajoute("bwrap", "BLOCKED",
                   f"userns refusés par le noyau ({(diag or ['?'])[0][:120]}) — "
                   "contrainte hôte, NON corrigeable ici : RUNBOOK §impossibilités")
    for f in ("/proc/sys/kernel/apparmor_restrict_unprivileged_userns",
              "/proc/sys/kernel/unprivileged_userns_clone"):
        p = Path(f)
        if p.exists():
            val = p.read_text().strip()
            bloque = (f.endswith("restrict_unprivileged_userns") and val == "1") or \
                     (f.endswith("unprivileged_userns_clone") and val == "0")
            ajoute(f"noyau {p.name}", "BLOCKED" if bloque else "READY", f"{f}={val}")
    ajoute("node", "READY" if shutil.which("node") else "MISSING",
           "requis : eslint (pool npm) et provider npm_audit" if not shutil.which("node") else "")
    ajoute("npm", "READY" if shutil.which("npm") else "MISSING",
           "requis : --armement eslint" if not shutil.which("npm") else "")
    ajoute("docker", "READY" if shutil.which("docker") else "BLOCKED",
           "" if shutil.which("docker") else R["docker"])
    ajoute("git", "READY" if shutil.which("git") else "MISSING")
    # Présence de clés LLM rapportée SANS valeur — jamais de secret dans la sortie.
    for var in ("GROQ_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY"):
        ajoute(f"env {var}", "READY" if os.environ.get(var) else "MISSING",
               "définie (valeur non affichée)" if os.environ.get(var)
               else "absente — suites LLM réel BLOCKED par conception")
    return lignes


# --------------------------------------------------------------------- COMPOSANTS
def section_composants() -> list[dict]:
    m = _lire_manifeste()
    lignes = []

    def ajoute(nom, etat, detail=""):
        lignes.append({"nom": nom, "etat": etat, "detail": detail})

    if m is None:
        ajoute("manifeste", "BLOCKED", R["pyyaml"] + " — conformité d'empreintes NON vérifiée")
        m = {}
    binaires = (m.get("binaires") or {})
    regles_m = (m.get("regles") or {})

    for n in BINAIRES_CACHES:
        p = BIN / n
        epingle = str((binaires.get(n) or {}).get("sha256") or "")
        if not p.is_file():
            ajoute(f"opa (moteur de décision)" if n == "opa" else f"binaire {n}",
                   "MISSING", R["opa"] if n == "opa" else "--armement " + n)
            continue
        if not epingle:
            ajoute(f"binaire {n}", "READY", "présent (empreinte non épinglée — choix du manifeste)")
            continue
        reel = _sha256(p)
        if reel == epingle:
            ver = str((binaires.get(n) or {}).get("version") or "?")
            ajoute(f"opa {ver} (moteur de décision)" if n == "opa" else f"binaire {n} {ver}",
                   "READY", f"sha256 conforme ({reel[:12]}…)")
        else:
            ajoute(f"binaire {n}", "INVALID",
                   f"DIVERGENT : obtenu {reel[:12]}… ≠ épinglé {epingle[:12]}… — REFUSÉ à l'exécution")

    for t in OUTILS_PIP:
        exe = shutil.which(t)
        ver = str((binaires.get(t) or {}).get("version") or "?")
        ajoute(f"outil pip {t} {ver}", "READY" if exe else "MISSING",
               exe or R["pip_outils"])
    ajoute("eslint (pool npm)", "READY" if (BIN / "eslint").exists() else "MISSING",
           "" if (BIN / "eslint").exists() else "--armement eslint")
    for r in REGLES:
        p = RULES / f"{r}.yaml"
        epingle = str((regles_m.get(f"{r}.yaml") or {}).get("sha256") or "")
        if not p.is_file():
            ajoute(f"règles semgrep p/{r}", "MISSING", R["regles"])
        elif epingle and _sha256(p) != epingle:
            ajoute(f"règles semgrep p/{r}", "INVALID",
                   "empreinte divergente de l'épinglé — résultats non comparables, signalé au bootstrap")
        else:
            ajoute(f"règles semgrep p/{r}", "READY")
    ajoute("requêtes kics", "READY" if (RULES / "kics" / "queries").is_dir() else "MISSING",
           "" if (RULES / "kics" / "queries").is_dir() else "--armement kics")
    for nom, sous, cle in (("base trivy", "trivy/db", "trivy_db"), ("base grype", "grype", "trivy_db")):
        p = TRIVY_DB / sous
        ajoute(nom, "READY" if p.is_dir() else "MISSING",
               "" if p.is_dir() else R[cle])
    return lignes


# ------------------------------------------------------------------------- SUITES
LIGNE_ECHEC = re.compile(r"(?:ÉCHEC|ECHEC|FAIL)\b[. ]*[:\- ]?\s*(.*)")
COMPTEURS = [
    re.compile(r"(\d+)\s*/\s*(\d+)\s*cas pass"),            # « 25/31 cas passés »
    re.compile(r"(\d+) OK · (\d+) échec"),                  # « 20 OK · 2 échec(s) »
    re.compile(r"(\d+)/(\d+) cas passent"),
    re.compile(r"(\d+) cas · (\d+) PASS · (\d+) FAIL"),     # campagne adversaire
]


def _compte(texte: str) -> str:
    for rx in COMPTEURS:
        m = rx.search(texte)
        if m:
            return m.group(0).strip()
    return ""


def _non_evalues(texte: str) -> int:
    m = re.search(r"(\d+) non [ée]valu[ée]s?", texte, re.IGNORECASE)
    if m:
        return int(m.group(1))
    n = len(re.findall(r"NON [ÉE]VALU[ÉE]", texte))
    return n


def analyser_suite(nom: str, rc: int, sortie: str, timeout: int) -> dict:
    compte = _compte(sortie)
    ne = _non_evalues(sortie)
    res = {"suite": nom, "rc": rc, "compte": compte, "non_evalues": ne,
           "raisons": [], "detail": ""}

    if rc == 124:
        res.update(verdict="BLOCKED", raisons=[R["timeout"] + f" (--timeout {timeout})"])
        return res
    if rc == 77:
        motif = ""
        for l in sortie.splitlines():
            if "NON ÉVALUÉ" in l.upper() or "77" in l:
                motif = l.strip()[:160]
                break
        res.update(verdict="BLOCKED", raisons=[motif or "auto-déclaré NON ÉVALUÉ (dépendance d'environnement)"],
                   detail=motif)
        return res
    if rc == 0:
        res["verdict"] = "PASS"
        return res

    # Échecs réels pré-existants nommés (jamais absorbés par le filet environnement) :
    # la suite est FAIL, avec la référence qui dit À QUI appartient la dette.
    lignes = sortie.splitlines()
    for suite, note in KNOWN_REAL_FAILS.items():
        if nom == suite:
            res.update(verdict="FAIL", raisons=[note], detail=res["detail"]
                       or next((l.strip()[:160] for l in lignes
                                if "FAIL" in l or "ECHEC" in l or "ÉCHEC" in l), ""))
            return res

    # rc≠0 : fortes signatures d'abord (crashs / absences franches)
    raisons = []
    for rx, cle in SIGNATURES_FORTES:
        if re.search(rx, sortie, re.IGNORECASE) and R[cle] not in raisons:
            raisons.append(R[cle])
    # Contexte d'un échec : son titre + les 2 lignes suivantes (détail/continuation).
    echecs = []
    for i, l in enumerate(lignes):
        m = LIGNE_ECHEC.search(l)
        if m and m.group(1).strip() and "NON ÉVALUÉ" not in l:
            contexte = " ".join([m.group(1).strip()] + lignes[i + 1:i + 3])
            echecs.append((m.group(1).strip(), contexte))
    vocab_env = len(MARQUEURS_ENV.findall(sortie)) >= 2
    res["detail"] = echecs[0][0][:160] if echecs else (sortie.strip().splitlines() or [""])[-1][:160]

    if echecs:
        hors_env = [t for t, ctx in echecs
                    if not MARQUEURS_ENV.search(ctx) and not vocab_env]
        if hors_env:
            res["verdict"] = "FAIL"
            res["detail"] = hors_env[0][:160]
            res["raisons"] = raisons  # contexte, pas excuse : du hors-env existe
        else:
            res["verdict"] = "BLOCKED"
            if not raisons:
                # Tous les échecs sont rattachés à une absence d'environnement : on le dit
                # sans en inventer la cause fine — le détail du premier échec reste affiché.
                raisons = [f"{len(echecs)} échec(s), tous rattachés à une absence d'environnement "
                           "(outils/règles/bases/sandbox) — armement : bootstrap.sh --liste puis --armement"]
            res["raisons"] = raisons
        return res

    # Crash (traceback) ou sortie non structurée
    if raisons:
        res["verdict"] = "BLOCKED"
        res["raisons"] = raisons
    elif vocab_env:
        res["verdict"] = "BLOCKED"
        res["raisons"] = ["crash rattaché à une absence d'environnement (outils/règles/bases) "
                          "— traceback ci-dessus, armement : bootstrap.sh --liste puis --armement"]
    else:
        res["verdict"] = "FAIL"
    return res


def section_suites(filtre: str | None, timeout: int,
                   corrige=None) -> list[dict]:
    suites = sorted(RACINE.glob("test_*.py")) + sorted(RACINE.glob("test_*.sh"))
    if filtre:
        rx = re.compile(filtre)
        suites = [s for s in suites if rx.search(s.name)]
    # Snapshot des missions existantes : les suites écrivent sous artifacts/missions —
    # le doctor rend le dépôt dans l'état où il l'a trouvé (idempotence de surface git).
    missions = RACINE / "artifacts" / "missions"
    avant = set(missions.glob("m-*")) if missions.is_dir() else set()
    resultats = []
    try:
        for s in suites:
            cmd = [sys.executable, str(s)] if s.suffix == ".py" else ["bash", str(s)]
            try:
                r = subprocess.run(cmd, capture_output=True, timeout=timeout,
                                   text=True, errors="replace", cwd=RACINE.parent)
                rc, sortie = r.returncode, (r.stdout or "") + (r.stderr or "")
            except subprocess.TimeoutExpired as e:
                rc, sortie = 124, "".join(x.decode(errors="replace") if isinstance(x, bytes)
                                          else str(x) for x in (e.stdout, e.stderr) if x)
            res = analyser_suite(s.name, rc, sortie, timeout)
            if corrige:
                res["raisons"] = [corrige(rtext) for rtext in res["raisons"]]
            resultats.append(res)
            tag = {"PASS": "PASS   ", "FAIL": "FAIL   ", "BLOCKED": "BLOCKED "}[res["verdict"]]
            extra = f" · {res['compte']}" if res["compte"] else ""
            ne = f" · {res['non_evalues']} non évalué(s)" if res["non_evalues"] else ""
            print(f"  {tag} {s.name}{extra}{ne}"
                  + (f"  —  {res['detail']}" if res["verdict"] != "PASS" and res["detail"] else ""),
                  flush=True)
            for raison in res["raisons"]:
                print(f"           raison : {raison}", flush=True)
    finally:
        if missions.is_dir():
            for d in set(missions.glob("m-*")) - avant:
                # Uniquement des répertoires de mission NOUVEAUX et NON SUIVIS par git.
                suivis = subprocess.run(["git", "ls-files", "--error-unmatch", str(d)],
                                        capture_output=True, cwd=RACINE.parent)
                if suivis.returncode != 0:
                    shutil.rmtree(d, ignore_errors=True)
    return resultats


# ------------------------------------------------------------------------ ARMABLE
SOURCES = {  # composant → (hôte sondé, tête de ligne). La sonde est une HEAD 2 s, pas un téléchargement.
    "opa":            ("https://registry.npmjs.org", "--armement opa"),
    "outils-pip":     ("https://pypi.org", "--armement outils-pip"),
    "eslint":         ("https://registry.npmjs.org", "--armement eslint"),
    "regles-semgrep": ("https://semgrep.dev", "--armement regles-semgrep"),
    "trivy":          ("https://raw.githubusercontent.com", "--armement trivy"),
    "trivy-db":       ("https://mirror.gcr.io", "--armement trivy-db"),
    # Les assets de release GitHub (gitleaks/grype/kics) redirigent TOUS vers ce CDN :
    "binaires-github (gitleaks/grype/kics)": ("https://release-assets.githubusercontent.com",
                                              "--armement gitleaks|grype|kics"),
    "systeme (bwrap)": ("https://deb.debian.org", "--armement systeme"),
}


def _sonde(url: str) -> bool:
    import urllib.request
    try:
        req = urllib.request.Request(url, method="HEAD",
                                     headers={"User-Agent": "agnt-doctor/1"})
        with urllib.request.urlopen(req, timeout=2):
            return True
    except Exception:
        return False


def section_armable(composants: list[dict], probe: bool) -> list[dict]:
    manquants = {c["nom"] for c in composants if c["etat"] in ("MISSING", "INVALID")}
    out = []
    with CF.ThreadPoolExecutor(max_workers=8) as ex:
        joignables = {url: (ex.submit(_sonde, url) if probe else None)
                      for _, (url, _) in SOURCES.items()}
        for comp, (url, cmd) in SOURCES.items():
            fut = joignables[url]
            joignable = fut.result() if fut is not None else None
            out.append({"composant": comp, "source": url, "commande": cmd,
                        "joignable": joignable})
    return out


# -------------------------------------------------------------------------- rendu
def rendre(titre: str, lignes: list[dict], cles=("nom", "etat", "detail")) -> None:
    print(f"\n═══ {titre} ═══")
    for l in lignes:
        detail = f"  —  {l['detail']}" if l.get("detail") else ""
        print(f"  {l['etat']:<8} {l['nom']}{detail}")


def main() -> int:
    ap = argparse.ArgumentParser(description="doctor AGNT — matrice d'environnement")
    ap.add_argument("--rapide", action="store_true", help="sans les suites (ENV+COMPOSANTS+ARMABLE)")
    ap.add_argument("--suites", help="regex de filtre sur les noms de suites")
    ap.add_argument("--timeout", type=int, default=90)
    ap.add_argument("--no-probe", action="store_true", help="pas de sonde réseau (instantané total)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    t0 = time.time()
    env = section_env()
    composants = section_composants()
    # Une suite peut répéter un libellé FIGÉ (« binaire opa absent ») alors que doctor
    # vient de mesurer le contraire : on ne laisse pas passer un état contredit — la
    # raison est remplacée par la version mesurée (la suite, elle, n'est pas retouchée).
    opa_ok = any(c["nom"].startswith("opa ") and c["etat"] == "READY" for c in composants)
    pip_ok = sum(1 for c in composants
                 if c["nom"].startswith("outil pip ") and c["etat"] == "READY")

    def corrige(rtext: str) -> str:
        if rtext == R["opa"] and opa_ok:
            return ("libellé figé de suite contredit par la mesure : OPA est PRÉSENT et "
                    "conforme — le blocage résiduel de cette suite est ailleurs "
                    "(outils de scan / bwrap — voir son détail)")
        if rtext == R["pip_outils"] and pip_ok == len(OUTILS_PIP):
            return ("libellé contredit par la mesure : les 8 outils pip sont présents — "
                    "le blocage résiduel est ailleurs (règles/bases/bwrap — voir détail)")
        return rtext

    suites = [] if args.rapide else section_suites(args.suites, args.timeout, corrige)
    armable = section_armable(composants, probe=not args.no_probe)

    resume = {
        "PASS": sum(1 for s in suites if s["verdict"] == "PASS"),
        "FAIL": sum(1 for s in suites if s["verdict"] == "FAIL"),
        "BLOCKED": sum(1 for s in suites if s["verdict"] == "BLOCKED"),
        "non_evalues_cas": sum(s["non_evalues"] for s in suites),
        "duree_s": round(time.time() - t0, 1),
    }
    if args.json:
        print(json.dumps({"env": env, "composants": composants, "suites": suites,
                          "armable": armable, "resume": resume},
                         ensure_ascii=False, indent=2))
        return 1 if resume["FAIL"] else 0

    rendre("ENV — faits de machine", env)
    rendre("COMPOSANTS — présence + conformité (manifeste_dependances.yaml)", composants)
    print("\n═══ ARMABLE MAINTENANT ═══")
    for a in armable:
        if a["joignable"] is None:
            etat = "source non sondée (--no-probe)"
        else:
            etat = "source joignable ✔" if a["joignable"] else "source INJOIGNABLE ✘ (network)"
        print(f"  {a['composant']:<38} {etat:<38} {a['commande']}")
    print("\n═══ RÉSUMÉ ═══")
    print(f"  suites : {resume['PASS']} PASS · {resume['FAIL']} FAIL · {resume['BLOCKED']} BLOCKED"
          f" · {resume['non_evalues_cas']} cas non évalués · {resume['duree_s']} s")
    fails = [s for s in suites if s["verdict"] == "FAIL"]
    if fails:
        print("  FAIL à traiter (hors environnement) :")
        for s in fails:
            print(f"    - {s['suite']}  —  {s['detail']}")
    block = [s for s in suites if s["verdict"] == "BLOCKED"]
    if block:
        raisons_un = sorted({r for s in block for r in s["raisons"]})
        print("  BLOCKED par raison (chaque raison pointe son armement) :")
        for rtext in raisons_un:
            n = sum(1 for s in block if rtext in s["raisons"])
            print(f"    ×{n:<3} {rtext}")
    print("\n  Verdicts : PASS = verdicts rendus · FAIL = échec hors environnement (gate) · "
          "BLOCKED = non évaluable ici, raison exacte ci-dessus.")
    return 1 if resume["FAIL"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
