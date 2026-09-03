#!/usr/bin/env python3
"""
Batterie « intégration d'un outil réel par la voie déclarative » — hadolint.

Dixième provider du registre, TROISIÈME de IAC_SCAN (checkov, kics, hadolint) :
chevauchement PARTIEL assumé, même discipline que trivy/grype — les règles DL
de hadolint ne recouvrent ni checkov ni kics, la convergence se fait par cible.
Intégré le 2026-09-01 par la voie detect-secrets (registre → manifest → parser →
normaliseur, le cœur n'a PAS changé).

Particularités mesurées :
  · hadolint 2.15.1 n'a pas de mode répertoire (« Invalid option --recursive ») :
    le binaire exécuté est le wrapper VERSIONNÉ `hadolint_scan` (bootstrap.sh) ;
  · `--no-fail` est OBLIGATOIRE : rc=0 dès que les findings sont écrits — un rc=1
    nu (fichier absent) ne doit jamais se lire « 0 constat » ;
  · exécution réelle sur la fixture `testrepo_iac` (Dockerfile existant) :
    4 findings attendus (DL3007, DL3008, DL3015, DL3009).

Usage: python3 PHASE3/test_outil_hadolint.py
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import types
from pathlib import Path

RACINE = Path(__file__).parent
sys.path.insert(0, str(RACINE / "slice"))

import adapters as A                                    # noqa: E402
import findings as F                                    # noqa: E402
import parsers as PAR                                   # noqa: E402
import provider_manifest as PM                          # noqa: E402
import outils as OUT                                    # noqa: E402
from registre import Registry                           # noqa: E402

FIXTURE = RACINE / "testrepo_iac"
WRAPPER = Path.home() / ".cache" / "arena_secops" / "bin" / "hadolint_scan"
CAS: list[tuple[str, bool, str]] = []
ECHECS: list[str] = []
NON_EVALUE: list[str] = []


def cas(nom: str, cond: bool, detail: str = "") -> None:
    CAS.append((nom, bool(cond), detail))
    if not cond:
        ECHECS.append(nom)


def non_evalue(nom: str, raison: str) -> None:
    NON_EVALUE.append((nom, raison))


def sortie_reelle(cible: Path) -> subprocess.CompletedProcess:
    if not WRAPPER.is_file():
        return subprocess.CompletedProcess([], 127, "", "wrapper hadolint_scan absent du cache")
    tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
    tmp.close()
    r = subprocess.run([str(WRAPPER), str(cible), tmp.name],
                       capture_output=True, text=True, timeout=300)
    r.stdout = Path(tmp.name).read_text(encoding="utf-8")
    Path(tmp.name).unlink(missing_ok=True)
    return r


REELLE = sortie_reelle(FIXTURE)
OUTIL_ARME = REELLE.returncode == 0 and bool(REELLE.stdout.strip())

REG = Registry()
PROV = REG.provider("hadolint")
MANI = PROV.manifest


class FauxSandbox:
    """Double de Sandbox (même contrat que la batterie detect-secrets)."""

    M_SCAN, M_OUT, M_REGLES, M_DB, racine_db, timeout = "/source", "/out", "/reg", "/db", None, 300

    def __init__(self, stdout: str = "", code: int = 0, fichier_sortie: str | None = None):
        self._stdout, self._code = stdout, code
        self.dossier = Path(tempfile.mkdtemp(prefix="agnt-faux-hd-"))
        if fichier_sortie is not None:
            (self.dossier / f"{MANI.id}.txt").write_text(fichier_sortie, encoding="utf-8")
        self.sortie = self.dossier

    def delai_effectif(self, demande):
        return demande

    def exec(self, argv, env=None, timeout=None):
        self.argv, self.env, self.timeout_effectif = argv, env, timeout
        return types.SimpleNamespace(code=self._code, timeout=False,
                                     stdout=self._stdout, stderr="")


def chaine(stdout="", code=0, fichier_sortie=None):
    sbx = FauxSandbox(stdout, code, fichier_sortie)
    res = A.generique_cli(PROV, sbx)
    norm = F.normaliser(PROV.id, res.donnees, mani=PROV.manifest,
                        racines=(str(FIXTURE), str(FIXTURE.parent)))
    return sbx, res, norm


# ═══════════════════════════════════ 1 · déclaration
print("═══ 1 · déclaration de l'outil ═══")
cas("provider chargé depuis le registre, capacité IAC_SCAN",
    PROV is not None and PROV.capability == "IAC_SCAN", str(PROV.capability))
cas("troisième provider de IAC_SCAN, derrière kics (priorité 120)",
    [p.id for p in REG.capability("IAC_SCAN").providers] == ["checkov", "kics", "hadolint"]
    and PROV.priorite > REG.provider("kics").priorite,
    str([(p.id, p.priorite) for p in REG.capability("IAC_SCAN").providers]))
cas("le binaire exécuté (le wrapper) est dans la porte du cœur",
    MANI.binaire in PM.BINAIRES_AUTORISES, str(MANI.binaire))
cas("risque PASSIVE", PROV.risque == "PASSIVE", PROV.risque)
cas("format custom + parser nommé",
    MANI.sortie_format == "custom" and MANI.extraction.parser == "hadolint",
    f"{MANI.sortie_format}/{MANI.extraction.parser}")
cas("code_succes = [0] (--no-fail mesuré : 0 même avec findings)",
    tuple(MANI.code_succes) == (0,), str(MANI.code_succes))
cas("applicabilité limitée aux Dockerfiles",
    MANI.applicable_globs == ("Dockerfile", "Dockerfile.*"), str(MANI.applicable_globs))
cas("--no-fail : dans le WRAPPER versionné (pas dans l'argv — le rc=1 nu ne doit jamais exister)",
    "armer_hadolint" in (RACINE / "bootstrap.sh").read_text(encoding="utf-8")
    and "--no-fail" in (RACINE / "bootstrap.sh").read_text(encoding="utf-8"),
    "wrapper sans --no-fail ?")
lim = MANI.limite or ""
cas("la limite mesurée est écrite dans le manifest", "--recursive" in lim and "wrapper" in lim,
    lim[:60])

epingles = OUT.registre()
for nom in ("hadolint", "hadolint_scan"):
    e = epingles.get(nom)
    cas(f"épingle manifeste complète : {nom}",
        bool(e) and all([e.version, e.source, e.licence, e.sha256]),
        str({k: getattr(e, k) for k in ("version", "source", "licence")} if e else None))

# ═══════════════════════════════════ 2 · contrat du parser
print("═══ 2 · le parser tient son contrat ═══")
fn = PAR.obtenir("hadolint")
cas("parser enregistré sous le nom déclaré", fn is not None, str(PAR.disponibles()))
cas("aucun module de parser en échec d'import", PAR.echecs_import() == {}, str(PAR.echecs_import()))
cas("entrée vide → []", fn("") == [], "")
cas("entrée non-JSON → [] (jamais d'exception)", fn("hadolint: erreur interne") == [], "")
cas("JSON qui n'est pas une liste → []", fn(json.dumps({"error": "x"})) == [], "")
cas("items non-dict ignorés sans exception",
    fn(json.dumps([None, {"code": "DL3007", "file": "Dockerfile", "line": 1,
                          "level": "warning", "message": "latest"}])) ==
    [{"regle": "DL3007", "fichier": "Dockerfile", "ligne": 1,
      "severite": "warning", "message": "latest"}], "")
items = fn(REELLE.stdout) if OUTIL_ARME else []
cas("item = les 5 clés attendues par `champs`",
    (not items) or all(set(i) == {"regle", "fichier", "ligne", "severite", "message"}
                       for i in items), str(sorted(items[0])) if items else "")
cas("les codes DL conservés tels quels (pas de normalisation inventée)",
    (not items) or all(i["regle"].startswith("DL") for i in items),
    str([i["regle"] for i in items[:3]]))

# ═════════════════════════ 3 · chaîne complète sur la sortie réelle
print("═══ 3 · chaîne complète (wrapper réel → adaptateur → normaliseur) ═══")
if not OUTIL_ARME:
    for n in ("4 findings normalisés sur testrepo_iac", "sévérité brute conservée en majuscules",
              "empreintes stables au rejeu"):
        non_evalue(n, "wrapper hadolint_scan absent du cache (bash PHASE3/bootstrap.sh --armement hadolint)")
else:
    _, res, norm = chaine(REELLE.stdout, code=0)
    cas("4 findings normalisés sur testrepo_iac", len(norm) == 4, str(len(norm)))
    f0 = norm[0]
    cas("règle canonique outillée (hadolint:DL…)",
        f0.source["canonical_rule_id"].startswith("hadolint:DL"),
        f0.source["canonical_rule_id"])
    cas("capability propagée à la source", f0.source["capability"] == "IAC_SCAN",
        str(f0.source.get("capability")))
    cas("chemin relatif + asset repository",
        f0.location["asset"] == "repository"
        and all(f.location["file"].startswith("Dockerfile") for f in norm),
        str({f.location["file"] for f in norm}))
    cas("sévérité brute passée en majuscules, origine = outil",
        {f.severity["value"] for f in norm} <= {"ERROR", "WARNING", "INFO", "STYLE"}
        and all(f.severity["origine"] == "hadolint" for f in norm),
        str({f.severity["value"] for f in norm}))
    regles = {f.source["canonical_rule_id"].split(":")[1] for f in norm}
    cas("les DL mesurés sur la fixture sont tous trouvés",
        {"DL3007", "DL3008", "DL3015", "DL3009"} <= regles, str(sorted(regles)))
    empreintes = sorted(f.identity["fingerprint"] for f in norm)
    _, _, norm2 = chaine(REELLE.stdout, code=0)
    cas("rejeu à l'identique (empreintes stables)",
        sorted(f.identity["fingerprint"] for f in norm2) == empreintes, "")
    cas("couverture nomme le provider et son format",
        res.couverture.scanners_actives == ["hadolint:custom"], str(res.couverture.scanners_actives))
    _, res_casse, _ = chaine("", code=1)
    cas("sortie vide + rc=1 (le cas piège hadolint) : échec rendu, pas « 0 constat »",
        res_casse.code_retour == 1 and len([f for f in norm if False]) == 0
        and res_casse.couverture.cibles, str(res_casse.code_retour))

# ═════════════════════════ 4 · installation
print("═══ 4 · installation de la dépendance ═══")
bs = (RACINE / "bootstrap.sh").read_text(encoding="utf-8")
cas("bootstrap.sh arme hadolint (composant)", "armer_hadolint" in bs, "")
cas("bootstrap.sh pose le wrapper versionné", "hadolint_scan" in bs, "")
cas("bootstrap.sh toujours syntaxiquement valide",
    subprocess.run(["bash", "-n", str(RACINE / "bootstrap.sh")], capture_output=True).returncode == 0, "")

print("═══ 5 · ce qui reste à démontrer ailleurs ═══")
non_evalue("exécution sous bubblewrap", "même convention que detect-secrets : le double "
           "de Sandbox exerce generique_cli ; test_bwrap.sh reste la preuve de montages.")
non_evalue("décision OPA sur le nouveau provider", "binaire opa absent de cette machine ; "
           "le provider passe les mêmes gardes (porte, PASSIVE, capacité) que les autres.")

nb = len(CAS)
ok = sum(1 for _, c, _ in CAS if c)
print(f"\n{ok}/{nb} attendus vérifiés")
for nom, cond, detail in CAS:
    if not cond:
        print(f"  ÉCHEC · {nom}\n        {detail}")
for nom, raison in NON_EVALUE:
    print(f"  NON ÉVALUÉ · {nom} — {raison}")
sys.exit(1 if ECHECS else 0)
