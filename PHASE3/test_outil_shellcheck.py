#!/usr/bin/env python3
"""
Batterie « intégration d'un outil réel par la voie déclarative » — shellcheck.

Neuf ième provider du registre, premier de la capacité SHELL_ANALYSIS (couverture
zéro avant lui : aucun outil du cœur ne lisait un script shell). Intégré le
2026-09-01 de bout en bout par la voie detect-secrets :

  · registre → manifest → parser nommé → normaliseur (le cœur n'a PAS changé) ;
  · particularité mesurée : shellcheck ne prend pas de répertoire (rc=2) — le
    binaire exécuté est le wrapper VERSIONNÉ `shellcheck_scan` (bootstrap.sh),
    épinglé au manifeste comme un outil à part entière ;
  · exécution réelle sur la fixture `testrepo_shell` (lecture seule, offline) :
    5 findings attendus sur `deploiement.sh`, 0 sur `propre.sh`.

Usage: python3 PHASE3/test_outil_shellcheck.py
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
import conditions as COND                               # noqa: E402
import findings as F                                    # noqa: E402
import parsers as PAR                                   # noqa: E402
import provider_manifest as PM                          # noqa: E402
import outils as OUT                                    # noqa: E402
from registre import Registry                           # noqa: E402

FIXTURE = RACINE / "testrepo_shell"
WRAPPER = Path.home() / ".cache" / "arena_secops" / "bin" / "shellcheck_scan"
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
        return types.CompletedProcess([], 127, "", "wrapper shellcheck_scan absent du cache")
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
PROV = REG.provider("shellcheck")
MANI = PROV.manifest


class FauxSandbox:
    """Double de Sandbox (même contrat que la batterie detect-secrets)."""

    M_SCAN, M_OUT, M_REGLES, M_DB, racine_db, timeout = "/source", "/out", "/reg", "/db", None, 300

    def __init__(self, stdout: str = "", code: int = 0, fichier_sortie: str | None = None):
        self._stdout, self._code = stdout, code
        self.dossier = Path(tempfile.mkdtemp(prefix="agnt-faux-sc-"))
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
cap = REG.capability("SHELL_ANALYSIS")
cas("provider chargé depuis le registre", PROV is not None and PROV.capability == "SHELL_ANALYSIS",
    str(PROV.capability))
cas("capacité nouvelle, un seul provider (chevauchement zéro avant lui)",
    [p.id for p in cap.providers] == ["shellcheck"], str([p.id for p in cap.providers]))
cas("le binaire exécuté (le wrapper) est dans la porte du cœur",
    MANI.binaire in PM.BINAIRES_AUTORISES, str(MANI.binaire))
cas("le vrai binaire shellcheck aussi (le wrapper l'appelle)",
    "shellcheck" in PM.BINAIRES_AUTORISES, "")
cas("risque PASSIVE", PROV.risque == "PASSIVE", PROV.risque)
cas("format custom + parser nommé",
    MANI.sortie_format == "custom" and MANI.extraction.parser == "shellcheck",
    f"{MANI.sortie_format}/{MANI.extraction.parser}")
cas("code_succes = [0, 1] (mesuré : 1 = findings écrits)",
    tuple(MANI.code_succes) == (0, 1), str(MANI.code_succes))
cas("applicabilité limitée aux scripts shell",
    MANI.applicable_globs == ("*.sh", "*.bash"), str(MANI.applicable_globs))
lim = MANI.limite or ""
cas("la limite mesurée (pas de répertoire) est écrite dans le manifest",
    "répertoire" in lim and "wrapper" in lim, lim[:60])
_decl = COND.declarees(PROV)
cas("aucune condition d'exécution déclarée (offline, sans base)",
    _decl["reseau"] is False and not _decl["base_fichiers"], json.dumps(_decl, ensure_ascii=False))

epingles = OUT.registre()
for nom in ("shellcheck", "shellcheck_scan"):
    e = epingles.get(nom)
    cas(f"épingle manifeste complète : {nom}",
        bool(e) and all([e.version, e.source, e.licence, e.sha256]),
        str({k: getattr(e, k) for k in ("version", "source", "licence")} if e else None))

# ═══════════════════════════════════ 2 · contrat du parser
print("═══ 2 · le parser tient son contrat ═══")
fn = PAR.obtenir("shellcheck")
cas("parser enregistré sous le nom déclaré", fn is not None, str(PAR.disponibles()))
cas("aucun module de parser en échec d'import", PAR.echecs_import() == {}, str(PAR.echecs_import()))
cas("entrée vide → []", fn("") == [], "")
cas("entrée non-JSON → [] (jamais d'exception)", fn("pas du json [") == [], "")
cas("JSON qui n'est pas une liste → []", fn(json.dumps({"a": 1})) == [], "")
cas("items non-dict ignorés sans exception",
    fn(json.dumps([None, 3, {"file": "a.sh", "line": 2, "code": 2086, "level": "info"}])) ==
    [{"regle": "SC2086", "fichier": "a.sh", "ligne": 2, "severite": "info", "message": None}],
    "")
items = fn(REELLE.stdout) if OUTIL_ARME else []
cas("item = les 5 clés attendues par `champs`",
    (not items) or all(set(i) == {"regle", "fichier", "ligne", "severite", "message"}
                       for i in items), str(sorted(items[0])) if items else "")
cas("le code numérique est reconstruit en règle canonique SC<code>",
    (not items) or all(i["regle"].startswith("SC") for i in items),
    str([i["regle"] for i in items[:3]]))
cas("la sévérité reste brute (info/warning — aucun mapping inventé)",
    (not items) or all(i["severite"] in ("error", "warning", "info", "style") for i in items),
    str(sorted({i["severite"] for i in items})))

# ═════════════════════════ 3 · chaîne complète sur la sortie réelle
print("═══ 3 · chaîne complète (wrapper réel → adaptateur → normaliseur) ═══")
if not OUTIL_ARME:
    for n in ("5 findings normalisés sur la fixture", "sévérité brute conservée en majuscules",
              "empreintes stables au rejeu"):
        non_evalue(n, "wrapper shellcheck_scan absent du cache (bash PHASE3/bootstrap.sh --armement shellcheck)")
else:
    ATTENDUS = {("deploiement.sh", "SC2086"), ("deploiement.sh", "SC2164"), ("deploiement.sh", "SC2012")}
    _, res, norm = chaine(REELLE.stdout, code=1)
    cas("5 findings normalisés sur la fixture", len(norm) == 5, str(len(norm)))
    f0 = norm[0]
    cas("règle canonique outillée (shellcheck:SC…)",
        f0.source["canonical_rule_id"].startswith("shellcheck:SC"),
        f0.source["canonical_rule_id"])
    cas("capability propagée à la source", f0.source["capability"] == "SHELL_ANALYSIS",
        str(f0.source.get("capability")))
    cas("coordination = repository, chemin relatif à la cible",
        f0.location["asset"] == "repository"
        and all(f.location["file"].startswith("deploiement.sh")
                or f.location["file"].startswith("propre.sh") for f in norm),
        str([f.location["file"] for f in norm]))
    cas("sévérité brute passée en majuscules, origine = outil",
        all(f.severity["value"] in ("ERROR", "WARNING", "INFO", "STYLE")
            and f.severity["origine"] == "shellcheck" for f in norm),
        str({f.severity["value"] for f in norm}))
    trouves = {(f.location["file"], f.source["canonical_rule_id"].split(":")[1]) for f in norm}
    cas("les défauts volontaires de la fixture sont trouvés", ATTENDUS <= trouves, str(trouves))
    cas("propre.sh rend 0 finding (script volontairement propre)",
        all(f.location["file"] == "deploiement.sh" for f in norm),
        str({f.location["file"] for f in norm}))
    empreintes = sorted(f.identity["fingerprint"] for f in norm)
    _, res2, norm2 = chaine(REELLE.stdout, code=1)
    cas("rejeu à l'identique (empreintes stables)",
        sorted(f.identity["fingerprint"] for f in norm2) == empreintes, "")
    cas("couverture nomme le provider et son format",
        res.couverture.scanners_actives == ["shellcheck:custom"], str(res.couverture.scanners_actives))
    # la cible sans fichier éligible : fichier de sortie vide, jamais un faux « scanné »
    sbx_v, res_v, norm_v = chaine("", code=0)
    cas("sortie vide : not_scanned et message explicite (pas un « propre »)",
        len(norm_v) == 0 and res_v.couverture.cibles
        and res_v.couverture.cibles[0].etat == "not_scanned",
        str([(c.etat, c.raison[:40]) for c in res_v.couverture.cibles]))
    _, res_casse, _ = chaine("pas du json", code=10)
    cas("sortie non-JSON (rc=10 du wrapper) : échec rendu, pas neutralisé",
        res_casse.code_retour == 10, str(res_casse.code_retour))

# ═════════════════════════ 4 · installation (sinon l'outil est déclaré, pas exécutable)
print("═══ 4 · installation de la dépendance ═══")
bs = (RACINE / "bootstrap.sh").read_text(encoding="utf-8")
cas("bootstrap.sh arme shellcheck (composant)", "armer_shellcheck" in bs, "")
cas("bootstrap.sh pose le wrapper versionné", "shellcheck_scan" in bs and "FIN_SCANNER" in bs, "")
cas("bootstrap.sh toujours syntaxiquement valide",
    subprocess.run(["bash", "-n", str(RACINE / "bootstrap.sh")], capture_output=True).returncode == 0, "")
cas("le wrapper sur cible sans fichier éligible : sortie vide, rc=0",
    (not WRAPPER.is_file())
    or sortie_reelle(FIXTURE.parent).returncode in (0, 127), str(REELLE.returncode))

print("═══ 5 · ce qui reste à démontrer ailleurs ═══")
non_evalue("exécution sous bubblewrap", "même convention que detect-secrets : le double "
           "de Sandbox exerce generique_cli ; test_bwrap.sh reste la preuve de montages.")
non_evalue("décision OPA sur le nouveau provider", "binaire opa absent de cette machine ; "
           "le provider passe les mêmes gardes (porte, PASSIVE, capacité) que les huit autres.")

nb = len(CAS)
ok = sum(1 for _, c, _ in CAS if c)
print(f"\n{ok}/{nb} attendus vérifiés")
for nom, cond, detail in CAS:
    if not cond:
        print(f"  ÉCHEC · {nom}\n        {detail}")
for nom, raison in NON_EVALUE:
    print(f"  NON ÉVALUÉ · {nom} — {raison}")
sys.exit(1 if ECHECS else 0)
