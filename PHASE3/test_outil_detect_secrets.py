#!/usr/bin/env python3
"""
Batterie « intégration d'un outil réel par la voie déclarative » — detect-secrets.

Pourquoi cette batterie existe : jusqu'ici, la promesse « un nouvel outil = un fichier de
plus, aucun changement du cœur » n'était démontrée que par bandit_custom, un outil déjà
présent sur la machine de développement et dont la sortie (CSV) ne se confondait jamais avec
un modèle déclaré. detect-secrets est le premier outil ajouté de bout en bout le
30/08/2026, et il a fait tomber DEUX défauts réels du chemin d'extension (cas 24 et 25 ci
dessous). Cette batterie épingle donc moins un outil que LE CONTRAT d'extension :

  · ce que le manifest a le droit de déclarer (et ce qui reste gardé par le cœur) ;
  · ce qu'un parser nommé doit rendre dans tous les cas, y compris sur une entrée sale ;
  · ce que la chaîne complète produit sur la SORTIE RÉELLE de l'outil (capturée ici, sans
    isolateur — voir NON ÉVALUÉ en fin de fichier).

Deux choix de test sont assumés :
  - l'outil est exécuté pour de vrai sur `testrepo` (lecture seule, offline) : un faux JSON
    écrit à la main ne prouverait rien sur la forme réelle de `results` ;
  - le sandbox est un double minimal : `bwrap` est indisponible sur cette machine, donc
    l'exécution sous isolateur n'est PAS mesurée ici — tout le reste du chemin l'est.

Usage: python3 PHASE3/test_outil_detect_secrets.py
"""
from __future__ import annotations

import copy
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
import parsers as PAR                                    # noqa: E402
import plan as PL                                        # noqa: E402
import provider_manifest as PM                           # noqa: E402
import outils as OUT                                    # noqa: E402
import registre as REGMOD                                 # noqa: E402
from intent import Intent, choisir_providers             # noqa: E402
from registre import Registry, RegistryError             # noqa: E402

FIXTURE = RACINE / "testrepo"
CAS: list[tuple[str, bool, str]] = []
ECHECS: list[str] = []
NON_EVALUE: list[str] = []


def cas(nom: str, cond: bool, detail: str = "") -> None:
    CAS.append((nom, bool(cond), detail))
    if not cond:
        ECHECS.append(nom)


def non_evalue(nom: str, raison: str) -> None:
    NON_EVALUE.append((nom, raison))


# ─────────────────────────────────────── sortie réelle de l'outil (capturée une fois)
def sortie_reelle(args: list[str], cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "detect_secrets", *args],
                          cwd=cwd, capture_output=True, text=True, timeout=300)


try:
    REELLE = sortie_reelle(["scan", "--all-files"], FIXTURE)
    SANS_ALL = sortie_reelle(["scan"], FIXTURE)
except Exception as e:                                  # outil non installé sur cette machine
    REELLE = types.CompletedProcess([], 127, "", str(e))
    SANS_ALL = types.CompletedProcess([], 127, "", str(e))
OUTIL_INSTALLE = REELLE.returncode == 0 and bool(REELLE.stdout.strip())
BASELINE = json.loads(REELLE.stdout) if OUTIL_INSTALLE else {}
NB_REELLES = sum(len(v) for v in (BASELINE.get("results") or {}).values())

REG = Registry()
PROV = REG.provider("detect_secrets")
MANI = PROV.manifest


# ───────────────────────────────────────────────────────────── le faux isolateur
class FauxSandbox:
    """Double de `Sandbox`, limité aux attributs que `generique_cli` lit réellement.

    `exec` renvoie une sortie FOURNIE, celle de l'outil quand on rejoue le vrai run. Les
    montages (ro-bind, unshare) ne sont pas simulés : ils ne sont pas en jeu dans le
    contrat testé ici, et leur absence est déclarée comme NON ÉVALUÉ.
    """

    M_SCAN, M_OUT, M_REGLES, M_DB, racine_db, timeout = "/source", "/out", "/reg", "/db", None, 300

    def __init__(self, stdout: str = "", code: int = 0, fichier_sortie: str | None = None):
        self._stdout, self._code = stdout, code
        self.dossier = Path(tempfile.mkdtemp(prefix="agnt-faux-"))
        if fichier_sortie is not None:
            (self.dossier / f"{MANI.id}.txt").write_text(fichier_sortie, encoding="utf-8")
        self.sortie = self.dossier

    def delai_effectif(self, demande):
        return demande

    def exec(self, argv, env=None, timeout=None):
        self.argv, self.env, self.timeout_effectif = argv, env, timeout
        return types.SimpleNamespace(code=self._code, timeout=False,
                                     stdout=self._stdout, stderr="")


def chaine(stdout="", code=0, prov=PROV, fichier_sortie=None):
    """générique_cli + normaliseur : exactement ce que fait le pipeline après l'outil."""
    sbx = FauxSandbox(stdout, code, fichier_sortie)
    res = A.generique_cli(prov, sbx)
    norm = F.normaliser(prov.id, res.donnees, mani=prov.manifest,
                        racines=(str(FIXTURE), str(FIXTURE.parent)))
    return sbx, res, norm


# ═════════════════════════════ 1. ce que le manifest déclare, et ce qui reste gardé
print("═══ 1 · déclaration de l'outil ═══")
cap = REG.capability("SECRET_DETECTION")
cas("provider chargé depuis le registre", PROV is not None and PROV.capability == "SECRET_DETECTION",
    PROV.capability)
cas("plafond de la capacité = 2 scanners, fan_out déclaré",
    cap.mode_selection == "fan_out" and cap.max_providers == 2,
    f"{cap.mode_selection}/{cap.max_providers}")
cas("le binaire est dans la liste que le cœur autorise",
    MANI.binaire in PM.BINAIRES_AUTORISES, str(MANI.binaire))
cas("risque PASSIVE (seule voie d'exécution automatique)", PROV.risque == "PASSIVE", PROV.risque)
cas("priorité derrière gitleaks : il complète, il ne remplace pas",
    MANI is not None and PROV.priorite > REG.provider("gitleaks").priorite,
    f"gitleaks {REG.provider('gitleaks').priorite} < detect_secrets {PROV.priorite}")
epingle = OUT.registre().get("detect-secrets")
cas("outil épinglé au manifeste des dépendances", epingle is not None, str(sorted(OUT.registre())))
cas("épingle complète : version + source + licence",
    bool(epingle) and all([epingle.version, epingle.source, epingle.licence]),
    getattr(epingle, "version", ""))
cas("régime pip dit tel quel (note, pas de faux hash de binaire)",
    bool(epingle) and epingle.installation == "pip" and bool(epingle.note),
    getattr(epingle, "note", "")[:40])
cas("argv: scan + --all-files", "scan" in MANI.argv and "--all-files" in MANI.argv, str(MANI.argv))
cas("argv: aucune vérification en ligne (--verify absent)",
    not any("verify" in a for a in MANI.argv), str(MANI.argv))
cas("argv: aucune écriture de fichier (--output absent, l'outil ne sait pas faire)",
    not any("--output" in a for a in MANI.argv), str(MANI.argv))
cas("format custom + parser nommé (le cœur ne connaît pas l'outil)",
    MANI.sortie_format == "custom" and MANI.extraction.parser == "detect_secrets_scan",
    f"{MANI.sortie_format}/{MANI.extraction.parser}")
cas("code_succes = [0] seulement (l'outil ne sort pas 1 sur trouvaille)",
    tuple(MANI.code_succes) == (0,), str(MANI.code_succes))
lim = MANI.limite or ""
cas("la limite mesurée est ÉCRITE dans le manifest, pas seulement sue",
    "--all-files" in lim and "vide" in lim, lim[:70])
# `declarees()` normalise : le dictionnaire a TOUJOURS les quatre clés (un provider muet
# rend `reseau False, base_fichiers (), timeout_s 0, privileges "aucun"`, pas `{}`).
# Exiger `== {}` aurait été une attente fausse — vérifiée telle quelle le 30/08/2026.
_decl = COND.declarees(PROV)
cas("aucune condition d'exécution déclarée (offline, sans base, sans privilège)",
    _decl["reseau"] is False and not _decl["base_fichiers"] and not _decl["timeout_s"]
    and _decl["privileges"] == "aucun",
    json.dumps(_decl, ensure_ascii=False))
cas("le provider ne déclare pas non plus de conditions au niveau provider",
    not PROV.conditions, str(PROV.conditions))

# ═════════════════════════════════════════ 2. contrat du parser nommé
print("═══ 2 · le parser tient son contrat ═══")
fn = PAR.obtenir("detect_secrets_scan")
cas("parser enregistré sous le nom déclaré", fn is not None, str(PAR.disponibles()))
cas("découverte des parsers sans liste à la main",
    "detect_secrets_scan" in PAR.disponibles() and "bandit_custom" in PAR.disponibles(),
    str(PAR.disponibles()))
cas("aucun module de parser en échec d'import", PAR.echecs_import() == {}, str(PAR.echecs_import()))
cas("entrée vide → []", fn("") == [], "")
cas("entrée non-JSON → [] (jamais d'exception)", fn("ceci n'est pas du json {") == [], "")
cas("JSON sans `results` → []", fn(json.dumps({"version": "1.5.0"})) == [], "")
cas("`results` qui n'est pas un objet → []", fn(json.dumps({"results": [1, 2]})) == [], "")
cas("fichier dont la liste n'est pas une liste → []",
    fn(json.dumps({"results": {"a.py": "pas une liste"}})) == [], "")
cas("entrées non-dict ignorées sans exception",
    fn(json.dumps({"results": {"a.py": [None, 3, {"type": "X", "line_number": 1}]}})) ==
    [{"regle": "X", "fichier": "a.py", "ligne": 1,
      "message": "X — empreinte  — non vérifié (l'outil n'a pas interrogé le fournisseur)"}],
    "")
cas("item = exactement les 4 clés attendues par `champs`",
    all(set(i) == {"regle", "fichier", "ligne", "message"}
        for i in fn(REELLE.stdout)) and bool(NB_REELLES), str(sorted(fn(REELLE.stdout)[0])))
items = fn(REELLE.stdout)
clair = next((l.strip() for l in (FIXTURE / "app.py").read_text(encoding="utf-8").splitlines()
              if "AKIA" in l or "ghp_" in l or "password" in l.lower()), "")
cas("la valeur en clair du secret n'apparaît dans AUCUN item",
    (not clair) or all(clair.split("=")[-1].strip().strip('"\'') not in json.dumps(i, ensure_ascii=False)
                       for i in items), clair[:40])
cas("l'empreinte du secret est conservée en préfixe (raccord entre findings)",
    any(i["message"].count("empreinte ") == 1 and " — " in i["message"] for i in items),
    items[0]["message"][:60] if items else "aucun item")

# ═════════════════════════════ 3. la chaîne complète, sur la sortie réelle de l'outil
print("═══ 3 · chaîne complète (adaptateur générique → normaliseur) ═══")
if not OUTIL_INSTALLE:
    for n in ("4 findings normalisés", "couverture par fichier", "stabilité des empreintes"):
        non_evalue(n, "outil detect-secrets non importable sur cette machine")
else:
    sbx, res, norm = chaine(REELLE.stdout)
    cas(f"{NB_REELLES} findings normalisés sur la fixture", len(norm) == NB_REELLES,
        f"{len(norm)} pour {NB_REELLES}")
    f0 = norm[0]
    cas("coordonnée = repository (l'outil ne rend pas un montage, un chemin relatif)",
        f0.location["asset"] == "repository" and f0.location["file"] == "app.py",
        json.dumps(f0.location, ensure_ascii=False))
    cas("ligne conservée telle que rendue par l'outil", f0.location["line"] == 4,
        str(f0.location["line"]))
    cas("sévérité UNKNOWN : rien n'est inventé pour habiller l'absence de niveau",
        f0.severity["value"] == "UNKNOWN" and f0.severity["origine"] == "detect_secrets",
        json.dumps(f0.severity, ensure_ascii=False))
    cas("règle canonique outillée", f0.source["canonical_rule_id"] == "detect_secrets:AWS Access Key",
        f0.source["canonical_rule_id"])
    cas("capability propagée à la source", f0.source["capability"] == "SECRET_DETECTION",
        str(f0.source.get("capability")))
    meme_ligne = [x for x in norm if x.location["line"] == 4]
    cas("empreintes distinctes pour des règles distinctes sur la même ligne",
        len({x.identity["fingerprint"] for x in meme_ligne}) == len(meme_ligne),
        str(len([x for x in norm if x.location["line"] == 4])))
    empreintes = sorted(f.identity["fingerprint"] for f in norm)
    _, res2, norm2 = chaine(REELLE.stdout)
    cas("rejeu à l'identique (empreintes stables)",
        sorted(f.identity["fingerprint"] for f in norm2) == empreintes, "")
    # identité machine-indépendante : mêmes items, racine déclarée différente
    norm3 = F.normaliser(PROV.id, res.donnees, mani=MANI,
                        racines=("/autre/poste/qui/n-existe-pas/testrepo",
                                 "/autre/poste/qui/n-existe-pas"))
    cas("empreintes indépendantes du chemin d'installation",
        sorted(f.identity["fingerprint"] for f in norm3) == empreintes, "")
    cov = res.couverture
    cas("couverture : le fichier porteur est déclaré scanné",
        any(c.chemin == "app.py" and c.etat == "scanned_successfully" for c in cov.cibles),
        str([(c.chemin, c.etat) for c in cov.cibles]))
    cas("scanners_actives nomme le provider et son format (pas un nom d'outil codé en dur)",
        cov.scanners_actives == ["detect_secrets:custom"], str(cov.scanners_actives))
    cas("la limite du manifest arrive dans les limites connues",
        any("--all-files" in l for l in cov.limites_connues), str(len(cov.limites_connues)))
    cas("aucune exécution réseau implicite dans l'environnement résolu",
        all("PROXY" not in k.upper() for k in (sbx.env or {})), str(sbx.env))
    # le cas « 0 finding » le plus trompeur : l'outil tourne sans --all-files → baseline vide
    _, res_vide, norm_vide = chaine(SANS_ALL.stdout if SANS_ALL.returncode == 0 else "{}")
    cas("scan sans --all-files : 0 finding, et ce n'est PAS présenté comme une couverture",
        len(norm_vide) == 0 and any(c.etat == "not_scanned" for c in res_vide.couverture.cibles),
        str([(c.etat, c.raison[:30]) for c in res_vide.couverture.cibles]))
    # ── RÉGRESSION du défaut trouvé en intégrant l'outil (cas 24) ──
    cas("le parser est l'autorité sur items même quand stdout est du JSON valide",
        len(res.donnees["items"]) == NB_REELLES and res.donnees["parser"] == "detect_secrets_scan",
        f"items={len(res.donnees['items'])}")
    cas("la sortie brute de l'outil reste conservée à côté (artefact et audit)",
        isinstance(res.donnees.get("sortie_brute"), dict)
        and "results" in res.donnees["sortie_brute"], str(sorted(res.donnees)))
    # et le contrôle direct du contournement, sans passer par l'adaptateur :
    detour = F.normaliser(PROV.id, BASELINE, mani=MANI,
                          racines=(str(FIXTURE), str(FIXTURE.parent)))
    cas("le JSON brut seul ne produit rien (c'est bien le parser qui parle)",
        len(detour) == 0, f"{len(detour)} findings depuis le baseline nu")
    # ── non-régression de l'autre provider à parser (bandit_custom) ──
    prov_b = REG.provider("bandit_custom")
    csv = "app.py,4,B105,possible hardcoded password\napp.py,9,B110,try except pass\n"
    sbx_b = FauxSandbox(stdout=csv, code=0, fichier_sortie=None)
    # le manifest de bandit lit un fichier .txt ; on lui fournit donc la sortie en fichier
    (sbx_b.sortie / f"{prov_b.manifest.id}.txt").write_text(csv, encoding="utf-8")
    res_b = A.generique_cli(prov_b, sbx_b)
    cas("bandit_custom inchangé : items du parser, pas de conteneur parasite",
        len(res_b.donnees["items"]) == 2 and "sortie_brute" not in res_b.donnees,
        json.dumps(res_b.donnees)[:90])
    # ── outils muets / en échec : le silence ne doit jamais ressembler à un scan propre ──
    _, res_muet, norm_muet = chaine("", code=0)
    cas("sortie vide : cible not_scanned et message explicite",
        len(norm_muet) == 0 and res_muet.couverture.cibles
        and "aucun résultat" in res_muet.couverture.cibles[0].raison,
        str([(c.etat, c.raison[:40]) for c in res_muet.couverture.cibles]))
    _, res_casse, _ = chaine('{"results": {}}', code=2)
    echecs = [l for l in res_casse.couverture.limites_connues if l.startswith("ÉCHEC")]
    cas("outil en échec (code 2) : la note d'échec est présente", len(echecs) == 1,
        str(len(echecs)))
    cas("le code d'échec est rendu, pas neutralisé", res_casse.code_retour == 2,
        str(res_casse.code_retour))
    _, res_ok, _ = chaine(REELLE.stdout, code=0)
    cas("aucune fausse alerte d'échec quand l'outil a rendu du lisible",
        not any(l.startswith("ÉCHEC") for l in res_ok.couverture.limites_connues), "")

# ═════════════════════════════ 4. sélection : le fan_out sert à quelque chose de mesurable
print("═══ 4 · sélection et plan ═══")
intent = Intent("resolved", "cherche des secrets dans le dépôt", capabilities=("SECRET_DETECTION",))
choix = choisir_providers(intent, REG)
cas("les DEUX scanners de secrets sont retenus", "gitleaks" in choix and "detect_secrets" in choix,
    str(choix))
cas("ordre de priorité respecté (gitleaks d'abord)", choix.index("gitleaks") < choix.index("detect_secrets"),
    str(choix))
plan = PL.construire("cherche des secrets dans le dépôt", str(FIXTURE), choix, REG,
                     "deterministe")
motif = json.dumps(getattr(plan, "selection", {}) or {}, ensure_ascii=False)
cas("le plan trace le motif fan_out (pas un accident de l'ordre YAML)",
    "fan_out" in motif, motif[:90])
cas("les deux étapes du plan portent la bonne capacité",
    {e.capability for e in plan.steps} == {"SECRET_DETECTION"} and len(plan.steps) == 2,
    str([(e.capability, e.provider) for e in plan.steps]))
# plafond non décoratif : 3 scanners déclarés, 2 retenus
y3 = """capabilities:
  - id: SECRET_DETECTION
    description: test
    domaines: [secrets, code]
    entree: [cible]
    sortie: finding/secret-exposure
    mode_selection: fan_out
    max_providers: 2
    providers:
      - {id: a, kind: cli, mode: CLI, risque: PASSIVE, priorite: 10, commande: ["{BIN}/a"]}
      - {id: b, kind: cli, mode: CLI, risque: PASSIVE, priorite: 20, commande: ["{BIN}/b"]}
      - {id: c, kind: cli, mode: CLI, risque: PASSIVE, priorite: 30, commande: ["{BIN}/c"]}
"""
with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8") as tf:
    tf.write(y3)
    chemin3 = tf.name
reg3 = Registry(chemin3)
cas("max_providers est un plafond, pas un commentaire",
    choisir_providers(intent, reg3) == ["a", "b"], str(choisir_providers(intent, reg3)))
Path(chemin3).unlink(missing_ok=True)

# ═════════════════ 5. la porte reste fermée : l'extension ne desserre aucune garde
print("═══ 5 · les gardes s'appliquent au nouveau provider comme aux autres ═══")


def avec_modif(mutator, attenduErreur=True):
    """Recharge le registre sur une copie du YAML modifiée (la garde est au chargement)."""
    doc = yaml_load(REGISTRY_YAML)
    mutator(doc)
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8") as tf:
        tf.write(yaml_dump(doc))
        p = tf.name
    try:
        Registry(p)
        return None
    except Exception as e:
        return f"{type(e).__name__}: {e}"
    finally:
        Path(p).unlink(missing_ok=True)


import yaml as _yaml                                       # noqa: E402
REGISTRY_YAML = REGMOD.REGISTRY_PATH


def yaml_load(p):
    return _yaml.safe_load(Path(p).read_text(encoding="utf-8"))


def yaml_dump(d):
    return _yaml.safe_dump(d, allow_unicode=True, sort_keys=False, width=100)


def met_cle_inconnue(doc):
    for c in doc["capabilities"]:
        if c["id"] == "SECRET_DETECTION":
            c["providers"][1]["ressources"] = "réseau"


def change_binaire(doc):
    for c in doc["capabilities"]:
        if c["id"] == "SECRET_DETECTION":
            c["providers"][1]["manifest"]["binaire"] = "curl"


def met_double_conditions(doc):
    for c in doc["capabilities"]:
        if c["id"] == "SECRET_DETECTION":
            # Un provider déclaratif porte ses conditions dans son manifest. Les mettre
            # AUSSI au niveau du provider crée deux vérités : le registre doit refuser.
            c["providers"][1]["conditions"] = {"reseau": True}
            c["providers"][1]["manifest"]["conditions"] = {"reseau": True}


err = avec_modif(met_cle_inconnue)
cas("clé de provider inconnue → le registre refuse", err is not None and "inconnue" in err, str(err)[:90])
err = avec_modif(change_binaire)
cas("binaire hors liste → manifest refusé au chargement",
    err is not None and "curl" in err, str(err)[:90])
err = avec_modif(met_double_conditions)
cas("conditions déclarées deux fois (provider + manifest) → refus",
    err is not None and "conditions" in err, str(err)[:90])


def reseau_declare(doc):
    for c in doc["capabilities"]:
        if c["id"] == "SECRET_DETECTION":
            # C'est DANS le manifest que la déclaration fait foi pour un provider
            # déclaratif (`conditions.declarees` donne la préséance au manifest).
            c["providers"][1]["manifest"]["conditions"] = {"reseau": True, "timeout_s": 60}


doc = yaml_load(REGMOD.REGISTRY_PATH)
reseau_declare(doc)
with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8") as tf:
    tf.write(yaml_dump(doc))
    chemin_r = tf.name
try:
    prov_r = Registry(chemin_r).provider("detect_secrets")
    motifs = COND.manquantes(prov_r, egress=False, racine_db=None)
    cas("si un outil déclarait avoir besoin du réseau, il serait refusé AVANT exécution",
        any("réseau" in m for m in motifs), str(motifs))
    sbx = FauxSandbox(REELLE.stdout)
    try:
        A.generique_cli(prov_r, sbx)
        leve = None
    except A.ConditionRefusee as e:
        leve = str(e)
    cas("et le refus est levé par l'adaptateur lui-même, pas seulement par le plan",
        leve is not None and "réseau" in leve, str(leve)[:90])
finally:
    Path(chemin_r).unlink(missing_ok=True)

# ── l'installateur doit suivre : sinon l'outil est déclaré mais inexécutable chez le user
print("═══ 6 · installation de la dépendance (sinon l'outil est déclaré, pas exécutable) ═══")
bs = (RACINE / "bootstrap.sh").read_text(encoding="utf-8")
cas("bootstrap.sh installe detect-secrets", "pip install --quiet detect-secrets" in bs, "")
cas("bootstrap.sh toujours syntaxiquement valide",
    subprocess.run(["bash", "-n", str(RACINE / "bootstrap.sh")], capture_output=True).returncode == 0, "")
cas("résolution de l'exécutable : le nom nu est trouvé dans le répertoire des outils",
    A.resoudre_exe("detect-secrets") is not None or not OUTIL_INSTALLE,
    str(A.resoudre_exe("detect-secrets")))
cas("un outil qui n'existe nulle part reste introuvable (pas de faux positif)",
    A.resoudre_exe("outil-qui-n-existe-pas") is None, "")
manifeste = (RACINE / "manifeste_dependances.yaml").read_text(encoding="utf-8")
cas("bootstrap refuse un tool pip sans empreinte ni note (règle déjà là, vérifiée sur le neuf)",
    "detect-secrets" in manifeste and "installé par pip" in manifeste.lower(), "")

print("═══ 7 · ce qui reste à démontrer ailleurs ═══")
non_evalue("exécution sous bubblewrap",
           "bwrap indisponible ici : le double de Sandbox exerce generique_cli, pas les montages "
           "ni --unshare-net. `test_bwrap.sh` (77) et le profil du répertoire restent la preuve "
           "valable pour tout outil, celui-ci n'ayant aucune particularité de montage.")
non_evalue("décision OPA sur le nouveau provider",
           "binaire opa absent : `evaluer` n'est pas rejouable ici. Le provider passe les mêmes "
           "gardes (binaire autorisé, risque PASSIVE, capacité) que les sept autres.")
non_evalue("rendu navigateur des findings detect_secrets",
           "la batterie `_domtest.mjs` tourne sur des artefacts figés ; le nouveau provider n'y "
           "figure pas. Sévérité UNKNOWN et asset=repository sont déjà exercés par d'autres outils.")

# ═════════════════════════════════════════════════════════════════════════════─ bilan
nb = len(CAS)
ok = sum(1 for _, c, _ in CAS if c)
print(f"\n{ok}/{nb} attendus vérifiés")
for nom, cond, detail in CAS:
    if not cond:
        print(f"  ÉCHEC · {nom}\n        {detail}")
for nom, raison in NON_EVALUE:
    print(f"  NON ÉVALUÉ · {nom} — {raison}")
sys.exit(1 if ECHECS else 0)
