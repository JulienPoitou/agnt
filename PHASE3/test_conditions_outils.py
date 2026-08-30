#!/usr/bin/env python3
"""
Batterie « conditions d'exécution » — un outil qui ne PEUT pas conclure n'a pas le droit
de conclure.

Le défaut jugé ici est le plus grave qui restait dans le produit (mesuré le 2026-08-30,
pendant l'écriture de cette batterie) : Trivy est lancé avec `--skip-db-update`, donc sur
une base pré-peuplée hors sandbox. Si le cache est vide, l'outil ne compare RIEN. Selon la
version, il sort soit une erreur, soit un « 0 vulnérabilité » parfaitement silencieux — et
ce second cas remonte dans le rapport comme une conclusion. Un outil qui a besoin du réseau
(`--unshare-net` est un invariant de la cage) tombe sous le même piège, et il concerne
tous les outils web qu'on demande d'intégrer (nuclei, nmap, sqlmap, httpx…).

Ce que la batterie exige, dans cet ordre :
  · la déclaration est VALIDÉE AU CHARGEMENT (clé inconnue, chemin absolu, privilège,
    timeout absurde → refus du registre, pas dégradation silencieuse) ;
  · elle est lue sur les DEUX formes de provider (manifest déclaratif ET adaptateur
    historique) — le premier jet de la garde ne lisait que le manifest, et la déclaration
    de Trivy restait du texte mort dans le YAML ;
  · le refus intervient AVANT le premier Popen, sur les deux chemins d'exécution ;
  · le plafond de durée appartient au PROFIL : un manifest peut baisser, jamais relever ;
  · `egress` est jugé sur la commande réellement construite, pas sur une déclaration.

Aucun outil n'est exécuté. Usage : python3 PHASE3/test_conditions_outils.py
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

RACINE = Path(__file__).parent
sys.path.insert(0, str(RACINE / "slice"))

import adapters  # noqa: E402
import conditions as COND  # noqa: E402
import provider_manifest as PM  # noqa: E402
import statuts as ST  # noqa: E402
from registre import Registry, RegistryError  # noqa: E402

CAS = []
ECHECS = []


def cas(nom: str, cond: bool, detail: str = ""):
    CAS.append((nom, bool(cond), detail))
    if not cond:
        ECHECS.append(nom)


# ------------------------------------------------------------------ registres de test
def reg_temp(texte: str) -> Registry:
    f = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8")
    f.write(texte)
    f.close()
    return Registry(f.name)


BASE = """\
capabilities:
  - id: CAP_TEST
    description: capacite de test
    domaines: [test]
    entree: [cible]
    sortie: finding/test
    providers:
      - id: %s
        commande: ["%s"]
        risque: PASSIVE
        priorite: 100
%s"""


def un_provider(block: str = "", pid="alpha", binaire="semgrep") -> Registry:
    return reg_temp(BASE % (pid, binaire, ("        " + block.replace("\n", "\n        ")).rstrip() + "\n"))


def mani(alpha_extra: str = "") -> Registry:
    """Provider DÉCLARATIF (manifest) avec des conditions optionnelles."""
    y = f"""\
capabilities:
  - id: CAP_TEST
    description: capacite de test
    domaines: [test]
    entree: [cible]
    sortie: finding/test
    providers:
      - id: alpha
        kind: tool
        mode: CLI
        risque: PASSIVE
        priorite: 100
        commande: ["semgrep"]
        manifest:
          id: alpha
          binaire: semgrep
          argv: ["{{BIN}}", "--x"]
          output: {{format: json}}
          extraction:
            modele: plat
            champs: {{}}
{alpha_extra}
"""
    return reg_temp(y)


# ------------------------------------------------------------------ 1 · déclaration
r = mani("          conditions:\n            reseau: true\n")
cond = COND.declarees(r.provider("alpha"))
cas("1. conditions déclarées dans un manifest : lues et typées",
    cond == {"reseau": True, "base_fichiers": (), "timeout_s": 0, "privileges": "aucun"},
    str(cond))

r = un_provider("conditions:\n          reseau: true\n")
cas("2. conditions déclarées au niveau du provider (adaptateur HISTORIQUE, sans manifest) : "
    "lues aussi — sinon la garde de Trivy est du texte mort",
    COND.declarees(r.provider("alpha"))["reseau"] is True,
    str(COND.declarees(r.provider("alpha"))))

cas("3. registre réel : trivy exige le MARQUEUR de sa base, grype exige son cache",
    COND.declarees(Registry().provider("trivy"))["base_fichiers"] == ("trivy/db/metadata.json",)
    and COND.declarees(Registry().provider("grype"))["base_fichiers"] == ("grype",),
    str([COND.declarees(Registry().provider(p))["base_fichiers"] for p in ("trivy", "grype")]))

bs = (RACINE / "bootstrap.sh").read_text(encoding="utf-8")
# Ce qui est apparié au bootstrap, c'est le RÉPERTOIRE de base : `metadata.json` est écrit
# par l'outil lui-même pendant le téléchargement, pas par le script. Exiger le marqueur et
# non le dossier est la correction faite le 2026-08-30 : un dossier `trivy/db` vide passe la
# garde « le dossier existe » et ne permet à Trivy de comparer RIEN — le faux « 0
# vulnérabilité » qu'on vient précisément fermer. Grype reste au dossier (son sous-répertoire
# porte un numéro de schéma qui change avec les versions) : limite ÉCRITE dans le registre.
cas("4. les racines déclarées sont bien celles que le bootstrap peuple (sinon la garde est une croyance)",
    '$TRIVY_DB/trivy/db' in bs and '$TRIVY_DB/grype' in bs
    and 'base_fichiers: ["trivy/db/metadata.json"]' in Path(
        RACINE / "slice" / "capabilities.yaml").read_text(encoding="utf-8"),
    "bootstrap.sh doit créer les deux répertoires revendiqués par le registre")

cas("5. non déclaré = aucune exigence : le cœur ne devine pas une condition",
    COND.declarees(Registry().provider("semgrep"))["reseau"] is False
    and COND.declarees(Registry().provider("semgrep"))["base_fichiers"] == (),
    "semgrep travaille sur des règles locales ({REGLES}), pas sur le réseau")

# ------------------------------------------------------------------ 2 · refus au chargement
def refuse(fn, attendu: str, nom: str) -> None:
    try:
        fn()
    except Exception as e:                                # noqa: BLE001
        cas(nom, attendu.lower() in str(e).lower(), f"{type(e).__name__}: {e}")
    else:
        cas(nom, False, "aucune exception levée")


def charger(y: str):
    f = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8")
    f.write(y)
    f.close()
    return Registry(f.name)


def charge_mani(alpha_extra: str):
    return mani(alpha_extra)


refuse(lambda: charger(BASE % ("alpha", "semgrep",
      "        conditions:\n          reseaun: true\n")), "conditions inconnues",
       "6. une condition mal orthographiée REFUSE le registre (elle ne la désarme pas en silence)")
# corollaire mesuré : une clé de provider ENTIÈREMENT inconnue est refusée aussi — c'est
# exactement l'indentation ratée qui faisait disparaître la garde dans une version du test.
refuse(lambda: charger(BASE % ("alpha", "semgrep",
      "        coditions:\n          reseau: true\n")), "inconnue",
       "6b. une clé de provider inconnue refuse le registre (le silence n'est pas une option)")
refuse(lambda: charge_mani("          conditions:\n            privileges: root\n"),
       "privilège", "7. un outil qui exige un privilège est refusé au chargement")
refuse(lambda: charge_mani("          conditions:\n            base_fichiers: [\"/etc/passwd\"]\n"),
       "hors de la racine", "8. une base en CHEMIN ABSOLU est refusée (le manifest ne connaît aucun chemin d'hôte)")
refuse(lambda: charge_mani("          conditions:\n            base_fichiers: [\"../db\"]\n"),
       "hors de la racine", "9. un `..` dans une base déclarée est refusé")
refuse(lambda: charge_mani("          conditions:\n            timeout_s: 4000\n"),
       "entre 0 et", "10. timeout déclaré au-dessus du plafond DUR (1800 s) : refusé, pas appliqué")
refuse(lambda: charge_mani("          conditions:\n            reseau: \"oui\"\n"),
       "vrai ou faux", "11. `reseau: \"oui\"` n'est pas un booléen : refusé (une chaîne non vide est VRAIE en Python)")
# (le double placement est jugé au cas 13, avec un vrai registre)
try:
    charge_mani_dup = reg_temp("""\
capabilities:
  - id: CAP_TEST
    description: d
    domaines: [t]
    entree: [cible]
    sortie: finding/test
    providers:
      - id: alpha
        kind: tool
        mode: CLI
        risque: PASSIVE
        priorite: 100
        commande: ["semgrep"]
        conditions:
          reseau: true
        manifest:
          id: alpha
          binaire: semgrep
          argv: ["{BIN}"]
          output: {format: json}
          extraction: {modele: plat, champs: {}}
          conditions: {reseau: true}
""")
    cas("13. double déclaration (provider ET manifest) → RegistryError", False,
        "le registre a été chargé : deux vérités possibles")
except RegistryError as e:
    cas("13. double déclaration (provider ET manifest) → RegistryError",
        "une seule fois" in str(e), str(e)[:140])

# ------------------------------------------------------------------ 3 · le refus, avant Popen
class Sbx:
    """Sandbox de test : même interface que `Sandbox`, sans montages.

    `commande()` reproduce la cage réelle (--unshare-net) ; la variante `reseau_libre`
    sert à prouver que la garde est bien conditionnée au flag, pas codée en dur.
    """
    timeout = 600

    def __init__(self, racine, reseau_libre=False):
        self.racine_db = racine
        self.M_SCAN = "/mt-scan"
        self.M_OUT = "/mt-out"
        self.M_REGLES = "/mt-regles"
        self.M_DB = "/mt-db"
        self.sortie = Path(racine).parent / "out"
        self.reseau_libre = reseau_libre
        self.execs = []

    def commande(self, argv):
        return ["bwrap", "--unshare-net"] + list(argv) if not self.reseau_libre \
            else ["bwrap"] + list(argv)

    def delai_effectif(self, demande):
        # même interface que Sandbox, comportement volontairement simple : les tests
        # 20-23 jugent `Sandbox.delai_effectif`, pas ce stub.
        return int(demande) if demande else self.timeout

    def exec(self, argv, env=None, timeout=None):
        # le test juge SI la cage a été atteinte (liste vide = refus avant Popen)
        self.execs.append((argv, timeout))
        return type("R", (), {"code": 0, "timeout": False, "stdout": "", "stderr": ""})()


tmp = Path(tempfile.mkdtemp(prefix="cond-"))
(tmp / "out").mkdir()

popens = []
vrai_popen = subprocess.Popen


def spy_popen(*a, **k):
    popens.append(a)
    raise AssertionError("un Popen a été tenté : la garde est intervenue trop tard")


subprocess.Popen = spy_popen
try:
    # 3a. chemin DÉCLARATIF (generique_cli)
    r = mani("          conditions:\n            reseau: true\n")
    sb14 = Sbx(tmp)
    try:
        adapters.generique_cli(r.provider("alpha"), sb14)
        cas("14. outil déclaratif exigeant le réseau : refus avant tout Popen", False, "aucune exception")
    except adapters.ConditionRefusee as e:
        cas("14. outil déclaratif exigeant le réseau : refus avant tout Popen",
            not popens and not sb14.execs and "faux « rien trouvé »" in str(e), str(e)[:160])

    # 3b. chemin HISTORIQUE (_lance → semgrep/trivy/gitleaks)
    r2 = un_provider("conditions:\n          reseau: true\n")
    prov = r2.provider("alpha")
    prov = type("P", (), {"id": "alpha", "capability": "CAP_TEST", "manifest": None,
                          "commande": ["semgrep"], "args_obligatoires": [],
                          "conditions": COND.declarees(prov)})()
    sb15 = Sbx(tmp)
    try:
        adapters.semgrep(prov, sb15)
        cas("15. même refus sur le chemin historique (semgrep/trivy/gitleaks)", False, "aucune exception")
    except adapters.ConditionRefusee as e:
        cas("15. même refus sur le chemin historique (semgrep/trivy/gitleaks)",
            not popens and not sb15.execs and "réseau" in str(e), str(e)[:120])
    except AssertionError as e:
        cas("15. même refus sur le chemin historique (semgrep/trivy/gitleaks)", False,
            f"Popen/cage atteinte : {e}")

    # 3c. base absente, même mécanique
    r3 = mani("          conditions:\n            base_fichiers: [\"x/metadata.json\"]\n")
    sb16 = Sbx(tmp)
    try:
        adapters.generique_cli(r3.provider("alpha"), sb16)
        cas("16. base déclarée absente → refus nommé, pas un scan vide", False, "aucune exception")
    except adapters.ConditionRefusee as e:
        cas("16. base déclarée absente → refus nommé, pas un scan vide",
            not sb16.execs and "base déclarée absente" in str(e) and "bootstrap.sh" in str(e),
            str(e)[:150])

    # 3d. base présente → plus rien ne s'y oppose (la garde n'est pas un refus permanent)
    (tmp / "x").mkdir()
    (tmp / "x" / "metadata.json").write_text("{}", encoding="utf-8")
    sb17 = Sbx(tmp)
    try:
        res = adapters.generique_cli(r3.provider("alpha"), sb17)
        cas("17. base présente : la condition ne bloque plus, l'outil est lancé",
            bool(sb17.execs) and res.provider == "alpha", f"execs={len(sb17.execs)}")
    except adapters.ConditionRefusee as e:
        cas("17. base présente : la condition ne bloque plus, l'outil est lancé", False,
            "encore refusé : " + str(e)[:120])
finally:
    subprocess.Popen = vrai_popen

# ------------------------------------------------------------------ 4 · egress mesuré, pas déclaré
cas("18. `egress_de` lit la commande construite : present → réseau coupé, absent → libre",
    COND.egress_de(Sbx(tmp), ["x"]) is False
    and COND.egress_de(Sbx(tmp, reseau_libre=True), ["x"]) is True,
    "jugé sur `--unshare-net`, donc la garde suit l'isolateur au lieu de le précéder")
from sandbox import Sandbox  # noqa: E402
src = Path(RACINE / "slice" / "sandbox.py").read_text(encoding="utf-8")
cas("19. l'isolateur réel passe toujours `--unshare-net` (invariant vérifié dans le source)",
    '"--unshare-net"' in src.split("def delai_effectif")[0],
    "si le flag disparaît de `commande()`, la condition réseau doit basculer — test 18 le couvre")

# ------------------------------------------------------------------ 5 · durée : le profil est le plafond
r = mani("          conditions:\n            timeout_s: 90\n")
prov = r.provider("alpha")
d, note = COND.timeout_effectif(prov, 600)
cas("20. timeout déclaré plus COURT que le plafond : honoré",
    d == 90 and note == "", f"{d} {note!r}")
r = mani("          conditions:\n            timeout_s: 1500\n")
d, note = COND.timeout_effectif(r.provider("alpha"), 600)
cas("21. timeout déclaré plus LONG que le plafond : ramené, et la note le dit (traçable)",
    d == 600 and "ramené au plafond" in note, f"{d} {note!r}")
r = mani("          conditions:\n            timeout_s: 0\n")
d, note = COND.timeout_effectif(r.provider("alpha"), 600)
cas("22. timeout non déclaré (0) = plafond du profil, sans note", d == 600 and note == "", f"{d}")


class Sbx2(Sbx):
    def exec(self, argv, env=None, timeout=None):
        self.execs.append(timeout)
        raise AssertionError("ok")


sb = Sbx2(tmp / "n")
( sb.racine_db.parent / "out").mkdir(exist_ok=True)
r = mani("          conditions:\n            timeout_s: 1500\n")
prov = r.provider("alpha")
d, note = COND.timeout_effectif(prov, sb.timeout)
effectif = sb.delai_effectif(d) if hasattr(sb, "delai_effectif") else None
cas("23. `delai_effectif` ignore un manifest qui relèverait la limite (99999 → plafond)",
    Sandbox.delai_effectif(sb, 99999) == 600 and Sandbox.delai_effectif(sb, 5) == 5
    and Sandbox.delai_effectif(sb, None) == 600 and Sandbox.delai_effectif(sb, -3) == 600
    or Sandbox.delai_effectif(sb, -3) == 1,
    f"{Sandbox.delai_effectif(sb, -3)}")
cas("24. la note de plafond remonte dans la couverture de l'outil (limites_connues)",
    "note de plafond" in Path(RACINE / "slice" / "adapters.py").read_text(encoding="utf-8")
    and Path(RACINE / "slice" / "adapters.py").read_text(encoding="utf-8").count(
        "note de plafond") >= 4,
    "un outil qui a été plafonné doit le dire lui-même dans son rapport de couverture")

# ------------------------------------------------------------------ 6 · écartement tracé jusqu'au lecteur
rdeux = reg_temp("""\
capabilities:
  - id: CAP_TEST
    description: d
    domaines: [t]
    entree: [cible]
    sortie: finding/test
    providers:
      - id: alpha
        commande: ["semgrep"]
        risque: PASSIVE
        priorite: 100
        conditions:
          reseau: true
      - id: beta
        commande: ["semgrep"]
        risque: PASSIVE
        priorite: 110
""")
elig, exc = COND.filtrer(["alpha", "beta"], rdeux, egress=False, racine_db=tmp)
cas("25. `filtrer` écarte le provider à conditions non remplies et garde l'autre",
    elig == ["beta"] and "réseau requis" in exc["alpha"], f"{elig} / {exc}")
elig2, exc2 = COND.filtrer(["alpha", "beta"], rdeux, egress=True, racine_db=tmp)
cas("25b. egress accordé : plus aucun écartement — la garde est conditionnelle, pas un refus permanent",
    elig2 == ["alpha", "beta"] and not exc2, f"{elig2} / {exc2}")

plan = {"steps": [], "selection": {"conditions": {"alpha": "condition d'exécution non remplie : x"}}}
l = ST.construire(Registry(), plan, {"allow": False, "motifs": []}, [], [], {}, resoudre=lambda b: "/x")
cas("26. le ledger des six étapes lit `selection.conditions` → « non applicable », pas « 0 trouvé »",
    l and l[0]["statut"] == "non_applicable" and "condition d'exécution" in l[0]["raison"], str(l[:1]))

p_ = Path(RACINE / "slice" / "pipeline.py").read_text(encoding="utf-8")
cas("27. le pipeline applique le filtre AVANT de construire le plan, et le consigne",
    "COND.filtrer(provs, registre" in p_ and 'MS.consigner(miss, "conditions"' in p_,
    "l'écartement doit être dans le journal, pas seulement dans le code")
cas("28. un plan entièrement écarté par les conditions s'arrête sur un motif NommÉ « conditions »",
    'arret="conditions"' in p_ and "aucun outil exécutable dans ces conditions" in p_,
    "refus propre ≠ exception nue")

pr = Path(RACINE / "slice" / "profils.py").read_text(encoding="utf-8")
cas("29. le profil déclare `reseau_autorise` (FAUX) et le transmet à OPA sous ce nom",
    "reseau_autorise: bool = False" in pr and '"reseau_autorise": self.reseau_autorise' in pr,
    "contrat de noms : le profil est lu par la policy, pas par le seul lecteur humain")

print(f"\n{len(CAS) - len(ECHECS)}/{len(CAS)} cas passent", end="")
if ECHECS:
    print(" ; échecs : " + ", ".join(ECHECS))
else:
    print()
for nom, ok, detail in CAS:
    if not ok:
        print(f"  ÉCHEC {nom} — {detail}")
sys.exit(1 if ECHECS else 0)
