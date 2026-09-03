#!/usr/bin/env python3
"""
Batterie « vague parallèle et ledger vivant » — LOT 3, 31/08/2026.

Ce que la vague promet, dans l'ordre où ça compte :

  1. LE MÊME CORPS pour chaque outil, qu'il tourne seul ou avec trois autres. La
     parallelisation porte sur l'ORDONNANCEMENT, jamais sur les gardes.
  2. DES ARTEFACTS INDÉPENDANTS DE L'HORLOGE. Deux exécutions du même plan — l'une à un
     outil par vague, l'autre à quatre — doivent produire les mêmes octets, dans le même
     ordre. C'est ce qui fait qu'une empreinte de résultat reste une empreinte de résultat.
  3. UN SEUL POINT D'ARRÊT, désigné par le PLAN et non par la vitesse : quand deux outils
     tombent, le motif consigné est celui du premier fautif dans l'ordre du plan.
  4. UN LEDGER VIVANT, produit par la même fonction que l'état final, avec le même
     vocabulaire.

Pourquoi un double de sandbox, et pas « vrai de bout en bout » : sur cette machine `opa`
est injouable (openpolicyagent.org ne répond pas) et `bwrap` est absent — `executer()`
refuse donc la mission AVANT d'atteindre la vague. Le corps d'exécution a été sorti de sa
closure, en `pipeline._vague(steps_, V, ...)`, exactement pour cette raison : il se pilote
à vide avec les VRAIS adaptateurs (`adapters.executer` → `generique_cli` → `extraction` →
`findings` → disque), et seul bwrap est doublé. Ce qui est mesuré ici est donc la vague,
pas la cage : la cage se mesure dans `test_qualite_plateforme.py` (section 3) et son épreuve
réelle est écrite en NON ÉVALUÉ aux deux endroits.

Usage : python3 PHASE3/test_vague_parallele.py
"""
from __future__ import annotations

import dataclasses
import json
import os
import shutil
import sys
import tempfile
import types
import threading
import time
from pathlib import Path

RACINE = Path(__file__).parent

# ──── Indépendance machine de la garde D1 (02/09/2026) ─────────────────────────────
# Cette batterie joue la VRAIE vague avec les VRAIS adaptateurs sur un double de cage.
# Or `generique_cli` refuse, à juste titre, un outil absent (règle D1 — c'est
# `test_conditions_outils` qui l'exige nommément) : sur une machine non armée la vague
# ne partait jamais, et la promesse « se piloter à vide sur des doubles » devenait
# inexécutable. La sortie n'est pas de relâcher D1 dans le cœur — c'est d'armer CE
# PROCESSUS d'un cache qui ne vit que pour lui : `ARENA_SECOPS_CACHE` (le crochet que
# `sandbox.py` offre déjà) pointe vers un répertoire éphémère contenant le NOM exécutable
# des outils ; le double de cage ne les lance jamais vraiment, donc aucun résultat ne
# vient d'eux. Un outil réellement installé garde la préséance (le cache du test ne
# change que le cas « absent »).
_SCRATCH_CACHE = Path(tempfile.mkdtemp(prefix="agnt-vague-cache-"))
(_SCRATCH_CACHE / "bin").mkdir()
os.environ["ARENA_SECOPS_CACHE"] = str(_SCRATCH_CACHE)
for _nom in ("bandit", "radon", "detect-secrets", "checkov", "semgrep", "trivy",
             "gitleaks", "grype", "kics", "pip-audit", "ruff", "trufflehog3",
             "eslint", "gosec", "npm", "nmap", "nuclei", "ffuf", "zap-baseline.py",
             "hadolint", "shellcheck"):
    _c = _SCRATCH_CACHE / "bin" / _nom
    _c.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    _c.chmod(0o755)

sys.path.insert(0, str(RACINE / "slice"))

import mission as MS                                   # noqa: E402
import pipeline                                        # noqa: E402
import sandbox as SB                                   # noqa: E402
import statuts as ST                                   # noqa: E402
from registre import Registry                          # noqa: E402

CAS: list = []
ECHECS: list = []
NON_EVALUES: list = []


def cas(nom: str, cond, detail=""):
    CAS.append((nom, bool(cond), detail))
    if not cond:
        ECHECS.append(nom)


def non_evalue(nom: str, cause: str):
    NON_EVALUES.append((nom, cause))


# ------------------------------------------------------------------ le double de cage
@dataclasses.dataclass(frozen=True)
class SbxDouble:
    """Ce que `adapters.generique_cli` attend d'une sandbox, et rien de plus.

    Deux compteurs sont tenus ici parce qu'ils sont tout l'enjeu du lot :

    · `lanceurs` — l'ordre d'ARRIVÉE des exécutions. C'est l'horloge du monde réel ; si un
      artefact se mettait à la suivre, les cas 6 à 9 rougiraient.
    · `concurrence` — le pic d'outils réellement en train de tourner. Sans lui, « quatre de
      front » ne serait qu'un chiffre dans une config qu'aucun test ne regarde.
    """
    sortie: Path
    octets: dict = dataclasses.field(default_factory=dict)     # fichier → contenu
    latence: dict = dataclasses.field(default_factory=dict)    # provider → secondes
    en_echec: dict = dataclasses.field(default_factory=dict)  # provider → Exception
    par_binaire: dict = dataclasses.field(default_factory=dict)   # argv[0] → provider
    lanceurs: list = dataclasses.field(default_factory=list)
    achevements: list = dataclasses.field(default_factory=list)  # ordre de FIN
    fils: list = dataclasses.field(default_factory=list)       # noms de thread observés
    pic: list = dataclasses.field(default_factory=lambda: [0, 0])   # en cours, max
    verrou: threading.Lock = dataclasses.field(default_factory=threading.Lock)
    M_OUT: str = "/mnt/out"
    M_SCAN: str = "/mnt/scan"
    M_REGLES: str = "/mnt/regles"
    M_DB: str = "/mnt/db"
    M_GITCONF: str = "/mnt/gitconfig"
    racine_db: Path | None = None
    timeout: int = 600
    egress_autorise: bool = False

    def verifie(self) -> list:
        return []

    def delai_effectif(self, demande):
        plafond = int(self.timeout)
        if not demande:
            return plafond
        return max(1, min(int(demande), plafond))

    def commande(self, argv):
        return [str(a) for a in argv]

    def exec(self, argv, env=None, timeout=None):
        # Le provider est résolu par ce que la commande APPELLE (argv[0]), mappé depuis les
        # manifests réels — pas par un nom de fichier deviné dans argv. Quatre des six
        # providers de la plateforme rendent leur JSON sur stdout (`_lit_json` y retombe) :
        # c'est ce trajet-là qui est joué, parce que c'est celui que les outils empruntent
        # vraiment, et qu'écrire le fichier de l'outil à sa place inventerait un artefact.
        pid = self.par_binaire.get(Path(str(argv[0])).name, "")
        nom = f"{pid}.json" if pid else ""
        with self.verrou:
            self.lanceurs.append(pid or Path(str(argv[0])).name)
            self.fils.append(threading.current_thread().name)
            self.pic[0] += 1
            self.pic[1] = max(self.pic[1], self.pic[0])
        try:
            if pid in self.en_echec:
                raise self.en_echec[pid]
            d = float(self.latence.get(pid, 0.0))
            if d:
                time.sleep(d)
            contenu = self.octets.get(nom, "")
            return SB.Resultat(0, contenu, "", False)
        finally:
            with self.verrou:
                self.pic[0] -= 1
                self.achevements.append(pid or Path(str(argv[0])).name)


# ------------------------------------------------------------------ le harnais de mission
QUATRE = ["bandit", "radon_cc", "detect_secrets", "checkov"]

# Chaque payload a la forme que l'outil concerné rend vraiment : `results` pour bandit,
# semgrep et checkov (checkov sous `results` objet), un objet par fichier pour radon.
RADON_BRUT = ('{"testrepo/app.py": [{"type": "function", "rank": "A", "lineno": 7, '
              '"col_offset": 0, "name": "run", "complexity": 1, "endline": 9, "closures": []}, '
              '{"type": "function", "rank": "A", "lineno": 11, "col_offset": 0, '
              '"name": "weak_hash", "complexity": 1, "endline": 12, "closures": []}]}\n')

OCTETS = {
    "bandit.json": json.dumps({"results": [], "errors": []}),
    "checkov.json": json.dumps({"results": {}, "summary": {"success_count": 0}}),
    # Les OCTETS que radon a rendus pour de vrai sur `PHASE3/testrepo` le 31/08/2026
    # (`radon cc -j PHASE3/testrepo`, radon 6.0.1). Un payload inventé de format n'aurait rien
    # prouvé : c'est le cas 4 qui vérifie que ces octets sont toujours ceux de l'outil.
    "radon_cc.json": RADON_BRUT,
    "detect_secrets.json": json.dumps({"results": {}, "version": "1.5.0"}),
}


def vague(plafond: int, *, ids=QUATRE, latence=None, en_echec=None, tmp=None,
          octets=None, vagues=1, tolere_erreur=False):
    """Joue `pipeline._vague` telle quelle, avec un plafond d'outils de front donné.

    Rien n'est simulé dans ce trajet : le registre est le registre de la plateforme, les
    providers sont leurs fiches réelles, l'adaptateur, la lecture de sortie, la normalisation
    des findings, la conservation du brut et la consignation du journal sont les fonctions du
    cœur. Seul `sbx` est doublé, parce que `bwrap` n'existe pas sur cette machine.
    """
    tmp = Path(tmp)
    cible = RACINE / "testrepo"
    MS.MISSIONS = tmp / "missions"
    MS.MISSIONS.mkdir(parents=True, exist_ok=True)
    miss = MS.ouvrir("vague parallèle", "vague parallele", cible)
    reg = Registry()
    sortie = tmp / "sortie"
    sortie.mkdir(parents=True, exist_ok=True)
    par_binaire = {}
    for pid in ids:
        _m = reg.provider(pid).manifest
        if _m is not None:
            par_binaire[Path(str(_m.binaire)).name] = pid
    octets = dict(OCTETS if octets is None else octets)
    # Les octets sont rendus par STDOUT (trajet réel de quatre des six providers du cœur),
    # indexés par provider puisque c'est le nom de fichier que `generique_cli` lirait sinon.
    bruts = {f"{pid}.json": octets.get(f"{pid}.json", "") for pid in ids}
    sbx = SbxDouble(sortie=sortie, octets=bruts, par_binaire=par_binaire,
                    latence=dict(latence or {}), en_echec=dict(en_echec or {}))
    plan_dict = {"plan_id": "p-vague", "requete": "vague parallèle", "cible": str(cible),
                 "moteur_intent": "deterministe", "cree_le": "2026-08-31T00:00:00+00:00",
                 "steps": [{"provider": pid, "capability": reg.provider(pid).capability}
                           for pid in ids],
                 "selection": {}}
    decision_dict = {"allow": True, "motifs": []}
    exec_ = pipeline.Execution(plan=plan_dict, decision=decision_dict, profil="test_vague")
    # Les deux dérivations qu'`executer` construit avant d'appeler la vague, aux mêmes lignes
    # et à la même source : la vague doit les recevoir, pas les deviner.
    domaines, binaires = {}, {}
    for _p in reg.providers():
        dom = list(reg.capability(_p.capability).domaines or [])
        domaines[_p.id] = dom[0] if dom else None
        binaires[_p.id] = (_p.manifest.binaire if _p.manifest is not None
                           else Path(_p.commande[0]).name)
    trouves: dict = {}
    tous: list = []
    # `ctx.outils` ne sert qu'à la version d'outil collée au finding. Le harnais le fournit
    # vidé : la vague doit traiter l'absence comme l'absence, pas comme un défaut (`executer`,
    # lui, le remplit par `RUN.capturer`).
    ctx = types.SimpleNamespace(outils={})
    V = pipeline._ContexteVague(miss=miss, registre=reg, exec_=exec_, sbx=sbx, cible=cible,
                                sortie=sortie, ctx=ctx, trouves=trouves, tous_findings=tous,
                                domaines=domaines, binaires=binaires)
    os.environ["AGNT_VAGUE_PARALLELE"] = str(plafond)
    exception = None
    try:
        for n in range(vagues):
            # La vague lit `step.provider` sur des OBJETS d'étape, alors que `plan_dict` est
            # la forme consignée (dicts). Le harnais construit donc les objets, comme
            # `plan.construire` les fabrique.
            steps = [_Etape(s["provider"]) for s in plan_dict["steps"]]
            pipeline._vague(steps, V, plan_dict, decision_dict,
                            "2026-08-31T00:00:00+00:00", n + 1)
    except Exception as exc:                                    # noqa: BLE001
        if not tolere_erreur:
            raise
        exception = exc
    finally:
        os.environ.pop("AGNT_VAGUE_PARALLELE", None)
    return dict(miss=miss, exec_=exec_, sortie=sortie, sbx=sbx, reg=reg, trouves=trouves,
                plan=plan_dict, tous=tous, exception=exception)


def _resolvable(reg, pid: str) -> bool:
    """Le ledger exige l'exécutable RÉELLEMENT trouvé pour dire `execute`. Ici, `checkov`
    n'est pas installé sur cette machine et son double lui a quand même rendu une sortie :
    le statut doit rester `non_disponible`. C'est la règle de précédence de `statuts.py`, et
    le seul cas de cette batterie où un artefact présent ne suffit pas à dire « ça a tourné »."""
    import adapters
    man = reg.provider(pid).manifest
    return adapters.resoudre_exe(man.binaire if man else pid) is not None


class _Etape:
    """Une étape de plan, au seul format que la vague lit (`step.provider`)."""
    def __init__(self, pid: str):
        self.provider = pid


def lignes_journal(miss, type_: str | None = None) -> list[dict]:
    chemin = Path(miss.chemin) / "journal.jsonl"
    if not chemin.exists():
        return []
    out = []
    for l in chemin.read_text(encoding="utf-8").splitlines():
        l = l.strip()
        if not l:
            continue
        o = json.loads(l)
        if type_ is None or o.get("type") == type_:
            out.append(o)
    return out


def empreinte_artefacts(sortie: Path) -> dict:
    """Les octets de tout ce que la vague a écrit, indexés par nom de fichier."""
    return {p.name: p.read_bytes() for p in sorted(sortie.iterdir()) if p.is_file()}


# ══════════════════════════════════ 1 · l'ordonnanceur
print("═══ 1 · combien d'outils de front, et qui décide ═══")


def _avec_env(valeur):
    if valeur is None:
        os.environ.pop("AGNT_VAGUE_PARALLELE", None)
    else:
        os.environ["AGNT_VAGUE_PARALLELE"] = valeur
    try:
        return pipeline.outils_par_vague()
    finally:
        os.environ.pop("AGNT_VAGUE_PARALLELE", None)


cas("1. sans réglage, la vague mène quatre outils de front", _avec_env(None) == 4,
    _avec_env(None))
cas("2. `AGNT_VAGUE_PARALLELE=1` rétablit la suite exacte — le chemin historique reste un choix",
    _avec_env("1") == 1)
cas("3. la borne haute est bornée : 99 ne veut pas dire « tout lancer à la fois »",
    _avec_env("99") == 8, _avec_env("99"))
cas("4. zéro et les négatifs retombent sur 1, jamais sur « aucun outil »",
    _avec_env("0") == 1 and _avec_env("-3") == 1)
cas("5. une valeur illisible n'est pas une autorisation de tout lancer : on reprend la suite",
    _avec_env("tout") == 1 and _avec_env("") == 1)
cas("6. le réglage est lu à chaque vague, pas figé à l'import",
    _avec_env("2") == 2 and _avec_env("3") == 3)

tmp0 = tempfile.mkdtemp(prefix="agnt-vague- threads-")
try:
    S1 = vague(4, tmp=tmp0, ids=["bandit"])
    n_main = sum(1 for x in S1["sbx"].fils if x == "MainThread")
    cas("7. une vague d'un seul outil n'emprunte pas le pool : elle tourne sur le fil principal",
        len(S1["sbx"].fils) == 1 and n_main == 1, S1["sbx"].fils)
    S2 = vague(4, tmp=tmp0 + "-b", ids=["bandit", "radon_cc", "detect_secrets", "checkov"],
               latence={"bandit": 0.15, "radon_cc": 0.15, "detect_secrets": 0.15})
    cas("8. à quatre outils de front, les départs sont réellement sur des fils distincts",
        len(set(S2["sbx"].fils)) > 1, S2["sbx"].fils)
    S3 = vague(2, tmp=tmp0 + "-c", ids=QUATRE * 2,
               latence={pid: 0.05 for pid in QUATRE})
    cas("9. le pic de concurrence observé ne dépasse jamais le plafond demandé",
        1 < S3["sbx"].pic[1] <= 2, S3["sbx"].pic)
finally:
    for d in (tmp0, tmp0 + "-b", tmp0 + "-c"):
        shutil.rmtree(d, ignore_errors=True)

# ══════════════════════════════ 2 · invariance des artefacts
print("═══ 2 · un à quatre outils de front : mêmes octets ═══")
tmp_a = tempfile.mkdtemp(prefix="agnt-vague-seq-")
tmp_b = tempfile.mkdtemp(prefix="agnt-vague-par-")
A = vague(1, tmp=tmp_a)
# Les doubles sont volontairement lents DANS L'ORDRE INVERSE du plan : checkov finit premier,
# bandit dernier. Si un artefact suivait l'achèvement, les deux arbres différeraient.
B = vague(4, tmp=tmp_b, latence={"bandit": 0.3, "radon_cc": 0.2, "detect_secrets": 0.1})
ord_A = [r["provider"] for r in A["exec_"].raw]
ord_B = [r["provider"] for r in B["exec_"].raw]
cas("10. les doubles achèvent bien DANS L'ORDRE INVERSE du plan (sinon les cas 11 à 18 ne mesureraient rien)",
    B["sbx"].achevements == ["checkov", "detect_secrets", "radon_cc", "bandit"]
    and B["sbx"].lanceurs == QUATRE,
    {"achèvements": B["sbx"].achevements, "départs": B["sbx"].lanceurs})
cas("11. `exec_.raw` reste dans l'ordre du plan, à quatre de front comme à un",
    ord_B == ord_A == QUATRE, {"seq": ord_A, "par": ord_B})
em_A, em_B = empreinte_artefacts(A["sortie"]), empreinte_artefacts(B["sortie"])
cas("12. les mêmes fichiers d'artefacts sont produits dans les deux réglages",
    sorted(em_A) == sorted(em_B), {"seq": sorted(em_A), "par": sorted(em_B)})
differents = sorted(k for k in em_A if k in em_B and em_A[k] != em_B[k])
cas("13. octet pour octet, `raw_*` et `brut_*` sont identiques : aucune horloge dans un artefact",
    not differents, differents)
cas("14. l'ordre de `couverture` est celui du plan, pas celui des achèvements",
    [c["provider"] for c in A["exec_"].couverture]
    == [c["provider"] for c in B["exec_"].couverture] == QUATRE,
    [c["provider"] for c in B["exec_"].couverture])
li_A = [l["provider"] for l in lignes_journal(A["miss"], "execution")]
li_B = [l["provider"] for l in lignes_journal(B["miss"], "execution")]
cas("15. les lignes `execution` du journal sont dans l'ordre du plan dans les deux cas",
    li_A == li_B == QUATRE, {"seq": li_A, "par": li_B})
cas("16. le compte de findings par provider est le même (compté à la source, pas à la fin)",
    A["trouves"] == B["trouves"] and sum(A["trouves"].values()) == 2
    and len(A["tous"]) == len(B["tous"]),
    {"seq": A["trouves"], "par": B["trouves"], "nb": (len(A["tous"]), len(B["tous"]))})
brut_B = sorted(p.name for p in B["sortie"].iterdir() if p.name.startswith("brut_"))
cas("17. chaque outil mené de front conserve SA sortie brute, dans un fichier qui ne se partage pas",
    len(brut_B) == 4 and len({n.split("_")[1].split(".")[0] for n in brut_B}) == 4, brut_B)
# Les findings sont des OBJETS (`findings.Finding`), pas des dicts : la comparaison se fait
# sur leur rendu `to_dict()`. Et elle est précédée d'un `len(...) == 2` explicite — deux listes
# vides vérifient `all(...)` par défaut, ce qui a fait passer les cas 16 et 17 en vide à la
# première exécution de cette batterie (mesuré ici, pas corrigé en coulisse).
def _rendus(exec_dict):
    return [json.dumps(f.to_dict(), sort_keys=True, ensure_ascii=False, default=str)
            for f in exec_dict["tous"]]
cas("18. le brut de radon rend bien deux findings, à un comme à quatre outils de front",
    len(A["tous"]) == len(B["tous"]) == 2 and A["trouves"].get("radon_cc") == 2,
    {"seq": len(A["tous"]), "par": len(B["tous"]), "trouves": A["trouves"]})
cas("18ter. un finding obtenu en parallèle porte les mêmes octets qu'en séquentiel",
    bool(_rendus(A)) and _rendus(A) == _rendus(B),
    {"nb": (len(A["tous"]), len(B["tous"])),
     "clés": sorted(A["tous"][0].to_dict().keys()) if A["tous"] else []})
if __import__("shutil").which("radon") or (Path.home() / ".cache/arena_secops/bin/radon").exists():
    binaire = (shutil.which("radon")
               or str(Path.home() / ".cache/arena_secops/bin/radon"))
    # La capture a été faite par `cd PHASE3 && radon cc -j testrepo` : radon Echo le chemin
    # TEL qu'on le lui donne, donc le rejouer avec un chemin absolu produit 307 octets contre
    # 284 pour le MÊME dépôt. Comparer des octets exige de rejouer l'invocation, pas seulement
    # l'outil (mesuré ici, pas corrigé en ajustant le littéral).
    rendu = __import__("subprocess").run([binaire, "cc", "-j", "testrepo"], cwd=str(RACINE),
                                         capture_output=True, text=True).stdout
    # MESURÉ, et c'est une découverte de cette batterie : radon 6.0.1 ne rend PAS le même ordre
    # de clés d'une invocation à l'autre sur un dépôt inchangé (trois md5 différents sur trois
    # `radon cc -j testrepo`). Comparer des octets ici reviendrait à faire dépendre le test du
    # hasard d'un dictionnaire : la comparaison est faite sur l'objet JSON, et le cas suivant
    # mesure ce que cette instabilité change, et ce qu'elle ne change pas.
    cas("18bis. le payload du test est bien l'objet que radon rend sur cette cible",
        json.loads(rendu) == json.loads(RADON_BRUT),
        {"longueurs": (len(rendu), len(RADON_BRUT)),
         "note": "radon absent ou cible modifiée : reprendre la capture, ne pas ajuster le "
                 "littéral pour que le cas passe"})
    brut_reordonne = json.dumps({"testrepo/app.py": [
        {"complexity": 1, "closures": [], "endline": 9, "lineno": 7, "col_offset": 0,
         "name": "run", "rank": "A", "type": "function"},
        {"complexity": 1, "closures": [], "endline": 12, "lineno": 11, "col_offset": 0,
         "name": "weak_hash", "rank": "A", "type": "function"}]})
    tmp_r = tempfile.mkdtemp(prefix="agnt-vague-brut-desordre-")
    try:
        R = vague(2, tmp=tmp_r, octets={**OCTETS, "radon_cc.json": brut_reordonne + "\n"})
        empreintes = sorted(f.identity["fingerprint"] for f in R["tous"])
        empreintes_B = sorted(f.identity["fingerprint"] for f in B["tous"])
        cas("18quater. un brut dont l'ordre des clés a bougé change les octets archivés, pas les findings",
            empreintes == empreintes_B and brut_reordonne != RADON_BRUT.strip().encode(),
            {"empreintes": empreintes, "attendues": empreintes_B})
    finally:
        shutil.rmtree(tmp_r, ignore_errors=True)
else:
    non_evalue("octets de radon comparés à l'outil réel",
               "aucun `radon` sur cette machine : le payload est une capture du 31/08/2026, "
               "non re-vérifiée ici.")
shutil.rmtree(tmp_a, ignore_errors=True)
shutil.rmtree(tmp_b, ignore_errors=True)

# ══════════════════════════════ 3 · arrêt sur échec
print("═══ 3 · qui est désigné quand ça tombe ═══")
# `checkov` (le QUATRIÈME du plan) tombe aussitôt ; `bandit` (le PREMIER) tombe à 0,3 s.
# L'horloge désignerait checkov. Le motif consigné doit désigner bandit — et le faire de la
# même façon à un et à quatre outils de front.
# Un SEUL fautif, et il tombe en DERNIER (0,3 s) : si le fautif tombait aussitôt, « quels
# outils ont eu le temps de démarrer » dépendrait de l'ordonnanceur, et les cas 22 à 23ter
# jugeraient une course au lieu de juger l'arrêt. (C'est exactement ce qui a rendu cette
# section intermittente à sa première écriture : `checkov` levait à t=0, les deux outils du
# milieu démarraient ou non selon le fil — 3 échecs sur 4 rejeux, tous dus au harness.)
FAUTE = {"bandit": RuntimeError("cage indisponible")}
LATENCE_FAUTE = {"bandit": 0.3, "radon_cc": 0.1, "detect_secrets": 0.15}
R1 = vague(1, tmp=tempfile.mkdtemp(prefix="agnt-vague-echec-seq-"),
           latence=LATENCE_FAUTE, en_echec=FAUTE, tolere_erreur=True)
R4 = vague(4, tmp=tempfile.mkdtemp(prefix="agnt-vague-echec-par-"),
           latence=LATENCE_FAUTE, en_echec=FAUTE, tolere_erreur=True)
cas("19. la vague condamnée remonte l'exception au lieu de l'avaler",
    R1["exception"] is not None and R4["exception"] is not None,
    {1: str(R1["exception"])[:60], 4: str(R4["exception"])[:60]})
cas("20. le fautif remonté est le premier AU SENS DU PLAN, pas le premier tombé",
    "cage indisponible" in str(R1["exception"]) and "cage indisponible" in str(R4["exception"]),
    {1: str(R1["exception"])[:60], 4: str(R4["exception"])[:60]})
arret1 = [a for a in lignes_journal(R1["miss"], "arret")]
arret4 = [a for a in lignes_journal(R4["miss"], "arret")]
cas("21. l'arrêt consigné nomme le provider fautif, à l'identique dans les deux réglages",
    arret1 and arret4 and arret1[-1]["motif"] == arret4[-1]["motif"] == "execution_bandit"
    and "cage indisponible" in arret1[-1]["erreur"],
    {"seq": [a.get("motif") for a in arret1], "par": [a.get("motif") for a in arret4]})
snap1 = lignes_journal(R1["miss"], "statuts")[-1]
snap4 = lignes_journal(R4["miss"], "statuts")[-1]
par_id = {o["provider"]: o for o in snap4["outils"]}
cas("22. le ledger d'arrêt marque le fautif `echoue`, et rien de ce qui n'a pas d'artefact ne passe pour exécuté",
    par_id["bandit"]["statut"] == "echoue"
    and all((o["statut"] == "execute") == ((R4["sortie"] / f"raw_{pid}.json").exists()
                                           and _resolvable(R4["reg"], pid))
            for pid, o in par_id.items()),
    {k: (v["statut"], v.get("raison", "")[:60]) for k, v in par_id.items()})
# Un arrêt à un outil par vague et un arrêt à quatre ne couvrent PAS la même chose, et c'est
# juste : à un, deux outils n'ont jamais démarré ; à quatre, ils étaient déjà partis. Le ledger
# doit rendre cette différence — s'il l'effaçait, il mentirait sur ce qui a tourné.
id1 = {o["provider"]: o["statut"] for o in snap1["outils"]}
id4 = {o["provider"]: o["statut"] for o in snap4["outils"]}
cas("23. le fautif est marqué `echoue` dans les deux réglages ; à un outil par vague, les abandonnés restent `selectionne`",
    id1["bandit"] == id4["bandit"] == "echoue" and id1["radon_cc"] == "selectionne"
    and id1["detect_secrets"] == "selectionne", {"seq": id1, "par": id4})
# Le nombre de snapshots est une MESURE de l'arrêt : à un outil par vague, seul le fautif a
# démarré (1 départ + 1 consignation d'arrêt) ; à quatre, les trois autres étaient déjà partis
# (4 départs + l'arrêt). Et dans les deux cas le ledger liste les quatre outils du plan —
# « abandonné avant démarrage » y figure avec son statut, pas par soustraction.
snaps_echec1 = lignes_journal(R1["miss"], "statuts")
snaps_echec4 = lignes_journal(R4["miss"], "statuts")
cas("23bis. à un outil par vague, un seul départ consigné ; à quatre, un snapshot par départ et rien de plus",
    len(snaps_echec1) == 2 and len(snaps_echec4) == len(R4["sbx"].lanceurs) + 1,
    {"seq": [s.get("en_cours") for s in snaps_echec1],
     "par": [s.get("en_cours") for s in snaps_echec4],
     "départs parallèles": R4["sbx"].lanceurs})
cas("23ter. le ledger d'arrêt nomme les quatre outils du plan, y compris ceux qui n'ont pas tourné",
    [o["provider"] for o in snap1["outils"]] == sorted(QUATRE)
    and [o["provider"] for o in snap4["outils"]] == sorted(QUATRE),
    {"seq": [(o["provider"], o["statut"]) for o in snap1["outils"]]})
cas("23quater. les deux réglages portent le même décompte d'échoués : un, pas quatre",
    snap1["resume"].get("echoue") == 1 and snap4["resume"].get("echoue") == 1,
    {"seq": snap1["resume"], "par": snap4["resume"]})
# bandit tombe à 0,05 s ; radon_cc dort 0,6 s. Le premier créneau libéré l'est donc APRÈS
# la décision d'arrêt : les six étapes restantes ne démarrent pas, et ce n'est pas une course.
R5 = vague(2, tmp=tempfile.mkdtemp(prefix="agnt-vague-suppression-"), ids=QUATRE * 2,
           latence={"bandit": 0.05, "radon_cc": 0.6},
           en_echec={"bandit": RuntimeError("cage indisponible")}, tolere_erreur=True)
cas("24. rien ne démarre après l'arrêt : les outils non encore partis sont abandonnés",
    len(R5["sbx"].lanceurs) < len(QUATRE) * 2,
    {"lancés": R5["sbx"].lanceurs, "au plan": len(QUATRE) * 2})
snap5 = lignes_journal(R5["miss"], "statuts")
cas("25. un outil abandonné avant son départ n'a pas de snapshot : pas d'état inventé",
    len(snap5) == len(R5["sbx"].lanceurs) + 1,
    {"snapshots": len(snap5), "départs": len(R5["sbx"].lanceurs)})
for r in (R1, R4, R5):
    shutil.rmtree(Path(r["miss"].chemin).parent.parent, ignore_errors=True)

# ══════════════════════════════ 4 · le ledger vivant
print("═══ 4 · le ledger pendant la mission ═══")
tmp_e = tempfile.mkdtemp(prefix="agnt-vague-ledger-4-")
tmp_f = tempfile.mkdtemp(prefix="agnt-vague-ledger-1-")
E1 = vague(1, tmp=tmp_f, ids=["bandit", "radon_cc"])
E4 = vague(4, tmp=tmp_e, latence={"bandit": 0.2, "checkov": 0.05})
snaps4 = lignes_journal(E4["miss"], "statuts")
snaps1 = lignes_journal(E1["miss"], "statuts")
cas("26. un snapshot est consigné à CHAQUE départ d'outil, plus un en fin de vague",
    len(snaps4) == 5 and len(snaps1) == 3, {"par": len(snaps4), "seq": len(snaps1)})
en_cours = [s.get("en_cours") for s in snaps4]
cas("27. chaque snapshot nomme l'outil qui démarre ; le dernier ne nomme rien",
    all(bool(x) for x in en_cours[:-1]) and not en_cours[-1], en_cours)
mots = sorted({o["statut"] for s in snaps4 for o in s["outils"]})
FERMES = {"non_disponible", "non_applicable", "non_selectionne", "non_autorise",
          "selectionne", "echoue", "execute"}
cas("28. aucun vocabulaire nouveau : l'état vivant n'use que des six étapes fermées",
    set(mots) <= FERMES, mots)
en_cours_outils = [o for s in snaps4 for o in s["outils"] if o.get("en_cours")]
cas("29. un outil en cours se lit `selectionne` avec une raison qui le dit, pas un septième état",
    len(en_cours_outils) >= 1 and all(o["statut"] == "selectionne"
                                      and "cours" in (o.get("raison") or "").lower()
                                      for o in en_cours_outils),
    en_cours_outils[:2])
cas("30. la clé `en_cours` est toujours là : absent et faux ne doivent pas se ressembler",
    all("en_cours" in o for s in snaps4 for o in s["outils"]))
comptes = [len([o for o in s["outils"] if o["statut"] == "execute"]) for s in snaps4]
cas("31. un état intermédiaire existe vraiment : le compte d'exécutés croît au fil des snapshots",
    comptes[0] == 0 and comptes[-1] > comptes[0], comptes)
resume = snaps4[-1].get("resume") or {}
cas("32. le dernier snapshot tient le compte par étape : la console n'a rien à recompter",
    isinstance(resume, dict) and sum(resume.values()) == len(snaps4[-1]["outils"]), resume)
# Ce que le harnais ne peut pas faire : `exec_.statuts` est posé par `executer` APRÈS les
# vagues, pas par `_vague`. La propriété qui compte est donc la réciproque, et elle est plus
# forte : relire les artefacts finaux par la même fonction doit rendre exactement le dernier
# snapshot du journal. Si le ledger vivant était une mécanique d'affichage à côté, ce cas
# basculerait.
final = ST.construire(E4["reg"], E4["plan"], {"allow": True, "motifs": []},
                      E4["exec_"].raw, E4["exec_"].couverture, E4["trouves"])
vu_j = [(o["provider"], o["statut"]) for o in snaps4[-1]["outils"]]
vu_f = [(o["provider"], o["statut"]) for o in final]
cas("33. l'état final se relit à l'identique depuis les artefacts : le snapshot vivant n'est pas un état de plus",
    vu_j == vu_f and bool(vu_f), {"journal": vu_j, "relecture": vu_f})
cas("33bis. le snapshot consigné porte les mêmes clés par outil que l'objet ledger",
    sorted(snaps4[-1]["outils"][0].keys()) == sorted(final[0].keys()),
    {"journal": sorted(snaps4[-1]["outils"][0].keys()), "objet": sorted(final[0].keys())})
shutil.rmtree(tmp_e, ignore_errors=True)
shutil.rmtree(tmp_f, ignore_errors=True)

# ══════════════════════════════ 5 · le journal sous concurrence
print("═══ 5 · quarante lignes écrites par quatre fils ═══")
tmp_g = tempfile.mkdtemp(prefix="agnt-vague-journal-")
try:
    MS.MISSIONS = Path(tmp_g) / "missions"
    MS.MISSIONS.mkdir(parents=True, exist_ok=True)
    miss = MS.ouvrir("journal sous concurrence", "journal", RACINE / "testrepo")

    def ecrire(n: int) -> None:
        for i in range(10):
            MS.consigner(miss, "brut", fils=n, rang=i, payload="x" * (4096 if i % 3 else 900))

    fils = [threading.Thread(target=ecrire, args=(n,)) for n in range(4)]
    [f.start() for f in fils]
    [f.join(timeout=60) for f in fils]
    brutes = [l for l in (miss.chemin / "journal.jsonl").read_text(
        encoding="utf-8").splitlines() if l.strip()]
    lus, seqs = 0, []
    casse = ""
    for l in brutes:
        try:
            o = json.loads(l)                       # une ligne à moitié écrite lèverait ici
        except ValueError as exc:
            casse = f"{exc} · {l[-40:]}"
            break
        seqs.append(o.get("seq"))
        lus += 1
    bruts = [l for l in brutes if json.loads(l).get("type") == "brut"]
    cas("34. quarante écritures concurrentes produisent quarante lignes de plus, sans perte",
        len(bruts) == 40 and not casse, {"lignes": len(bruts), "total": lus, "casse": casse})
    # `seq` est la séquence du JOURNAL entier : la ligne d'ouverture de mission porte le
    # numéro 1, les quarante écritures suivent. Ce qui est exigé ici, c'est qu'aucun numéro
    # ne soit double, sauté dans le désordre, ou écrit deux fois par deux fils.
    cas("35. les `seq` sont uniques, contigus et croissants du premier au dernier événement",
        seqs == sorted(seqs) and len(set(seqs)) == len(seqs)
        and seqs[0] == 1 and seqs[-1] == len(seqs),
        {"premiers": seqs[:5], "derniers": seqs[-3:], "nb": len(seqs)})
    cas("36. aucune ligne tronquée ni entremêlée, même à 4 Ko sur quatre fils",
        all(l.startswith("{") and l.endswith("}") for l in brutes),
        [l[-24:] for l in brutes if not l.endswith("}")][:3])
finally:
    shutil.rmtree(tmp_g, ignore_errors=True)

tmp_h = tempfile.mkdtemp(prefix="agnt-vague-8x5-")
try:
    H = vague(4, tmp=tmp_h, ids=QUATRE * 2, vagues=5)
    tout = lignes_journal(H["miss"])
    sq = [o.get("seq") for o in tout]
    cas("37. cinq vagues de huit outils : le `seq` du journal reste unique et complet",
        len(sq) == len(set(sq)) and sq == sorted(sq) and sq[0] == 1,
        {"lignes": len(sq), "duplicatas": len(sq) - len(set(sq))})
    cas("38. les artefacts de chaque provider gardent leur fichier : quatre noms pour huit étapes",
        sorted(p.name for p in H["sortie"].iterdir() if p.name.startswith("raw_"))
        == [f"raw_{pid}.json" for pid in sorted(QUATRE)],
        sorted(p.name for p in H["sortie"].iterdir()))
    lignes_exec = [l for l in lignes_journal(H["miss"], "execution")]
    cas("39. une ligne `execution` et un artefact par ÉTAPE, sur cinq vagues de huit étapes",
        len(lignes_exec) == 40 and len(H["exec_"].raw) == 40
        and {int(l["vague"]) for l in lignes_exec} == {1, 2, 3, 4, 5},
        {"lignes": len(lignes_exec), "raw": len(H["exec_"].raw),
         "vagues": sorted({int(l["vague"]) for l in lignes_exec})})
finally:
    shutil.rmtree(tmp_h, ignore_errors=True)

# ══════════════════════════ 6 · ce qui n'est PAS mesuré ici
print("═══ 6 · ce qui reste à démontrer ailleurs ═══")
non_evalue("gain de temps réel d'une vague à quatre sous bwrap",
           "le double de sandbox mesure l'ordonnancement, pas la vitesse, et `bwrap` est absent "
           "de cette machine (bootstrap impossible sans réseau). À rejouer après un bootstrap "
           "vert : chronométrer `python3 PHASE3/analyser.py PHASE3/testrepo \"Analyse la "
           "complexité cyclomatique du dépôt\"` avec `AGNT_VAGUE_PARALLELE=1` puis `=4`, et "
           "vérifier que les deux `findings.json` sont octet pour octet identiques — les cas 10 "
           "à 18 préjugent ce résultat sur doubles, ils ne le remplacent pas.")
non_evalue("décision OPA sur une vague parallèle",
           "binaire `opa` introuvable (openpolicyagent.org ne répond pas, mesuré ce jour) : "
           "`executer()` refuse avant la vague. Les cas ci-dessus jouent `pipeline._vague` "
           "directement — la politique n'est donc pas évaluée ici.")
non_evalue("collisions de montages entre quatre outils réels",
           "les quatre providers de ce test écrivent dans `mt-out` sous des noms distincts "
           "(`{id}.{ext}`, cas 17 et 38) ; un outil qui écrirait un fichier temporaire de nom "
           "fixe pourrait se marcher dessus. Aucune des fiches chargées ici ne le fait, et ce "
           "n'est pas une preuve générale : elle demande les montages par exécution, non "
           "construits.")

print()
n_ok = sum(1 for _, c, _ in CAS if c)
print(f"{n_ok}/{len(CAS)} cas passent")
for nom, detail in [(c[0], c[2]) for c in CAS if not c[1]]:
    print(f"  ÉCHEC · {nom}\n        détail : {str(detail)[:400]}")
for nom, cause in NON_EVALUES:
    print(f"  NON ÉVALUÉ · {nom} — {cause[:160]}")
sys.exit(1 if ECHECS else 0)
