#!/usr/bin/env python3
"""
Grille qualité de la plateforme — LOT 3 (egress rendu réel, vague parallèle, ledger vivant).

Seize points, plus deux falsifications. Cette batterie ne rejoue pas les suites déjà en place
(`test_conditions_outils`, `test_statuts_outils`, `test_isolateur`, `test_vague_parallele`) :
elle verrouille les COUTURES du lot — les endroits où un faux pas ne se voit pas dans un seul
module mais rend un artefact mensonger. Trois familles de faits y passent :

  · la garde d'export : fermée par défaut, accordée par la mission, jugée sur la COMMANDE
    construite (une seule autorité), et tracée jusqu'au `run_id` ;
  · le tri-état « non demandé / accordé / refusé » : les trois doivent rester trois faits
    distincts dans le CLI, l'archive, l'API et l'écran ;
  · la cohérence de ce qui est écrit avec ce qui est affirmé — y compris dans la documentation.

Ce qui n'est PAS évalué ici, et c'est dit au point 17 : le `bwrap` réel (absent de cette
machine) et la décision d'OPA (binaire injouable, openpolicyagent.org ne répond pas). Les cas
1 à 6 mesurent donc la commande et l'environnement remis à un processus, joués contre un
**bouchon de bwrap** : le bouchon prouve ce que le cœur a demandé, pas ce que noyau applique.

Usage : python3 PHASE3/test_qualite_plateforme.py
"""
from __future__ import annotations

import json
import sys
import types
import tempfile
from pathlib import Path

RACINE = Path(__file__).parent
sys.path.insert(0, str(RACINE / "slice"))
sys.path.insert(0, str(RACINE / "interface"))

import conditions as COND                              # noqa: E402
import mission as MS                                   # noqa: E402
import pipeline                                        # noqa: E402
import profils as PF                                   # noqa: E402
import run as RUN                                      # noqa: E402
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


# ------------------------------------------------------------------ un bouchon de bwrap
def cage(tmp: Path, *, egress: bool = False) -> tuple[SB.Sandbox, Path, Path]:
    """Une Sandbox dont le `bwrap` est un script qui enregistre ce qu'on lui a passé.

    Le bouchon écrit argv et env dans deux fichiers. C'est la seule façon de mesurer
    l'environnement RÉELLEMENT remis à l'outil sans bwrap : `Sandbox.exec` compose ce couple
    avant le Popen, et c'est exactement là que le LOT 3 a changé quelque chose.
    """
    tmp.mkdir(parents=True, exist_ok=True)
    argv_f, env_f = tmp / "argv.txt", tmp / "env.txt"
    stub = tmp / "faux-bwrap"
    stub.write_text(
        "#!/bin/sh\n"
        f'printf "%s\\n" "$@" > {argv_f}\n'
        f"env > {env_f}\n"
        'if [ "${1:-}" = "--version" ]; then echo "bouchon-de-bwrap 0"; fi\n'
        "exit 0\n",
        encoding="utf-8")
    stub.chmod(0o755)
    scan, regles, sortie = tmp / "scan", tmp / "regles", tmp / "sortie"
    db, gitconf = tmp / "db.bin", tmp / "gitconfig"
    for d in (scan, regles, sortie):
        d.mkdir(parents=True, exist_ok=True)
    db.write_bytes(b"base")
    gitconf.write_text("[safe]\n\tdirectory = *\n", encoding="utf-8")
    montages = {}
    for cle in ("M_SCAN", "M_REGLES", "M_DB", "M_OUT", "M_GITCONF"):
        # Les points de montage vus de l'ENFANT sont libres ici : le bouchon ne monte rien,
        # et `verifie()` exige seulement qu'ils existent sur l'hôte (leçon n°1 du module).
        montages[cle] = str(tmp / cle.lower().replace("m_", "montage-"))
        Path(montages[cle]).mkdir(parents=True, exist_ok=True)
    sbx = SB.Sandbox(bwrap=str(stub), racine_scan=scan, racine_regles=regles, racine_db=db,
                     sortie=sortie, gitconfig=gitconf, egress_autorise=egress, **montages)
    return sbx, argv_f, env_f


tmp = Path(tempfile.mkdtemp(prefix="agnt-grille-"))
SBX, ARGV, ENV = cage(tmp)
SBX_E, ARGV_E, ENV_E = cage(tmp / "egress", egress=True)

# ═══════════════════════════ 1 · le défaut est fermé, et il est réel
print("═══ 1 · ce que la cage fait par défaut ═══")
cas("1. les deux profils livrés ferment la sortie réseau",
    all(p.reseau_autorise is False for p in PF.PROFILS.values()),
    {n: p.reseau_autorise for n, p in PF.PROFILS.items()})
cas("2. `Sandbox` sans réglage coupe le réseau : `--unshare-net` est dans la commande",
    "--unshare-net" in SB.Sandbox().commande(["true"]))
cas("3. le défaut est porté par la CLASSE, pas seulement par les deux instances livrées",
    SB.Sandbox().egress_autorise is False and SB.Sandbox().commande(["true"]).count("--unshare-net") == 1)
# Les deux lancements ci-dessous sont joués contre le bouchon : ils remplissent argv.txt et
# env.txt, c'est-à-dire la commande et l'environnement QUE LE CŒUR A REMIS à l'outil.
SBX.exec(["true"])
SBX_E.exec(["true"])
cas("4. la commande passée à bwrap coupe le réseau (mesuré sur le processus lancé, pas sur le champ)",
    "--unshare-net" in ARGV.read_text(encoding="utf-8"), ARGV.read_text(encoding="utf-8")[:120])
cas("5. et l'outil autorisé à sortir ne reçoit PAS le drapeau",
    "--unshare-net" not in ARGV_E.read_text(encoding="utf-8"),
    ARGV_E.read_text(encoding="utf-8")[:120])
env_e = ENV_E.read_text(encoding="utf-8")
env_c = ENV.read_text(encoding="utf-8")
cas("6. la double ceinture est posée avec la coupure et retirée avec l'accord : les deux ou rien",
    "HTTP_PROXY" in env_c and "HTTP_PROXY" not in env_e,
    {"coupé": [l for l in env_c.splitlines() if "PROXY" in l],
     "accordé": [l for l in env_e.splitlines() if "PROXY" in l]})
cas("7. `conditions.egress_de` suit la commande, dans les deux sens",
    COND.egress_de(SBX, ["true"]) is False and COND.egress_de(SBX_E, ["true"]) is True)

# ═══════════════════════════ 2 · l'état de la cage est une identité d'exécution
print("═══ 2 · la garde d'export change l'empreinte, donc le run_id ═══")
reg = Registry()
c_coup = RUN.capturer(SBX, RACINE.parent / "PHASE3" / "policy" / "policy.rego", reg.empreinte())
c_ouv = RUN.capturer(SBX_E, RACINE.parent / "PHASE3" / "policy" / "policy.rego", reg.empreinte())
cas("8. `limites_appliquees()` nomme l'état réseau, dans les deux configurations",
    "reseau" in c_coup.sandbox and "reseau" in c_ouv.sandbox
    and c_coup.sandbox["reseau"] != c_ouv.sandbox["reseau"],
    {"coupé": c_coup.sandbox.get("reseau"), "ouvert": c_ouv.sandbox.get("reseau")})
cas("9. deux cages différentes sont deux contextes : l'empreinte de contexte change",
    c_coup.contexte_empreinte != c_ouv.contexte_empreinte,
    {"coupé": c_coup.contexte_empreinte, "ouvert": c_ouv.contexte_empreinte})
cas("10. et donc deux `run_id` : un run mené cage ouverte ne se confond pas avec un run fermé",
    RUN.nouveau_run_id("p1", c_coup, "abc") != RUN.nouveau_run_id("p1", c_ouv, "abc"))

# ═══════════════════════════ 3 · le tri-état, jusqu'au rapport
print("═══ 3 · « non demandé », « accordé », « refusé » restent trois faits ═══")
import analyser                                          # noqa: E402
cas("11. CLI : l'absence du drapeau vaut « le profil fait foi », pas « refusé »",
    analyser._booleen({}, "egress") is None and analyser._booleen({"egress": "false"}, "egress") is False
    and analyser._booleen({"egress": "true"}, "egress") is True,
    {str(k): analyser._booleen({k: v}, "egress") for k, v in (("absent", ""), ("false", "false"),
                                                               ("true", "true"))})
try:
    opts, _ = analyser._options_depuis_argv(["cible", "question", "--egress"])
    nu_refuse = False
except ValueError:
    nu_refuse = True
cas("12. `--egress` nu est refusé : un drapeau de sécurité n'a pas de valeur par défaut muette",
    nu_refuse)
try:
    analyser._options_depuis_argv(["--egress", "peut-être"])
    valeur_refusee = False
except ValueError:
    valeur_refusee = True
cas("13. `--egress peut-être` est refusé plutôt que lu comme vrai", valeur_refusee)
e_test = pipeline.Execution(plan={}, decision={}, egress={"demande": "mission", "autorise": True,
                                                           "profil": "controlled_dev",
                                                           "delegation": True},
                            vague_parallele=4,
                            clusters={"stats": {}, "clusters": [], "non_regroupe": []})
_IT = types.SimpleNamespace(requete="grille", capabilities=["CODE_METRICS"], motifs=[])
_PLAN = types.SimpleNamespace(plan_id="p", empreinte=lambda: "empreinte-de-plan")
rap = pipeline._rapport(_IT, _PLAN, e_test)
cas("14. le rapport porte l'état de la garde et le parallélisme appliqué (clés présentes, même fermé)",
    "egress" in rap and "outils_par_vague" in rap and rap["egress"]["autorise"] is True
    and rap["outils_par_vague"] == 4, {k: rap.get(k) for k in ("egress", "outils_par_vague")})
rap_vide = pipeline._rapport(_IT, _PLAN, pipeline.Execution(plan={}, decision={},
                                                             clusters={"stats": {}, "clusters": [], "non_regroupe": []}))
cas("14bis. une exécution sans délégation rend `egress` vide et un parallélisme nul : absent ≠ faux",
    rap_vide.get("egress") == {} and rap_vide.get("outils_par_vague") == 0,
    {k: rap_vide.get(k) for k in ("egress", "outils_par_vague")})
import api as API                                      # noqa: E402
dossier = tmp / "archive"
dossier.mkdir(parents=True, exist_ok=True)
(dossier / "rapport.json").write_text(json.dumps(rap), encoding="utf-8")
(dossier / "run.json").write_text(json.dumps(
    {"execution_profile": "controlled_dev", "egress": rap["egress"], "run_id": "r-1"}),
    encoding="utf-8")
donnees = API._charger(str(dossier))
cas("15. l'interface relit les deux champs depuis l'archive, sans les réinventer",
    donnees["run"].get("egress") == rap["egress"]
    and donnees["run"].get("outils_par_vague") == 4, donnees["run"])
cas("15bis. et le nom du profil qui a décidé : la clé lue est celle que l'archive écrit",
    donnees["run"].get("profil") == "controlled_dev", donnees["run"].get("profil"))
dossier2 = tmp / "archive-vide"; dossier2.mkdir(parents=True, exist_ok=True)
(dossier2 / "rapport.json").write_text("{}", encoding="utf-8")
v = API._charger(str(dossier2))["run"]
cas("15ter. archive sans ces champs : ils restent absents, ils ne deviennent pas `false` ni 1",
    "egress" not in v or v["egress"] is None, v)
cap = API._capacites()
cas("16. `/api/capacites` dit ce que le profil autorise : la case de l'écran ne ment pas sur son effet",
    cap["profil"]["reseau_autorise"] is False and cap["profil"]["nom"] == PF.actif().nom
    and isinstance(cap["profil"]["profils_ouvrant_la_sortie"], list), cap.get("profil"))
cas("16bis. aucun profil de la plateforme n'ouvre la sortie : la liste est vide, pas absente",
    cap["profil"]["profils_ouvrant_la_sortie"] == [], cap["profil"])

# ── le ledger vivant, joué sur une VRAIE mission (refusée par OPA, journal bel et bien écrit)
# Une mission refusée laisse un journal : `_ledger` est consigné sur les sorties interrompues,
# et c'est exactement ce que lit la console. Ce bloc ne peut donc pas être fabriqué par un dict
# de test — mais il ne prouve PAS la décision de politique, qu'OPA refuse de rendre ici.
import time                                              # noqa: E402
dossier_vivant = tmp / "missions-vivantes"; dossier_vivant.mkdir(parents=True, exist_ok=True)
MS.MISSIONS = dossier_vivant
# Une demande qui DÉBOUCHE sur un plan : « grille : le ledger vivant » ne mappe aucune capacité
# et la mission s'arrête à l'intention, avant tout ledger (mesuré à la première exécution de ce
# bloc — le cas aurait porté sur une mission sans journal de statuts, donc sur rien).
question_vivant = "Analyse la complexité cyclomatique du dépôt"
pose_le = time.time()
refus = None
try:
    analyser.lancer(question_vivant, RACINE / "testrepo", moteur="deterministe", egress=True)
except Exception as exc:                                # noqa: BLE001 — OPA refuse, c'est le cas
    refus = exc
mission_dir = next(iter(sorted(dossier_vivant.iterdir())), None)
journal_vivant = ((mission_dir or tmp) / "journal.jsonl")
_evenements = [json.loads(l) for l in journal_vivant.read_text(encoding="utf-8").splitlines()
               if l.strip()] if journal_vivant.exists() else []
cas("16quater. OPA a refusé, et le journal dit QUAND même qui était disponible",
    type(refus).__name__ == "PolicyError"
    and any(e["type"] == "statuts" for e in _evenements)
    and any(e["type"] == "arret" for e in _evenements),
    {"exception": type(refus).__name__ if refus else None,
     "types": [e["type"] for e in _evenements]})
eg = next((e for e in _evenements if e["type"] == "egress"), {})
cas("16octies. la ligne `egress` du journal porte la demande, l'accord, le profil et la délégation",
    eg.get("demande") == "mission" and eg.get("autorise") is True
    and eg.get("delegation") is True and eg.get("profil") == PF.actif().nom, eg)
if mission_dir is not None:
    v = API._vivante(question_vivant, str(RACINE / "testrepo"), pose_le)
    cas("16quinquies. la console relit CETTE mission : outils, comptes, et nom de mission",
        v is not None and v["mission"] == mission_dir.name
        and isinstance(v.get("outils"), list) and v["outils"],
        {"vivante": None if v is None else {k: str(v[k])[:60] for k in ("mission", "resume")}})
    cas("16sexies. et refuse toute mission antérieure à la demande : aucun emprunt d'avancement",
        API._vivante(question_vivant, str(RACINE / "testrepo"), time.time() + 60) is None)
    refus_etat = getattr(refus, "agnt_refus", None) or {}
    cas("16nonies. le refus emporte l'état de la cage : la demande est lisible sans relire le journal",
        refus_etat.get("egress", {}).get("autorise") is True
        and refus_etat.get("egress", {}).get("delegation") is True
        and refus_etat.get("resume") is not None,
        {"egress": refus_etat.get("egress"), "resume": refus_etat.get("resume"),
         "note": "un refus n'archive pas de `rapport.json` (rien n'a tourné) : c'est l'objet "
                 "d'erreur qui porte l'état, et les deux lisent les mêmes champs"})
MS.MISSIONS = RACINE / "artifacts" / "missions"

# ═══════════════════════════ 4 · falsifications
print("═══ 4 · ce qui arrive quand un champ ment ═══")


class SbxMenteur(SB.Sandbox):
    """Un objet qui DÉCLARE le contraire de ce qu'il construit.

    Le champ `egress_autorise` n'est pas l'autorité : `conditions.egress_de` lit la commande.
    Ces deux cas existent pour que ça le reste — si quelqu'un branchait la garde sur le champ
    (le défaut exact corrigé par ce lot), les deux cas basculent.
    """
    def commande(self, argv):
        base = super().commande(argv)
        if self.egress_autorise:                      # dit « ouvert » mais reste coupé
            return base + ["--unshare-net"]
        return [x for x in base if x != "--unshare-net"]   # dit « coupé » mais laisse sortir


menteur_ferm = SbxMenteur(**{**SBX.__dict__, "egress_autorise": True})
menteur_ouvert = SbxMenteur(**{**SBX.__dict__, "egress_autorise": False})
cas("F1. un Sandbox qui se déclare ouvert mais coupe le réseau est jugé COUPÉ",
    COND.egress_de(menteur_ferm, ["true"]) is False)
cas("F2. un Sandbox qui se déclare fermé mais laisse passer le réseau est jugé OUVERT",
    COND.egress_de(menteur_ouvert, ["true"]) is True,
    "la commande fait foi dans les deux sens : c'est la définition d'une autorité unique")

# ═══════════════════════════ 5 · le vocabulaire reste fermé
print("═══ 5 · le ledger ne s'élargit pas ═══")
plan_dict = {"plan_id": "p", "steps": [{"provider": "bandit", "capability": "CAP"}],
             "selection": {"conditions": {"bandit": "egress_non_autorise : réseau requis"}}}
ledger = ST.construire(reg, plan_dict, {"allow": True, "motifs": []}, [], [], {},
                       en_cours="bandit")
FERMES = {"non_disponible", "non_applicable", "non_selectionne", "non_autorise",
          "selectionne", "echoue", "execute"}
cas("17. l'exécution en cours n'introduit aucun septième statut",
    all(o["statut"] in FERMES for o in ledger) and bool(ledger),
    [o["statut"] for o in ledger])
cas("18. le motif d'écartement lié au réseau est classé, pas inventé : le lecteur sait quoi changer",
    any(o["provider"] == "bandit" and "egress" in json.dumps(o, ensure_ascii=False)
        for o in ledger), ledger)
cas("19. la clé `en_cours` est posée sur chaque entrée du ledger", all("en_cours" in o for o in ledger))

# ═══════════════════════════ 6 · ce qui est écrit et ce qui est affirmé
print("═══ 6 · la documentation dit ce que le code fait ═══")
doc = (RACINE.parent / "README_USAGE.md").read_text(encoding="utf-8")
cas("20. README_USAGE documente le drapeau CLI et la variable de parallélisme qu'il nomme",
    "--egress" in doc and "AGNT_VAGUE_PARALLELE" in doc
    and "--egress" in open(RACINE / "analyser.py", encoding="utf-8").read()
    and "AGNT_VAGUE_PARALLELE" in (RACINE / "slice" / "pipeline.py").read_text(encoding="utf-8"))
etat = (RACINE.parent / "PROJET_ETAT.md").read_text(encoding="utf-8")
cas("21. PROJET_ETAT déclare le gain de temps de la vague comme NON ÉVALUÉ ici, pas comme mesuré",
    "NON ÉVALUÉ" in etat and "AGNT_VAGUE_PARALLELE" in etat, etat.count("NON ÉVALUÉ"))
rego = (RACINE.parent / "PHASE3" / "policy" / "policy.rego").read_text(encoding="utf-8").lower()
cas("22. la règle réseau n'a pas émigré dans `policy.rego` : elle vit dans conditions+sandbox",
    not any(m in rego for m in ("unshare", "egress", "reseau", "network", "http_proxy")),
    [m for m in ("unshare", "egress", "reseau", "network", "http_proxy") if m in rego])
cas("23. `pipeline.executer` et `analyser.lancer` ont le MÊME nom de paramètre (une seule grammaire)",
    "egress" in pipeline.executer.__code__.co_varnames
    and "egress" in analyser.lancer.__code__.co_varnames)

# ═══════════════════════════ 7 · ce qui reste à démontrer ailleurs
print("═══ 7 · NON ÉVALUÉ ═══")
non_evalue("application réelle de la garde réseau par le noyau",
           "les cas 1 à 7 sont joués contre un bouchon de `bwrap` : ils prouvent la commande "
           "et l'environnement demandés, pas l'effet du namespace réseau. Sur cette machine "
           "`bwrap` est absent (`deb.debian.org` injoignable) ; ailleurs, `bash "
           "PHASE3/test_bwrap.sh` (77 cas) et l'exécution réelle d'un outil `reseau: true` "
           "restent les épreuves qui manquent.")
non_evalue("décision d'OPA sur un profil à sortie accordée",
           "`PolicyEngine` exige le binaire `opa` (openpolicyagent.org ne répond pas, mesuré "
           "aujourd'hui) : le `profil_eff` transmis à `evaluer` avec `reseau_autorise: true` "
           "n'a donc jamais été vu par OPA. À rejouer : `python3 PHASE3/analyser.py "
           "PHASE3/testrepo \"Analyse les dépendances\" --egress=true` puis lire le champ "
           "`egress` de `rapport.json` et la ligne `egress` du journal.")
non_evalue("rendu navigateur du bloc `egress` et du ledger vivant",
           "`interface/_domtest.mjs` tourne sur des artefacts figés : la case réseau et le bloc "
           "#vivante sont branchés côté app.js (libellé lu dans `/api/capacites`), mais leur "
           "rendu demande une mission jouée, donc `opa`.")

print()
n_ok = sum(1 for _, c, _ in CAS if c)
print(f"{n_ok}/{len(CAS)} cas passent")
for nom, detail in [(c[0], c[2]) for c in CAS if not c[1]]:
    print(f"  ÉCHEC · {nom}\n        détail : {str(detail)[:400]}")
for nom, cause in NON_EVALUES:
    print(f"  NON ÉVALUÉ · {nom} — {cause[:150]}")
sys.exit(1 if ECHECS else 0)
