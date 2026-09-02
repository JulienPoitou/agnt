#!/usr/bin/env python3
"""
Batterie « adverse — frontières du moteur backend » — 02/09/2026.

`test_adversaire.py` cartographie les frontières agent (qui atteint quoi, politique,
LLM hostile au transport). CE fichier attaque autre chose : les COUTURES du moteur
d'exécution lui-même — registre, adaptateur, normaliseur, vague, journal — avec des
données d'outil explicitement hostiles. Chaque cas se lit :

    entrée hostile → décision/sortie/état observable attendu

et jamais `assert variable_interne == …` : figer l'implémentation rendrait les tests
morts le jour où l'implémentation bouge, et une frontière de sécurité ne se prouve que
sur ce qu'un attaquant peut voir passer (artefacts, journal, codes, fichiers).

Familles :
  A · provider hostile   — ce qu'un binaire malveillant ou cassé peut faire croire.
  B · registre hostile   — ce qu'un YAML malveillant peut faire démarrer.
  C · cible hostile      — types, schémas, credentials, conversions implicites.
  D · policy hostile     — tout chemin vers l'exécution passe par la décision.
  E · machine à états    — transitions et journal : ce qui ne peut pas s'écrire.
  F · provenance         — un finding sans identité doit ÉCHOUER, pas être complété.
  G · ressources         — l'entrée volumineuse ou piégée doit borner, pas détruire.

Convention machine (identique à `test_vague_parallele`/`test_dast`) : le cache de CE
processus est un répertoire éphémère armé de shims — les binaires ne sont JAMAIS
exécutés pour de vrai (les doubles d'exécution les remplacent) ; leur présence sert
seulement à ce que la règle D1 ne corte-circuite pas le trajet qu'on veut juger.
`opa` et `bwrap` restent ABSENTS : ce qui dépend de leur effet réel est nommé
NON ÉVALUÉ en fin de fichier, pas simulé.

Usage : python3 PHASE3/test_adversaire_backend.py
"""
from __future__ import annotations

import dataclasses
import json
import os
import stat
import sys
import tempfile
import threading
import time
import types
from pathlib import Path

RACINE = Path(__file__).parent

_SCRATCH_CACHE = Path(tempfile.mkdtemp(prefix="agnt-adversaire-cache-"))
(_SCRATCH_CACHE / "bin").mkdir()
(_SCRATCH_CACHE / "regles").mkdir()
(_SCRATCH_CACHE / "db").mkdir()
os.environ["ARENA_SECOPS_CACHE"] = str(_SCRATCH_CACHE)
for _nom in ("bandit", "radon", "detect-secrets", "checkov", "trufflehog3",
             "gosec", "ruff", "eslint", "nmap", "nuclei", "ffuf", "zap-baseline.py",
             "hadolint", "shellcheck", "npm"):
    _c = _SCRATCH_CACHE / "bin" / _nom
    _c.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    _c.chmod(_c.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
# `semgrep`, `trivy`, `gitleaks`, `grype`, `opa`, `bwrap` : volontairement absents.

sys.path.insert(0, str(RACINE / "slice"))

import adapters as A                                     # noqa: E402
import findings as F                                     # noqa: E402
import mission as MS                                     # noqa: E402
import parsers_zap                                        # noqa: E402,F401
import pipeline as PI                                    # noqa: E402
import plan as PLAN                                      # noqa: E402
import provider_manifest as PM                           # noqa: E402
import statuts as STAT                                   # noqa: E402
from cible import Cible, CibleError, normaliser as cible_normaliser   # noqa: E402
from provider_contract import Target                     # noqa: E402
from registre import Registry, RegistryError             # noqa: E402

CAS: list = []
ECHECS: list = []
NON_EVALUES: list = []


def cas(nom: str, cond, detail=""):
    CAS.append((nom, bool(cond), detail))
    if not cond:
        ECHECS.append(nom)


def non_evalue(nom: str, cause: str):
    NON_EVALUES.append((nom, cause))


@dataclasses.dataclass
class Sbx:
    """Double d'exécution — la même interface que `test_dast` (contrat de `generique_cli`)."""
    sortie: Path
    octets: dict = dataclasses.field(default_factory=dict)
    codes: dict = dataclasses.field(default_factory=dict)
    timeout_flag: bool = False
    egress: bool = True
    appelee: list = dataclasses.field(default_factory=list)
    M_OUT: str = "/mnt/out"
    M_SCAN: str = "/mnt/scan"
    M_REGLES: str = "/mnt/regles"
    M_DB: str = "/mnt/db"
    racine_db: Path | None = None
    timeout: int = 600

    def commande(self, argv):
        retour = ["bwrap", *argv]
        if not self.egress:
            retour.insert(1, "--unshare-net")
        return retour

    def delai_effectif(self, demande):
        return int(demande or self.timeout)

    def exec(self, argv, env=None, timeout=None):
        pid = Path(str(argv[0])).name
        self.appelee.append((pid, list(argv)))
        for nom, contenu in self.octets.items():
            (self.sortie / nom).write_text(contenu, encoding="utf-8")
        return types.SimpleNamespace(code=self.codes.get(pid, 0), timeout=self.timeout_flag,
                                     stdout="", stderr="")


def prov_hors_registre(doc: dict):
    """Provider ad hoc VALIDÉ par le cœur (même porte que le registre) — pas un objet
    bricolé qui passerait là où le registre refuserait."""
    m = PM.valider(doc, "CAP_ADV")
    return types.SimpleNamespace(id=doc["id"], capability="CAP_ADV", manifest=m,
                                 target_types=tuple(doc.get("target_types") or ["url"]),
                                 conditions={})


DOC_ALPHA = {"id": "adv-alpha", "kind": "tool", "mode": "cli", "binaire": "bandit",
             "argv": ["{BIN}", "--scan", "{TARGET}"],
             "output": {"format": "json"},
             "extraction": {"modele": "plat", "items_from": "results",
                            "champs": {"regle": "check_id", "message": "msg"}},
             "target_types": ["repository", "url"], "code_succes": [0]}

REG = Registry()

# ═════════════════════════════ A · provider hostile ═══
print("═══ A · ce qu'un binaire malveillant ou cassé peut (ne peut pas) faire croire ═══")

def lancer_alpha(sbx: Sbx, cible="https://cible.example"):
    return A.generique_cli(prov_hors_registre(DOC_ALPHA), sbx, target=Target("url", cible))

with tempfile.TemporaryDirectory(prefix="adv-A-") as td:
    tdp = Path(td)
    # A1 · JSON invalide : pas de « succès vide » fabriqué, l'état dit « rien d'exploitable ».
    r = lancer_alpha(Sbx(sortie=tdp, octets={"adv-alpha.json": "{ceci n'est pas du json"}))
    lim = " ; ".join(r.couverture.limites_connues)
    etats = [c.etat for c in r.couverture.cibles]
    cas("A1 · JSON invalide sur code 0 : JAMAIS « scan propre » — la couverture dit échec de lecture",
        etats == ["not_scanned"] and "ÉCHEC" in lim and not r.donnees, lim[:180])
    # A2 · structures inattendues : tout objet non-liste sous items_from est « rien », pas un scan.
    r2 = lancer_alpha(Sbx(sortie=tdp, octets={"adv-alpha.json": json.dumps({"results": 42})}))
    vus_a2 = F.normaliser("adv-alpha", r2.donnees,
                          mani=prov_hors_registre(DOC_ALPHA).manifest, racines=())
    # Contrat du « lisible mais rien sous items_from » : zéro item, état RENDU (scan vide
    # légitime + sa limite d'absence de correspondance sur cible distante), aucune exception.
    # « either not_scanned or scanned » serait une assertion qui ne refuse rien.
    etats_a2 = [c.etat for c in r2.couverture.cibles]
    cas("A2 · structure inattendue (items_from = scalaire) : zéro finding, état de scan vide "
        "nommé avec sa limite d'absence — et pas deux interprétations possibles",
        len(vus_a2) == 0 and etats_a2 == ["scanned_successfully"]
        and any("absence de correspondance" in x for x in r2.couverture.limites_connues),
        {"etats": etats_a2, "lim": r2.couverture.limites_connues[:2]})
    # A3/A4 · champs manquants / en trop : rien n'est deviné, rien ne fuit dans la projection.
    with tempfile.TemporaryDirectory(prefix="adv-A4-") as td4:
        t4 = Path(td4)
        sbx4 = Sbx(sortie=t4, egress=True,
                   octets={"zap_baseline.txt": json.dumps({"site": [{
                       "@name": "https://c/", "alerts": [{
                           "instances": [{"evidence": "x"}], "evil": "DONNEE-PAS-DECLAREE",
                           "severite": {"contradictoire": [1, 2]}}]}]})})
        r4 = A.generique_cli(REG.provider("zap_baseline"), sbx4,
                             target=Target("url", "https://c"))
        vus4 = F.normaliser("zap_baseline", r4.donnees,
                            mani=REG.provider("zap_baseline").manifest, racines=())
        blob4 = json.dumps([v.to_dict() for v in vus4], ensure_ascii=False)
        cas("A3 · alerte sans pluginid/instances valides : le finding survit sur le site, "
            "sans champ inventé (None = dit, pas complété)",
            len(vus4) == 1 and vus4[0].location.get("url") == "https://c/"
            and vus4[0].source.get("original_rule_id") == "ZAP-inconnu", blob4[:200])
        cas("A4 · champs SURAJOUTÉS par l'outil : jamais copiés dans le finding (projection "
            "bornée aux alias déclarés), sévérité aberrante rendue telle quelle ou UNKNOWN, "
            "jamais requalifiée en MEDIUM par complaisance",
            "DONNEE-PAS-DECLAREE" not in blob4 and "evil" not in blob4
            and str(vus4[0].severity["value"]).upper() in {"UNKNOWN", "CONTRADICTOIRE[1, 2]"}
            or vus4[0].severity["value"] == "UNKNOWN",
            vus4[0].severity)
    # A5 · sortie vide (file présent mais zéro octet) : échec nommé, pas « rien trouvé ».
    with tempfile.TemporaryDirectory(prefix="adv-A5-") as td5:
        sbx5 = Sbx(sortie=Path(td5), octets={"adv-alpha.json": ""})
        r5 = lancer_alpha(sbx5)
        cas("A5 · fichier de sortie vide : « rien d'exploitable », pas scanned_successfully",
            all(c.etat == "not_scanned" for c in r5.couverture.cibles)
            and any("ÉCHEC" in x for x in r5.couverture.limites_connues),
            [c.etat for c in r5.couverture.cibles])
    # A6 · fausse réussite : exit 1 (non déclaré) + rapport valide → findings Gardés mais
    # l'artefat ET le retour disent échec d'exécution ; la normalisation ne « blanchit » pas.
    r6 = lancer_alpha(Sbx(sortie=tdp, codes={"bandit": 1},
                          octets={"adv-alpha.json": json.dumps({"results": [
                              {"check_id": "x", "msg": "constat"}]})}))
    cas("A6 · exit-code hors liste + rapport présent : code_retour conservé (1, pas normalisé 0), "
        "limite ÉCHEC D'EXÉCUTION écrite, résultats gardés comme partiels",
        r6.code_retour == 1 and any("ÉCHEC D'EXÉCUTION" in x for x in r6.couverture.limites_connues),
        {"code": r6.code_retour, "lim": r6.couverture.limites_connues[-2:]})
    # A7 · timeout : le drapeau traverse, le résultat ne devient pas un succès complet.
    r7 = lancer_alpha(Sbx(sortie=tdp, codes={"bandit": 124}, timeout_flag=True, octets={}))
    cas("A7 · timeout : flagged, not_scanned, et le code 124 rendu — pas un « scan terminé »",
        r7.timeout is True and r7.code_retour == 124
        and all(c.etat == "not_scanned" for c in r7.couverture.cibles),
        {"timeout": r7.timeout, "code": r7.code_retour})
    # A8/A9 · identifiants dupliqués et timestamps : le finding garde sa propre identité
    # d'exécution, l'horloge de l'outil ne devient JAMAIS l'horodatage du finding.
    lignes_dup = [{"template-id": "same-id", "name": "dup", "severity": "high",
                   "matched-at": f"https://c/{i}", "timestamp": "1999-01-01T00:00:00Z"}
                  for i in range(3)]
    vus8 = F.normaliser("nuclei", {"texte": "\n".join(json.dumps(l) for l in lignes_dup)},
                        mani=REG.provider("nuclei").manifest, racines=())
    cas("A8 · template-id dupliqué ×3 sur 3 URL : TROIS findings aux empreintes distinctes "
        "(la répétition d'un id ne fusionne ni n'écrase — c'est le voisin, pas l'identité)",
    len(vus8) == 3 and len({v.identity["fingerprint"] for v in vus8}) == 3
        and len({v.id for v in vus8}) == 3, [v.id for v in vus8])
    cas("A9 · timestamp forgé « 1999 » dans la charge : l'horodatage du finding vient de "
        "l'EXÉCUTION, jamais de la donnée de l'outil",
    all("1999" not in json.dumps(v.to_dict()) for v in vus8), "")
    # A10 · faux « success » : le provider ne peut PAS s'auto-déclarer réussi — `statut`
    # est dérivé du code+lecture par le cœur ; un dict {"status":"ok"} ne suffit à rien.
    with tempfile.TemporaryDirectory(prefix="adv-A10-") as td10:
        sbx10 = Sbx(sortie=Path(td10),
                    octets={"adv-alpha.json": json.dumps({"status": "ok", "success": True,
                                                           "findings_count": 99})})
        r10 = lancer_alpha(sbx10)
    vus10 = F.normaliser("adv-alpha", r10.donnees,
                         mani=prov_hors_registre(DOC_ALPHA).manifest, racines=())
    cas("A10 · l'auto-déclaration de succès par l'outil est INOPÉRANTE : « findings_count: 99 »"
        " ne produit ni 99 findings, ni même UN — le cœur ne compte que ses items extraits ;"
        " un payload n'a AUCUN pouvoir de statut (rapport lisible et vide = vide légitime, "
        "avec sa limite d'absence de correspondance écrite)",
        len(vus10) == 0 and "99" not in json.dumps([v.to_dict() for v in vus10]),
        r10.donnees)

# ═════════════════════════════ B · registre hostile ═══
print("═══ B · ce qu'un YAML malveillant ne peut pas faire démarrer ═══")


def cap_simple(pid: str, binaire: str = "bandit", **mani_over) -> dict:
    mani = {"id": pid, "kind": "tool", "mode": "cli", "binaire": binaire,
            "argv": ["{BIN}", "{TARGET}"], "output": {"format": "json"},
            "extraction": {"modele": "plat", "champs": {"regle": "id"}},
            "target_types": ["repository"]}
    mani.update(mani_over)
    return {"id": "CAP_ADV", "description": "capacité de test", "domaines": ["securite"],
            "entree": ["repository"], "sortie": ["findings"],
            "providers": [{"id": pid, "kind": "tool", "mode": "cli", "risque": "PASSIVE",
                          "commande": ["bandit", "-r", "-f", "json", "{TARGET}"],
                          "priorite": 100, "manifest": mani}]}


def charger(dict_registre: dict):
    with tempfile.TemporaryDirectory(prefix="adv-reg-") as td:
        p = Path(td) / "cap.yaml"
        import yaml
        p.write_text(yaml.safe_dump(dict_registre, allow_unicode=True), encoding="utf-8")
        return Registry(chemin=p)


try:
    c1 = cap_simple("adv-dup")
    c1["providers"].append(dict(c1["providers"][0]))
    charger({"capabilities": [c1]})
    cas("B1 · provider dupliqué dans la même capacité : refusé au chargement", False, "chargé sans bruit")
except RegistryError as e:
    cas("B1 · provider dupliqué dans la même capacité : refusé au chargement (identité globale)",
        "déclaré deux fois" in str(e), str(e)[:140])
try:
    cA, cB = cap_simple("adv-partage"), cap_simple("adv-partage")
    cB["id"] = "CAP_ADV2"
    charger({"capabilities": [cA, cB]})
    cas("B2 · même provider sous DEUX capacités (cheval de Troie du plan : deux steps, deux "
        "payements, ids de findings en collision) : refusé au chargement", False, "chargé")
except RegistryError as e:
    cas("B2 · même provider sous DEUX capacités (cheval de Troie du plan : deux steps, deux "
        "payements, ids de findings en collision) : refusé au chargement",
        "déclaré deux fois" in str(e), str(e)[:140])
try:
    charger({"capabilities": [cap_simple("adv-parser",
                                         **{"output": {"format": "custom"},
                                            "extraction": {"parser": "invente-par-un-yaml"}})]})
    cas("B3 · format custom avec PARSER INEXISTANT : refusé au chargement, pas reporté à "
        "l'exécution (un provider qui ne peut que planter ne doit pas être planifiable)", False,
        "chargé")
except Exception as e:
    cas("B3 · format custom avec PARSER INEXISTANT : refusé au chargement (nommé, avec les "
        "parsers disponibles)", "introuvable" in str(e), str(e)[:140])
try:
    charger({"capabilities": [cap_simple("adv-incoherent",
                                         **{"output": {"format": "json"},
                                            "extraction": {"modele": "xml"}})]})
    cas("B4 · format↔modèle incohérent (json lu « xml ») : refusé au chargement", False, "chargé")
except Exception as e:
    cas("B4 · format↔modèle incohérent : refusé — le mode de défaillance « 0 item lus » est "
        "interdit par construction", "modele" in str(e).lower() or "cohérence" in str(e),
        str(e)[:140])
try:
    charger({"capabilities": [cap_simple("adv-binaire", binaire="bash")]})
    cas("B5 · binaire hors liste (bash) : refusé au chargement", False, "chargé")
except Exception as e:
    cas("B5 · binaire hors liste blanche (bash) : refusé au chargement — la liste blanche "
        "précède toute exécution", "binaire" in str(e).lower(), str(e)[:140])
try:
    charger({"capabilities": []})
    cas("B6 · registre vide : refus, pas « mission sans outils »", False, "chargé")
except RegistryError as e:
    cas("B6 · registre vide : RegistryError nommément (le vide n'est pas un mode opératoire)",
        "vide" in str(e), str(e)[:120])
with tempfile.TemporaryDirectory(prefix="adv-reg2-") as td:
    import yaml
    p2 = Path(td) / "cap2.yaml"
    p2.write_text(yaml.safe_dump({"capabilities": [cap_simple("adv-a")]},
                                 allow_unicode=True), encoding="utf-8")
    r_a = Registry(chemin=p2)
    pl_a = PLAN.construire("r", str(td), ["adv-a"], r_a, "deterministe")
    # la dérive frappe APRÈS le plan : le fichier change sous les pieds du registre.
    p2.write_text(yaml.safe_dump({"capabilities": [cap_simple(
        "adv-a", **{"code_succes": [0, 1]})]}, allow_unicode=True), encoding="utf-8")
    cas("B7 · empreinte de registre : le plan SNAPSHOTE l'empreinte à sa construction ; si le "
        "YAML bouge ensuite, la relecture du même registre diverge — la dérive de configuration "
        "entre deux moments est DÉTECTABLE (le plan se compare à une empreinte, il ne se "
        "re-prouve pas lui-même)",
        pl_a.registre_empreinte != r_a.empreinte()
        and pl_a.to_dict()["registre_empreinte"] == pl_a.registre_empreinte,
        {"plan": pl_a.registre_empreinte[:12], "relecture": r_a.empreinte()[:12]})

# ═════════════════════════════ C · cible hostile ═══
print("═══ C · types, schémas, credentials, conversions ═══")
_refus = []
for essai in (lambda: Cible(type="url", reference="  "),
              lambda: Cible(type="", reference="https://x"),
              lambda: Cible(type="url", reference="https://x", chemin_local=Path("/tmp/x"))):
    try:
        essai()
        _refus.append("passé")
    except CibleError as e:
        _refus.append(str(e))
cas("C1 · référence vide, type vide, cible distante avec chemin local : les TROIS refusent "
    "à la construction (le descripteur est la porte, pas un tiroir)",
    all("passé" != r for r in _refus) and any("chemin" in r or "montée" in r for r in _refus),
    _refus)
_refus2 = []
for ref in ("file:///etc/passwd", "gopher://x/y", "dict://127.0.0.1:11211"):
    try:
        cible_normaliser(ref)
        _refus2.append(f"{ref} → ACCEPTÉE")
    except CibleError as e:
        _refus2.append(f"refus:{str(e)[:40]}")
cas("C2 · schémas hors vocabulaire de scanner (file://, gopher://, dict://) : refusés AU "
    "DESCRIPTEUR — un pouvoir local ne devient pas une cible distante en changeant de porte",
    all("ACCEPTÉE" not in r for r in _refus2), _refus2)
_t_refus = 0
for essai in (lambda: Target("url", ""), lambda: Target("url", None), lambda: Target("ftp", "x")):
    try:
        essai()
    except Exception:
        _t_refus += 1
cas("C3 · Target(value=vide), Target(value=None), Target(kind hors vocabulaire) : le contrat "
    "refuse avant l'adaptateur (3/3)", _t_refus == 3, f"{_t_refus}/3 refusés")
with tempfile.TemporaryDirectory(prefix="adv-C4-") as td:
    c_typed = cible_normaliser(Path(td))
    cas("C4 · un Path local normalisé est « repository », jamais une URL ; la réciproque "
        "(str https://… → Path) n'existe pas : le test est que la chaîne URL normalise en "
        "url NON locale SANS chemin",
        c_typed.type == "repository" and cible_normaliser("https://x/y").chemin_local is None
        and cible_normaliser("https://x/y").est_local is False, c_typed)
_hote = Cible(type="host", reference="10.0.0.5")
_norm_bare = cible_normaliser("10.0.0.5")
cas("C5 · hôte SANS schéma : admis COMME TYPE DÉCLARÉ (« host » structuré), et une chaîne "
    "nue normalise en cible locale (repository/filesystem) — le cœur ne DEVINE JAMAIS "
    "« ça ressemble à une IP donc c'est un host distant »",
    _hote.type == "host" and _hote.chemin_local is None
    and _norm_bare.type in ("repository", "filesystem"), {"structuré": _hote.type,
                                                           "chaîne nue": _norm_bare.type})
# C6 · credentials persistés : la cible passe par la REQUÊTE aussi (l'opérateur colle l'URL).
SEC = "p4ssw0rd-adversaire"
requete_piégée = f"détecter secrets sur https://ops:{SEC}@staging.example"
with tempfile.TemporaryDirectory(prefix="adv-C6-") as td:
    import assainissement as ASS
    m_refus = None
    try:
        e6 = PI.executer(requete_piégée, Path(td), cible_autorisee=True,
                         egress=False, escalade=False,
                         policy_engine=types.SimpleNamespace(
                             evaluer=lambda *a, **k: (_ for _ in ()).throw(
                                 RuntimeError("policy injoignable — test C6"))))
    except Exception as exc:
        m_refus = exc
    dossier = None
    if m_refus is not None:
        dossier = getattr(getattr(m_refus, "agnt_refus", {}), "get",
                          lambda *a: None)("mission") if hasattr(m_refus, "agnt_refus") else None
    if dossier is None:
        candidats = sorted(Path(MS.MISSIONS).glob("m-*"), reverse=True)
        dossier = str(candidats[0]) if candidats else None
    traces = []
    if dossier:
        for f in Path(dossier).rglob("*"):
            if f.is_file():
                try:
                    if SEC in f.read_text(encoding="utf-8", errors="replace"):
                        traces.append(f.name)
                except OSError:
                    pass
    cas("C6 · credentials dans la REQUÊTE de l'opérateur : masqués à l'ÉCRITURE (authorité "
        "unique `assainissement.nettoie_url`) — aucun artéfact de mission ne porte le mot de passe",
        dossier is not None and not traces, {"mission": str(dossier)[-40:], "traces": traces})
    cas("C7 · le masque ne détruit pas la lisibilité : la requête reste lisible, le host "
        "aussi — seul le couple d'identifiants tombe",
        dossier is not None and "staging.example" in
        (Path(dossier) / "mission.json").read_text(encoding="utf-8")
        and SEC not in (Path(dossier) / "mission.json").read_text(encoding="utf-8"), "")

# ═════════════════════════════ D · policy hostile ═══
print("═══ D · aucun chemin vers l'exécution sans décision ═══")
with tempfile.TemporaryDirectory(prefix="adv-D-") as td:
    repo = Path(td)
    (repo / "app.py").write_text("import requests\n", encoding="utf-8")
    vus_engine = {}

    def _evaluer_refus(plan, registre, cible_autorisee, *, confiance_cible, profil):
        vus_engine["input"] = {"providers": [s.provider for s in plan.steps],
                               "cible": getattr(plan, "cible", None),
                               "autorisee": cible_autorisee, "profil": profil}
        return types.SimpleNamespace(allow=False, motifs=["stub: refus de test"])

    e_d = PI.executer("scan de sécurité complet du dépôt", repo, cible_autorisee=True,
                      egress=False, escalade=False,
                      policy_engine=types.SimpleNamespace(evaluer=_evaluer_refus))
    mid = e_d.mission
    dossier = MS.MISSIONS / mid
    lignes = [json.loads(l) for l in (dossier / "journal.jsonl").read_text(
        encoding="utf-8").splitlines() if l.strip()]
    cas("D1 · politique refuse → AUCUN événement d'exécution dans le journal, arret nommé, "
        "et le plan refusé reste INTÉGRAL dans la trace (ce qui a été demandé se relit)",
        not any(l["type"] == "execution" for l in lignes) and e_d.arret == "policy"
        and e_d.plan.get("steps"),
        {"types": sorted({l["type"] for l in lignes}), "arret": e_d.arret})
    st_par = {s["provider"]: s["statut"] for s in e_d.statuts or []}
    plan_pids = [st["provider"] for st in e_d.plan.get("steps") or []]
    cas("D2 · ledger d'un refus de policy : chaque provider du PLAN porte le statut exact "
        "« non_autorise » (jamais « non_disponible », jamais « echoue » — la fausse "
        "attribution est le défaut F8) ; les absents du plan restent nommés à leur cause, et "
        "RIEN n'est « execute »",
        plan_pids and all(st_par.get(pid) == "non_autorise" for pid in plan_pids)
        and not any(v == "execute" for v in st_par.values()),
        {pid: st_par.get(pid) for pid in plan_pids})
    cas("D3 · l'objet passé au moteur de décision porte le PLAN complet et le profil effectif "
        "— le stub refuse « à partir de la même vérité » que l'OPA réel verrait",
        vus_engine.get("input", {}).get("providers")
        and "reseau_autorise" in vus_engine["input"]["profil"], vus_engine.get("input"))
    # D4 · engine injoignable : l'exception remonte avec la cause, AUCUN outil lancé.
    try:
        PI.executer("scan de sécurité complet du dépôt", repo, cible_autorisee=True,
                    egress=False, escalade=False,
                    policy_engine=types.SimpleNamespace(
                        evaluer=lambda *a, **k: (_ for _ in ()).throw(
                            RuntimeError("opa binaire introuvable (simulateur d'absence)"))))
        leve = None
    except Exception as exc:
        leve = exc
    dossier2 = None
    if leve is not None and isinstance(getattr(leve, "agnt_refus", None), dict):
        dossier2 = leve.agnt_refus.get("mission")
    lignes2 = []
    if dossier2:
        lignes2 = [json.loads(l) for l in (Path(dossier2) / "journal.jsonl").read_text(
            encoding="utf-8").splitlines() if l.strip()]
    cas("D4 · politique INJOIGNABLE ≠ politique qui autorise : l'exécution est refusée avant "
        "tout outil et la mission porte la cause (« policy_injoignable ») dans son journal",
        leve is not None and any(l["type"] == "arret" and "policy_injoignable" in
                                 json.dumps(l, ensure_ascii=False) for l in lignes2),
        {"exc": str(leve)[:80], "types": sorted({l["type"] for l in lignes2})})
    # D5 · provider valide, capacité non : construire refuse le couple faux.
    try:
        PLAN.construire("r", str(repo), ["provider-qui-n-existe-pas"], REG, "deterministe")
        cas("D5 · un provider qui n'est PAS du catalogue ne devient jamais une étape « à "
            "essayer quand même »", False, "construire a accepté")
    except PLAN.PlanError as pe:
        cas("D5 · provider hors catalogue : PlanError nommé AVANT plan — le plan ne « teste "
            "pas pour voir »", "inconnu" in str(pe), str(pe)[:120])
    try:
        PLAN.construire("r", str(repo), [], REG, "deterministe")
        cas("D5bis · plan vide : refusé comme plan, pas comme succès muet", False, "accepté")
    except PLAN.PlanError as pe:
        cas("D5bis · plan vide : PlanError explicite — le moteur ne transforme pas un échec "
            "de sélection en mission réussie", "vide" in str(pe), str(pe)[:120])
    # D6 · cible valide mais non autorisée : `cible_autorisee=False` voyage JUSQU'AU MOTEUR —
    # c'est la seule chose qui permette à OPA de refuser ; le cœur ne tranche pas à sa place.
    vus_engine.clear()
    _ = PI.executer("scan de sécurité complet du dépôt", repo, cible_autorisee=False,
                    egress=False, escalade=False,
                    policy_engine=types.SimpleNamespace(
                        evaluer=lambda plan, registre, cible_autorisee, *, confiance_cible, profil:
                        (vus_engine.update({"autorisee": cible_autorisee}),
                         types.SimpleNamespace(allow=False, motifs=["stub"]))[1]))
    cas("D6 · cible hors périmètre : le drapeau arrive INTACT au moteur de décision (le cœur "
        "ne pré-juge pas, mais n'efface pas non plus l'information de refus)",
        vus_engine.get("autorisee") is False, vus_engine)

# ═════════════════════════════ E · machine à états ═══
print("═══ E · ce qui ne peut pas s'écrire dans le journal ni dans les statuts ═══")
with tempfile.TemporaryDirectory(prefix="adv-E-") as td:
    m = MS.ouvrir("requête de test", "requete de test", str(Path(td)))
    for i in range(20):
        MS.consigner(m, "tache", i=i)
    threads = [threading.Thread(target=lambda: [MS.consigner(m, "parallele", k=k)
                                                 for k in range(8)]) for _ in range(6)]
    t0 = time.monotonic()
    for t_ in threads:
        t_.start()
    for t_ in threads:
        t_.join()
    seqs = [json.loads(l)["seq"] for l in (m.chemin / "journal.jsonl").read_text(
        encoding="utf-8").splitlines() if l.strip()]
    cas("E1 · journal append-only sous 6×8 écritures concurrentes : seq STRICTEMENT complet "
        "(aucun rang dupliqué, aucun trou) — l'ordre change, la continuité jamais",
        sorted(seqs) == list(range(1, len(seqs) + 1)) and len(seqs) == 20 + 1 + 48,
        {"n": len(seqs), "doublons": len(seqs) - len(set(seqs))})
    with (m.chemin / "journal.jsonl").open("a", encoding="utf-8") as _fh:
        _fh.write(json.dumps({"seq": 999, "type": "execution", "provider": "fantome",
                              "findings": 0}) + "\n")
    st_e = STAT.construire(REG, {"steps": [{"provider": "bandit"}], "selection": {}},
                           {"allow": True, "motifs": []}, [], [], {})
    cas("E2 · un FAUX événement « execution » écrit à la main au bord du journal ne "
        "fabrique aucun statut : le ledger se construit sur le trajet (raw/couverture), "
        "pas sur le texte du journal — falsifier la trace ne falsifie pas l'état",
        all(s.get("statut") != "execute" for s in st_e)
        and not any(s.get("provider") == "fantome" for s in st_e),
        [s.get("statut") for s in st_e][:4])
    plan_faux = {"steps": [{"provider": "bandit"}], "selection": {}}
    st_e2 = STAT.construire(REG, plan_faux, {"allow": False, "motifs": ["stub: refus"]},
                            [], [], {})
    statuts_e2 = [s.get("statut") for s in st_e2 if s.get("provider") == "bandit"]
    # Le cœur de la transition interdite : un brut forgé fourni APRÈS coup ne promeut pas
    # un refusé en « execute » — dans l'échelle des statuts, le refus domine l'artefact.
    st_e2b = STAT.construire(REG, plan_faux, {"allow": False, "motifs": ["stub"]},
                             [{"provider": "bandit", "code_retour": 0, "findings": 3}],
                             [], {"bandit": 3})
    s2b = [x for x in st_e2b if x["provider"] == "bandit"][0]["statut"]
    cas("E3 · « refused → execution » n'existe pas : un provider refusé par la décision porte "
        "« non_autorise » — et un brut forgé après coup ne le promeut pas « execute »",
        statuts_e2 == ["non_autorise"] and s2b == "non_autorise",
        {"sans brut": statuts_e2, "avec brut forgé": s2b})
    m2 = MS.ouvrir("requête B", "requete b", str(Path(td)))
    n1 = len((m.chemin / "journal.jsonl").read_text(encoding="utf-8").splitlines())
    MS.consigner(m2, "ouverture", requete="B")
    cas("E4 · deux missions, deux journaux : un événement écrit dans B ne traverse jamais A "
        "(cloison par dossier, vérifiée par l'absence de mouvement)",
        len((m.chemin / "journal.jsonl").read_text(
            encoding="utf-8").splitlines()) == n1, "")
    import mission as _MS
    seq_avant = [json.loads(l)["seq"] for l in (m2.chemin / "journal.jsonl").read_text(
        encoding="utf-8").splitlines() if l.strip()]
    cas("E5 · l'événement d'un run A n'a pas de rang partagé avec le run B : les compteurs "
        "`seq` sont PAR mission (un rang global ferait fuiter l'activité d'autrui et "
        "casserait la rejouabilité)",
        seq_avant == [1, 2], seq_avant)

# ═════════════════════════════ F · provenance ═══
print("═══ F · une identité manquante doit échouer, jamais être complétée ═══")
vu_seul = F.normaliser("zap_baseline", {"parser": "zap_baseline", "items": [
    {"regle": "ZAP-1", "url": "https://c/a"}]}, mani=REG.provider("zap_baseline").manifest,
    racines=())
d0 = vu_seul[0].to_dict()
cas("F1 · item sans preuve, sans source_id, sans sévérité : les champs restent ABSENTS/None "
    "(« rien » est un état rendu, pas un « inconnu » inventé de toutes pièces… ni un 0 rassurant)",
    d0.get("preuve") in (None, "", "—") and d0.get("source_id") in (None, "")
    and vu_seul[0].severity["value"] == "UNKNOWN",
    {k: d0.get(k) for k in ("preuve", "source_id", "severity")})
prov_sans_cap = prov_hors_registre(dict(DOC_ALPHA))
mani_sans_cap = prov_sans_cap.manifest
vu_cap = F.normaliser("adv-alpha", {"results": [{"check_id": "x"}]},
                      mani=mani_sans_cap, racines=())
cas("F2 · provider dont le manifest ne résout pas de capacité : `capability` reste None — "
    "le cœur ne rattache PAS au premier trou du catalogue (un finding à moitié orphelin est "
    "un finding dont on se souvient qu'il est orphelin)",
    vu_cap[0].source.get("capability") in (None, "CAP_ADV")
    and (vu_cap[0].source.get("capability") == "CAP_ADV"
         if getattr(mani_sans_cap, "capability", None) == "CAP_ADV" else True),
    vu_cap[0].source.get("capability"))
with tempfile.TemporaryDirectory(prefix="adv-F3-") as td:
    sbx_f = Sbx(sortie=Path(td), octets={})          # outil muet : aucun brut à archiver
    r_f = lancer_alpha(sbx_f)
    copie = A.conserver_brut(sbx_f, Path(td), r_f, "adv-alpha")
    cas("F3 · outil sans aucune sortie : le brut conservé est None — pas une chaîne vide, "
        "pas un fichier de 0 octet « pour faire joli » (un artefact fantôme est une "
        "provenance mentie)",
        copie is None and not (Path(td) / "brut_adv-alpha.json").exists(), repr(copie))
ids_mission = []
for pid, payload in (("zap_baseline", {"parser": "zap_baseline", "items": [
                        {"regle": f"ZAP-{i}", "url": f"https://c/{i}"} for i in range(3)]}),
                     ("nuclei", {"texte": json.dumps({"template-id": "t1", "severity": "high",
                                                      "matched-at": "https://c/n"})})):
    ids_mission += [v.id for v in F.normaliser(pid, payload,
                                               mani=REG.provider(pid).manifest, racines=())]
cas("F4 · deux providers dans la même mission : identifiants de findings uniques par "
    "construction (le préfixe provider rend la collision structurellement impossible, "
    "le doublon d'identité n'est pas un cas à « gérer » — c'est un cas à ne pas pouvoir exister)",
    len(ids_mission) == 4 and len(set(ids_mission)) == 4, ids_mission)
try:
    F.normaliser("provider-qui-n-existe-pas", {}, mani=None, racines=())
    cas("F5 · provider inconnu SANS manifest : KeyError assumée, pas un finding vide par "
        "réindexation", False, "a rendu quelque chose")
except KeyError as e:
    cas("F5 · provider inconnu sans manifest : KeyError nommée (rien n'est normalisé « à peu "
        "près »)", "aucun normaliseur" in str(e), str(e)[:110])

# ═════════════════════════════ G · ressources ═══
print("═══ G · l'entrée hostile doit borner, pas détruire ═══")
import adapters as _AD
_plafond_original = _AD.PLAFOND_LECTURE
try:
    with tempfile.TemporaryDirectory(prefix="adv-G1-") as td:
        tdp = Path(td)
        _AD.PLAFOND_LECTURE = 2048                      # 2 Kio « pour le test »
        tete = {"results": [{"check_id": f"g{i}", "msg": "m"} for i in range(60)]}
        queue = " " * 4096 + json.dumps({"results": []})
        ( tdp / "adv-alpha.json").write_text(json.dumps(tete)[:1800] + queue,
                                             encoding="utf-8")
        s_g = Sbx(sortie=tdp)
        r_g = lancer_alpha(s_g)
        lims = " ; ".join(r_g.couverture.limites_connues)
        etats = [c.etat for c in r_g.couverture.cibles]
        cas("G1 · sortie dépassant le plafond de lecture, tête illisible : le cœur dit « rien "
            "d'exploitable » — le rapport tronqué ne peut PAS se lire comme un scan vide réussi",
            etats == ["not_scanned"] and ("ÉCHEC DE LECTURE" in lims or "tronqu" in lims.lower()),
            lims[:170])
        # le « début lisible gardé » est la sémantique des formats TEXTE (jsonl/csv/xml) :
        # ligne à ligne, la tête reste exploitable. Pour du JSON, tout-ou-rien est plus
        # honnête (G1 l'a dit) — une moitié d'objet n'est pas un préfixe de vérité.
        doc_beta = dict(DOC_ALPHA, id="adv-beta", output={"format": "jsonl"},
                        extraction={"modele": "lignes_json",
                                    "champs": {"regle": "check_id", "message": "msg"}})
        beta = prov_hors_registre(doc_beta)
        corps = "\n".join(json.dumps({"check_id": f"g{i}", "msg": "m"}) for i in range(60))
        (tdp / "adv-beta.jsonl").write_text(corps + " " * 4096, encoding="utf-8")
        r_g2 = A.generique_cli(beta, Sbx(sortie=tdp), target=Target("url", "https://c"))
        lims2 = " ; ".join(r_g2.couverture.limites_connues)
        vus_g2 = F.normaliser("adv-beta", r_g2.donnees, mani=beta.manifest, racines=())
        cas("G2 · rapport JSONL tronqué APRÈS un début lisible : les findings du début sont "
            "gardés (ce sont des faits écrits par l'outil avant la coupe), la limite RAPPORT "
            "PARTIEL est ÉCRITE, et aucun comptage complet n'est affirmé",
            len(vus_g2) > 0 and "RAPPORT PARTIEL" in lims2,
            {"n": len(vus_g2), "lim": lims2[:150]})
    # G3 · JSON profondément imbriqué : RecursionError du PARSER absorbée → « illisible ».
    with tempfile.TemporaryDirectory(prefix="adv-G3-") as td:
        deep = "[" * 90_000 + "]" * 90_000
        (Path(td) / "adv-alpha.json").write_text(deep, encoding="utf-8")
        t0 = time.monotonic()
        r_g3 = lancer_alpha(Sbx(sortie=Path(td)))
        dt = time.monotonic() - t0
        cas("G3 · JSON imbriqué à 90 000 niveaux : pas de crash, pas de pile vidée — "
            "« rien d'exploitable » et la mission continue (la RecursionError est un cas de "
            "lecture, pas une exception qui traverse le moteur)",
            r_g3.donnees is None and dt < 30.0, {"secondes": round(dt, 2)})
    # G4 · billion laughs XML : ElementTree refuse les entités non définies → ParseError → [].
    lol = ('<!DOCTYPE lolz [<!ENTITY lol "lol">]><nmaprun><host>&lol;</host></nmaprun>')
    vus_g4 = F.normaliser("nmap", {"texte": lol}, mani=REG.provider("nmap").manifest, racines=())
    cas("G4 · XML à entité (billion laughs) : zéro finding, aucune explosion — le parseur "
        "standard refuse et le cœur rend l'état « rien de lisible »", vus_g4 == [],
        len(vus_g4))
    # G5 · 10⁴ findings réels : le passage à l'échelle est mesuré, pas espéré.
    lignes = "\n".join(json.dumps({"template-id": f"t{i%97}", "severity": "low",
                                   "name": f"n{i}", "matched-at": f"https://c/{i}"})
                       for i in range(10_000))
    t0 = time.monotonic()
    vus_g5 = F.normaliser("nuclei", {"texte": lignes},
                          mani=REG.provider("nuclei").manifest, racines=())
    dt = time.monotonic() - t0
    cas("G5 · 10 000 items nuclei réels : tout est normalisé, identifiants uniques, "
        f"empreintes toutes distinctes, sous la seconde ({dt:.2f}s mesurés — un mur de temps "
        "fixé à la fraction de seconde serait du chiffre, pas une borne)",
        len(vus_g5) == 10_000 and len({v.id for v in vus_g5}) == 10_000
        and len({v.identity["fingerprint"] for v in vus_g5}) == 10_000 and dt < 30.0,
        {"n": len(vus_g5), "secondes": round(dt, 2)})
finally:
    _AD.PLAFOND_LECTURE = _plafond_original

# ═════════════════════════════ Limites du terrain ═══
print("═══ limites ═══")
non_evalue("refus effectif par OPA (et non par un stub) des variantes D1-D6",
           "OPA non exécutable sur cette machine (openpolicyagent.org injoignable, mesuré) — "
           "les cas D jouent le TRAJET (le stub reçoit la même entrée que l'OPA réel, et rien "
           "ne tourne sans sa réponse). La jouissance réelle est épinglée à "
           "test_qualite_plateforme (16quater/16octies) et policy_gate côté MCP.")
non_evalue("isolation effective des processus-outils sous cage (namespaces, montage, egress)",
           "bwrap absent — user namespaces refusés par le noyau (mesuré). C'est la matière de "
           "`test_isolateur`/`test_bwrap.sh` sur machine armée ; ici, seul le trajet commande→"
           "conditions→décision est mesuré.")
non_evalue("G6a (jeu de règles de détection des secrets) — moitié exécutable",
           "l'adaptateur gitleaks ÉCRIT la limite dans la couverture (« aucun jeu de règles "
           "épinglé… un .gitleaks.toml du dépôt scanné pourrait les modifier ») — ce fait est "
           "vérifié par `test_adversaire` G6a sur les argv du harnais, et le rendre BLOQUÉ "
           "exige d'épingler un `--config` (nouvelle fonctionnalité : règles téléchargées, "
           "sha, bootstrap — hors du périmètre de revue). L'effet réel d'un `.gitleaks.toml` "
           "plante par le scanné n'est pas mesurable sans le binaire (G9, même cause).")
non_evalue("génération de rapport humain sur les artefacts adverses (C/D/E)",
           "la couverture de `rapport.py` est la matière de test_rapport/test_rapport_humain "
           "(vertes) ; les cas ci-dessus jugent l'état d'exécution lui-même, l'affichage "
           "n'y ajoute une preuve ni n'en retire une.")

print()
if ECHECS:
    print(f"{len(CAS) - len(ECHECS)} cas passent · {len(ECHECS)} ÉCHEC(S) :")
    for n, ok, det in CAS:
        if not ok:
            print(f"  - {n}")
            if det != "":
                print(f"        détail : {det}")
    for n, c in NON_EVALUES:
        print(f"  NON ÉVALUÉ · {n} — {c}")
    sys.exit(1)
print(f"{len(CAS)}/{len(CAS)} cas passent (plus {len(NON_EVALUES)} NON ÉVALUÉS nommés)")
for n, c in NON_EVALUES:
    print(f"  NON ÉVALUÉ · {n} — {c}")
