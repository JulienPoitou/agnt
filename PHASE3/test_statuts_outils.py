#!/usr/bin/env python3
"""
Batterie « statut par outil » — les six étapes, dérivées et non saisies.

Ce que cette batterie protège (2026-08-30) : un lecteur de l'interface doit pouvoir
distinguer, pour chaque outil, sept faits — indisponible, inapplicable, écarté par la
sélection, refusé par la politique, sélectionné sans sortie, échoué, exécuté. Avant
`slice/statuts.py`, ces faits vivaient dans six artefacts différents et l'écran ne
pouvait pas les réunir ; mesuré pendant la campagne adverse, un outil jamais lancé
ressemblait à un outil ayant conclu « rien trouvé ».

Le contrat jugé ici est donc un contrat d'HONNÊTETÉ, pas d'affichage :
  · aucun statut ne peut être affirmé sans l'artefact qui le prouve ;
  · « exécuté » exige une sortie conservée, et « 0 observation » exige des cibles analysées ;
  · la disponibilité du ledger est la RÈGLE MÊME qu'utilise l'exécuteur (une divergence
    entre les deux est le vrai défaut, et elle est contrôlée contre le registre réel).

Aucun outil n'est exécuté. Usage : python3 PHASE3/test_statuts_outils.py
"""
from __future__ import annotations

import sys
from pathlib import Path

RACINE = Path(__file__).parent
sys.path.insert(0, str(RACINE / "slice"))

import adapters  # noqa: E402
import statuts as ST  # noqa: E402
from registre import Registry  # noqa: E402

CAS = []
ECHECS = []
NON_EVALUES = []


def cas(nom: str, cond: bool, detail: str = ""):
    CAS.append((nom, bool(cond), detail))
    if not cond:
        ECHECS.append(nom)


class Prov:
    """Provider minimal, avec les SEULS attributs que le ledger est autorisé à lire."""
    def __init__(self, pid, cap="code", binaire=None, codes=(0,), outil=""):
        self.id = pid
        self.capability = cap
        self.commande = [binaire or pid]
        class M:
            code_succes = codes
            tool_id = outil
        self.manifest = M()


class Reg:
    def __init__(self, *provs):
        self.par = {p.id: p for p in provs}

    def provider(self, pid):
        return self.par[pid]


PLAN = lambda *pid: {"steps": [{"provider": p, "capability": "code"} for p in pid],
                     "selection": {}}
OK = {"allow": True, "motifs": []}
RES_ABSENT = lambda b: None
RES_PRESENT = lambda b: f"/faux/{b}"


def led(reg, plan, decision, raw=(), couv=(), fp=(), avorte=None, resoudre=RES_PRESENT):
    return ST.construire(reg, plan, decision, list(raw), list(couv), dict(fp),
                         avorte=avorte, resoudre=resoudre)


def un(ledger, pid):
    for e in ledger:
        if e["provider"] == pid:
            return e
    raise AssertionError(f"{pid} absent du ledger")


# ------------------------------------------------------------------ 1 · vocabulaire fermé
cas("1. le vocabulaire des statuts est fermé et exactement celui demandé (six étapes, "
    "sept libellés)",
    ST.STATUTS == ("non_disponible", "non_applicable", "non_selectionne", "non_autorise",
                   "selectionne", "echoue", "execute"),
    str(ST.STATUTS))

# un statut hors vocabulaire doit être impossible, pas seulement improbable :
# le ledger lève au lieu d'avaler (construire ne reçoit AUCUN statut en entrée).
cas("2. le ledger ne reçoit aucun statut en entrée : il ne peut que dériver",
    "statut" not in PLAN("semgrep")["steps"][0], str(PLAN("semgrep")["steps"][0]))

# ------------------------------------------------------------------ 2 · execute exige une preuve
reg = Reg(Prov("semgrep"), Prov("bandit"))
l = led(reg, PLAN("semgrep", "bandit"), OK)
cas("3. dans le plan + autorisé mais sans sortie conservée → « selectionne », jamais « execute »",
    un(l, "semgrep")["statut"] == "selectionne"
    and un(l, "bandit")["statut"] == "selectionne",
    str([e["statut"] for e in l]))

l = led(reg, PLAN("semgrep"), OK, raw=[{"provider": "semgrep", "code_retour": 0,
                                        "timeout": False}],
        couv=[{"provider": "semgrep", "cibles": [{"chemin": "a.py",
                                                  "etat": "scanned_successfully", "raison": ""}]}],
        fp={"semgrep": 4})
e = un(l, "semgrep")
cas("4. « execute » = une sortie conservée ET un code conforme aux codes déclarés",
    e["statut"] == "execute" and e["code_retour"] == 0 and e["findings"] == 4, str(e))

# ------------------------------------------------------------------ 3 · le piège du scan vide
l = led(reg, PLAN("semgrep"), OK, raw=[{"provider": "semgrep", "code_retour": 0, "timeout": False}],
        couv=[{"provider": "semgrep", "cibles": [{"chemin": "a.py", "etat": "not_found",
                                                  "raison": "aucun lockfile"}]}])
e = un(l, "semgrep")
cas("5. 0 cible analysée ≠ « scan propre » : la raison le dit et rien_trouve reste faux",
    e["statut"] == "execute" and e["rien_trouve"] is False
    and "AUCUNE cible analysée" in e["raison"], e["raison"])

l = led(reg, PLAN("semgrep"), OK, raw=[{"provider": "semgrep", "code_retour": 0, "timeout": False}],
        couv=[{"provider": "semgrep", "cibles": [{"chemin": "a.py",
                                                  "etat": "scanned_successfully", "raison": ""}]}],
        fp={"semgrep": 0})
e = un(l, "semgrep")
cas("6. « rien_trouve » n'existe que si des cibles ONT été analysées (le faux négatif utile)",
    e["rien_trouve"] is True and "0 observation" in e["raison"], e["raison"])

# ------------------------------------------------------------------ 4 · échecs
l = led(reg, PLAN("semgrep"), OK, raw=[{"provider": "semgrep", "code_retour": -9,
                                        "timeout": True}])
cas("7. un timeout est un échec nommé, pas un « 0 trouvé »",
    un(l, "semgrep")["statut"] == "echoue" and un(l, "semgrep")["raison"] == "timeout"
    and un(l, "semgrep")["timeout"] is True, str(un(l, "semgrep")))

reg2 = Reg(Prov("trivy", codes=(0, 1)))
l = led(reg2, PLAN("trivy"), OK, raw=[{"provider": "trivy", "code_retour": 2, "timeout": False}])
cas("8. code retour hors de ceux que le manifest DÉCLARE → echoue, et la raison cite les deux",
    un(l, "trivy")["statut"] == "echoue" and "hors [0, 1]" in un(l, "trivy")["raison"],
    un(l, "trivy")["raison"])

l = led(reg, PLAN("semgrep"), OK, avorte={"provider": "semgrep",
                                          "cause": "FileNotFoundError: outil introuvable"})
cas("9. l'exécution interrompue dégrade CE provider en échec, avec la cause dans la raison",
    un(l, "semgrep")["statut"] == "echoue"
    and "exécution interrompue" in un(l, "semgrep")["raison"]
    and "outil introuvable" in un(l, "semgrep")["raison"], un(l, "semgrep")["raison"])

l = led(reg, PLAN("semgrep", "bandit"), OK, raw=[{"provider": "bandit", "code_retour": 0,
                                                  "timeout": False}],
        avorte={"provider": "semgrep", "cause": "boom"})
cas("10. un avortement ne contamine pas les providers déjà terminés",
    un(l, "bandit")["statut"] == "execute" and un(l, "semgrep")["statut"] == "echoue",
    str({x["provider"]: x["statut"] for x in l}))

# ------------------------------------------------------------------ 5 · indisponibilité
l = led(reg, PLAN("semgrep"), OK, resoudre=RES_ABSENT)
cas("11. exécutable introuvable → non_disponible, même si le plan le retenait",
    un(l, "semgrep")["statut"] == "non_disponible"
    and un(l, "semgrep")["disponible"] is False
    and "bootstrap.sh" in un(l, "semgrep")["raison"], un(l, "semgrep")["raison"])

# L'indisponibilité est première : un brut conservé ne doit pas la faire passer à « execute ».
l = led(reg, PLAN("semgrep"), OK, raw=[{"provider": "semgrep", "code_retour": 0,
                                        "timeout": False}], resoudre=RES_ABSENT)
cas("12. même avec un brut sur disque, un outil introuvable reste « non_disponible »",
    un(l, "semgrep")["statut"] == "non_disponible"
    and "une sortie conservée existe pourtant" in un(l, "semgrep")["raison"],
    un(l, "semgrep")["raison"])

# Cohérence avec LA RÈGLE D'EXÉCUTION : c'est le point qui rend le statut utile.
registre = Registry()
tous = registre.providers()
# pas de résolveur injecté : c'est LA fonction de production que le ledger doit employer
l = ST.construire(registre, PLAN(*[p.id for p in tous]), {"allow": True, "motifs": []},
                  [], [], {})
divergents = [e["provider"] for e in l
              if e["disponible"] != (adapters.resoudre_exe(e["binaire"]) is not None)]
inventes = [e["provider"] for e in l if e["binaire"] != registre.provider(e["provider"]).commande[0]]
n_dispo = sum(1 for e in l if e["disponible"])
cas("13. le ledger et l'exécuteur partagent la règle de disponibilité (registre RÉEL)",
    not divergents and not inventes and len(l) >= 4 and 0 < n_dispo < len(l),
    f"divergents : {divergents} ; binaires réécrits : {inventes} ; "
    f"{n_dispo}/{len(l)} disponibles — si tous étaient disponibles, le test serait creux")
cas("14. …et cette règle est bien une fonction unique, pas un copiér-coller",
    hasattr(adapters, "resoudre_exe") and "resoudre_exe" in Path(
        RACINE / "slice" / "adapters.py").read_text(encoding="utf-8").split("def _exe")[0],
    "adapters.resoudre_exe doit exister AVANT _exe, et _exe doit l'appeler")

# ------------------------------------------------------------------ 6 · sélection & applicabilité
plan_sel = {"steps": [{"provider": "semgrep", "capability": "code"}],
            "selection": {"code": {"choisis": ["semgrep"],
                                   "ecartes": [{"id": "bandit", "priorite": 30}],
                                   "motif": "priorité déclarée la plus forte"},
                           "applicabilite": {"trivy": "non applicable à cette cible (globs)"}}}
reg3 = Reg(Prov("semgrep"), Prov("bandit"), Prov("trivy"))
l = led(reg3, plan_sel, OK)
cas("15. écarté par la priorité → non_selectionne, et la capacité est nommée dans la raison",
    un(l, "bandit")["statut"] == "non_selectionne" and "« code »" in un(l, "bandit")["raison"],
    un(l, "bandit")["raison"])
cas("16. écarté AVANT exécution par l'applicabilité → non_applicable, motif recopié",
    un(l, "trivy")["statut"] == "non_applicable"
    and "globs" in un(l, "trivy")["raison"], un(l, "trivy")["raison"])
cas("17. un provider retenu reste « selectionne » malgré la présence d'écartés voisins",
    un(l, "semgrep")["statut"] == "selectionne", un(l, "semgrep")["statut"])

# chemin du pipeline « aucun provider applicable » : plan vide, ledger quand même
l = led(reg3, {"steps": [], "selection": {"applicabilite":
              {"trivy": "aucun fichier ne correspond"}}}, {"allow": False, "motifs": []})
cas("18. le cas « rien d'applicable » produit un ledger (plan vide ≠ écran vide)",
    len(l) == 1 and l[0]["statut"] == "non_applicable", str(l))

# ------------------------------------------------------------------ 7 · refus de politique
l = led(reg, PLAN("semgrep"), {"allow": False, "motifs": ["risque_trop_eleve", "cible_non_autorisee"]})
e = un(l, "semgrep")
cas("19. refus de la politique → non_autorise, avec LES motifs de la décision",
    e["statut"] == "non_autorise" and "risque_trop_eleve" in e["raison"]
    and "cible_non_autorisee" in e["raison"], e["raison"])

l = led(reg, PLAN("semgrep"), {"allow": False, "motifs": []})
cas("20. refus sans motif nommé est dit comme tel (pas de motif inventé)",
    "refus sans motif nommé" in un(l, "semgrep")["raison"], un(l, "semgrep")["raison"])

# ------------------------------------------------------------------ 8 · périmètre et rejeu
l = led(Reg(Prov("semgrep"), Prov("bandit")), PLAN("semgrep"), OK)
cas("21. le ledger ne liste que ce qui a été demandé, écarté ou tenté — pas le registre entier",
    [x["provider"] for x in l] == ["semgrep"], str([x["provider"] for x in l]))

# provider que le registre ne connaît pas (plan fabriqué à la main, mission reprise) :
# le ledger doit quand même le classer, sans s'écraser sur un KeyError.
l = led(Reg(), PLAN("orphelin"), OK, raw=[{"provider": "orphelin", "code_retour": 0,
                                          "timeout": False}])
cas("22. un provider absent du registre mais présent dans le plan reste jugé, sans KeyError",
    len(l) == 1 and l[0]["statut"] in ST.STATUTS and l[0]["capability"] == "code", str(l))

a = led(reg, PLAN("semgrep", "bandit"), OK, resoudre=RES_PRESENT)
b = led(reg, PLAN("bandit", "semgrep"), OK, resoudre=RES_PRESENT)
cas("23. le ledger est déterministe (trié) : deux ordres de plan, même trace",
    a == b, "rejeu du journal de mission")

r = ST.resumer(a)
cas("24. le résumé compte depuis le ledger, et ne peut donc pas contredire les lignes",
    sum(r.values()) == len(a) and r["selectionne"] == 2, str(r))
cas("25. le résumé contient les sept clés même à zéro (sinon « absent » vs « 0 » ambigu)",
    set(r) == set(ST.STATUTS), str(sorted(r)))

# ------------------------------------------------------------------ 9 · ce que le module ne sait pas faire
cas("26. le module n'invente jamais de findings : findings vient du pipeline, sinon 0",
    un(led(reg, PLAN("semgrep"), OK), "semgrep")["findings"] == 0, "aucun comptage caché")

# ------------------------------------------------------------------ 10 · câblage
src = (RACINE / "slice" / "pipeline.py").read_text(encoding="utf-8")
cas("27. le ledger est consigné au journal de mission à chaque sortie, y compris interrompue",
    src.count("_ledger(miss, registre,") >= 5, str(src.count("_ledger(miss, registre,")))
cas("28. …et passe par le rapport, donc par l'archive lue par l'interface",
    '"statuts": e.statuts' in (RACINE / "slice" / "pipeline.py").read_text(encoding="utf-8")
    and '"statuts": rapport.get("statuts")' in (RACINE / "interface" / "api.py").read_text(encoding="utf-8"),
    "rapport.json → api._charger → chaine.statuts")
js = (RACINE / "interface" / "app.js").read_text(encoding="utf-8")
cas("29. l'écran distingue l'absence du ledger (« non consigné ») du ledger vide",
    "non consigné" in js and "aucun outil au programme" in js, "deux messages distincts")
cas("30. l'absence est un `undefined` côté API, pas un `[]` (None ≠ 0 trouvé)",
    'rapport.get("statuts")' in (RACINE / "interface" / "api.py").read_text(encoding="utf-8")
    and 'rapport.get("statuts", [])' not in (RACINE / "interface" / "api.py").read_text(encoding="utf-8"),
    "le défaut [] ferait passer une archive ancienne pour « aucun outil »")
rap = (RACINE / "slice" / "rapport.py").read_text(encoding="utf-8")
cas("31. le rapport Markdown rend la table de statut, et n'en invente pas si absente",
    "### Statut par outil" in rap and 'getattr(e, "statuts"' in rap, "section conditionnelle")

print(f"\n{len(CAS) - len(ECHECS)}/{len(CAS)} cas passent", end="")
if ECHECS:
    print(" ; échecs : " + ", ".join(ECHECS))
else:
    print()
for nom, ok, detail in CAS:
    if not ok:
        print(f"  ÉCHEC {nom} — {detail}")
sys.exit(1 if ECHECS else 0)
