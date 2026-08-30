#!/usr/bin/env python3
"""
Batterie « escalade bornée » — une vague de plus, décidée par des faits consignés.

Ce qui est demandé : qu'un outil qui tourne sans rien pouvoir analyser ne laisse pas la
capacité découverte. Ce qui est REFUSÉ : une boucle d'agent qui décide seule de relancer.
La frontière est exactement là, et c'est elle que ce fichier juge :

  · le déclencheur est un fait du ledger (`execute` + `cibles_analysees == 0`), pas une
    impression ; un outil qui a analysé et rien trouvé n'escalade PAS — sinon on ferait
    dire au nombre de findings ce que la couverture dit déjà ;
  · un outil ÉCHOUÉ n'escalade pas non plus : son échec est une cause à réparer, pas un
    trou à combler en silence avec un autre outil (choix assumé, documenté au cas 4) ;
  · un seul suppléant par capacité, PASSIF uniquement, dans l'ordre de priorité déclaré ;
  · la vague 2 passe par `plan.construire` (budget MAX_ETAPES) et par une SECONDE
    décision OPA : sans `allow`, rien ne tourne ;
  · une escalade refusée reste affichée (rapport + écran), pas reléguée au journal.

Usage : python3 PHASE3/test_escalade.py
"""
from __future__ import annotations

import ast
import sys
import tempfile
from pathlib import Path

RACINE = Path(__file__).resolve().parent
sys.path.insert(0, str(RACINE / "slice"))

import statuts as ST  # noqa: E402
from registre import Registry  # noqa: E402

CAS = []
ECHECS = []
NON_EVALUES = []


def cas(nom: str, cond, detail: str = ""):
    if cond is None:
        NON_EVALUES.append((nom, detail))
        return
    CAS.append((nom, bool(cond), detail))
    if not cond:
        ECHECS.append(nom)


Y = """\
capabilities:
  - id: CAP_A
    description: capacite A
    domaines: [a]
    entree: [cible]
    sortie: finding/a
    providers:
      - id: a_prioritaire
        kind: tool
        mode: CLI
        risque: PASSIVE
        priorite: 100
        commande: ["semgrep"]
      - id: a_suppleant
        kind: tool
        mode: CLI
        risque: PASSIVE
        priorite: 110
        commande: ["semgrep"]
  - id: CAP_B
    description: capacite B
    domaines: [b]
    entree: [cible]
    sortie: finding/b
    providers:
      - id: b_seul
        kind: tool
        mode: CLI
        risque: PASSIVE
        priorite: 100
        commande: ["semgrep"]
  - id: CAP_D
    description: capacite D
    domaines: [d]
    entree: [cible]
    sortie: finding/d
    providers:
      - id: d1
        kind: tool
        mode: CLI
        risque: PASSIVE
        priorite: 100
        commande: ["semgrep"]
      - id: d2
        kind: tool
        mode: CLI
        risque: PASSIVE
        priorite: 110
        commande: ["semgrep"]
  - id: CAP_E
    description: capacite E
    domaines: [e]
    entree: [cible]
    sortie: finding/e
    providers:
      - id: e1
        kind: tool
        mode: CLI
        risque: PASSIVE
        priorite: 100
        commande: ["semgrep"]
      - id: e2
        kind: tool
        mode: CLI
        risque: ACTIVE
        priorite: 110
        commande: ["semgrep"]
  - id: CAP_C
    description: capacite C a risques non admissibles
    domaines: [c]
    entree: [cible]
    sortie: finding/c
    providers:
      - id: c_actif
        kind: tool
        mode: CLI
        risque: ACTIVE
        priorite: 100
        commande: ["semgrep"]
      - id: c_passif
        kind: tool
        mode: CLI
        risque: PASSIVE
        priorite: 120
        commande: ["semgrep"]
"""
_f = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8")
_f.write(Y)
_f.close()
reg = Registry(_f.name)


def entree(prov, cap, statut, cibles, findings=0):
    return {"provider": prov, "capability": cap, "statut": statut,
            "cibles_analysees": cibles, "findings": findings}


# ------------------------------------------------------------------ 1 · déclencheurs
d = ST.declencheurs_escalade([entree("a_prioritaire", "CAP_A", "execute", 0)], reg, set(), 3)
cas("1. outil exécuté sans aucune cible analysée → un suppléant est proposé",
    d == [{"provider": "a_prioritaire", "capacite": "CAP_A",
           "motif": "outil lancé sans aucune cible analysée", "suppleant": "a_suppleant"}],
    str(d))

cas("2. outil exécuté AVEC des cibles analysées → rien n'est escaladé (0 finding n'est pas un trou)",
    ST.declencheurs_escalade([entree("a_prioritaire", "CAP_A", "execute", 4, findings=0)],
                             reg, {"a_prioritaire"}, 3) == [],
    "escalade sur un scan propre = sur-interprétation du nombre de findings")

cas("3. outil jamais lancé (sélectionné, non exécuté) → pas d'escalade : c'est l'exécution qui manque",
    ST.declencheurs_escalade([entree("a_prioritaire", "CAP_A", "selectionne", 0)], reg, set(), 3) == [],
    "un trou d'exécution se répare, pas se contourne")

cas("4. outil échoué → PAS de suppléant automatique (choix assumé, non accident)",
    ST.declencheurs_escalade([entree("a_prioritaire", "CAP_A", "echoue", 0)], reg, set(), 3) == [],
    "remplacer un échec par un autre outil masquerait la cause ; le ledger doit rester rouge")

cas("5. capacité sans second provider → aucun déclencheur inventé",
    ST.declencheurs_escalade([entree("b_seul", "CAP_B", "execute", 0)], reg, set(), 3) == [],
    "pas de suppléant fictif, pas d'outil hors registre")

cas("6. seul un provider PASSIF est proposé comme suppléant",
    [x["suppleant"] for x in ST.declencheurs_escalade(
        [entree("c_actif", "CAP_C", "execute", 0)], reg, {"c_actif"}, 3)] == ["c_passif"],
    "le risque ACTIVE n'entre pas par une porte de derrière")

cas("7. un provider déjà tenté n'est jamais relancé (ni double exécution, ni double facture)",
    ST.declencheurs_escalade([entree("a_prioritaire", "CAP_A", "execute", 0)], reg,
                             {"a_prioritaire", "a_suppleant"}, 3) == [],
    "le suppléant déjà essayé = rien de neuf à tenter")

deux = [entree("a_prioritaire", "CAP_A", "execute", 0), entree("d1", "CAP_D", "execute", 0)]
cas("8. deux trous, deux suppléants : chaque capacité n'en fournit qu'un",
    [x["suppleant"] for x in ST.declencheurs_escalade(deux, reg, set(), 3)] == ["a_suppleant", "d2"],
    str(ST.declencheurs_escalade(deux, reg, set(), 3)))

QUATRE = [entree("a_prioritaire", "CAP_A", "execute", 0),
          entree("b_seul", "CAP_B", "execute", 0),
          entree("d1", "CAP_D", "execute", 0),
          entree("e1", "CAP_E", "execute", 0)]
# Quatre trous, DEUX suppléants disponibles : CAP_B n'a qu'un provider (lui-même, exclu),
# CAP_E n'a qu'un ACTIVE (non admissible). Le plafond, lui, est mesuré au cas 9b.
cas("9. plafond dur : le nombre de suppléants ne dépasse jamais le plafond demandé",
    len(ST.declencheurs_escalade(QUATRE, reg, set(), 4)) == 2
    and len(ST.declencheurs_escalade(QUATRE, reg, set(), 1)) == 1,
    f"4 trous → 2 propositions, et 1 avec un plafond à 1")
cas("9b. un déclencheur ne se propose JAMAIS lui-même comme suppléant (mesuré, corrigé)",
    all(x["suppleant"] != x["provider"] for x in ST.declencheurs_escalade(QUATRE, reg, set(), 9)),
    "relancer le même outil sur la même cible = seconde facture sans progression")

cas("10. une capacité absente du registre ne fait pas tomber la fonction",
    ST.declencheurs_escalade([entree("zoulou", "CAP_INCONNUE", "execute", 0)], reg, set(), 3) == [],
    "robustesse : un ledger ne doit pas pouvoir faire planter l'escalade")

# ------------------------------------------------------------------ 2 · câblage
pl = (RACINE / "slice" / "pipeline.py").read_text(encoding="utf-8")
# Ce cas grepait `pl.count("for step in steps_:") == 1` : une seule boucle dans le fichier,
# preuve qu'il n'existait qu'un corps d'exécution. LOT 3 a remplacé cette boucle par un
# ordonnanceur (un outil par appel `_un`, fusion des artefacts dans l'ordre du plan), donc le
# littéral compte désormais DEUX boucles pour une raison licite : le chemin séquentiel
# (`AGNT_VAGUE_PARALLELE=1`, ou une vague d'un seul outil) et la consolidation. Le compte de
# boucles ne disait donc plus ce qu'on voulait garantir. L'invariant est repris à sa source :
# UN SEUL corps défini (`def _vague(` une fois), APPELÉ par les deux vagues.
cas("11. la vague 1 et la vague 2 partagent LE MÊME corps d'exécution (pas de boucle bis)",
    pl.count("def _vague(") == 1
    and "_vague(plan.steps, V, plan.to_dict()" in pl
    and "_vague(plan2.steps, V, plan2.to_dict()" in pl
    and pl.count("V = _ContexteVague(") == 1,
    "un seul corps, un seul contexte de mission, deux appels : la vague 2 ne peut pas avoir "
    "son propre chemin ni sa propre copie d'artefacts")
cas("11b. le corps de la vague est au niveau du module, donc testable sans `opa` ni `bwrap`",
    "_vague" in {n.name for n in ast.parse(pl).body if isinstance(n, ast.FunctionDef)},
    "un corps capturé dans une closure ne se prouve qu'en rejouant la mission entière")
cas("12. la vague 2 est construite COMME un plan (budget, providers connus) et non lancée à la main",
    "plan2 = P.construire(" in pl, "P.construire applique verifier_budget")
cas("13. OPA est ré-interrogé sur le plan de la vague 2 avant toute exécution",
    "decision2 = moteur.evaluer(plan2, registre, cible_autorisee" in pl
    and "if decision2 and decision2.allow:" in pl, "sans allow, rien ne tourne")
cas("14. moteur de décision injoignable pendant l'escalade = escalade refusée, pas exécutée à l'aveugle",
    'except Exception as exc:                          # noqa: BLE001\n                _consigner_arret(miss, "escalade_policy_injoignable", exc)' in pl,
    "l'exception est consignée et decision2 reste None")
cas("15. escalade refusée : le motif est écrit dans la trace de l'escalade",
    'd["motif_refus"]' in pl and 'd["execute"] = False' in pl, "motif + drapeau")
cas("16. le déclencheur vient du ledger, pas d'une jauge parallèle",
    "STAT.declencheurs_escalade(provisoire, registre, tentes, MAX_ESCALADE)" in pl,
    "une seule mesure de « qu'est-ce qui a couvert »")
cas("17. l'escalade est consignée au journal de mission",
    'MS.consigner(miss, "escalade", declencheurs=declencheurs' in pl, "rejouable")
cas("18. la vague est tracée dans le brut, l'exécution et le finding",
    '"vague": vague' in pl and 'f_.source["vague"] = vague' in pl
    and 'MS.consigner(miss, "execution", provider=prov.id, vague=vague' in pl,
    "sans ce champ, deux vagues sont indiscernables dans les artefacts")
cas("19. MAX_ESCALADE est un petit entier, pas une notion",
    isinstance(ST.__dict__.get("_", None) or pl, (str, dict)) and "MAX_ESCALADE = 3" in pl,
    "plafond borné à 3 suppléants")
r = (RACINE / "slice" / "rapport.py").read_text(encoding="utf-8")
cas("20. le rapport rend l'escalade, y compris les tentatives refusées",
    "Escalade bornée (vague 2)" in r and "escalades" in r, "section dédiée")
js = (RACINE / "interface" / "app.js").read_text(encoding="utf-8")
cas("21. l'écran rend les escalades dans son propre bloc (un `statuts` vide ne l'avale pas)",
    "function blocEscalades(" in js and "blocEscalades(s, chaine.escalades)" in js
    and "Escalade : aucun déclencheur" in js, "trois états : absent, aucun, listé")
api = (RACINE / "interface" / "api.py").read_text(encoding="utf-8")
cas("22. l'API transmet escalades SANS défaut à [] (archive muette ≠ aucune tentative)",
    '"escalades": rapport.get("escalades")' in api, "None garde le sens de l'absence")

# ------------------------------------------------------------------ 3 · non évalué, dit
cas("23. exécution RÉELLE d'une vague 2 (outil lancé, 0 cible, suppléant autorisé) : jugée ici ?",
    None,
    "NON ÉVALUÉ sur cette machine : la décision OPA est requise pour atteindre l'exécution "
    "(binaire `opa` absent, `bootstrap.sh` impossible sans réseau). Les cas 11-14 prouvent "
    "le câblage, pas l'exécution. À rejouer sur WSL/Windows après bootstrap : "
    "python3 PHASE3/analyser.py PHASE3/testrepo \"Analyse les dépendances de ce dépôt\" sur "
    "une cible sans lockfile, puis vérifier la ligne `escalade` du journal de mission.")

print(f"\n{len(CAS) - len(ECHECS)}/{len(CAS)} cas passent", end="")
if ECHECS:
    print(" ; échecs : " + ", ".join(ECHECS))
else:
    print()
for nom, ok, detail in CAS:
    if not ok:
        print(f"  ÉCHEC {nom} — {detail}")
for nom, detail in NON_EVALUES:
    print(f"  NON ÉVALUÉ {nom} — {detail}")
sys.exit(1 if ECHECS else 0)
