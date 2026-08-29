#!/usr/bin/env python3
"""
Batterie « sélection des providers » — priorité explicite + motif traçable.

Décision actée le 2026-08-28 (option 1 de PAUSE_ARCHITECTURE_SELECTION.md) :
- la plus petite `priorite:` déclarée gagne ; égalité → ordre de déclaration ;
- seul un provider PASSIF peut être choisi automatiquement ;
- plan.json trace {choisis, ecartes, motif} — et le motif ne ment jamais
  (un choix imposé par l'appelant est dit comme tel) ;
- la sélection est HORS empreinte du plan : elle se déduit du registre, déjà
  empreinté — le rejeu des plans existants n'est pas affecté.

Aucun outil n'est exécuté. Le cas multi-provider est testé sur un registre
temporaire synthétique : c'est la première fois que le mécanisme est exercé en
situation d'arbitrage réel, alors qu'aucune capacité du registre réel n'a encore
deux providers.

Usage: python3 PHASE3/test_selection.py
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

RACINE = Path(__file__).parent
sys.path.insert(0, str(RACINE / "slice"))

import plan as PL  # noqa: E402
from intent import Intent, choisir_providers  # noqa: E402
from registre import Registry, RegistryError  # noqa: E402

CAS = []
ECHECS = []


def cas(nom: str, cond: bool, detail: str = ""):
    CAS.append((nom, cond, detail))
    if not cond:
        ECHECS.append(nom)


YAML_DEUX = """\
capabilities:
  - id: CAP_TEST
    description: capacite de test
    domaines: [test]
    entree: [cible]
    sortie: finding/test
    providers:
      - id: alpha
        commande: ["alpha"]
        risque: PASSIVE
        priorite: 50
      - id: beta
        commande: ["beta"]
        risque: PASSIVE
        priorite: 100
      - id: gamma
        commande: ["gamma"]
        risque: INTRUSIVE
        priorite: 10
"""

YAML_EGALITE = """\
capabilities:
  - id: CAP_TEST
    description: capacite de test
    domaines: [test]
    entree: [cible]
    sortie: finding/test
    providers:
      - id: premier
        commande: ["premier"]
        risque: PASSIVE
        priorite: 100
      - id: second
        commande: ["second"]
        risque: PASSIVE
        priorite: 100
"""

YAML_MAUVAIS = YAML_DEUX.replace("priorite: 50", "priorite: vite")


def registre_temp(yaml_text: str) -> Registry:
    f = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8")
    f.write(yaml_text)
    f.close()
    return Registry(f.name)


def main() -> int:
    # 1. La priorité est lue et validée
    r2 = registre_temp(YAML_DEUX)
    cas("1a. priorite lue depuis le YAML",
        r2.provider("alpha").priorite == 50 and r2.provider("beta").priorite == 100)
    try:
        registre_temp(YAML_MAUVAIS)
        cas("1b. priorite non entière refusée", False, "aucune erreur levée")
    except RegistryError as e:
        cas("1b. priorite non entière refusée", "priorite" in str(e), str(e))

    # 2. Arbitrage : la plus petite priorité gagne, INTRUSIVE exclu même prioritaire
    it = Intent("resolved", "teste", capabilities=["CAP_TEST"])
    cas("2a. choisir_providers prend la priorité 50", choisir_providers(it, r2) == ["alpha"],
        str(choisir_providers(it, r2)))
    cas("2b. gamma (INTRUSIVE, priorité 10) reste exclu",
        "gamma" not in choisir_providers(it, r2))

    # 3. Égalité → ordre de déclaration (tri stable, déterministe)
    r_eq = registre_temp(YAML_EGALITE)
    cas("3. égalité tranchée par l'ordre de déclaration",
        choisir_providers(it, r_eq) == ["premier"])

    # 4. Registre réel : motif de sélection tracé dans le plan.
    # MODIFIÉ le 2026-08-29 (étape 4) : IAC_SCAN est passé de un_seul à fan_out
    # (2e provider réel : kics, qualifié par le harnais — GO utilisateur). Le test
    # assertait le motif de l'ANCIEN mode (« seul provider PASSIF », devenu faux) ;
    # il asserte maintenant le motif du mode DÉCLARÉ (fan_out). Même intention —
    # un motif honnête et tracé — aucun contrôle supprimé.
    r_reel = Registry()
    p = PL.construire("analyse l'infrastructure", "/cible", ["checkov", "kics"],
                      r_reel, "test")
    sel = p.to_dict()["selection"]["IAC_SCAN"]
    cas("4a. sélection présente dans plan.to_dict()",
        sel["choisis"] == ["checkov", "kics"] and sel["ecartes"] == [])
    cas("4b. motif honnête : fan_out déclaré", "fan_out déclaré" in sel["motif"], sel["motif"])

    # 5. Multi-provider : motif de priorité + écartés nommés
    p2 = PL.construire("teste", "/cible", ["alpha"], r2, "test")
    sel2 = p2.to_dict()["selection"]["CAP_TEST"]
    cas("5a. écartés nommés avec leur priorité",
        {"id": "beta", "priorite": 100} in sel2["ecartes"], str(sel2["ecartes"]))
    cas("5b. motif de priorité gagnante",
        "priorité déclarée la plus forte" in sel2["motif"] and "beta" in sel2["motif"],
        sel2["motif"])

    # 6. Honnêteté : un choix imposé hors ordre est dit comme tel
    p3 = PL.construire("teste", "/cible", ["beta"], r2, "test")
    sel3 = p3.to_dict()["selection"]["CAP_TEST"]
    cas("6. choix imposé par l'appelant : dit explicitement",
        "imposée par l'appelant" in sel3["motif"] and "alpha" in sel3["motif"], sel3["motif"])

    # 7. Rejeu : depuis_json accepte le plan (version inchangée) et la sélection survit
    lu = PL.depuis_json(p.to_json())
    cas("7a. version de plan inchangée", lu["version"] == PL.VERSION_PLAN)
    # (mêmes providers qu'en 4 — modification du 2026-08-29 : fan_out IAC_SCAN)
    cas("7b. sélection relue",
        lu["selection"]["IAC_SCAN"]["choisis"] == ["checkov", "kics"])

    # 8. L'empreinte du plan ne dépend PAS de la sélection (champ documentaire)
    from dataclasses import replace
    p_sans = replace(p, selection={})
    cas("8. empreinte identique avec ou sans sélection", p.empreinte() == p_sans.empreinte())

    for nom, cond, detail in CAS:
        print(("OK   " if cond else "ECHEC") + f" {nom}" + (f" — {detail}" if detail and not cond else ""))
    print(f"\n{len(CAS) - len(ECHECS)}/{len(CAS)} cas vérifiés")
    return 1 if ECHECS else 0


if __name__ == "__main__":
    sys.exit(main())
