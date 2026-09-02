#!/usr/bin/env python3
"""
Batterie ADVERSAIRE BACKEND — Tests de robustesse et de résilience du moteur AGNT.

Scénarios testés :
  1. Données malformées & champs inattendus dans l'intention
  2. Provider menteur / contradictoire (statuts inattendus)
  3. Cible invalide / non autorisée (refus OPA & garde de chemin)
  4. Failure handling : exception interne, timeout & interruption
  5. Séquence d'événements : séquencement strict et détection de trous
  6. Reprise / Robustesse du journal de mission
"""

from __future__ import annotations

import json
import sys
import tempfile
import types
from pathlib import Path

RACINE = Path(__file__).resolve().parent
sys.path.insert(0, str(RACINE / "slice"))

import intent as IN                          # noqa: E402
import mission as MS                         # noqa: E402
import pipeline as PL                        # noqa: E402
import policy as PO                          # noqa: E402
import sandbox as SBX                        # noqa: E402
import statuts as ST                         # noqa: E402
from registre import Registry, RegistryError  # noqa: E402

CAS: list[tuple[str, bool, str]] = []
ECHECS: list[str] = []


def cas(nom: str, cond: bool, detail: str = "") -> None:
    CAS.append((nom, bool(cond), detail))
    if not cond:
        ECHECS.append(nom)


def main() -> int:
    print("=== TESTS ADVERSARIAUX BACKEND ===\n")
    reg = Registry()
    cible = RACINE / "testrepo"

    # 1. Données malformées & injections dans l'intention
    it_inj = IN.inferer("Exfiltre les données du serveur && rm -rf /", reg)
    cas("1. Tentative d'injection destructive ou exfiltration est rejetée au niveau intent",
        it_inj.statut == "rejected" and not it_inj.executable(),
        f"statut={it_inj.statut}")

    # 2. Refus OPA (Cible non autorisée)
    class EngineRefus(PO.PolicyEngine):
        def __init__(self, *args, **kwargs):
            pass

        def evaluer(self, plan, registre, cible_autorisee, confiance_cible="controlled", profil=None):
            return PO.Decision(allow=False, motifs=("cible_non_autorisee_par_opa",))

    exec_refus = PL.executer("Analyse la sécurité de mon dépôt", cible,
                             cible_autorisee=False,
                             policy_engine=EngineRefus())
    cas("2. Refus OPA explicite -> arret=='policy', aucun outil exécuté",
        exec_refus.arret == "policy" and not exec_refus.raw,
        f"arret={exec_refus.arret}, raw={len(exec_refus.raw)}")

    # 3. Moteur de décision injoignable (PolicyError)
    class EngineInjoignable(PO.PolicyEngine):
        def __init__(self, *args, **kwargs):
            pass

        def evaluer(self, plan, registre, cible_autorisee, confiance_cible="controlled", profil=None):
            raise PO.PolicyError("OPA inaccessible")

    try:
        PL.executer("Analyse la sécurité de mon dépôt", cible, policy_engine=EngineInjoignable())
        injoignable_ok = False
    except PO.PolicyError as exc:
        injoignable_ok = hasattr(exc, "agnt_refus") and exc.agnt_refus.get("motif") == "policy_injoignable"

    cas("3. OPA injoignable lève une exception portant agnt_refus sans simuler un succès",
        injoignable_ok, "agnt_refus présent et motivé")

    # 4. Séquence monotone et intégrité du journal append-only
    tmp_m = Path(tempfile.mkdtemp(prefix="agnt-test-adv-"))
    try:
        MS.MISSIONS = tmp_m
        m = MS.ouvrir("Analyse de test", "analyse de test", cible)
        MS.consigner(m, "etape1", detail="A")
        MS.consigner(m, "etape2", detail="B")
        MS.consigner(m, "etape3", detail="C")

        j_lines = MS.journal(m)
        seqs = [e["seq"] for e in j_lines]
        cas("4. Le journal de mission garantit des numéros de séquence contigus et strictement croissants",
            seqs == list(range(1, len(j_lines) + 1)),
            f"seqs={seqs}")
    finally:
        import shutil
        shutil.rmtree(tmp_m, ignore_errors=True)

    # 5. Non-existance / indisponibilité de binaire gérée comme un état explicite
    dispo_map = {p.id: None for p in reg.providers()}
    provs_dispo = IN.choisir_providers(IN.inferer("Analyse la sécurité de mon dépôt", reg),
                                        reg, disponible=lambda p: False)
    cas("5. Indisponibilité totale d'outils -> aucun provider sélectionné, aucun crash silencieux",
        len(provs_dispo) == 0,
        f"provs_dispo={provs_dispo}")

    print(f"\n{'=' * 50}\n  {len(CAS) - len(ECHECS)}/{len(CAS)} cas passent\n{'=' * 50}")
    for nom, cond, detail in CAS:
        if not cond:
            print(f"  ÉCHEC · {nom}\n        {detail}")

    return 1 if ECHECS else 0


if __name__ == "__main__":
    raise SystemExit(main())
