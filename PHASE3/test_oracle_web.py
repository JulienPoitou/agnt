#!/usr/bin/env python3
"""Oracle web : N/N, témoin, partiels, erreurs, mapping cycle (fixtures).

Usage : python PHASE3/test_oracle_web.py
"""
from __future__ import annotations

import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parent
sys.path.insert(0, str(RACINE / "slice"))

from cycle_vie import transition                                      # noqa: E402
from oracle import VerdictStatus                                       # noqa: E402
from oracle_web import (DemandeVerification, ObservationRejeu,        # noqa: E402
                        RUNTIME_VERIFIED, juger)

CAS: list[tuple[str, bool, str]] = []
ECHECS: list[str] = []


def cas(nom: str, cond: bool, detail: str = "") -> None:
    CAS.append((nom, bool(cond), detail))
    if not cond:
        ECHECS.append(nom)


def obs(status=200, corps=b"ok admin", extrait="admin", erreur=""):
    return ObservationRejeu.depuis_corps(status, corps, extrait, erreur)


def main() -> int:
    cas("runtime NON vérifié déclaré", RUNTIME_VERIFIED is False)
    d = DemandeVerification(url="https://t/x", expect_status=200,
                            expect_body_contains="admin", control_url="https://t/")
    temoin_ok = ObservationRejeu.depuis_corps(200, b"page banale")
    j = juger(d, [obs(), obs(), obs()], temoin_ok)
    cas("3/3 + témoin propre → CONFIRMED + verifier_ok",
        j.verdict == VerdictStatus.CONFIRMED and j.cycle_evenement == "verifier_ok"
        and j.replay_reussis == 3 and j.temoin_respecte is True, j.motif)
    cas("verdict mappé au cycle sans saut",
        transition("candidate", j.cycle_evenement) == "verified")
    a = DemandeVerification(url="https://t/x", intensity="aggressive")
    j = juger(a, [ObservationRejeu.depuis_corps(200, b"x") for _ in range(5)], None)
    cas("5/5 agressif sans témoin → CONFIRMED, temoin None (pas inventé)",
        j.verdict == VerdictStatus.CONFIRMED and j.temoin_respecte is None, j.motif)
    j = juger(d, [obs(), obs(), obs()],
              ObservationRejeu.depuis_corps(200, b"ok admin", "admin"))
    cas("témoin qui matche → REFUTED + rejeter (preuve générique)",
        j.verdict == VerdictStatus.REFUTED and j.cycle_evenement == "rejeter"
        and j.temoin_respecte is False, j.motif)
    j = juger(d, [obs(), obs(), ObservationRejeu.depuis_corps(404, b"rien")], temoin_ok)
    cas("2/3 → POTENTIAL, pas de verdict cycle (ni ok ni ko)",
        j.verdict == VerdictStatus.POTENTIAL and j.cycle_evenement == ""
        and j.replay_reussis == 2, j.motif)
    j = juger(d, [ObservationRejeu.depuis_corps(404, b"a") for _ in range(3)], temoin_ok)
    cas("0/3 → REFUTED", j.verdict == VerdictStatus.REFUTED
        and j.cycle_evenement == "rejeter", j.motif)
    j = juger(d, [obs(corps=b"ok admin"), obs(corps=b"ok admin!"), obs()], temoin_ok)
    cas("digests distincts → flag contradictory (orthogonal)",
        j.contradictory is True and j.verdict == VerdictStatus.POTENTIAL, j.motif)
    j = juger(d, [obs(), obs()], temoin_ok)
    cas("rejeu incomplet → INCONCLUSIVE",
        j.verdict == VerdictStatus.INCONCLUSIVE and j.cycle_evenement == "", j.motif)
    j = juger(d, [obs(), obs(erreur="timeout", corps=None, status=None), obs()], temoin_ok)
    cas("rejeu en erreur → INCONCLUSIVE (jamais un verdict)",
        j.verdict == VerdictStatus.INCONCLUSIVE, j.motif)
    j = juger(d, [obs(status=500), obs(status=500), obs(status=500)], temoin_ok)
    cas("statut inattendu partout → REFUTED", j.verdict == VerdictStatus.REFUTED
        and j.cycle_evenement == "rejeter", j.motif)
    import dataclasses
    champs = {f.name for f in dataclasses.fields(obs())}
    cas("corps jamais conservé (digest seul, aucun champ brut)",
        champs == {"status", "body_digest", "body_taille", "contient_extrait", "erreur"}
        and len(obs().body_digest) == 64, sorted(champs))
    md = juger(d, [obs(), obs(), obs()], temoin_ok).to_dict()
    cas("jugement sérialisable (verdict, replay, historique)",
        md["verdict"] == "confirmed" and md["replay"] == "3/3"
        and isinstance(md["historique"], list) and len(md["historique"]) >= 3)

    print(f"\n{'=' * 50}\n  {len(CAS) - len(ECHECS)}/{len(CAS)} cas passent\n{'=' * 50}")
    for nom, cond, detail in CAS:
        if not cond:
            print(f"  ÉCHEC · {nom}\n        {detail}")
    return 1 if ECHECS else 0


if __name__ == "__main__":
    sys.exit(main())
