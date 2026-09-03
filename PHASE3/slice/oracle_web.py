"""Oracle web : vérification http_response par rejeu + témoin (Stream C).

Une observation DAST ne devient un verdict que par REJEU :
  · N observations indépendantes (N=3 normal, 5 aggressive) ;
  · verdict CONFIRMED ssi N/N concordent (même statut, même digest de corps) ;
  · un TÉMOIN (control_url, page banale 200) doit NE PAS matcher : s'il
    matche aussi, la "preuve" est générique → REFUTED, pas CONFIRMED ;
  · observations en erreur/timeout → INCONCLUSIVE (jamais un verdict) ;
  · observations contradictoires → POTENTIAL + flag contradictory (orthogonal,
    doctrine `oracle.py`).

Transport-agnostique : ce module juge des OBSERVATIONS (données), il ne fait
aucun HTTP. L'exécuteur de rejeu réel arrive avec le runtime Linux.
`RUNTIME_VERIFIED = False` tant qu'aucun rejeu réel n'a été mesuré.

Hygiène secrets : le corps de réponse n'est JAMAIS conservé — seul son
digest sha256 + sa taille (+ présence d'un extrait attendu, booléen).
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from oracle import VerdictStatus

RUNTIME_VERIFIED = False

REPLAY_PAR_INTENSITE = {"normal": 3, "aggressive": 5}


@dataclass(frozen=True)
class DemandeVerification:
    """Ce qu'il faut prouver : recette http_response + témoin."""
    url: str
    expect_status: int = 200
    expect_body_contains: str = ""
    control_url: str = ""
    intensity: str = "normal"

    @property
    def replay_attendus(self) -> int:
        return REPLAY_PAR_INTENSITE.get(self.intensity, 3)


@dataclass(frozen=True)
class ObservationRejeu:
    """UNE exécution de rejeu. Corps = digest + taille, jamais le texte."""
    status: int | None
    body_digest: str
    body_taille: int
    contient_extrait: bool = False
    erreur: str = ""

    @staticmethod
    def depuis_corps(status: int | None, corps: bytes | None,
                     extrait: str = "", erreur: str = "") -> "ObservationRejeu":
        if corps is None:
            return ObservationRejeu(status, "", 0, False, erreur or "sans_corps")
        digest = hashlib.sha256(corps).hexdigest()
        try:
            texte = corps.decode("utf-8", errors="replace")
        except Exception:
            texte = ""
        return ObservationRejeu(status, digest, len(corps),
                                bool(extrait) and extrait in texte, erreur)


@dataclass
class Jugement:
    verdict: VerdictStatus
    replay_reussis: int
    replay_total: int
    temoin_respecte: bool | None
    contradictory: bool = False
    motif: str = ""
    cycle_evenement: str = ""          # événement cycle_vie correspondant
    historique: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"verdict": self.verdict.value, "replay": f"{self.replay_reussis}/{self.replay_total}",
                "temoin_respecte": self.temoin_respecte, "contradictory": self.contradictory,
                "motif": self.motif, "cycle_evenement": self.cycle_evenement,
                "historique": self.historique}


def _concorde(obs: ObservationRejeu, demande: DemandeVerification) -> bool:
    """L'observation matche-t-elle la recette ?"""
    if obs.erreur or obs.status is None:
        return False
    if obs.status != demande.expect_status:
        return False
    if demande.expect_body_contains and not obs.contient_extrait:
        return False
    return True


def juger(demande: DemandeVerification, observations: list[ObservationRejeu],
          temoin: ObservationRejeu | None = None) -> Jugement:
    """Rend un verdict à partir des observations de rejeu + témoin."""
    hist = [{"etape": "demande", "replay_attendus": demande.replay_attendus,
             "observations_recues": len(observations)}]
    if len(observations) < demande.replay_attendus:
        return Jugement(VerdictStatus.INCONCLUSIVE, 0, demande.replay_attendus, None,
                        False, f"rejeu_incomplet : {len(observations)}/{demande.replay_attendus}",
                        "", hist + [{"etape": "rejet", "motif": "rejeu_incomplet"}])
    if any(o.erreur or o.status is None for o in observations):
        return Jugement(VerdictStatus.INCONCLUSIVE, 0, demande.replay_attendus, None,
                        False, "rejeu_en_erreur : un rejeu sans réponse n'est pas une preuve",
                        "", hist + [{"etape": "rejet", "motif": "rejeu_en_erreur"}])
    reussis = sum(1 for o in observations if _concorde(o, demande))
    digests = {o.body_digest for o in observations}
    contradictoire = len(digests) > 1
    hist.append({"etape": "rejeu", "reussis": reussis, "digests_distincts": len(digests)})
    temoin_ok = None
    if temoin is not None and demande.control_url:
        temoin_ok = not _concorde(temoin, demande)
        hist.append({"etape": "temoin", "respecte": temoin_ok})
        if not temoin_ok:
            return Jugement(VerdictStatus.REFUTED, reussis, demande.replay_attendus, False,
                            contradictoire, "temoin_matche : la preuve est générique, pas une faille",
                            "rejeter", hist + [{"etape": "verdict", "verdict": "refuted"}])
    if reussis == demande.replay_attendus and not contradictoire:
        return Jugement(VerdictStatus.CONFIRMED, reussis, demande.replay_attendus, temoin_ok,
                        False, f"rejeu_{reussis}/{demande.replay_attendus}_concordant",
                        "verifier_ok", hist + [{"etape": "verdict", "verdict": "confirmed"}])
    if reussis == 0:
        return Jugement(VerdictStatus.REFUTED, 0, demande.replay_attendus, temoin_ok,
                        contradictoire, "aucun_rejeu_concordant",
                        "rejeter", hist + [{"etape": "verdict", "verdict": "refuted"}])
    return Jugement(VerdictStatus.POTENTIAL, reussis, demande.replay_attendus, temoin_ok,
                    contradictoire, f"rejeu_partiel_{reussis}/{demande.replay_attendus}",
                    "", hist + [{"etape": "verdict", "verdict": "potential"}])
