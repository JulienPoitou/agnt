"""Policy engine — OPA décide, Python applique.

Aucune règle de sécurité ne vit dans ce fichier : il construit l'entrée, appelle OPA,
et transmet la décision. Si une règle devait être ajoutée, ce serait dans policy.rego.

C'est ce qui rend la frontière déterministe : la décision est reproductible sans LLM,
et testable sans exécuter le moindre outil.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import profils

POLICY_DIR = Path(__file__).resolve().parent.parent / "policy"
POLICY_FILE = POLICY_DIR / "policy.rego"
QUERY = "data.plateforme.autorisation.decision"


class PolicyError(Exception):
    """OPA n'a pas pu répondre. On refuse : l'absence de décision n'est pas une autorisation."""


@dataclass(frozen=True)
class Decision:
    allow: bool
    motifs: tuple[str, ...] = field(default_factory=tuple)
    brut: str = ""


class PolicyEngine:
    def __init__(self, opa: Path, policy: Path = POLICY_FILE, timeout: int = 30) -> None:
        self.opa = Path(opa)
        self.policy = Path(policy)
        self.timeout = timeout
        if not self.opa.exists():
            raise PolicyError(f"binaire OPA introuvable : {self.opa}")
        if not self.policy.exists():
            raise PolicyError(f"politique introuvable : {self.policy}")

    # ------------------------------------------------------------------ entrée
    @staticmethod
    def entree(plan, registre, cible_autorisee: bool,
               confiance_cible: str = "controlled", profil: dict | None = None) -> dict:
        """Construit l'entrée d'OPA.

        `capability_ids` et non `capabilities` : OPA ignore un champ d'entrée nommé
        `capabilities` (piège vérifié, documenté dans policy.rego).
        """
        return {
            "plan": {
                "steps": [s.to_dict() for s in plan.steps],
                "registre_empreinte": plan.registre_empreinte,
            },
            "registre": {
                "providers": [p.id for p in registre.providers()],
                "capability_ids": [c.id for c in registre.capabilities()],
                "capabilities_detail": [
                    {"id": c.id, "providers": [p.id for p in c.providers]}
                    for c in registre.capabilities()
                ],
                # OPA reçoit une vue déclarative des providers, pas leurs commandes
                # ni leurs secrets. Cette information permet à la policy de vérifier
                # qu'un binding MCP (serveur + outil + transport) est bien celui du
                # registre, au lieu de faire confiance au plan seul.
                "providers_detail": [
                    {
                        "id": p.id,
                        "capability": p.capability,
                        "transport": p.transport,
                        "identity": p.identity.to_dict(),
                        "target_types": list(p.target_types),
                        "risk": p.risque,
                    }
                    for p in registre.providers()
                ],
                "empreinte": registre.empreinte(),
            },
            "cible": {"autorisee": cible_autorisee, "confiance": confiance_cible,
                      # Additif (2026-08-30) : le descripteur STRUCTURÉ de la cible,
                      # à côté des champs historiques qu'OPA compare déjà. Les règles
                      # actuelles ne lisent que `autorisee`/`confiance` — ces deux clés
                      # ne cassent donc rien — et une règle future pourra décider sur
                      # `type`/`local` (cible distante = pas de sous-processus local)
                      # sans changer le schéma. `getattr` : `entree()` peut recevoir un
                      # plan antérieur sans descripteur.
                      "type": (getattr(plan, "cible_descr", None) or {}).get("type"),
                      "local": (getattr(plan, "cible_descr", None) or {}).get("local")},
            # Le moteur DÉCLARE ce qu'il sait faire ; OPA DÉCIDE. Si cette déclaration
            # ment, la garde ne vaut rien — d'où le test dédié.
            # Le profil vient de profils.py, pas d'un dictionnaire improvisé ici.
            "profil_sandbox": profil or profils.actif().to_dict(),
        }

    # ------------------------------------------------------------------ décision
    def evaluer(self, plan, registre, cible_autorisee: bool,
                confiance_cible: str = "controlled", profil: dict | None = None) -> Decision:
        doc = self.entree(plan, registre, cible_autorisee, confiance_cible, profil)
        cmd = [
            str(self.opa), "eval",
            "-d", str(self.policy),
            "-I",                                   # entrée sur stdin
            "--stdin-input",
            "-f", "raw",
            QUERY,
        ]
        try:
            r = subprocess.run(cmd, input=json.dumps(doc), capture_output=True,
                               text=True, timeout=self.timeout)
        except subprocess.TimeoutExpired as e:
            raise PolicyError(f"OPA a dépassé {self.timeout}s") from e

        if r.returncode != 0:
            # Une politique qui ne compile pas ne doit JAMAIS valoir autorisation.
            raise PolicyError(f"OPA en erreur (code {r.returncode}) : {r.stderr.strip()[:400]}")

        sortie = (r.stdout or "").strip()
        if not sortie:
            raise PolicyError("OPA n'a rendu aucune décision")
        try:
            d = json.loads(sortie.splitlines()[-1])
        except json.JSONDecodeError as e:
            raise PolicyError(f"sortie d'OPA illisible : {sortie[:200]}") from e

        return Decision(
            allow=bool(d.get("allow")),
            motifs=tuple(sorted(d.get("motifs") or [])),
            brut=sortie,
        )

