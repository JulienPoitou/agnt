"""Gouvernance MCP : classification du risque + audit sans secrets (Stream G).

Complète (sans dupliquer) la garde existante (`mcp_provider.py` valide le
contrat, `test_mcp_policy_gate.py` prouve l'ordre policy-avant-transport) :
  · `classifier` : niveau déclaré + signaux aggravants (egress, endpoint
    distant, privilèges) + approbation humaine requise ou non ;
  · `auditer` : journal append-only des décisions (autorise/refuse) avec
    digest des arguments — JAMAIS les valeurs (un token d'outil n'a rien à
    faire dans un journal).
"""
from __future__ import annotations

import hashlib
import json
import time

NIVEAUX = ("PASSIVE", "ACTIVE", "EXPLOIT")


def _champ(manifest, nom: str, defaut=""):
    if isinstance(manifest, dict):
        return manifest.get(nom, defaut)
    return getattr(manifest, nom, defaut)


def classifier(manifest) -> dict:
    """Risque déclaré + signaux. Ne devine pas : signaux listés, niveau déclaré."""
    risque = str(_champ(manifest, "risque", "PASSIVE") or "PASSIVE").upper()
    signaux = []
    if risque not in NIVEAUX:
        # Fail-closed : un risque non déclaré est traité comme ACTIVE et
        # signalé — jamais rétrogradé en silence vers PASSIVE.
        signaux.append("risque_inconnu")
        risque = "ACTIVE"
    if bool(_champ(manifest, "reseau", False)):
        signaux.append("egress_requis")
    endpoint = str(_champ(manifest, "endpoint", "") or "")
    if endpoint and not any(h in endpoint for h in ("127.0.0.1", "localhost", "::1")):
        signaux.append("endpoint_distant")
    if str(_champ(manifest, "privileges", "aucun") or "aucun") != "aucun":
        signaux.append("privileges_eleves")
    transport = str(_champ(manifest, "transport", "") or "")
    if transport and transport != "stdio":
        signaux.append(f"transport_{transport}")
    exige_approbation = risque in ("ACTIVE", "EXPLOIT") or "endpoint_distant" in signaux
    return {"niveau": risque, "signaux": signaux,
            "exige_egress": "egress_requis" in signaux,
            "exige_approbation": exige_approbation}


def empreinte_args(args) -> str:
    """Digest stable des arguments (noms + valeurs hashées, jamais persistées)."""
    canonique = json.dumps(args, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False, default=str)
    return hashlib.sha256(canonique.encode("utf-8")).hexdigest()


def auditer(decision: str, outil: str, motifs, args=None, journal=None) -> dict:
    """Journalise une décision d'appel d'outil MCP. `decision` ∈ {autorise, refuse}."""
    if decision not in ("autorise", "refuse"):
        raise ValueError(f"décision inconnue : {decision!r}")
    if not outil or not isinstance(outil, str):
        raise ValueError("outil nommé exigé")
    entree = {"t": round(time.time(), 3), "decision": decision, "outil": outil,
              "motifs": list(motifs or []),
              "args_digest": empreinte_args(args) if args is not None else None}
    if journal is not None:
        from pathlib import Path
        p = Path(journal)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entree, ensure_ascii=False) + "\n")
    return entree
