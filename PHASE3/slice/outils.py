"""Registre des Tools — étape 2 de l'architecture gelée (2026-08-29).

Formalise ce qui existait déjà de manière éparse :
    · manifeste_dependances.yaml (versions, sha256, hashs de distribution)
    · BINAIRES_AUTORISES (whitelist, dans provider_manifest)
    · CACHE_BIN (artefacts installés)

Un TOOL est un artefact épinglé (source, version, empreinte, licence). Ce n'est
PAS un provider : plusieurs providers peuvent partager le même tool
(bandit/bandit_custom, semgrep/semgrep_go) — l'installation est unique par tool.

Ce module ne DÉCIDE rien : il expose les faits déclarés au manifeste. La
whitelist reste dans provider_manifest (invariant de sécurité), la vérification
des empreintes reste dans bootstrap.sh.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

MANIFESTE = Path(__file__).resolve().parent.parent / "manifeste_dependances.yaml"


class ToolError(Exception):
    pass


@dataclass(frozen=True)
class Tool:
    id: str
    installation: str          # "binaire" (sha256) | "pip" (hash de distribution)
    version: str
    sha256: str                # "" pour les tools pip — honnêtement absent
    distribution_hash: str     # "" pour les binaires autonomes
    source: str
    licence: str
    role: str                  # "outil" (sert des providers) | "moteur" (ex. OPA)
    note: str


def registre(chemin: Path | None = None) -> dict[str, Tool]:
    """Charge les tools déclarés. Échoue bruyamment si une entrée est incomplète :
    un tool sans licence ou sans source n'est pas traçable."""
    doc = yaml.safe_load((chemin or MANIFESTE).read_text(encoding="utf-8")) or {}
    out: dict[str, Tool] = {}
    for tid, e in (doc.get("binaires") or {}).items():
        pip = (e.get("distribution") == "pip")
        t = Tool(
            id=tid,
            installation="pip" if pip else "binaire",
            version=str(e.get("version") or ""),
            sha256=str(e.get("sha256") or ""),
            distribution_hash=str(e.get("distribution_hash") or ""),
            source=str(e.get("source") or ""),
            licence=str(e.get("licence") or ""),
            role=str(e.get("role") or "outil"),
            note=str(e.get("note") or ""),
        )
        manquants = [k for k in ("version", "source", "licence")
                     if not getattr(t, k)]
        if manquants:
            raise ToolError(f"tool {tid!r} : champs manquants {manquants}")
        if not pip and not t.sha256:
            raise ToolError(f"tool {tid!r} : installation binaire sans sha256")
        if pip and not (t.distribution_hash or t.note):
            raise ToolError(f"tool {tid!r} : installation pip sans empreinte ni note")
        out[tid] = t
    return out


def outil(tid: str) -> Tool:
    t = registre().get(tid)
    if t is None:
        raise ToolError(f"tool inconnu : {tid!r}")
    return t
