#!/usr/bin/env python3
"""
Harnais de qualification des providers — étape 4 (2026-08-29).

Ce que c'est : le point d'entrée UNIQUE qui transforme un candidat du pool en
PREUVES de qualification. Il ne décide JAMAIS qu'un outil est bon : il produit
un dossier (artefact brut, méta d'exécution, stabilité, ATTENDUS) que des
humains approuvent — l'approbation et la whitelist restent manuelles
(invariants gelés).

Ce qu'il fait, et rien d'autre :
    · exécute le candidat DANS LA SANDBOX (la preuve qui compte : l'outil tourne
      sous bwrap, sans réseau, avec les montages réels) ;
    · enregistre la sortie brute + méta (version, empreinte du binaire, code de
      retour, durée, limites appliquées) ;
    · mesure la stabilité de sortie (deux exécutions, comparaison octet à octet —
      une sortie instable est une INFORMATION, pas un échec) ;
    · génère ATTENDUS.yaml depuis l'artefact + la spec d'extraction proposée.

Usage (bibliothèque) : voir harnais_grype_kics.py, qui qualifie les deux premiers
providers du pool.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import time
from dataclasses import asdict
from pathlib import Path

import yaml

RACINE = Path(__file__).parent
sys.path.insert(0, str(RACINE / "slice"))

import provider_manifest as PM  # noqa: E402
from sandbox import Sandbox  # noqa: E402

CACHE_BIN = Path.home() / ".cache" / "arena_secops" / "bin"
CACHE_REGLES = Path.home() / ".cache" / "arena_secops" / "rules"
CACHE_DB = Path.home() / ".cache" / "arena_secops" / "trivy-cache"


def _sandbox(cible: Path, sortie: Path, timeout: int = 600) -> Sandbox:
    return Sandbox(
        bwrap="bwrap",
        racine_scan=cible,
        racine_regles=CACHE_REGLES,
        racine_db=CACHE_DB,
        sortie=sortie,
        gitconfig=RACINE / "gitconfig",
        timeout=timeout,
    )


def _resoudre(argv: list[str], binaire: str) -> list[str]:
    """Mêmes placeholders que le runtime (BIN/TARGET/OUT/REGLES/DB) — le harnais
    exécute comme le runtime exécutera, sinon la preuve ne vaut rien."""
    bin_path = str(CACHE_BIN / binaire) if (CACHE_BIN / binaire).exists() else binaire
    return [a.replace("{BIN}", bin_path) for a in argv]


def capturer(tool_id: str, binaire: str, argv: list[str], cible: Path,
             repertoire_captures: Path, timeout: int = 600,
             env: dict | None = None) -> dict:
    """Exécute dans la sandbox, enregistre artefact brut + méta. Retourne le méta."""
    repertoire_captures.mkdir(parents=True, exist_ok=True)
    sortie = RACINE / "run"
    sortie.mkdir(parents=True, exist_ok=True)
    for f in sortie.iterdir():          # le harnais possède ce répertoire : on le vide
        if f.is_file():
            f.unlink()
    sbx = _sandbox(cible, sortie, timeout=timeout)
    problemes = sbx.verifie()
    if problemes:
        raise RuntimeError(f"sandbox invalide : {problemes}")

    argv_resolu = _resoudre(argv, binaire)
    # Les jetons TARGET/OUT/REGLES/DB sont résolus comme dans l'adapter générique.
    # Aligné sur adapters.generique_cli : {OUT} est le FICHIER de sortie attendu,
    # {OUT_DIR} le répertoire. Le harnais exécute comme le runtime exécutera.
    argv_resolu = [a.replace("{TARGET}", Sandbox.M_SCAN)
                    .replace("{OUT_DIR}", Sandbox.M_OUT)
                    .replace("{OUT}", f"{Sandbox.M_OUT}/{tool_id}.json")
                    .replace("{REGLES}", Sandbox.M_REGLES)
                    .replace("{DB}", Sandbox.M_DB)
                   for a in argv_resolu]
    t0 = time.monotonic()
    r = sbx.exec(argv_resolu, env=env)
    duree_ms = int((time.monotonic() - t0) * 1000)

    # Sortie : fichier écrit dans le montage de sortie, sinon stdout.
    donnees, origine = None, ""
    candidats = sorted(sortie.glob(f"*{tool_id}*")) + sorted(sortie.glob("*.json"))
    for f in candidats:
        try:
            donnees = json.loads(f.read_text(encoding="utf-8"))
            origine = f"fichier:{f.name}"
            break
        except Exception:
            continue
    if donnees is None and r.stdout:
        try:
            donnees = json.loads(r.stdout)
            origine = "stdout"
        except Exception:
            donnees = None
    if donnees is None:
        raise RuntimeError(
            f"{tool_id} : aucune sortie JSON exploitable (code={r.code}, "
            f"stderr={r.stderr[-300:]!r})")

    binaire_chemin = CACHE_BIN / binaire
    meta = {
        "tool": tool_id,
        "binaire": binaire,
        "version_binaire_sha256": (hashlib.sha256(binaire_chemin.read_bytes()).hexdigest()
                                   if binaire_chemin.exists() else "binaire hors cache"),
        "argv": argv_resolu,
        "env": env or {},
        "code_retour": r.code,
        "timeout": r.timeout,
        "duree_ms": duree_ms,
        "sortie_origine": origine,
        "cible": str(cible),
        "sandbox_limites": sbx.limites_appliquees(),
        "stderr_extrait": (r.stderr or "")[-400:],
    }
    (repertoire_captures / f"{tool_id}.json").write_text(
        json.dumps(donnees, ensure_ascii=False, indent=2), encoding="utf-8")
    (repertoire_captures / f"{tool_id}.meta.yaml").write_text(
        yaml.safe_dump(meta, allow_unicode=True, sort_keys=False), encoding="utf-8")
    meta["_donnees"] = donnees
    return meta


def stabilite(tool_id: str, binaire: str, argv: list[str], cible: Path,
              repertoire_captures: Path, env: dict | None = None,
              normaliser=None) -> dict:
    """Deuxième exécution : la sortie est-elle octet pour octet identique ?
    Réponse honnête dans le dossier (les horodatages rendent souvent la réponse
    « non » — c'est une information pour l'extraction, pas un échec).

    `normaliser` (optionnel) : callable(artefact_json) -> objet comparable. S'il est
    fourni, on mesure AUSSI la stabilité du CONTENU normalisé (findings triés par
    clé), qui est ce qui compte pour les ATTENDUS. Mesuré sur kics 2.1.20 : les
    horodatages et l'ordre d'énumération (maps Go) varient entre deux exécutions ;
    l'ensemble des détections, non."""
    avant = (repertoire_captures / f"{tool_id}.json").read_bytes()
    seconde = capturer(tool_id, binaire, argv, cible,
                       repertoire_captures.parent / "_stabilite", env=env)
    apres = (repertoire_captures.parent / "_stabilite" / f"{tool_id}.json").read_bytes()
    stable = avant == apres
    resultat = {"identique_octet_pour_octet": stable,
                "taille_1": len(avant), "taille_2": len(apres)}
    if normaliser is not None:
        import json as _json
        resultat["identique_contenu_normalise"] = (
            normaliser(_json.loads(avant)) == normaliser(_json.loads(apres)))
    # Restaure l'artefact de référence (la 2e exécution ne doit pas l'écraser).
    (repertoire_captures / f"{tool_id}.json").write_bytes(avant)
    return resultat


def generer_attendus(chemin: Path, doc: dict) -> None:
    chemin.write_text(yaml.safe_dump(doc, allow_unicode=True, sort_keys=False,
                                     width=100), encoding="utf-8")


def dossier(chemin: Path, contenu: dict) -> None:
    chemin.write_text(yaml.safe_dump(contenu, allow_unicode=True, sort_keys=False,
                                     width=100), encoding="utf-8")
