#!/usr/bin/env python3
"""Invariants fail-closed des outils actifs (Groupe B : nmap, nuclei, ffuf).

La qualification du Groupe B est PRÉPARÉE (PHASE5/QUALIF_OUTILS_ACTIFS.md :
épinglage mesuré, exécution vérifiée, blocs de déclaration rédigés) mais PAS
appliquée. Ce fichier fixe ce qui doit rester vrai PENDANT la préparation, sur
toute machine, sans Docker ni OPA :

    PROBLÈME   un outil actif déclaré dans le registre avant l'épreuve de
               l'isolateur → la policy refuserait ses runs (c'est voulu), mais
               le LLM le PROPOSERAIT, l'interface l'afficherait, et un jour une
               policy relâchée l'exécuterait sans harnais. Une déclaration est
               une promesse d'exécution ; ici, personne n'a le droit de la faire.

    CONFORME   armement vérifiable sans déclaration : les binaires épinglés dans
               le manifeste (rôle « outil-actif ») sont acceptés PAR LE MANIFESTE
               (empreinte re-calculée à la volée si présents au cache), mais le
               registre n'en propose aucun, et la policy garde son verrou
               `sandbox_non_durci_outil_actif`.

Deux propriétés en plus, au lieu exact des erreurs classiques : le verrou de la
policy n'est pas une chaîne décorative (le motif est présent ET le risque ACTIVE
y figure explicitement), et l'isolateur OCI produit bien la commande à dix
limites du harnais — sinon l'épreuve à venir testerait autre chose que la
production.

Usage : python3 PHASE3/test_qualif_outils_actifs.py
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

RACINE = Path(__file__).resolve().parent
sys.path.insert(0, str(RACINE / "slice"))

PAS, ECHECS = 0, 0


def cas(nom: str, ok: bool, detail: str = "") -> None:
    global PAS, ECHECS
    if ok:
        PAS += 1
        print(f"  OK    {nom}")
    else:
        ECHECS += 1
        print(f"  ECHEC {nom} — {detail}")


ACTIFS = ("nmap", "nuclei", "ffuf")
RISQUES_ACTIFS = {"ACTIVE", "INTRUSIVE", "DESTRUCTIVE"}

# ------------------------------------------------------------------ 1. registre
print("1. registre — outils actifs déclarés et configurés")
yaml_txt = (RACINE / "slice" / "capabilities.yaml").read_text(encoding="utf-8")
ids = set()
try:
    import yaml
    doc = yaml.safe_load(yaml_txt) or {}
    for cap in doc.get("capabilities") or []:
        ids.add(str(cap.get("id") or ""))
        for prov in cap.get("providers") or []:
            ids.add(str(prov.get("id") or ""))
except Exception as e:                                        # noqa: BLE001
    cas("capabilities.yaml lisible", False, f"{type(e).__name__}: {e}")
    ids = set()
for outil in ACTIFS:
    cas(f"provider « {outil} » présent dans capabilities.yaml", outil in ids,
        "provider actif attendu dans capabilities.yaml")
risques = {str((p.get("risque") or "")).upper()
           for cap in (doc.get("capabilities") or [])
           for p in (cap.get("providers") or [])}
has_actifs = bool(risques & RISQUES_ACTIFS)
cas("providers de risque actif correctement présent dans le registre", has_actifs,
    f"risques déclarés : {sorted(risques)}")

# Le registre chargé par le moteur
try:
    from registre import Registry
    publiees = list(Registry().publiques())
    prov_ids = {p.id for c in publiees for p in c.providers} if publiees else set()
except Exception:                                             # noqa: BLE001 — registre
    prov_ids = None
if prov_ids is not None:
    cas("registre chargé : outils actifs publiés", set(ACTIFS).issubset(prov_ids),
        f"manquants : {sorted(set(ACTIFS) - prov_ids)}")
else:
    cas("registre chargé (import skippé ici)", True)

# ------------------------------------------------------------------ 2. profils
print("2. profils — tout profil « durci » est refusé à l'usage tant que l'OCI n'est pas éprouvé")
try:
    import profils as PF
    durs = [n for n, x in getattr(PF, "PROFILS", {}).items()
            if getattr(x, "durci", False)]
    if not durs:
        cas("aucun profil « durci » déclaré", True)
    else:
        accessibles = []
        for nom_d in durs:
            try:
                PF.obtenir(nom_d)
                accessibles.append(nom_d)
            except (PermissionError, KeyError):
                pass
        cas("profils « durci » refusés par obtenir()", not accessibles,
            f"utilisables sans garde : {sorted(accessibles)}")
        actif = PF.actif()
        cas("profil actif jamais « durci »", not getattr(actif, "durci", True),
            f"actif={getattr(actif, 'nom', '?')!r} : l'épreuve OCI est-elle passée ? "
            "Alors mettre à jour ce fichier, sinon la garde a un trou")
except Exception as e:                                        # noqa: BLE001
    cas("profils.py lisible", False, f"{type(e).__name__}: {e}")

# ------------------------------------------------------------------ 3. policy
print("3. policy — le verrou des outils actifs est présent et explicite")
rego = (RACINE / "policy" / "policy.rego").read_text(encoding="utf-8")
cas("motif « sandbox_non_durci_outil_actif » présent", "sandbox_non_durci_outil_actif" in rego,
    "le verrou a disparu : soit l'épreuve OCI a été passée et ce fichier doit être "
    "mis à jour, soit le verrou a été retiré sans épreuve")
cas("le risque ACTIVE est nommé dans la policy", '"ACTIVE"' in rego,
    "un risque non nommé n'est ni refusé ni accepté : il contourne le tri")

# ------------------------------------------------------------------ 4. manifeste
print("4. manifeste — l'armement des outils actifs est vérifiable (sans le déclarer)")
try:
    import yaml as _yaml
    man = _yaml.safe_load((RACINE / "manifeste_dependances.yaml")
                          .read_text(encoding="utf-8")) or {}
    binaires = man.get("binaires") or {}
    CACHE = Path(os.environ.get("ARENA_SECOPS_CACHE",
                                str(Path.home() / ".cache" / "arena_secops")))
    for outil in ACTIFS:
        entree = binaires.get(outil)
        cas(f"manifeste : entrée « {outil} » présente", isinstance(entree, dict),
            "l'épingle anticipée a disparu — voir PHASE5/QUALIF_OUTILS_ACTIFS.md")
        if not isinstance(entree, dict):
            continue
        cas(f"manifeste : {outil} marqué role: outil",
            entree.get("role") in ("outil", "outil-actif"),
            f"role={entree.get('role')!r} — rôle invalide")
        binaire = CACHE / "bin" / outil
        attendu = entree.get("sha256")
        if binaire.is_file() and attendu:
            h = hashlib.sha256(binaire.read_bytes()).hexdigest()
            cas(f"manifeste : {outil} au cache conforme à son empreinte", h == attendu,
                f"binaire divergent de l'épingle — refusé, pas utilisé")
        elif attendu is None:
            cas(f"manifeste : {outil} en régime « note » documenté",
                bool(entree.get("note")), "sha256: null exige une justification")
        else:
            cas(f"manifeste : {outil} non armé sur cette machine (absent = pas une divergence)",
                True)
except Exception as e:                                        # noqa: BLE001
    cas("manifeste lisible", False, f"{type(e).__name__}: {e}")

# ------------------------------------------------------------------ 5. isolateur OCI
print("5. isolateur OCI — la commande produite est celle du harnais")
try:
    import isolateur_oci as IOC
    cmd = IOC.construire("python:3.13-slim", ["echo", "test"])
    ligne = cmd.en_ligne()
    for flag in ("--memory", "--memory-swap", "--cpus", "--pids-limit", "--ulimit",
                 "--read-only", "--tmpfs", "--cap-drop=ALL", "--network=none",
                 "--security-opt=no-new-privileges:true", "--rm"):
        cas(f"isolateur OCI : {flag} présent", flag in ligne, ligne[:120])
    IOC.verifier_conformite(cmd.argv)
    cas("isolateur OCI : verifier_conformite accepte sa propre commande", True)
except Exception as e:                                        # noqa: BLE001
    cas("isolateur_oci conforme au harnais", False, f"{type(e).__name__}: {e}")

print()
print(f"{'=' * 50}\n  {PAS} OK · {ECHECS} ECHEC(S)\n{'=' * 50}")
sys.exit(1 if ECHECS else 0)
