#!/usr/bin/env python3
"""Outil jetable — extrait les 5 parties PROJET_MANQUANTS et vérifie les empreintes.

Règles :
  · ancrage : en-têtes « ## FICHIER : `chemin` » HORS bloc, clôtures extérieures ```` ;
  · machine à états : un « ## FICHIER » ou une clôture à l'intérieur d'un bloc ````
    est du contenu, pas une structure ;
  · vérification : SHA-256 du contenu normalisé (CRLF→LF, exactement un saut de
    ligne final) contre la table d'empreintes de chaque partie — AVANT toute
    écriture dans l'arbre ;
  · collision : un fichier déjà présent et DIFFÉRENT n'est jamais écrasé en
    silence — il est signalé.
"""
import hashlib
import re
import sys
from pathlib import Path

UPLOADS = Path("/home/user/uploads")
RACINE = Path("/home/user")
STAGING = Path("/tmp/manquants")

HEADER = re.compile(r"^## FICHIER : `([^`]+)`\s*$")
# ouverture : 4+ backticks avec étiquette de langage possible (````python) ;
# fermeture : 4+ backticks nus. Le contenu interne n'utilise que ``` (3).
FENCE_OPEN = re.compile(r"^`{4,}[^`\s]*\s*$")
FENCE_CLOSE = re.compile(r"^`{4,}\s*$")
SHA_ROW = re.compile(r"^\|\s*`([^`]+)`\s*\|\s*([\d\s]+)\s*\|\s*`([0-9a-f]{64})`\s*\|")

def normaliser(texte: str) -> str:
    return texte.replace("\r\n", "\n").replace("\r", "\n").rstrip("\n") + "\n"

def extraire_partie(chemin: Path):
    """Retourne {chemin: contenu_normalise} et la table d'empreintes annoncée."""
    lignes = chemin.read_text(encoding="utf-8").splitlines()
    fichiers: dict[str, str] = {}
    empreintes: dict[str, str] = {}
    dans_bloc = False
    courant: str | None = None
    bloc: list[str] = []
    for ligne in lignes:
        if m := SHA_ROW.match(ligne):
            empreintes[m.group(1)] = m.group(3)
            continue
        if dans_bloc:
            if FENCE_CLOSE.match(ligne):
                fichiers[courant] = normaliser("\n".join(bloc))
                dans_bloc, courant, bloc = False, None, []
            else:
                bloc.append(ligne)
            continue
        if m := HEADER.match(ligne):
            courant = m.group(1)
            continue
        if courant and FENCE_OPEN.match(ligne):
            dans_bloc, bloc = True, []
    return fichiers, empreintes

def main():
    total_ok = total_echec = 0
    a_copier: list[tuple[Path, Path]] = []
    collisions: list[str] = []
    for partie in sorted(UPLOADS.glob("PROJET_MANQUANTS_PARTIE*.md")):
        fichiers, empreintes = extraire_partie(partie)
        print(f"\n=== {partie.name} : {len(fichiers)} fichiers extraits, "
              f"{len(empreintes)} empreintes annoncées ===")
        for chemin_rel, contenu in fichiers.items():
            reel = hashlib.sha256(contenu.encode("utf-8")).hexdigest()
            attendu = empreintes.get(chemin_rel)
            if attendu is None:
                print(f"  SANS EMPREINTE  {chemin_rel}")
                total_echec += 1
                continue
            if reel != attendu:
                print(f"  EMPREINTE FAUSSE  {chemin_rel}")
                print(f"     attendu {attendu[:16]}… obtenu {reel[:16]}…")
                total_echec += 1
                continue
            cible = RACINE / chemin_rel
            if cible.exists():
                existant = normaliser(cible.read_text(encoding="utf-8"))
                if existant == contenu:
                    print(f"  DÉJÀ PRÉSENT, IDENTIQUE  {chemin_rel}")
                    total_ok += 1
                    continue
                collisions.append(chemin_rel)
                print(f"  COLLISION (non écrasé)  {chemin_rel}")
                total_echec += 1
                continue
            tampon = STAGING / chemin_rel
            tampon.parent.mkdir(parents=True, exist_ok=True)
            tampon.write_text(contenu, encoding="utf-8", newline="\n")
            a_copier.append((tampon, cible))
            total_ok += 1
            print(f"  OK  {chemin_rel}")
    # aucune erreur → on verse dans l'arbre
    if total_echec == 0:
        for src, dst in a_copier:
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
        print(f"\nVERDICT : {total_ok} fichiers conformes, versés dans l'arbre. 0 échec.")
    else:
        print(f"\nVERDICT : {total_ok} conformes, {total_echec} problèmes — RIEN n'est versé.")
        if collisions:
            print("Collisions :", ", ".join(collisions))
    return 0 if total_echec == 0 else 1

sys.exit(main())
