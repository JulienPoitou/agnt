#!/usr/bin/env python3
"""Outil jetable : extrait l'arborescence depuis PROJET_COMPLET.md.

Stratégie robuste aux collisions de clôtures : les sections sont délimitées
par les en-têtes « ## FICHIER : `chemin` ». Pour chaque section, le contenu
est compris entre la PREMIÈRE ligne de clôture après l'en-tête et la DERNIÈRE
ligne de clôture avant l'en-tête suivant (les clôtures internes des .md
embarqués restent donc à l'intérieur du contenu).
"""
import re
import sys
from pathlib import Path

SRC = Path("/home/user/uploads/PROJET_COMPLET.md")
RACINE = Path("/home/user")

lignes = SRC.read_text(encoding="utf-8").splitlines()

HEADER = re.compile(r"^## FICHIER : `([^`]+)`\s*$")
FENCE = re.compile(r"^\s*(`{3,}|~{3,})")

# 1. Repérer les en-têtes
index = [(m.group(1), i) for i, l in enumerate(lignes) if (m := HEADER.match(l))]
if not index:
    sys.exit("Aucun en-tête FICHIER trouvé.")

rapport = []
for n, (chemin, debut) in enumerate(index):
    fin_section = index[n + 1][1] if n + 1 < len(index) else len(lignes)
    bloc = lignes[debut + 1 : fin_section]

    # première clôture = ouverture ; dernière clôture de la section = fermeture
    ouv = next((k for k, l in enumerate(bloc) if FENCE.match(l)), None)
    fer = next((k for k in reversed(range(len(bloc))) if FENCE.match(bloc[k])), None)
    if ouv is None or fer is None or fer <= ouv:
        rapport.append((chemin, "ECHEC: clôture introuvable"))
        continue
    contenu = "\n".join(bloc[ouv + 1 : fer]) + "\n"

    cible = RACINE / chemin
    cible.parent.mkdir(parents=True, exist_ok=True)
    cible.write_text(contenu, encoding="utf-8")
    rapport.append((chemin, f"OK ({len(contenu)} octets, {contenu.count(chr(10))} lignes)"))

ok = sum(1 for _, s in rapport if s.startswith("OK"))
print(f"Fichiers extraits : {ok}/{len(index)}")
for c, s in rapport:
    if not s.startswith("OK"):
        print(f"  PROBLEME  {c}: {s}")
sys.exit(0 if ok == len(index) else 1)
