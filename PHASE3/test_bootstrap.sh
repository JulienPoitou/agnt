#!/usr/bin/env bash
# L'empreinte des binaires que bootstrap.sh TELECHARGE — le contrôle qui manquait de face.
#
# PROBLÈME  `bootstrap.sh` vérifiait le SHA-256 de ce qui était DÉJÀ dans le cache, mais pas de
#           ce qu'il venait de télécharger. Une page d'erreur HTTP écrite dans `$BIN/opa`, un
#           artefact tronqué ou un miroir qui sert autre chose donnaient quand même
#           « environnement prêt » ; la divergence ne remontait qu'au premier scan, sous un
#           message d'isolateur — et `curl -sL` rend 0 sur une réponse 404, donc rien ne
#           signalait la panne à l'installation.
# CORRECTIF le 2026-08-30 : `curl -fsSL` (une erreur HTTP échoue au lieu d'écrire) et une
#           seconde boucle `verifier_binaire` APRÈS le dernier téléchargement.
#
# Ce fichier juge les trois faces du contrôle — divergent (refus), conforme (rien à dire),
# absent (l'absence n'est pas une divergence) — plus la POSITION de la boucle : placée avant le
# téléchargement de grype/kics, elle n'aurait rien jugé du tout. C'est exactement l'erreur que
# j'ai commise en écrivant le correctif, et c'est la mesure qui l'a trouvée.
#
# Aucun réseau, aucun paquet : `verifier_binaire` et `sha_attendu` sont SOURCÉS depuis
# bootstrap.sh (le code jugé est donc le code du dépôt, pas une copie qui divergerait).
#
# Usage : bash PHASE3/test_bootstrap.sh
set -uo pipefail
B="$(cd "$(dirname "$0")" && pwd)"
# Ce test SOURCÉ le code de bootstrap.sh, qui appelle `python3 -c "import yaml"`. Sans PyYAML,
# les trois faces se réduisent à « manifeste illisible » et la face conforme ne veut plus rien
# dire : dans ce cas le test se déclare NON ÉVALUÉ (sortie 77) au lieu de rendre un verdict
# qu'il ne peut pas motiver. C'est la dépendance du TEST, pas celle du produit — le produit,
# lui, est censé refuser quand PyYAML manque, et c'est ce que juge la face ILLISIBLE.
python3 -c "import yaml" 2>/dev/null || { echo "NON ÉVALUÉ  python3-yaml absent de cet environnement (sudo apt-get install -y python3-yaml)"; exit 77; }
TRAVAIL="$(mktemp -d)"
trap 'rm -rf "$TRAVAIL"' EXIT

# --------------------------------------------------------------- sourcing du contexte
# Tout bootstrap.sh jusqu'à la boucle de pré-vérification : en-tête, chemins, sha_attendu,
# verifier_binaire. La borne est cherchée, et son absence est un échec du test — pas un saut.
fin=$(grep -n '^for b in trivy gitleaks opa grype kics; do' "$B/bootstrap.sh" | head -1 | cut -d: -f1)
[ -n "$fin" ] || { echo "ÉCHEC  borne de sourcing introuvable dans bootstrap.sh"; exit 1; }
# On prend tout l'en-tête, jusqu'à la veille de la première boucle : les variables de chemins,
# `log`, `err`, `sha_attendu`, `verifier_binaire`. `set +e` est ajouté parce que bootstrap.sh
# pose `set -euo pipefail` et que ce test, lui, APPELLE ce qui doit échouer pour le juger.
{ echo "set -uo pipefail"; echo "B=\"$B\""; sed -n "1,$((fin - 1))p" "$B/bootstrap.sh"; echo "set +e"; } \
  > "$TRAVAIL/contexte.sh"
# `log` et `err` écrivent sur stderr/stdout : on les garde, ils sont le message qu'on juge.

PASS=0; FAIL=0
v(){ if [ "$2" = "$3" ]; then echo "  OK    $1"; PASS=$((PASS+1)); else echo "  ECHEC $1 (attendu $2, obtenu $3)"; FAIL=$((FAIL+1)); fi; }
lancer(){ ( source "$TRAVAIL/contexte.sh"
            C="$TRAVAIL/cache"; BIN="$C/bin"; RULES="$C/rules"; MANIFESTE="$1"
            mkdir -p "$BIN"
            for b in "${@:2}"; do verifier_binaire "$b" "$BIN/$b"; done ) 2>&1; }

cp "$B/manifeste_dependances.yaml" "$TRAVAIL/manifeste_reel.yaml"

echo "=== face DIVERGENTE : un binaire présent mais différent de l'empreinte épinglée"
sortie=$(source "$TRAVAIL/contexte.sh"
         C="$TRAVAIL/c1"; BIN="$C/bin"; MANIFESTE="$TRAVAIL/manifeste_reel.yaml"; mkdir -p "$BIN"
         printf 'opa : 404 page not found\n' > "$BIN/opa"
         verifier_binaire opa "$BIN/opa" 2>&1; echo "rc=$?")
v "refus (retour non nul)" "rc=1" "$(printf '%s' "$sortie" | tail -1)"
v "le nom du binaire est cité" 1 "$(printf '%s' "$sortie" | grep -c 'opa : SHA-256 inattendu')"
v "les deux empreintes sont données (sinon le message est inutilisable)" 2 \
  "$(printf '%s' "$sortie" | grep -cE 'attendu : [0-9a-f]{64}|obtenu  : [0-9a-f]{64}')"
v "la conduite à tenir est dite" 1 "$(printf '%s' "$sortie" | grep -c 'binaire REFUSÉ')"

echo; echo "=== face CONFORME : le contrôle accepte ce qui correspond (sinon il refuse tout)"
source "$TRAVAIL/contexte.sh"
C="$TRAVAIL/c2"; BIN="$C/bin"; mkdir -p "$BIN"
printf 'charge du test, conforme par construction\n' > "$BIN/opa"
reel=$(sha256sum "$BIN/opa" | cut -d' ' -f1)
# Le manifeste de TEST reçoit cette empreinte : c'est la seule façon de juger la face
# « conforme » sans falsifier le manifeste épinglé du dépôt, qui reste intact.
python3 - "$TRAVAIL/manifeste_reel.yaml" "$TRAVAIL/manifeste_test.yaml" "$reel" <<'PY'
import re, sys
src, dst, valeur = sys.argv[1], sys.argv[2], sys.argv[3]
t = open(src, encoding="utf-8").read()
nouveau, n = re.subn(r'(  opa:\n(?:.*\n)*?    sha256: )\S+', r'\g<1>' + valeur, t, count=1)
assert n == 1, "motif opa/sha256 introuvable dans le manifeste — le test ne prouverait rien"
t = nouveau
open(dst, "w", encoding="utf-8").write(t)
PY
sortie=$(source "$TRAVAIL/contexte.sh"
         C="$TRAVAIL/c2"; BIN="$C/bin"; MANIFESTE="$TRAVAIL/manifeste_test.yaml"
         verifier_binaire opa "$BIN/opa" 2>&1; echo "rc=$?")
v "aucun refus sur un binaire conforme" "rc=0" "$(printf '%s' "$sortie" | tail -1)"
v "aucun message d'erreur parasite" 0 "$(printf '%s' "$sortie" | grep -c 'inattendu')"

echo; echo "=== face ABSENTE : l'absence n'est pas une divergence (sinon machine neuve = échec)"
sortie=$(source "$TRAVAIL/contexte.sh"
         C="$TRAVAIL/c3"; BIN="$C/bin"; MANIFESTE="$TRAVAIL/manifeste_reel.yaml"; mkdir -p "$BIN"
         verifier_binaire opa "$BIN/opa" 2>&1; echo "rc=$?")
v "un binaire absent ne lève pas une erreur d'empreinte" "rc=0" "$(printf '%s' "$sortie" | tail -1)"

echo; echo "=== face ILLISIBLE : le manifeste ne peut pas être lu (PyYAML absent, fichier cassé)"
sortie=$(source "$TRAVAIL/contexte.sh"
         C="$TRAVAIL/c4"; BIN="$C/bin"; MANIFESTE="$TRAVAIL/pas_un_manifeste.yaml"; mkdir -p "$BIN"
         printf 'charge\n' > "$BIN/opa"
         printf "binaires: :\n" > "$MANIFESTE"   # YAML invalide : pas une carte, et pas d'apostrophe
         verifier_binaire opa "$BIN/opa" 2>&1; echo "rc=$?")
v "refus au lieu de passer en silence" "rc=1" "$(printf '%s' "$sortie" | tail -1)"
v "la panne est nommée (manifeste illisible)" 1 \
  "$(printf '%s' "$sortie" | grep -c 'manifeste illisible')"
v "la conduite à tenir est dite (PyYAML)" 1 "$(printf '%s' "$sortie" | grep -c 'python3-yaml')"
# Un manifeste ABSENT est un autre cas, traité avant celui-ci dans la fonction : les deux
# doivent refuser, mais pas pour la même raison — l'un est un fichier qui manque, l'autre un
# fichier qu'on ne peut pas lire, et c'est ce second qui passait en silence.
absent=$(source "$TRAVAIL/contexte.sh"
         C="$TRAVAIL/c5"; BIN="$C/bin"; MANIFESTE="$TRAVAIL/inexistant.yaml"; mkdir -p "$BIN"
         printf 'charge\n' > "$BIN/opa"
         verifier_binaire opa "$BIN/opa" 2>&1; echo "rc=$?")
v "manifeste manquant refusé aussi (branche déjà présente)" "rc=1" "$(printf '%s' "$absent" | tail -1)"

echo; echo "=== POSITION du contrôle dans bootstrap.sh"
# Calculs séparés, pas de `$( [ … ] )` imbriqué dans un argument qui continue sur la ligne
# suivante : la ligne 117 de ce fichier a fait planter bash pour moins que ça, et un test de
# pré-vol qui meurt sur sa propre syntaxe ne prévient personne.
pos_verif=$(grep -n '  verifier_binaire "\$b"' "$B/bootstrap.sh" | tail -1 | cut -d: -f1)
dernier_installe=$(grep -n 'tar -xzf /tmp/kics.tgz' "$B/bootstrap.sh" | tail -1 | cut -d: -f1)
nb_appels=$(grep -c '  verifier_binaire "\$b"' "$B/bootstrap.sh")
curl_sans_f=$(grep -c 'curl -sL -o' "$B/bootstrap.sh")
ordre=0
if [ -n "$pos_verif" ] && [ -n "$dernier_installe" ] && [ "$pos_verif" -gt "$dernier_installe" ]; then
  ordre=1
fi
v "le contrôle suit l'extraction du dernier binaire (kics)" 1 "$ordre"
v "le contrôle est appelé deux fois — cache existant ET après téléchargement" 2 "$nb_appels"
v "plus aucun curl sans -f : une erreur HTTP ne s'écrit plus dans le cache" 0 "$curl_sans_f"

echo; echo "  $PASS OK · $FAIL ÉCHEC"
[ "$FAIL" -eq 0 ]
