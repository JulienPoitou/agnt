#!/usr/bin/env bash
# Ce harnais juge les contrôles d'intégrité de bootstrap.sh :
#   1. l'empreinte des binaires que bootstrap.sh TELECHARGE — le contrôle qui manquait de face ;
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
#   2. la config gitleaks (SEC-G6a/F7) : cinq faces — source AGNT absente, manifeste absent,
#      épinglage manquant, source divergente, source conforme — jouées sur la fonction
#      `installer_config_gitleaks` SOURCÉE depuis bootstrap.sh, avec des dépôts factices.
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

echo; echo "=== SEC-G6a/F7 : la grille de secrets vient d'AGNT, jamais du dépôt analysé"
# Les cinq faces de l'installation — absente, manifeste manquant, épinglage manquant,
# divergente, conforme — sont jouées sur la fonction RÉELLE de bootstrap.sh (source
# depuis l'en-tête), avec des dépôts de travail factices pour ne pas toucher au réel.
gl_source="$B/regles/gitleaks.toml"
gl_reel=$(sha256sum "$gl_source" | cut -d' ' -f1)
gl_epingle=$(python3 -c "
import sys, yaml
m = yaml.safe_load(open('$B/manifeste_dependances.yaml', encoding='utf-8'))
print((m.get('regles', {}).get('gitleaks.toml') or {}).get('sha256') or '')
")
v "la config AGNT existe dans le dépôt de travail et son empreinte est épinglée" \
  "$gl_reel" "$gl_epingle"

sortie=$(source "$TRAVAIL/contexte.sh"
         B="$TRAVAIL/faux_absent"; mkdir -p "$B/regles"
         C="$TRAVAIL/c1"; RULES="$C/rules"; MON=""; MANIFESTE="$TRAVAIL/manifeste_reel.yaml"
         mkdir -p "$RULES"
         installer_config_gitleaks 2>&1; echo "rc=$?")
v "source absente : refus (retour non nul)" "rc=1" "$(printf '%s' "$sortie" | tail -1)"
v "la panne est nommée (config AGNT absente)" 1 \
  "$(printf '%s' "$sortie" | grep -c 'config gitleaks AGNT absente')"
v "et rien n'est installé dans \$RULES" "0" \
  "$( [ -f "$TRAVAIL/c1/rules/gitleaks.toml" ] && echo 1 || echo 0 )"

sortie=$(source "$TRAVAIL/contexte.sh"
         B="$TRAVAIL/faux_ok"; mkdir -p "$B/regles"; cp "$gl_source" "$B/regles/gitleaks.toml"
         C="$TRAVAIL/c2"; RULES="$C/rules"; MANIFESTE="$TRAVAIL/inexistant.yaml"
         mkdir -p "$RULES"
         installer_config_gitleaks 2>&1; echo "rc=$?")
v "manifeste absent : refus (retour non nul)" "rc=1" "$(printf '%s' "$sortie" | tail -1)"
v "la cause est dite (manifeste absent)" 1 "$(printf '%s' "$sortie" | grep -c 'manifeste absent')"

python3 - "$TRAVAIL/manifeste_reel.yaml" "$TRAVAIL/manifeste_sans_epingle.yaml" <<'PY'
import sys, yaml
src, dst = sys.argv[1], sys.argv[2]
m = yaml.safe_load(open(src, encoding="utf-8"))
del m["regles"]["gitleaks.toml"]
open(dst, "w", encoding="utf-8").write(yaml.safe_dump(m, sort_keys=False))
PY
sortie=$(source "$TRAVAIL/contexte.sh"
         B="$TRAVAIL/faux_ok2"; mkdir -p "$B/regles"; cp "$gl_source" "$B/regles/gitleaks.toml"
         C="$TRAVAIL/c3"; RULES="$C/rules"; MANIFESTE="$TRAVAIL/manifeste_sans_epingle.yaml"
         mkdir -p "$RULES"
         installer_config_gitleaks 2>&1; echo "rc=$?")
v "épinglage manquant : refus (retour non nul)" "rc=1" "$(printf '%s' "$sortie" | tail -1)"
v "la cause est dite (aucune empreinte épinglée)" 1 \
  "$(printf '%s' "$sortie" | grep -c 'aucune empreinte épinglée')"

sortie=$(source "$TRAVAIL/contexte.sh"
         B="$TRAVAIL/faux_divergent"; mkdir -p "$B/regles"
         printf "autre grille, pas l'empreinte du dépôt\n" > "$B/regles/gitleaks.toml"
         C="$TRAVAIL/c4"; RULES="$C/rules"; MANIFESTE="$TRAVAIL/manifeste_reel.yaml"
         mkdir -p "$RULES"
         installer_config_gitleaks 2>&1; echo "rc=$?")
v "source divergente : refus (retour non nul)" "rc=1" "$(printf '%s' "$sortie" | tail -1)"
v "la panne est nommée (SHA-256 inattendu)" 1 "$(printf '%s' "$sortie" | grep -c 'SHA-256 inattendu')"
v "les deux empreintes sont données (sinon le message est inutilisable)" 2 \
  "$(printf '%s' "$sortie" | grep -cE 'attendu : [0-9a-f]{64}|obtenu  : [0-9a-f]{64}')"
v "la conduite à tenir est dite (mettre à jour l'un, pas l'autre)" 1 \
  "$(printf '%s' "$sortie" | grep -c 'mettre à jour l.un, pas l.autre')"

sortie=$(source "$TRAVAIL/contexte.sh"
         B="$TRAVAIL/faux_conforme"; mkdir -p "$B/regles"; cp "$gl_source" "$B/regles/gitleaks.toml"
         C="$TRAVAIL/c5"; RULES="$C/rules"; MANIFESTE="$TRAVAIL/manifeste_reel.yaml"
         mkdir -p "$RULES"
         installer_config_gitleaks 2>&1; echo "rc=$?")
v "source conforme : succès (retour nul)" "rc=0" "$(printf '%s' "$sortie" | tail -1)"
v "la grille est installée dans \$RULES (montée lecture seule côté Sandbox)" 1 \
  "$( [ -f "$TRAVAIL/c5/rules/gitleaks.toml" ] && echo 1 || echo 0 )"
v "l'empreinte installée est bien celle épinglée" "$gl_epingle" \
  "$(sha256sum "$TRAVAIL/c5/rules/gitleaks.toml" | cut -d' ' -f1)"
v "le seul --config admissible est celui d'AGNT (registre, autorité unique)" 1 \
  "$(grep -c -- '--config={REGLES}/gitleaks.toml' "$B/slice/capabilities.yaml")"

echo; echo "=== POSITION des contrôles dans bootstrap.sh"
def_gl=$(grep -n '^installer_config_gitleaks()' "$B/bootstrap.sh" | cut -d: -f1)
appel_gl=$(grep -n '^installer_config_gitleaks$' "$B/bootstrap.sh" | cut -d: -f1)
v "la fonction est définie AVANT la borne de sourcing du harnais (code réel jugé)" 1 \
  "$( [ -n "$def_gl" ] && [ "$def_gl" -lt "$fin" ] && echo 1 || echo 0 )"
v "l'appel est unique et hors de l'en-tête (exécuté après l'installation des outils)" 1 \
  "$( [ -n "$appel_gl" ] && [ "$appel_gl" -gt "$fin" ] && echo 1 || echo 0 )"
# Calculs séparés pour les bornes, sinon un argument vide meurt sur « integer expression
# expected » — le harnais ne doit pas mourir sur sa propre syntaxe.
borne_semgrep=$(grep -n '^for r in python' "$B/bootstrap.sh" | cut -d: -f1)
borne_trivy=$(grep -n '^# .*base Trivy' "$B/bootstrap.sh" | cut -d: -f1)
v "l'appel suit la boucle des règles Semgrep et précède la base Trivy" 1 \
  "$( [ -n "$appel_gl" ] && [ -n "$borne_semgrep" ] && [ -n "$borne_trivy" ] && [ "$appel_gl" -gt "$borne_semgrep" ] && [ "$appel_gl" -lt "$borne_trivy" ] && echo 1 || echo 0 )"
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
