#!/usr/bin/env bash
# Harnais de validation des 8 conditions de sandbox — PHASE 3.
#
# À exécuter sur une machine AVEC Docker. Cet environnement de travail n'en a pas,
# donc ces tests n'ont pas pu y être lancés : voir RESULTATS_TESTS.md §4.
#
# Ce qui est déjà validé ailleurs (exécution réelle, sans conteneur) :
#   - besoins réseau des trois outils
#   - formats de sortie et validité SARIF
#   - comportement des flags (--redact, --skip-db-update, --disable-telemetry)
#
# Ce que ce script valide : les conditions qui dépendent du conteneur.
#   rootless · filesystem lecture seule · capabilities supprimées · limites de ressources
#
# Usage :  ./harnais_sandbox.sh
# Pré-requis : docker, et la base Trivy déjà téléchargée (docker run --rm \
#              -v trivy-cache:/root/.cache/trivy aquasec/trivy image --download-db-only)

set -uo pipefail

FIXTURE="${FIXTURE:-$(cd "$(dirname "$0")/testrepo" && pwd)}"
PASS=0; FAIL=0; SKIP=0

vert() { printf '\033[32m%s\033[0m' "$1"; }
rouge() { printf '\033[31m%s\033[0m' "$1"; }

verdict() {  # verdict <nom> <code_attendu> <code_obtenu>
  if [ "$2" = "$3" ]; then
    echo "  $(vert OK)   $1"; PASS=$((PASS+1))
  else
    echo "  $(rouge ÉCHEC) $1 (attendu $2, obtenu $3)"; FAIL=$((FAIL+1))
  fi
}

# Options communes : les 8 conditions, appliquées à chaque outil.
# --read-only            filesystem en lecture seule
# --cap-drop=ALL         aucune capability Linux
# --network=none         réseau désactivé
# --user 1000:1000       rootless
# --pids-limit / --memory / --cpus   limites de ressources
# --tmpfs /tmp           seul point inscriptible
SANDBOX=(--read-only --cap-drop=ALL --network=none --user 1000:1000
         --pids-limit=256 --memory=1g --cpus=1 --tmpfs /tmp
         -v "$FIXTURE:/scan:ro" --workdir /scan)

echo "=== Dépôt de test : $FIXTURE ==="
echo

# ---------------------------------------------------------------- GITLEAKS
echo "--- Gitleaks (image officielle : tourne en root, pas de USER) ---"
# L'image officielle n'a pas de USER : on impose 1000 au runtime.
docker run --rm "${SANDBOX[@]}" zricethezav/gitleaks:latest \
  git /scan --report-format json --report-path /tmp/gl.json --redact --no-banner >/dev/null 2>&1
verdict "gitleaks tourne en rootless + read-only + sans réseau" 0 $?

# Vérifie que le secret n'apparaît nulle part dans la sortie.
if docker run --rm "${SANDBOX[@]}" zricethezav/gitleaks:latest \
     git /scan --report-format json --report-path - --redact --no-banner 2>/dev/null \
     | grep -q 'ghp_16C7e42F292c6912E7710c838347Ae178B4a'; then
  echo "  $(rouge ÉCHEC) le secret apparaît malgré --redact"; FAIL=$((FAIL+1))
else
  echo "  $(vert OK)   aucun secret en clair dans la sortie"; PASS=$((PASS+1))
fi
echo

# ---------------------------------------------------------------- TRIVY
echo "--- Trivy (base de 1,3 Go à monter en lecture seule) ---"
# La base DOIT être pré-peuplée : sans elle, Trivy échoue même avec --skip-db-update
# (« --skip-db-update cannot be specified on the first run »).
if ! docker volume inspect trivy-cache >/dev/null 2>&1; then
  echo "  $(rouge ÉCHEC) volume trivy-cache absent — pré-téléchargez la base d'abord"; FAIL=$((FAIL+1))
else
  docker run --rm "${SANDBOX[@]}" \
    -v trivy-cache:/home/user/.cache/trivy:ro \
    aquasec/trivy:latest fs --cache-dir /home/user/.cache/trivy \
    --scanners vuln --skip-db-update --skip-java-db-update --disable-telemetry \
    --format json --output /tmp/tv.json --no-progress /scan >/dev/null 2>&1
  verdict "trivy tourne hors ligne, rootless, read-only, sans réseau" 0 $?

  # Preuve que le réseau est bien coupé : sans cache, ça doit échouer.
  docker run --rm "${SANDBOX[@]}" aquasec/trivy:latest \
    fs --cache-dir /tmp/vide --scanners vuln --offline-scan --disable-telemetry \
    --format json --no-progress /scan >/dev/null 2>&1
  verdict "trivy échoue bien quand la base est absente (le réseau est vraiment coupé)" 1 $?
fi
echo

# ---------------------------------------------------------------- SEMGREP
echo "--- Semgrep (règles à monter, image nonroot) ---"
# Les règles DOIVENT être locales : avec --config p/... Semgrep échoue sans réseau.
REGLES="${REGLES:-$(cd "$(dirname "$0")/rules" && pwd)}"
if [ ! -d "$REGLES" ]; then
  echo "  $(rouge SAUT) $REGLES introuvable — téléchargez d'abord :"; SKIP=$((SKIP+1))
  echo "        curl -sL -o rules/python.yaml https://semgrep.dev/c/p/python"
else
  docker run --rm "${SANDBOX[@]}" \
    -v "$REGLES:/regles:ro" \
    semgrep/semgrep:nonroot \
    semgrep scan --config /regles/python.yaml --metrics=off --disable-version-check \
    --json --output /tmp/sg.json --quiet /scan >/dev/null 2>&1
  verdict "semgrep tourne en rootless + read-only + sans réseau" 0 $?

  # L'image nonroot exige que le volume soit lisible par l'uid 1000.
  docker run --rm "${SANDBOX[@]}" -v "$REGLES:/regles:ro" semgrep/semgrep:nonroot \
    id -u 2>/dev/null | grep -q '^1000$'
  verdict "l'utilisateur du conteneur est bien l'uid 1000" 0 $?
fi
echo

# ---------------------------------------------------------------- SYNTHÈSE
echo "================================"
echo "  $(vert "$PASS OK")   $(rouge "$FAIL ÉCHEC")   $SKIP SAUT"
echo "================================"
if [ "$FAIL" -gt 0 ]; then
  echo
  echo "Un échec ici signifie qu'une des 8 conditions n'est pas tenable telle quelle."
  echo "Ne pas passer au minimal core avant d'avoir résolu — c'est le but de ce script."
  exit 1
fi
echo "Les 8 conditions sont tenables. Le minimal core peut démarrer."
