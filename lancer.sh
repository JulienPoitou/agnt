#!/usr/bin/env bash
# ============================================================================
# Lance la console opérationnelle (dossier PHASE3/interface/) branchée sur le
# VRAI moteur. La console est servie PAR l'API elle-même — même origine, zéro
# build, zéro node.
#
#   ./lancer.sh            -> API moteur + console sur http://127.0.0.1:8141
#
# Pré-requis : python3 (venv). Pour de VRAIS résultats d'analyse (pas seulement
# un refus nommé), installez les outils épinglés une fois :
#   bash PHASE3/bootstrap.sh   (~3,7 Go)
# ============================================================================
set -euo pipefail
cd "$(dirname "$0")"

API_PORT="${API_PORT:-8141}"
API_PID=""

# --- 0. détection OS (F7 : multi-OS) ------------------------------------------
# Linux/macOS : .venv/bin/python ; Windows sous Git Bash (MINGW/MSYS/CYGWIN) :
# .venv/Scripts/python.exe. Sous Windows natif (cmd/PowerShell), relancer ce
# script depuis Git Bash — le script reste bash-only, sans dépendance nouvelle.
_SYS="$(uname -s 2>/dev/null || echo unknown)"
case "$_SYS" in
  MINGW*|MSYS*|CYGWIN*|Windows_NT|Windows*) OS="windows";;
  Darwin*) OS="macos";;
  *) OS="linux";;
esac
if [ "$OS" = "windows" ]; then
  PYBIN=".venv/Scripts/python.exe"
else
  PYBIN=".venv/bin/python"
fi
# Création du venv : python3 quand il existe, sinon python (cas Windows).
if command -v python3 >/dev/null 2>&1; then PY_CREATE="python3"; else PY_CREATE="python"; fi
# /tmp n'existe pas hors Unix : TMPDIR (défini par l'OS) avec repli /tmp.
LOG_FICHIER="${TMPDIR:-/tmp}/agnt-api.log"

tout_arreter() {
  [ -n "$API_PID" ] && kill "$API_PID" 2>/dev/null || true
}
trap tout_arreter EXIT INT TERM

# --- 1. environnement Python (API moteur) ----------------------------------
if [ ! -d .venv ]; then
  echo ">> création du venv Python (.venv)… [$OS]"
  "$PY_CREATE" -m venv .venv
  "$PYBIN" -m pip install --quiet --upgrade pip
  "$PYBIN" -m pip install --quiet -r requirements-interface.txt
else
  "$PYBIN" -c "import yaml" 2>/dev/null || \
    "$PYBIN" -m pip install --quiet -r requirements-interface.txt
fi

# --- 2. API moteur ----------------------------------------------------------
# Les outils épinglés par bootstrap.sh vivent dans ce cache : on l'expose au
# PATH pour que la résolution d'exécutables (adapters.resoudre_exe) les trouve.
export PATH="${ARENA_SECOPS_CACHE:-$HOME/.cache/arena_secops}/bin:$PATH"
echo ">> démarrage de l'API moteur sur 127.0.0.1:$API_PORT …"
"$PYBIN" PHASE3/interface/api.py --host 127.0.0.1 --port "$API_PORT" \
  > "$LOG_FICHIER" 2>&1 &
API_PID=$!

# On attend que l'API réponde (max ~15 s).
for _ in $(seq 1 30); do
  if curl -sf "http://127.0.0.1:$API_PORT/api/capacites" >/dev/null 2>&1; then
    echo ">> API moteur prête."
    break
  fi
  sleep 0.5
done

echo ">> console opérationnelle : http://127.0.0.1:$API_PORT  (Ctrl+C pour quitter)"
wait "$API_PID"
