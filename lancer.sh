#!/usr/bin/env bash
# ============================================================================
# Lance la belle interface (console React/Vite) branchée sur le VRAI moteur.
#
#   ./lancer.sh            -> démarre l'API moteur (8141) + la console (5173)
#   ./lancer.sh --build     -> sert la version de PRODUCTION (vite preview)
#
# Pré-requis : python3 (venv) et node/npm. La console s'installe toute.
# Pour de VRAIS résultats d'analyse (pas seulement un refus nommé), installez
# les outils épinglés une fois :  bash PHASE3/bootstrap.sh   (~3,7 Go)
# ============================================================================
set -euo pipefail
cd "$(dirname "$0")"

API_PORT="${API_PORT:-8141}"
WEB_PORT="${WEB_PORT:-5173}"
API_PID=""

tout_arreter() {
  [ -n "$API_PID" ] && kill "$API_PID" 2>/dev/null || true
}
trap tout_arreter EXIT INT TERM

# --- 1. environnement Python (API moteur) ----------------------------------
if [ ! -d .venv ]; then
  echo ">> création du venv Python (.venv)…"
  python3 -m venv .venv
  .venv/bin/python -m pip install --quiet --upgrade pip
  .venv/bin/python -m pip install --quiet -r requirements-interface.txt
else
  .venv/bin/python -c "import yaml" 2>/dev/null || \
    .venv/bin/python -m pip install --quiet -r requirements-interface.txt
fi

# --- 2. dépendances front ---------------------------------------------------
if [ ! -d node_modules ]; then
  echo ">> installation des dépendances web (npm install)…"
  npm install --no-audit --no-fund
fi

# --- 3. API moteur ----------------------------------------------------------
# Les outils épinglés par bootstrap.sh vivent dans ce cache : on l'expose au
# PATH pour que la résolution d'exécutables (adapters.resoudre_exe) les trouve.
export PATH="${ARENA_SECOPS_CACHE:-$HOME/.cache/arena_secops}/bin:$PATH"
echo ">> démarrage de l'API moteur sur :$API_PORT …"
.venv/bin/python PHASE3/interface/api.py --host 127.0.0.1 --port "$API_PORT" \
  > /tmp/agnt-api.log 2>&1 &
API_PID=$!

# On attend que l'API réponde (max ~15 s) avant de lancer la console.
for _ in $(seq 1 30); do
  if curl -sf "http://127.0.0.1:$API_PORT/api/capacites" >/dev/null 2>&1; then
    echo ">> API moteur prête."
    break
  fi
  sleep 0.5
done

# --- 4. console -------------------------------------------------------------
if [ "${1:-}" = "--build" ]; then
  echo ">> build de production…"
  npm run build
  echo ">> console sur http://localhost:$WEB_PORT  (Ctrl+C pour quitter)"
  PORT="$WEB_PORT" npm run preview
else
  echo ">> console de dev sur http://localhost:$WEB_PORT  (Ctrl+C pour quitter)"
  PORT="$WEB_PORT" npm run dev
fi
