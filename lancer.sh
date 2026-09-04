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

# --- 2. API moteur ----------------------------------------------------------
# Les outils épinglés par bootstrap.sh vivent dans ce cache : on l'expose au
# PATH pour que la résolution d'exécutables (adapters.resoudre_exe) les trouve.
export PATH="${ARENA_SECOPS_CACHE:-$HOME/.cache/arena_secops}/bin:$PATH"
echo ">> démarrage de l'API moteur sur 127.0.0.1:$API_PORT …"
.venv/bin/python PHASE3/interface/api.py --host 127.0.0.1 --port "$API_PORT" \
  > /tmp/agnt-api.log 2>&1 &
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
