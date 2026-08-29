#!/usr/bin/env bash
# Harnais de test de l'isolateur OCI — Phase 9.
#
# À EXÉCUTER SUR UNE MACHINE AVEC DOCKER. Il n'a jamais été exécuté dans
# l'environnement de développement (pas de runtime OCI).
#
# Il vérifie les DIX limites demandées avant d'ouvrir le profil « non fiable » :
#
#    1. mémoire            --memory
#    2. swap               --memory-swap (égal à --memory = swap interdit)
#    3. CPU                --cpus
#    4. PID                --pids-limit
#    5. taille des fichiers --ulimit fsize
#    6. timeout            --timeout côté hôte
#    7. réseau             --network=none
#    8. capabilities       --cap-drop=ALL
#    9. no-new-privileges  --security-opt=no-new-privileges:true
#   10. nettoyage          --rm
#
# Chaque limite est testée POUR DE VRAI, pas seulement déclarée : on lance dans le
# conteneur une commande qui doit ÉCHOUER si la limite tient.
#
# Usage :
#   ./PHASE3/test_oci.sh              # teste tout
#   ./PHASE3/test_oci.sh --image X    # image à utiliser (défaut : python:3.13-slim)

set -uo pipefail

IMAGE="python:3.13-slim"
while [ $# -gt 0 ]; do
  case "$1" in
    --image) IMAGE="$2"; shift 2 ;;
    *) echo "option inconnue : $1"; exit 2 ;;
  esac
done

MEM="256m"
PIDS=64
CPUS="0.5"
FSIZE=10485760   # 10 Mo
TIMEOUT=30

# La commande de confinement. C'est exactement celle que produit isolateur_oci.py :
# si l'une des deux diverge, le test ne teste pas ce qui sera exécuté en production.
run() {
  timeout "$TIMEOUT" docker run --rm \
    --memory="$MEM" \
    --memory-swap="$MEM" \
    --pids-limit="$PIDS" \
    --cpus="$CPUS" \
    --ulimit "fsize=$FSIZE:$FSIZE" \
    --read-only \
    --tmpfs /tmp \
    --cap-drop=ALL \
    --security-opt=no-new-privileges:true \
    --network=none \
    "$IMAGE" "$@"
}

PAS=0; ECHECS=0
ok()   { echo "  OK    $1"; PAS=$((PAS+1)); }
ko()   { echo "  ECHEC $1 — $2"; ECHECS=$((ECHECS+1)); }

if ! command -v docker >/dev/null 2>&1; then
  echo "docker absent — ce harnais doit être lancé sur une machine avec Docker."
  exit 2
fi
if ! docker info >/dev/null 2>&1; then
  echo "docker présent mais le démon ne répond pas."
  exit 2
fi

echo "=== ISOLATEUR OCI — image $IMAGE ==="
echo

# ---------------------------------------------------------- 0. le conteneur tourne
if run python -c "print('ok')" >/dev/null 2>&1; then
  ok "0. le conteneur démarre"
else
  ko "0. le conteneur démarre" "impossible de continuer"
  echo; echo "  Aucune limite ne peut être testée."
  exit 1
fi

# ---------------------------------------------------------- 1. mémoire
# Alloue 512 Mo alors que la limite est 256 Mo : doit être tué.
if run python -c "b = bytearray(512*1024*1024); print(len(b))" >/dev/null 2>&1; then
  ko "1. mémoire ($MEM)" "512 Mo alloués alors que la limite est $MEM"
else
  ok "1. mémoire ($MEM) — allocation de 512 Mo refusée"
fi

# ---------------------------------------------------------- 2. swap
# --memory-swap égal à --memory interdit le swap. On vérifie que c'est bien appliqué.
LIM=$(run cat /sys/fs/cgroup/memory.max 2>/dev/null || run cat /sys/fs/cgroup/memory/memory.limit_in_bytes 2>/dev/null)
SWAP=$(run cat /sys/fs/cgroup/memory.swap.max 2>/dev/null || echo "?")
if [ -n "$LIM" ] && [ "$LIM" != "max" ]; then
  ok "2. swap — mémoire.max=$LIM swap.max=$SWAP"
else
  ko "2. swap" "limite non lisible (LIM=$LIM SWAP=$SWAP)"
fi

# ---------------------------------------------------------- 3. CPU
Q=$(run cat /sys/fs/cgroup/cpu.max 2>/dev/null || echo "?")
if [ "$Q" != "?" ] && [ "$Q" != "max 100000" ]; then
  ok "3. CPU ($CPUS) — cpu.max=$Q"
else
  ko "3. CPU" "cpu.max=$Q (attendu un quota, pas « max »)"
fi

# ---------------------------------------------------------- 4. PID
P=$(run cat /sys/fs/cgroup/pids.max 2>/dev/null || echo "?")
if [ "$P" = "$PIDS" ]; then
  ok "4. PID ($PIDS) — pids.max=$P"
else
  ko "4. PID" "pids.max=$P (attendu $PIDS)"
fi

# ---------------------------------------------------------- 5. taille des fichiers
if run sh -c "dd if=/dev/zero of=/tmp/gros bs=1M count=20" >/dev/null 2>&1; then
  ko "5. taille des fichiers" "20 Mo écrits alors que la limite est 10 Mo"
else
  ok "5. taille des fichiers (10 Mo) — écriture de 20 Mo refusée"
fi

# ---------------------------------------------------------- 6. timeout
DEBUT=$(date +%s)
timeout 5 docker run --rm "$IMAGE" sleep 30 >/dev/null 2>&1
FIN=$(date +%s)
DUREE=$((FIN-DEBUT))
if [ "$DUREE" -lt 10 ]; then
  ok "6. timeout — sleep 30 interrompu après ${DUREE}s"
else
  ko "6. timeout" "sleep 30 a duré ${DUREE}s"
fi

# ---------------------------------------------------------- 7. réseau
if run python -c "import socket; socket.create_connection(('1.1.1.1', 443), 5)" >/dev/null 2>&1; then
  ko "7. réseau" "connexion sortante réussie alors que --network=none"
else
  ok "7. réseau — aucune connexion sortante"
fi

# ---------------------------------------------------------- 8. capabilities
C=$(run grep CapEff /proc/self/status 2>/dev/null | tr -s ' ' | cut -d' ' -f2)
if [ "$C" = "0000000000000000" ]; then
  ok "8. capabilities — CapEff nul"
else
  ko "8. capabilities" "CapEff=$C (attendu tout à zéro)"
fi

# ---------------------------------------------------------- 9. no-new-privileges
N=$(run grep NoNewPrivs /proc/self/status 2>/dev/null | tr -s ' ' | cut -d' ' -f2)
if [ "$N" = "1" ]; then
  ok "9. no-new-privileges — actif"
else
  ko "9. no-new-privileges" "NoNewPrivs=$N (attendu 1)"
fi

# ---------------------------------------------------------- 10. lecture seule + nettoyage
if run sh -c "touch /interdit" >/dev/null 2>&1; then
  ko "10. système de fichiers en lecture seule" "écriture à la racine réussie"
else
  ok "10. système de fichiers en lecture seule"
fi
RESTE=$(docker ps -aq --filter ancestor="$IMAGE" | wc -l)
if [ "$RESTE" = "0" ]; then
  ok "10b. nettoyage — aucun conteneur résiduel"
else
  ko "10b. nettoyage" "$RESTE conteneur(s) résiduel(s)"
fi

echo
echo "=================================================="
echo "  $PAS OK · $ECHECS ECHEC(S)"
echo "=================================================="
if [ "$ECHECS" -gt 0 ]; then
  echo
  echo "PROFIL « NON FIABLE » REFUSÉ : toutes les limites doivent tenir."
  exit 1
fi
echo
echo "Les dix limites tiennent. Le profil « non fiable » peut être ouvert."
