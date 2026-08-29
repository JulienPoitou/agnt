#!/usr/bin/env bash
# Bootstrap de l'environnement de test — à lancer avant tout test.
#
# POURQUOI CE SCRIPT EXISTE
#   1. Dans cet environnement de travail, les binaires installés hors du workspace et les
#      fichiers cachés (.git) ne survivent pas entre les sessions : tout doit pouvoir être
#      reconstruit de zéro.
#   2. Le workspace a un budget (128 Mo / 10 000 fichiers). Les binaires (OPA 59 Mo,
#      Gitleaks 21 Mo, Trivy 168 Mo) et la base de vulnérabilités Trivy (1,3 Go) sont donc
#      stockés HORS du workspace, dans ~/.cache/arena_secops.
#
# Le workspace ne contient que : code, docs, tests, fixtures.
set -euo pipefail

B="$(cd "$(dirname "$0")" && pwd)"
C="${ARENA_SECOPS_CACHE:-$HOME/.cache/arena_secops}"
BIN="$C/bin"
RULES="$C/rules"
TRIVY_DB="$C/trivy-cache"
TRIVY_VERSION=0.74.0
GITLEAKS_VERSION=8.30.1
OPA_VERSION=1.20.0
GRYPE_VERSION=0.118.0
KICS_VERSION=2.1.20

log(){ printf '\033[36m==>\033[0m %s\n' "$1"; }
err(){ printf '\033[31mERREUR\033[0m %s\n' "$1" >&2; }
mkdir -p "$BIN" "$RULES"

MANIFESTE="$B/manifeste_dependances.yaml"

# ---------------------------------------------------------------- vérification
# Un cache externe non vérifié n'est pas une reconstruction reproductible : il peut
# contenir un binaire inattendu. On vérifie le SHA-256 contre le manifeste, et on
# REFUSE un binaire qui ne correspond pas au lieu de l'utiliser.
sha_attendu() {  # sha_attendu <section> <nom>
  python3 -c "
import sys, yaml
m = yaml.safe_load(open('$MANIFESTE', encoding='utf-8'))
print((m.get(sys.argv[1], {}).get(sys.argv[2]) or {}).get('sha256') or '')
" "$1" "$2" 2>/dev/null
}

verifier_binaire() {  # verifier_binaire <nom> <chemin>
  local nom="$1" chemin="$2" attendu reel
  [ -f "$chemin" ] || return 0
  [ -f "$MANIFESTE" ] || { err "manifeste absent : $MANIFESTE"; return 1; }
  attendu=$(sha_attendu binaires "$nom")
  [ -z "$attendu" ] && return 0
  reel=$(sha256sum "$chemin" | cut -d' ' -f1)
  if [ "$reel" != "$attendu" ]; then
    err "$nom : SHA-256 inattendu"
    err "  attendu : $attendu"
    err "  obtenu  : $reel"
    err "  binaire REFUSÉ — supprimez-le ou mettez à jour le manifeste"
    return 1
  fi
  return 0
}

for b in trivy gitleaks opa grype kics; do
  verifier_binaire "$b" "$BIN/$b" || exit 1
done

# ---------------------------------------------------------------- dépendances système
# bubblewrap est installé par apt, et apt n'est PAS persistant entre les sessions :
# sans cette étape, tous les tests d'exécution tombent sur « bwrap: No such file ».
if ! command -v bwrap >/dev/null 2>&1; then
  log "bubblewrap (apt)"
  sudo -n apt-get install -y -qq bubblewrap uidmap >/dev/null 2>&1 \
    || log "installation de bubblewrap impossible — les tests d'exécution échoueront"
fi

# ---------------------------------------------------------------- binaires
[ -x "$BIN/trivy" ] || {
  log "trivy $TRIVY_VERSION"
  curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b "$BIN" >/dev/null
}
[ -x "$BIN/gitleaks" ] || {
  log "gitleaks $GITLEAKS_VERSION"
  curl -sL -o /tmp/gl.tgz "https://github.com/gitleaks/gitleaks/releases/download/v$GITLEAKS_VERSION/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"
  tar -xzf /tmp/gl.tgz -C "$BIN" gitleaks
  rm -f /tmp/gl.tgz
}
[ -x "$BIN/opa" ] || {
  log "opa $OPA_VERSION"
  curl -sL -o "$BIN/opa" "https://openpolicyagent.org/downloads/v$OPA_VERSION/opa_linux_amd64_static"
}
chmod +x "$BIN"/* 2>/dev/null || true
command -v semgrep >/dev/null || { log "semgrep"; pip install --quiet semgrep; }
# bandit aussi : pip n'est PAS persistant entre les sessions. Sans lui, les deux
# providers déclaratifs (bandit et bandit_custom) ne produisent rien — et le pipeline
# ne disait rien, ce qui est le pire mode d'échec.
command -v bandit >/dev/null || { log "bandit"; pip install --quiet bandit; }
# checkov : provider IAC_SCAN (Phase 5A, décision du 2026-08-28). pip n'est pas
# persistant — même raison que bandit. Empreinte RECORD dans le manifeste.
command -v checkov >/dev/null || { log "checkov"; pip install --quiet checkov; }

# ---------------------------------------------------------------- grype + kics
# Étape 4 (2026-08-29) : 2e providers réels (fan-out trivy×grype, checkov×kics).
# Tarballs des releases GitHub, empreintes vérifiées par verifier_binaire.
[ -x "$BIN/grype" ] || {
  log "grype $GRYPE_VERSION"
  curl -sL -o /tmp/grype.tgz "https://github.com/anchore/grype/releases/download/v$GRYPE_VERSION/grype_${GRYPE_VERSION}_linux_amd64.tar.gz"
  tar -xzf /tmp/grype.tgz -C "$BIN" grype
}
[ -x "$BIN/kics" ] || {
  log "kics $KICS_VERSION"
  curl -sL -o /tmp/kics.tgz "https://github.com/Checkmarx/kics/releases/download/v$KICS_VERSION/kics_${KICS_VERSION}_linux_amd64.tar.gz"
  tar -xzf /tmp/kics.tgz -C "$BIN" kics
}
# Bibliothèque de requêtes kics (1810 fichiers OPA) : PAS dans le tarball binaire
# (mesuré le 2026-08-29 : 3 entrées — LICENSE, README, kics). Asset officiel
# extracted-info.zip, sha256 épinglé. Sans elle : « unable to find queries ».
if [ ! -d "$RULES/kics/queries" ]; then
  log "bibliothèque de requêtes kics (extracted-info.zip)"
  curl -sL -o /tmp/kics-info.zip "https://github.com/Checkmarx/kics/releases/download/v$KICS_VERSION/extracted-info.zip"
  echo "305fd652d9291fb5f0a3437a4f0a2c953fffa7d2827bb4fd4907c82c1a8cbad9  /tmp/kics-info.zip" | sha256sum -c - || exit 1
  rm -rf /tmp/kics-assets && mkdir -p /tmp/kics-assets
  (cd /tmp/kics-assets && unzip -q /tmp/kics-info.zip "assets/queries/*")
  mkdir -p "$RULES/kics"
  cp -r /tmp/kics-assets/assets/queries "$RULES/kics/queries"
fi
# Base grype (~2 Go) sous trivy-cache/grype : portée par le montage M_DB existant.
if [ ! -d "$TRIVY_DB/grype" ]; then
  log "base de vulnérabilités grype (hors workspace)"
  GRYPE_DB_CACHE_DIR="$TRIVY_DB/grype" "$BIN/grype" db update >/dev/null
fi

# ---------------------------------------------------------------- règles Semgrep
for r in python security-audit javascript golang; do
  [ -s "$RULES/$r.yaml" ] || {
    log "règles Semgrep p/$r"
    curl -sL -o "$RULES/$r.yaml" "https://semgrep.dev/c/p/$r"
  }
done

# ---------------------------------------------------------------- base Trivy
# 1,3 Go. Sans elle Trivy échoue : « --skip-db-update cannot be specified on the first run ».
if [ ! -d "$TRIVY_DB/trivy/db" ]; then
  log "base de vulnérabilités Trivy (1,3 Go, hors workspace)"
  XDG_CACHE_HOME="$TRIVY_DB" "$BIN/trivy" image --download-db-only --no-progress >/dev/null
fi

# ---------------------------------------------------------------- fixture
# Le .git ne survit pas aux sessions : recréé à chaque bootstrap.
for F in "$B/testrepo" "$B/testrepo_xtool" "$B/testrepo_go"; do
  [ -d "$F" ] || continue
  if [ ! -d "$F/.git" ]; then
    log "fixture : recréation du dépôt git dans $(basename "$F")"
    ( cd "$F" && git init -q . && git config user.email test@test.local \
      && git config user.name test && git add -A && git commit -qm "fixture de test" )
  fi
done

# ---------------------------------------------------------------- points de montage
# bwrap ne peut pas créer un point de montage sous une racine déjà montée en lecture
# seule : toutes les cibles de --ro-bind et --bind doivent exister AVANT l'appel.
# Ce sont des répertoires VIDES : quelques octets, ils restent dans le workspace.
mkdir -p "$B/mt-scan" "$B/mt-regles" "$B/mt-db" "$B/mt-out" "$B/run"
touch "$B/gitconfig.ro"
printf '[safe]\n\tdirectory = *\n' > "$B/gitconfig"

# ---------------------------------------------------------------- règles : divergence signalée
# Les règles viennent de semgrep.dev et ÉVOLUENT. Une divergence n'est pas une erreur de
# sécurité, mais elle change ce qui est détecté : elle doit être signalée, pas ignorée.
if [ -f "$MANIFESTE" ]; then
  for r in python.yaml security-audit.yaml javascript.yaml golang.yaml; do
    [ -f "$RULES/$r" ] || continue
    attendu=$(sha_attendu regles "$r")
    reel=$(sha256sum "$RULES/$r" | cut -d' ' -f1)
    if [ -n "$attendu" ] && [ "$reel" != "$attendu" ]; then
      printf '\033[33mAVERTISSEMENT\033[0m règles %s divergent du manifeste : les résultats peuvent différer\n' "$r"
    fi
  done
fi

log "environnement prêt"
echo "    cache      : $C   ($(du -sh "$C" 2>/dev/null | cut -f1))"
echo "    workspace  : $(du -sh --exclude=.cache "$B/.." 2>/dev/null | cut -f1)  (hors cache)"
# Affichages de version : capture complète puis extraction de la ligne — aucun tube,
# donc aucune course SIGPIPE avec `set -o pipefail` (le 141 intermittent du
# 2026-08-28, que de simples `|| true` ne feraient que masquer).
_v=$("$BIN/trivy" --version 2>/dev/null) && printf '%s\n' "${_v%%$'\n'*}" || true
"$BIN/gitleaks" version || true
_v=$("$BIN/opa" version 2>/dev/null) && printf '%s\n' "${_v%%$'\n'*}" || true
_v=$(semgrep --version 2>/dev/null) && printf '%s\n' "${_v##*$'\n'}" || true

