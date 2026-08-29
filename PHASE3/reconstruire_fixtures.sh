#!/usr/bin/env bash
# Recrée les dépôts git internes des fixtures de test (exclus du dépôt via
# .gitignore : un dépôt git imbriqué n'est pas versionnable tel quel).
# Sans eux, les batteries qui exercent gitleaks (historique git requis)
# échouent sur un clone frais. Les fichiers des fixtures — y compris leurs
# faux secrets volontaires — SONT versionnés ; seul l'historique est recréé.
set -euo pipefail
cd "$(dirname "$0")"
for f in testrepo testrepo_go testrepo_xtool; do
  if [ -d "$f/.git" ]; then
    echo "$f : déjà initialisé"
    continue
  fi
  git init -q "$f"
  git -C "$f" add -A
  git -C "$f" -c user.email="fixture@local" -c user.name="fixture" \
      commit -qm "fixture de test (historique recréé)"
  echo "$f : historique recréé"
done
