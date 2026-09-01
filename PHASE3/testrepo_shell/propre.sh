#!/bin/bash
# Fixture shellcheck — script VOLONTAIREMENT propre (0 finding attendu).
set -euo pipefail

repertoire="${1:?répertoire manquant}"

rm -rf "${repertoire:?}/tmp"

cd /tmp

total="$(find . -maxdepth 1 -type f | wc -l)"
echo "total: ${total}"
