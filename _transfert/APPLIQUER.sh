#!/usr/bin/env bash
# Application des correctifs de la session bundle — 2026-08-28.
#
# Usage :  bash APPLIQUER.sh <racine_du_projet>
# Exemple : bash APPLIQUER.sh ~/projet
#
# Ce script est VOLONTAIREMENT bruyant : dry-run d'abord, application ensuite,
# vérifications à la fin. Si un hunk échoue (le workspace source a divergé du
# bundle), il s'arrête et le dit — rien n'est appliqué à moitié en silence.
set -euo pipefail

R="${1:?usage : APPLIQUER.sh <racine_du_projet>}"
D="$(cd "$(dirname "$0")" && pwd)"
PATCH="$D/projet_2026-08-28.patch"

[ -d "$R" ] || { echo "ERREUR : racine introuvable : $R" >&2; exit 1; }
[ -f "$PATCH" ] || { echo "ERREUR : patch introuvable : $PATCH" >&2; exit 1; }
cd "$R"

# Le patch suppose l'arborescence du projet. Garde-fou minimal.
[ -f PHASE3/bootstrap.sh ] || { echo "ERREUR : PHASE3/bootstrap.sh absent de $R — mauvaise racine ?" >&2; exit 1; }

echo "==> 1/4 dry-run du patch (aucune écriture)"
patch -p1 --dry-run < "$PATCH"

echo "==> 2/4 application du patch"
patch -p1 --no-backup-if-mismatch < "$PATCH"

echo "==> 3/4 fixture IaC"
if [ -d PHASE3/testrepo_iac ]; then
  echo "    PHASE3/testrepo_iac existe déjà — NON écrasé (comparer à la main si besoin)"
else
  cp -r "$D/testrepo_iac" PHASE3/testrepo_iac
  echo "    copié : PHASE3/testrepo_iac (5 fichiers, ATTENDUS.yaml inclus)"
fi

echo "==> 4/4 vérifications statiques"
bash -n PHASE3/bootstrap.sh && echo "    bootstrap.sh : syntaxe OK"
python3 - <<'EOF'
import sys, yaml
sys.path.insert(0, 'PHASE3/slice')
caps = yaml.safe_load(open('PHASE3/slice/capabilities.yaml', encoding='utf-8'))
ids = [c['id'] for c in caps['capabilities']]
assert 'IAC_SCAN' in ids, 'IAC_SCAN absent de capabilities.yaml'
iac = next(c for c in caps['capabilities'] if c['id'] == 'IAC_SCAN')
import provider_manifest as pm
pm.valider(iac['providers'][0]['manifest'], 'IAC_SCAN')
print('    capabilities.yaml : IAC_SCAN présent, manifest checkov validé')
m = yaml.safe_load(open('PHASE3/manifeste_dependances.yaml', encoding='utf-8'))
assert 'javascript.yaml' in m['regles'], 'javascript.yaml absent du manifeste'
assert 'checkov' in m['binaires'], 'checkov absent du manifeste'
print('    manifeste : javascript.yaml + checkov présents')
EOF

echo
echo "Terminé. Suite à faire DANS CET ORDRE :"
echo "  1. bash PHASE3/bootstrap.sh        (télécharge javascript.yaml + checkov, exit 0 attendu)"
echo "  2. python3 PHASE3/test_securite.py (porte bloquante)"
echo "  3. les autres batteries — échecs ATTENDUS possibles :"
echo "     - test_manifest : un manifest de plus (checkov) — attente de count à étendre"
echo "     - test_slice : une demande générique inclut désormais IAC_SCAN — attentes extensibles"
echo "     - test_independant : si les 2 échecs persistent, voir README_PORTAGE.md §pyyaml"
