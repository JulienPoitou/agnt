#!/usr/bin/env bash
# Validation des conditions de sandbox avec bubblewrap — sans Docker.
#
# Quatre pièges rencontrés pour de vrai, tous corrigés ici :
#   1. la racine est montée en LECTURE SEULE : les points de montage doivent exister
#      AVANT et être déclarés APRÈS --ro-bind / /
#   2. /tmp est un tmpfs, il disparaît à la sortie : les rapports doivent aller dans un
#      répertoire BINDÉ depuis l'hôte, sinon on conclut à tort que rien n'a été produit
#   3. ne jamais faire rm -rf sur un répertoire déjà bindé : ça casse le montage
#   4. dans un user namespace, git rejette le dépôt (propriétaire douteux) :
#      il faut un GIT_CONFIG_GLOBAL avec safe.directory
set -uo pipefail
B=/home/user/PHASE3
# Binaires, règles et base Trivy vivent HORS du workspace depuis la Phase 3.1.
# Ce harnais pointait encore sur l'ancien agencement (PHASE3/rules, PHASE3/gitleaks…) :
# bwrap échouait au montage (exit 1) et les « OK » restants étaient des faux positifs
# (rapports absents). Aligné sur sandbox.py le 2026-08-28 — même variable d'environnement.
C="${ARENA_SECOPS_CACHE:-$HOME/.cache/arena_secops}"
OUT=$B/out
mkdir -p "$OUT" "$B/mt-scan" "$B/mt-regles" "$B/mt-db" "$B/mt-out"
rm -f "$OUT"/* 2>/dev/null
printf '[safe]\n\tdirectory = *\n' > "$B/gitconfig"
# bwrap ne peut PAS créer un point de montage sous une racine déjà montée en lecture
# seule : les cibles de --ro-bind et --bind doivent toutes exister avant l'appel.
touch "$B/gitconfig.ro"
PASS=0; FAIL=0
v(){ if [ "$2" = "$3" ]; then echo "  OK    $1"; PASS=$((PASS+1)); else echo "  ECHEC $1 (attendu $2, obtenu $3)"; FAIL=$((FAIL+1)); fi; }
nres(){ python3 -c "import json;print(len(json.load(open('$1')).get('results',[])))" 2>/dev/null || echo ERREUR; }
nvul(){ python3 -c "import json;d=json.load(open('$1'));print(sum(len(r.get('Vulnerabilities') or []) for r in d.get('Results',[])))" 2>/dev/null || echo ERREUR; }

run(){ local t="$1"; shift
  timeout "$t" bwrap \
    --ro-bind / / \
    --ro-bind "$B/testrepo"        "$B/mt-scan" \
    --ro-bind "$C/rules"           "$B/mt-regles" \
    --ro-bind "$C/trivy-cache/trivy" "$B/mt-db" \
    --ro-bind "$B/gitconfig"       "$B/gitconfig.ro" \
    --bind    "$OUT"               "$B/mt-out" \
    --dev /dev --proc /proc --tmpfs /tmp \
    --unshare-user --unshare-pid --unshare-net --unshare-ipc --unshare-uts \
    --die-with-parent "$@"; }

echo "=== GITLEAKS ==="
run 120 env GIT_CONFIG_GLOBAL="$B/gitconfig.ro" "$C/bin/gitleaks" git "$B/mt-scan" \
  --report-format json --report-path "$B/mt-out/gl.json" --redact --no-banner >/dev/null 2>&1
# gitleaks renvoie 1 QUAND il trouve des leaks : c'est le comportement normal, pas un échec.
rc=$?
v "rootless + read-only + sans réseau (rc=1 car 1 leak trouvé)" 1 $rc
v "rapport produit sur l'hôte" oui "$(test -s "$OUT/gl.json" && echo oui || echo non)"
v "1 leak détecté" 1 "$(python3 -c "import json;print(len(json.load(open('$OUT/gl.json'))))" 2>/dev/null || echo ERREUR)"
v "aucun secret en clair" non "$(grep -q 'ghp_16C7e42F292c6912E7710c838347Ae178B4a' "$OUT/gl.json" 2>/dev/null && echo oui || echo non)"

echo; echo "=== SEMGREP (règles locales) ==="
run 300 env HOME=/tmp SEMGREP_SEND_METRICS=off /usr/local/bin/semgrep scan \
  --config "$B/mt-regles/python.yaml" --config "$B/mt-regles/security-audit.yaml" \
  --metrics=off --disable-version-check --json --output "$B/mt-out/sg.json" --quiet "$B/mt-scan" >/dev/null 2>&1
v "rootless + read-only + sans réseau" 0 $?
v "2 vulnérabilités trouvées" 2 "$(nres "$OUT/sg.json")"

echo; echo "=== TRIVY (base 1,3 Go en lecture seule) ==="
run 300 env HOME=/tmp TMPDIR=/tmp "$C/bin/trivy" fs --cache-dir "$B/mt-db" --scanners vuln \
  --skip-db-update --skip-java-db-update --disable-telemetry \
  --format json --output "$B/mt-out/tv.json" --no-progress "$B/mt-scan" >/dev/null 2>&1
v "rootless + read-only + sans réseau" 0 $?
v "62 vulnérabilités trouvées (50 pip + 12 npm)" 62 "$(nvul "$OUT/tv.json")"

echo; echo "=== TIMEOUT imposé de l'extérieur ==="
# Un outil réel finit en 0,2 s : pour prouver que le timeout fonctionne il faut une
# commande qui dépasse réellement la limite.
run 2 /bin/sleep 30 >/dev/null 2>&1
v "le timeout coupe l'exécution" 124 $?

echo; echo "=== PREUVE que le réseau est vraiment coupé ==="
run 60 env HOME=/tmp TMPDIR=/tmp "$C/bin/trivy" fs --cache-dir /tmp/vide --scanners vuln \
  --offline-scan --disable-telemetry --no-progress "$B/mt-scan" >/dev/null 2>"$OUT/net.err"
v "trivy échoue sans base pré-peuplée" 1 $?
v "l'erreur cite bien un échec de connexion" oui "$(grep -qiE 'connection refused|proxyconnect|no such host|network' "$OUT/net.err" && echo oui || echo non)"

echo; echo "=============================="
echo "  $PASS OK   $FAIL ECHEC"
echo "=============================="
[ "$FAIL" -eq 0 ]
