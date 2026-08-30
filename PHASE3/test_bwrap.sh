#!/usr/bin/env bash
# Validation des conditions d'isolateur avec bubblewrap — sans Docker, sans réseau.
#
# QUAND LE LANCER : après `bash PHASE3/bootstrap.sh`, sur la machine où tu veux vraiment
# scanner. C'est le test le plus court entre « le bootstrap a réussi » et « les outils vont
# pouvoir tourner » : il reprend les quatre pièges rencontrés pour de vrai, tous corrigés ici
#   1. la racine est montée en LECTURE SEULE : les points de montage doivent exister
#      AVANT et être déclarés APRÈS --ro-bind / /
#   2. /tmp est un tmpfs, il disparaît à la sortie : les rapports doivent aller dans un
#      répertoire BINDÉ depuis l'hôte, sinon on conclut à tort que rien n'a été produit
#   3. ne jamais faire rm -rf sur un répertoire déjà bindé : ça casse le montage
#   4. dans un user namespace, git rejette le dépôt (propriétaire douteux) :
#      il faut un GIT_CONFIG_GLOBAL avec safe.directory
#
# CODES DE SORTIE : 0 tout est passé · 1 au moins un échec · 77 rien n'a pu être mesuré
# (bwrap absent, ou AppArmor qui refuse les namespaces). 77 n'est PAS un succès : un test
# d'environnement qui ne peut pas tourner doit se dire non évalué, sinon il devient un faux
# vert — exactement le défaut que le constat G8 de la campagne adverse a fermé côté binaires.
#
# Usage : ./PHASE3/test_bwrap.sh        (les chemins viennent du dépôt, pas d'un home en dur)
set -uo pipefail

B="$(cd "$(dirname "$0")" && pwd)"                       # <dépôt>/PHASE3
C="${ARENA_SECOPS_CACHE:-$HOME/.cache/arena_secops}"     # binaires, règles, base Trivy
M="${ARENA_SECOPS_MONTEURS:-$B}"                         # destinations de montage — même racine
                                                          # que sandbox.RACINE_MONTEURS et que
                                                          # bootstrap.sh ($B/mt-*), sinon les
                                                          # deux côtés se répondent l'un l'autre
                                                          # et le premier vrai scan échoue avec
                                                          # « lancer bootstrap.sh » après un
                                                          # bootstrap réussi (corrigé le
                                                          # 2026-08-30 : c'était en dur sous
                                                          # /home/user/PHASE3, soit nulle part)
OUT="$M/mt-out"
SEMGREP="$(command -v semgrep || echo /usr/local/bin/semgrep)"
NON_EVALUE=0

say(){ printf '%s\n' "$1"; }
note(){ printf '  NON ÉVALUÉ  %s\n' "$1"; NON_EVALUE=$((NON_EVALUE+1)); }

# ------------------------------------------------------------------ CANARY · namespaces
# Ces flags sont ceux de Sandbox.commande() (slice/sandbox.py) — pas des flags.Choisis pour
# l'occasion : si cette ligne échoue, tout le reste du script échouerait pour la même raison,
# et la cause n'est ni dans le dépôt ni dans les outils.
if ! command -v bwrap >/dev/null 2>&1; then
  say "=== CANARY · création des namespaces"
  note "bwrap absent. Sur WSL (Ubuntu) : sudo apt-get install -y bubblewrap uidmap"
  say ""
  say "  rien n'a été mesuré — ce n'est pas un succès. Sortie 77."
  exit 77
fi
ERRF="$(mktemp)"
bwrap --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp \
      --unshare-user --unshare-pid --unshare-net --unshare-ipc --unshare-uts true 2>"$ERRF"
case $? in
  0) say "=== CANARY · OK — user+pid+net+ipc+uts, racine en lecture seule" ;;
  *) say "=== CANARY · ÉCHEC : $(head -c 240 "$ERRF" | tr '\n' ' ')"
     if grep -qiE 'uid map|Operation not permitted|RTM_NEWADDR' "$ERRF"; then
       say "  cause connue : AppArmor réserve la création de namespaces non privilégiés"
       say "  à vérifier   : sysctl kernel.apparmor_restrict_unprivileged_userns  (1 = restreint)"
       say "                 cat /proc/sys/kernel/unprivileged_userns_clone          (doit être 1)"
       say "  à corriger   : profil AppArmor limité à /usr/bin/bwrap — /etc/apparmor.d/bwrap"
       say "                   abi <abi/4.0,>"
       say "                   include <tunables/global>"
       say "                   profile bwrap /usr/bin/bwrap flags=(unconfined) {"
       say "                     userns,"
       say "                     include if exists <local/bwrap>"
       say "                   }"
       say "                 sudo apparmor_parser -r /etc/apparmor.d/bwrap"
       say "               C'est préféré à `sysctl kernel.apparmor_restrict_unprivileged_userns=0`,"
       say "               qui rouvre les namespaces à tous les processus de la machine."
     fi
     say "  (le réseau est coupé VOLONTAIREMENT : --unshare-net est la garde du proxy noir."
     say "   le retirer ferait passer ce test plus souvent et rendrait l'isolateur moins sûr.)"
     rm -f "$ERRF"; exit 1 ;;
esac
rm -f "$ERRF"

mkdir -p "$OUT" "$M/mt-scan" "$M/mt-regles" "$M/mt-db"
printf '[safe]\n\tdirectory = *\n' > "$M/gitconfig"
touch "$M/gitconfig.ro"      # bwrap ne crée pas une destination sous une racine déjà l.e.

PASS=0; FAIL=0
v(){ if [ "$2" = "$3" ]; then echo "  OK    $1"; PASS=$((PASS+1)); else echo "  ECHEC $1 (attendu $2, obtenu $3)"; FAIL=$((FAIL+1)); fi; }
nres(){ python3 -c "import json;print(len(json.load(open('$1')).get('results',[])))" 2>/dev/null || echo ERREUR; }
nvul(){ python3 -c "import json;d=json.load(open('$1'));print(sum(len(r.get('Vulnerabilities') or []) for r in d.get('Results',[])))" 2>/dev/null || echo ERREUR; }

run(){ local t="$1"; shift
  timeout "$t" bwrap \
    --ro-bind / / \
    --ro-bind "$B/testrepo"        "$M/mt-scan" \
    --ro-bind "$C/rules"           "$M/mt-regles" \
    --ro-bind "$C/trivy-cache/trivy" "$M/mt-db" \
    --ro-bind "$M/gitconfig"       "$M/gitconfig.ro" \
    --bind    "$OUT"               "$M/mt-out" \
    --dev /dev --proc /proc --tmpfs /tmp \
    --unshare-user --unshare-pid --unshare-net --unshare-ipc --unshare-uts \
    --chdir "$M/mt-scan" --die-with-parent "$@"; }

# Un outil absent du cache n'est pas une régression : c'est `bootstrap.sh` qui le pose.
# Le dire évite de lire « ECHEC trivy » là où il faut lire « trivy non installé ».
outil(){ if [ ! -x "$1" ]; then note "$2 introuvable ($1) — lancer bootstrap.sh"; return 1; fi; return 0; }

echo; echo "=== GITLEAKS ==="
if outil "$C/bin/gitleaks" gitleaks; then
  rm -f "$OUT/gl.json"
  run 120 env GIT_CONFIG_GLOBAL="$M/gitconfig.ro" "$C/bin/gitleaks" git "$M/mt-scan" \
    --report-format json --report-path "$M/mt-out/gl.json" --redact --no-banner >/dev/null 2>&1
  rc=$?   # gitleaks renvoie 1 QUAND il trouve des leaks : comportement normal, pas un échec
  v "rootless + lecture seule + sans réseau (rc=1 car un leak est attendu)" 1 $rc
  v "rapport produit sur l'hôte" oui "$(test -s "$OUT/gl.json" && echo oui || echo non)"
  v "1 leak détecté" 1 "$(python3 -c "import json;print(len(json.load(open('$OUT/gl.json'))))" 2>/dev/null || echo ERREUR)"
  v "aucun secret en clair" non "$(grep -q 'ghp_16C7e42F292c6912E7710c838347Ae178B4a' "$OUT/gl.json" 2>/dev/null && echo oui || echo non)"
fi

echo; echo "=== SEMGREP (règles locales du bootstrap) ==="
if [ ! -f "$C/rules/python.yaml" ]; then
  note "règles semgrep absentes ($C/rules/python.yaml) — lancer bootstrap.sh"
elif ! command -v semgrep >/dev/null 2>&1 && [ ! -x /usr/local/bin/semgrep ]; then
  note "semgrep introuvable dans le PATH — `pip install semgrep` (le bootstrap le fait)"
else
  rm -f "$OUT/sg.json"
  run 300 env HOME=/tmp SEMGREP_SEND_METRICS=off "$SEMGREP" scan \
    --config "$M/mt-regles/python.yaml" --config "$M/mt-regles/security-audit.yaml" \
    --metrics=off --disable-version-check --json --output "$M/mt-out/sg.json" --quiet "$M/mt-scan" >/dev/null 2>&1
  v "rootless + lecture seule + sans réseau" 0 $?
  v "2 vulnérabilités trouvées" 2 "$(nres "$OUT/sg.json")"
fi

echo; echo "=== TRIVY (base de vulnérabilités en lecture seule) ==="
if outil "$C/bin/trivy" trivy; then
  if [ ! -d "$C/trivy-cache/trivy" ]; then
    note "base Trivy absente ($C/trivy-cache/trivy) — premier lancement de trivy, ou bootstrap partiel"
  else
    rm -f "$OUT/tv.json"
    run 300 env HOME=/tmp TMPDIR=/tmp "$C/bin/trivy" fs --cache-dir "$M/mt-db" --scanners vuln \
      --skip-db-update --skip-java-db-update --disable-telemetry \
      --format json --output "$M/mt-out/tv.json" --no-progress "$M/mt-scan" >/dev/null 2>&1
    v "rootless + lecture seule + sans réseau" 0 $?
    v "62 vulnérabilités trouvées (50 pip + 12 npm)" 62 "$(nvul "$OUT/tv.json")"
  fi
fi

echo; echo "=== TIMEOUT imposé de l'extérieur ==="
# Un outil réel finit en 0,2 s : pour prouver que le timeout fonctionne il faut une
# commande qui dépasse réellement la limite.
run 2 /bin/sleep 30 >/dev/null 2>&1
v "le timeout coupe l'exécution" 124 $?

echo; echo "=== PREUVE que le réseau est vraiment coupé ==="
if outil "$C/bin/trivy" trivy; then
  rm -f "$OUT/net.err"
  run 60 env HOME=/tmp TMPDIR=/tmp "$C/bin/trivy" fs --cache-dir /tmp/vide --scanners vuln \
    --offline-scan --disable-telemetry --no-progress "$M/mt-scan" >/dev/null 2>"$M/mt-out/net.err"
  v "trivy échoue sans base pré-peuplée" 1 $?
  v "l'erreur cite bien un échec de connexion" oui "$(grep -qiE 'connection refused|proxyconnect|no such host|network' "$OUT/net.err" && echo oui || echo non)"
fi

echo; echo "=============================="
echo "  $PASS OK · $FAIL ÉCHEC · $NON_EVALUE NON ÉVALUÉ"
echo "=============================="
[ "$FAIL" -eq 0 ] || exit 1
[ "$PASS" -gt 0 ] || exit 77        # rien mesuré du tout = non évalué, jamais un vert
exit 0
