#!/usr/bin/env bash
# Bootstrap de l'environnement de test — armement REPRODUCTIBLE, rien par défaut.
#
# POURQUOI CE SCRIPT EXISTE
#   1. Dans cet environnement de travail, les binaires installés hors du workspace et les
#      fichiers cachés (.git) ne survivent pas entre les sessions : tout doit pouvoir être
#      reconstruit de zéro.
#   2. Le workspace a un budget (128 Mo / 10 000 fichiers). Les binaires (OPA 44 Mo,
#      Gitleaks 21 Mo, Trivy 161 Mo) et la base de vulnérabilités Trivy (1,3 Go) sont donc
#      stockés HORS du workspace, dans ~/.cache/arena_secops.
#
# RÉGIME D'ARMEMENT (2026-08-31 — chantier devops, accord propriétaire explicite)
#   SANS FLAG : RIEN N'EST TÉLÉCHARGÉ. Le script vérifie ce qui existe déjà
#   (empreintes SHA-256 contre manifeste_dependances.yaml), prépare ce qui est LOCAL et
#   gratuit (points de montage, .git des fixtures), imprime l'état et s'arrête.
#   Télécharger exige une demande explicite :  bash PHASE3/bootstrap.sh --armement opa
#   Un composant dont la source est injoignable ÉCHOUE en le disant (source épinglée,
#   raison, conduite à tenir) — jamais de silence, jamais de version de substitution.
#
#   Composants : systeme monteurs fixtures opa outils-pip eslint regles-semgrep
#                trivy trivy-db gitleaks grype kics tout
#   --liste    : tableau d'état par composant (aucun téléchargement), code 0.
#   Idempotent : relancer ne retélécharge pas ce qui est déjà présent ET conforme à
#   son empreinte ; un binaire présent mais divergent est REFUSÉ (à supprimer à la main).
#
# Le workspace ne contient que : code, docs, tests, fixtures.
set -euo pipefail

B="$(cd "$(dirname "$0")" && pwd)"
C="${ARENA_SECOPS_CACHE:-$HOME/.cache/arena_secops}"
BIN="$C/bin"
RULES="$C/rules"
TRIVY_DB="$C/trivy-cache"

log(){ printf '\033[36m==>\033[0m %s\n' "$1"; }
ok(){ printf '\033[32m  OK\033[0m  %s\n' "$1"; }
err(){ printf '\033[31mERREUR\033[0m %s\n' "$1" >&2; }
mkdir -p "$BIN" "$RULES"

MANIFESTE="$B/manifeste_dependances.yaml"

# ---------------------------------------------------------------- vérification
# Un cache externe non vérifié n'est pas une reconstruction reproductible : il peut
# contenir un binaire inattendu. On vérifie le SHA-256 contre le manifeste, et on
# REFUSE un binaire qui ne correspond pas au lieu de l'utiliser.
sha_attendu() {  # sha_attendu <section> <nom>
  # Le `2>/dev/null` qui suivait cette commande a été RETIRÉ le 2026-08-30 (mesuré par
  # test_bootstrap.sh) : sans PyYAML, `python3` échouait en silence, `attendu` revenait vide,
  # `verifier_binaire` y lisait « aucune empreinte épinglée » et bootstrap déclarait
  # « environnement prêt » SANS AVOIR VÉRIFIÉ UN SEUL BINAIRE. Un manifeste illisible est une
  # panne de vérification, pas une absence d'exigence — l'absence d'empreinte doit rester un
  # choix du manifeste (sha256: null), jamais un accident d'environnement.
  python3 -c "
import sys, yaml
m = yaml.safe_load(open('$MANIFESTE', encoding='utf-8'))
print((m.get(sys.argv[1], {}).get(sys.argv[2]) or {}).get('sha256') or '')
" "$1" "$2"
}

# champ_manifeste <section> <nom> <clé> — version, source… même autorité que sha_attendu :
# le manifeste est la SEULE source de vérité des versions épinglées (plus de constante de
# version dans ce script : la dérive « script dit 1.20.0, manifeste épingle 0.70.0 » est
# mesurée — OPA, 2026-08-30/31 — elle ne peut plus se produire).
champ_manifeste() {
  python3 -c "
import sys, yaml
m = yaml.safe_load(open('$MANIFESTE', encoding='utf-8'))
print((m.get(sys.argv[1], {}).get(sys.argv[2]) or {}).get(sys.argv[3]) or '')
" "$1" "$2" "$3"
}

verifier_binaire() {  # verifier_binaire <nom> <chemin>
  local nom="$1" chemin="$2" attendu reel
  [ -f "$chemin" ] || return 0
  [ -f "$MANIFESTE" ] || { err "manifeste absent : $MANIFESTE"; return 1; }
  if ! attendu=$(sha_attendu binaires "$nom"); then
    err "$nom : manifeste illisible ($MANIFESTE) — la vérification d'empreinte n'a pas pu avoir lieu"
    err "  requis : python3 + PyYAML · sudo apt-get install -y python3-yaml"
    return 1
  fi
  [ -z "$attendu" ] && return 0        # aucune empreinte épinglée pour CE nom : choix du manifeste
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

# Pré-vérification de ce qui est DÉJÀ dans le cache — dans tous les modes, avant toute
# action. (La borne de sourcing de test_bootstrap.sh est la ligne `for` ci-dessous :
# tout ce qui précède — et rien de ce qui suit — est exécuté au sourcing.)
for b in trivy gitleaks opa grype kics shellcheck hadolint shellcheck_scan hadolint_scan; do
  verifier_binaire "$b" "$BIN/$b" || exit 1
done

# ================================================================= parsing des demandes
ARMEMENTS=()
MODE_LISTE=0
usage() {
  cat <<'FIN'
Usage : bootstrap.sh                 vérification seule — RIEN n'est téléchargé
        bootstrap.sh --armement X    arme X (répétable, ou liste séparée par des virgules)
        bootstrap.sh --liste         état par composant (aucun téléchargement)
Composants :
  systeme          bwrap + uidmap via apt (sudo -n)
  monteurs         points de montage bwrap + gitconfig (local, fait dans tous les modes)
  fixtures         .git des fixtures de test (local, fait dans tous les modes)
  opa              moteur de décision (paquet npm épinglé — lire le manifeste)
  outils-pip       semgrep, bandit, checkov, detect-secrets, radon, pip-audit, ruff,
                   trufflehog3 — versions épinglées lues dans le manifeste
  eslint           eslint via npm, dans le pool (pas en global)
  regles-semgrep   jeux python / security-audit / javascript / golang (semgrep.dev)
  trivy / trivy-db scanner + sa base de vulnérabilités (1,3 Go hors workspace)
  gitleaks / grype / kics   binaires des releases GitHub (+ requêtes kics, base grype)
  shellcheck / hadolint   linters passifs + wrappers de récursion versionnés (empreintes au manifeste)
  tout             tous les composants ci-dessus, dans cet ordre
FIN
}
while [ $# -gt 0 ]; do
  case "$1" in
    --armement)
      [ $# -ge 2 ] || { err "--armement attend un nom de composant (voir --aide)"; exit 1; }
      IFS=',' read -ra _a <<< "$2"; ARMEMENTS+=("${_a[@]}"); shift 2;;
    --armement=*) IFS=',' read -ra _a <<< "${1#*=}"; ARMEMENTS+=("${_a[@]}"); shift;;
    --liste) MODE_LISTE=1; shift;;
    --aide|-h|--help) usage; exit 0;;
    *) err "argument inconnu : $1"; usage >&2; exit 1;;
  esac
done
[ "${#ARMEMENTS[@]}" -eq 0 ] && [ "$MODE_LISTE" -eq 0 ] && MODE_LISTE=1   # défaut : état, rien de plus

demande() { local d; for d in "${ARMEMENTS[@]:-}"; do [ "$d" = "$1" ] && return 0; done; return 1; }
demande_tout() { demande tout; }
voulu() { demande "$1" || demande_tout; }

# ---------------------------------------------------------------- helpers d'armement
epingle() {  # epingle <binaire> <champ> → valeur ou refus explicite (pas de repli inventé)
  local v
  if ! v=$(champ_manifeste binaires "$1" "$2") || [ -z "$v" ]; then
    err "$1 : champ '$2' illisible dans $MANIFESTE — python3 + PyYAML requis, entrée manifeste complète exigée"
    return 1
  fi
  printf '%s' "$v"
}

telecharge() {  # telecharge <url> <dest> — échec PROPRE et explicite, jamais de tronçon muet
  local url="$1" dest="$2"
  curl -fsSL --max-time 300 -o "$dest" "$url" || {
    err "téléchargement impossible : $url"
    err "  réseau absent, ou source injoignable depuis cette machine — l'épingle n'est PAS contournée :"
    err "  aucune autre version ni aucune autre source ne sera installée à la place."
    return 1
  }
  [ -s "$dest" ] || { err "artefact vide : $url"; rm -f "$dest"; return 1; }
}

verifier_archive() {  # verifier_archive <nom> <fichier> — audit du canal si le manifeste épingle l'archive
  local nom="$1" f="$2" attendu reel
  attendu=$(champ_manifeste binaires "$nom" tarball_sha256 2>/dev/null) || attendu=""
  [ -z "$attendu" ] && return 0
  reel=$(sha256sum "$f" | cut -d' ' -f1)
  if [ "$reel" != "$attendu" ]; then
    err "$nom : SHA-256 de l'archive téléchargée inattendu (canal de distribution divergent)"
    err "  attendu : $attendu"; err "  obtenu  : $reel"; err "  archive REFUSÉE"
    return 1
  fi
}

ARM_ECHECS=()
tenter() {  # tenter <nom> <fonction> — un composant qui échoue n'arrête PAS les suivants
  local nom="$1" fn="$2"
  if "$fn"; then ok "$nom"; else ARM_ECHECS+=("$nom"); fi
}

# ---------------------------------------------------------------- composants
preparer_monteurs() {
  # bwrap ne peut pas créer un point de montage sous une racine déjà montée en lecture
  # seule : toutes les cibles de --ro-bind et --bind doivent exister AVANT l'appel.
  # Ce sont des répertoires VIDES : quelques octets, ils restent dans le workspace.
  mkdir -p "$B/mt-scan" "$B/mt-regles" "$B/mt-db" "$B/mt-out" "$B/run"
  touch "$B/gitconfig.ro"
  printf '[safe]\n\tdirectory = *\n' > "$B/gitconfig"
  ok "monteurs (mt-*, gitconfig) — local, rien téléchargé"
}

preparer_fixtures() {
  # Le .git ne survit pas aux sessions : recréé à chaque bootstrap. Local, aucun réseau.
  local F
  for F in "$B/testrepo" "$B/testrepo_xtool" "$B/testrepo_go"; do
    [ -d "$F" ] || continue
    if [ ! -d "$F/.git" ]; then
      log "fixture : recréation du dépôt git dans $(basename "$F")"
      ( cd "$F" && git init -q . && git config user.email test@test.local \
        && git config user.name test && git add -A && git commit -qm "fixture de test" )
    fi
  done
  ok "fixtures (.git) — local, rien téléchargé"
}

armer_systeme() {
  # bubblewrap est installé par apt, et apt n'est PAS persistant entre les sessions :
  # sans cette étape, tous les tests d'exécution tombent sur « bwrap: No such file ».
  command -v bwrap >/dev/null 2>&1 && { ok "bwrap : déjà présent ($(command -v bwrap))"; return 0; }
  log "bubblewrap (apt)"
  # `sudo -n` ne marche QUE sans mot de passe : sur un poste neuf (WSL fraichement installé),
  # sudo demande le mot de passe, l'option `-n` fait échouer la commande, et le message
  # d'avant se bornait à dire « les tests échoueront » — sans dire quoi taper. C'est le
  # premier écueil réel du premier lancement, il doit être nommable depuis la sortie.
  sudo -n apt-get install -y -qq bubblewrap uidmap >/dev/null 2>&1 || {
    # Ni le paquet ni l'effet noyau ne sont en notre pouvoir depuis ce sandbox : mesuré le
    # 2026-08-31, deb.debian.org est injoignable ici, et kernel.apparmor_restrict_unprivileged_userns
    # refuse les user namespaces. L'impossibilité est DITE (RUNBOOK_ENVIRONNEMENT.md), pas maquillée.
    err "bubblewrap non installé — sans lui, AUCUN outil ne tourne (l'isolateur refuse avant tout Popen)"
    err "  à lancer à la main : sudo apt-get update && sudo apt-get install -y bubblewrap uidmap"
    err "  puis revérifier :    bash PHASE3/test_bwrap.sh   (0 = prêt · 77 = rien de mesuré · 1 = bloqué, la cause est affichée)"
    err "  note sandbox : même installé, des user namespaces refusés par le noyau (apparmor_restrict_unprivileged_userns=1)"
    err "               le rendent inutilisable ici — LIMITATION DOCUMENTÉE, pas un défaut de ce script."
    return 1
  }
}

armer_opa() {
  # MOTEUR de décision. L'amont (openpolicyagent.org) et les assets de release GitHub sont
  # INJOIGNABLES depuis certaines machines (mesuré 2026-08-30, revérifié 2026-08-31) —
  # le manifeste épingle un binaire 0.70.0 porté par un paquet npm tiers, avec la
  # justification complète et ce qui a été vérifié. Ici : télécharger la SOURCE épinglée,
  # vérifier l'archive si le manifeste la fige, poser le binaire, laisser
  # verifier_binaire REFUSER toute divergence. Aucune autre source n'est tentée.
  if [ -x "$BIN/opa" ]; then ok "opa : déjà présent (conformité vérifiée en fin de script)"; return 0; fi
  local version source tgz
  version=$(epingle opa version) || return 1
  source=$(epingle opa source) || return 1
  log "opa $version (source épinglée du manifeste — ré-épinglage justifié dans manifeste_dependances.yaml)"
  tgz="$(mktemp /tmp/opa-archive.XXXXXX.tgz)"
  telecharge "$source" "$tgz" || { rm -f "$tgz"; return 1; }
  verifier_archive opa "$tgz" || { rm -f "$tgz"; return 1; }
  local ext; ext="$(mktemp -d /tmp/opa-extract.XXXXXX)"
  tar -xzf "$tgz" -C "$ext" 2>/dev/null || { err "opa : archive illisible (pas un tar.gz ?)"; rm -rf "$tgz" "$ext"; return 1; }
  local trouve; trouve="$(find "$ext" -type f -name opa | head -1)"
  if [ -z "$trouve" ]; then
    err "opa : aucun binaire « opa » dans l'archive épinglée ($source) — contenu inattendu, rien installé"
    rm -rf "$tgz" "$ext"; return 1
  fi
  cp "$trouve" "$BIN/opa" && chmod +x "$BIN/opa"
  rm -rf "$tgz" "$ext"
  verifier_binaire opa "$BIN/opa"   # empreinte du binaire posé : refuse la moindre divergence
}

armer_outils_pip() {
  # Versions lues dans le manifeste — la porte d'épinglage. Régime « venv actif respecté » :
  # l'installation va dans l'environnement de `python3` courant (activer /tmp/agnt-venv ou
  # équivalent AVANT si l'on veut un pool jetable ; voir RUNBOOK_ENVIRONNEMENT.md).
  local t pkg version rc=0
  for t in semgrep bandit checkov detect-secrets radon pip-audit ruff trufflehog3; do
    pkg=$(epingle "$t" package 2>/dev/null) || pkg=""
    [ -z "$pkg" ] && pkg="$t"
    version=$(epingle "$t" version) || return 1
    if command -v "$t" >/dev/null 2>&1; then ok "$t : déjà présent ($(command -v "$t"))"; continue; fi
    log "$t $version (pip → $(python3 -c 'import sys; print(sys.prefix)'))"
    python3 -m pip install --quiet "$pkg==$version" || {
      err "$t : pip install $pkg==$version a échoué (réseau absent ou PyPI injoignable) — version épinglée NON contournée"
      rc=1
    }
  done
  return $rc
}

armer_eslint() {
  local version
  version=$(epingle eslint version) || return 1
  # eslint : seul outil du catalogue passé par npm (registry joignable ici, contrairement aux
  # assets GitHub). Il vit dans le POOL, pas dans le PATH : `npm install -g` échoue sur une
  # machine sans droits, et un outil de scan n'a rien à faire dans l'environnement système.
  if ! command -v npm >/dev/null 2>&1; then
    err "npm absent — eslint (et le provider npm_audit) ne peuvent pas être armés ici"
    err "  node/npm s'installent avec le système (nvm, apt nodejs…) : hors périmètre de ce script, signalé, pas masqué"
    return 1
  fi
  [ -x "$BIN/eslint" ] && { ok "eslint : déjà présent"; return 0; }
  log "eslint $version (npm, dans le pool)"
  npm install --no-audit --no-fund --prefix "$C/node" "eslint@$version" || {
    err "eslint : npm install a échoué (registry.npmjs.org injoignable ?)"
    return 1
  }
  printf '#!/bin/sh\nexec env NODE_PATH="%s/node/node_modules" node %s/node/node_modules/eslint/bin/eslint.js "$@"\n' "$C" "$C" > "$BIN/eslint"
  chmod +x "$BIN/eslint"
}

armer_regles_semgrep() {
  # Jeux ÉPINGLÉS par empreinte (section `regles` du manifeste) : le jeu p/ci produisait un
  # scan vide sur nos fixtures (160 règles, 0 résultat) — changer de jeu change ce qui est
  # détecté, donc seule la source épinglée est tentée. semgrep.dev est injoignable depuis
  # certains réseaux (mesuré 2026-08-31) : l'échec est alors explicite, jamais substitué.
  local r rc=0
  for r in python security-audit javascript golang; do
    [ -s "$RULES/$r.yaml" ] && { ok "règles p/$r : déjà présentes"; continue; }
    log "règles Semgrep p/$r"
    telecharge "https://semgrep.dev/c/p/$r" "$RULES/$r.yaml" || {
      err "règles p/$r NON armées — semgrep.dev injoignable → SAST semgrep partiel (le doctor le dira)"
      rc=1
    }
  done
  return $rc
}

armer_trivy() {
  local version
  version=$(epingle trivy version) || return 1
  [ -x "$BIN/trivy" ] && { ok "trivy : déjà présent"; return 0; }
  log "trivy $version"
  # install.sh vit sur raw.githubusercontent.com — injoignable depuis certains réseaux
  # (mesuré 2026-08-31) : on le télécharge dans un FICHIER, jamais curl|sh, et l'échec est explicite.
  local inst; inst="$(mktemp /tmp/trivy-install.XXXXXX.sh)"
  telecharge "https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh" "$inst" || { rm -f "$inst"; return 1; }
  sh "$inst" -b "$BIN" >/dev/null || { rm -f "$inst"; err "trivy : install.sh a échoué (assets GitHub injoignables ?)"; return 1; }
  rm -f "$inst"
}

armer_trivy_db() {
  # 1,3 Go, hors workspace. Sans elle Trivy échoue : « --skip-db-update cannot be specified
  # on the first run ». Source : mirror.gcr.io — injoignable depuis certains réseaux (mesuré).
  [ -d "$TRIVY_DB/trivy/db" ] && { ok "base trivy : déjà présente"; return 0; }
  [ -x "$BIN/trivy" ] || { err "base trivy : le binaire trivy est requis d'abord (--armement trivy)"; return 1; }
  log "base de vulnérabilités Trivy (1,3 Go, hors workspace)"
  XDG_CACHE_HOME="$TRIVY_DB" "$BIN/trivy" image --download-db-only --no-progress >/dev/null || {
    err "base trivy NON armée — mirror.gcr.io injoignable ou téléchargement interrompu ; rien n'a été substitué"
    return 1
  }
}

armer_gitleaks() {
  local version
  version=$(epingle gitleaks version) || return 1
  [ -x "$BIN/gitleaks" ] && { ok "gitleaks : déjà présent"; return 0; }
  log "gitleaks $version"
  # Assets de release GitHub : redirigés vers release-assets.githubusercontent.com,
  # injoignable depuis certains réseaux (mesuré 2026-08-31). Échec explicite, pas de contour.
  local tgz; tgz="$(mktemp /tmp/gitleaks.XXXXXX.tgz)"
  telecharge "https://github.com/gitleaks/gitleaks/releases/download/v$version/gitleaks_${version}_linux_x64.tar.gz" "$tgz" || { rm -f "$tgz"; return 1; }
  verifier_archive gitleaks "$tgz" || { rm -f "$tgz"; return 1; }
  tar -xzf "$tgz" -C "$BIN" gitleaks || { rm -f "$tgz"; err "gitleaks : archive inattendue (binaire absent du tarball)"; return 1; }
  rm -f "$tgz"
}

armer_grype() {
  local version
  version=$(epingle grype version) || return 1
  [ -x "$BIN/grype" ] || {
    log "grype $version"
    local tgz; tgz="$(mktemp /tmp/grype.XXXXXX.tgz)"
    telecharge "https://github.com/anchore/grype/releases/download/v$version/grype_${version}_linux_amd64.tar.gz" "$tgz" || { rm -f "$tgz"; return 1; }
    verifier_archive grype "$tgz" || { rm -f "$tgz"; return 1; }
    tar -xzf "$tgz" -C "$BIN" grype || { rm -f "$tgz"; err "grype : archive inattendue"; return 1; }
    rm -f "$tgz"
  }
  # Base grype (~2 Go) sous trivy-cache/grype : portée par le montage M_DB existant.
  if [ ! -d "$TRIVY_DB/grype" ]; then
    log "base de vulnérabilités grype (hors workspace)"
    GRYPE_DB_CACHE_DIR="$TRIVY_DB/grype" "$BIN/grype" db update >/dev/null || {
      err "base grype NON armée — téléchargement impossible ; le binaire, lui, est en place et vérifié"
      return 1
    }
  fi
}

armer_kics() {
  local version
  version=$(epingle kics version) || return 1
  [ -x "$BIN/kics" ] || {
    log "kics $version"
    local tgz; tgz="$(mktemp /tmp/kics.XXXXXX.tgz)"
    telecharge "https://github.com/Checkmarx/kics/releases/download/v$version/kics_${version}_linux_amd64.tar.gz" "$tgz" || { rm -f "$tgz"; return 1; }
    verifier_archive kics "$tgz" || { rm -f "$tgz"; return 1; }
    tar -xzf "$tgz" -C "$BIN" kics || { rm -f "$tgz"; err "kics : archive inattendue"; return 1; }
    rm -f "$tgz"
  }
  # Bibliothèque de requêtes kics (1810 fichiers OPA) : PAS dans le tarball binaire
  # (mesuré le 2026-08-29 : 3 entrées — LICENSE, README, kics). Asset officiel
  # extracted-info.zip, sha256 épinglé. Sans elle : « unable to find queries ».
  if [ ! -d "$RULES/kics/queries" ]; then
    log "bibliothèque de requêtes kics (extracted-info.zip)"
    local zip; zip="$(mktemp /tmp/kics-info.XXXXXX.zip)"
    telecharge "https://github.com/Checkmarx/kics/releases/download/v$version/extracted-info.zip" "$zip" || { rm -f "$zip"; return 1; }
    local attendu reel
    attendu=$(epingle kics rules_asset_sha256) || { rm -f "$zip"; return 1; }
    reel=$(sha256sum "$zip" | cut -d' ' -f1)
    [ "$reel" = "$attendu" ] || { err "kics : extracted-info.zip SHA-256 inattendu ($reel ≠ $attendu) — REFUSÉ"; rm -f "$zip"; return 1; }
    rm -rf /tmp/kics-assets && mkdir -p /tmp/kics-assets
    (cd /tmp/kics-assets && unzip -q "$zip" "assets/queries/*")
    mkdir -p "$RULES/kics"
    cp -r /tmp/kics-assets/assets/queries "$RULES/kics/queries"
    rm -f "$zip"
  fi
}

armer_shellcheck() {
  local version
  version=$(epingle shellcheck version) || return 1
  [ -x "$BIN/shellcheck" ] || {
    log "shellcheck $version"
    local txz; txz="$(mktemp /tmp/shellcheck.XXXXXX.tar.xz)"
    telecharge "https://github.com/koalaman/shellcheck/releases/download/v$version/shellcheck-v$version.linux.x86_64.tar.xz" "$txz" || { rm -f "$txz"; return 1; }
    verifier_archive shellcheck "$txz" || { rm -f "$txz"; return 1; }
    tar -xJf "$txz" -C "$BIN" --strip-components=1 shellcheck-v$version/shellcheck || {
      rm -f "$txz"; err "shellcheck : archive inattendue (binaire absent du tarball)"; return 1; }
    rm -f "$txz"
  }
  # Wrapper de récursion : shellcheck ne scanne pas un répertoire (mesuré 2026-09-01 :
  # rc=2 « inappropriate type »). Contenu VERSIONNÉ ici, empreinte épinglée au
  # manifeste (shellcheck_scan) — réécrit à chaque exécution (contenu déterministe,
  # pas un artefact téléchargé) puis vérifié par la boucle du bas : modifier le
  # contenu ici sans re-épingler REFUSE l'environnement.
  cat > "$BIN/shellcheck_scan" << 'FIN_SCANNER'
#!/bin/sh
# Wrapper de récursion pour shellcheck — shellcheck ne prend pas de répertoire
# (mesuré 2026-09-01 : rc=2 « inappropriate type »). Contenu VERSIONNÉ dans
# bootstrap.sh et épinglé par empreinte dans manifeste_dependances.yaml ;
# installé par bootstrap.sh à côté du binaire.
#
# Usage : shellcheck_scan <rep_cible> <fichier_sortie_json>
#   · aucun .sh/.bash → fichier de sortie VIDE, rc=0 (rien à scanner ; en
#     pratique l'applicabilité a déjà écarté cette cible — jamais « 0 constat »
#     d'un scan qui aurait dû avoir lieu)
#   · xargs -r : jamais de shellcheck sans argument (sinon lecture de stdin)
#   · -S style : les findings de style sont inclus, avec leur niveau d'origine
#   · rc=10 : la sortie n'est pas du JSON valide (troncature, outil qui parle
#     sur stdout) — un rc hors vocabulaire de shellcheck (0-4), jamais un 0
#     fabriqué sur une sortie illisible
DIR=$(dirname "$0")
if [ -z "$(find "$1" -type f \( -name '*.sh' -o -name '*.bash' \) -print -quit)" ]; then
  : > "$2"
  exit 0
fi
find "$1" -type f \( -name '*.sh' -o -name '*.bash' \) -print0 \
  | xargs -0 -r "$DIR/shellcheck" -f json -S style > "$2"
python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$2" || exit 10
exit 0
FIN_SCANNER
  chmod +x "$BIN/shellcheck_scan"
}

armer_hadolint() {
  local version
  version=$(epingle hadolint version) || return 1
  [ -x "$BIN/hadolint" ] || {
    log "hadolint $version"
    local dest; dest="$(mktemp /tmp/hadolint.XXXXXX.bin)"
    telecharge "https://github.com/hadolint/hadolint/releases/download/v$version/hadolint-linux-x86_64" "$dest" || { rm -f "$dest"; return 1; }
    # L'asset EST le binaire (non compressé) : l'empreinte du « tarball » vaut pour
    # le binaire ; la pose se fait par déplacement, pas par extraction.
    verifier_archive hadolint "$dest" || { rm -f "$dest"; return 1; }
    mv "$dest" "$BIN/hadolint"
    chmod +x "$BIN/hadolint"
  }
  # Wrapper hadolint_scan : contenu VERSIONNÉ (même politique que shellcheck_scan).
  cat > "$BIN/hadolint_scan" << 'FIN_SCANNER'
#!/bin/sh
# Wrapper de récursion pour hadolint — pas de mode répertoire en 2.15.1 (mesuré
# 2026-09-01 : « Invalid option --recursive »). Contenu VERSIONNÉ dans
# bootstrap.sh et épinglé par empreinte ; installé par bootstrap.sh.
#
# Usage : hadolint_scan <rep_cible> <fichier_sortie_json>
#   · --no-fail : rc=0 dès que les findings sont écrits — un rc=1 de hadolint
#     nu vient d'un autre défaut (fichier absent) et ne doit PAS se lire
#     « 0 constat » ; d'où la validation JSON ci-dessous
#   · aucun Dockerfile* → fichier de sortie VIDE, rc=0 (applicabilité déjà passée)
#   · rc=10 : sortie non JSON valide — hors vocabulaire hadolint, jamais un 0 fabriqué
DIR=$(dirname "$0")
if [ -z "$(find "$1" -type f \( -name 'Dockerfile' -o -name 'Dockerfile.*' \) -print -quit)" ]; then
  : > "$2"
  exit 0
fi
find "$1" -type f \( -name 'Dockerfile' -o -name 'Dockerfile.*' \) -print0 \
  | xargs -0 -r "$DIR/hadolint" --no-fail --format json > "$2"
python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$2" || exit 10
exit 0
FIN_SCANNER
  chmod +x "$BIN/hadolint_scan"
}

# ---------------------------------------------------------------- préparations locales
# Locales et gratuites : faites dans TOUS les modes (y compris la vérification seule) —
# elles sont le prérequis de l'isolateur, pas un téléchargement.
preparer_monteurs
preparer_fixtures

# chmod concentré : uniquement après une pose de binaire vérifiée (armement), pas en aveugle.

# ---------------------------------------------------------------- mode --liste (défaut)
if [ "$MODE_LISTE" -eq 1 ] && [ "${#ARMEMENTS[@]}" -eq 0 ]; then
  log "vérification seule — RIEN n'a été téléchargé (armement : --armement <composant>, --aide pour la liste)"
  etat_binaire() {  # présent+conforme / présent+DIVERGENT / absent
    local n="$1"
    if [ ! -f "$BIN/$n" ]; then printf 'absent'; return; fi
    local a r; a=$(sha_attendu binaires "$n" 2>/dev/null) || a=""
    if [ -z "$a" ]; then printf 'présent (empreinte non épinglée)'; return; fi
    r=$(sha256sum "$BIN/$n" | cut -d' ' -f1)
    [ "$r" = "$a" ] && printf 'présent, conforme' || printf 'DIVERGENT (refusé à l’exécution)'
  }
  printf '  %-22s %s\n' "opa ($(champ_manifeste binaires opa version 2>/dev/null || echo '?'))" "$(etat_binaire opa)"
  printf '  %-22s %s\n' "trivy" "$(etat_binaire trivy)"
  printf '  %-22s %s\n' "gitleaks" "$(etat_binaire gitleaks)"
  printf '  %-22s %s\n' "grype" "$(etat_binaire grype)"
  printf '  %-22s %s\n' "kics" "$(etat_binaire kics)"
  printf '  %-22s %s
' "shellcheck (+scan)" "$(etat_binaire shellcheck) / $(etat_binaire shellcheck_scan)"
  printf '  %-22s %s
' "hadolint (+scan)" "$(etat_binaire hadolint) / $(etat_binaire hadolint_scan)"
  for t in semgrep bandit checkov detect-secrets radon pip-audit ruff trufflehog3; do
    printf '  %-22s %s\n' "$t (pip)" "$(command -v "$t" >/dev/null 2>&1 && echo "présent ($(command -v "$t"))" || echo absent)"
  done
  printf '  %-22s %s\n' "eslint (npm, pool)" "$([ -x "$BIN/eslint" ] && echo présent || echo absent)"
  for r in python security-audit javascript golang; do
    printf '  %-22s %s\n' "règles p/$r" "$([ -s "$RULES/$r.yaml" ] && echo présentes || echo absentes)"
  done
  printf '  %-22s %s\n' "requêtes kics" "$([ -d "$RULES/kics/queries" ] && echo présentes || echo absentes)"
  printf '  %-22s %s\n' "base trivy" "$([ -d "$TRIVY_DB/trivy/db" ] && echo présente || echo absente)"
  printf '  %-22s %s\n' "base grype" "$([ -d "$TRIVY_DB/grype" ] && echo présente || echo absente)"
  printf '  %-22s %s\n' "bwrap (système)" "$(command -v bwrap >/dev/null 2>&1 && echo "présent ($(command -v bwrap))" || echo "absent — apt, et userns noyau à vérifier (RUNBOOK)")"
  echo "  ── la matrice des suites et la raison de chaque BLOCKED : python3 PHASE3/doctor.py"
  exit 0
fi

# ---------------------------------------------------------------- armement demandé
log "cache : $C"
voulu systeme        && tenter systeme armer_systeme
voulu opa            && tenter opa armer_opa
voulu outils-pip     && tenter outils-pip armer_outils_pip
voulu eslint         && tenter eslint armer_eslint
voulu regles-semgrep && tenter regles-semgrep armer_regles_semgrep
voulu trivy          && tenter trivy armer_trivy
voulu gitleaks       && tenter gitleaks armer_gitleaks
voulu grype          && tenter grype armer_grype
voulu kics           && tenter kics armer_kics
voulu shellcheck     && tenter shellcheck armer_shellcheck
voulu hadolint       && tenter hadolint armer_hadolint
voulu trivy-db       && tenter trivy-db armer_trivy_db

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

# ---------------------------------------------------------------- vérification APRÈS installation
# La boucle du haut ne juge que ce qui DÉJÀ dans le cache : sur une machine neuve, elle ne
# voit rien et passe (c'est voulu — l'absence n'est pas une divergence). Mais rien ne
# contrôlait ce que le script vient de télécharger lui-même : une réponse d'erreur écrite
# dans $BIN/opa (page HTML, troncature, miroir qui sert un autre artefact) partait sagement
# dans le cache, « environnement prêt » affiché. Même fonction, même politique : empreinte
# épinglée absente du manifeste = on n'invente rien ; présente et divergente = on refuse,
# avant de dire que l'environnement est prêt.
for b in trivy gitleaks opa grype kics shellcheck hadolint shellcheck_scan hadolint_scan; do
  verifier_binaire "$b" "$BIN/$b" || exit 1
done

# (placé ICI, après le dernier téléchargement — grype et kics sont installés plus bas que
#  trivy/gitleaks/opa, et une vérification placée entre les deux ne jugerait pas les seconds.)

if [ "${#ARM_ECHECS[@]}" -gt 0 ]; then
  err "armement incomplet : ${ARM_ECHECS[*]} — chaque cause est imprimée ci-dessus, rien n'a été substitué"
  exit 1
fi
log "environnement prêt (composants demandés)"
echo "    cache      : $C   ($(du -sh "$C" 2>/dev/null | cut -f1))"
echo "    workspace  : $(du -sh --exclude=.cache "$B/.." 2>/dev/null | cut -f1)  (hors cache)"
# Affichages de version : capture complète puis extraction de la ligne — aucun tube,
# donc aucune course SIGPIPE avec `set -o pipefail` (le 141 intermittent du
# 2026-08-28, que de simples `|| true` ne feraient que masquer).
[ -x "$BIN/trivy" ]    && { _v=$("$BIN/trivy" --version 2>/dev/null) && printf '%s\n' "${_v%%$'\n'*}" || true; }
[ -x "$BIN/gitleaks" ] && { "$BIN/gitleaks" version || true; }
[ -x "$BIN/opa" ]      && { _v=$("$BIN/opa" version 2>/dev/null) && printf '%s\n' "${_v%%$'\n'*}" || true; }
command -v semgrep >/dev/null 2>&1 && { _v=$(semgrep --version 2>/dev/null) && printf '%s\n' "${_v##*$'\n'}" || true; }
true
