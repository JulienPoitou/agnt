# Mode Laboratoire Propriétaire — contrôle d'admission (P2)

Statut : livré (commit isolé, voir `git log -1 --stat` / handoff AGNT v1).
Périmètre : **point de garde Security pur** — aucun exécuteur, aucune
exécution d'outil, aucune modification du pipeline, du Transport, de la
Cible, des contrats Product, de l'API History, de l'UI ou du gate re-lié.

---

## 1. Ce que ce module est

`PHASE3/mode_laboratoire.py` est un **contrôle d'admission** déterministe :
il répond à une seule question — *« cette session laboratoire demandée
localement par l'opérateur propriétaire est-elle admissible ? »* — avec les
capacités **déjà autorisées** par AGNT et **aucune** protection désactivée.

Il ne lit ni `argv`, ni aucune donnée de cible, ni fixture, ni journal, ni
artefact. Il ne lance aucun binaire, n'ouvre aucun socket, n'écrit rien hors
de l'audit renvoyé. Il ne modifie aucun fichier de garde existant : il les
**exige tous** (sandbox, policy, intégrité des empreintes, garde de chemin,
P0.1 `cible_autorisee`, registre des cibles, redaction).

Il est volontairement **hors pipeline** : l'activation réelle (runner/CLI
locale) est un développement hors périmètre CORE, à décider séparément. Ce
module fournit la **décision** ; il ne fournit pas le moyen de l'exécuter.

## 2. Design — activation locale double

Deux facteurs, tous deux **locaux opérateur**, tous deux requis, aucun
n'étant transportable par une entrée non locale :

| Facteur | Forme | Contrôles |
|---|---|---|
| F1 — connaissance | jeton CLI locale `cli-<aléatoire 32..128 [A-Za-z0-9_-]>` | comparaison **temps constant** (`hmac.compare_digest`) contre la config locale ; chaîne vide ⇒ `optin-cli-sans-config` |
| F2 — possession | fichier-bloc régulier `0600` **exact** (`& 0o077 == 0`), détenu par l'UID courant, sous `racine_conf`, **hors de toute racine de cible**, sans symlink, contenu `agnt-labo-optin-<aléatoire 32..128>` | lecture + contrôle de format ; jeton comparé en temps constant contre `jeton_fichier_attendu` ; jeton **jamais** renvoyé hors de la fonction de lecture |

Canal d'activation : `cli-local` **uniquement**. HTTP (corps ou en-tête),
LLM, navigateur/UI, données cible / fixture / journal / artefact, réponse MCP
ou provider tiers ⇒ `canal-interdit`. Le module ne charge jamais un contenu
de cible ; un fichier `optin` placé dans la cible est explicitement refusé
(`optin-fichier-dans-cible`) *et* ne peut pas activer quoi que ce soit.

Profil : `controlled_dev` uniquement (seul profil honnête d'après
`slice/profils.py`) ; `public`, `production`, `limites_a_prouver` et tout
profil inconnu ⇒ `profil-interdit`.

Cible : strictement locale, sous une racine explicitement contrôlée,
présente sur disque, inscrite dans le registre local avec
`autorisee is True` (P0.1), opérateur figurant dans `operateurs_autorises`.

## 3. Codes de refus (démontrés par le harnais)

- Opt-in : `optin-absent`, `optin-incomplet`, `optin-invalide`,
  `optin-cli-sans-config`, `optin-fichier-{absent, non-absolu, non-local,
  dans-cible, symlink, introuvable, etranger, permissif, illisible,
  invalide}`.
- Canal / profil : `canal-interdit`, `profil-interdit`.
- Egress : `egress-non-ferme`, `egress-global-interdit`.
- Capacités : `capacite-non-autorisee`, `provider-non-autorise`,
  `commande-libre-interdite`, `capacites-aucune`.
- Gardes : `policy-indisponible`, `policy-refusee`, `regles-absentes`,
  `integrite-divergente`, `sandbox-non-conforme`.
- Cible : `operateur-inconnu`, `cible-{absente, non-locale, traversal,
  non-absolue, hors-racine, symlink-sortant, non-autorisee}`,
  `aucune-racine`.

## 4. Fichiers touchés

- `PHASE3/mode_laboratoire.py` (nouveau) — le contrôle d'admission.
- `PHASE3/test_mode_laboratoire.py` (nouveau) — batterie déterministe
  (52 vérifications, `python3` **et** `.venv/bin/python`).
- `docs/coordination/MODE_LABORATOIRE.md` (ce document).
- `README.md` — pointeur d'une ligne vers ce document.

Aucun fichier `CORE/`, `MCP/`, `PHASE3/pipeline*`, `PHASE3/interface/`,
`PHASE3/analyse*`, `PHASE3/regles/`, `PHASE3/transport/`, contrats Product,
UI ou gate re-lié n'a été modifié (vérifié par `git status --porcelain`
avant commit et par le harnais).

## 5. Matrice de tests

| # | Section | Vérifications |
|---|---|---|
| 1 | baseline | désactivé par défaut ; absence d'opt-in = refus ; aucun état global actif |
| 2 | opt-in | double opt-in + fixture contrôlée ⇒ accepté ; 0/1 facteur refusé ; jeton invalide ; bloc permissif/symlink/hors conf/dans cible/contenu arbitraire/non absolu |
| 3 | canaux | http-corps, http-en-tête, llm, ui, cible, fixture, journal, artefact, mcp, provider, inconnu ⇒ refus ; cible gorgée de jetons n'active rien |
| 4 | cible | URL, `ssh://`, `//hôte`, `hôte:port`, scp-like `git@hôte:repo`, `file://`, traversal, hors racine, `~`, symlink sortant, absente, non autorisée, non absolue ; symlink interne accepté |
| 5 | profil | public/production/limites_a_prouver/inconnu/durci/utilisateur ⇒ refus |
| 6 | egress + capacités | egress demandé refusé ; egress global implicite refusé ; capacité/provider hors registre refusés ; commande libre refusée ; liste vide refusée ; IDs réels de `capabilities.yaml` acceptés |
| 7 | gardes existantes | policy indisponible/refusée, règles absentes, empreintes divergentes, sandbox non conforme ⇒ refus |
| 8 | conservation | contexte immuable ; registre/liste opérateur/`autorisee` conservés ; P0.1 (`cible_autorisee: bool = False`) intact |
| 9 | audit | aucun secret/jeton/argv/chemin absolu/payload dans la décision ni la synthèse ; empreintes 16 hex ; message de refus sans chemin |
| 10 | gardes intactes | `verifier_cible`/`CheminInterdit` disponibles ; `profils.actif()` = `controlled_dev` ; `limites_a_prouver` inutilisable ; `empreintes_conformes`/`Sandbox` présents ; aucun fichier de garde modifié |
| 11 | e2e | **NON ÉVALUÉ** si OPA/bwrap absents — jamais un PASS |

## 6. Refus démontrés (extraits)

```
REFUSE — [optin-absent] mode désactivé par défaut : le double opt-in local est requis
REFUSE — [canal-interdit] activation par un canal non local ... interdite
REFUSE — [cible-non-locale] cible distante (URL/hôte) interdite ...
REFUSE — [cible-traversal] traversée de répertoire interdite
REFUSE — [cible-symlink-sortant] lien symbolique sortant de la cible détecté
REFUSE — [profil-interdit] profil public, production ou incertain interdit
REFUSE — [egress-non-ferme] ouverture réseau demandée : le laboratoire garde l'egress fermé
REFUSE — [capacite-non-autorisee] capacité hors registre AGNT demandée
REFUSE — [integrite-divergente] empreintes de binaires ou de règles divergentes
```

## 7. Limites environnementales (explicites)

- **OPA absent, bwrap absent** dans cette sandbox : la preuve E2E de la
  porte bloquante existante (policy OPA + sandbox bwrap réels) est **NON
  ÉVALUÉE**. Aucun PASS n'est affirmé à sa place. La batterie P2 est
  volontairement pure et n'en dépend pas.
- **Gitleaks non exécuté** (binaire absent / OPA absent) : la détection de
  secrets réelle (G9) reste **NON RÉSOLUE** ; ce module ne l'affirme pas.
- **Runner/CLI d'activation réel non livré** : ce module ne lit ni `argv`
  réel ni données de cible ; le raccord est hors périmètre CORE et reste à
  décider.
- `capabilities.yaml` est la source de vérité des capacités ; sa lecture
  YAML nécessite `.venv/bin/python` (PyYAML absent du python3 global) — le
  module n'en dépend pas (les ensembles proviennent du canal local).

## 8. Confirmations

- Aucun bypass : toute la logique passe par la décision ; aucune porte de
  secours, aucun `if __debug__`, aucune exception qui accepte.
- URL distante : refusée (`^scheme://`, `//hôte`, `hôte:port`,
  `utilisateur@hôte:` en tête).
- Egress global : refusé — le module n'ouvre rien ; toute demande
  (explicite ou implicite) est un refus.
- Aucun merge / cherry-pick : branche isolée sur `arena/01a05426-agnt`,
  consultation de `origin/arena/01a05425-agnt` en lecture seule (P1).
- Aucun changement CORE / MCP / Product / Web / UI / policy / regles /
  manifests / gate re-lié.
- Aucune installation d'OPA/bwrap/scanner/dépendance système ; aucune
  ouverture d'URL ; aucun pilote Strix ; aucun serveur externe.
