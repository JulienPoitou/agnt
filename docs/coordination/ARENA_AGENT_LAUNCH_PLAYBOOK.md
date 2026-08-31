# ARENA AGENT LAUNCH PLAYBOOK

> Playbook de coordination pour la vague de lancement **V0 console dogfoodable**.
> Mainteneur : orchestrateur AGNT — session `arena/01a05944-agnt` (base `89bd3b1` = `origin/orchestrator` = `origin/main`).
> Créé le 2026-08-31. La mémoire de coordination vivante reste `docs/coordination/PROJECT_STATE.md` ; ce playbook décrit la **procédure de lancement** de la vague.

---

## 0. Objectif de la vague V0

Console web V0 réellement testable dans le navigateur par le propriétaire seul :

- lancer une mission depuis l'interface web ;
- suivre l'exécution ;
- voir un résultat ou un refus honnête ;
- revoir l'historique ;
- **sans** faux « 0 résultat », **sans** faux succès ;
- **sans** repartir dans des audits complets inutiles.

## 1. Règle absolue : 1 agent = 1 branche produit = 1 session Arena

- Jamais deux agents sur la même branche.
- Jamais un builder qui reprend la branche d'un autre.
- Jamais de merge / rebase / cherry-pick / force-push par un builder. L'intégration est décidée et réalisée par l'orchestrateur (ou le propriétaire), jamais builder↔builder.
- Arena crée souvent une branche de session `arena/...` dérivée de la branche produit choisie. Ce n'est **pas** un blocage : le builder vérifie que sa branche de session est bien dérivée de **sa** branche produit (même SHA de base), puis travaille dessus.
- Les branches partagées `arena/builder-*` (héritage de la collision Git du 30/08, figées à `4433af6`) sont **interdites** : personne ne travaille dessus.

## 2. Branches produit (vague V0)

Toutes alignées sur `89bd3b1` (= `origin/main`, PR #14 fusionnée) au 2026-08-31 :

| Rôle | Agent | Branche produit | Mission (résumé) | État |
|---|---|---|---|---|
| Coordination | ORCHESTRATOR | `orchestrator` | coordination, décisions, intégration | actif — session `arena/01a05944-agnt` (base `89bd3b1`) |
| Cœur | CORE-HAPPY-PATH | `core-console-v0` | cœur d'exécution, happy path honnête | **LIVRÉ** sur une branche Arena dérivée de `core-console-v0` — **pas de relance immédiate** |
| Lancement | DEVOPS-LAUNCH | `devops-launch-v0` | lancement local simple (une commande) | branch-check en attente |
| API | API-BFF | `api-bff-v0` | BFF console : lancer / suivre / résultat-refus / historique | branch-check en attente |
| Front | WEB-CONSOLE | `web-console-v0` | console navigateur utilisable branchée sur le BFF | branch-check en attente |
| Qualité | QA-DOGFOOD | `qa-gate-v0` | gate dogfood : scénario bout-en-bout rejouable | branch-check en attente |

## 3. État actuel du projet (2026-08-31)

- `main` (`89bd3b1`) contient déjà beaucoup de travail intégré, dont la ligne CORE (cœur d'exécution) et le front existant.
- Le front existe déjà : on ne repart **pas** de zéro, on ne refait **pas** l'interface.
- Le besoin : une console V0 dogfoodable — pas un audit global, pas une refonte.
- Mémoire de coordination détaillée : `docs/coordination/PROJECT_STATE.md` (source de vérité vivante).
- Handoffs reçus : `docs/coordination/handoffs/` (dont la ligne CORE).

## 4. Piège Git connu : refs locales limitées à `main`

Les sessions Arena clonent avec un refspec limité (`+refs/heads/main:refs/remotes/origin/main`).
Conséquence : `git log origin/<branche>` échoue (« unknown revision ») **même si la branche existe** sur le dépôt distant. Faux négatif déjà observé au démarrage de la session orchestrateur avec `origin/orchestrator`.

Commandes fiables pour vérifier une branche distante :

```bash
git fetch origin
git fetch origin <branche_produit>                 # met à jour FETCH_HEAD
git log -1 --oneline FETCH_HEAD                    # SHA réel de la branche produit
git ls-remote --heads origin <branche_produit>     # alternative sans ref locale
git merge-base --is-ancestor FETCH_HEAD HEAD && echo "BASE OK" || echo "BASE KO"
```

**Ne jamais conclure « branche inexistante » sans `git ls-remote`.**

## 5. Mini branch-check (AVANT toute mission — le builder ne modifie rien)

Prompt à envoyer tel quel (remplacer `{AGENT}` et `{BRANCHE_PRODUIT}`) :

```text
Tu es {AGENT}. Ta branche produit est {BRANCHE_PRODUIT}.
NE MODIFIE RIEN : n'écris aucun fichier, ne commit rien, ne pousse rien, pas de merge/rebase.
Exécute seulement ces commandes et rapporte leur sortie :
1. git fetch origin
2. git fetch origin {BRANCHE_PRODUIT}
3. git log -1 --oneline FETCH_HEAD
4. git status --short --branch
5. git branch --show-current
6. git merge-base --is-ancestor FETCH_HEAD HEAD && echo "BASE OK" || echo "BASE KO"
Puis réponds exactement :
- BRANCHE COURANTE:
- SHA origin/{BRANCHE_PRODUIT}:
- BASE: OK / KO
- PROPRE (aucune modification locale): OUI / NON
- VERDICT: BRANCH CHECK OK / BLOCKED
VERDICT = OK si et seulement si :
- la branche courante est {BRANCHE_PRODUIT} OU une branche arena/... avec BASE OK
  (une branche de session Arena dérivée de la bonne base n'est PAS un blocage) ;
- et le statut est propre.
Sinon BLOCKED, raison en une ligne. Si tu as déjà modifié des fichiers, réponds BLOCKED et dis-le.
```

Décision orchestrateur selon la réponse :

| Réponse du builder | Décision orchestrateur |
|---|---|
| `BRANCH CHECK OK` | envoyer la mission longue adaptée |
| `BLOCKED` (mauvaise branche / mauvaise base) | demander de relancer la session Arena sur la bonne branche produit — rien d'autre |
| fichiers déjà modifiés pendant le check | classer `NEED-FIX` |

## 6. Ordre de lancement des missions

1. **DEVOPS-LAUNCH** (`devops-launch-v0`) — lancement local simple : une commande démarre tout ; le propriétaire doit pouvoir lancer sans deviner.
2. **API-BFF** (`api-bff-v0`) — contrat + endpoints console : lancer une mission, suivre l'exécution, résultat/refus honnête, historique. Le contrat BFF est publié dans le handoff.
   *(1 et 2 peuvent se chevaucher : branches et sessions distinctes.)*
3. **WEB-CONSOLE** (`web-console-v0`) — brancher le front **existant** sur le BFF (contrat de l'étape 2). Pas de refonte d'UI.
4. **QA-DOGFOOD** (`qa-gate-v0`) — gate finale : scénario navigateur bout-en-bout rejouable (lancement → suivi → résultat ou refus honnête → historique), preuve fournie.
5. **CORE-HAPPY-PATH** — déjà livré : pas de relance immédiate.

Priorités :

- **P0** : console navigateur réellement utilisable ; lancement local simple ; résultat ou refus honnête ; historique lisible.
- **P1** : polish API/UI ; qualité de présentation ; preuves rejouables.
- **P2** : sécurité plus complète ; sophistication ultérieure ; prompts avancés supplémentaires.

## 7. Handoffs : comment nourrir l'orchestrateur

- Un rapport court par fin de mission, au format décision :

```text
STATUS: DONE / BLOCKED / NEED-FIX
AGENT:
BRANCH:      (branche de session arena/... + branche produit d'origine)
SHA:         (SHA poussé — le SHA est la preuve, avant le nom de branche)
LIVRABLE:    (une ligne)
VALIDATION:  (comment le propriétaire vérifie : commande ou URL, résultat attendu)
BLOCKERS:    (rien, ou liste courte)
NEXT:        (proposition courte)
```

- Rapport détaillé en fichier : `docs/coordination/handoffs/{AGENT}-{ref}-{AAAA-MM-JJ}.md`, avec le bloc existant `=== AGNT HANDOFF v1 ===` … `=== END AGNT HANDOFF ===` (agent, domaine, branche, statut, commits, livrables, tests PASS/FAIL/BLOCKED/NON ÉVALUÉ, blocages, périmètre non touché, confiance).
- Mission en cours : bloc `=== AGNT PROGRESS v1 ===`.
- Le builder pousse **sa** branche de session (`git push origin arena/<sa-session>`). Jamais de merge/rebase/cherry-pick/force-push, jamais sur la branche d'un autre.
- Rapport honnête : un échec ou un refus documenté vaut mieux qu'un succès inventé. Pas de faux « 0 résultat », pas de faux succès.

## 8. Règle « NO AUDIT LOOP »

Si un builder : a la bonne branche, a poussé, a livré quelque chose de cohérent → pas de boucle d'audit, pas de re-vérification en triple. On passe au chantier suivant.
Vérification orchestrateur = minimale : la branche/SHA existent, pas de collision évidente, le builder reste dans son périmètre, pas de merge/rebase/force-push.

## 9. Anti-collision — check-list rapide

- Un agent = une branche produit = une session Arena. Un agent ne touche qu'à **sa** branche de session.
- Ne jamais travailler sur `arena/builder-*` (branches partagées historiques, figées à `4433af6`).
- Ne jamais pousser sur `main`, `orchestrator`, ou la branche produit d'un autre.
- Avant de pousser : `git branch --show-current` pour confirmer sa propre branche de session.
- En cas de doute : rapporter `BLOCKED` avec la sortie brute des commandes — ne pas « réparer » Git soi-même.
