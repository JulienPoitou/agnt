# Audit bout-en-bout — transition par transition (2026-08-30)

Cet audit répond à une question que les suites unitaires laissent ouverte : à chaque
frontière, **ce qui entre ressort-il, dans le bon format, avec ses erreurs, et jusqu'à
l'écran ?** Ni les tests ni la relecture de code ne répondent à ça — un champ renommé d'un
côté, une liste devenue dictionnaire de l'autre, font une page vide sans faire rougir un
test. Chaque ligne est donc jugée par une exécution, et marquée :

    PROUVÉ        une mesure verte ici, sur ces données, et la mesure est falsifiable (le
                  correctif retiré, elle tombe)
    OBSERVÉ       vu tourner, pas couvert par une assertion durable
    NON ÉVALUÉ    injouable sur cette machine — la raison est dite, jamais remplacée par un « OK »

| # | Transition | Ce qui entre → ce qui sort | Erreurs et conservation | Verdict |
|---|---|---|---|---|
| 1 | Navigateur → `POST /api/runs` | `{cible, question, confiance, moteur, modele?}` → `202 {id, statut:"en_file", position}` | `400` sur JSON invalide, cible hors liste (+ liste des admises), question vide ou > `TAILLE_MAX_REQUETE`. La question voyage **sans retravail** vers l'intention | PROUVÉ — `test_interface.py` (31/31), et en réel par HTTP sur le port 8142 |
| 2 | API → `analyser.lancer()` | `(mission, Path(cible), moteur, confiance)` → `(code, resume)` | `PolicyError`/`SandboxError` remontées **telles quelles**, marquées dans le registre, jamais converties en erreur générique. `resume.motif` porte la cause | PROUVÉ — run réel : motif « binaire OPA introuvable » reçu à travers l'API |
| 3 | Requête → intention (déterministe ou LLM) | texte + registre → `Intent{statut, capacités, motifs, moteur}` | Réponse invalide, schéma invalide, erreur de transport → repli tracé `moteur="deterministe(repli:X)"`. Garde-fous `interdit()` **avant** la borne de taille ; `Intent.requete` garde le texte entier, `motifs["requete_bornee"]` dit ce qui a été tronqué | PROUVÉ — `test_garde_fous.py` (29/29), campagne A1-A10, E1-E3 |
| 4 | Capacités → providers (applicabilité) | capacités → providers + `exclus{motif}` | Aucun applicable → `arret="applicabilite"`, **pas** une panne. `plan.selection` garde choisis **et** écartés | PROUVÉ — `test_selection.py` (13/13), D3 ; écartés affichés (harnais) |
| 5 | Providers → plan typé | registre → `plan{plan_id, empreinte, steps[{capability, provider, commande, args, risque, sorties}], requete, requete_canonique}` | `PlanError` sur budget dépassé, drapeau inconnu, capacité hors catalogue. Aucun argv ne vient de la phrase | PROUVÉ — campagne B1-B7 ; `plan.json` réel relu par le harnais |
| 6 | Plan → politique (OPA) | plan + registre + `cible_autorisee` + confiance → `Decision{allow, motifs}` | `PolicyEngine.__init__` **lève** si le binaire manque : l'exception remonte ET, depuis aujourd'hui, la cause est consignée au journal (`pipeline._consigner_arret`, campagne E6, falsifié par `git stash`). Le refus décidé s'arrête avant tout outil, avec `profil` | PROUVÉ pour l'arrêt injoignable et le refus décidé ; **NON ÉVALUÉ** : une évaluation OPA réelle (binaire absent de cette machine) |
| 7 | Plan → garde de chemin | `commande + args` → autorisation ou `PathEscape` | Une remontée hors cible n'est jamais aplatie ; le refus est tracé dans la couverture, pas dans un message d'erreur | PROUVÉ — `test_chemins.py` (48/48), C3a |
| 8 | Garde → exécution sous bwrap | `Sandbox{racines, limites, empreintes}` → `Resultat{code, stdout, stderr, timeout}` + `couverture[provider]` | Outil absent, empreinte divergente, timeout → **entrée de couverture motivée**, jamais un trou ni un « 0 constat ». Environnement de l'outil borné (`environ_outil` : ni `HOME`, ni `PATH`, ni jeton) | PARTIELLEMENT PROUVÉ — G7/G8 PASS avec `bandit` réel installé par pip ; **NON ÉVALUÉ** sous bwrap (pas de `bwrap` installable ici, `apt` bloqué) |
| 9 | Sortie d'outil → findings | brut + manifest + `racines` → `Finding.to_dict()` | Provider déclaratif sans manifest → `KeyError` nommé (mesuré aujourd'hui : `normaliser()` prend un **id de provider**, pas un nom de fichier). Chemins relatifs à la cible ; secrets masqués à l'émission | PROUVÉ — `test_chemins.py`, `test_rapport_humain.py` (18/18), C1/C2/C6 |
| 10 | Findings → clustering | findings → `clusters.json{stats, clusters, clusters_inter_outils}` | `cluster_id` conservé mot pour mot jusqu'à l'écran (12/12 dans le harnais) ; findings absents → `findings_absents=true`, **pas** un compteur à zéro | PROUVÉ — harnais sur données réelles ; corrélation multi-outils déjà mesurée sur `requests`/`terraform-aws-vpc` |
| 11 | Exécution → deux rapports | `Execution` → `RAPPORT.md`, `rapport_humain.md`, findings/clusters/plan écrits | `OSError` du rendu remontée (pas de fichier partiel) ; les trois rendus passent par `rapport_humain.sur()` | PROUVÉ — `test_rapport_humain.py`, F6 + C3b (verdict à deux faces) |
| 12 | Archive → API → écran | dossier `sortie/` → `api._charger()` → `rendu()` | Fichier absent → clé absente et `findings_absents`, **jamais** de valeur comblée. Chaque finding (16/16), chaque cluster (12/12), chaque provider des steps, la requête, sa forme canonique, les empreintes et `run.sortie` ressortent à l'écran ; `textContent` partout | PROUVÉ — `_domtest.mjs` (48/48) sur artefacts réels, avec régression volontaire vérifiée (8 contrôles tombent quand le rendu est saboté) |
| 13 | API qui disparaît EN COURS de RUN | `GET /api/runs/<id>` rejette (serveur arrêté, connexion coupée) | C'était un **spinner éternel** : `json()` laissait la rejection remonter, la boucle `for(;;)` tournait sans fin, l'écran restait à « envoi… » puis « run x · ? ». Depuis le 2026-08-30 : le transport est ramené à `{ok:false, status:0}`, trois silences puis la cause est écrite, et la boucle se termine. Mesuré dans les deux états (avec le garde : 4 requêtes, sans : 400 — la borne du harnais, pas la sienne) | PROUVÉ — `_domtest.mjs`, scénarios `sert_puis_meurt` et `redemarre`, falsifiés par copie sabotée (`AGNT_APP_JS`) |
| 14 | File d'attente de l'API | deux `POST /api/runs` d'affilée → deux `id` distincts, un seul travailleur | Le partage critique est le répertoire `PHASE3/run/` des sorties brutes : deux missions simultanées s'y effaceraient l'une l'autre. La file est à un occupant par construction ; ses compteurs sont jugés (`position` = taille de file à l'insertion, mesurée `[1, 1]` — documenté à la ligne qui le produit). | PARTIEL — compteurs PROUVÉS (`test_interface.py`) ; **NON ÉVALUÉ** pour les octets écrits dans `run/` (aucune exécution d'outil possible ici) |

## Ce que l'audit laisse ouvert, en clair

1. **Aucune exécution réelle d'outil n'a eu lieu sur cette machine** : `bwrap` n'est pas
   installable ici et `opa` n'a pas pu être téléchargé. Les lignes 6 et 8 sont les deux seules
   où le chemin complet (isolateur + politique réelle + outil réel) n'est pas prouvé de bout en
   bout. Elles le seront au premier `bootstrap.sh` suivi d'un scan réel, et les contrôles qui doivent
   alors parler existent déjà : `test_isolateur.py`, `test_empreintes.py`, campagne G7/G8, D1.
2. **Les montages de l'isolateur étaient hors sol** (littéral `/home/user/PHASE3/…`) : corrigé
   aujourd'hui, sinon la ligne 8 échouait sur *toute* machine, y compris celle de l'auteur du doc.
3. **La décision F2 (`cible_autorisee`, campagne D4) attend l'arbitrage du propriétaire** : le
   test reste rouge et documenté, il n'a pas été-adouci.
4. L'affichage dans un vrai navigateur (CSS, détails/summary, scroll) n'est jugé par aucun
   automatisation de ce dépôt : le harnais exécute `app.js`, pas le moteur de rendu. Le vérifier
   demande une ouverture réelle de la page — c'est l'étape qui reste à faire à la main, et elle
   est courte : `bootstrap.sh`, `api.py`, un dépôt au choix, un RUN.
