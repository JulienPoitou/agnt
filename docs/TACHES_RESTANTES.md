# Tâches restantes — état au 2026-09-01

Liste tenue à jour dans `docs/` ; les libellés entre guillemets reprennent les
chantiels tels que déclarés dans `PROJET_ETAT.md` / `PHASE3/DECISIONS_PROPOSEES.md`.
Le tableau de bord est désormais branché sur le moteur réel
(`PHASE3/interface/dashboard_api.py`, port 8142).

## A. Tableau de bord (suite directe du branchement)

1. **Remplacer la grille « 22 phases » Xalgoryx** (page détail de scan) par le
   registre des six étapes AGNT (`statuts` par outil de `rapport.json`) — la
   méthodologie Xalgoryx est décorative, elle ne dit rien du moteur.
2. **WebSocket `/ws`** pour le live feed (actuellement « Déconnecté ») :
   diffuser les événements `journal.jsonl` d'un run en cours.
3. **Rebranding** : nom « Xalgorix », logo et lien GitHub
   (github.com/xalgorix/xalgorix) dans la sidebar → agnt.
4. **Page New Scan** : brancher sur les vrais champs du moteur — sélecteur de
   cibles depuis `GET /api/cibles`, confiance (`controlled`/`untrusted`),
   moteur (`auto`/`llm`/`deterministe`) + modèle Groq, egress. Aujourd'hui les
   champs Xalgoryx sont traduits au mieux (`instruction` → question, 1 seule
   cible, `scan_intensity: passive` → `untrusted`).
5. **Onglet Config** du détail : projeter plan/couverture/autorisation AGNT
   (déjà dans `MH.projeter()` : `plan`, `coverage`, `intent`).
6. **Pages inertes** (Schedules, Email Triage, Chat, Integrations, uploads,
   réglages en écriture) : le serveur répond 501 refus nommé — les masquer de
   la navigation ou les implémenter côté moteur.
7. **Suite de tests HTTP** pour `dashboard_api.py` (sur le modèle de
   `test_interface.py`) : projections scans/findings/events, refus 501, dédoublonnage run/archive.

## B. Moteur — chantiers ouverts déclarés

8. **Décisions D7–D10 en attente d'arbitrage** (`PHASE3/DECISIONS_PROPOSEES.md`) :
   D7 `CODE_STATIC_ANALYSIS` en `fan_out` ; D8 répertoire de travail déclaré par
   manifest ; D9 septième jeton `{URL}` pour les cibles non-chemins ; D10
   `max_providers` de SECRET_DETECTION à 3.
9. **Correctifs F restants** (ordre fixé G → F1 → F2 → F4 → F3 → F5/F6) :
   **F2** `cible_autorisee` (« attend l'arbitrage du propriétaire », 1 FAIL
   persistant de `test_securite.py`), F5, F6, F7/G6a (épinglage des règles de
   secrets — non mesurable sans outils réels).
10. **Jeu d'essais adverses sur le classifieur** + politique de relance/file
    d'attente LLM (taux de repli déterministe non mesuré — « validé en
    production » non atteint).
11. **Décision providers en attente** (`PHASE5/DECISION_PROVIDERS_PROPOSEE.md`) :
    groupe A (checkov, sigma, grype) / groupe B (nmap, ffuf, zap).
12. **Isolation mémoire / OCI** : `PHASE3/test_oci.sh` jamais exécuté ;
    `RLIMIT_AS` casse trivy et gitleaks → le profil « dépôt non fiable » reste fermé.
13. **Dette `cadre`** : le modèle de findings ne porte pas le `cadre`
    (framework) en natif — dette actée le 2026-08-28.
14. **Dette pyflakes** : 1 import différé mort dans `interface/api.py:60`
    (`Registry`) et 6 imports inutilisés dans `test_adversaire.py`.
15. **Backlog PHASE1** : 281 entrées (40 NEXT haute importance) — réexamen
    périodique, règle anti-dispersion.

## C. Environnement

16. **Exécution réelle du moteur** : la machine Windows actuelle ne peut pas
    exécuter de mission (`ModuleNotFoundError: resource`, opa absent, bwrap
    user-ns refusés) — le tableau de bord l'affiche honnêtement en `failed`.
    Exécuter sous WSL/Linux, ou portage.
