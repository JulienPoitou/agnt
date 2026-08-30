# AGNT — mémoire de coordination

> **Mainteneur :** orchestrateur AGNT.  
> **But :** conserver les décisions, contrats, travaux terminés, dépendances et limites utiles entre les handoffs.  
> **Règle :** ce document est une synthèse vivante, pas une copie des rapports bruts ni un journal de logs. Les commits et handoffs restent les preuves détaillées.

**Dernière mise à jour :** 2026-08-30  
**Base d'intégration connue :** `main` / `4433af6`

---

## Règles de coordination

- Ne pas refaire un audit global après chaque handoff.
- Faire confiance aux rapports builders par défaut ; ne vérifier que ce qui peut changer une décision d'intégration ou signaler un risque sérieux.
- Les builders construisent sur leurs branches ; l'orchestrateur prépare et décide les intégrations.
- Ne pas recréer une fonctionnalité déjà marquée **terminée** sans décision explicite.
- Tout nouveau contrat partagé doit être ajouté ci-dessous avec ses consommateurs.

---

## Décisions architecturales actives

| Décision | Conséquence à préserver |
|---|---|
| **Provider ≠ Transport** | Un provider décrit ce qui est exécuté ; un transport décrit comment il est exécuté. Un provider n'est pas implicitement un binaire local. |
| **Registre AGNT = autorité** | Capability, provider, serveur, outil, arguments autorisés et conditions viennent du registre ; ni le LLM ni un serveur externe ne peuvent étendre les permissions. |
| **Transport fail-closed** | `sandbox_cli` est fourni par le cœur ; un transport tiers doit être enregistré avant le chargement d'un manifest qui le déclare. Aucun fallback silencieux vers un CLI local. |
| **État par mission** | Les artefacts bruts vivent dans `<mission>/run`; aucun répertoire global `PHASE3/run` ne doit être réintroduit pour une exécution. |
| **Intention locale à l'appel** | Les nouveaux flux passent `moteur_intent` et `fournisseur_llm` à `pipeline.executer()` ; les globales historiques sont un repli de compatibilité seulement. |
| **Journal explicatif append-only** | Le journal porte au minimum l'intention et la sélection de providers ; il ne dépend pas uniquement de `plan.json`. |
| **Policy avant invocation** | Une policy absente, indisponible ou refusée n'autorise jamais une exécution locale ou externe. |
| **Cible distincte du sandbox** | `Cible(type, reference, chemin_local=None)` est le descripteur canonique ; une cible distante ne devient jamais un `Path`, ne passe jamais à `sandbox_cli` et est filtrée à l'applicabilité. |
| **Types de cible effectifs** | `target_types` des manifests gouverne réellement l'applicabilité ; la représentation sûre de cible est ajoutée de manière compatible au plan, journal et entrée OPA. |
| **Pas de faux état produit** | Quand l'API répond mais qu'aucune mission n'existe, l'interface affiche un accueil réel, jamais des données de démonstration. |
| **Progressive disclosure** | L'UX montre d'abord le résultat métier ; providers et détails techniques restent secondaires. Les données non fiables sont rendues avec `textContent`, jamais `innerHTML`. |
| **Dimensions de statut séparées** | Statut Mission, applicabilité, sélection, condition, autorisation, disponibilité, exécution, détection et complétude sont distincts ; aucune absence/erreur/refus ne devient `rien_trouve` ou un compteur zéro. |
| **Forme API History détenue par Product** | Les schémas Product versionnés (`agnt.history.v1`, `agnt.timeline.v1`, `agnt.execution-status.v1`) sont l'autorité pour les noms de champs et enveloppes HTTP. Le gate Security complète ce contrat par des contrôles de fuite/contradiction ; il ne crée jamais un dialecte concurrent. |
| **Provenance MCP : faits puis projection** | MCP possède les faits de transport/protocole/serveur ; CORE les projette dans la forme Product ; Security valide leur exposition. Aucun builder ne crée une seconde API History ou n'élève une déclaration de provider en confiance AGNT. |
| **Autorisation de cible explicite** | `cible_autorisee` n'a aucun défaut permissif : seul `True` explicite l'arme ; l'API dérive cette autorisation exclusivement de la liste opérateur `cibles_admises()`. |
| **Jeux de règles de sécurité contrôlés** | Un scanner ne doit jamais charger une configuration fournie par le dépôt analysé. Une règle doit venir d'une source AGNT de confiance, montée en lecture seule et vérifiée. |
| **Mode laboratoire propriétaire, pas bypass** | Un mode explicite peut faciliter des tests sur cibles contrôlées, mais ne désactive jamais sandbox, policy, intégrité, autorisation de cible ou redaction ; il ne peut être activé ni par LLM ni par API cliente. |
| **Agents Pentest AI tiers : valeur, pas étiquette** | Un projet n'est ni retenu ni exclu parce qu'il est « concurrent ». Un agent complet ne devient pas un second orchestrateur ; seule une frontière composant bornée peut être envisagée. Strix est le seul candidat de pilote ultérieur, après les gates existants. |

---

## État des builders

| Builder | Branche | Statut rapporté | Derniers commits | Prochaine mission assignée |
|---|---|---|---|---|
| CORE | `arena/01a05415-agnt` | `COMPLETED_WITH_LIMITATIONS` | `91f1775`, `5f3f522`, `0f73325`, `084bb73`, `d1c236c`, `8eb4005`, `f1f323d`, `729c2c0`, `fed13d6`, `e36c53a` | **P1 actif :** aligner le lecteur/API History sur les contrats Product, avec `data.timeline` et `data.executions[]` structurés ; ne pas réécrire le lecteur livré. |
| MCP | `arena/01a05417-agnt` | `COMPLETED_WITH_LIMITATIONS` | `458d23b`, `be68844`, `229601a`, `b6b650d`, `6e04ff8` | Interop stdio terminée dans son périmètre ; aucun nouveau chantier MCP assigné. Raccord Transport CORE réservé à l'intégration coordonnée. |
| WEB | `arena/01a0541a-agnt` | `PARTIAL` — aucun changement retenu | aucun commit | **P1 :** carte d'adoption Product UI et préparation d'intégration ; ne pas modifier les fichiers UI/API avant référence CORE consolidée. |
| SECURITY | `arena/01a05426-agnt` | `COMPLETED_WITH_LIMITATIONS` | `d1d562f`, `e5838003`, `cf1eea6` | **P1 actif :** re-bind du gate adversarial sur les contrats Product, sans merge ; Mode laboratoire reprend après ce jalon. |
| PRODUCT & UX | `arena/01a05425-agnt` | `COMPLETED` | `18c1aad`, `bb2de26`, `226029fa`, `cebdf10f`, `3f96e255` | Gate black-box livré ; attente contrôlée de l'API CORE réelle pour certification History/Timeline/Status. |

---

## Terminé — ne pas refaire

### CORE

- Suppression de la mutation des globales d'intention dans les flux modernes.
- Isolation des sorties d'exécution par mission avec `Execution.sortie`.
- Séparation Provider / Transport.
- Module de transport extensible et validation fail-closed des manifests.
- Observabilité structurée : décision d'intention et sélection de providers dans le journal.
- Descripteur canonique `Cible`, normalisé une seule fois à la frontière du pipeline.
- `target_types` validé et appliqué à la sélection ; URL/non-local représentable mais jamais convertie en chemin ou exécutée par CLI local.
- Représentation sûre de cible ajoutée de façon additive au plan, journal de mission et entrée OPA.
- Lecteur canonique `mission_history.py` et endpoints lecture seule `GET /api/missions` / `GET /api/missions/{mission_id}` livrés avec pagination, filtres, projection redacted, validation traversal/symlink et polling enrichi.

### MCP

- Première couche d'intégration MCP dans le pipeline AGNT existant, sans second orchestrateur.
- Binding obligatoire registre ↔ capability ↔ provider ↔ serveur ↔ outil.
- Validation locale des déclarations, arguments, types de cible et sorties non fiables.
- Normalisation des findings MCP dans le chemin commun AGNT.
- Provenance MCP, corrélation, ledger, reporting, API et SARIF enrichis de façon additive.
- Tests contractuels, intégration simulée et serveurs/processus MCP locaux réellement exercés pour HTTP, Streamable HTTP et stdio.
- Bootstrap MCP explicite, timeout/classification, annulation stdio et HTTP, redaction de secrets et policy/egress fail-closed testés.
- Annulation HTTP réelle prouvée : fermeture TCP, serveur contrôlé observant EOF/reset, worker rejoint, absence de réponse tardive/retry et statut `cancelled` distinct.
- Interopérabilité indépendante stdio ajoutée dans `6e04ff8` : SDK officiel `mcp==2.1.1`, handshake/outils/appel réels et 20 tests déclarés verts ; push confirmé. La preuve ne couvre ni HTTP/SSE/streaming ni annulation protocolaire, et le diff ne touche aucun module générique CORE.
- Compatibilité avec le module Transport CORE encore provisoire : une implémentation locale de `transports.py` existe faute du CORE canonique dans le checkout MCP.

### WEB

- Baseline UI/API caractérisée et verte : `_domtest.mjs` 103/103, `test_interface.py` 34/35 avec un non-évalué environnemental.
- Recadrage respecté : aucune implémentation retenue, aucune route archive/bundle/fichier, aucun changement non commité.
- Le périmètre Web est désormais de consommer les contrats Product et les endpoints CORE stabilisés, jamais de reconstruire persistance ou historique côté client.

### SECURITY

- Correctif P0.1 F2/D4 : l'autorisation d'une cible n'est plus implicite dans pipeline, CLI ou API.
- L'API ignore toute tentative client de définir `cible_autorisee` et utilise uniquement la liste d'admission opérateur.
- Tests adversariaux et de régression ajoutés pour l'autorisation de cible et le journal.
- SEC-G6a fermé : gitleaks reçoit une configuration AGNT explicite sous `{REGLES}`, épinglée, installée par bootstrap et vérifiée avant tout `Popen`.
- La cible ne peut plus fournir son propre `.gitleaks.toml` pour réduire la détection ; absence/divergence de règles = refus fail-closed.
- Gate adversarial History/Timeline/Status ajouté dans `cf1eea6` : runner stdlib, corpus hostile de 81 fixtures et 93 vérifications déclarées vertes ; push du SHA confirmé. Il reste **candidat non re-lié** : son schéma temporaire ne doit pas devenir le contrat API.

### PRODUCT & UX

- Refonte de l'espace mission : navigation, création simplifiée et résultats organisés par progressive disclosure.
- État d'accueil réel quand l'API répond sans mission ; démos uniquement quand l'API est indisponible et explicitement étiquetées.
- États fiables d'attente, exécution, refus, erreur et perte de connexion.
- Présentation améliorée des findings et design system responsive avec thèmes clair/sombre/système.
- Rendu sécurisé maintenu via `textContent`.
- Contrat versionné d'historique persistant : Mission `1 → 0..1 Run`, schéma `agnt.history.v1`, fixtures anonymisées et tests autonomes.
- Endpoints produit décidés : `GET /api/missions` et `GET /api/missions/{mission_id}` ; le polling temporaire `GET /api/runs/{submission_id}` reste distinct.
- Contrat de timeline `agnt.timeline.v1` : projection read-only du journal sous `data.timeline`, ordre par `seq`, provenance allowlistée/redacted et compatibilité additive avec `data.events`.
- Contrat de statuts `agnt.execution-status.v1` : dimensions séparées, preuve obligatoire avant `rien_trouve` ou compteur zéro, 18 scénarios de sécurité et mappings CORE/MCP normatifs.
- Gate black-box Product/API : validation HTTP réelle ou capture contrôlée, détection de faux zéros, fixtures servies, identifiants confondus, artefacts maquillés, données sensibles et dérive de schéma.

---

## Travaux actifs et prochains jalons

### P1 — CORE : alignement History / Timeline / Status sur les contrats Product

Le lecteur canonique et les endpoints History sont livrés (`729c2c0`, `fed13d6`, `e36c53a`) avec 30 tests HTTP. Les fichiers Product n'étaient pas visibles dans le checkout CORE : une passe d'alignement explicite est requise avant intégration.

- conserver le lecteur unique, l'API GET read-only et les projections Security déjà livrés ;
- aligner la forme exacte de réponse sur `agnt.history.v1` ;
- ajouter `data.timeline` à partir du journal, sans second store ni événement inventé ;
- conserver `data.events` legacy séparé ;
- enrichir `data.executions[]` selon `agnt.execution-status.v1`, sans remplacer le statut Mission ;
- lancer le gate Product/API sur une référence intégrée/captures contrôlées avant feu vert WEB ;
- préserver le POST Security et l'autorisation explicite de cible.

### P1 — MCP : raccord final au Transport CORE lors de l'intégration coordonnée

Le bootstrap MCP et les tests locaux réels sont terminés. Le raccord reste provisoire car la branche MCP contient une réimplémentation locale de `transports.py` et utilise `obtenir`, alors que le CORE canonique fournit `enregistrer`, `fournit`, `connus` et `deleguer`.

À traiter lors d'une intégration CORE + MCP ciblée, sans merge aveugle :
- conserver `mcp_bootstrap.initialiser_mcp` et les tests E2E ;
- supprimer la duplication de transport générique au profit du module CORE ;
- adapter le dispatch au nom/signatures canoniques ;
- rejouer la batterie MCP sur l'arbre intégré.

### P2 — MCP : interopérabilité avec une implémentation indépendante, preuve bornée terminée

`6e04ff8` apporte une preuve **DÉCLARÉE** de compatibilité stdio avec le SDK officiel `mcp==2.1.1` : handshake, découverte, appel, timeout, refus, annulation pré-invocation et passage par le pipeline commun. Le push est **CONFIRMÉ** et le diff est limité à la documentation MCP et au test d'interopérabilité.

La portée reste volontairement limitée à stdio : HTTP, Streamable HTTP, SSE, streaming, ressources, prompts, authentification, JSON-RPC malformé et annulation protocolaire ne sont pas démontrés contre cette implémentation. Ne pas rejouer ni élargir cette preuve sans besoin produit explicite.

### P1 — MCP : provenance lors de l'intégration coordonnée

Le handoff MCP déclare les statuts et la provenance compatibles Product ; cette déclaration est acceptée dans son périmètre. La projection HTTP reste de la responsabilité de CORE et sera éprouvée par les gates sur l'arbre intégré.

Aucun chantier MCP complémentaire n'est assigné à ce stade. Si le re-bind Security ou CORE révèle un terme précis non couvert, demander alors à MCP une clarification ciblée, sans rouvrir son interopérabilité stdio ni modifier les contrats CORE génériques.

### PRODUCT & UX — gate API prêt, attente de certification CORE

Les trois contrats produit et le gate black-box sont terminés :
- historique `agnt.history.v1` ;
- timeline `agnt.timeline.v1` ;
- statuts `agnt.execution-status.v1` ;
- `docs/coordination/api-conformance-gate/product_api_gate.py`.

Ne pas créer de quatrième contrat, de nouvelle UI ou de CI trompeuse sur fixtures. Dès que CORE livre l'API réelle, Product & UX exécute le gate avec `--base-url` et `--require-full-coverage`, valide les captures contrôlées et donne le feu vert produit à WEB.

### P1 — WEB : carte d'adoption et préparation d'intégration

WEB n'a aucun code à construire sans dupliquer Product & UX ou devancer le lecteur CORE. Travail utile autorisé : comparer de façon ciblée la refonte Product UI (`18c1aad`) aux invariants DOM/API WEB existants, documenter les dépendances et préparer le plan d'adoption sans modifier `index.html`, `app.js`, `style.css` ou `api.py`.

- Product UI est déjà livré ; ne pas le réécrire.
- L'historique est consommé seulement après livraison de `GET /api/missions` par CORE.
- Les bundles dogfooding, `localStorage`, fixtures et fichiers d'archives ne sont jamais une source d'historique Web.
- L'exposition d'artefacts ou de téléchargements attend une décision Security explicite.

### STRAT — Réévaluation des agents Pentest AI externes

Évaluation ciblée terminée dans `docs/coordination/PENTEST_AI_AGENT_REEVALUATION.md`, à partir des rapports Phase 1 et des métadonnées publiques actualisées. Aucun code tiers n'a été audité, exécuté ou intégré.

- **Composant candidat, plus tard :** Strix, uniquement comme backend de laboratoire isolé et après les jalons Security/CORE en cours.
- **Références :** CyberStrikeAI, PentAGI, Decepticon, Shannon, Redamon et CAI.
- **Écartés pour le produit actuel :** PentestGPT, PentestAgent et GHOSTCREW/PentestAgent MCP.
- **Aucun pilote ni intégration n'est assigné** ; le rapport fixe les critères d'une décision propriétaire ultérieure.

### P1 — SECURITY : gate adversarial History / Timeline / Status livré, re-bind requis

Security a livré `cf1eea6` (push **CONFIRMÉ**) : un runner stdlib, 81 fixtures hostiles et un harnais dont les 93 vérifications sont **DÉCLARÉES** vertes. Il protège utilement contre secrets, chemins/artefacts bruts, payloads, faux zéros, contradictions et provenance MCP non fiable.

Un conflit de contrat est toutefois **CONFIRMÉ** par comparaison ciblée des branches distantes : les contrats Product existent sur `arena/01a05425-agnt` (`3f96e255`) et utilisent notamment `schema_version`, `items`/`page`, `status`, `data.timeline`, `sequence`/`timestamp`/`kind`. Le gate Security, construit dans un checkout où ces fichiers étaient absents, attend une enveloppe temporaire `api`/`endpoint`/`data`, le champ `statut` et `seq`/`ts`/`type`. Il rejettera donc une réponse Product conforme.

Conséquence : ne pas demander à CORE d'adopter le dialecte Security et ne pas présenter ce gate comme feu vert de release avant re-bind. **Mission P1 relancée :** Security adapte ses allowlists, runner et fixtures aux trois schémas Product, conserve les contrôles hostiles, puis le gate Product et le gate Security seront exécutés contre la même API CORE intégrée. Les valeurs MCP temporaires (`transport`/`protocol`) restent à confirmer avec MCP. Aucun merge n'est autorisé dans cette mission.

### P1 — SECURITY : Mode laboratoire propriétaire borné

Le handoff `cf1eea6` ne couvre pas le Mode laboratoire. Ce chantier demandé par le propriétaire est mis en attente du re-bind P1, jamais un bypass générique.

Invariants :
- activation locale explicite et double opt-in opérateur ;
- impossible à activer via LLM, corps API ou donnée de cible ;
- restreint à des racines/cibles contrôlées ;
- egress fermé par défaut et explicitement borné ;
- sandbox, policy fail-closed, intégrité, redaction et autorisation de cible restent actifs ;
- journal/audit obligatoire ;
- refus automatique dans un profil public/production.

---

## Contrats et dépendances entre builders

```text
CORE : Provider / Transport / mission artifacts / future Cible
  ├── MCP : transport "mcp", résultats externes, provenance
  ├── WEB : affichage des artefacts par mission et provenance additive
  ├── SECURITY : autorisation explicite de cible, invariants egress/policy/secrets, confiance externe et règles scanners de confiance
  └── PRODUCT & UX : modèle de cible, point de composition des extensions et contrat de consultation de l'historique
```

### Contrat MCP à préserver

```python
transports.enregistrer("mcp", executeur)
# executeur(provider, sandbox) -> ResultatBrut
```

- Un manifest MCP déclare `transport: mcp`.
- L'enregistrement doit précéder le chargement du registre concerné.
- Le dispatch canonique CORE passe par `transports.deleguer`; la variante MCP locale utilisant `obtenir` est provisoire et ne doit pas survivre à l'intégration.
- `tools/list` est informatif, jamais une autorité d'autorisation.
- Les nouveaux champs de provenance doivent être additifs pour Web/API/SARIF.

### Contrat Cible à préserver

- Forme publique : `Cible(type, reference, chemin_local=None)` et `Cible.normaliser(Path | str | Cible)`.
- `to_dict()` expose une référence sûre, pas le userinfo éventuel d'une URL ; le champ historique `cible` texte reste compatible.
- `repository` et `filesystem` sont aujourd'hui les types locaux effectivement chargés ; `url` est représentable mais aucun transport ne peut encore la recevoir.
- Le contrat Transport actuel ne reçoit pas `Cible`. Toute évolution pour une cible distante est un chantier conjoint CORE + MCP + SECURITY, sans cacher l'URL dans Sandbox ou un global.

### Implémentation CORE History candidate

- `mission_history.py` est l'unique lecteur de projection pour les GET History ; il ne crée ni base ni index autoritaire.
- Listing : `GET /api/missions`, liste vide HTTP 200, pagination base64 opaque, filtres `status` / `target_type`, tri stable.
- Détail : projection redacted, artefacts manquants explicites, ID validé et symlinks/traversal refusés.
- Cette implémentation est **candidate**, non encore certifiée contre les fichiers Product réels absents du checkout CORE ; ne pas activer WEB avant gate Product/API réel.

### Contrat produit de statuts à préserver

- `agnt.execution-status.v1` enrichit `data.executions[]` sans changer les statuts Mission History v1.
- Les dimensions applicabilité, sélection, condition, autorisation, disponibilité, exécution, détection, complétude et preuve sont séparées.
- `rien_trouve` et `findings_count: 0` exigent exécution terminée, invocation prouvée, sortie normalisée, cible analysée et artefact Findings lisible sans contradiction.
- `timed_out`, `cancelled`, `unavailable`, `echoue`, refus et absence de données ne deviennent jamais zéro finding.
- Une contradiction produit `conflict`, jamais le résultat le plus rassurant.

### Contrat produit de timeline à préserver

- La timeline est une projection read-only du journal canonique sous `data.timeline` dans `GET /api/missions/{mission_id}` ; elle n'est ni un second journal ni un endpoint séparé.
- `seq` définit ordre et identité (`<mission_id>:<source_sequence>`); le timestamp ne sert jamais seul à ordonner.
- `data.events` reste un fallback minimal legacy ; WEB préfère `data.timeline` et ne fusionne jamais les deux.
- Les payloads inconnus, événements déduits d'artefacts et snapshots `statuts` éclatés sont interdits.
- Provenance MCP : additive, secondaire, allowlistée et redacted ; absence de provenance ne signifie jamais local, disponible ou fiable.

### Contrat produit d'historique à préserver

- Une **Mission** est le dossier persistant visible par l'utilisateur ; un **Run** est son exécution technique. Cardinalité actuelle : `Mission 1 → 0..1 Run`.
- `mission_id` est l'identifiant persistant visible ; l'ID de `POST /api/runs` reste temporaire pour soumission/polling.
- Historique : `GET /api/missions`; détail : `GET /api/missions/{mission_id}`. Ne pas détourner `GET /api/runs` en liste d'historique.
- Statuts canoniques : `en_file`, `en_cours`, `termine`, `refuse`, `erreur`, `inconnu`. `indisponible` décrit une disponibilité, pas le statut d'une mission.
- Listing sans historique : HTTP 200 avec `items: []`; aucun fallback vers des fixtures ou des données de démonstration.
- Un compteur à zéro n'est affichable que si un artefact findings lisible prouve réellement zéro ; sinon utiliser `missing_artifacts`.

### Contrat d'autorisation de cible à préserver

- `pipeline.executer(..., cible_autorisee=None)` doit refuser ; seul un booléen `True` explicite autorise la cible.
- L'API dérive l'autorisation de `cibles_admises()` ; un champ client `cible_autorisee` ne doit jamais influencer cette décision.
- Le futur descripteur `Cible` de CORE ne doit pas réintroduire d'autorisation implicite par type, chemin ou défaut.

### Consignes cross-builder actuelles

- **WEB :** branche réelle `arena/01a0541a-agnt`. Ne pas supposer un unique `PHASE3/run`; consommer uniquement les données de mission/API stabilisées, tolérer les champs MCP additionnels et ne jamais reconstruire un historique depuis filesystem, bundles, fixtures ou localStorage.
- **SECURITY :** fermer SEC-G6a avant les chantiers secondaires, puis définir/tester les invariants d'un backend externe : egress, endpoint contrôlé par registre, secrets, timeout, policy avant appel, confiance et absence de bypass sandbox implicite.
- **CORE / MCP :** tout nouvel appel à `pipeline.executer()` ou nouveau type de cible doit préserver l'autorisation explicite ; aucune cible externe ne doit contourner la liste opérateur et la policy. Une cible URL ne doit pas être exécutée tant que le contrat Transport ne reçoit pas explicitement `Cible`.
- **PRODUCT & UX :** historique, timeline, statuts et gate sont terminés. Ne pas créer de quatrième contrat, UI ou CI certifiante sur fixtures : attendre le lecteur/API CORE, exécuter le gate réel avec couverture exigée, puis donner le feu vert à WEB.
- **CORE :** conserver le lecteur History livré et l'aligner sur les fichiers Product : ajouter `data.timeline` et `data.executions[]` structurés depuis le journal/ledger, puis lancer le gate Product/API contre `--base-url` et publier des captures contrôlées à couverture complète.
- **WEB :** consommer exclusivement `/api/missions` pour l'historique, en utilisant `mission_id` comme référence persistante ; ne jamais reconstruire une liste locale ni mapper absence/refus/erreur vers zéro finding. Attendre le passage du gate Product/API réel.

---

## Risques d'intégration à suivre

| Risque | Gravité | État / réponse prévue |
|---|---:|---|
| CORE et MCP ont tous deux touché des fichiers centraux (`pipeline`, `registre`, `adapters`, etc.). | Élevée à l'intégration | Le MCP local réimplémente actuellement `transports.py` et utilise un dispatch différent du CORE ; intégration ciblée obligatoire, aucun merge aveugle. |
| Initialisation du transport MCP avant validation des manifests. | Élevée | Bootstrap explicite `mcp_bootstrap.initialiser_mcp` livré et testé localement ; raccord au module CORE canonique encore requis. |
| Serveur MCP externe hors sandbox locale. | Élevée | Contrôles Security et provenance/confiance obligatoires ; jamais présenter cela comme sandboxé. |
| Interopérabilité MCP seulement locale, pas contre un serveur tiers. | Moyenne | preuve indépendante **DÉCLARÉE** pour le SDK officiel `mcp==2.1.1` en stdio (20 tests déclarés, commit/push confirmés) ; HTTP, Streamable HTTP, SSE et compatibilité générale restent non démontrés. |
| Contrat Transport ne reçoit pas encore le descripteur `Cible` pour une exécution distante. | Architecturale P1 | Les URL sont représentables et filtrées, mais non exécutables ; évolution conjointe CORE/MCP/SECURITY requise avant support distant réel. |
| Compatibilité MCP avec une implémentation tierce indépendante. | Moyenne | Preuve indépendante terminée pour `mcp==2.1.1` en stdio seulement ; ne pas généraliser aux autres SDK, profils ou transports. |
| PRODUCT & UX et WEB peuvent modifier les mêmes fichiers d'interface (`index.html`, `app.js`, `style.css`). | Élevée à l'intégration | Product UI est déjà livré ; WEB a été recadré et ne modifie pas ces fichiers. Préparer une adoption ciblée après référence consolidée, jamais une seconde refonte. |
| History API candidate diverge des contrats Product non visibles sur la branche CORE. | Élevée à l'intégration | Lecteur/API CORE est livré et testé localement, mais doit être aligné sur `agnt.history.v1`, `data.timeline` et `data.executions[]`, puis passer le gate Product/API réel avant activation WEB. |
| Exposition API History/Timeline/Status de données sensibles ou payloads non allowlistés. | Haute sécurité d'intégration | Gate Security candidat livré (`cf1eea6`), mais son schéma temporaire diverge de façon **confirmée** du contrat Product (`statut` vs `status`, enveloppe et événements). Re-bind obligatoire, puis exécution des deux gates contre la même API ; CORE reste propriétaire de la projection/redaction. Toute clarification MCP sera demandée seulement sur écart précis. |
| Le contrat d'autorisation de cible peut être perdu lors des évolutions CORE/MCP. | Haute sécurité | Préserver `cible_autorisee=True` explicite et l'autorité exclusive de la liste opérateur API ; tests de régression Security déjà ajoutés. |
| Un « bypass » générique pourrait devenir une backdoor publique ou désactiver des garanties de sécurité. | Haute sécurité | Remplacer le concept par un Mode laboratoire propriétaire borné, local, audité et impossible à activer depuis le LLM/API ; Security en est propriétaire. |

---

## Limitations d'environnement connues

Ces éléments ne sont pas des régressions de code tant qu'aucune preuve contraire n'apparaît :

- Binaire OPA absent : validation de policy réelle incomplète.
- `bwrap` et plusieurs outils de scan/caches absents : certaines batteries E2E sont non évaluables.
- Pas de serveur MCP tiers ni de credential de test : interopérabilité externe réelle non prouvée à ce stade, malgré les tests HTTP/Streamable HTTP/stdio contre serveurs locaux contrôlés.
- L'annulation HTTP est démontrée au niveau transport ; aucune notification protocolaire MCP d'annulation n'est revendiquée si le profil ne la fournit pas.
- Certains tests historiques échouent uniquement parce que `bandit`, `checkov`, `detect-secrets` et `radon` sont absents.
- L'API conserve actuellement les runs en mémoire et n'expose pas encore de liste persistée de missions ; l'historique produit reste volontairement désactivé.
- Gitleaks réel est absent : SEC-G6a est fermé côté AGNT par argv/configuration/empreinte ; la mesure du comportement interne du binaire face à un `.gitleaks.toml` hostile reste non évaluée (SEC-G9).

---

## Backlog architectural connu

| ID | Sujet | Priorité | Statut |
|---|---|---:|---|
| CORE-001 | Cible typée / descriptor canonique | P1 | Terminé — `8eb4005`, `f1f323d` |
| CORE-004 | Historique Mission persistant et API lecture seule `agnt.history.v1` | P1 | Livré candidat — `729c2c0`, `fed13d6`, `e36c53a`; alignement Product requis |
| CORE-006 | Projection `data.timeline` et `data.executions[]` conforme aux contrats Product | P1 intégration | En cours — CORE |
| CORE-005 | Contrat Transport recevant Cible pour providers distants | P1 architecture | Ouvert — joint CORE/MCP/SECURITY |
| CORE-002 | Graphe d'exécution explicite dans `plan.json` | P2 | Différé |
| CORE-003 | Validation E2E avec OPA/bwrap/outils | Environnement | Bloqué |
| MCP-001 | Validation OPA réelle | P1 environnement | Bloqué |
| MCP-002 | Serveur MCP réel contrôlé | P1 | Terminé localement — HTTP, Streamable HTTP et stdio contrôlés |
| MCP-003 | Annulation HTTP MCP pendant un appel bloquant | P2 | Terminé — `b6b650d`, preuve socket/worker contrôlée |
| MCP-004 | Raccord MCP au module Transport CORE canonique | P1 intégration | Ouvert — intégration coordonnée requise |
| MCP-005 | Interopérabilité avec une implémentation MCP indépendante | P2 | Terminé borné — preuve **DÉCLARÉE** `6e04ff8`, SDK `mcp==2.1.1` stdio ; autres transports/SDK non prouvés |
| PRODUCT-001 | Endpoint d'historique persistant des missions | P1 | Contrat produit terminé ; implémentation CORE/WEB à planifier |
| PRODUCT-002 | Comparaison de runs et vues globales Findings/Reports | P2 | Différé |
| PRODUCT-003 | Timeline et projection sûre de provenance | P2 | Terminé — `226029fa` |
| PRODUCT-004 | Sémantique produit des statuts/exécution/disponibilité | P2 | Terminé — `cebdf10f` |
| PRODUCT-005 | Validation produit des réponses History/Timeline/Status réelles | P1 intégration | Gate livré — dépend du lecteur/API CORE et de captures complètes |
| GATE-001 | Endpoints CORE requis pour validation API réelle | Intégration | Bloqué — CORE en cours |
| GATE-002 | Captures CORE couvrant toute la matrice sémantique | Qualité | Ouvert — CORE/MCP/SECURITY |
| GATE-003 | Corpus hostiles complémentaire au gate Product | Sécurité | Livré candidat — `cf1eea6`; re-bind Product et table MCP obligatoire avant valeur de gate d'intégration |
| WEB-001 | Adoption de la refonte Product UI et états honnêtes | P1 | En attente de référence consolidée ; carte d'adoption active |
| WEB-002 | Consommation UI de `/api/missions` et détail | P1 | Bloqué — dépend de CORE History/Timeline et validation Security |
| WEB-003 | Validation navigateur réelle d'un run terminé | P2 environnement | Bloqué — OPA/bwrap/outils absents |
| TIMELINE-001 | Projection `data.timeline` dans le lecteur canonique CORE | P1 intégration | En cours — CORE |
| TIMELINE-002 | Noms source des événements intention/sélection alignés à CORE | Intégration | Ouvert |
| TIMELINE-003 | Allowlists transport/protocole MCP approuvées avec Security | Sécurité | Ouvert — solliciter MCP uniquement si le re-bind Security remonte un écart précis |
| SEC-G6a | Configuration gitleaks contrôlée par le dépôt cible | P1 haute sécurité | Terminé — `e5838003`, config AGNT épinglée/fail-closed |
| SEC-G9 | Mesure réelle gitleaks face à un `.gitleaks.toml` hostile | P2 environnement | Bloqué |
| SEC-HIST-001 | Gate adversarial d'exposition History/Timeline/Status | P1 intégration sécurité | En cours — re-bind Security assigné sur les contrats Product ; API CORE intégrée ensuite |
| SEC-LAB-001 | Mode laboratoire propriétaire borné, testé et audité | P1 pré-publication | En attente après SEC-HIST-001 — aucun handoff associé à `cf1eea6` |
| SEC-B6 | Durcissement garde-fous homoglyphes / espaces | P3 | Différé |
| SEC-B7 | Borne de taille de requête sortante fournisseur | P3 | Différé |
| STRAT-001 | Faisabilité d'un backend Strix dans le Mode Laboratoire Propriétaire | P2 post-intégration | Différé — décision propriétaire requise après SEC-LAB, Cible/Transport et double gate API |

---

## Ordre d'intégration prévisionnel

1. Préserver les correctifs Security poussés P0.1 `d1d562f`, SEC-G6a `e5838003` et le corpus candidat `cf1eea6`; ne pas déclarer G9 mesuré sans vrai gitleaks ni le schéma temporaire Security comme contrat API.
2. Prendre les trois schémas Product versionnés comme référence de forme, puis CORE aligne son lecteur/API History candidat sur eux en préservant Cible et l'autorisation explicite de cible. Aucun merge n'est implicite dans cette étape.
3. **Mission Security active :** re-lier son gate au contrat Product, sans perdre les contrôles hostiles ni créer de second format. Consulter MCP seulement si un écart précis de provenance est constaté. Le Mode laboratoire reprend après ce jalon.
4. CORE termine `data.timeline` et `data.executions[]` enrichi à partir des contrats, puis les gates Product/API **et** Security sont lancés contre la même API réelle avec couverture complète. Product & UX valide alors le résultat sans toucher à l'UI partagée.
5. Réconcilier CORE + MCP autour du module Transport canonique et rejouer les tests sur l'arbre intégré ; aucun merge aveugle. Ne pas supporter les URL distantes avant le contrat Cible/Transport joint.
6. Finaliser la carte d'adoption WEB sans code concurrent, puis intégrer la refonte Product UI et les endpoints CORE stabilisés après double feu vert produit/Security.
7. Seulement après ces jalons, le propriétaire pourra décider d'un pilote Strix strictement local et isolé ; aucun agent tiers complet n'est intégré dans le cœur AGNT.

> Cet ordre est révisable dès réception des handoffs Web, Security et Product.
