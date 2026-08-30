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
| **Autorisation de cible explicite** | `cible_autorisee` n'a aucun défaut permissif : seul `True` explicite l'arme ; l'API dérive cette autorisation exclusivement de la liste opérateur `cibles_admises()`. |
| **Jeux de règles de sécurité contrôlés** | Un scanner ne doit jamais charger une configuration fournie par le dépôt analysé. Une règle doit venir d'une source AGNT de confiance, montée en lecture seule et vérifiée. |

---

## État des builders

| Builder | Branche | Statut rapporté | Derniers commits | Prochaine mission assignée |
|---|---|---|---|---|
| CORE | `arena/01a05415-agnt` | `COMPLETED_WITH_LIMITATIONS` | `91f1775`, `5f3f522`, `0f73325`, `084bb73`, `d1c236c`, `8eb4005`, `f1f323d` | **P1 :** lecteur canonique d'historique Mission et API en lecture seule selon le contrat produit. |
| MCP | `arena/01a05417-agnt` | `COMPLETED_WITH_LIMITATIONS` | `458d23b`, `be68844`, `229601a` | **P2 :** annulation HTTP réellement interruptible ; **P1 intégration :** raccord final au module CORE canonique à traiter lors de l'intégration coordonnée. |
| WEB | non reçu | en attente de handoff | — | À définir après handoff. |
| SECURITY | `arena/01a05426-agnt` | `PARTIAL` | `d1d562f` — non poussé au handoff | **P1 :** pousser le correctif P0.1 puis fermer SEC-G6a : jeu de règles gitleaks de confiance. |
| PRODUCT & UX | `arena/01a05425-agnt` | `COMPLETED` | `18c1aad`, `bb2de26`, `226029fa`, `cebdf10f` | En attente contrôlée : validation produit de l'API History/Timeline/Status dès livraison CORE ; aucun quatrième contrat à créer maintenant. |

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

### MCP

- Première couche d'intégration MCP dans le pipeline AGNT existant, sans second orchestrateur.
- Binding obligatoire registre ↔ capability ↔ provider ↔ serveur ↔ outil.
- Validation locale des déclarations, arguments, types de cible et sorties non fiables.
- Normalisation des findings MCP dans le chemin commun AGNT.
- Provenance MCP, corrélation, ledger, reporting, API et SARIF enrichis de façon additive.
- Tests contractuels, intégration simulée et serveurs/processus MCP locaux réellement exercés pour HTTP, Streamable HTTP et stdio.
- Bootstrap MCP explicite, timeout/classification, annulation stdio, redaction de secrets et policy/egress fail-closed testés.
- Compatibilité avec le module Transport CORE encore provisoire : une implémentation locale de `transports.py` existe faute du CORE canonique dans le checkout MCP.

### SECURITY

- Correctif P0.1 F2/D4 : l'autorisation d'une cible n'est plus implicite dans pipeline, CLI ou API.
- L'API ignore toute tentative client de définir `cible_autorisee` et utilise uniquement la liste d'admission opérateur.
- Tests adversariaux et de régression ajoutés pour l'autorisation de cible et le journal.

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

---

## Travaux actifs et prochains jalons

### P1 — CORE : lecteur canonique d'historique Mission et API lecture seule

Implémenter le contrat produit versionné `agnt.history.v1` sans base parallèle :
- `GET /api/missions` et `GET /api/missions/{mission_id}` depuis les headers, journal et artefacts canoniques ;
- `mission_id` persistant distinct du polling temporaire `run_id` ;
- statuts, pagination, filtres et `missing_artifacts` conformes au contrat Product & UX ;
- données sûres/redacted, sans chemins absolus, sorties brutes, argv ou secrets ;
- enrichissement additif du polling avec `mission_id` / `detail_href`;
- préservation stricte du contrat Security d'autorisation explicite de cible.

### P1 — MCP : raccord final au Transport CORE lors de l'intégration coordonnée

Le bootstrap MCP et les tests locaux réels sont terminés. Le raccord reste provisoire car la branche MCP contient une réimplémentation locale de `transports.py` et utilise `obtenir`, alors que le CORE canonique fournit `enregistrer`, `fournit`, `connus` et `deleguer`.

À traiter lors d'une intégration CORE + MCP ciblée, sans merge aveugle :
- conserver `mcp_bootstrap.initialiser_mcp` et les tests E2E ;
- supprimer la duplication de transport générique au profit du module CORE ;
- adapter le dispatch au nom/signatures canoniques ;
- rejouer la batterie MCP sur l'arbre intégré.

### P2 — MCP : annulation HTTP réellement interruptible

Le timeout HTTP est prouvé, mais l'annulation pendant une requête HTTP bloquante reste ouverte. Le prochain lot MCP doit traiter ce comportement sans modifier le pipeline générique ni promettre une annulation protocolaire non démontrée.

### PRODUCT & UX — attente contrôlée de l'intégration CORE

Les trois contrats produit sont maintenant terminés :
- historique `agnt.history.v1` ;
- timeline `agnt.timeline.v1` ;
- statuts `agnt.execution-status.v1`.

Ne pas créer un quatrième contrat ou une UI concurrente. Dès que CORE livre le lecteur/API History + Timeline, Product & UX validera la conformité réelle des réponses et des états contre ces contrats, puis donnera le feu vert produit à WEB.

### P1 — SECURITY : jeu de règles gitleaks de confiance

Avant tout autre chantier Security :
- pousser le commit P0.1 `d1d562f` sur sa branche ;
- fermer SEC-G6a en forçant gitleaks à utiliser un fichier `gitleaks.toml` AGNT sous `{REGLES}` ;
- installer/pinner/vérifier ce fichier via les mécanismes bootstrap et empreintes existants ;
- refuser l'exécution plutôt que retomber sur une configuration découverte dans le dépôt cible ;
- ajouter les régressions argv/configuration correspondantes ;
- laisser G9 honnêtement non évalué tant qu'un vrai gitleaks n'est pas disponible.

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

- **WEB :** ne pas supposer un unique `PHASE3/run`; utiliser les données de mission et tolérer les champs MCP additionnels (`transport`, serveur, outil, protocole, confiance, disponibilité, corrélation).
- **SECURITY :** fermer SEC-G6a avant les chantiers secondaires, puis définir/tester les invariants d'un backend externe : egress, endpoint contrôlé par registre, secrets, timeout, policy avant appel, confiance et absence de bypass sandbox implicite.
- **CORE / MCP :** tout nouvel appel à `pipeline.executer()` ou nouveau type de cible doit préserver l'autorisation explicite ; aucune cible externe ne doit contourner la liste opérateur et la policy. Une cible URL ne doit pas être exécutée tant que le contrat Transport ne reçoit pas explicitement `Cible`.
- **PRODUCT & UX :** historique, timeline et statuts sont terminés. Ne pas créer de quatrième contrat ou modifier l'UI : attendre le lecteur/API CORE, puis valider la conformité réelle avant de donner le feu vert à WEB.
- **CORE :** implémenter l'historique, `data.timeline` et l'enrichissement structuré de `data.executions[]` depuis le lecteur canonique de mission, sans base parallèle, puis faire valider les réponses contre les contrats Product.
- **WEB :** consommer exclusivement `/api/missions` pour l'historique, en utilisant `mission_id` comme référence persistante ; ne jamais reconstruire une liste locale ni mapper absence/refus/erreur vers zéro finding.

---

## Risques d'intégration à suivre

| Risque | Gravité | État / réponse prévue |
|---|---:|---|
| CORE et MCP ont tous deux touché des fichiers centraux (`pipeline`, `registre`, `adapters`, etc.). | Élevée à l'intégration | Le MCP local réimplémente actuellement `transports.py` et utilise un dispatch différent du CORE ; intégration ciblée obligatoire, aucun merge aveugle. |
| Initialisation du transport MCP avant validation des manifests. | Élevée | Bootstrap explicite `mcp_bootstrap.initialiser_mcp` livré et testé localement ; raccord au module CORE canonique encore requis. |
| Serveur MCP externe hors sandbox locale. | Élevée | Contrôles Security et provenance/confiance obligatoires ; jamais présenter cela comme sandboxé. |
| Interopérabilité MCP seulement locale, pas contre un serveur tiers. | Moyenne | HTTP, Streamable HTTP et stdio sont exercés contre des serveurs/processus contrôlés ; compatibilité tierce reste non démontrée. |
| Contrat Transport ne reçoit pas encore le descripteur `Cible` pour une exécution distante. | Architecturale P1 | Les URL sont représentables et filtrées, mais non exécutables ; évolution conjointe CORE/MCP/SECURITY requise avant support distant réel. |
| Annulation HTTP en cours d'appel MCP. | Moyenne | Timeout et fermeture de session existent ; interruption réelle d'un appel bloquant reste à prouver/implémenter dans un lot MCP P2. |
| PRODUCT & UX et WEB peuvent modifier les mêmes fichiers d'interface (`index.html`, `app.js`, `style.css`). | Élevée à l'intégration | Product & UX travaille désormais sur le contrat d'historique hors de ces fichiers ; attendre le handoff WEB avant tout nouveau chantier UI. |
| Historique/timeline/statuts affichés sans source backend persistée. | Élevée produit | Contrats produit terminés ; CORE doit exposer lecteur/API, `data.timeline` et `data.executions[]` enrichi avant toute activation WEB, sans données de démonstration après une réponse API. |
| Gitleaks peut charger une configuration hostile du dépôt et masquer des secrets (SEC-G6a). | Haute sécurité | Correctif Security P1 actif : config AGNT explicite, vérifiée et fail-closed ; ne pas déclarer la détection de secrets fiable avant fermeture. |
| Le contrat d'autorisation de cible peut être perdu lors des évolutions CORE/MCP. | Haute sécurité | Préserver `cible_autorisee=True` explicite et l'autorité exclusive de la liste opérateur API ; tests de régression Security déjà ajoutés. |

---

## Limitations d'environnement connues

Ces éléments ne sont pas des régressions de code tant qu'aucune preuve contraire n'apparaît :

- Binaire OPA absent : validation de policy réelle incomplète.
- `bwrap` et plusieurs outils de scan/caches absents : certaines batteries E2E sont non évaluables.
- Pas de serveur MCP tiers ni de credential de test : interopérabilité externe réelle non prouvée à ce stade, malgré les tests HTTP/Streamable HTTP/stdio contre serveurs locaux contrôlés.
- Certains tests historiques échouent uniquement parce que `bandit`, `checkov`, `detect-secrets` et `radon` sont absents.
- L'API conserve actuellement les runs en mémoire et n'expose pas encore de liste persistée de missions ; l'historique produit reste volontairement désactivé.
- Gitleaks réel est absent : la vulnérabilité de configuration hostile est reproductible par contrat/argv mais sa mesure avec le binaire reste non évaluée.

---

## Backlog architectural connu

| ID | Sujet | Priorité | Statut |
|---|---|---:|---|
| CORE-001 | Cible typée / descriptor canonique | P1 | Terminé — `8eb4005`, `f1f323d` |
| CORE-004 | Historique Mission persistant et API lecture seule `agnt.history.v1` | P1 | En cours — CORE |
| CORE-005 | Contrat Transport recevant Cible pour providers distants | P1 architecture | Ouvert — joint CORE/MCP/SECURITY |
| CORE-002 | Graphe d'exécution explicite dans `plan.json` | P2 | Différé |
| CORE-003 | Validation E2E avec OPA/bwrap/outils | Environnement | Bloqué |
| MCP-001 | Validation OPA réelle | P1 environnement | Bloqué |
| MCP-002 | Serveur MCP réel contrôlé | P1 | Terminé localement — HTTP, Streamable HTTP et stdio contrôlés |
| MCP-003 | Annulation HTTP MCP pendant un appel bloquant | P2 | En cours — MCP |
| MCP-004 | Raccord MCP au module Transport CORE canonique | P1 intégration | Ouvert — intégration coordonnée requise |
| PRODUCT-001 | Endpoint d'historique persistant des missions | P1 | Contrat produit terminé ; implémentation CORE/WEB à planifier |
| PRODUCT-002 | Comparaison de runs et vues globales Findings/Reports | P2 | Différé |
| PRODUCT-003 | Timeline et projection sûre de provenance | P2 | Terminé — `226029fa` |
| PRODUCT-004 | Sémantique produit des statuts/exécution/disponibilité | P2 | Terminé — `cebdf10f` |
| PRODUCT-005 | Validation produit des réponses History/Timeline/Status réelles | P1 intégration | En attente — dépend du lecteur/API CORE |
| TIMELINE-001 | Projection `data.timeline` dans le lecteur canonique CORE | P2 | Ouvert — CORE |
| TIMELINE-002 | Noms source des événements intention/sélection alignés à CORE | Intégration | Ouvert |
| TIMELINE-003 | Allowlists transport/protocole MCP approuvées avec Security | Sécurité | Ouvert |
| SEC-G6a | Configuration gitleaks contrôlée par le dépôt cible | P1 haute sécurité | En cours — SECURITY |
| SEC-G9 | Mesure réelle gitleaks face à un `.gitleaks.toml` hostile | P2 environnement | Bloqué |
| SEC-B6 | Durcissement garde-fous homoglyphes / espaces | P3 | Différé |
| SEC-B7 | Borne de taille de requête sortante fournisseur | P3 | Différé |

---

## Ordre d'intégration prévisionnel

1. Pousser et préserver le correctif Security P0.1 `d1d562f`, puis fermer SEC-G6a avant de considérer le scan de secrets fiable.
2. Implémenter le lecteur/API d'historique CORE selon le contrat produit, en préservant Cible et l'autorisation explicite de cible.
3. Finaliser l'annulation HTTP MCP de manière honnête et isolée ; ne pas supporter les URL distantes avant le contrat Cible/Transport joint.
4. CORE implémente `data.timeline` et `data.executions[]` enrichi avec le lecteur d'historique selon les contrats produit ; Product & UX valide alors les réponses réelles, sans toucher à l'UI partagée.
5. Réconcilier CORE + MCP autour du module Transport canonique et rejouer les tests sur l'arbre intégré ; aucun merge aveugle.
6. Security approuve les allowlists/redaction de provenance et les statuts hostiles avant exposition WEB.
7. Adapter WEB aux endpoints stabilisés après feu vert produit, sans reconstruire de logique métier côté UI.

> Cet ordre est révisable dès réception des handoffs Web, Security et Product.
