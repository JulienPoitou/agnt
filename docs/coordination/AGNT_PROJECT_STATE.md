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
| **Cible distincte du sandbox** | Une cible n'est pas automatiquement un `Path` local ; une cible distante ne doit jamais être montée ou exécutée comme un faux chemin local. |
| **Pas de faux état produit** | Quand l'API répond mais qu'aucune mission n'existe, l'interface affiche un accueil réel, jamais des données de démonstration. |
| **Progressive disclosure** | L'UX montre d'abord le résultat métier ; providers et détails techniques restent secondaires. Les données non fiables sont rendues avec `textContent`, jamais `innerHTML`. |
| **Autorisation de cible explicite** | `cible_autorisee` n'a aucun défaut permissif : seul `True` explicite l'arme ; l'API dérive cette autorisation exclusivement de la liste opérateur `cibles_admises()`. |
| **Jeux de règles de sécurité contrôlés** | Un scanner ne doit jamais charger une configuration fournie par le dépôt analysé. Une règle doit venir d'une source AGNT de confiance, montée en lecture seule et vérifiée. |

---

## État des builders

| Builder | Branche | Statut rapporté | Derniers commits | Prochaine mission assignée |
|---|---|---|---|---|
| CORE | `arena/01a05415-agnt` | `COMPLETED_WITH_LIMITATIONS` | `91f1775`, `5f3f522`, `0f73325`, `084bb73`, `d1c236c` | **P1 :** descripteur de cible canonique et typé, branché sans réécriture du moteur. |
| MCP | `arena/01a05417-agnt` | `COMPLETED_WITH_LIMITATIONS` | `458d23b`, `be68844` | **P1 :** alignement sur le contrat CORE et test contre un serveur MCP contrôlé réel. |
| WEB | non reçu | en attente de handoff | — | À définir après handoff. |
| SECURITY | `arena/01a05426-agnt` | `PARTIAL` | `d1d562f` — non poussé au handoff | **P1 :** pousser le correctif P0.1 puis fermer SEC-G6a : jeu de règles gitleaks de confiance. |
| PRODUCT & UX | `arena/01a05425-agnt` | `COMPLETED` | `18c1aad`, `bb2de26` | **P2 :** contrat de timeline/provenance sûre, sans toucher aux fichiers UI partagés. |

---

## Terminé — ne pas refaire

### CORE

- Suppression de la mutation des globales d'intention dans les flux modernes.
- Isolation des sorties d'exécution par mission avec `Execution.sortie`.
- Séparation Provider / Transport.
- Module de transport extensible et validation fail-closed des manifests.
- Observabilité structurée : décision d'intention et sélection de providers dans le journal.

### MCP

- Première couche d'intégration MCP dans le pipeline AGNT existant, sans second orchestrateur.
- Binding obligatoire registre ↔ capability ↔ provider ↔ serveur ↔ outil.
- Validation locale des déclarations, arguments, types de cible et sorties non fiables.
- Normalisation des findings MCP dans le chemin commun AGNT.
- Provenance MCP, corrélation, ledger, reporting, API et SARIF enrichis de façon additive.
- Tests contractuels et intégration simulée en mémoire.

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

---

## Travaux actifs et prochains jalons

### P1 — CORE : descripteur de cible typé

Créer une représentation canonique de la cible, en réutilisant le vocabulaire existant `target_types`.

Critères clés :
- compatibilité avec les appels historiques utilisant `Path` ;
- sélection de providers selon le type de cible ;
- plan, policy et journal capables de décrire une cible structurée ;
- pas de conversion silencieuse d'une URL en chemin local ;
- `sandbox_cli` ne reçoit qu'une cible locale autorisée ;
- aucun modèle `Target/Cible` concurrent côté MCP, Web ou Security.

### P1 — MCP : intégration prête à fusionner et test réel contrôlé

- S'appuyer sur le contrat CORE de transport plutôt que le redéfinir.
- Prévoir un bootstrap explicite et déterministe de `transports.enregistrer("mcp", ...)` avant `Registry()`.
- Éviter toute duplication durable de contrat Provider/Transport.
- Ajouter un serveur MCP local contrôlé pour exercer réellement les transports effectivement implémentés.
- Prouver binding, refus policy/egress, timeout, redaction, provenance et nettoyage de ressources.
- Ne pas présenter une simulation en mémoire comme une interopérabilité MCP tierce réelle.

### P2 — PRODUCT & UX : contrat de timeline et provenance sûre

Le contrat P1 d'historique est terminé dans `docs/coordination/MISSION_HISTORY_CONTRACT.md` avec schéma, fixtures et tests.

Définir maintenant, sans implémenter backend ou UI, la projection sûre du journal append-only en timeline lisible :
- ordre, horodatage, états et niveaux de détail non inventés ;
- provenance MCP additive et redacted ;
- compatibilité avec `agnt.history.v1` ;
- critères d'acceptation pour CORE, WEB, MCP et SECURITY.

Le builder Product & UX ne touche pas à `index.html`, `app.js` ou `style.css` dans ce lot afin d'éviter un conflit avec builder-web avant réception de son handoff.

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
- `tools/list` est informatif, jamais une autorité d'autorisation.
- Les nouveaux champs de provenance doivent être additifs pour Web/API/SARIF.

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
- **CORE / MCP :** tout nouvel appel à `pipeline.executer()` ou nouveau type de cible doit préserver l'autorisation explicite ; aucune cible externe ne doit contourner la liste opérateur et la policy.
- **PRODUCT & UX :** ne pas créer une deuxième source de vérité pour les types de cible ou les extensions. Le contrat d'historique est terminé ; définir maintenant la timeline/provenance sans modifier les fichiers UI partagés avant coordination avec WEB.
- **CORE :** implémenter l'historique depuis le lecteur canonique de mission, sans base parallèle, et enrichir le polling par `mission_id` / `detail_href` dès disponibilité.
- **WEB :** consommer exclusivement `/api/missions` pour l'historique, en utilisant `mission_id` comme référence persistante ; ne jamais reconstruire une liste locale.

---

## Risques d'intégration à suivre

| Risque | Gravité | État / réponse prévue |
|---|---:|---|
| CORE et MCP ont tous deux touché des fichiers centraux (`pipeline`, `registre`, `adapters`, etc.). | Élevée à l'intégration | MCP doit réduire les doublons et fournir une carte de compatibilité ; aucun merge aveugle. |
| Initialisation du transport MCP avant validation des manifests. | Élevée | Bootstrap explicite et déterministe requis avant intégration MCP. |
| Serveur MCP externe hors sandbox locale. | Élevée | Contrôles Security et provenance/confiance obligatoires ; jamais présenter cela comme sandboxé. |
| Test MCP uniquement simulé. | Élevée pour la preuve d'interopérabilité | Builder MCP crée un serveur contrôlé local et des tests E2E réels. |
| Cible encore principalement représentée par un `Path`. | Architecturale P1 | Mission CORE active ; Web/MCP/Security ne créent pas d'abstraction concurrente. |
| Annulation HTTP en cours d'appel MCP. | Moyenne | MCP-003 reste ouvert jusqu'à preuve réelle ou solution documentée. |
| PRODUCT & UX et WEB peuvent modifier les mêmes fichiers d'interface (`index.html`, `app.js`, `style.css`). | Élevée à l'intégration | Product & UX travaille désormais sur le contrat d'historique hors de ces fichiers ; attendre le handoff WEB avant tout nouveau chantier UI. |
| Historique global affiché sans source backend persistée. | Élevée produit | Contrat P1 terminé ; garder l'historique désactivé jusqu'à l'implémentation réelle de `GET /api/missions`, sans données de démonstration après une réponse API. |
| Gitleaks peut charger une configuration hostile du dépôt et masquer des secrets (SEC-G6a). | Haute sécurité | Correctif Security P1 actif : config AGNT explicite, vérifiée et fail-closed ; ne pas déclarer la détection de secrets fiable avant fermeture. |
| Le contrat d'autorisation de cible peut être perdu lors des évolutions CORE/MCP. | Haute sécurité | Préserver `cible_autorisee=True` explicite et l'autorité exclusive de la liste opérateur API ; tests de régression Security déjà ajoutés. |

---

## Limitations d'environnement connues

Ces éléments ne sont pas des régressions de code tant qu'aucune preuve contraire n'apparaît :

- Binaire OPA absent : validation de policy réelle incomplète.
- `bwrap` et plusieurs outils de scan/caches absents : certaines batteries E2E sont non évaluables.
- Pas de serveur MCP tiers ni de credential de test : interopérabilité externe réelle non prouvée à ce stade.
- Certains tests historiques échouent uniquement parce que `bandit`, `checkov`, `detect-secrets` et `radon` sont absents.
- L'API conserve actuellement les runs en mémoire et n'expose pas encore de liste persistée de missions ; l'historique produit reste volontairement désactivé.
- Gitleaks réel est absent : la vulnérabilité de configuration hostile est reproductible par contrat/argv mais sa mesure avec le binaire reste non évaluée.

---

## Backlog architectural connu

| ID | Sujet | Priorité | Statut |
|---|---|---:|---|
| CORE-001 | Cible typée / descriptor canonique | P1 | En cours — CORE |
| CORE-002 | Graphe d'exécution explicite dans `plan.json` | P2 | Différé |
| CORE-003 | Validation E2E avec OPA/bwrap/outils | Environnement | Bloqué |
| MCP-001 | Validation OPA réelle | P1 environnement | Bloqué |
| MCP-002 | Serveur MCP réel contrôlé | P1 | En cours — MCP |
| MCP-003 | Annulation HTTP MCP pendant un appel bloquant | P2 | Ouvert |
| PRODUCT-001 | Endpoint d'historique persistant des missions | P1 | Contrat produit terminé ; implémentation CORE/WEB à planifier |
| PRODUCT-002 | Comparaison de runs et vues globales Findings/Reports | P2 | Différé |
| PRODUCT-003 | Timeline et projection sûre de provenance | P2 | En cours — PRODUCT & UX |
| SEC-G6a | Configuration gitleaks contrôlée par le dépôt cible | P1 haute sécurité | En cours — SECURITY |
| SEC-G9 | Mesure réelle gitleaks face à un `.gitleaks.toml` hostile | P2 environnement | Bloqué |
| SEC-B6 | Durcissement garde-fous homoglyphes / espaces | P3 | Différé |
| SEC-B7 | Borne de taille de requête sortante fournisseur | P3 | Différé |

---

## Ordre d'intégration prévisionnel

1. Pousser et préserver le correctif Security P0.1 `d1d562f`, puis fermer SEC-G6a avant de considérer le scan de secrets fiable.
2. Stabiliser le lot CORE Cible sans casser les contrats actuels, notamment l'autorisation explicite de cible.
3. Finaliser l'alignement MCP sur les extension points CORE et sa preuve E2E contrôlée.
4. Implémenter l'historique à partir du contrat produit terminé, après stabilisation du lecteur canonique CORE ; ne pas réactiver l'UI avant l'endpoint réel.
5. Finaliser le contrat produit de timeline/provenance en parallèle, sans toucher à l'UI partagée.
6. Examiner les diff/contrats CORE + MCP + SECURITY ensemble et préparer une stratégie de merge ciblée.
7. Adapter WEB aux contrats stabilisés, sans reconstruire de logique métier côté UI.

> Cet ordre est révisable dès réception des handoffs Web, Security et Product.
