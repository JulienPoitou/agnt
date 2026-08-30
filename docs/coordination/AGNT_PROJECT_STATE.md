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

---

## État des builders

| Builder | Branche | Statut rapporté | Derniers commits | Prochaine mission assignée |
|---|---|---|---|---|
| CORE | `arena/01a05415-agnt` | `COMPLETED_WITH_LIMITATIONS` | `91f1775`, `5f3f522`, `0f73325`, `084bb73`, `d1c236c` | **P1 :** descripteur de cible canonique et typé, branché sans réécriture du moteur. |
| MCP | `arena/01a05417-agnt` | `COMPLETED_WITH_LIMITATIONS` | `458d23b`, `be68844` | **P1 :** alignement sur le contrat CORE et test contre un serveur MCP contrôlé réel. |
| WEB | non reçu | en attente de handoff | — | À définir après handoff. |
| SECURITY | non reçu | en attente de handoff | — | À définir après handoff. |
| PRODUCT & UX | `arena/01a05425-agnt` | `COMPLETED_WITH_LIMITATIONS` | `18c1aad` | **P1 :** contrat produit/API minimal pour l'historique réel des missions, sans toucher aux fichiers UI partagés. |

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

### PRODUCT & UX

- Refonte de l'espace mission : navigation, création simplifiée et résultats organisés par progressive disclosure.
- État d'accueil réel quand l'API répond sans mission ; démos uniquement quand l'API est indisponible et explicitement étiquetées.
- États fiables d'attente, exécution, refus, erreur et perte de connexion.
- Présentation améliorée des findings et design system responsive avec thèmes clair/sombre/système.
- Rendu sécurisé maintenu via `textContent`.

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

### P1 — PRODUCT & UX : contrat d'historique réel des missions

Définir, sans implémenter un backend ou une nouvelle UI concurrente, le contrat produit qui débloquera l'historique :
- relation explicite entre une Mission et un Run ;
- états réellement supportés, identifiants, résumé et détails consultables ;
- endpoint de listing paginé et endpoint de relecture compatibles avec les routes actuelles ;
- provenance, confidentialité, rétention et comportement hors ligne ;
- exemples de réponses et critères d'acceptation pour CORE et WEB.

Le builder Product & UX ne touche pas à `index.html`, `app.js` ou `style.css` dans ce lot afin d'éviter un conflit avec builder-web avant réception de son handoff.

---

## Contrats et dépendances entre builders

```text
CORE : Provider / Transport / mission artifacts / future Cible
  ├── MCP : transport "mcp", résultats externes, provenance
  ├── WEB : affichage des artefacts par mission et provenance additive
  ├── SECURITY : invariants egress, policy, secrets, confiance externe
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

### Consignes cross-builder actuelles

- **WEB :** ne pas supposer un unique `PHASE3/run`; utiliser les données de mission et tolérer les champs MCP additionnels (`transport`, serveur, outil, protocole, confiance, disponibilité, corrélation).
- **SECURITY :** définir et tester les invariants d'un backend externe : egress, endpoint contrôlé par registre, secrets, timeout, policy avant appel, confiance et absence de bypass sandbox implicite.
- **PRODUCT & UX :** ne pas créer une deuxième source de vérité pour les types de cible ou les extensions. Définir le contrat d'historique réel avant toute réactivation d'onglet ou de données globales ; ne pas modifier les fichiers UI partagés avant coordination avec WEB.

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
| Historique global affiché sans source backend persistée. | Élevée produit | Garder l'historique désactivé jusqu'au contrat puis à l'endpoint réel ; aucune donnée de démonstration après une réponse API. |

---

## Limitations d'environnement connues

Ces éléments ne sont pas des régressions de code tant qu'aucune preuve contraire n'apparaît :

- Binaire OPA absent : validation de policy réelle incomplète.
- `bwrap` et plusieurs outils de scan/caches absents : certaines batteries E2E sont non évaluables.
- Pas de serveur MCP tiers ni de credential de test : interopérabilité externe réelle non prouvée à ce stade.
- Certains tests historiques échouent uniquement parce que `bandit`, `checkov`, `detect-secrets` et `radon` sont absents.
- L'API conserve actuellement les runs en mémoire et n'expose pas encore de liste persistée de missions ; l'historique produit reste volontairement désactivé.

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
| PRODUCT-001 | Endpoint d'historique persistant des missions | P1 | Bloqué par contrat backend ; contrat produit en cours |
| PRODUCT-002 | Comparaison de runs et vues globales Findings/Reports | P2 | Différé |

---

## Ordre d'intégration prévisionnel

1. Stabiliser le lot CORE Cible sans casser les contrats actuels.
2. Finaliser l'alignement MCP sur les extension points CORE et sa preuve E2E contrôlée.
3. Finaliser le contrat produit d'historique avant toute implémentation backend/UI de cette fonctionnalité.
4. Examiner les diff/contrats CORE + MCP ensemble et préparer une stratégie de merge ciblée.
5. Intégrer les contraintes SECURITY sur les transports externes.
6. Adapter WEB aux contrats stabilisés, sans reconstruire de logique métier côté UI.

> Cet ordre est révisable dès réception des handoffs Web, Security et Product.
