# MASTER PROMPT — PLATEFORME IA CYBERSÉCURITÉ

## 1. NOTRE OBJECTIF

Nous voulons construire une plateforme open source permettant à une IA d'orchestrer un écosystème de centaines d'outils de cybersécurité existants.

L'utilisateur décrit son besoin en langage naturel.

Exemples :

- « Analyse la sécurité de mon dépôt. »
- « Vérifie cette application web. »
- « Cherche des vulnérabilités dans cette infrastructure. »
- « Analyse ces logs. »
- « Vérifie mes dépendances. »
- « Cherche des secrets exposés. »

La plateforme comprend le besoin, détermine les capacités nécessaires, sélectionne les outils appropriés, les exécute dans un environnement contrôlé, rassemble les résultats, les normalise et présente une analyse compréhensible.

Le principe fondamental est :

```
USER REQUEST
    ↓
INTENT
    ↓
CAPABILITIES
    ↓
TOOLS
    ↓
EXECUTION
    ↓
RESULTS
    ↓
FINDINGS
    ↓
CORRELATION
    ↓
ANALYSIS
    ↓
REMEDIATION / VERIFICATION
```

Nous ne voulons PAS recréer les outils de cybersécurité.

Nous voulons construire la couche d'abstraction et d'orchestration au-dessus d'eux.

---

# 2. LE CONCEPT CENTRAL

La plateforme doit raisonner en priorité avec des CAPABILITIES plutôt qu'avec des outils.

Exemple :

```
Utilisateur :
« Trouve les endpoints de cette application. »

L'IA identifie :

CAPABILITY:
WEB_ENDPOINT_DISCOVERY

Puis cherche les outils capables de fournir cette capacité :

- Katana
- FFUF
- GAU
- etc.

Elle choisit le ou les outils pertinents selon le contexte.
```

Cela permet de rendre notre architecture indépendante des outils.

Un outil peut être remplacé sans modifier toute la logique de la plateforme.

Architecture conceptuelle :

```
CAPABILITY
    ↓
TOOL PROVIDERS
    ↓
EXECUTION
```

---

# 3. POSITIONNEMENT

La plateforme doit être :

- open source
- auto-hébergeable
- multi-LLM
- multi-outils
- multi-domaines
- MCP-compatible
- extensible
- auditable
- sécurisée par conception

Elle doit couvrir principalement la cybersécurité défensive, tout en pouvant supporter des capacités offensives dans un contexte explicitement autorisé.

Domaines potentiels :

- AppSec
- sécurité web
- réseau
- cloud
- containers
- dépendances
- secrets
- code
- threat intelligence
- DFIR
- SOC
- pentest autorisé
- purple team

---

# 4. CE QUE NOUS NE VOULONS PAS FAIRE

Nous ne voulons pas :

- recréer Nmap
- recréer Nuclei
- recréer Semgrep
- recréer DefectDojo
- recréer un gateway MCP générique sans valeur supplémentaire
- développer immédiatement des centaines d'intégrations
- construire un système multi-agent extrêmement complexe dès le début
- construire un graphe de sécurité énorme avant d'avoir un produit fonctionnel
- dépendre d'un seul fournisseur d'IA
- laisser l'IA constituer notre seule barrière de sécurité

Nous devons réutiliser intelligemment l'existant.

---

# 5. PRINCIPES ARCHITECTURAUX

## 5.1 AI ≠ Security Boundary

L'IA peut décider.

Elle ne doit jamais être la seule autorité permettant une action dangereuse.

Les règles de sécurité doivent être déterministes.

Exemples :

- cible autorisée ?
- outil autorisé ?
- niveau de risque ?
- action passive ou active ?
- confirmation nécessaire ?
- limites de ressources ?
- réseau autorisé ?
- durée maximale ?
- permissions disponibles ?

Concept :

```
AI PLANNER
    ↓
POLICY ENGINE
    ↓
EXECUTION
```

et non :

```
AI
    ↓
SHELL
```

---

# 6. LES GRANDES PHASES DU PROJET

## PHASE 0 — DISCOVERY

Objectif :

Comprendre l'écosystème existant avant d'écrire du code.

Nous recherchons les repositories et projets pertinents :

* agents IA cyber
* MCP servers
* MCP aggregators
* gateways
* registries
* orchestrateurs
* SOAR
* scanners
* vulnerability management
* sandboxing
* threat intelligence
* normalisation des findings

Livrable :

Une cartographie de l'écosystème.

STATUT :
EN COURS / TERMINÉE selon l'avancement réel.

---

## PHASE 1 — ANALYSE DE L'EXISTANT

Nous prenons l'inventaire obtenu pendant la Phase 0 et nous le réduisons fortement.

Objectifs :

* supprimer les doublons
* regrouper les projets similaires
* identifier les architectures intéressantes
* sélectionner les repositories les plus importants
* comprendre ce qui existe déjà
* déterminer ce qui peut être réutilisé
* identifier les véritables lacunes

Nous ne devons PAS analyser profondément 125 repositories.

Nous devons arriver à environ 10–20 repositories critiques.

> ⚠️ Écart acté le 2026-08-27 : la cible retenue pour la Phase 1 est une shortlist de
> **35–40 repos maximum**, pas 10–20. Voir `PROJET_ETAT.md` → « Décisions actées ».
> Ce paragraphe est conservé tel quel pour l'historique ; la valeur opposable est celle de `PROJET_ETAT.md`.

Pour chaque repository important :

* architecture
* composants
* points forts
* limites
* code réutilisable
* idées à reprendre
* idées à éviter

Livrable :

Une architecture de référence et une stratégie BUILD / INTEGRATE / ADAPT / IGNORE.

---

## PHASE 2 — ARCHITECTURE

Nous définissons précisément notre architecture.

Les grandes couches envisagées sont :

```
USER
↓
UI / API
↓
INTENT ENGINE
↓
CAPABILITY REGISTRY
↓
PLANNER / ROUTER
↓
POLICY ENGINE
↓
EXECUTION ENGINE
↓
TOOLS / MCP SERVERS
↓
RESULT NORMALIZATION
↓
FINDINGS
↓
CORRELATION
↓
REPORTING
```

Cette architecture n'est PAS figée.

Elle doit être validée ou corrigée après l'analyse des repositories.

Livrable :

Architecture technique détaillée.

---

## PHASE 3 — MINIMAL CORE

Construire uniquement le cœur minimal.

Objectif :

Faire fonctionner la tuyauterie sans chercher à créer immédiatement une plateforme complète.

Le système doit pouvoir :

1. recevoir une demande ;
2. identifier une capability ;
3. trouver un outil correspondant ;
4. exécuter l'outil ;
5. récupérer son résultat ;
6. retourner le résultat.

Très peu d'outils au départ.

Exemple :

* Semgrep
* Trivy
* Nmap

ou une sélection équivalente.

Livrable :

Premier moteur fonctionnel.

---

## PHASE 4 — PREMIER WORKFLOW END-TO-END

Choisir UN scénario extrêmement bien défini.

Exemple :

« Analyse la sécurité de mon repository. »

Workflow :

```
Repository
↓
IA
↓
Capabilities
↓
Semgrep / Trivy / secret scanner
↓
Results
↓
Findings
↓
AI analysis
↓
Report
```

Livrable :

Premier workflow réellement utilisable.

---

## PHASE 5 — CAPABILITY REGISTRY

Construire le véritable cœur différenciant.

Le registry doit représenter les capacités disponibles.

Exemple :

```
WEB_ENDPOINT_DISCOVERY
CODE_STATIC_ANALYSIS
SECRET_DETECTION
DEPENDENCY_ANALYSIS
NETWORK_DISCOVERY
CONTAINER_SCAN
CVE_LOOKUP
LOG_ANALYSIS
```

Chaque capability référence plusieurs tools/providers.

Exemple :

```
SECRET_DETECTION
├── Gitleaks
├── TruffleHog
└── GitHub secret scanning
```

L'IA ne dépend donc plus directement d'un outil spécifique.

Livrable :

Capability system extensible.

---

## PHASE 6 — ORCHESTRATION

Permettre à l'IA de composer plusieurs capabilities.

Exemple :

```
Audit web :

DISCOVERY
↓
ENDPOINT DISCOVERY
↓
TECHNOLOGY DETECTION
↓
VULNERABILITY SCANNING
↓
VALIDATION
↓
FINDINGS
```

L'IA doit pouvoir construire un workflow adapté au contexte.

Livrable :

Moteur d'orchestration.

---

## PHASE 7 — SECURITY / EXECUTION

Renforcer massivement la sécurité de l'exécution.

Éléments :

* sandbox
* isolation réseau
* isolation filesystem
* resource limits
* timeouts
* permissions
* secrets management
* audit logs
* policy engine
* scope enforcement
* classification des outils

Classification possible :

```
PASSIVE
ACTIVE
INTRUSIVE
DESTRUCTIVE
```

Les actions risquées doivent pouvoir nécessiter une validation humaine.

Livrable :

Execution layer sécurisé.

---

## PHASE 8 — FINDINGS / NORMALISATION

Les outils produisent des formats très différents.

Nous devons les rendre exploitables par la plateforme.

Standards possibles :

* SARIF
* CVE
* CVSS
* CWE
* STIX
* SBOM

Nous devons conserver :

```
RAW RESULT
+
NORMALIZED FINDING
```

Ne jamais détruire la donnée originale.

Livrable :

Unified Findings Model.

---

## PHASE 9 — CORRELATION

Une fois les findings normalisés, commencer à les corréler.

Exemple :

```
Nmap
+
Nuclei
+
CVE database
+
Cloud scanner

→ même asset
→ même service
→ même vulnérabilité potentielle
```

Objectif :

Passer de :

« voici 50 résultats »

à :

« voici 3 problèmes réellement importants ».

Livrable :

Premier moteur de corrélation.

---

## PHASE 10 — MULTI-DOMAIN

Étendre progressivement les capacités :

* Web
* Code
* Network
* Cloud
* Containers
* Dependencies
* Secrets
* SOC
* DFIR
* Threat Intelligence

Ne jamais ajouter un domaine uniquement pour augmenter le nombre d'outils.

Chaque nouveau domaine doit apporter un workflow utile.

---

## PHASE 11 — REMEDIATION / VERIFICATION

L'IA peut proposer :

* correction de code
* modification de configuration
* patch
* règle de détection
* mitigation

Puis :

```
CORRECTION
↓
RE-SCAN
↓
COMPARISON
↓
VERIFICATION
```

Objectif :

Créer une boucle :

```
DETECT → UNDERSTAND → FIX → VERIFY
```

---

## PHASE 12 — ÉCOSYSTÈME

Seulement lorsque le cœur est stable :

* plugins
* MCP tiers
* marketplace/registry
* tool discovery
* trust scoring
* signatures
* versioning
* capabilities externes

Les intégrations externes doivent être considérées comme potentiellement hostiles.

---

## PHASE 13 — SCALE

Dernière étape :

* multi-user
* organisations
* RBAC
* distributed execution
* queues
* workers
* observability
* caching
* quotas
* cloud deployment

La scalabilité vient APRÈS la validation du produit.

---

# 7. ORDRE DE PRIORITÉ

Toujours respecter cet ordre :

1. Comprendre l'existant
2. Réduire le problème
3. Définir l'architecture
4. Construire le cœur minimal
5. Prouver un workflow complet
6. Construire le capability layer
7. Ajouter l'orchestration
8. Sécuriser l'exécution
9. Normaliser les findings
10. Corréler
11. Étendre les domaines
12. Ajouter les fonctionnalités avancées
13. Scaler

---

# 8. RÈGLE CONTRE LA DISPERSION

À chaque nouvelle idée, fonctionnalité ou repository découvert, poser quatre questions :

1. Est-ce nécessaire au stade actuel ?
2. Est-ce directement lié au fil conducteur ?
3. Existe-t-il déjà une solution fiable ?
4. Est-ce que cela rapproche réellement d'un workflow fonctionnel ?

Si la réponse est non :

→ mettre l'idée dans une BACKLOG
→ ne pas interrompre la phase actuelle.

Nous devons constamment distinguer :

```
NOW / NEXT / LATER / NEVER
```

---

# 9. FIL CONDUCTEUR ABSOLU

Le projet doit toujours revenir à cette question :

> Comment transformer une intention de cybersécurité exprimée en langage naturel en une exécution fiable de capacités spécialisées, puis transformer leurs résultats en informations de sécurité exploitables ?

Tout composant qui ne contribue pas clairement à cette chaîne doit être considéré comme secondaire.

---

# 10. ÉTAT ACTUEL DU PROJET

Phase actuelle :

**PHASE 0 — DISCOVERY**

La recherche des repositories GitHub est en cours de finalisation.

Une fois l'inventaire terminé :

→ Phase 1 : analyse et réduction de l'inventaire.

IMPORTANT :

Ne pas commencer immédiatement à coder.

Ne pas sélectionner arbitrairement des technologies.

Ne pas construire l'architecture finale avant d'avoir étudié les repositories les plus pertinents.

La prochaine étape doit être décidée à partir des résultats de la Phase 0.

---

# 11. NOTE DE SESSION (ajoutée le 2026-08-27)

- Les phases sont des **portes successives**, pas une liste de fonctionnalités :
  tant qu'une phase n'est pas validée, on ne construit pas la suivante.
- État réel côté workspace : **vide au démarrage de cette session**.
  L'inventaire des ~125 repos n'a pas encore été matérialisé en fichier.
  → Voir `PROJET_ETAT.md` pour le statut suivi.

---

# 12. CE QU'ON A APPRIS EN ROUTE

Ajouté le 2026-08-28. Ces points ne figuraient pas dans le plan initial. Ils viennent de la
construction, pas de la réflexion. Ils sont là pour que les leçons survivent au projet.

## Ce qui n'était pas prévu du tout

### 1. Un outil peut faire fuiter un mot de passe

Bandit renvoie la valeur **réelle** du credential dans son champ `issue_text`. Si on conserve
les résultats bruts tels quels, **on crée nous-mêmes la fuite**.

Règle ajoutée : conserver l'empreinte, les métadonnées et une version masquée. Jamais la
valeur. C'est une exception explicite au principe « ne jamais détruire la donnée originale » —
et cette limite doit être écrite quelque part, sinon quelqu'un la redécouvrira en produisant
une fuite.

### 2. Un outil qui ne tourne pas ressemble à un outil qui n'a rien trouvé

Bandit avait disparu de la machine. La machine a continué, sans erreur, en produisant un
rapport qui avait l'air normal. **C'est le pire mode d'échec possible pour un outil de
sécurité** : le silence qui rassure.

Règle ajoutée : un outil absent ou en échec doit être déclaré dans la couverture, avec la
mention explicite « ce scan n'a rien couvert, ce n'est pas une absence de problème ».

### 3. Il y a deux publics pour le rapport

Le plan initial parle d'« analyse compréhensible ». Ce n'est pas suffisant : ce sont **deux
documents différents**.

- un ingénieur veut les empreintes, les versions, de quoi rejouer
- une personne qui décide veut savoir quoi corriger, en deux minutes

Un seul document ne peut pas servir les deux. Le nôtre était écrit pour le premier, et
inutilisable pour le second.

### 4. Chaque outil a sa propre échelle de gravité

Trivy dit `HIGH`. Semgrep dit `ERROR`. Bandit dit `MEDIUM`. Sans traduction, **tout remontait
en « indéterminé »** — donc personne ne savait quoi corriger en premier.

Règle ajoutée : traduire les échelles, et quand une échelle n'est pas reconnue, dire
« indéterminée » plutôt que d'inventer une gravité.

### 5. Les règles de sécurité savent déjà à quelle librairie elles s'appliquent

On allait écrire une table de correspondance à la main. En fait **les règles Semgrep
contiennent déjà l'information**, dans `metadata.technology` (et non `metadata.packages`,
qui est vide).

Conséquence importante : notre table manuelle n'avait **qu'une ligne**. Donc la corrélation
était aveugle à tout sauf à un cas. Sur le premier dépôt de test, elle avait « marché »
**par chance**.

Règle ajoutée : le mapping s'extrait des règles, il ne s'écrit pas.

### 6. Le modèle d'IA peut être limité par son fournisseur

Groq bloque les appels rapprochés. Sans pause, les appels échouent de façon intermittente et
le système bascule sur le moteur de secours sans qu'on sache pourquoi.

Conséquence pour la production : **il faudra une file d'attente et des relances.** Ce n'est
pas un détail d'implémentation, c'est une contrainte d'architecture.

## Ce qui était dans le plan, mais mal formulé

### 7. « Des centaines d'outils » est un mauvais objectif

Le plan initial dit « orchestrer un écosystème de centaines d'outils ». En pratique, ce qui
compte c'est la **capacité à en ajouter**, pas le nombre.

On en a 5. Et on sait en ajouter un **sans toucher au moteur**. C'est ça, la vraie réussite —
pas un catalogue.

### 8. La corrélation est un goulot, pas une phase

Le plan la place en phase 9, comme une étape parmi d'autres. En réalité **c'est le cœur du
produit** : c'est la seule chose qui transforme « voici 50 résultats » en « voici 3 problèmes ».

Et elle dépend entièrement de la qualité du mapping des règles. Si le mapping est mauvais, la
corrélation est aveugle — peu importe la qualité du moteur.

### 9. On a trop durci trop tôt

Isolation Docker, politique de conservation des secrets, test du contrat LLM… Tout ça est
utile. Mais tout a été fait **avant que quiconque ait utilisé le produit une seule fois**.

C'est exactement le piège que la règle NOW / NEXT / LATER / NEVER est censée éviter. La leçon :

> **Faire utiliser le produit avant de durcir ce que personne n'utilise encore.**

## Où on en est, honnêtement

```
le moteur fonctionne          ✅
le rapport pour humain existe ✅
quelqu'un l'a utilisé         ❌ jamais
des centaines d'outils        ❌ on en a 5
```

**Le moteur marche. Le produit n'existe pas encore.**

