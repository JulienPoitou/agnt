```
# MODE BUILDER — AGNT EXTERNAL PROVIDERS / MCP

Tu travailles sur le dépôt GitHub :

`https://github.com/JulienPoitou/agnt`

## BRANCHE DE TRAVAIL

Tu travailles EXCLUSIVEMENT sur :

`arena/builder-mcp`

Cette branche est dédiée à l'intégration des **providers externes**, en particulier MCP, et à la préparation du moteur pour accueillir des capacités qui ne sont pas simplement des binaires locaux exécutés via `subprocess`.

Tu peux lire tout le dépôt.

Tu ne dois pas modifier ou remplacer arbitrairement le travail des autres branches.

---

# 1. MISSION

Ta mission est de faire évoluer AGNT pour qu'il puisse intégrer proprement des **providers externes**.

Le cas prioritaire est :

> permettre à AGNT d'utiliser des outils/capacités exposés par un serveur MCP tout en conservant les garanties d'AGNT : sélection, policy, conditions, traçabilité, normalisation, corrélation et reporting.

Mais attention :

**Le but n'est PAS simplement "ajouter MCP".**

Le véritable objectif est de supprimer le couplage implicite :

```text
provider = binaire local
provider = subprocess
provider = argv
provider = fichier YAML + executable
```

AGNT doit pouvoir évoluer vers :

```text
                 Provider
                    │
        ┌───────────┼───────────┐
        ↓           ↓           ↓
   Local CLI      MCP        HTTP/API
        │           │           │
     process     transport    request
```

sans que le pipeline principal ait besoin de connaître les détails de transport.

---

# 2. RÈGLE ABSOLUE : PAS D'AUDIT INFINI

Tu ne dois PAS refaire l'audit complet d'AGNT.

Une reconnaissance ciblée suffit.

Inspecte principalement :

* registre ;
* manifests ;
* provider abstractions ;
* adapters ;
* execution ;
* policy ;
* sandbox ;
* conditions ;
* findings ;
* ledger ;
* configuration ;
* tests associés.

Puis construis.

Le comportement attendu est :

```text
READ
→ UNDERSTAND
→ DESIGN MINIMUM NECESSARY
→ IMPLEMENT
→ TEST
→ COMMIT
→ CONTINUE
```

Pas :

```text
READ
→ AUDIT
→ AUDIT
→ AUDIT
→ RAPPORT
→ ATTENDRE
```

---

# 3. OBJECTIF ARCHITECTURAL

AGNT doit pouvoir représenter proprement plusieurs familles de providers.

À terme :

```text
LocalBinaryProvider
MCPProvider
HTTPProvider
ContainerProvider
LibraryProvider
RemoteExecutionProvider
```

Tu n'es PAS obligé d'implémenter toutes ces familles maintenant.

Tu dois surtout construire une abstraction suffisamment propre pour que leur ajout futur ne force pas une réécriture du pipeline.

---

# 4. CONTRAT FONDAMENTAL

Sépare clairement :

```text
CAPABILITY
PROVIDER
TRANSPORT
EXECUTION BACKEND
TARGET
RESULT
FINDING
```

Une capacité répond à :

> QUOI veut-on accomplir ?

Un provider répond à :

> QUI sait accomplir cette capacité ?

Un transport répond à :

> COMMENT communique-t-on avec ce provider ?

Un execution backend répond à :

> DANS QUEL ENVIRONNEMENT cette opération s'exécute-t-elle ?

Une cible répond à :

> SUR QUOI l'opération porte-t-elle ?

Ne mélange pas ces niveaux.

---

# 5. MCP N'EST PAS UNE FAILLE DANS LA POLICY

Principe de sécurité fondamental :

```text
LLM
 ↓
intent
 ↓
capability
 ↓
provider
 ↓
policy
 ↓
execution
```

MCP ne doit jamais permettre de contourner :

* OPA ;
* les conditions ;
* les restrictions de cible ;
* les règles de risque ;
* la traçabilité ;
* l'assainissement ;
* les limites d'exécution.

Le fait qu'un outil soit externe ne doit pas le rendre "de confiance".

---

# 6. NE PAS CRÉER UN DEUXIÈME MOTEUR

Interdiction de créer :

```text
MCP pipeline
```

parallèle à :

```text
AGNT pipeline
```

Le chemin doit rester conceptuellement :

```text
Mission
 ↓
Intent
 ↓
Capabilities
 ↓
Provider selection
 ↓
Plan
 ↓
Policy
 ↓
Execution backend
 ↓
Result
 ↓
Normalization
 ↓
Correlation
 ↓
Report
```

MCP doit être **un type de provider/execution**, pas un nouveau système d'orchestration.

---

# 7. ANALYSE CIBLÉE DU COUPLAGE ACTUEL

Cherche dans le code tous les endroits où le moteur suppose implicitement :

```text
provider.binaire
provider.argv
subprocess.Popen
command
args
executable
filesystem
```

Classe ces occurrences :

### Couplage légitime

Certaines parties doivent effectivement rester spécifiques aux providers locaux.

### Couplage architectural

Certaines parties devraient dépendre d'un contrat générique.

Ne transforme pas aveuglément chaque occurrence.

---

# 8. DESIGN DU CONTRAT PROVIDER

Si le code actuel le permet, construis un contrat conceptuel de ce type :

```text
Provider
 ├── identity
 ├── capabilities
 ├── target requirements
 ├── risk
 ├── availability
 ├── transport
 ├── execution
 └── result contract
```

Le contrat réel doit naturellement respecter les conventions existantes d'AGNT.

Ne copie pas cette structure littéralement si une meilleure structure existe déjà.

Le code existant reste prioritaire.

---

# 9. MCP DISCOVERY

Le système doit idéalement pouvoir distinguer :

```text
MCP server
    ↓
tools
    ↓
capabilities
```

Mais attention :

**ne donne jamais directement au modèle le pouvoir de transformer arbitrairement un outil MCP en capability autorisée.**

Les capacités autorisées doivent rester contrôlées par le registre/policy.

Un serveur MCP qui expose :

```text
tool_A
tool_B
tool_C
```

ne signifie pas automatiquement :

```text
AGNT peut exécuter A/B/C.
```

Il faut une relation explicite :

```text
registered capability
        ↕
approved provider/tool
        ↕
MCP server
```

---

# 10. IDENTITÉ DES PROVIDERS

Chaque provider externe doit avoir une identité stable.

Évite les identités dépendant uniquement :

```text
hostname
process id
adresse mémoire
ordre de découverte
```

Une identité logique doit être reproductible.

Elle devra pouvoir apparaître dans :

* plan ;
* ledger ;
* journal ;
* findings ;
* rapport ;
* audit trail.

---

# 11. VERSIONNAGE

Prévois la possibilité de distinguer :

```text
provider identity
provider version
server version
tool version
protocol version
```

Ne mélange pas ces informations.

Le reporting devra pouvoir dire :

```text
provider = X
tool = Y
version = Z
transport = MCP
```

sans ambiguïté.

---

# 12. DISPONIBILITÉ

Le système actuel possède déjà une notion de provider indisponible.

Exploite-la.

Pour MCP, une indisponibilité peut être :

```text
server unavailable
transport unavailable
authentication unavailable
tool unavailable
capability unavailable
protocol mismatch
timeout
```

Une indisponibilité doit être explicitement traçable.

Ne transforme jamais :

```text
provider indisponible
```

en :

```text
provider absent de la mission
```

sans explication.

---

# 13. TIMEOUTS

Un provider externe ne doit jamais pouvoir bloquer indéfiniment une mission.

Construis ou exploite des contrats permettant :

* timeout de connexion ;
* timeout d'appel ;
* timeout global ;
* annulation ;
* propagation de l'arrêt.

Ne fais pas dépendre toute la mission d'un serveur MCP qui ne répond plus.

---

# 14. CONCURRENCE

Le moteur d'AGNT supporte déjà des exécutions parallèles.

Un provider MCP doit pouvoir s'insérer dans ce modèle.

Attention aux états partagés :

```text
MCP client global
MCP session globale
connexion partagée
cache global
credentials globales
```

Une mission ne doit pas pouvoir contaminer une autre mission.

Si le transport nécessite un état mutable, isole-le au niveau approprié.

---

# 15. SÉCURITÉ DES ENTRÉES

Les données suivantes doivent être considérées comme non fiables :

```text
MCP server metadata
tool descriptions
tool schemas
tool output
remote errors
remote strings
tool names
arguments
```

Ne mets jamais directement une donnée externe dans :

```text
shell command
policy expression
filesystem path
HTML
Markdown sensible
log non structuré
```

sans validation/assainissement approprié.

---

# 16. TOOL SCHEMAS

MCP permet à un outil de déclarer des paramètres.

Le cœur doit traiter ces schémas comme des données non fiables.

Il faut empêcher qu'un schéma externe puisse :

* modifier le plan ;
* contourner une validation ;
* injecter une commande ;
* modifier le niveau de risque ;
* modifier les permissions ;
* contourner la policy.

Le schéma décrit une interface.

Il ne définit PAS l'autorisation.

---

# 17. ARGUMENTS

C'est un point central.

Le modèle ne doit jamais pouvoir produire arbitrairement :

```text
shell command
```

et demander à MCP de l'exécuter.

Le flux doit rester :

```text
LLM
 ↓
structured intent
 ↓
registered capability
 ↓
approved provider
 ↓
validated arguments
 ↓
policy
 ↓
provider invocation
```

Si un outil MCP accepte une URL :

```text
url
```

cela ne signifie pas que n'importe quelle URL est automatiquement autorisée.

La validation de cible reste du ressort d'AGNT.

---

# 18. TARGET MODEL

Le MCP provider doit être compatible avec l'évolution future du modèle de cible.

AGNT doit pouvoir évoluer de :

```text
repository path
```

vers :

```text
repository
URL
host
network
container
image
cloud resource
```

Ne construis pas maintenant tous ces types.

Mais ne crée pas une abstraction MCP qui rend leur ajout plus difficile.

---

# 19. RESULT CONTRACT

Un provider externe doit retourner un résultat que le moteur peut normaliser.

Le transport ne doit pas dicter le format final des findings.

Le flux doit être :

```text
MCP output
 ↓
provider result
 ↓
normalizer
 ↓
Finding
```

et non :

```text
MCP output
 ↓
directly displayed
```

---

# 20. FINDINGS

Ne laisse pas MCP créer arbitrairement des findings de confiance.

Le moteur doit appliquer les mêmes règles de normalisation que les autres providers :

* identité ;
* source ;
* localisation ;
* sévérité ;
* evidence ;
* fingerprint ;
* assainissement.

Les findings MCP doivent être indistinguables structurellement des findings provenant d'un outil local.

---

# 21. TRAÇABILITÉ

Chaque appel externe pertinent doit pouvoir être reconstruit.

Le journal doit idéalement permettre de déterminer :

```text
mission
→ provider
→ serveur
→ outil
→ capacité
→ arguments validés
→ décision policy
→ début
→ fin
→ statut
→ résultat
```

Attention aux secrets.

Ne loggue jamais :

* tokens ;
* API keys ;
* credentials ;
* secrets renvoyés par un provider.

Utilise les mécanismes d'assainissement existants.

---

# 22. POLICY

Le provider MCP doit être soumis à la policy.

Le policy engine doit pouvoir répondre à des questions comme :

```text
Ce provider est-il autorisé ?
Cette capability est-elle autorisée ?
Cette cible est-elle autorisée ?
Cette opération est-elle autorisée ?
Le réseau est-il autorisé ?
Le niveau de risque est-il compatible ?
```

Ne contourne jamais OPA simplement parce que MCP est externe.

Si l'architecture actuelle ne permet pas de représenter proprement MCP dans OPA, améliore le contrat.

---

# 23. SANDBOX

Ne prétends pas qu'un serveur MCP est sandboxé simplement parce qu'AGNT est sandboxé.

Il y a potentiellement plusieurs frontières :

```text
AGNT process
     ↓
MCP client
     ↓
network
     ↓
MCP server
     ↓
external tool
```

La sandbox locale protège ce qu'elle contient.

Elle ne protège pas magiquement le serveur distant.

Le système doit donc représenter correctement la frontière de confiance.

---

# 24. TRUST MODEL

Construis une distinction claire entre :

```text
trusted local execution
untrusted local tool
trusted configured MCP server
untrusted remote MCP server
```

Ne donne pas au remote provider plus de confiance qu'il n'en mérite.

---

# 25. AUTHENTIFICATION

Si MCP nécessite une authentification :

* ne hardcode jamais de secrets ;
* ne commit jamais de credentials ;
* ne les place jamais dans les manifests versionnés ;
* utilise la configuration sécurisée existante ;
* masque les secrets dans les logs.

Si aucune infrastructure d'authentification propre n'existe encore, implémente uniquement le socle nécessaire.

Ne construis pas un système IAM entier.

---

# 26. CONFIGURATION

Privilégie une configuration déclarative.

Exemple conceptuel :

```yaml
provider:
  id: ...
  transport: mcp
  endpoint: ...
  capabilities:
    - ...
```

Mais adapte cela au format réel d'AGNT.

Le registre doit rester la source d'autorisation.

Évite les listes codées en dur.

---

# 27. EXTENSIBILITÉ

Un nouvel MCP provider devrait idéalement pouvoir être ajouté sans :

```text
modifier pipeline.py
modifier intent.py
modifier analyser.py
ajouter une condition spéciale
ajouter un if provider == "mcp"
```

Cherche activement les futurs :

```text
if provider == ...
if tool == ...
if transport == ...
```

et élimine-les lorsqu'une abstraction déclarative est raisonnablement possible.

Mais ne remplace pas un simple `if` par 500 lignes d'abstraction.

---

# 28. TESTS

Construis des tests qui prouvent les invariants importants.

Priorité :

### Provider contract

Un provider externe respecte le contrat.

### Policy

Un provider externe ne contourne pas la policy.

### Arguments

Les arguments sont validés avant invocation.

### Isolation

Une mission ne partage pas incorrectement l'état d'une autre.

### Timeout

Un provider bloqué ne bloque pas indéfiniment la mission.

### Findings

Une sortie MCP peut être normalisée.

### Ledger

L'appel est traçable.

### Secrets

Les credentials ne se retrouvent pas dans les artefacts.

### Failure

Serveur absent / timeout / tool absent / réponse invalide :

→ statut explicite.

Ne crée pas de tests qui prétendent qu'un vrai serveur MCP fonctionne si tu n'en as pas exécuté un.

---

# 29. TESTS RÉELS VS MOCKS

Les mocks sont acceptés pour tester :

```text
contrats
erreurs
timeouts
validation
policy
normalisation
```

Mais ils ne prouvent pas :

```text
MCP réellement opérationnel
```

Si tu construis un test réel, indique clairement :

```text
REAL
```

et si tu utilises un faux serveur :

```text
INTEGRATION SIMULATED
```

Ne confonds jamais les deux.

---

# 30. COMPATIBILITÉ AVEC BUILDER-CORE

`builder-core` travaille simultanément sur les abstractions du moteur.

Tu dois donc :

* exploiter les contrats déjà présents ;
* éviter de créer une abstraction concurrente ;
* si nécessaire, proposer une extension minimale du contrat ;
* ne pas réécrire le cœur pour ton seul cas MCP.

Si tu dois modifier une interface fondamentale :

1. fais la modification minimale ;
2. conserve la compatibilité autant que possible ;
3. teste les anciens providers ;
4. documente le nouveau contrat dans le code ;
5. commit proprement.

---

# 31. COMPATIBILITÉ AVEC BUILDER-TOOLS

`builder-tools` ajoutera de nombreux outils locaux.

Ton travail doit rendre les différences entre :

```text
local provider
external provider
```

explicites mais gérables.

Le nouveau système ne doit pas rendre l'ajout d'un scanner local plus compliqué.

---

# 32. COMPATIBILITÉ AVEC BUILDER-WEB

Le futur UI doit pouvoir afficher :

```text
provider
transport
availability
status
tool
findings
```

sans connaître les détails du protocole MCP.

Expose donc des informations structurées.

Ne force pas le frontend à parser des messages bruts.

---

# 33. COMPATIBILITÉ AVEC BUILDER-SECURITY

`builder-security` travaillera sur :

* sandbox ;
* policy ;
* isolation ;
* sécurité d'exécution.

Si tu détectes un problème relevant clairement de SECURITY :

* ne l'absorbe pas silencieusement ;
* laisse une note technique claire ;
* ne construis pas une seconde implémentation de sandbox.

---

# 34. CE QUE TU NE DOIS PAS FAIRE

Ne :

* crée pas un deuxième orchestrateur ;
* ne contourne pas OPA ;
* ne contourne pas le registre ;
* ne donne pas au LLM des permissions supplémentaires ;
* ne hardcode pas les outils MCP ;
* ne hardcode pas les serveurs MCP ;
* ne stocke pas de credentials ;
* ne transforme pas MCP en shell distant ;
* ne considère pas les tool descriptions comme fiables ;
* ne considère pas les résultats MCP comme sûrs ;
* ne supprime pas la traçabilité ;
* ne désactive pas le sandbox pour "faire fonctionner MCP" ;
* ne prétends pas avoir validé MCP réellement si aucun serveur réel n'a été utilisé ;
* ne réécris pas tout le cœur.

---

# 35. PRIORITÉ DES CHANTIERS

Cherche d'abord les obstacles architecturaux.

Ordre recommandé :

```text
P0
Provider abstraction bloquante

P1
Transport/execution contract

P1
Policy + validation

P1
Result contract

P2
Timeout / cancellation

P2
Observability

P2
Configuration déclarative

P3
Real MCP integration

P3
UX
```

Mais si le dépôt actuel révèle un ordre plus pertinent, suis le code et explique brièvement pourquoi.

---

# 36. MODE BUILDER

Tu dois travailler comme un ingénieur autonome.

Tu peux :

* créer les abstractions nécessaires ;
* modifier les modules concernés ;
* ajouter des tests ;
* ajouter des manifests ;
* ajouter des fixtures ;
* installer des dépendances de développement raisonnables ;
* lancer les tests ;
* corriger les régressions ;
* commit.

Tu ne dois pas demander confirmation pour chaque petite décision.

Décide toi-même lorsque la décision est locale et réversible.

Demande seulement lorsqu'une décision implique une rupture majeure ou un choix produit impossible à déduire.

---

# 37. BOUCLE DE TRAVAIL

Pour chaque lot :

```text
1. Reconnaissance ciblée
2. Choix du problème
3. Implémentation
4. Tests ciblés
5. Tests de régression
6. Mesure
7. Commit
8. Prochain problème
```

Ne t'arrête pas après avoir créé une interface vide.

Une abstraction compte uniquement si elle est utilisée.

---

# 38. CRITÈRE DE RÉUSSITE

À la fin de ton travail, AGNT doit être plus proche de :

```text
                 AGNT
                   │
            Provider Contract
                   │
       ┌───────────┼───────────┐
       ↓           ↓           ↓
     Local         MCP        Future
     CLI          Tools       Remote
       │           │
       └───────────┼───────────┘
                   ↓
              Normalizer
                   ↓
                Finding
                   ↓
              Correlation
                   ↓
                Report
```

Le gain recherché n'est pas :

> "MCP est maintenant mentionné dans le code."

Le gain recherché est :

> "Ajouter un nouveau type de provider ne nécessite plus de casser le cœur."

---

# 39. PREUVE

Pour chaque fonctionnalité importante, classe-la :

```text
IMPLEMENTED + VERIFIED
IMPLEMENTED + PARTIALLY VERIFIED
IMPLEMENTED + NOT EXERCISED
BLOCKED
```

Ne transforme jamais un mock en preuve réelle.

---

# 40. COMMIT

Chaque lot cohérent doit être committé.

Format :

```text
mcp: <description>
```

Exemples :

```text
mcp: introduce external provider contract
mcp: validate external provider capabilities
mcp: add MCP transport backend
mcp: normalize MCP tool results
mcp: enforce provider timeout
```

Commits petits, cohérents et réversibles.

---

# 41. RAPPORT

À la fin de chaque lot :

```text
LOT
- objectif

IMPLEMENTED
- ...

VERIFIED
- ...

TESTS
- ...

COMMIT
- SHA

LIMITATIONS
- ...

NEXT
- ...
```

Ne rédige pas un audit complet du dépôt.

Le dépôt doit contenir l'essentiel du travail.

---

# 42. PREMIÈRE ACTION

Commence maintenant.

Fais une reconnaissance ciblée du contrat actuel entre :

```text
registry
provider
adapter
execution
policy
result
```

Identifie le **premier couplage qui empêcherait réellement un provider externe**.

Puis corrige-le.

Ne reste pas bloqué à la phase de conception.

Si le contrat actuel est déjà suffisamment générique, ne crée pas une abstraction inutile : construis directement l'adaptateur MCP minimal qui respecte les contrats existants.

Après le premier lot :

```text
TEST
→ COMMIT
→ CONTINUE
```

# RÈGLE FINALE

> MCP doit devenir une capacité d'AGNT, pas devenir un deuxième AGNT.

Construis l'interface qui permettra à AGNT d'accueillir des providers externes pendant que les autres builders travaillent en parallèle.

**READ ENOUGH TO ACT.
ACT.
VERIFY.
COMMIT.
CONTINUE.**
```