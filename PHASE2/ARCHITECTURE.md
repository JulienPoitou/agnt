# PHASE 2 — ARCHITECTURE TECHNIQUE

_Décision validée le 2026-08-27. Licence de travail : Apache-2.0._

**La phrase d'architecture :**

```
LLM → Plan typé → OPA → Executor déterministe → Sandbox → Tools
```

Tout le reste attend que ce chemin fonctionne de bout en bout.

---

## 1. Les couches

```
UI / API                        FastAPI
  ↓
INTENT ENGINE                   LLM + registre de capacités en contexte
  ↓                             sortie validée par schéma, jamais du texte libre
PLAN (objet typé, sérialisable) ← LA FRONTIÈRE DE SÉCURITÉ
  ↓
POLICY ENGINE                   OPA en sidecar HTTP — autorise ou refuse le plan
  ↓
EXECUTOR                        Python déterministe, sans shell arbitraire
  ↓
ADAPTERS                        un par type de provider
  ↓
SANDBOX                         conteneur rootless, réseau coupé
  ↓
TOOLS
  ↓
NORMALIZATION                   RAW conservé + FINDING interne + export SARIF
  ↓
FINDINGS STORE                  source de vérité
  ↓
CORRELATION → ANALYSIS → REPORTING → REMEDIATION      (phases 9 à 11)
```

### 1.1 Pourquoi le plan est la frontière

L'IA ne produit **jamais** une commande. Elle produit un objet typé et sérialisable.

```
AI PLANNER → PLAN → POLICY ENGINE → EXECUTOR
```

Trois conséquences structurantes, pas seulement stylistiques :

- le policy engine évalue des **données**, donc ses règles sont testables sans LLM ;
- le plan est **auditable** : on peut rejouer une exécution et montrer ce qui a été autorisé ;
- `AI → SHELL` devient **impossible par construction**, pas simplement découragé.

### 1.2 Le capability registry : qui connaît quoi

```
Le planner ne connaît pas Trivy.
Le registry connaît Trivy.
L'adaptateur sait exécuter Trivy.
```

Le moteur ne contient **aucun nom d'outil en dur**. Le registre, si — c'est son rôle, et c'est
une donnée, pas du code. Ajouter un outil = ajouter un bloc YAML.

---

## 2. Le modèle de provider — graphe contrôlé, pas récursion libre

Les quatre kinds sont retenus :

```
tool          → CLI/API directe
mcp_server    → un serveur MCP
aggregator    → expose d'autres providers
gateway       → route vers plusieurs providers
```

**Mais la résolution n'est pas récursive libre.** Un provider peut en référencer un autre,
dans un graphe contraint par :

| Contrainte | Règle |
|---|---|
| Profondeur maximale | bornée, configurée, **pas infinie** |
| Détection de cycles | obligatoire, à la résolution |
| Liste d'origines | chaque provider trace sa provenance |
| Limites de confiance | un provider tiers n'hérite pas de la confiance de son parent |
| Validation par étape | **chaque** saut repasse par le policy engine |
| Timeout global | borne la chaîne entière, pas seulement chaque saut |
| Résolution dynamique | **interdite** sans autorisation explicite |

**En Phase 3, le chemin est réduit à :**

```
capability → outil CLI → sandbox
```

Aucun agrégateur, aucun gateway, aucun MCP dans le chemin d'exécution. La résolution
multi-sauts viendra après, quand ce chemin simple fonctionnera réellement.

---

## 3. Le schéma du capability registry

Aucun des 324 projets inventoriés ne fournit ce schéma : les registries existants décrivent
des *serveurs MCP*, pas des capacités de sécurité et leurs providers. **BUILD**, inspiré de
Cortex (analyzer / job / flavor) et Velociraptor (artifacts / acls).

```yaml
id: SECRET_DETECTION
description: "Détecte secrets et credentials exposés dans du code ou son historique"
domaines: [code, secrets]
sortie: finding/secret-exposure

providers:
  - id: gitleaks
    kind: tool
    mode: CLI
    risque: PASSIVE
    preconditions: {cible: [repo, filesystem]}
    cout: faible
    licence: MIT
    # Ajouté après lecture du code (PHASE3/VERIF_OUTILS.md) :
    image: zricethezav/gitleaks
    run_as_user: 1000              # l'image officielle tourne en root
    args_obligatoires: ["--redact"]  # sans ça, le secret est stocké EN CLAIR
```

Champs obligatoires d'un provider : `id`, `kind`, `mode`, `risque`
(`PASSIVE` / `ACTIVE` / `INTRUSIVE` / `DESTRUCTIVE`), `preconditions`, `cout`.

**`args_obligatoires` n'est pas optionnel.** La lecture du code a montré que chaque outil a ses
propres pièges — télémétrie activée par défaut chez Trivy, secrets en clair chez Gitleaks,
images qui tournent en root. Ces flags ne peuvent pas être laissés à la discrétion du planner :
ils sont imposés par le registre et vérifiés par le policy engine.

La classification de risque est **une donnée du registre**, évaluée par le policy engine avant
exécution. Ce n'est jamais une décision de l'IA.

---

## 4. Findings — le modèle interne est la source de vérité

```
RAW RESULT                    immuable, jamais détruit
    +
NORMALIZED FINDING INTERNE    source de vérité
    +
SARIF IMPORT / EXPORT         format d'échange, pas le modèle
```

**SARIF ne porte pas le cycle de vie.** Le modèle interne conserve :

```
status · first_seen · last_seen · false_positive · reopened · verified
evidence · asset · source_tool · source_run
```

`source_run` est ce qui rend la boucle `DETECT → FIX → VERIFY` possible : sans lien vers
l'exécution d'origine, on ne peut pas prouver qu'un re-scan a réellement corrigé quelque chose.

### 4.1 Deux contraintes découvertes en lisant le code

**La sévérité ne peut pas être déléguée aux outils.** La structure `Finding` de Gitleaks
(`report/finding.go`) ne contient **aucun champ de sévérité** — seulement `RuleID`, `Tags` et
`Entropy`. Notre modèle interne doit donc porter la sévérité et la dériver lui-même.

**Conserver le RAW entre en conflit avec la sécurité.** Gitleaks renvoie le champ `Secret`
**en clair**, et `--redact` n'est pas actif par défaut. Conserver le RAW intégral reviendrait
à stocker des credentials en clair dans notre base — ce qui viole notre propre principe
« aucun secret par défaut ».

**Décision actée le 2026-08-27 : la valeur du secret n'entre jamais dans notre base.**

On conserve uniquement les métadonnées utiles : type, fichier, ligne, outil, fingerprint/hash,
sévérité. La valeur du secret est **amputée du RAW au moment de la normalisation**, avant tout
stockage.

Conséquences à assumer :

- le RAW n'est donc **pas** intégralement conservé pour ce type de finding. C'est une exception
  explicite et volontaire au principe « ne jamais détruire la donnée originale ».
- si un jour on a besoin de la valeur exacte, **on relance l'outil**. C'est le prix de la décision.
- chaque adaptateur qui manipule des secrets doit passer les flags de redaction de l'outil
  (`--redact` pour Gitleaks) **et** amputer au niveau de la normalisation. Les deux, pas un seul :
  le flag protège la sortie de l'outil, l'amputation protège notre base.

---

## 5. Policy engine — OPA en sidecar

OPA est validé comme autorité de décision : politiques Rego, APIs exposées, bundles
signables. **Mais pas comme SDK Python.**

```
Python execution engine
    ↓  HTTP  (ou WASM)
OPA
```

OPA est écrit en Go et son intégration native est `github.com/open-policy-agent/opa/rego`.
Depuis Python, c'est un appel réseau ou un module WASM — pas un import.

**Répartition des rôles :** OPA **décide**, le code Python **applique**. Le moteur ne doit
jamais contenir de règle de sécurité en dur, sinon il existe deux autorités et la seconde
est contournable.

---

## 6. Sandbox — conditions non négociables

Le conteneur simple n'est acceptable en Phase 3 **que** si les huit conditions sont remplies :

```
rootless
filesystem en lecture seule
réseau désactivé par défaut
capabilities Linux supprimées
limite CPU / mémoire / PIDs
timeout obligatoire
workspace temporaire
aucun secret par défaut
```

Cohérent pour Semgrep, Trivy et Gitleaks sur un dépôt local : ce sont des outils **passifs**.

**Cette configuration ne doit pas être réutilisée pour des outils actifs.** Nuclei avec réseau,
un navigateur piloté, du fuzzing — c'est un autre régime d'isolement, à traiter en Phase 7.
Le classer `PASSIVE` dans le registre serait une erreur de sécurité, pas une simplification.

---

## 7. Orchestration — pas de LangGraph, pas de Temporal en Phase 3

```
Plan JSON déclaratif
    ↓
Python runner
    ↓
OPA
    ↓
adapters
    ↓
sandbox
```

LangGraph apporte un graphe d'agents persistants, Temporal une exécution durable avec reprise
et retries. **Ensemble, ce sont deux systèmes de coordination installés avant d'avoir un seul
workflow qui fonctionne.**

**Ce qui est fait quand même :** les interfaces du planner et de l'executor sont écrites pour
être remplaçables — le plan est un objet sérialisable, l'executor prend un plan et rend un
résultat. Ni LangGraph ni Temporal ne sont installés, mais aucun des deux ne demandera de
refondre le cœur le jour où on les ajoutera.

---

## 8. Stack

| Choix | Valeur | Justification |
|---|---|---|
| Langage | **Python** | FastAPI, MCP/FastMCP, écosystème des outils de sécurité, parsing SARIF, prototypage rapide |
| API | FastAPI | |
| Policy | OPA, sidecar HTTP | autorité de décision externe au moteur |
| Exécution | Python runner | déterministe, sans shell arbitraire |
| Sandbox | conteneur rootless | les 8 conditions ci-dessus |
| Stockage | **SQLite en local**, PostgreSQL visé pour la plateforme | SQLite suffit au premier test et retire une dépendance |

**Python n'est pas justifié par l'import de repositories.** Vérification faite : OPA est appelé
en HTTP, DefectDojo est un modèle à adapter et non une appli à importer, FastMCP ne sert à rien
tant qu'il n'y a pas de MCP, et agent-governance-toolkit n'a pas encore été lu. **Le minimal
core n'importe aucun code externe**, donc aucune licence ne le contraint.

---

## 9. Périmètre du minimal core (Phase 3)

```
1 scénario        analyse de sécurité d'un repository local
3 capabilities    CODE_STATIC_ANALYSIS · DEPENDENCY_ANALYSIS · SECRET_DETECTION
3 providers       Semgrep · Trivy · Gitleaks
1 plan JSON       déclaratif, sérialisable, rejouable
1 policy          OPA, appelé comme service ou moteur WASM
1 executor        Python, sans shell arbitraire
1 sandbox         conteneur rootless, réseau désactivé
1 normalisation   raw conservé + modèle interne + export SARIF
1 rapport         résumé des findings
```

**Exclus absolument de cette phase :**

```
MCP · agrégateurs · gateways · corrélation · remédiation
multi-user · Temporal · LangGraph · UI riche
```

---

## 10. Les cinq décisions, actées

| Décision | Verdict |
|---|---|
| Findings | **Modèle interne = source de vérité.** SARIF en import/export seulement |
| Policy engine | **OPA en sidecar HTTP ou WASM.** OPA décide, Python applique |
| Sandbox | **Conteneur restreint** pour les outils passifs, isolation renforcée en Phase 7 |
| Orchestration | **Ni LangGraph ni Temporal** dans le minimal core ; interfaces préparées |
| ContextForge | **Hors périmètre opérationnel**, référence uniquement |

---

## 11. Corrections apportées aux données de Phase 1

Trois fiches étaient techniquement fausses, elles sont corrigées dans `NOTES.csv` :

| Repo | Avant | Après | Pourquoi |
|---|---|---|---|
| `open-policy-agent/opa` | code réutilisable / **SDK** | composant d'infrastructure / **HTTP sidecar** | OPA est en Go, pas de SDK Python |
| `DefectDojo/django-DefectDojo` | code réutilisable / **import** | **référence architecturale** / lecture | on adapte un modèle, on n'importe pas une appli Django |
| `microsoft/agent-governance-toolkit` | SDK | **à confirmer** | code non lu, décision prématurée |

**Effet mesuré :** INTEGRATE passe de 13 à **12**, et les imports de code de 4 à **2** — dont
un « à confirmer » et FastMCP, inutile avant que MCP existe.

---

## 12. État de la vérification par lecture du code

Fait le 2026-08-27, détaillé dans `PHASE3/VERIF_OUTILS.md`.

### Vérifié

| Point | Résultat |
|---|---|
| Formats de sortie | **Trivy et Semgrep produisent du SARIF nativement** — l'export est gratuit |
| Rootless | Semgrep a un stage `nonroot` ; Trivy et Gitleaks tournent **en root** par défaut |
| Gitleaks | **le secret est renvoyé en clair**, `--redact` non actif par défaut |
| Trivy | **télémétrie vers Aqua activée par défaut**, `--disable-telemetry` requis |
| Trivy | `--offline-scan` **ne coupe pas** la mise à jour de base — piège |

### Ce que ça ajoute à l'architecture

1. **Un pré-chauffage hors sandbox** pour la base de vulnérabilités Trivy
   (`--download-db-only`, puis montage lecture seule + `--skip-db-update --skip-java-db-update`).
   C'est une étape d'orchestration, pas un détail d'adaptateur.
2. **`args_obligatoires` dans le schéma de provider** — voir §3.
3. **La sévérité est notre responsabilité**, pas celle des outils.
4. **Décision à trancher :** RAW chiffré ou RAW amputé — voir §4.1.

### Toujours non vérifié — Docker absent de cet environnement

| Point | Risque |
|---|---|
| **Semgrep sans réseau** (registre de règles, metrics) | **élevé** — seul point capable de changer le périmètre de Phase 3 |
| Les trois outils en `--read-only` + `--cap-drop=ALL` | moyen |
| OPA en sidecar sous charge — latence par décision | moyen |
| Droits du workspace pour l'uid 1000 de Semgrep | moyen, mais documenté par le Dockerfile lui-même |

**Rien n'a été exécuté.** Tout ce qui précède vient du code source et des Dockerfiles.

