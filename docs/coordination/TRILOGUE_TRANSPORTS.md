# TRILOGUE TRANSPORTS — re-mesuré (session coordinée)

> **Session :** `arena/01a0585a-agnt` (rattrapage coordonné, docs uniquement)
> **Base :** `main` `dfc412d` (PR #13 — contient la ligne CORE PR #6, le raccord
> MCP-004 et le registre canonical `transports`) — **le dossier MCP a bougé depuis
> le rapport d'origine ; rien n'a été forcé, chaque case est re-mesurée telle quelle.**
> **Date/heure des mesures :** 2026-08-31, 15:18–15:21 UTC, venv `/tmp/agnt-premier-run-venv`
> (PyYAML 6.0.3, mcp 2.1.1), `PYTHONPATH=PHASE3/slice`.
> **Méthode :** `Registry(chemin=<yaml temporaire>)`, un bloc par cas, chaque cas
> dans un **sous-processus Python frais** (état `transports._EXECUTEURS` vierge,
> sauf les cas qui déclarent `transports.enregistrer("http", …)`). Le registre
> temporaire porte une capacité unique dont le provider est le cas testé.

## FAITS mesurés (tableau cas → observation)

| Cas | Déclaration | Observation (exacte) |
|---|---|---|
| **C** | `transport: http` + contrat `mcp` **valide**, **sans manifest** | **REFUSÉ** mais à l'erreur `RegistryError: p_probe: le kind 'api' n'est pas implémenté pour un provider local (seul 'cli' l'est)` — la cause annoncée n'est **pas** le transport : le `http` déclaré a été abandonné, le provider est construit `sandbox_cli` et son post-init rejette le kind local. |
| **C2** | idem C, mais `kind: tool`, `commande: [bandit]` | **CHARGÉ** — `transport: sandbox_cli`, `manifest: false`, `fournit_http: false`, `connus: ["sandbox_cli"]`. Le repli silencieux est confirmé : le `transport: http` déclaré n'est **jamais** passé à `transports.fournit()`. |
| **C3** | idem C2 + `transports.enregistrer("http", …)` **posé** | **CHARGÉ** — toujours `transport: sandbox_cli`, malgré `fournit_http: true`. L'enregistrement de l'opérateur ne suffit pas : la construction ne lit jamais la clé provider `transport`. |
| **F** | `transport: carrier_pigeon` (non enregistré) + contrat `mcp` valide | **CHARGÉ** — `transport: sandbox_cli` ; un transport **inconnu** est lui aussi rabattu en silence. |
| **J** | `transport: http` + `mcp: {}` | **CHARGÉ** — `transport: sandbox_cli` : `mcp: {}` sert de **jeton de présence** (la clé existe → la garde ligne 274 passe) et n'est jamais validé en contenu. |
| **J2** | `mcp: {}` seul (transport par défaut `sandbox_cli`) | **CHARGÉ** — le bloc `mcp` vide est totalement ignoré, sans erreur. |
| **J3** | `transport: mcp` + `mcp: {}` | **REFUSÉ** — `RegistryError: MCP: server_id invalide — identifiant stable attendu (lettres, chiffres, . _ : -)`. **La validation de contenu n'existe que sur la branche `transport: "mcp"` exacte.** |
| **K** | `transport: http` + `mcp` avec clé inventée `machine_inventee` | **CHARGÉ** — `transport: sandbox_cli` : la clé inventée n'est pas vue (`MCP.valider` n'est pas appelée sur ce chemin). |
| **K2** | `transport: mcp` + `mcp` avec `machine_inventee` | **REFUSÉ** — `RegistryError: MCP: contrat contient des clés inconnues ['machine_inventee'] — contrat fermé, aucune garantie implicite`. |
| **H** | `transport: http` + **manifest valide** (sans `transport` dans le manifest), `transports.enregistrer("http")` posé, **pas de clé `mcp`** | **REFUSÉ** — `RegistryError: p_probe: provider externe sans contrat de transport` (règle **clé `mcp`**, `registre.py:274`) : même un transport enregistré est refusé si la clé `mcp` manque. |
| `Manifest_voie_ok` | idem H mais le manifest porte `transport: http` | **REFUSÉ** — même erreur (la règle clé `mcp` précède la lecture du manifest). |
| `Manifest_voie_complete` | `transport: http` + clé `mcp` **valide** + manifest portant `transport: http` + `http` enregistré | **CHARGÉ** — `transport: http`, `manifest: true`. **Seule voie qui fonctionne** pour un transport non-local : manifest porteur du transport + présence `mcp` + enregistrement. |
| **G** | manifest **sans `binaire`** | **REFUSÉ** — `ManifestError: manifest invalide : 'binaire' absent`. |
| **I** | manifest `binaire: evil` | **REFUSÉ** — `ManifestError: … binaire 'evil' ni dans la liste du cœur ni épinglé dans manifeste_dependances.yaml…` (liste de binaires : `BINAIRES_AUTORISES` + rôle `outil` du manifeste d'approvisionnement). |
| **I2** | manifest `argv` = chaîne shell | **REFUSÉ** — `ManifestError: … 'argv' est une chaîne. Le manifest doit être une LISTE…`. |
| **DISPATCH** (mesure complémentaire) | provider `id: trivy`, `transport: http`, contrat `mcp` valide, `commande: [trivy]`, sans manifest | **CHARGÉ** `transport: sandbox_cli` puis `adapters.executer()` **dispatche vers l'adaptateur LOCAL `trivy`** (échec mesuré : `FileNotFoundError: outil introuvable : trivy …` — il s'apprêtait à résoudre le binaire local ; avec trivy armé, le sous-processus sandboxé local aurait été lancé). |

## Structure du défaut (mesurée en lecture, pas en hypothèse)

Dans `registre.py` (HEAD `dfc412d`) :

1. **L. 270** : `transport = str(p.get("transport", sandbox_cli))` — la clé provider est lue, mais uniquement pour **brancher**.
2. **L. 274** : règle « provider externe **sans clé `mcp`** » → `RegistryError` (cas H — elle refuse aussi une voie manifest légitime sans `mcp`).
3. **L. 286** : la branche `if transport == "mcp"` — **seule** porte qui valide le contenu `mcp` (`mcp_provider.valider`, qui refuse clés inconnues et `server_id` vide : J3, K2).
4. **L. 325–341** : construction du `Provider` — `transport=(mani.transport if mani is not None else TRANSPORT_SANDBOX_CLI)`. **La clé provider `transport` n'est jamais réutilisée** : sans manifest (ou manifest sans champ transport), le provider atterrit en `sandbox_cli` **silencieusement** (C2, C3, F, J, K).
5. **`Provider.__post_init__` (l. 117–121)** : la garde `transports.fournit(self.transport)` voit le **résultat** du repli (`sandbox_cli` → toujours `True`), jamais le transport déclaré (`http`, `carrier_pigeon`). Le contrat de `transports.py` (« jamais rabattu en silence », « validé au chargement ») est **contredit par la construction du registre** : le garde-fou existe mais est placé après la perte d'information.

Conséquence en chaîne : la disponibilité (`pipeline._disponibilite`), l'entrée OPA (`policy.entree` → `providers_detail[].transport`) et le dispatch (`adapters.executer` → `transport = getattr(prov,"transport")`) lisent tous `sandbox_cli` — donc la **policy autorise un plan décrit comme local** et l'adaptateur **exécute localement** un provider que l'opérateur a déclaré HTTP. Le cas DISPATCH le prouve avec l'id `trivy` (adaptateur historique) ; avec un id sans adaptateur, l'exécution échoue en `KeyError: aucun adaptateur pour …` — un échec *accidentel*, pas un refus de transport nommé.

## OPTIONS

1. **Validation par `transports.fournit()` au chargement** — appliquer la garde sur la clé provider `transport` telle qu'elle a été **déclarée**, avant toute construction : un `http` non enregistré → `RegistryError` explicite.
   - Force : colmate C/F/K (clé jamais validée) et rend C3 inutile.
   - Limite : ne corrige pas la règle clé `mcp` (H) — la voie manifest légitime reste fausses-refusée ; ne garanti pas que les *conditions réseau* soient portées par le transport.
2. **Transport opérateur enregistré** — rendre la déclaration d'un transport non-local DÉPENDANTE d'un `transports.enregistrer(…)` préalable (déjà le contrat de `transports.py`), et refuser au chargement tout provider dont le transport déclaré n'est pas dans `connus()` **y compris** quand aucun manifest n'existe.
   - Force : aligne `transports.py` et `registre.py` (une seule autorité : `fournit()`).
   - Limite : dépend de l'ordre d'enregistrement au démarrage (un registre chargé avant l'enregistrement échouerait) — acceptable pour un démarrage applicatif unique (`api.py` fait déjà `initialiser_mcp` avant toute lecture).
3. **Suppression du repli silencieux → refus fail-closed nommé — RECOMMANDÉE** — la construction du `Provider` refuse **(a)** `transport` déclaré non-local sans manifest porteur du même transport, et **(b)** manifest porteur d'un transport que `fournit()` ne connaît pas (déjà le cas dans `provider_manifest._transport_valide`). Le message nomme le transport attendu et les `connus()`, comme le fait déjà `transports.deleguer`.
   - Force : un seul point de décision (construction du Provider), aucune information perdue, l'erreur est un **refus** (type `RegistryError`/`ManifestError`), pas un repli.
   - Raison décisive : le comportement actuel est un **défaut** (perte d'information), pas un **choix** — rien dans la doc du registre ni du contrat transports n'assume « rabattre http sur sandbox_cli ».

## Impact sécurité

- **Fail-closed :** violation démontrée — une déclaration `transport: http` + contrat `mcp` + `commande` + id d'adaptateur local ⇒ **exécution locale sandboxée** (DISPATCH). Avec un id sans adaptateur : échec `KeyError` non nommé (lisible, mais pas un refus de transport).
- **Egress / policy avant invocation :** OPA voit `transport: sandbox_cli` (faux) et décide sur ce fait ; la politique `policy.rego` ne connaît jamais `http`. Les **conditions réseau** du contrat MCP (`conditions.reseau = server_transport != "stdio"`) sont dans `MCPManifest` — **perdues** quand le manifest est absent (le repli ne garde ni le transport ni ses conditions : un outil externe peut être jugé « sans réseau » et lancé dans une cage `--unshare-net` → résultat vide en code 0, le pire mode d'échec du projet).
- **YAML / migration :** le registre de production (`PHASE3/slice/capabilities.yaml`) ne contient **aucune clé `transport`** (mesuré : tous les providers sont `sandbox_cli` implicites, manifestes sans champ transport) → **migration nulle** pour la plateforme ; seuls les manifests/registres d'agents qui déclarent un transport non-local sont concernés, et ils sont aujourd'hui refusés ou rabattus — le correctif les rendra refusés **proprement**, ce qui est le contrat attendu par `transports.py`.
- **Condition non négociable** (rappel à toute implémentation) : **tout transport non local porte ses conditions réseau** — `reseau`/`requires_network` déclarés dans le contrat, jamais déduits, jamais perdus par un repli. C'est ce que la recommandation 3 préserve (le manifest MCP les porte déjà ; la construction n'a plus le droit de les abandonner).

## RECOMMANDATION (argumentée)

Adopter l'**option 3** : dans `registre.py`, la construction du `Provider` doit échouer si le transport déclaré au niveau provider (`p["transport"]`) diffère de celui résolu (`mani.transport` ou `sandbox_cli`) **sans** un manifest porteur du même transport — et tout transport non fourni doit lever avant la construction (au même endroit où `provider_manifest._transport_valide` le fait déjà sur la voie manifest). En complément (option 1, non exclusive) : valider la clé provider `transport` contre `transports.connus()` **avant** la règle clé `mcp`, pour que l'erreur nomme le transport et non « sans contrat de transport ».

Les options 1 et 2 seules laissent soit la voie manifest fausse-refusée (H), soit la perte des conditions réseau ; elles sont compatibles mais insuffisantes. Ce document **ne corrige pas le défaut** : la décision d'implémentation est propriétaire et reste en attente (périmètre de cette session : docs uniquement, défaut documenté, non réparé).

## Fermeture

- Cas **J/K « acceptés »** du dossier d'origine : reproduits sur **ce** chemin (`transport != "mcp"` + clé `mcp` → contenu jamais validé) ; sur la branche `transport: "mcp"`, main a bougé (J3/K2 refusent désormais, `mcp_provider._refuser_clefs`). Aucune carte d'origine recopiée.
- La seule voie non-locale qui charge correctement (mesurée) : `transport: http` + `mcp` valide + manifest `transport: http` + `enregistrer("http")` — `Manifest_voie_complete`.
