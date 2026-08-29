# PHASE 3 — VÉRIFICATION DES TROIS OUTILS PAR LECTURE DU CODE

_Sources : Dockerfiles officiels, `pkg/flag/*.go` (Trivy), `report/finding.go` (Gitleaks),_
`cli/src/semgrep/constants.py` et `commands/scan.py` (Semgrep), branches `main` / `master` / `develop`.

⚠️ **Limite de cette vérification : Docker n'est pas disponible dans cet environnement.**
Rien n'a été **exécuté**. Tout ce qui suit vient de la lecture du code source et des Dockerfiles.
Les conclusions marquées « à tester » ne sont pas des faits établis.

---

## 1. Trivy

### Formats de sortie — vérifié dans `pkg/types/report.go`

```go
FormatTable      = "table"      FormatJSON      = "json"
FormatTemplate   = "template"   FormatSarif     = "sarif"
FormatCycloneDX  = "cyclonedx"  FormatSPDX      = "spdx"
FormatSPDXJSON   = "spdx-json"  FormatGitHub    = "github"
FormatCosignVuln = "cosign-vuln"
```

**Trivy produit du SARIF nativement.** Notre décision « modèle interne + SARIF en export » est
donc directement applicable, sans convertisseur à écrire.

### Le problème : il a besoin d'une base de vulnérabilités

Vérifié dans `pkg/flag/db_flags.go` :

| Flag | Rôle |
|---|---|
| `--download-db-only` | télécharge la base sans scanner |
| `--skip-db-update` | ne met pas à jour la base |
| `--skip-java-db-update` | idem pour la base Java |
| `--db-repository` | source OCI alternative pour trivy-db |

**Conclusion : un mode hors ligne existe, mais il exige une étape hors sandbox** — pré-télécharger
la base, puis la monter en lecture seule avec `--skip-db-update --skip-java-db-update`.

⚠️ **Piège à ne pas tomber dedans :** `--offline-scan` **ne fait pas** ce que son nom suggère.
Son usage réel, dans `pkg/flag/scan_flags.go` :

```go
OfflineScanFlag = Flag[bool]{
    Name:  "offline-scan",
    Usage: "do not issue API requests to identify dependencies",
}
```

Il coupe les requêtes API d'identification de dépendances, **pas** la mise à jour de la base.
Se fier à ce flag seul laisserait Trivy tenter un accès réseau au démarrage.

### 🔴 Télémétrie activée par défaut

```go
DisableTelemetryFlag = Flag[bool]{
    Name:  "disable-telemetry",
    Usage: "disable sending anonymous usage data to Aqua",
}
```

C'est un flag de **désactivation** : par défaut, Trivy envoie des données d'usage à Aqua.
Dans un outil de sécurité, sur le dépôt d'un client, c'est inacceptable. **`--disable-telemetry`
doit être passé systématiquement**, et pas seulement pour respecter le « réseau désactivé ».

### Dockerfile

`FROM alpine:3.24.1`, aucune directive `USER` → **root par défaut**. Il installe `git`.
Pour notre usage il faut forcer un utilisateur non root au runtime.

---

## 2. Semgrep

### Formats de sortie — vérifié dans `cli/src/semgrep/constants.py`

```python
class OutputFormat(Enum):
    TEXT · JSON · GITLAB_SAST · GITLAB_SECRETS · JUNIT_XML · SARIF · EMACS · VIM

    def is_json(self):
        return self in [OutputFormat.JSON, OutputFormat.SARIF]
```

**Semgrep produit aussi du SARIF nativement.**

### Dockerfile — le meilleur des trois

Il existe un stage dédié `nonroot` :

```dockerfile
FROM semgrep-cli AS nonroot
RUN ... mv /usr/local/bin/semgrep-core /home/semgrep/bin ...
USER semgrep          # adduser -D -u 1000
```

Donc **rootless : oui**, via `semgrep/semgrep:nonroot`.

**Mais le commentaire du Dockerfile est un avertissement direct pour nous :**

> « We can't make this the default in the semgrep-cli stage above because of permissions errors
> on the mounted volume when using instructions for running semgrep with docker »

Autrement dit : en non-root, **le volume monté doit être lisible par l'uid 1000**. Notre
« workspace temporaire » doit donc être créé avec les bons droits, sinon le scan échoue.
C'est exactement le genre de détail qui fait perdre une journée en Phase 3.

### ❓ Non vérifié

Le comportement de Semgrep **sans réseau** : accès au registre de règles, `--metrics`,
téléchargements. Ce point reste ouvert et doit être testé.

---

## 3. Gitleaks

### Structure du finding — vérifié dans `report/finding.go`

```go
type Finding struct {
    RuleID, Description string
    StartLine, EndLine, StartColumn, EndColumn int
    Line   string `json:"-"`        // exclu du JSON
    Match  string
    Secret string                   // ← LE SECRET EN CLAIR
    File, SymlinkFile, Commit, Link string
    Entropy float32
    Author, Email, Date, Message string
    Tags []string
    Fingerprint string              // ← identifiant unique
}
```

Le paquet déclare aussi `CWE = "CWE-798"` (*Use of Hard-coded Credentials*), donc le CWE est
fourni.

**Deux conséquences directes pour notre modèle de findings :**

1. **Il n'y a aucun champ de sévérité.** Notre modèle interne devra la porter lui-même et la
   dériver de `RuleID` / `Tags`. Un outil ne peut pas nous donner ce qu'il ne calcule pas.
2. **`Fingerprint` existe déjà** : c'est notre identifiant de déduplication, gratuit.

### 🔴 Le secret est stocké en clair par défaut

`Secret string` contient la valeur réelle du credential, et `--redact` existe mais **n'est pas
activé par défaut** — vérifié dans `cmd/root.go` :

```go
rootCmd.PersistentFlags().Uint("redact", 0,
    "redact secrets from logs and stdout. To redact only parts of the secret just apply a
     percent value from 0..100. For example --redact=20 (default 100%)")
rootCmd.Flag("redact").NoOptDefVal = "100"
```

**Si nous conservons le RAW RESULT tel quel, notre base contiendra des secrets en clair.**
C'est une violation directe de notre propre principe « aucun secret par défaut ».
Décision obligatoire : passer `--redact` systématiquement, ou chiffrer le champ au stockage.

### Dockerfile — deux problèmes

```dockerfile
FROM alpine:3.22
RUN apk add --no-cache bash git openssh-client
RUN git config --global --add safe.directory '*'
ENTRYPOINT ["gitleaks"]
```

- **Aucun `USER`** → root par défaut.
- **`git config --global --add safe.directory '*'`** désactive globalement la protection
  `safe.directory` de git. C'est un garde-fou de supply chain supprimé pour tous les dépôts.
- `openssh-client` est installé alors qu'un scan local n'en a pas besoin : surface inutile.

---

## 4. Bilan contre les huit conditions de sandbox

| Condition | Semgrep | Trivy | Gitleaks |
|---|---|---|---|
| rootless | ✅ stage `nonroot` | ⚠️ à forcer au runtime | ⚠️ à forcer au runtime |
| filesystem lecture seule | ✅ à tester | ✅ à tester | ✅ à tester |
| réseau désactivé | ❓ **non vérifié** | ❌ **base à pré-peupler** | ✅ à tester |
| capabilities supprimées | ✅ à tester | ✅ à tester | ✅ à tester |
| limites CPU/mémoire/PIDs | ✅ runtime | ✅ runtime | ✅ runtime |
| timeout obligatoire | ✅ runtime | ✅ runtime | ✅ runtime |
| workspace temporaire | ⚠️ **droits uid 1000** | ✅ | ✅ |
| aucun secret par défaut | ✅ | ✅ | 🔴 **`--redact` requis** |

**Aucune des trois images officielles n'est utilisable telle quelle.**

---

## 5. Ce que ça change dans l'architecture

1. **Chaque adaptateur doit porter sa propre configuration durcie**, pas une configuration
   générique : flags réseau, télémétrie, redaction, utilisateur. Le schéma de provider doit
   donc inclure un champ `args_obligatoires`.
2. **Un pré-chauffage hors sandbox est nécessaire** pour Trivy (base de vulnérabilités).
   C'est une étape d'orchestration à part entière, pas un détail d'adaptateur.
3. **La conservation du RAW entre en conflit avec la sécurité** pour Gitleaks. Il faut trancher :
   RAW chiffré, ou RAW amputé des champs sensibles. Le principe « ne jamais détruire la donnée
   originale » a une limite, et c'est celle-là.
4. **Notre modèle de findings ne peut pas déléguer la sévérité aux outils.** Gitleaks n'en
   fournit aucune. La sévérité est notre responsabilité.

---

## 6. Ce qui reste à tester — non vérifié faute de Docker

| Point | Risque |
|---|---|
| Semgrep sans réseau (registre de règles, metrics) | **élevé** : pourrait invalider le scénario |
| Les trois outils en `--read-only` + `--cap-drop=ALL` | moyen |
| Scan Trivy avec base montée en lecture seule | moyen |
| Permissions du workspace pour l'uid 1000 de Semgrep | moyen, mais connu et documenté |

Le premier est le seul capable de faire changer le périmètre de la Phase 3. À tester avant
d'écrire le runner.
