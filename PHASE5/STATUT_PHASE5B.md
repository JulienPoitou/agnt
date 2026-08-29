# PHASE 5B — POLITIQUE DE CONSERVATION + NIVEAU 2

_Deux chantiers, dans l'ordre demandé : la sécurité des sorties d'abord, le niveau 2 ensuite._

---

## 1. La politique de conservation des sorties

### Le problème, constaté

Les findings étaient masqués, mais **`raw_bandit.json` partait dans le bundle avec le
credential en clair** — 4 occurrences. Tester uniquement les findings laissait passer la fuite.

### La règle

```
conserver la donnée brute si elle est sûre ;
sinon conserver son empreinte, ses métadonnées et une version masquée.
```

Ce n'est pas une exception au principe « ne jamais détruire la donnée originale » : c'est sa
limite. Un secret en clair dans nos artefacts est une fuite **que nous créons**.

### Le modèle, dans `manifeste.json`

```json
"conservation_des_sorties": {
  "raw_bandit.json": {
    "raw_output": {
      "digest": "d11c0e9e8292d3ed",
      "size": 4329,
      "stored": false,
      "reason": "secret_detected",
      "redactions": 1
    },
    "sanitized_output": {
      "path": "raw_bandit.redacted.json",
      "redactions": 1
    }
  },
  "raw_trivy.json": {
    "raw_output": { "digest": "e56ca11375cc7598", "size": 276530, "stored": true }
  }
}
```

Une sortie sûre est conservée **telle quelle** : masquer sans raison détruirait des données
utiles.

### Deux niveaux de motifs — et pourquoi

Le dilemme est réel : un motif large attrape les chemins de fichiers, un motif précis rate les
clés sans étiquette. La solution n'est pas de choisir, c'est de **séparer les usages**.

| Niveau | Sert à | Coût d'un faux positif |
|---|---|---|
| **PRÉCIS** | masquage des findings, champ par champ | détruit une donnée utile, systématiquement |
| **LARGE** | détection de sûreté + garde-fou | un arrêt bruyant, aucune donnée perdue |

Pour une **sortie brute**, la détection ET le masquage utilisent le jeu large : mieux vaut
masquer un chemin de 40 caractères que laisser passer une clé.

Pour les **findings**, le masquage large ne s'applique qu'aux champs de **texte libre déclarés
par le manifest** :

```yaml
extraction:
  masquer_large: [message]     # Bandit met la valeur réelle du credential dans issue_text
```

Le cœur ne devine rien : il applique ce que le manifest déclare.

### Les faux positifs qui ont forcé cette conception

Un motif générique `[A-Za-z0-9/+=]{40}` a été essayé, puis **supprimé**. Constaté sur données
réelles :

```
/user/PHASE3/artifacts/b01ecd1ecf3f6f45/     ← chemin absolu, 40 caractères
message/STVX7X7IDWAH5SKE6MBMY3TEI6ZODBTK     ← PURL de paquet
```

**112 faux positifs sur un seul scan Trivy**, qui détruisaient des références utiles. La leçon :
un jeu de caractères qui inclut `/` ne peut pas distinguer une clé base64 d'un chemin.

### Le test

`test_bundle.py` — **25/25**. Il cherche le secret dans **chaque fichier** du bundle :

```
manifeste.json · run.json · findings.json · clusters.json
rapport.md · rapport.sarif · raw_*.json · plan.json
```

Et il vérifie que la cible contient **réellement** des secrets — sinon le test ne prouve rien.

---

## 2. Niveau 2 de la promesse

```
outil CLI → format non standard → parser spécifique isolé → même cœur inchangé
```

**Démontré : 21/21.**

### L'architecture

```
slice/
  pipeline.py · policy.py · plan.py · findings.py · clusterer.py · rapport.py · extraction.py
      ↑ aucun ne connaît bandit (vérifié sur le CODE, commentaires exclus)
  adapters.py
      ↑ connaît le format générique « custom », pas l'outil
  parsers.py            ← registre de parsers, par NOM
  parsers_bandit.py     ← parser spécifique, hors du cœur
```

Le manifest référence le parser **par son nom** :

```yaml
extraction:
  parser: bandit_custom
  items_from: items
  jetons_outil: ["{relpath}", "{line}", "{test_id}", "{msg}"]
```

Le pipeline ne connaît que `parsers.obtenir(nom)`. Il ne sait pas que Bandit existe, ni ce
qu'est un CSV.

### Contrat d'un parser

```
parse(texte) -> list[dict]
  · chaque dict porte au minimum `regle` et `fichier`
  · les valeurs sont déjà assainies
  · aucune exception sur entrée inattendue : retourner []
```

Si un parser ne respecte pas ce contrat, c'est le parser qui est faux, pas le cœur.

### Une faille réelle trouvée en route

Ma validation de placeholders n'attrapait que les **majuscules** (`[A-Z_]+`). Donc :

```
--msg-template "{relpath},{line},{test_id},{msg}"
```

passait la validation **sans être vu**. Corrigé : la casse est ignorée, et les jetons propres à
l'outil doivent être **déclarés explicitement** dans le manifest.

```
jeton non déclaré  → refusé : « placeholder '{relpath}' inconnu »
jeton déclaré      → accepté, et passé tel quel à l'outil
```

### Le manifest exige un parser

```
format custom sans parser   → refusé
parser inexistant           → refusé : « Disponibles : ['bandit_custom'] »
```

### Résultat

```
findings par outil : semgrep 2 · bandit 5 · bandit_custom 5 · trivy 62 · gitleaks 1
```

Les deux formats de Bandit **convergent sur le même jeu de règles** — vérifié. Et le parser
masque les secrets du texte libre.

---

## 3. Invariants métier, pas des quantités

Le niveau 2 a aussi corrigé une fragilité : `assert len(steps) >= 3` devient faux dès qu'on
ajoute un provider. Remplacé par des invariants :

```
7a. les capacités obligatoires sont présentes
7b. aucune capacité inconnue n'est sélectionnée
7c. chaque provider sélectionné existe dans le registre
7d. chaque provider déclaratif a un manifest valide
7e. chaque étape porte un risque déclaré
7f. aucun outil interdit n'est introduit
7g. des providers supplémentaires restent autorisés   (5 providers, 3 capacités obligatoires)
```

La logique est bien : **providers supplémentaires autorisés, capacités obligatoires toujours
exigées** — et non « n'importe quel plan de taille supérieure à 3 est valide ».

---

## 4. Traçabilité du paquet Bandit

```yaml
bandit:
  package: bandit
  version: "1.9.4"
  distribution: pip
  distribution_hash: "9e7243122bf141ee55c31127efb175e0"
  verification: empreinte SHA-256 du fichier RECORD de la distribution installée
```

Le SHA d'un binaire autonome n'a pas de sens ici — Bandit est installé par pip. C'est
l'empreinte du **paquet Python réellement utilisé** qui est tracée.

---

## 5. Suite de tests

```
test_securite       16/16   porte bloquante
test_slice          10/10
test_tracabilite    12/12
test_intentions     22/22
test_correlation     7/7
test_independant    10/10
test_manifest       27/27   niveau 1
test_niveau2        21/21   niveau 2
test_bundle         25/25   aucun secret dans tout le bundle
test_rapport        21/21
somme des codes : 0
```

## 6. Ce que ça ne prouve toujours pas

- **Un seul parser spécifique.** Le contrat est posé, mais un seul format non standard est
  exercé. Un second parser sur un format réellement différent renforcerait la preuve.
- **La détection de secrets reste heuristique.** Une clé exotique sans préfixe connu et sans
  étiquette peut passer. Le garde-fou large réduit le risque, il ne l'élimine pas.
- **Le LLM n'est toujours pas branché.** Le contrat d'intention est prêt et testé.
