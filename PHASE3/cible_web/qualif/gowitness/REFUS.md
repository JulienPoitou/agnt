# REFUS — gowitness (G1, vague-web/g1, 2026-09-05)

Statut : **REFUSÉ** (refus nommé, motif documenté — issue d'un arbitrage
attendu par la commande : « si la sortie n'est pas normalisable en findings
honnêtes, REFUSE-le nommément »).

Identification du binaire écarté : gowitness 3.1.1 (git df54b38),
sha256 `57b3188e24782c27fdf72493ce599537efd3187d03b80f8afe733c72d68c5517`
(staging `~/.cache/arena_secops/staging/gowitness/gowitness`).

## Motifs (dans l'ordre de poids)

1. **Aucun navigateur sur la machine (mesuré).** gowitness 3.1.1 est un
   preneur de captures d'écran : chaque mode de `gowitness scan` (cidr, file,
   nessus, nmap, single) exige un binaire Chrome/Chromium. Aucun `chrome`,
   `chromium`, `chromium-browser`, `google-chrome` sur le système, aucun cache
   playwright (`~/.cache/ms-playwright`) ni puppeteer — mesuré le 2026-09-05.
   Deux épreuves d'échec, toutes deux rc=1 :
   - run PAR DÉFAUT (`gowitness_run_defaut.txt`) : `failed to initialize
     chrome context: exec: "google-chrome": executable file not found in
     $PATH` — sans `--chrome-path`, le binaire ne télécharge RIEN, il échoue
     nommément ;
   - épreuve d'échec contrôlée (`gowitness_run_echec.txt`, `--chrome-path`
     pointant sur un chemin inexistant pour NE PAS déclencher de
     téléchargement) : `failed to initialize chrome context: fork/exec
     /nonexistent/chrome: no such file or directory` (code 1).

2. **Le canal d'acquisition du navigateur est hors règles.** L'aide de
   l'outil promet « downloads a platform-appropriate binary by default »
   (`gowitness_help_scan_single.txt`). Le canal réellement embarqué dans le
   binaire a été mesuré par `strings` (`gowitness_canal_chrome.txt`) :
   `https://storage.googleapis.com/chromium-browser-snapshots/…` et
   `https://registry.npmmirror.com/-/binary/chromium-browser-snapshots/…` —
   aucun des deux n'est une release GitHub officielle. La règle de
   provisionnement de la qualification est « téléchargements depuis les
   releases GitHub officielles uniquement » : il n'existe donc AUCUN canal
   conforme pour acquérir le navigateur requis (Chromium n'est pas publié en
   binaires par le projet chromium sur GitHub ; une construction depuis les
   sources est hors de proportion pour une épreuve).

3. **L'artefact primaire n'est pas normalisable en findings honnêtes.** La
   valeur propre de gowitness est le JPEG/PNG (rendu visuel). Une image n'est
   pas un finding projetable (pas de règle, pas de coordonnée lisible par
   l'oracle). Les métadonnées annexes (`--write-jsonl` : statut, titre,
   longueur) sont, elles, déjà couvertes honnêtement par la sonde httpx
   (WEB_HTTP_PROBE, qualifiée) — projeter uniquement ces métadonnées
   reviendrait à déclarer gowitness pour ce qu'il n'est pas.

## Conséquences (convention du registre)

- AUCUNE épingle dans `manifeste_dependances.yaml` (un binaire inutilisable
  n'est pas une dépendance traçable — l'épingle autorise, elle ne documente
  pas une impossibilité).
- AUCUN plugin `plugins/gowitness.yaml` (le registre refuserait de toute
  façon un plugin sans épingle).
- Le binaire reste dans le staging (~/.cache/arena_secops/staging/gowitness/)
  uniquement comme pièce à conviction ; il n'est pas référencé par le dépôt.

## Pièces

- `gowitness_run_defaut.txt` — run par défaut sans `--chrome-path` (rc=1 :
  « google-chrome » absent du PATH, aucun téléchargement tenté).
- `gowitness_run_echec.txt` — épreuve d'échec contrôlée (rc=1, chrome requis).
- `gowitness_help_scan_single.txt` — `--help` (chrome requis par défaut).
- `gowitness_canal_chrome.txt` — canaux de téléchargement embarqués (strings).
- `gowitness_version.txt` — identification de la version (3.1.1).
- `gowitness.meta.yaml` — métadonnées de la décision.
