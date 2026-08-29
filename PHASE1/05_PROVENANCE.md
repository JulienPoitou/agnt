# PHASE 1 — PROVENANCE DES DONNÉES

_Comment chaque chiffre de ce dossier a été obtenu. Objectif : que tu puisses tout rejouer,_
_et distinguer ce qui est mesuré de ce qui est jugé._

---

## 1. Ce qui est MESURÉ (régénérable)

| Donnée | Source exacte | Méthode |
|---|---|---|
| Étoiles | `github.com/{repo}` | champ `"stargazerCount"` du JSON embarqué — **valeur exacte**, pas l'arrondi « 31k » |
| Dernier commit | `github.com/{repo}/commits/HEAD.atom` | 2e balise `<updated>` du flux Atom — date ISO exacte |
| Licence | `github.com/{repo}` | `"spdxId"`, sinon `"license":{"name":...}`, sinon repli texte sur liste blanche |
| Archivage | `github.com/{repo}` | bandeau « Public archive » / « This repository has been archived » |
| Existence d'un repo | `github.com/{repo}` | code HTTP 200 / 404, redirects suivis |

**Aucune de ces valeurs n'est estimée.** Elles sont en cache dans `PHASE1/.cache_meta.json`,
horodatées par un numéro de version de parseur : modifier le parseur invalide le cache.

## 2. Ce qui est JUGÉ (saisi à la main)

| Donnée | Fichier | Base du jugement |
|---|---|---|
| C1 / C2 / C3 | `PHASE1/NOTES.csv` | lecture du README + arborescence de 1er niveau, profils dans `PHASE1/.profils/` |
| Motif | `PHASE1/NOTES.csv` | une phrase par repo |

Ces notes sont un **jugement d'architecture**, pas une mesure. Elles vivent dans un fichier
séparé de l'inventaire précisément pour qu'on puisse les contredire sans refaire la collecte.
Seuls **43 repos** sont notés — ceux de la shortlist. Les 281 autres ne sont pas notés, et le
moteur de score refuse d'inventer une note : ils sortent en `A_NOTER`.

## 3. Chaîne de traitement

```
uploads/liste complete.txt          444 fiches brutes
        │  PHASE1/parse_liste.py    → 333 uniques (111 doublons sur URL)
        ▼
PHASE1/00_INVENTAIRE.csv
        │  PHASE1/fix_urls.py       → 14 URL corrigées (vérifiées 200), 9 doublons de plus,
        │                             25 fiches classées hors périmètre
        ▼
PHASE1/00_INVENTAIRE.csv            324 uniques
        │  PHASE1/enrich.py         → 618 requêtes github.com, parallélisme 6
        ▼
PHASE1/00_INVENTAIRE_ENRICHI.csv    295 exploitables
        │  PHASE1/scoring.py  +  PHASE1/NOTES.csv
        ▼
PHASE1/01_GRILLE_TRI.csv            43 notés → 38 retenus
```

Tout est rejouable : `parse_liste.py && fix_urls.py && enrich.py && gen_notes.py && scoring.py`.

## 4. Pourquoi pas l'API GitHub

`api.github.com` renvoie `limit: 60/h` en non authentifié. 324 repos × 2 appels = 648 requêtes,
soit ~11 h de collecte. Les pages `github.com` et les flux Atom ne renvoient **aucun** header
`x-ratelimit` ni `Retry-After` (vérifié le 2026-08-27), et répondent en 0,13–0,64 s.
618 requêtes ont été passées en 45 s à parallélisme 6, sans un seul blocage.

Le quota API a été préservé et n'a servi qu'à deux recherches de repos par nom
(`abusech/URLhaus`, `abusech/ThreatFox`) — les seuls cas non devinables.

## 5. Erreurs corrigées en cours de route

Chacune a été trouvée par un test, pas par relecture. Elles sont listées parce qu'elles
indiquent où le pipeline était fragile.

| Erreur | Symptôme | Correction |
|---|---|---|
| Étoiles tronquées | `31k` → 31 | lecture du champ exact `stargazerCount` |
| Regex de licence trop large | `vault → "actual"`, `cai → "startup"` | liste blanche + mots vides + entités HTML dé-échappées |
| Cache sans version | le parseur corrigé ne changeait rien | `PARSER_VERSION` |
| Dédup avant correction d'URL | `wazuh/wazuh` et `GreyDGL/PentestGPT` en double | 2e passe de dédup dans `fix_urls.py` |
| `etat` écrasé | 15 fiches « pas d'URL » alors que 15 étaient classées | affectation dans chaque branche |
| Appariement sensible à la casse | `MCPJungle/MCPJungle` noté mais jamais lu | comparaison en minuscules |
| Notes orphelines ignorées | une note sans repo correspondant passait en exit 0 | échec bloquant |
| Archivage non branché sur une gate | `cai` archivé mais INTEGRATE possible | gate **G5** |

Tests en place : `PHASE1/test_parse_page.py` (15 cas, 15 conformes) et le contrôle
notes-orphelines de `scoring.py`.

## 6. Limites assumées

- **Les 59 « licence inconnue » ne sont pas 59 repos sans licence.** C'est « SPDX non lisible ».
  Chaque cas doit être revérifié avant de conclure. Le sens de l'erreur est conservateur.
- **Les étiquettes de section du fichier source sont parfois fausses** : `langchain`, `grafana`,
  `keycloak`, `vault`, `moby` sont classés « Vulnerability Management ». Non corrigé — le
  reclassement des 295 entrées est un chantier distinct.
- **C1/C2/C3 reposent sur README + arborescence**, pas sur une lecture du code. Suffisant pour
  un tri et une stratégie BUILD/INTEGRATE/ADAPT/IGNORE ; insuffisant pour décider d'un fork.
  Les repos qu'on voudrait réellement réutiliser en code méritent une lecture en Phase 2.
