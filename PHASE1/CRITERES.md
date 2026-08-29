# PHASE 1 — BARÈME DE NOTATION ET RÈGLES DE DÉCISION

_Décision utilisateur du 2026-08-27. Ordre de priorité imposé :_
**1. Qualité de l'architecture → 2. Réutilisabilité du code → 3. Couverture fonctionnelle.**

Raison assumée : l'objectif de la Phase 1 est de comprendre **comment construire correctement la
plateforme**, pas d'empiler des fonctionnalités. Un repo dont le code est inutilisable mais dont
l'architecture est exemplaire **reste pertinent** — il alimente l'architecture de référence.

---

## 1. Critères pondérés

| # | Critère | Poids | Ce qu'on mesure |
|---|---|---|---|
| C1 | **Qualité de l'architecture** | **50 %** | Séparation des couches (intent / capabilities / policy / execution / normalization), présence d'un **policy engine déterministe distinct de l'IA**, abstraction outils ↔ capabilities, extensibilité (plugin / provider / registry), modèle de données des findings, gestion des erreurs et idempotence, traçabilité / audit |
| C2 | **Réutilisabilité du code** | **30 %** | Licence, langage et stack, modularité (bibliothèque vs binaire monolithique), qualité des tests, documentation, couplage, présence d'API stables |
| C3 | **Couverture fonctionnelle** | **20 %** | Recouvrement du fil conducteur, capacités réellement apportées, outils pilotés, domaines couverts |

Note de **0 à 5** par critère. Score total = `0,5·C1 + 0,3·C2 + 0,2·C3` (sur 5).

### Ancrage des notes (pour éviter la notation au feeling)

| Note | C1 — Architecture | C2 — Réutilisabilité | C3 — Couverture |
|---|---|---|---|
| 5 | Architecture de référence : couches nettes, policy séparée de l'IA, abstractions stables | Bibliothèque modulaire, licence permissive, tests solides, API documentée | Couvre plusieurs capacités du fil conducteur |
| 3 | Couches présentes mais couplées ; politique mêlée à la logique métier | Code correct mais monolithique ou faiblement testé | Couvre une capacité précise |
| 1 | Script / pipeline linéaire, aucune abstraction | Code jetable, fork inévitable | Périphérique au fil conducteur |

---

## 2. Portes bloquantes (gates)

Appliquées **avant** la pondération. Une gate peut déclasser un repo quel que soit son score.

| Gate | Condition | Effet | Calculée par |
|---|---|---|---|
| **G1 — Inactif** | aucun commit depuis > 18 mois | `reference-only` : étudié pour l'architecture (C1), **jamais** INTEGRATE | `gate_g1()` ✅ |
| **G2 — Licence** | licence inconnue, commerciale, ou copyleft | bloque la **réutilisation de code** — voir §2.1 | `gate_g2()` ✅ |
| **G5 — Archivé** | bandeau « Public archive » sur le repo | lecture seule : ni INTEGRATE, ni réutilisation de code | `gate_g5()` ✅ |

**Pourquoi G5 est distincte de G1.** Un repo peut être archivé le jour même de son dernier
commit : `aliasrobotics/cai` a été archivé le 2026-08-22 avec un commit du 2026-08-22. La date
seule ne le disqualifiait pas. Inversement `smicallef/spiderfoot` n'est pas archivé mais n'a plus
bougé depuis 2023-11. Il faut les deux gates. 14 repos de l'inventaire sont archivés.

### 2.1 Une gate de licence bloque le code, pas l'exécution

C'est la règle la plus souvent mal appliquée du barème, donc elle est écrite explicitement :

| Usage prévu | La gate G2 s'applique ? | Pourquoi |
|---|---|---|
| **outil externe** (lancé en CLI / appelé en API / conteneur) | **NON** | on n'importe rien, on consomme un programme. Sa licence ne nous contamine pas |
| **code réutilisable** (import, fork, extraction de module) | **OUI** | là, la licence s'applique pleinement |
| **composant d'infrastructure** (déployé à côté) | **NON** pour le déploiement, **OUI** si on le modifie | |
| **référence architecturale** (on lit, on s'inspire) | **NON** | les idées ne sont pas sous licence |

Conséquence directe : **Semgrep (LGPL-2.1) et Nuclei sont INTEGRATE en tant qu'outils**, alors
qu'un fork de leur code serait bloqué. Sans cette distinction, la Phase 3 partirait sur
l'hypothèse fausse qu'il faut réécrire la moitié des outils qu'on veut simplement exécuter.

### 2.3 Licence de la plateforme : Apache-2.0 (décision provisoire du 2026-08-27)

**Retenue : Apache-2.0.** Cohérente avec le positionnement open source, auto-hébergeable,
extensible et intégrable. Elle apporte la rétrocession de brevet, ce qui compte en cybersécurité,
et c'est la licence de la majorité de nos INTEGRATE (OPA, Trivy, Prowler, ToolHive, FastMCP).

**Portée exacte de cette décision :**
- Phase 1 et Phase 2 : notation sous cette hypothèse.
- Avant distribution publique : validation juridique + inventaire des dépendances.
- Elle ne rend **pas** réutilisable un composant GPL, LGPL, MPL ou AGPL. Chaque dépendance
  conserve sa propre licence et s'analyse séparément.

**Ce qui changerait si on passait en AGPL-3.0** : seuls **16 repos** de l'inventaire sont sous
copyleft fort, et **aucun des 4 repos dont on prévoit d'importer le code** n'en fait partie
(OPA, DefectDojo, agent-governance-toolkit et FastMCP sont Apache-2.0, BSD-3, MIT, Apache-2.0).
La décision est donc réversible à ce stade — mais **pas après le premier commit public**.

### 2.2 Les deux gates NON automatisées — à ne pas croire calculées

`G3` et `G4` étaient décrites dans une version précédente de ce document sans aucune
implémentation dans `scoring.py`. Elles sont **retirées des gates** et deviennent des points de
contrôle manuels, parce qu'elles ne sont pas décidables depuis les métadonnées GitHub :

| Point de contrôle | Pourquoi ce n'est pas automatisable | Où il sera traité |
|---|---|---|
| **Supply chain (G3)** — dépendances mortes, binaire fermé, build non reproductible | demande de lire les manifests et la chaîne de build | Phase 2, par repo candidat à INTEGRATE. **Pénalité de −1 au score uniquement lorsqu'un problème est confirmé**, jamais par défaut |
| **Trust** — le projet exécute du contenu tiers (serveur MCP, plugin) sans isolation | demande de lire le code d'exécution | Phase 7, sur la couche d'exécution |

**Règle absolue : ne jamais inventer de valeur pour G3 ou G4 quand la donnée manque.**
Un verdict ne peut pas se réclamer d'elles tant qu'aucun problème n'est confirmé par une lecture.
Le champ `penalite` de `NOTES.csv` reste vide par défaut.

---

## 3. Vocabulaire des verdicts — définitions strictes

Ces cinq mots sont employés partout dans le projet. Voici ce qu'ils veulent dire, et seulement ça.

| Verdict | Définition | Test qui décide |
|---|---|---|
| **INTEGRATE** | on l'utilise **tel quel**, sans le modifier | « est-ce qu'on peut s'en servir sans toucher à son code ? » |
| **ADAPT** | on reprend **son code**, en le wrappant, forkant ou en extrayant un module | « est-ce qu'on importe quelque chose ? » + licence compatible |
| **ADAPT (archi)** | on ne reprend **ni l'outil ni le code** : on reproduit son architecture | « est-ce que le pattern vaut plus que l'implémentation ? » |
| **IGNORE** | écarté du produit, motif tracé en une phrase | « est-ce qu'il apporte quelque chose au fil conducteur ? » |
| **BUILD** | **aucun repo** ne couvre ce besoin | verdict porté sur une **lacune**, jamais sur un repo |

**Règles de priorité, dans l'ordre :**

1. **L'usage prévu prime sur le score.** Un repo dont l'usage est `référence architecturale`
   est **toujours** `ADAPT (archi)`, quel que soit son score : on ne l'exécute pas et on ne
   l'importe pas, donc on ne l'intègre pas. C'est cette règle qui sépare réellement ce qu'on
   déploie de ce qu'on imite.
2. Une gate **G1** ou **G5** (inactif / archivé) interdit INTEGRATE et ADAPT-code, quel que soit
   le score. Le repo retombe en `ADAPT (archi)` si C1 ≥ 4, sinon selon son score.
3. Une gate **G2** (licence) n'interdit **que** les usages `code réutilisable` et
   `composant d'infrastructure` — voir §2.1. Un usage `outil externe` passe malgré la gate.
4. À usage et gates égaux, le score décide : `≥ 4,0 et C1 ≥ 4` → INTEGRATE ; `> 3,0` → ADAPT ;
   `≤ 3,0 et C1 ≥ 4` → ADAPT (archi) ; `≤ 3,0 et C1 < 4` → IGNORE.
5. **Frontières exactes** : `3,0` strict n'est pas ADAPT. `4,0` est INTEGRATE.

**BUILD ne se déduit pas d'un score.** Il apparaît quand une brique de notre architecture ne
trouve aucun candidat dans tout l'inventaire. En Phase 1, deux briques seulement : l'**intent
engine** et la **corrélation multi-outils**.

## 4. Champ « usage prévu » — obligatoire pour tout repo noté

Depuis la révision du 2026-08-27, `NOTES.csv` porte deux champs supplémentaires. Sans eux, un
verdict INTEGRATE est ambigu : on ne sait pas si on parle d'exécuter l'outil ou d'importer son
code, et la gate G2 ne peut pas être appliquée correctement.

| `usage` | Sens | Gate G2 |
|---|---|---|
| `outil externe` | piloté en CLI / API / conteneur, non modifié | ne s'applique pas |
| `code réutilisable` | importé, forké, ou module extrait | s'applique |
| `composant d'infrastructure` | déployé à côté de nous (moteur, base, runtime) | s'applique si modifié |
| `référence architecturale` | lu et imité, jamais exécuté ni importé | ne s'applique pas |

`mode_integration` précise le comment : `CLI`, `API`, `SDK`, `conteneur`, `import`, `lecture`.

Deux champs complètent la fiche depuis le 2026-08-27 :

| Champ | Valeurs | Rôle |
|---|---|---|
| `confiance` | `haute` / `moyenne` / `faible` | `haute` = vérifié dans le code ou l'inventaire ; `moyenne` = README et arborescence seulement ; `faible` = inférence à confirmer |
| `preuve` | texte libre | ce qui a été réellement observé |
| `penalite` | vide ou `1` | G3, uniquement si un problème de supply chain est **confirmé** |

**État honnête : toutes les notes actuelles sont en `confiance = moyenne`.** Aucun code n'a été
lu, aucun test compté. Passer en `haute` est l'objet du P1.

## 5. Passage score → verdict

Application mécanique des règles du §3. Implémentée dans `scoring.py::verdict()` :
les gates d'abord (G1/G5 bloquent tout, G2 ne bloque que `code réutilisable` et
`composant d'infrastructure`), puis le score pondéré, puis C1 pour départager.

## 6. Sorties attendues de la Phase 1

| Fichier | Contenu |
|---|---|
| `PHASE1/00_INVENTAIRE.csv` | ta liste, structurée : `owner/name, catégorie, note, lien` |
| `PHASE1/01_GRILLE_TRI.csv` | grille complète, une ligne par repo, avec C1/C2/C3, score, gates, verdict, motif |
| `PHASE1/02_SHORTLIST.md` | 35–40 fiches : architecture, composants, points forts, limites, code réutilisable, idée à reprendre, idée à éviter |
| `PHASE1/03_ARCHI_REFERENCE.md` | synthèse transverse : les 5 questions de conception + BUILD/INTEGRATE/ADAPT/IGNORE par brique |
| `PHASE1/99_BACKLOG.md` | tout ce qui est écarté, classé NEXT / LATER / NEVER |

---

## 7. Triage obligatoire — les trois niveaux

Décision du 2026-08-27 : **ne pas transformer la Phase 1 en audit de 324 repositories.**

```
38 repos shortlist  -> analyse approfondie (NOTES.csv)
70 repos « Haute »  -> triage obligatoire (une ligne complète + motif)
211 autres          -> triage minimal
 29 fiches sans repo -> N/A
```

Le triage produit six champs obligatoires : `statut`, `motif` d'une ligne, `categorie`,
`importance`, `licence_connue`, `url_resolue`. Il **classe**, il ne juge pas l'architecture :
aucun C1/C2/C3 n'y est inventé. Implémenté dans `gen_triage.py`, sortie `02_TRIAGE.csv`.

Répartition réelle mesurée : **38 SHORTLIST, 5 IGNORE, 65 TRIAGE-HAUTE, 187 TRIAGE-MINIMAL,
29 N/A** = 324. Le « 70 » annoncé comptait les 5 fiches « Haute » sans repo exploitable,
qui relèvent du N/A.

## 8. Porte de sortie de la Phase 1 — critère binaire

La Phase 1 n'est **pas validée** tant que `03_ARCHI_REFERENCE.md` ne répond pas à ces cinq questions,
chacune avec le ou les repos qui ont tranché :

1. **Modèle de capability** — comment représenter une capacité et ses providers ?
2. **Policy engine** — où se situe la frontière déterministe, et que couvre-t-elle exactement ?
3. **Exécution / sandbox** — quel niveau d'isolement, et qui l'impose ?
4. **Findings** — quel modèle unifié, et comment préserver la donnée brute ?
5. **Orchestration** — workflow déclaré à l'avance, ou composé dynamiquement par l'IA ?

---

## 9. État

- Barème : **figé** (ce fichier).
- Inventaire : **non fourni** — en attente du dépôt du fichier par l'utilisateur.
- Notation : **aucun repo noté à ce jour.** Toute grille produite avant l'arrivée du fichier serait inventée.

