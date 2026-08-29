# PHASE 3 — VERTICAL SLICE : RÉSULTATS

_État : **10/10 critères de réussite validés**, `python3 PHASE3/test_slice.py` → exit 0._

---

## 1. Ce qui tourne

```
« Analyse la sécurité de mon dépôt »
   ↓
intent engine        → CODE_STATIC_ANALYSIS, DEPENDENCY_ANALYSIS, SECRET_DETECTION
   ↓
registre             → semgrep, trivy, gitleaks   (lus dans capabilities.yaml)
   ↓
plan typé            → plan_id e6f24a71248449fa, 3 étapes, sérialisable
   ↓
OPA                  → allow=true
   ↓
sandbox bwrap        → rootless, lecture seule, sans réseau, sans capability
   ↓
raw results          → 3 fichiers conservés (672 o + 6,9 Ko + 276 Ko)
   ↓
couverture           → ce qui a été analysé, et ce qui ne l'a PAS été
   ↓
findings             → 65, avec identité source ET canonique
   ↓
clustering v0        → 65 → 8 clusters, aucune perte
   ↓
rapport
```

**Chiffres réels :** 65 findings (62 Trivy, 2 Semgrep, 1 Gitleaks), 8 clusters,
0 fuite de secret.

---

## 2. Les huit clusters — et pourquoi ce ne sont pas trois

| Cluster | Membres | Confiance | Raison |
|---|---|---|---|
| CL-001 | 41 | high | même paquet : django |
| CL-002 | 10 | high | même paquet : lodash |
| CL-003 | 4 | high | même paquet : requests |
| CL-004 | 3 | high | même paquet : pyyaml |
| CL-005 | 2 | medium | même fichier, lignes proches (Semgrep 9 et 12) |
| CL-006 | 2 | high | même paquet : minimist |
| CL-007 | 2 | high | même paquet : flask |
| CL-008 | 1 | low | même règle : github-pat |

**Le brief demandait trois clusters. J'en ai huit, et je ne les ai pas réduits.**

Les 62 vulnérabilités Trivy portent sur **six paquets distincts**. Les fusionner en un seul
groupe reviendrait à dire « django, lodash, requests, pyyaml, minimist et flask, c'est le même
problème » — ce qui est faux. Tu l'avais écrit toi-même : *« Ne force jamais 64 résultats en
3 problèmes uniquement parce que la démo attend 3 problèmes. »*

**Ce que les huit prouvent :** le regroupement est explicable, chaque cluster expose sa raison,
et 65 findings en entrée donnent 65 findings répartis en sortie. Aucune perte.

**Ce que les huit ne prouvent pas :** la corrélation multi-outils. Aucun cluster ne mélange
Semgrep, Trivy et Gitleaks, parce que sur cette fixture ils ne parlent pas du même sujet.
Pour la démontrer il faudrait un dépôt où deux outils signalent la même chose — par exemple
une dépendance vulnérable vue par Trivy **et** un appel dangereux à cette dépendance vu par
Semgrep. C'est un travail sur la fixture, pas sur le moteur.

---

## 3. Ce que la couverture déclare — le point le plus utile

```
semgrep
   analysé      : app.py
   limite       : jeu de règles épinglé sur python/security-audit — un dépôt d'un
                  autre langage ressortirait vide sans erreur

trivy
   analysé      : requirements.txt, package-lock.json
   NON analysé  : package.json [not_scanned] — manifeste npm présent mais ignoré
   limite       : base de vulnérabilités figée au pré-chauffage

gitleaks
   analysé      : historique git, app.py
   limite       : valeur des secrets masquée à la source, jamais stockée
   limite       : une clé AWS réaliste peut être classée generic-api-key
```

Sans ça, le rapport dirait « 65 problèmes trouvés » et passerait sous silence que la base de
CVE est figée et que le jeu de règles est limité à Python.

---

## 4. Bugs trouvés en construisant — tous corrigés

Chacun a été trouvé par un test ou par une erreur réelle, jamais par relecture.

| # | Bug | Symptôme observé | Correction |
|---|---|---|---|
| 1 | `asdict()` récursif dans `plan.construire` | `'dict' object has no attribute 'to_dict'` | `dataclasses.replace` |
| 2 | `prov.args` au lieu de `prov.args_obligatoires` | `AttributeError` | renommé |
| 3 | Chemins fictifs `/regles/` écrits dans le registre | Semgrep : `path /regles/python.yaml does not exist` | jetons `{BIN}` `{SCAN}` `{REGLES}` `{DB}` `{OUT}` |
| 4 | **`--output` injecté à tous les outils** | Gitleaks s'exécutait, ne trouvait rien, **rendait 0** | chaque adaptateur déclare son propre drapeau |
| 5 | Binaires absents du PATH du sandbox | `bwrap: execvp trivy: No such file or directory` | résolution `{BIN}` puis PATH |
| 6 | **Cible non passée aux outils** | Trivy : `Require at least 1 argument` ; Semgrep a scanné **135 fichiers** au lieu de 3 | cible ajoutée en dernier |
| 7 | Clustering par bloc `ligne//3` | lignes 9 et 12 non fusionnées | union-find sur le voisinage |
| 8 | `Registry.descr()` itérait sur les clés | `AttributeError: 'str' object has no attribute 'id'` | `.values()` |
| 9 | **`descr()` listait les noms de providers** | le LLM voyait « providers : semgrep » | retiré — voir §5 |

### Les deux qui comptent

**Le bug 4 est le plus dangereux.** Gitleaks recevait `--output`, qu'il ne connaît pas, donc il
ne trouvait rien et **rendait un code de succès**. Un échec silencieux, exactement le mode
d'échec que la décision D1 vise à empêcher.

**Le bug 6 aussi.** Sans cible, Semgrep scanne le répertoire courant : 135 fichiers au lieu de
3, et un rapport qui a l'air plausible.

Dans les deux cas, la **couverture** a signalé le problème — c'est elle qui a rendu ces bugs
visibles au lieu de les laisser passer.

---

## 5. Un défaut d'architecture trouvé, pas un bug

`Registry.descr()` listait les providers :

```
- CODE_STATIC_ANALYSIS : Analyse statique du code source…
    domaines : code, appsec
    providers : semgrep          ← FUITE
```

Le LLM voyait donc le nom des outils. C'est la violation directe de la règle du projet :
*« le planner ne connaît pas Trivy, le registre connaît Trivy. »*

Corrigé : le LLM ne voit plus que l'identifiant de capacité, sa description, ses domaines et
le **nombre** de providers. Le critère 4 le vérifie maintenant mécaniquement.

---

## 6. Les dix critères, avec leurs preuves

| # | Critère | Preuve |
|---|---|---|
| 1 | Une phrase produit un plan JSON valide | `plan_id=e6f24a71248449fa`, 3 étapes, version 1.0 |
| 2 | Uniquement capabilities et providers autorisés | 3 étapes, 0 hors registre |
| 3 | OPA autorise ou refuse | nominal=true ; refus : `cible_non_autorisee`, `risque_trop_eleve`, `commande_suspecte` |
| 4 | Aucun chemin IA → shell | `descr()` sans nom d'outil ni drapeau ni chemin ; commande forgée refusée |
| 5 | Les trois outils s'exécutent en sandbox | codes 0/0/0, trois sorties non vides |
| 6 | Raw results conservés | 672 o + 6,9 Ko + 276 Ko |
| 7 | Non-analysés et limites déclarés | 1 cible `not_scanned`, 3 providers avec limites |
| 8 | Identité source + canonique | 65 findings, 0 sans identité, 0 fuite de secret |
| 9 | Clusters explicables, aucune perte | 65 → 8 clusters + 0 non regroupé = 65 |
| 10 | Rejeu identique | même plan_id, même empreinte, mêmes findings, mêmes clusters |

---

## 7. Limites assumées de ce slice

- **Un seul processus Python.** Aucun service, aucune file, aucun plugin.
- **Une seule forme d'exécution : `cli`.** Le registre **refuse** `api`, `async_job`,
  `stream` et `recursive` à la construction — il échoue au lieu de faire semblant.
- **Intent engine déterministe.** Correspondance de mots-clés, pas de LLM. Choix assumé :
  un intent engine non reproductible empêcherait le critère 10. Le branchement LLM prendra
  la même place, avec le même schéma de sortie validé.
- **Limites CPU / mémoire / PIDs non imposées.** bwrap ne le fait pas ; il faudrait cgroups v2
  ou un runtime OCI.
- **Corrélation multi-outils non démontrée** — voir §2.

---

## 8. Comment rejouer

```bash
./PHASE3/bootstrap.sh          # reconstruit binaires, règles, base 1,3 Go, fixture
python3 PHASE3/slice/pipeline.py "Analyse la sécurité de mon dépôt" PHASE3/testrepo
python3 PHASE3/test_slice.py   # les dix critères
```

Le bootstrap existe parce que dans cet environnement les binaires installés hors du workspace
et les fichiers cachés (`.git`) ne survivent pas entre les sessions. Toute la chaîne est donc
reconstructible de zéro.
