# PHASE 3 — DÉCISIONS ARCHITECTURALES PROPOSÉES

**⚠️ Aucune de ces décisions n'est appliquée.** Elles attendent ton accord.

Chacune vient d'une observation mesurée, pas d'une préférence. Le fichier de preuve est
`RESULTATS_TESTS.md`.

---

## D1 — Épingler la configuration des outils

**Ce que j'ai mesuré.** Sur le même dépôt de test :

```
p/ci                        → 160 règles chargées, 0 résultat
p/python + p/security-audit → les 2 vulnérabilités trouvées
```

**Le problème.** Un scan peut se terminer en succès, exit 0, avec un rapport vide — et donner
une confiance injustifiée. C'est le pire mode d'échec pour un outil de sécurité : le faux
négatif silencieux.

**Ce que je propose.**

- un champ `config_epinglee` dans le schéma de provider : jeu de règles, version, source ;
- ce champ est **obligatoire**, jamais laissé au défaut de l'outil ;
- un **test de non-régression par provider** : un fixture vulnérable connu doit produire au
  moins un finding attendu. Sans ce test, rien ne garantit qu'une mise à jour de règles ne
  rende pas un adaptateur aveugle.

**Si on ne le fait pas.** On peut livrer un adaptateur qui ne détecte rien, et le découvrir
chez un utilisateur.

---

## D2 — Modéliser la couverture et l'incomplétude

**C'est, à mon avis, la décision la plus importante des six.**

**Ce que j'ai mesuré.**

```
sans package-lock.json → fichiers analysés : ['requirements.txt']
avec package-lock.json → fichiers analysés : ['package-lock.json', 'requirements.txt']
                         + 12 vulnérabilités npm
```

Aucun avertissement de Trivy dans les deux cas. Un dépôt npm sans lockfile ressort avec un
rapport qui a l'air propre.

**Le problème.** Nos deux capacités manquantes — intent engine et corrélation — ne servent à
rien si les données d'entrée sont silencieusement incomplètes. Un rapport incomplet qui se
présente comme complet est **pire** qu'une absence de rapport.

**Ce que je propose.** Ajouter au modèle de données, par exécution :

```yaml
couverture:
  analyse:      [requirements.txt, app.py]
  ignore:
    - cible: package.json
      raison: lockfile absent, dépendances npm non résolues
      outil: trivy
  langues_vues: [python]
  langues_ignorees: [javascript]
```

Et dans le rapport, afficher explicitement ce qui n'a **pas** été analysé.

**Décision à trancher dans cette décision :** est-ce qu'un scan incomplet change le code de
retour ?

| Option | Effet |
|---|---|
| **A** — informatif seulement | le rapport affiche les manques, le scan reste « réussi » |
| **B** — bloquant | un scan incomplet échoue, on force la complétude |

**Ma recommandation : A.** B casserait les CI sur des cas légitimes (un dépôt sans dépendances
npm n'a pas besoin de lockfile). Mais le manque doit être **visible**, pas devinable.

**Si on ne le fait pas.** On produit des rapports faussement rassurants, et on perd la seule
chose qui justifie qu'on nous fasse confiance plutôt qu'à un outil lancé à la main.

---

## D3 — Le sandbox est imposé par nous, pas délégué aux images

**Ce que j'ai mesuré.**

| Image officielle | Utilisateur par défaut | Particularité |
|---|---|---|
| `semgrep/semgrep` | root | un stage `nonroot` existe, mais son Dockerfile avertit de problèmes de permissions sur volumes |
| `aquasec/trivy` | **root** | aucune directive `USER` |
| `zricethezav/gitleaks` | **root** | aucune directive `USER`, et fait `git config --global --add safe.directory '*'` |

**Le problème.** Compter sur les images officielles, c'est déléguer notre frontière de sécurité
à des mainteneurs tiers qui n'ont pas nos exigences.

**Ce que j'ai prouvé.** En imposant nous-mêmes les contraintes avec bubblewrap, les trois outils
tournent correctement — **11 tests sur 11**, y compris en uid 1000 avec le dépôt en lecture seule.

**Ce que je propose.** L'isolation est **notre** responsabilité, appliquée par notre couche
d'exécution, quel que soit l'outil. Conséquence : on peut intégrer n'importe quel outil sans se
demander si son image est bien élevée.

**Décision à trancher : quel runtime ?**

| Option | Couvre | Manque |
|---|---|---|
| **bwrap** | rootless, lecture seule, capabilities, réseau, timeout — **testé ici** | limites CPU / mémoire / PIDs |
| **OCI** (docker/podman) | tout, y compris les limites | non testable dans cet environnement |
| **bwrap + cgroups v2** | tout | à écrire et à tester |

**Ma recommandation :** interface d'isolation unique, **bwrap pour la Phase 3**, OCI en Phase 7.
L'interface doit cacher le choix, pour qu'on puisse changer sans réécrire les adaptateurs.

---

## D4 — Le réseau suit la classification de risque

**Ce que j'ai mesuré.** Aucun des trois outils n'a besoin de réseau **pendant le scan**. Ce dont
ils ont besoin, c'est de mettre à jour leurs données — et ça, c'est de la maintenance, pas du scan.

**Ce que je propose.** Formaliser ce que tu as dit :

| Classification | Réseau | Exemples |
|---|---|---|
| `PASSIVE` | **aucun** | Semgrep, Trivy, Gitleaks |
| `ACTIVE` | filtré, cibles du scope uniquement | Nuclei, scanners réseau |
| `INTRUSIVE` / `DESTRUCTIVE` | filtré **+ validation humaine** | exploitation |

**Pourquoi ce n'est pas du confort.** Le dépôt analysé est une entrée hostile. Un `Makefile`
piégé peut exfiltrer le code au moment où l'outil le lit. Couper le réseau est la mesure la plus
simple contre ça — mais seulement pour les outils qui n'en ont pas besoin.

**Si on ne le fait pas.** Soit on bloque des outils légitimes, soit on laisse un accès libre à
un environnement qui traite du code non fiable.

---

## D5 — Le pré-chauffage devient une opération de premier ordre

**Ce que j'ai mesuré.**

| Données | Taille | Fréquence de rafraîchissement |
|---|---|---|
| Base Trivy | **1,3 Go** | régulière — des CVE paraissent chaque jour |
| Règles Semgrep | ~1 Mo | à chaque évolution des jeux |

Et deux preuves que ce n'est pas optionnel :

```
--offline-scan seul, cache vide  → failed to download vulnerability DB: connection refused
--skip-db-update, cache vide     → --skip-db-update cannot be specified on the first run
```

**Ce que je propose.**

- un composant `Préparateur` distinct de l'executor, qui s'occupe de télécharger et rafraîchir ;
- la **fraîcheur des données fait partie de la couverture** (lien avec D2) : un scan avec une
  base de trois mois doit le dire ;
- le pré-chauffage est **hors sandbox** — il a besoin de réseau, et c'est légitime.

**Si on ne le fait pas.** Trivy échoue au premier scan, ou pire : tourne avec une base périmée
et rate des CVE récentes sans le signaler.

---

## D6 — Normaliser les identifiants de règle

**Ce que j'ai mesuré.**

```
règle depuis le registre Semgrep : python.lang.security.audit.subprocess-shell-true...
même règle depuis un fichier local : rules.python.lang.security.audit.subprocess-shell-true...
                                     ^^^^^^ préfixe ajouté
```

**Le problème.** La même vulnérabilité a deux identifiants selon l'origine de la règle. Sans
normalisation, **notre déduplication et notre corrélation produiraient des doublons** — c'est-à-
dire qu'on raterait précisément notre principal différenciant.

**Ce que je propose.**

- un `id_canonique` calculé par nos soins, stocké à côté de `id_source` ;
- la déduplication et la corrélation utilisent **uniquement** `id_canonique` ;
- le cas Semgrep est le premier d'une liste : chaque adaptateur devra déclarer sa règle de
  normalisation.

**Si on ne le fait pas.** « Voici 3 problèmes importants » devient « voici 6 problèmes », dont
la moitié sont des doublons. On perd la promesse centrale du projet.

---

## Ce qui ne change PAS

Pour que ce soit clair : **aucune de ces six décisions ne remet en cause l'architecture.**

```
LLM → Plan typé → OPA → Executor déterministe → Sandbox → Tools
```

Cette chaîne reste. Le modèle de findings reste. SARIF en export reste. Apache-2.0 reste.
Python reste.

Les six décisions portent toutes sur **la configuration des providers et la qualité des
données** — ce qui confirme le choix de mettre cette configuration dans le registre plutôt que
dans le moteur.

---

## Résumé pour décision

| # | Décision | Ma recommandation | Urgence |
|---|---|---|---|
| D1 | `config_epinglee` | oui, + test de non-régression par provider | avant l'écriture des adaptateurs |
| D2 | Couverture / incomplétude | oui, **option A** (informatif) | **avant le modèle de données** |
| D3 | Sandbox imposé par nous | oui, interface unique, bwrap en Phase 3 | avant l'executor |
| D4 | Réseau selon le risque | oui | avant l'executor |
| D5 | Préparateur dédié | oui, fraîcheur incluse dans la couverture | avant le premier scan |
| D6 | `id_canonique` | oui | avant la corrélation (Phase 9) |

**D2 est celle qui presse le plus** : elle touche au modèle de données, et tout le reste en
dépend.
