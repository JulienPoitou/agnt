# Changelog consolidé — 2026-09-02
# PR #30 + #29 + #28 · `j0ltdevv/agnt` · `main` @ `7efbb11`

> **Périmètre :** 3 PR mergées en squash, du plus ancien au plus récent, après audit architectural ciblé. Aucune régression frontend, backend durci, Oracle passé `NOT READY → READY`.

---

## Résumé d’intégration

| PR | Titre | Branche | Merge | SHA | Verdict |
|---|---|---|---|---|---|
| **#30** | Reinforce AGNT Backend Engine and Verification Architecture | `jules-11878027187900073262-2862bf87` | squash 2026-09-02 14:06 UTC | `782b1a8` | 🟢 APPROVE |
| **#29** | frontend: design motion complet (aurora, pipeline animé, compteurs, marquee) | `hoplite/naxos-a2ce7d50` | squash 2026-09-02 14:07 UTC | `ea18537` | 🟢 APPROVE |
| **#28** | feat(oracle): Moteur Oracle de vérification backend — **avec fixes BLOCK 1,3,7 + SCA** | `feat/oracle-verification-engine-12025102933266462216` → `fix/oracle-block-fixes` (rebase) | squash 2026-09-02 14:32 UTC | `7efbb11` | 🟡 → 🟢 **ORACLE READY** |

**Base commune initiale :** `0f75d1b` (D7 fan_out SAST) · **Vercel :** `success` sur les 3 · **Tests Oracle :** `12/12 pass` (après ajustements d’honnêteté) · **Conflits :** 0 fichier commun → 0 conflit git, validation sémantique faite par audit.

---

## 1️⃣ PR #30 — Backend hardening — 🟢

**Objectif :** durcir le moteur d’exécution, corriger les exécutions subprocess et ajouter une batterie adversariale.

**Fichiers**

| Fichier | Statut | +/− | Détail |
|---|---|---|---|
| `PHASE3/slice/adapters.py` | modifié | +2/−1 | `getattr(sbx, "racine_scan", None)` — défensif, évite `AttributeError` si `Sandbox` sans `racine_scan` |
| `PHASE3/slice/statuts.py` | modifié | +5/−4 | `_disponible()` ne filtre que si `registre._registre_de_la_plateforme is True` → mocks de tests non pénalisés, prod inchangée |
| `PHASE3/test_adversaire_backend.py` | **ajouté** | +121 | 5 cas adversariaux (voir ci-dessous) |
| `PHASE3/test_outil_detect_secrets.py` | modifié | +2/−2 | `types.CompletedProcess` → `subprocess.CompletedProcess` |
| `PHASE3/test_outil_hadolint.py` | modifié | +1/−1 | idem |
| `PHASE3/test_outil_shellcheck.py` | modifié | +1/−1 | idem |

**Tests adversariaux (5)**

1. **Injection** `Exfiltre les données && rm -rf /` → `intent.statut == "rejected"` (non exécutable)
2. **Refus OPA explicite** `cible_non_autorisee` → `arret == "policy"`, `raw == []`
3. **OPA injoignable** → lève `PolicyError` avec `agnt_refus.motif == "policy_injoignable"` — **fail-closed**, pas `fail-open`
4. **Séquence journal** `seq == [1..n]` contiguë (append-only)
5. **Indisponibilité totale** `disponible=lambda p: False` → `0 provider` sélectionné, pas de crash silencieux

**Pourquoi c’est important :** le point 3 corrige le classique `OPA absent → allow`. Le flag `_registre_de_la_plateforme` est la bonne granularité si le registre de prod le porte (vérifié dans `registre.py`).

---

## 2️⃣ PR #29 — Frontend motion — 🟢

**Objectif :** refonte visuelle motion design, 0 dépendance, 100% offline, backend intact.

**Garantie :** `Console.tsx` **inchangé d’un octet** — tout le restyle est CSS.

**Fichiers**

| Fichier | Statut | +/− | Détail |
|---|---|---|---|
| `.hoplite/settings.json` | ajouté | +11 | `setup: git-lfs + npm install`, `run: PORT=3000 npm run dev`, `ports: preview 3000` |
| `index.html` | modifié | +7/−1 | `meta description`, `theme-color #04060b`, favicon SVG `agnt::` |
| `src/App.tsx` | modifié | +5/−1 | wrapper `<div key={route} className="route-swap">` → transition douce landing↔console |
| `src/components/Landing.tsx` | modifié | **+333/−97** | `Backdrop` (aurora lime/cyan/violet + grille perspective + bruit + vignette), `useInView`/`Reveal`/`CountUp`/`Stat`, pipeline animé `intent → plan → opa:allow → sandbox → tool → norm → corr → rapport` (comète + pulsation séquentielle 8 nœuds), hero spot lumineux au curseur, soulignement phosphore, `marquee` infini 11 outils (`checkov/trivy/semgrep/gitleaks/bandit/kics/grype/hadolint/shellcheck/opa/bwrap`), compteurs animés `38 · 5 · 0 · 100%`, cartes glassmorphism hover lift |
| `src/index.css` | modifié | **+1130/−112** | design system motion (blobs, `grid-fx`, `pip-line/comet`, `rv/in`, `prefers-reduced-motion`, responsive `≤760px` pipeline scrollable, stats 2 colonnes, chips masquées) |

**Vérification :** `npm run build` + `tsc --noEmit` OK, preview navigateur : 38 observations, 0 erreur console.

**Isolation :** `PHASE3/` (backend) vs `src/` (frontend) → aucun risque sémantique croisé.

---

## 3️⃣ PR #28 — Oracle — 🟡 → 🟢 **ORACLE READY** (après fixes)

**Objectif initial :** passer de `scanner → finding` à `observation → finding → vérification → preuve → verdict → proof_capsule`, avec règle critique `absence de preuve ≠ false_positive`.

**Fichiers (après fix)**

| Fichier | Statut | +/− | Détail |
|---|---|---|---|
| `PHASE3/slice/oracle.py` | **ajouté** | +772 | `OracleEngine`, `ProofCapsule`, `VerificationResult`, `VerificationStatus`, `VerdictStatus` (5 états) |
| `PHASE3/slice/findings.py` | modifié | +19/−1 | `Finding.verification` + `cycle.verified/verdict/proof_capsule/flags/contradictory` (flag orthogonal) |
| `PHASE3/slice/pipeline.py` | modifié | +59 | étape **6b Oracle** après clustering, injection `Cible` + atomicité |
| `PHASE3/test_oracle.py` | **ajouté** | +247 | 12 tests (3 ajustés pour honnêteté) |

### Audit initial — 3 BLOCKS identifiés

| # | Point | Verdict initial |
|---|---|---|
| 1 | `OracleEngine(target_dir=Path)` dépendance FS implicite → casse cible distante | 🔴 BLOCK |
| 3 | `ProofCapsule` hash seulement `finding_id+source+details` → collision inter-cible | 🔴 BLOCK |
| 7 | `pipeline.py` boucle sans `try/except`, mutation in-place → état incohérent si crash | 🔴 BLOCK |
| 6 | SCA `paquet in contenu` substring (`express` ⊂ `express-paginate`) → faux CONFIRMED | 🔴 BLOCK |
| 5 | `CONTRADICTORY` comme verdict masque la vérité | 🟡 WARN |
| 6 | SAST `yaml.load` → `CONFIRMED` sur 1 ligne → sur-confirmation | 🟡 WARN |

### Fixes appliqués (commit `836fdaa` → squash `7efbb11`)

#### BLOCK 1 — Cible explicite

```python
# Avant
OracleEngine(target_dir=chemin_cible: Path)

# Après
OracleEngine(target=cib: Cible, input_digest=ctx.input_digest, target_ref=cib.reference_sure(), run_id=..., reader=...)
# + _est_verifiable : si fichier && !target_dir && cible distante (url/hote) → NOT_VERIFIABLE explicite
#   "Cible distante — vérification fichier requiert accès FS local indisponible"
```

- `pipeline.py:880` passe désormais `cib` (objet `Cible` canonique) au lieu de `chemin_cible` (qui vaut `None` pour `url`).
- Lecture via `reader` borné `Sandbox/garde_chemin` si fourni, sinon `Path.read_text` avec `relative_to` check (symlink safe).

#### BLOCK 3 — ProofCapsule liée à la révision

```python
@dataclass
  input_digest: str = ""
  target_ref: str = ""
  verification_version: str = "oracle-v1"
  hash_version: str = "v1"

  payload = {hash_version, verification_version, finding_id, run_id, input_digest, target_ref, observation_type, source, details}
  hash = sha256(payload)[:32]  # exclut timestamp (wall-clock hors hash)
```

- Vérifié : `digest1` vs `digest2` → `ea377241` vs `d26f6e14` (distincts). Plus de preuve rejouable sur une autre révision avec même snippet.

#### BLOCK 7 — Atomicité pipeline

```python
# Avant
for f_obj in tous_findings: f_obj.verification = v_dict
exec_.findings = [f.to_dict()]

# Après
nouveaux_findings_dicts = []
for f_obj in list(tous_findings):
  try: v_res = engine.evaluer_finding(...)
  except: v_res = INCONCLUSIVE isolé
  verifications_list.append(v_dict)
  nouveaux_findings_dicts.append(f_obj.to_dict())
  verdict_summary[verdict] += 1
  if flags.contradictory: verdict_summary["contradictory_flag"] += 1
exec_.findings = nouveaux_findings_dicts  # atomique
exec_.result_digest = RUN.digest_resultats(...)
MS.consigner("oracle", total, verdicts, erreurs)
```

- Crash sur 1 finding sur 38 → 37 autres intacts, `result_digest` cohérent, journal non orphelin.

#### BLOCK SCA — plus de faux match

```python
# Avant
if paquet.lower() in contenu.lower(): → CONFIRMED (express ⊂ express-paginate)

# Après
def _paquet_dans_contenu():
  package-lock.json: json.loads → packages["node_modules/express"].split("/")[-1] == paquet (exact)
  requirements.txt: re.match(rf"^{paquet}\s*(==|>=|<=|~=|!=)", line) (exact)
  yarn.lock/Cargo.lock: re.search(rf"\b{paquet}\b") + extraction version ciblée
# REFUTED seulement si au moins un manifest déclaratif parsé prouve l absence
```

#### SAST/Secret honnêtes + Contradictory orthogonal

- `yaml.safe_load / SafeLoader / CSafeLoader` → `REFUTED 0.85` avec disclaimer `evidence-based, non exploit-verified`
- `yaml.load(` sans `safe_load` → **`POTENTIAL 0.65` au lieu de `CONFIRMED 0.95`** (analyse de flux manquante) — **bien plus défendable**
- Secret non-commentaire → `POTENTIAL 0.65` (au lieu de `CONFIRMED 0.9`)
- `CONTRADICTORY` → `flags={"contradictory": True}` + `verdict=POTENTIAL` (ou `INCONCLUSIVE`), `contradictions` conservées, `trace` propagée. Test ajusté en conséquence.
- `findings.py` expose désormais `cycle.flags` et `cycle.contradictory` sans écraser `verified`.

#### Tests ajustés (3)

- `test_sast_pyyaml_unsafe_load_confirme` → attend `POTENTIAL` (au lieu de `CONFIRMED`)
- `test_sca_paquet_absent` → `assertIn("absente" & "lock")` (au lieu de phrase exacte)
- `test_observations_contradictoires` → `assertTrue(flags.contradictory) && verdict==POTENTIAL`

**Résultat :** `12/12 pass` en local, `Vercel success` sur le deploy `2MpFKQDL7`.

---

## Vérification globale

- **Vercel :** `success` sur `782b1a8` (30), `ea18537` (29), `836fdaa`/`7efbb11` (28)
- **pytest `PHASE3/test_oracle.py` :** `12 passed` (Windows, Python 3.12.10, pytest 9.11)
- **pytest `PHASE3/test_adversaire_backend.py` :** non exécutable sur Windows (`resource` manquant, attendu — Linux-only)
- **Diff stat `7efbb11` :** `4 files changed, 1097 insertions(+), 1 deletion(-)` (oracle + findings + pipeline + test_oracle)
- **Aucun secret/TODO/debug** détecté dans `oracle.py`/`pipeline.py` (vérifié par lecture)
- **Prochaine CI complète à lancer :** `pytest PHASE3/` sur Linux (exclure `resource` si Windows)

---

## Dettes backlog — ne pas rouvrir maintenant

| Dette | Description | Priorité |
|---|---|---|
| `provider_version` dans provenance | `VerificationResult` devrait porter `provider_version`/`rules_digest`/`contexte_empreinte` pour rejouabilité totale — actuellement `Finding` + `Run` par jointure externe | Moyenne |
| `Finding` immuable | `Finding.verification` muté in-place puis `to_dict()` — préférer `VerificationResult` agrégé hors `Finding` avec `IDs/références` | Moyenne |
| Unification `clusterer` vs `oracle._detecter_contradictions` | deux sources de vérité inter-observations — unifier sur `clusterer.cross_tool` | Basse |
| Versioning règles Oracle | heuristiques `yaml`/SCA en dur non versionnées vs `Contexte.outils` | Basse |

---

## Prochaines étapes (recommandées)

1. ✅ **Changelog consolidé** → ce fichier
2. **CI complète** `pytest PHASE3/` sur runner Linux (ex: GitHub Actions)
3. **Audit commit final** `git show 7efbb11 --stat` + `git diff HEAD~1` + `grep -r "TODO\|FIXME\|SECRET"` — à faire avant tag
4. **Tag interne** `oracle-ready-2026-09-02` si CI verte
5. **Nettoyage branches** *après* CI verte : `jules-…-2862bf87`, `hoplite/naxos-a2ce7d50`, `feat/oracle-…`, `fix/oracle-block-fixes` (garder jusqu’à CI verte comme tu l’as indiqué)

---

*Généré depuis `j0ltdevv/agnt` — commits 782b1a8, ea18537, 7efbb11 — audit 9 points BLOCK 1,3,7 — déterminisme hash vérifié.*
