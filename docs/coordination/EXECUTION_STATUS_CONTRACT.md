# AGNT Execution Status Semantics — Product Contract v1

Status: **implementation contract** · Version: `agnt.execution-status.v1` · Owner: Product/UX  
Compatible with: [`agnt.history.v1`](MISSION_HISTORY_CONTRACT.md) and
[`agnt.timeline.v1`](MISSION_TIMELINE_CONTRACT.md)  
Scope: normalized status semantics for existing `data.executions[]`. No endpoint, store,
journal, backend, provider, Finding model, or UI is introduced.

## 1. Non-negotiable model

These dimensions are independent:

```text
Mission lifecycle
≠ provider applicability / selection / authorization
≠ provider availability
≠ execution result
≠ detection result
≠ event consequence
≠ data completeness
```

A product statement is valid only in its own dimension. In particular:

```text
provider unavailable ≠ execution failed ≠ no findings
policy refused ≠ provider failed
execution completed ≠ coverage complete ≠ mission secure
findings artifact absent ≠ findings count 0
```

This contract normalizes existing evidence into each item of the history detail's existing
`data.executions[]`. It does not add a second execution list. A detail MAY advertise
`execution_status_schema: "agnt.execution-status.v1"`; each execution item then conforms to
[`execution-status-v1.schema.json`](execution-status-v1.schema.json).

CORE serializes structured facts and reason codes. WEB maps those codes to localized copy. A
free error message, CSS color, timestamp, or isolated file never determines a status.

### Evidence boundary for this version

**Observed on this branch:** CORE ledger values `non_disponible`, `non_applicable`,
`non_selectionne`, `non_autorise`, `selectionne`, `echoue`, `execute`; structured booleans/counts
`disponible`, `timeout`, `en_cours`, `rien_trouve`, `cibles_analysees`, `findings`, return code;
selection/applicability/condition/policy artifacts; egress category; Mission journal and
normalized findings.

**Announced, not observed on this branch:** MCP terminal values `timed_out`, `cancelled`, remote
`unavailable`/failure and partial provenance. Their mappings below are normative integration
requirements, not claims that the current repository emits them. Unknown MCP values remain
unknown until MCP supplies validated structured enums.

## 2. Dimension 1 — Mission status (unchanged)

Exactly the history v1 vocabulary:

- `en_file`: submission known in current queue;
- `en_cours`: active ownership is proven;
- `termine`: terminal close is recorded;
- `refuse`: explicit intent/condition/policy/fail-closed stop;
- `erreur`: classified technical mission failure;
- `inconnu`: terminal/current state cannot be proved.

No `annule`, `timeout`, `indisponible`, or `sans_resultat` Mission status is added. Those facts
belong to provider execution or completeness. One provider timeout does not automatically set
Mission `erreur`; the mission may finish with partial coverage. Mission status remains sourced
from history v1, not aggregated in WEB from provider rows.

## 3. Dimension 2 — Provider decision path

The old ledger's single `statut` remains accepted as source evidence, but v1 projects it into
four explicit fields so distinct decisions cannot overlap.

### Applicability

- `applicable`: target compatibility is positively established;
- `non_applicable`: declared target constraints prove incompatibility;
- `inconnu`: compatibility was not evaluated or evidence is absent.

### Selection

- `selectionne`: provider is present in the authoritative plan;
- `non_selectionne`: selection evidence explicitly rejected/preferred another provider;
- `inconnu`: no authoritative plan/selection evidence.

### Execution condition

- `remplie`: required preconditions are proven satisfied;
- `bloquee`: a structured condition (egress, rule pack, database, configuration) blocked use;
- `inconnu`: condition was not evaluated or proof is missing.

A blocked condition is **not** target inapplicability. Legacy CORE currently folds both into
`non_applicable`; use `motif_categorie` or structured selection conditions to separate them.
If no structured discriminator exists, keep applicability/condition `inconnu` rather than parse
free text.

### Authorization

- `autorise`: an authoritative policy decision allowed this provider/plan;
- `non_autorise`: an authoritative policy decision explicitly denied it;
- `non_evalue`: policy could not decide or was never reached;
- `inconnu`: policy evidence is incomplete/contradictory.

OPA unavailable is `non_evalue` with `policy_unavailable`, not an invented explicit deny. The
Mission remains `refuse` under the already-defined fail-closed lifecycle mapping.

## 4. Dimension 3 — Provider availability

Vocabulary:

- `disponible`: prerequisites needed to invoke this provider are proven present;
- `indisponible`: a structured check proves invocation cannot currently occur;
- `inconnu`: availability was not checked or evidence is incomplete.

Availability reason codes:

- `binary_missing`;
- `rule_pack_missing`;
- `rule_pack_invalid`;
- `dependency_database_missing`;
- `external_server_unavailable`;
- `transport_unavailable`;
- `configuration_invalid`;
- `environment_incomplete`;
- `availability_not_checked`;
- `availability_evidence_conflict`.

Egress blocked before an MCP call means condition `bloquee`; it does not prove the remote
provider unavailable because no availability call occurred. Use availability `inconnu` unless
an independent approved health signal exists.

## 5. Dimension 4 — Execution result

Canonical product vocabulary:

| Value | Meaning | Invoked | Usable output | Default tier | Safe product text | Semantic tone |
|---|---|---:|---|---|---|---|
| `non_lance` | Evidence proves no invocation occurred | no | no | mission | “Non exécuté” + safe reason | neutral/warning |
| `en_cours` | Invocation started and has no terminal evidence | yes | no yet | summary/mission | “Analyse en cours” | informational |
| `termine` | Invocation ended with accepted output | yes | yes | mission | “Analyse terminée” | success for execution only |
| `echoue` | Invocation ended without accepted output | yes | no | mission | “L’analyse a échoué” | danger |
| `timed_out` | Deadline ended/aborted invocation | yes or unknown | no unless explicitly partial | mission | “Délai d’exécution dépassé” | warning/danger |
| `cancelled` | Structured cancellation acknowledged | yes or unknown | no unless explicitly partial | mission | “Analyse annulée” | neutral/warning |
| `unavailable` | Invocation could not begin because provider was unavailable | no | no | mission | “Provider indisponible” | warning |
| `inconnu` | Execution state cannot be proved | unknown | unknown | mission | “État d’exécution inconnu” | warning |

Each execution object separately carries:

- `invocation`: `oui`, `non`, `inconnu`;
- `output`: `exploitable`, `partiel`, `non_exploitable`, `inconnu`;
- `reason_code`: stable allowlisted code;
- `proof`: `recorded`, `derived`, `provider_reported`, `unknown`.

`provider_reported` describes provenance of the status, not trust. A remote `success` is mapped
to `termine` only after its response satisfies the transport contract and normalization rules.

Recommended execution reason codes:

- `not_in_plan`, `target_not_applicable`, `condition_blocked`, `policy_denied`,
  `policy_unavailable`, `mission_stopped_before_execution`;
- availability codes from section 4;
- `deadline_exceeded`, `cancellation_acknowledged`, `remote_failure`, `local_failure`,
  `unexpected_exit_code`, `invalid_provider_output`, `normalization_failed`;
- `execution_evidence_missing`, `execution_evidence_conflict`.

Cause absent: retain the execution value only when terminal evidence proves it; use generic
safe copy and omit reason detail. If even the value is unproved, return `inconnu`.

### Visual/accessibility semantics

- Never communicate status by color alone: always text plus icon/shape and accessible label.
- Green means only “execution completed/available”, never “secure” or “no vulnerabilities”.
- Blue/information: queued/running.
- Amber/warning: unavailable, timeout, cancelled, partial, unknown, coverage limitation.
- Red/danger: explicit failure or denial where user action is required.
- Grey/neutral: not selected or not applicable.
- Refusal is not styled/labeled as scanner failure; cancellation is not styled as timeout.

This contract defines semantics, not CSS tokens.

## 6. Dimension 5 — Detection result

Vocabulary:

- `findings_presents`: readable normalized finding evidence proves one or more findings from
  this provider;
- `rien_trouve`: successful execution, at least one target actually analyzed, and readable
  normalized finding evidence proves exactly zero findings for this provider;
- `non_evalue`: detection could not validly be evaluated (not run, unavailable, denied,
  inapplicable, blocked, failed, timed out, cancelled, or no analyzed target);
- `inconnu`: execution may have completed, but expected detection evidence is missing,
  unreadable, unattributable, or contradictory.

### Proof required for `rien_trouve`

All conditions are mandatory:

1. execution `termine`;
2. invocation `oui`;
3. output `exploitable`;
4. provider ledger/raw evidence has an accepted terminal code/status;
5. coverage proves `analyzed_targets > 0`;
6. the normalized findings artifact is present and readable;
7. findings can be authoritatively attributed to the provider;
8. attributed `findings_count == 0`;
9. no contradiction/incomplete marker affects those facts.

If any condition is absent, `rien_trouve` is forbidden. `findings_count: 0` is present only with
`rien_trouve`; otherwise the count is omitted. A successful tool process with zero analyzed
targets is `non_evalue`, not `rien_trouve`.

### Proof required for `findings_presents`

Readable normalized findings artifact + authoritative provider attribution + count greater
than zero. Process stdout counts, remote claims, or journal summary alone may support technical
diagnostics but do not replace the normalized artifact.

## 7. Dimension 6 — Completeness

Every execution item has:

- `state`: `complete`, `partial`, `unavailable`, `conflict`;
- `missing`: stable logical field/evidence names;
- `limitations`: safe reason codes.

Rules:

- `partial`: useful facts exist but optional/expected evidence is missing;
- `unavailable`: no safe useful execution evidence;
- `conflict`: authoritative sources disagree; never choose the most reassuring value;
- missing finding artifact after a proven completed invocation yields detection `inconnu`, not
  `rien_trouve`;
- unknown status/MCP values yield the affected dimension `inconnu` and limitation
  `unknown_source_status`;
- frontend must not resolve conflicts, parse free messages, or fill defaults.

## 8. Deterministic source mapping

Precedence is based on structured evidence, not optimism:

1. explicit canonical terminal evidence from the mission ledger/artifacts;
2. validated provider/MCP terminal status plus accepted normalized output;
3. current structured CORE ledger fields;
4. conservative unknown/non-evaluated state.

A lower-priority source cannot override a higher-priority contradiction. Any contradiction sets
completeness `conflict` and the affected status `inconnu` unless one source is explicitly
non-authoritative.

### Current CORE ledger mapping

| CORE `statut` / evidence | Decision projection | Availability | Execution | Detection |
|---|---|---|---|---|
| `non_disponible` + structured absence | preserve plan/selection facts; other decision fields from artifacts | `indisponible` | `unavailable` | `non_evalue` |
| `non_applicable` + target discriminator | applicability `non_applicable`, selection `non_selectionne`, authorization `non_evalue` | preserve check | `non_lance` | `non_evalue` |
| `non_applicable` + condition discriminator | condition `bloquee`; applicability stays proven/unknown separately | preserve or `inconnu` | `non_lance` | `non_evalue` |
| `non_selectionne` | selection `non_selectionne`; applicability only if separately proved | preserve check | `non_lance` | `non_evalue` |
| `non_autorise` + explicit policy deny | selection `selectionne`, authorization `non_autorise` | preserve check | `non_lance` | `non_evalue` |
| `non_autorise` + `policy_injoignable` | selection `selectionne`, authorization `non_evalue` | preserve check | `non_lance` | `non_evalue` |
| `selectionne` + `en_cours: true` | selection `selectionne`, authorization `autorise` | preserve check | `en_cours` | `non_evalue` |
| `selectionne`, terminal Mission, no invocation evidence | selection `selectionne`; authorization from policy | preserve check | `non_lance` if absence is proved, otherwise `inconnu` | `non_evalue` or `inconnu` accordingly |
| `echoue` + `timeout: true` | preserve decision facts | preserve check | `timed_out` | `non_evalue` |
| `echoue` + structured cancellation | preserve decision facts | preserve check | `cancelled` | `non_evalue` |
| `echoue` otherwise | preserve decision facts | preserve check | `echoue` | `non_evalue` |
| `execute`, accepted output, analyzed targets > 0, normalized count > 0 | selected/authorized | `disponible` | `termine` | `findings_presents` |
| `execute` + every zero-proof condition in section 6 | selected/authorized | `disponible` | `termine` | `rien_trouve` |
| `execute`, accepted output, zero analyzed targets | selected/authorized | `disponible` | `termine` | `non_evalue` |
| unknown ledger status | only separately proved fields | `inconnu` unless separate proof | `inconnu` | `inconnu` |

The current boolean `disponible` is accepted as a local availability observation only when its
resolver/check is authoritative for that provider kind. It must not be applied to remote MCP
providers unless MCP supplies an equivalent structured check.

### MCP mapping

| Validated MCP/transport fact | Availability | Execution | Detection | Proof |
|---|---|---|---|---|
| provider/transport unavailable before dispatch | `indisponible` | `unavailable` | `non_evalue` | provider-reported or recorded transport fact |
| request dispatched, deadline exceeded | preserve known availability | `timed_out` | `non_evalue` | recorded deadline outcome |
| cancellation acknowledged | preserve known availability | `cancelled` | `non_evalue` | recorded acknowledgment |
| remote structured error | preserve known availability | `echoue` | `non_evalue` | provider-reported, redacted |
| malformed/unsupported payload | preserve known availability | `echoue` (`invalid_provider_output`) | `non_evalue` | recorded validator result |
| valid response but normalization fails | preserve known availability | `echoue` (`normalization_failed`) | `non_evalue` | recorded normalizer result |
| valid normalized findings count > 0 | `disponible` if independently known | `termine` | `findings_presents` | recorded normalized artifact |
| valid normalized zero with analyzed target proof | `disponible` if independently known | `termine` | `rien_trouve` | recorded normalized artifact |
| unknown future MCP status | `inconnu` where affected | `inconnu` | `inconnu` | unknown |

Never map by matching text such as “timeout”, “cancelled”, or “unavailable” inside a free remote
error. MCP must provide a validated status enum/reason code.

## 9. Security and product scenarios

For all cases below, “advanced” still means redacted structured facts; endpoints, tokens,
headers, raw errors, argv, environment, local paths, raw payloads, and stack traces stay hidden.

| Situation | User sees | Advanced detail | Possible Mission status | Detection | WEB must never infer |
|---|---|---|---|---|---|
| Target lacks explicit authorization | “Mission refusée — cible non autorisée” | `target_not_authorized`; no provider execution fabricated | `refuse` | `non_evalue` | no provider failure, no zero |
| OPA unavailable | “Mission refusée — validation de sécurité indisponible” | `policy_unavailable`, authorization `non_evalue`, fail-closed | `refuse` | `non_evalue` | not explicit policy deny, not scanner error |
| Egress disabled before MCP call | “Provider non exécuté — accès réseau non autorisé” | condition `bloquee`, `egress_not_authorized`; availability usually unknown | `refuse` if no valid coverage, otherwise possibly `termine` | `non_evalue` | remote unavailable or timed out |
| Local provider binary absent | “Provider indisponible” | `binary_missing`, invocation `non` | `refuse`, `termine`, or `erreur` according to mission evidence | `non_evalue` | failed invocation or zero |
| Trusted rule pack absent/invalid | “Analyse non exécutée — règles indisponibles” | `rule_pack_missing` / `rule_pack_invalid` | `refuse`, `termine`, or `erreur` | `non_evalue` | clean scan |
| Provider not applicable | “Non applicable à cette cible” | safe target constraint code | usually `termine` if other coverage; `refuse` if none | `non_evalue` | unavailable or failed |
| MCP provider unavailable | “Provider externe indisponible” | safe provider/transport IDs and reason code | `termine`, `refuse`, or `erreur` from Mission evidence | `non_evalue` | timeout, deny, zero |
| MCP timeout | “Délai d’exécution dépassé” | deadline reason, redacted correlation ID | `termine` partial or `erreur` | `non_evalue` | cancelled/unavailable/zero |
| MCP cancellation | “Analyse annulée” | cancellation acknowledgment and safe IDs | `termine` partial, `erreur`, or `inconnu`; no new Mission status | `non_evalue` | timeout or success |
| Redacted remote MCP error | “Le provider externe a échoué” | `remote_failure`, partial provenance | `termine` partial or `erreur` | `non_evalue` | raw message or zero |
| Invalid/non-normalizable output | “Résultat provider inexploitable” | validator/normalizer reason code | `termine` partial or `erreur` | `non_evalue` | completed detection or zero |
| Findings artifact absent after completed invocation | “Résultat de détection indisponible” | missing `findings`, completeness partial/unavailable | `termine` or `inconnu` from Mission evidence | `inconnu` | zero |
| Journal/artifact incomplete | “Informations de mission incomplètes” | logical missing fields, timeline limitations | `inconnu` unless terminal evidence survives | `inconnu`/`non_evalue` | success from isolated file |
| MCP provenance partial | result plus “Provenance partielle” | only validated present provenance keys | unchanged | based on normalized result, not provenance alone | local/trusted defaults |
| Unknown timeline event | “Événement non reconnu enregistré” in technical tier | safe source kind only | unchanged or `inconnu` if terminal semantics uncertain | unchanged unless evidence conflicts | arbitrary payload semantics |

## 10. Safe product messages

WEB localizes `reason_code`; CORE/MCP do not hardcode rich UI prose. Required semantics:

- include the object and action: “Dependency analysis — délai dépassé”;
- distinguish “non exécuté”, “indisponible”, “refusé”, “échoué”, and “annulé”;
- for `rien_trouve`: “Aucun finding remonté sur les cibles analysées”, followed by coverage
  limitations; never “Aucun problème” or “Le projet est sécurisé”;
- for missing reason: “Cause non consignée”, not a guessed cause;
- for incomplete data: “Résultat incomplet — certaines informations ne sont pas disponibles”.

Messages are single-line/bounded in list/summary contexts and rendered as text. Provider-supplied
free messages are not user copy until allowlisted, redacted, and bounded.

## 11. Empty, loading, offline, incomplete, and unknown

- No providers in a proven plan: explain “Aucun provider sélectionné”; do not show zero findings.
- `data.executions` absent: execution data unavailable, not an empty successful execution.
- `data.executions: []` is meaningful only if backend proves an empty execution set and supplies
  Mission refusal/incomplete context.
- Loading: preserve prior truthful state and label refresh; do not temporarily reset counts.
- Offline/API failure: API availability state, not Mission/provider status; never substitute
  fixtures.
- Incomplete: show coverage warning before interpreting detection counts.
- Unknown enum: affected dimension `inconnu`, retain safe source code only in technical detail,
  add `unknown_source_status`.
- Conflicting evidence: completeness `conflict`, no reassuring result/count.

## 12. Compatibility

### History v1

- Mission status is unchanged and remains authoritative.
- Existing `data.executions[]` is enriched in place; no second array/route.
- `findings_summary.total: 0` still requires a readable findings artifact. Provider-level zero
  adds stricter attribution/coverage proof and does not weaken history truth rules.
- Missing execution fields remain absent/unknown, never frontend defaults.

### Timeline v1

- Timeline event consequence is unchanged.
- Provider execution records may be referenced by safe `provider_id`/`run_id`; they are not
  recomputed from timeline labels.
- `provider_completed/completed` supports execution completion but not detection
  `rien_trouve` without section 6 evidence.
- `unknown_event_recorded` never creates an execution result.

## 13. Minimum fields for implementation

Each `data.executions[]` item conforming to v1 contains:

- `provider_id` and optional safe capability/display label;
- `applicability`, `selection`, `condition`, `authorization` values;
- `availability: {value, reason_code?, proof}`;
- `execution: {value, invocation, output, reason_code?, proof}`;
- `detection: {value, findings_count?, analyzed_targets?, proof}`;
- `completeness: {state, missing, limitations}`;
- optional allowlisted provenance from timeline v1.

Decision dimensions should carry `proof` and optional structured `reason_code` as well. Dates,
return-code class, timeout/cancellation acknowledgment, wave, and safe correlation IDs are
technical optional fields. Raw return text is forbidden.

## 14. Builder acceptance criteria

### CORE

1. Project structured dimensions into existing `data.executions[]`; do not create a parallel
   status store or UI messages.
2. Preserve Mission status from history v1 independently of provider aggregation.
3. Emit structured reason codes and proof origin; never require WEB to parse `raison`.
4. Prove `rien_trouve` with accepted execution, analyzed-target coverage, readable normalized
   findings, provider attribution, and zero count.
5. Mark missing/contradictory evidence; do not select the most reassuring source.
6. Keep legacy ledger readable and map it according to section 8.

### MCP

1. Map transport outcomes distinctly: `timed_out`, `cancelled`, `unavailable`, `failed`.
2. Supply structured status/reason and whether dispatch/cancellation acknowledgment occurred.
3. Provider success becomes `termine` only after validation/normalization.
4. Keep provenance allowlisted and redacted per timeline v1.
5. Never include endpoint, token, header, raw payload/error, stack, argv, environment, or path.

### SECURITY

1. Validate status/reason enums and reject unsafe unknown payload fields before serialization.
2. Preserve explicit target/policy denial versus policy unavailability/fail-closed.
3. Classify trusted rule-pack missing/invalid as unavailable/non-evaluated, never clean.
4. Test hostile free messages, enum confusion, contradictory artifacts, forged zero counts,
   cancellation/timeout ambiguity, and secret-bearing metadata.
5. Ensure redaction happens server-side; frontend escaping is defense-in-depth.

### WEB

1. Render each dimension independently with text/icon/accessibility label; never color alone.
2. Never derive Mission status from provider rows or derive provider state from Mission status.
3. Never render zero unless backend returns detection `rien_trouve` or
   `findings_presents` with authoritative `findings_count`.
4. Show coverage/incomplete warnings before a zero-result interpretation.
5. Do not parse free reasons, raw MCP values, CSS classes, timestamps, or artifact presence.
6. Unknown values render as unknown, not success; cancelled remains distinct from timeout.

## 15. Out of scope

- UI components, CSS colors/tokens, filters, or frontend store.
- API routes, pipeline/ledger modifications, MCP transport implementation.
- New Mission statuses.
- Retry/relaunch behavior and cancellation controls.
- Cross-mission aggregation/comparison.
- Scoring whether a Mission is “secure”.
- Changing existing Finding or policy models.
