# AGNT Mission Timeline & Safe Provenance — Product Contract v1

Status: **implementation contract** · Version: `agnt.timeline.v1` · Owner: Product/UX  
Companion to: [`agnt.history.v1`](MISSION_HISTORY_CONTRACT.md)  
Scope: deterministic projection of existing mission evidence. This contract does not add an
endpoint, journal, store, telemetry system, or UI.

## 1. Product decision

The timeline is a **read-only projection**, never a source of truth. Its only sources are the
persisted mission header, append-only journal, and already-normalized/redacted mission
artifacts defined by the history contract.

It is added under the existing detail response:

```text
GET /api/missions/{mission_id}?timeline_limit=200&timeline_cursor=<opaque>
└── data.timeline : agnt.timeline.v1
```

No separate timeline endpoint is introduced in v1. The existing optional `data.events` field
in `agnt.history.v1` remains compatible as a legacy minimal projection. New implementations
SHOULD emit `data.timeline`; WEB prefers it when present and may fall back to `data.events`
without merging the two. This is additive because `data` already permits companion fields.

The Mission/Run decisions from history v1 remain unchanged: Mission is user-visible and
persistent; Run is technical; cardinality is `Mission 1 → 0..1 Run`; `mission_id` is primary.

## 2. What the timeline is — and is not

The timeline answers “what recorded evidence says happened, in what recorded order.” It does
not reconstruct an ideal workflow and does not infer milestones from artifact existence.

Hard rules:

1. **No evidence, no event.** A report file does not prove a `report_generated` event; a cluster
   file does not prove a `correlation_completed` event; file modification time is not a mission
   timestamp.
2. One valid journal line produces **at most one** projected timeline event. Snapshot payloads
   such as provider `statuts` are not exploded into fictional events sharing one timestamp.
3. Journal `seq` determines order. Timestamp is display data only.
4. Raw journal payload is never returned. Known event kinds are projected through an allowlist;
   unknown kinds produce a safe generic event rather than raw payload or silent disappearance.
5. Mission status, event consequence, provider availability, and data completeness are separate
   dimensions.

## 3. Timeline envelope

```json
{
  "schema_version": "agnt.timeline.v1",
  "state": "complete",
  "ordering": "journal_sequence_ascending",
  "events": [],
  "returned_events": 0,
  "total_events": 0,
  "truncated": false,
  "next_cursor": null,
  "limitations": []
}
```

Required:

- `schema_version`: exactly `agnt.timeline.v1`;
- `state`: `complete`, `partial`, or `unavailable`;
- `ordering`: exactly `journal_sequence_ascending`;
- `events`: ordered array;
- `returned_events`: number of items in this response;
- `truncated`: whether additional valid source events were omitted;
- `next_cursor`: opaque continuation token or `null`;
- `limitations`: stable safe reason codes, never raw errors.

`total_events` is optional. It is present only when the reader can count valid projectable
source events authoritatively. `state: unavailable` requires `events: []`, a limitation reason,
and no invented start/end event.

Canonical limitation codes v1:

- `journal_missing`;
- `journal_unreadable`;
- `history_prefix_missing`;
- `history_gap_detected`;
- `timestamp_missing`;
- `payload_redacted`;
- `provenance_partial`;
- `projection_version_unsupported`.

Unknown limitation codes must render as “Certaines informations sont indisponibles”, never as
success.

### Large timelines

Default `timeline_limit` is 200; minimum 1, maximum 500. Continuation uses
`timeline_cursor` on the **same Mission detail route**. The first page starts at the earliest
valid sequence; subsequent pages continue strictly after the cursor. Cursor semantics are
opaque to WEB. `truncated: true` requires non-null `next_cursor`. Pages must not duplicate or
reorder events. Mission summary/status remains present on every detail response, so pagination
cannot hide the final mission state.

## 4. Event model

```json
{
  "event_id": "m-20260830T101500Z-a1b2c3d4:7",
  "position": 7,
  "source": {"kind": "journal", "sequence": 7},
  "time": {"state": "recorded", "timestamp": "2026-08-30T10:15:31Z"},
  "category": "execution",
  "kind": "provider_completed",
  "consequence": "completed",
  "visibility": "mission",
  "safe_summary": "Dependency analysis completed",
  "references": {
    "mission_id": "m-20260830T101500Z-a1b2c3d4",
    "run_id": "run-anonymized-01",
    "provider_id": "mcp-dependency-assessment"
  },
  "provenance": {},
  "data_state": "complete",
  "limitations": []
}
```

### Required fields

- `event_id`: deterministic `<mission_id>:<source-sequence>` for valid journal sequences;
- `position`: response ordering position, stable for the same valid journal prefix;
- `source`: allowlisted source kind and source sequence; no source path;
- `time`: explicit timestamp state;
- `category`: product grouping;
- `kind`: canonical event kind;
- `consequence`: consequence of this event, not Mission status;
- `visibility`: minimum disclosure tier;
- `safe_summary`: bounded, single-line, redacted human fallback;
- `references.mission_id`: stable owning mission;
- `data_state`: event projection completeness;
- `limitations`: safe reason codes.

### Timestamp

```json
{"state": "recorded", "timestamp": "2026-08-30T10:15:31Z"}
{"state": "unavailable"}
{"state": "redacted"}
```

`timestamp` is allowed only with `state: recorded`. Missing/malformed source time produces
`state: unavailable` and event limitation `timestamp_missing`; it never receives current time,
mission creation time, neighboring time, or file mtime.

### Enums

Categories:

- `mission`, `intent`, `plan`, `policy`, `execution`, `coverage`, `correlation`, `report`,
  `security`, `system`, `unknown`.

Consequences:

- `recorded`, `started`, `progress`, `completed`, `succeeded`, `refused`, `failed`, `skipped`,
  `unavailable`, `unknown`.

Visibility tiers:

- `summary`: immediately useful to understand the mission;
- `mission`: useful when opening mission details;
- `technical`: support/provenance detail, collapsed by default.

`visibility` is the minimum tier at which the event appears. It is not an authorization flag.
SECURITY redaction applies at every tier.

Data state:

- `complete`: all allowlisted fields for this event were available;
- `partial`: useful evidence exists but one or more expected fields are missing;
- `redacted`: at least one field was intentionally removed or transformed;
- `unavailable`: event existence is known but safe details are not available.

## 5. Deterministic ordering and identity

Projection algorithm:

1. Read valid JSON journal lines in append order.
2. Validate positive integer `seq` values.
3. Sort/project by `seq` ascending; timestamp never reorders events.
4. For duplicate sequence values, retain the **first physical valid line**, mark the timeline
   `partial` with `history_gap_detected`, and do not invent a replacement sequence.
5. For missing sequence values, retain later valid events in sequence order, mark `partial`
   with `history_gap_detected`.
6. Assign `position` by projected order starting at 1 across the full timeline, not per page.
7. Set `event_id = mission_id + ":" + seq`.
8. Two reads of the same journal prefix and projection version must produce byte-equivalent
   event identity/order (safe summary localization may be performed by WEB, not CORE).

A malformed line is not sent as payload. If the reader can continue, mark the timeline partial;
if it cannot safely establish ordering, return `state: unavailable`.

## 6. Projection registry for known source events

The registry is versioned code/config in the history reader, not a new persisted journal.
Payload fields not explicitly named below are discarded.

| Journal source kind | Timeline kind | Category | Consequence | Visibility | Allowlisted context |
|---|---|---|---|---|---|
| `ouverture` | `mission_created` | mission | recorded | summary | mission reference only; request/target already in summary |
| `confiance` | `trust_scope_recorded` | security | recorded | technical | profile label, target trust level after allowlist |
| `egress` | `network_scope_recorded` | security | recorded/refused | technical | requested/authorized booleans, safe profile label |
| intent decision event | `intent_resolved` | intent | completed/refused | summary | capability labels, safe reason code |
| `applicabilite` | `providers_filtered` | plan | skipped | mission | count and safe provider IDs; no raw path/glob reason |
| `conditions` | `provider_conditions_evaluated` | policy | unavailable/skipped | mission | count, safe reason codes |
| provider selection event | `providers_selected` | plan | completed | mission | capability labels, selected/omitted safe provider IDs |
| `plan` | `plan_created` | plan | completed | summary | `plan_id`, provider count; provider IDs at mission tier |
| explicit policy decision | `policy_decided` | policy | succeeded/refused | summary | allow boolean, stable safe reason codes |
| `contexte` | `execution_context_created` | execution | started | technical | `run_id`; digests only technical |
| `execution` | `provider_completed` | execution | completed/failed | mission | provider ID, wave, timeout, return-class, findings count |
| `statuts` | `coverage_updated` | coverage | progress/completed | mission | aggregate counts; detailed ledger stays in executions |
| `escalade` | `escalation_decided` | policy | completed/refused | mission | trigger count, allow, safe reason codes, optional plan ID |
| `cloture` | `mission_completed` | mission | succeeded | summary | authoritative finding/cluster counts, result digest technical |
| `arret` | `mission_stopped` | mission/policy/system | refused/failed | summary | stable classified reason and redacted safe summary |
| `reprise` | `mission_resumed` | mission | started | mission | no arbitrary payload |

The current branch proves `ouverture`, `confiance`, `egress`, `applicabilite`, `conditions`,
`plan`, `contexte`, `execution`, `statuts`, `escalade`, `cloture`, and `arret` in code; committed
legacy journals also contain `reprise`, test-only `test`, and older subsets. CORE-reported
intent/provider-selection events must be mapped by their actual stable source kind when merged;
the table does not authorize guessing their occurrence.

For `execution`, nonzero return or timeout may justify `failed`; code zero justifies
`completed`, not a claim that coverage was complete. Provider ledger status remains the
authority for `non_disponible`, `non_autorise`, and other provider states.

A finding/cluster/report artifact alone never creates a timeline event. It may be referenced
only by a journal event that already proves its production and time.

## 7. Mission status versus event consequence

History v1 remains authoritative for Mission status:

- `cloture` supports Mission `termine`; its timeline event is `mission_completed/succeeded`;
- classified policy/intent/condition `arret` supports Mission `refuse`; timeline explains why;
- classified technical `arret` supports Mission `erreur`; timeline event consequence is failed;
- a proven active owner supports `en_file`/`en_cours`; timeline only shows recorded events;
- missing terminal/current proof supports Mission `inconnu`; timeline is partial/unavailable.

A provider event `failed` does not automatically make the Mission `erreur`; another provider
may complete and coverage may be partial. A provider `non_disponible` does not become a Mission
status. An event `completed` is not equivalent to security success or zero findings.

## 8. Unknown events

Unknown source kinds are never silently discarded. Project exactly one event:

```json
{
  "category": "unknown",
  "kind": "unknown_event_recorded",
  "consequence": "recorded",
  "visibility": "technical",
  "safe_summary": "Un événement non reconnu a été consigné",
  "data_state": "unavailable",
  "limitations": ["projection_version_unsupported"]
}
```

The source kind may be exposed as `source.source_kind` only after validation against
`^[a-z0-9_.-]{1,64}$`. No other payload key/value is copied. Unknown terminal-looking events
must also set timeline state `partial`; WEB shows an “information incomplete” warning and does
not reinterpret Mission status.

## 9. Safe provenance contract

Provenance remains additive on timeline events and normalized findings/executions. Missing
provenance is omitted and represented by `data_state: partial` plus `provenance_partial` only
when provenance was expected. Never default missing `provider_kind` to local/trusted.

### Visibility matrix

| Field | History list | Mission business detail | Technical detail | Required transformation / rationale |
|---|---|---|---|---|
| `provider_id` | No; aggregate count only | Yes as approved display label | Yes | Validate stable ID; raw ID collapsed behind capability in business view |
| `provider_kind` | Aggregate `kinds` only | Yes when external/MCP affects interpretation | Yes | Map enum to “Local”, “External”, “MCP”; absence = unavailable |
| `transport` | No | No | Yes | Allowlisted enum/name only; never endpoint/configuration |
| `server_id` | No | No | Yes when useful for support | Stable opaque/approved ID; pseudonymize tenant/host-derived values |
| `tool_id` | No | Approved display label only | Yes | Validate ID; do not expose arbitrary remote tool description |
| `protocol` | No | No | Yes | Allowlisted protocol name and bounded version only |
| `confidence` | No | Yes when it changes interpretation | Yes | Map documented enum/score to plain-language explanation; never invent |
| `availability` | No | Yes when it limits coverage | Yes | Render separately from Mission status; use declared provider status |
| `request_id` | No | No | Support detail only | Opaque, bounded, optionally hashed; never linkable credential/session ID |
| `correlation_id` | No | No | Support detail only | Opaque, bounded, optionally hashed; not a Finding cluster ID |

`provider_id`, `server_id`, `tool_id`, `request_id`, and `correlation_id` must match a bounded
safe identifier grammar or be omitted/hashed. The API must not expose values derived directly
from a URL, filesystem path, hostname containing tenant data, username, or credential.

### Provenance shape

```json
{
  "provider_id": "mcp-dependency-assessment",
  "provider_kind": "mcp",
  "transport": "stdio",
  "server_id": "security-tools",
  "tool_id": "scan_repository",
  "protocol": {"name": "mcp", "version": "2025-11-25"},
  "confidence": {"level": "medium", "basis": "provider_declared"},
  "availability": "available",
  "request_id": "req-support-7f19",
  "correlation_id": "corr-support-22ab"
}
```

Allowed provider kinds: `local`, `mcp`, `external`. Transport/protocol vocabularies are
additive but values must be allowlisted by MCP/SECURITY before exposure. Confidence levels v1:
`low`, `medium`, `high`, `unknown`; `basis` is required when confidence exists and is one of
`provider_declared`, `agnt_assessed`, `corroborated`, `unknown`. Provider-declared confidence
must never be presented as AGNT verification.

Availability is distinct from confidence and Mission/event status. Recommended values:
`available`, `degraded`, `unavailable`, `unknown`. A partial MCP provenance object is preserved
with only validated fields; absent fields are not synthesized.

### Never exposed

At every visibility tier, reject or redact:

- endpoint/URL/URI/socket address and URL userinfo;
- token, credential, password, cookie, authorization or arbitrary headers;
- argv/command, environment variables, local paths, mount paths;
- raw MCP request/response, raw provider output/stderr;
- stack trace, exception repr, policy input, unbounded diagnostic text;
- remote metadata not explicitly allowlisted by this contract.

Redaction must happen before serialization, not only in WEB. WEB still renders every string as
text, never markup.

## 10. Safe summaries and reason codes

CORE should emit structured facts and stable reason codes; it should not build rich localized
copy. Known `kind` and reason codes are mapped by WEB to human labels. `safe_summary` is a
single-line fallback, maximum 240 Unicode code points after control-character removal and
redaction.

Useful summary examples:

- “Mission créée”;
- “Plan créé avec 4 capacités”;
- “Analyse des dépendances terminée”;
- “Mission refusée par la politique”;
- “Couverture incomplète : un provider indisponible”.

Forbidden summaries include raw exception messages, target paths, command lines, endpoints,
provider payload excerpts, secrets, or “aucun problème” inferred from missing data.

## 11. Required edge-state behavior

### Mission refused before Run

Timeline may contain creation, trust/network scope, intent/plan/policy evidence, then stop. It
MUST omit `run_id`, execution start, provider completion, correlation, and report events unless
those events independently exist. Mission status is `refuse`, not `termine` or `erreur` unless
the classified stop says technical failure.

### Mission in progress

Return the valid journal prefix with `state: complete` relative to that prefix and Mission
status `en_cours` only while current ownership is proven. New reads may append events; existing
event IDs/order cannot change. Do not insert placeholder future steps.

### Only terminal events available

Return them in source order, set `state: partial`, add `history_prefix_missing`, and show an
incomplete-history warning. Do not synthesize mission creation or execution steps.

### Partial MCP provenance

Keep only validated present fields. Mark the affected event `partial` with
`provenance_partial` when provenance is expected. Do not label the provider local, trusted, or
available by default.

### Redacted artifacts

Keep the event if its occurrence is safe and proven; set `data_state: redacted` and
`payload_redacted`. Explain that details were withheld. Do not expose hashes of low-entropy
secrets as a substitute.

### Missing journal

Return `timeline.state: unavailable`, `events: []`, `limitations: ["journal_missing"]` and add
`events` to history v1 `missing_artifacts`. The Mission detail may still show independently
proven normalized artifacts, but WEB must not invent their chronology.

## 12. Acceptance criteria by builder

### CORE

1. Project `data.timeline` from the canonical mission journal reader on
   `GET /api/missions/{mission_id}`; no persisted second timeline.
2. Preserve sequence ordering and deterministic event IDs; never order by timestamp alone.
3. Apply the allowlist projection registry and serialization-time redaction.
4. Expose completeness, truncation, cursors, and limitations exactly as defined.
5. Do not synthesize finding/correlation/report events from files.
6. Keep history v1 Mission status mapping unchanged.
7. Add structured event classification/reason codes to future journal entries additively;
   continue reading legacy events.

### WEB

1. Prefer `data.timeline`, fall back to legacy `data.events`, never merge both.
2. Render summary-tier events first; mission and technical tiers progressively disclosed.
3. Use array order/position, not client-side timestamp sorting.
4. Render missing timestamp as unavailable and never substitute browser time.
5. Show partial/truncated/redacted warnings and continuation affordance.
6. Treat unknown event kinds generically and visibly; never render arbitrary payload/HTML.
7. Keep provider failure/availability separate from Mission status and zero findings.

### MCP

1. Attach provenance additively using validated fields; do not replace normalized Finding or
   execution models.
2. Distinguish provider-declared confidence from AGNT-assessed/corroborated confidence.
3. Never place endpoints, auth material, raw request/response, headers, environment, or stack
   traces in exposed provenance.
4. Supply stable safe IDs or allow them to be omitted/pseudonymized.
5. Do not use `correlation_id` as a Finding cluster identity.

### SECURITY

1. Approve identifier grammar and transport/protocol allowlists before exposure.
2. Enforce redaction server-side for event summaries, references, provenance, and errors.
3. Reject unsafe unknown payloads rather than passing them through.
4. Verify pagination cursors disclose no path, tenant, timestamp internals, or credentials.
5. Test URL userinfo, control characters, secret material, path traversal, oversized values,
   malformed journal lines, duplicate/gapped sequences, and hostile MCP metadata.

## 13. Out of scope

- Timeline UI, animation, charts, or frontend state store.
- Separate timeline endpoint or event database.
- Live streaming/WebSocket/SSE.
- Cross-mission timeline or comparison.
- Full raw journal, provider logs, or artifact downloads.
- Inference of unrecorded phases.
- New CORE/MCP journal events, pipeline changes, or Finding model changes.
- Authorization, multi-tenant retention, and support-role access policy.
