# AGNT Mission History API — Product Contract v1

Status: **implementation contract** · Version: `1.0` · Owner: Product/UX  
Scope: persistent mission history and mission detail. This is not an implementation and does not activate the UI.

## 1. Decision: Mission versus Run

### Canonical model today

A **Mission** is the user-visible, persisted record created from one request and one target. A
**Run** is the technical execution inside that mission.

Current cardinality is deliberately minimal:

```text
Mission 1 ── 0..1 Run
```

A mission can have no run because intent, applicability, conditions, or policy may stop it
before an execution context and `run_id` exist. A successful execution has exactly one
`run_id`. **A rerun creates a new Mission today.** Do not introduce a `runs[]` aggregate or a
long-lived “project mission” until the engine actually supports multiple runs per mission.
Future comparison compares two `mission_id` values and may use their technical `run_id` and
digests; it does not require changing this v1 model.

Related objects:

- **Result**: the immutable output of the run when it exists; identified technically by
  `result_digest` when available.
- **Finding**: a normalized observation belonging to one mission result.
- **Cluster**: a correlation of finding IDs from that same result.
- **Report**: a rendered view derived from the result; its availability is factual artifact
  metadata, not proof that the mission succeeded.
- **Event / journal**: append-only evidence of mission lifecycle and decisions. The journal is
  the lifecycle source of truth.
- **Provider / provenance**: contributor and origin metadata attached to executions/findings;
  it is not the primary navigation model.

### Identifiers

| Identifier | Meaning | Product visibility |
|---|---|---|
| `mission_id` | Stable persisted ID (`m-…`) | **Primary URL and visible reference** |
| API submission `id` from `POST /api/runs` | Transient in-memory job/polling ID | Temporary while launching only |
| `run_id` | Technical execution context ID | Detail → technical provenance |
| `plan_id` | Deterministic plan identity | Detail → technical provenance |
| `result_digest` | Result integrity/comparison key | Detail → technical provenance |
| `input_digest` / execution context digest | Reproducibility keys | Advanced detail only |

The submission ID must never be relabeled as a persistent mission ID. `mission_id` remains
valid after an API restart; the submission ID does not.

## 2. Source of truth and persistence

The backend MUST project history from the existing persisted mission directory, header,
append-only journal, and run/result artifacts. It MUST NOT create an independent Mission or
Run database as a second authority.

An optional index/cache is allowed only when it is completely rebuildable from mission
artifacts and journal entries. Filesystem storage paths are implementation details and are
never API identifiers.

Observed sources on this branch:

- `<missions>/<mission_id>/mission.json`: `mission_id`, creation time, request, target;
- `<missions>/<mission_id>/journal.jsonl`: ordered lifecycle, plan, context, execution,
  stop/close and provider status events;
- mission result directory: plan, run, findings, clusters, report, intent and context.

CORE has separately reported migration of result artifacts to `<mission>/run`; the endpoint
implementation should use CORE's canonical mission reader rather than hard-code either the
older `sortie` directory or the newer `run` directory.

### Immutability

- `mission.json` identity/header and existing journal lines are immutable.
- The journal is append-only; the list summary is a **projection** and may change while events
  and artifacts are appended.
- Once a terminal event is present, the execution result and counts are immutable. Later
  redaction/index versions may change presentation, not the recorded result.
- A process restart must not leave a persisted item claiming `en_cours` unless the backend can
  prove that the same worker still owns it. Otherwise return `inconnu` and `incomplete: true`.

## 3. User journey and progressive disclosure

```text
History list
  mission ID · safe request title · safe target · status · dates · trustworthy counts
    ↓ GET /api/missions/{mission_id}
Mission summary
    ↓
Findings and clusters / report
    ↓
Coverage and provider execution states
    ↓
Sanitized provenance and journal events
```

List rows never contain finding evidence, report bodies, raw error output, local paths,
commands, endpoints, or credentials.

## 4. Why `/api/missions`

`POST /api/runs` and `GET /api/runs/<id>` already represent an active, transient submission
and use an in-memory polling ID. A persisted mission can exist with **zero** runs. Changing the
meaning of `<id>` on the existing route would make restart behavior ambiguous and break
compatibility.

Therefore v1 adds:

- `GET /api/missions` — persisted history;
- `GET /api/missions/{mission_id}` — persisted detail.

Existing routes remain unchanged:

- `POST /api/runs` starts work;
- `GET /api/runs/{submission_id}` polls that submission;
- once known, polling SHOULD add `mission_id` and `detail_href` without removing existing
  fields: `"detail_href": "/api/missions/m-…"`.

No `GET /api/runs` listing is defined in v1. It would list a mixture of transient jobs and
persisted missions and would incorrectly exclude stopped-before-run missions.

## 5. `GET /api/missions` listing

### Request

```http
GET /api/missions?limit=25&cursor=<opaque>&status=termine&target_type=repository
```

- `limit`: default 25, minimum 1, maximum 100.
- `cursor`: opaque server token. Clients MUST NOT parse it.
- `status`: optional, one canonical mission status from section 7; repeatable or
  comma-separated is an implementation choice that must be documented consistently.
- `target_type`: optional canonical target type once supplied by CORE's target descriptor.
- No free-text search, severity filter, date range, or provider filter in v1.

### Ordering and response

Stable order is `created_at DESC, mission_id DESC`. The cursor must preserve that ordering.
New missions may appear before page one; already-returned cursor pages must not duplicate
items.

```json
{
  "schema_version": "agnt.history.v1",
  "items": ["MissionSummary"],
  "page": {
    "limit": 25,
    "next_cursor": "opaque-or-null"
  }
}
```

`items: []` with HTTP 200 is the only empty-history response. It means “connected, no persisted
missions”, not offline and not a failure. API errors use the standard error envelope in
section 10 and must never be replaced with fixtures.

### `MissionSummary`

Required fields:

```json
{
  "mission_id": "m-20260830T101500Z-a1b2c3d4",
  "detail_href": "/api/missions/m-20260830T101500Z-a1b2c3d4",
  "request": {"title": "Analyse les risques importants de ce dépôt"},
  "target": {"type": "repository", "display_name": "acme-service"},
  "status": "termine",
  "created_at": "2026-08-30T10:15:00Z",
  "updated_at": "2026-08-30T10:16:42Z",
  "artifacts": {
    "detail": true,
    "findings": true,
    "clusters": true,
    "report": true
  }
}
```

Optional only when authoritative:

- `started_at`, `completed_at`, `duration_ms`;
- `run_id` (secondary; omit for stopped-before-run missions);
- `findings_summary: {total, by_severity}` only after a readable findings artifact exists;
- `clusters_count` only after a readable clusters artifact exists;
- `contributors: {count, kinds}` as a safe synthesis (`local`, `mcp`, `external`), not names or
  endpoints;
- `incomplete: true` and `incomplete_reason` when persisted evidence is insufficient.

A real analyzed result with zero findings may return `total: 0`. A missing or unreadable
findings artifact MUST omit `findings_summary`; it must not return zero.

`request.title` is a length-bounded, control-character-free display projection of the actual
request. It must not contain generated marketing text. `target` must reuse CORE's canonical
safe target descriptor when available; until then it may expose only an admitted display name
and type, never the absolute path.

## 6. `GET /api/missions/{mission_id}` detail

### Response

```json
{
  "schema_version": "agnt.history.v1",
  "mission": {"...": "MissionSummary plus technical IDs when available"},
  "data": {
    "request": {"original": "...", "canonical": "..."},
    "intent": {},
    "plan": {},
    "findings": [],
    "clusters": {},
    "report": {"available": true, "format": "markdown", "content": "..."},
    "coverage": {},
    "executions": [],
    "events": []
  },
  "missing_artifacts": []
}
```

The detail is an API projection of the same artifacts already consumed by the current Mission
view. CORE may adapt existing `_charger`/canonical readers; it must not recompute findings or
clusters. Fields under `data` are optional by artifact availability:

- `findings` is present only if `findings.json` was read successfully. It may legitimately be
  `[]` after a completed analysis.
- `clusters` is present only if cluster output exists and was read successfully.
- `report` is present only from a retained safe report artifact.
- `coverage` and `executions` come from archived status/coverage evidence.
- `events` is a sanitized, ordered projection of the journal; raw journal payload is not sent.
- `request.original` means the closest **redacted, display-safe** representation retained by
  the API; it is not permission to return the mission header verbatim when it contains a
  credential. `request.canonical` follows the same rule.
- `missing_artifacts` explicitly names expected but absent/unreadable artifacts using stable
  logical names such as `findings`, `clusters`, `report`, `run`. It never includes paths.

For in-progress missions, the endpoint may return partial fields with `status: en_cours`.
Clients must replace/update the projection on later responses, not merge counts heuristically.

### Sanitized events

Each event may expose only:

```json
{
  "sequence": 7,
  "timestamp": "2026-08-30T10:15:31Z",
  "kind": "provider_completed",
  "status": "execute",
  "capability": "Dependency analysis",
  "provider": {"id": "provider-safe-id", "display_name": "Dependency scanner"},
  "safe_message": "Analysis completed"
}
```

`sequence`, `timestamp`, and `kind` are required. The remaining fields are optional. Full raw
journal delivery, complete timeline taxonomy, argv, environment, policy input, stack traces,
and raw tool output are out of scope.

## 7. Canonical lifecycle statuses

The API uses the existing backend vocabulary; WEB maps it to localized labels.

| API status | Guaranteed meaning | Product label |
|---|---|---|
| `en_file` | Submission accepted and known to the current queue | En attente |
| `en_cours` | Current process can prove work is active | En cours |
| `termine` | Terminal close event/result completed | Terminée |
| `refuse` | Explicit intent/policy/condition decision stopped execution | Refusée |
| `erreur` | Explicit technical failure was recorded | Échec |
| `inconnu` | Persistence is incomplete or cannot prove a terminal/current state | État inconnu |

`indisponible` is **not** a mission lifecycle status in v1. It is either:

- an HTTP/API availability state handled by WEB; or
- a provider execution status (`non_disponible`) inside mission detail.

Provider statuses remain those emitted by the engine (`selectionne`, `execute`, `echoue`,
`non_disponible`, `non_autorise`, `non_applicable`, `non_selectionne`). They must not be
collapsed into “zero findings”.

Status projection precedence: explicit terminal journal event > proven current in-memory owner
> incomplete/unknown. Never infer `termine` from report or findings file existence alone.

Implementable journal mapping for legacy artifacts:

1. latest valid terminal event `cloture` → `termine`;
2. latest `arret` with motif `intent_*`, `conditions`, `applicabilite`, `policy`, or
   `policy_injoignable` → `refuse` (the latter is the existing fail-closed behavior);
3. latest `arret` carrying an `erreur` outside those known fail-closed motifs → `erreur`;
4. no terminal event + a currently owned submission correlated to this `mission_id` → its
   proven `en_file`/`en_cours` state;
5. otherwise → `inconnu` with `incomplete: true`.

CORE should add a structured terminal classification to future journal events rather than
extend motif-string parsing. That addition is evidence in the same journal, not a second state
store. Readers must retain the legacy mapping above.

## 8. Dates

All dates use RFC 3339 UTC (`Z` preferred):

- `created_at`: mission header creation time;
- `started_at`: first proven execution start/context event; omit if no run started;
- `completed_at`: terminal close/stop/error timestamp; omit if nonterminal/unknown;
- `updated_at`: timestamp of the latest valid journal event;
- `duration_ms`: only when authoritative start and terminal timestamps both exist.

Do not use directory modification time as a business timestamp. It may be used internally to
optimize scanning only after validating the artifact content.

## 9. Provenance, including MCP

Provenance is additive under a finding `source.provenance` and/or an execution
`provenance`. Existing normalized finding IDs and `source.tool` remain valid.

```json
{
  "provider_id": "mcp-sast",
  "provider_kind": "mcp",
  "transport": "stdio",
  "server_id": "security-tools",
  "tool_id": "scan_repository",
  "confidence": "high",
  "availability": "available"
}
```

Visibility:

- **List**: only optional aggregate contributor count/kinds.
- **Mission result**: provider/tool display name and contribution.
- **Technical detail**: IDs, provider kind, transport, server ID, confidence, availability.
- **Never expose**: server URL containing credentials, auth/header values, tokens, raw MCP
  request/response, environment variables, local command/argv, or unredacted error payload.

All provenance keys are optional and additive because local providers may not produce MCP
metadata. Absence means “not recorded”, never “local” or “trusted”. MCP should preserve the
normalized finding's current source fields and attach provenance rather than create a second
finding representation.

## 10. Truth, privacy, and redaction

### Mandatory response rules

- Never return secrets, tokens, credentials, cookies, authorization headers, private keys, or
  unredacted secret evidence in list/detail previews.
- Strip URL userinfo and sensitive query parameters; list responses should prefer a safe host
  label rather than a full URL.
- Never return absolute local paths. Return a safe target display name and relative finding
  locations only after traversal/control-character checks.
- Bound request titles and safe messages; remove control characters and line breaks from list
  fields. Never render raw content as HTML.
- Return stable safe error codes plus redacted messages. Stack traces, exception repr, policy
  input, filesystem layout, and raw provider stderr are excluded.
- Artifact names in `missing_artifacts` are logical allowlisted values, never filenames supplied
  by tools.
- Existing artifact redaction remains the authority. The history API must not bypass it by
  reopening raw outputs.

Suggested error envelope:

```json
{
  "error": {
    "code": "MISSION_NOT_FOUND",
    "message": "Mission introuvable"
  }
}
```

Expected HTTP statuses: 400 invalid cursor/filter, 404 unknown mission, 409 mission artifacts
currently inconsistent/retryable, 500 redacted server failure, 503 service unavailable.

### Demo and empty states

- Fixtures in `docs/coordination/fixtures/` are contract test data and MUST NEVER be used as
  automatic product fallback.
- API reachable + `items: []` → real empty state inviting the first mission.
- Loading → skeleton/progress, preserving previous truthful state if appropriate.
- API error → contextual error with retry; do not substitute zero counts.
- Network/offline → explicit offline state. Existing separately labeled demo mode may be shown
  only when the API is genuinely unavailable and must never appear as history.
- Missing field/artifact → “not recorded / result incomplete”; never zero or “no issue”.

## 11. Retention boundary

Retained now: mission header, append-only journal, normalized/sanitized result artifacts,
reports, and approved provenance according to the existing artifact retention policy.

Listed: safe summary projections only. Consultable in detail: normalized findings, clusters,
safe report, coverage, execution states, sanitized event/provenance projections. Raw outputs
remain inaccessible through this v1 history API.

Not decided in v1: deletion endpoint, retention duration/quotas, legal hold, per-user ownership,
multi-tenant access, export permissions, and authentication. WEB must not promise delete,
sharing, or indefinite retention. Before non-local/multi-user deployment, SECURITY must define
authorization and tenant isolation.

## 12. Field mapping

| Product concept | Artifact/source | API field |
|---|---|---|
| Mission reference | `mission.json.mission_id` | `mission_id` |
| Request | mission header / intent | `request.title`; detail `request.original/canonical` |
| Target | canonical target descriptor; legacy admitted target | `target.type/display_name` |
| Created | mission header `cree_le` | `created_at` |
| Updated / lifecycle | latest valid journal line | `updated_at`, `status` |
| Technical execution | context/run artifact | optional `run_id`, technical detail |
| Finding count/severity | readable normalized findings artifact | optional `findings_summary` |
| Clusters | readable clusters artifact | optional `clusters_count`, detail `clusters` |
| Report availability | retained report existence | `artifacts.report`, detail `report` |
| Coverage/provider state | archived report/status ledger | detail `coverage`, `executions` |
| Timeline seed | sanitized journal projection | detail `events` |
| MCP provenance | normalized source/provenance supplied by MCP | detail provenance; aggregate list only |

## 13. Acceptance criteria for CORE

1. `GET /api/missions` enumerates persisted mission sources, not process memory, with stable
   ordering and cursor pagination.
2. `GET /api/missions/{mission_id}` survives restart and reads the canonical mission/artifact
   layout without duplicating engine models.
3. A mission stopped before execution is listed without `run_id` and with an evidence-backed
   status.
4. Missing findings never produces `findings_summary.total: 0`; a real empty findings artifact
   may produce zero.
5. Polling responses add `mission_id`/`detail_href` once known while preserving current fields.
6. Absolute storage paths, raw outputs, stack traces, credentials, and unredacted evidence do
   not appear in either endpoint.
7. Journal prefix remains append-only; any cache/index is rebuildable.
8. Fixture contract tests pass, including ID consistency, lifecycle vocabulary, count
   consistency, and forbidden-data checks.

## 14. Acceptance criteria for WEB

1. History consumes only `GET /api/missions`; it does not scan local storage, artifacts, or
   browser fixtures.
2. Row links use `detail_href`/`mission_id`, never transient submission IDs.
3. Required states exist: loading, real empty, loaded, partial/incomplete, API error, offline.
4. Optional counts are omitted or labeled unknown when absent; they are never defaulted to zero.
5. Status labels map only the canonical statuses in section 7; unknown values render as unknown,
   never success.
6. Detail progressively reveals summary → results → execution → provenance/events.
7. `missing_artifacts` produces a coverage/incomplete warning, not “no findings”.
8. All target/request/provider strings are rendered as text, never trusted markup.
9. Contract fixtures are used only in tests/development with an unmistakable fixture marker.

## 15. Out of scope / deferred

- Run comparison UI and diff semantics.
- Advanced search and filtering.
- Complete event taxonomy and full timeline visualization.
- Global Findings, Clusters, and Reports views.
- Artifact download/raw-output endpoints.
- Multi-run Mission aggregation.
- Deletion, retention administration, authentication, and multi-user authorization.
