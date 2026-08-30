# AGNT Product/API Conformance Gate

Black-box, read-only validator for `agnt.history.v1`, `agnt.timeline.v1`, and
`agnt.execution-status.v1`. It uses only the Python standard library and does not import the
AGNT backend.

## Run against a real API

```sh
python3 docs/coordination/api-conformance-gate/product_api_gate.py \
  --base-url http://127.0.0.1:8141

# equivalent
AGNT_API_BASE_URL=http://127.0.0.1:8141 \
  python3 docs/coordination/api-conformance-gate/product_api_gate.py
```

Optional:

```sh
# Prove that a known transient submission ID is not used as a persistent mission_id
--submission-id <id-returned-by-POST-api-runs>

# Validate fewer details / expose every passing assertion
--max-details 10 --verbose
```

The live gate performs GET requests only. It checks the default list, `limit=1`, one observed
status filter, one observed target-type filter, an invalid status filter, cursor continuation
when available, and up to 25 Mission details. It never creates or modifies a Mission.

## Run against captured real responses

```sh
python3 docs/coordination/api-conformance-gate/product_api_gate.py \
  --capture /path/to/capture-manifest.json
```

Capture manifest format:

```json
{
  "submission_id": "optional-transient-id",
  "responses": [
    {
      "role": "list",
      "path": "/api/missions?limit=25",
      "status": 200,
      "body_file": "list.json"
    },
    {
      "role": "detail",
      "path": "/api/missions/m-...",
      "status": 200,
      "body_file": "detail.json"
    },
    {
      "role": "empty_list",
      "path": "/api/missions?status=en_cours",
      "status": 200,
      "body": {
        "schema_version": "agnt.history.v1",
        "items": [],
        "page": {"limit": 25, "next_cursor": null}
      }
    }
  ]
}
```

`body_file` must remain inside the manifest directory. Captures from a real API must not use
`--fixture-mode` and therefore fail if `$fixture` or demo markers are present.

## Fixture validation versus real validation

The anonymized example is contract/test data, not API output:

```sh
python3 docs/coordination/api-conformance-gate/product_api_gate.py \
  --capture docs/coordination/api-conformance-gate/examples/anonymized-capture/capture-manifest.json \
  --fixture-mode
```

`--fixture-mode` only permits explicit fixture markers. Never use it as evidence that a real API
does not expose demo data. Real validation tests HTTP status, query behavior and captured/live
payloads. Fixture validation proves the gate and expected shapes, not the CORE endpoint.

## Cases and exit codes

Validated invariants include:

- HTTP 200 empty list with `items: []`;
- persistent `mission_id`, optional distinct transient submission ID;
- filters, limits, ordering and cursor pagination;
- no fixture/demo markers in real responses;
- canonical Mission status;
- strictly ordered timeline journal sequences and deterministic event IDs;
- independent legacy `data.events` and `data.timeline` counts (the gate never merges them);
- separate provider decision, availability, execution, detection and completeness dimensions;
- timeout, cancellation, failure, unavailability, refusal and non-applicability remain distinct;
- zero findings only with complete `rien_trouve` proof;
- logical `missing_artifacts` without fabricated data/counts;
- allowlisted MCP provenance;
- no sensitive paths, credentials, endpoints/configuration, argv, raw payload, private key,
  stack trace, credential URL or active markup.

Exit codes:

- `0`: every observed response conforms;
- `1`: contract violation, malformed capture, transport failure, or non-JSON response;
- `2`: no violation, but `--require-full-coverage` requested cases not present in the dataset.

A single live environment may not naturally contain every semantic case. Use captured responses
from controlled CORE integration tests and `--require-full-coverage` to gate the complete case
matrix (`empty_list`, zero proved, findings, unavailable, non-applicable, refusal, timeout,
cancellation, failure, incomplete, unknown, MCP provenance, and submission-ID distinction).
