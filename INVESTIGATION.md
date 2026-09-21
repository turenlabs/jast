# Investigation Contract

JAST 0.4 investigations do not replace, dismiss or modify original findings.
They are new, consented model assessments using only source already stored in
the same scan. No live filesystem retrieval, repository execution, invented
paths or external tools. Maximum three inference rounds (transport retries may
add requests). No automatic resume after interruption: start a new investigation.

New IPC (argument keys camelCase):
- `start_investigation({findingId, consent})` -> Investigation
- `get_investigation({investigationId})` -> Investigation
- `list_investigations({findingId})` -> Investigation[] newest first
- `get_active_investigation()` -> Investigation | null
- `cancel_investigation({investigationId})` -> null

Investigation:
```
{
  id: string, scan_id: string, finding_id: string,
  status: "running" | "completed" | "cancelled" | "interrupted" | "failed",
  outcome: "model_supported" | "model_not_supported" | "unresolved" | null,
  created_at: number, max_rounds: 3, error: string | null,
  steps: [{round:number, request_sha256:string, request_json:string,
           response_json:string, action:string, claim_supported:number,
           evidence_sufficient:number, action_confidence:number}],
  plan: {target: {finding_id:string,category:string,label:string,chunk:Chunk},
         candidates: Context[], warnings:string[]}
}
```

Chunk has existing id/path/start_line/end_line/code/request_json/request_sha256.
Context has id/source_chunk_id/path/start_line/end_line/code/request_sha256.
Context IDs are selected by a Choice question; Rust maps them to fixed snippets.
Candidate matching is lexical, not a proven call graph. Snippets may be partial.
The plan is frozen at start; every validated completed round stores exact
request/response and hash. HTTP/schema failures are reported as errors rather
than fabricated successful decisions.

Allowed actions: `read:<context-id>`, `stop_supported`, `stop_not_supported`,
`stop_unresolved`. Reads are absent in round 3. Round 1 also asks one
`relevance:<context-id>` Noul per catalogue candidate; later rounds offer
`read:` only for excerpts whose relevance was >=0.35 (all remain eligible when
no assessment exists). A `read:` or terminal stop chosen with
action_confidence <0.35 resolves as `unresolved` rather than spending evidence
budget or asserting a verdict the model itself is unsure about. A supporting
stopping choice also requires support >=0.8 and sufficient-evidence >=0.8; a
rejecting stopping choice requires support <=0.2 and sufficient-evidence >=0.8.
Otherwise outcome unresolved. These are explicit routing policies, not
calibrated truth guarantees. All terminal model assessments are unverified,
never "confirmed" or "safe".

Only one scan OR investigation runs at a time. Native guards are authoritative.
The UI must poll the active investigation even after changing candidate/page,
show a global progress/cancel control, require a new unchecked consent box for
each selected candidate, and expose prior runs and evidence/response traces.
The key remains in OS keychain. In-flight calls may finish after cancellation.
Budget exhaustion or lack of useful context means unresolved, not a negative.
