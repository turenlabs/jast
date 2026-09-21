# JAST Native Contract

All JSON uses snake_case. Invoke command argument keys use camelCase per Tauri default.
Native commands return values below or reject with safe user-facing error strings.

- `get_settings()` -> Settings
- `set_threshold({threshold: number})` -> Settings — persists the candidate
  probability cutoff in [0,1]; rejected while a scan or investigation runs.
  Applies to scans started afterward; each scan row records the value it ran
  with and resumes keep it.
- `remove_api_key()` -> Settings
- `select_repository({excludedPatterns: string[]})` -> Preview | null (native directory picker; null means cancelled)
- `start_scan({previewId: string, consent: boolean})` -> ScanSummary
- `list_scans()` -> ScanSummary[] (newest first)
- `get_scan({scanId: string})` -> {scan: ScanSummary, findings: Finding[]}
- `get_evidence({scanId: string, chunkId: string})` -> Evidence
- `get_file_view({scanId: string, path: string})` -> FileView (all recorded regions for one file in a scan)
- `get_preview_evidence({previewId: string, chunkId: string})` -> Evidence (response_json=null)
- `cancel_scan({scanId: string})` -> null
- `resume_scan({scanId: string, consent: boolean})` -> ScanSummary
- `set_dismissed({findingId: string, dismissed: boolean})` -> null
- `export_scan({scanId: string})` -> string | null (native save dialog, exports JSON)

v0.4 also exposes explicit snapshot-only candidate investigation commands. Their
types, actions, consent and terminal-state semantics are specified in
[`INVESTIGATION.md`](INVESTIGATION.md). Scan exports include an `investigations`
array with plans and validated completed-round traces. Original scan scores and
dismissal state remain independent.

Settings: {key_configured:boolean, key_error:string|null, model:string, threshold:number,
check_count:number, supported_languages:string[], privacy_notice:string}

Preview: {id:string, repo_name:string, repo_path:string, files:number, chunks:number,
bytes:number, estimated_tokens:number, exclusions: {path:string,reason:string}[],
excluded_count:number, unsupported_count:number, checks:string[], warnings:string[],
limit_reached:boolean, limit_reasons:string[], exclusion_reasons:Record<string,number>,
languages:{language:string,files:number,chunks:number,check_count:number}[],
regions:{id:string,path:string,start_line:number,end_line:number,language:string,check_count:number}[],
context_files:number}

ScanSummary: {id:string, repo_name:string, repo_path:string,
status:"running"|"completed"|"cancelled"|"interrupted"|"failed",
total:number, completed:number, cached:number, findings:number, created_at:number,
error:string|null, coverage:Coverage|null, uncertain_regions:number,
threshold:number|null}

Coverage: {included_files:number, planned_regions:number, excluded_count:number,
unsupported_count:number, limit_reached:boolean, limit_reasons:string[],
exclusion_reasons:Record<string,number>, exclusions:{path:string,reason:string}[],
warnings:string[], context_policy:string, context_files:number}

Finding: {id:string, chunk_id:string, path:string, language:string, start_line:number, end_line:number,
category:string, label:string, severity:"high"|"medium"|"low", probability:number,
context_missing:number, sink:string|null, source:string|null, impact:number|null,
priority:number, duplicate_of:string|null, dismissed:boolean}

Evidence: {path:string,language:string,start_line:number,end_line:number,code:string,
request_json:string,response_json:string|null}

FileView: {path:string, language:string, regions:{id:string, start_line:number,
end_line:number, code:string, status:string, cache_hit:boolean}[]}
- regions are the immutable snapshot chunks for that path in the given scan,
  ordered by line range. status is "ok" once a validated response is committed;
  anything else is unreviewed (pending/queued). code is snapshot source only.

Notes:
- created_at is Unix seconds. total/completed count chunks, not files or checks.
- completed is completion of planned jobs, never proof of full repository coverage.
- coverage is persisted at consent for v0.3 onward. Older records retain null
  coverage (unknown); do not infer coverage from region counts or fill defaults.
- threshold on ScanSummary is the candidate cutoff recorded when the scan was
  created; null means the scan predates the setting and ran the fixed 0.5.
- uncertain_regions counts completed regions whose model context_missing >= 0.5,
  even if there are no candidate findings. It is not an objective completeness test.
- start_line/end_line delimit reviewed region, NOT a proven exact vulnerable line.
- Findings are probabilities >= the scan's recorded threshold; severity is a static check classification,
  NOT evidence of exploitability. Missing context is separate from probability.
- sink/source name model-selected call-site identifiers in the region, or null
  (none_visible or not asked). impact is the model's 0-3 level score, or null
  for requests that predate the question. priority = probability x (impact/3,
  or 0.5 when absent) x (1 - context_missing): a composite ordering weight, not
  a truth score. duplicate_of links a candidate to the higher-priority finding
  on the same file+category whose line range overlaps; it is an overlap hint,
  not a proven-duplicate claim. All four are null for pre-v0.5 findings.
- v0.4 supports Java, Python, Go, JavaScript, TypeScript, PHP, Rust, Ruby.
- Settings.check_count is the total unique catalogue, not checks per region.
- Preview.checks is the union of selected language packs; per-language/region
  check_count gives the actual number run on each region. Every check in that
  language's pack is run. Unsupported files are counted.
- Saved requests are immutable. Resuming older Java scans retains their original
  eleven checks; new Java scans use the expanded pack. No SQLite migration.
- Poll get_scan/list_scans every 1.5-2 seconds only while a scan is running.
- User must explicitly consent before start AND resume. Preview is an immutable
  snapshot held by Rust. In-flight API request may finish after cancellation.
- API key goes to OS keychain. No localStorage/sessionStorage or logging of key.
- No browser mock results presented as real. Browser mode may show initial shell
  with a clear desktop-required message; tests can inject Tauri IPC mocks.
- Code and metadata go to TypeSafe, not offline. No repository code execution.
- Commands accept only IDs except native directory/save dialogs and exclude patterns.
