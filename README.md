# JAST Desktop

A multi-language, local-workspace desktop app for Jev-assisted security triage.
Built with Rust, Tauri 2, React and TypeScript. No AST and no execution of
repository code, build scripts, hooks or dependencies.

## Why

Conventional SAST encodes vulnerability knowledge as semantic rules: queries and
patterns hand-written per language, framework, and weakness class. That works
well for syntax-shaped bugs and badly for judgment-shaped ones — whether
attacker-controlled data reaches a sink unsafely depends on the value's origin,
the branch that selected it, the wrapper around it, and whether the defense
protects the *actual* use. Encoding that as rules is where SAST gets expensive.

Jev is a general-purpose classifier, not a code model: it evaluates structured
state against typed questions and returns probabilities, so it can supply the
semantic judgment a rule would otherwise have to encode. JAST keeps every
deterministic mechanic in Rust — inventory, region bounds, hashing, consent,
persistence — and asks Jev explicit, human-reviewable questions with explicit
criteria instead of shipping a rule library. The result is a *basic* SAST
without semantic rules: fast candidate signals over bounded source with honest
scope limits (no cross-file taint tracking yet, no verdicts), not a claim of
whole-program proof.

## Use

1. Launch `src-tauri/target/release/bundle/macos/JAST.app` after building.
2. Open Settings and save a TypeSafe API key to the OS keychain.
3. Select a repository. Add exclusion globs before selecting if needed.
4. Review file/region counts, exclusions and exact source/upload requests.
5. Explicitly authorize sending that snapshot to TypeSafe and start scanning.
6. Review candidate findings, region source and raw model responses. Dismiss or
   restore signals and export a scan as JSON through the native save dialog.
7. Select a candidate and use **Investigate candidate** to authorize a bounded
   follow-up using source already captured in that scan. Review the action/evidence
   trace and model assessment separately from the original score.

Source code **leaves your machine** for inference at `api.typesafe.ai`.
"Local workspace" does not mean offline inference. Development tests use synthetic
data and mocked responses, not your key or real repository uploads.

## Features

- Native directory picker and OS-keychain credential settings. Keys are not saved
  in SQLite, browser storage, exports or logs. The key is never returned to the UI.
- Immutable, inspectable source snapshots bind upload consent to actual input.
  Edits after preview do not alter an in-progress or resumed scan.
- Every check in a language's pack runs on every region of that language. There
  is no benchmark category oracle or model-based prefilter that silently drops
  categories. The preview shows language counts and actual checks per region.
- New scans keep files whole when they fit 24 KiB. Larger files use byte-bounded
  regions, not arbitrary 200-line cuts. Native guidance and shared review policy
  appear once in request state, with category-specific questions referencing them.
- Saved coverage records retain inventory limits, skip reasons, unsupported-file
  counts and exclusion examples in history and JSON exports. Completed means the
  selected workload finished, not that the entire repository was audited.
- Candidates remain explicitly unverified. Model-reported missing context is
  visible across all completed regions, including those with no candidates.
- Fourteen shared checks cover SQL/command/LDAP/XPath injection, traversal, XSS,
  weak hashing/crypto/randomness, cookie security, trust boundaries, SSRF, code
  injection and unsafe deserialization. JS/TS add prototype pollution; Rust adds
  unsafe-memory checks. Language-specific guidance distinguishes native API
  semantics, such as shell invocation versus argument arrays or unsafe Rust
  operations versus the mere presence of an `unsafe` block.
- Pinned `jev-1.13.0`, explicit missing-context signal. The candidate probability
  threshold is configurable in Settings (default 0.5); each scan records the
  value it was created with, so resuming an old scan and exporting it always
  reflect the threshold that actually ran, never a later setting.
- SQLite scan history and transactional result/finding persistence. Interrupted
  scans can resume the original snapshot after renewed consent.
- Full-request SHA-256 cache includes code, questions, model and region boundaries.
  Matching requests reuse scores; changed code/questions/models miss the cache.
- Existing v0.1 Java history remains readable and resumable with its saved eleven
  checks. Responses, including cached responses, must match the exact question
  keys in their stored request. New scans use the new language packs; no database
  migration or history deletion is required.
- Cancellation stops further requests; an in-flight call may finish and be saved.
- Bounded transient-error retry/backoff. Terminal errors preserve completed work
  and show a resumable failure instead of treating missing results as safe.
- Searchable/filterable findings, source-region viewer, raw requests/responses,
  dismissal state and consistent JSON exports, including partial scan status.
- Explicit model-directed investigations: Jev chooses an available evidence
  excerpt with a `Choice` question, then assesses the candidate again against the
  updated state. A maximum of three rounds runs, with no generated paths or tools.
- Each region request also asks typed questions alongside the category Nouls:
  `sink_pointer`/`source_pointer` Choices over code-extracted call identifiers
  (plus `none_visible`), and an `impact` Score on a fixed 0-3 scale. Answers are
  shown as candidate evidence pointers, not proven dataflow.
- Findings carry a composite `priority` weight (probability x normalized model
  impact x remaining context confidence) used for ordering and a weak/medium/high
  signal band; it is a routing weight, not a calibrated risk score.
- Same-file, same-category candidates on overlapping regions are linked to the
  highest-priority one as an overlap hint instead of counting them twice.

## Investigations

The initial broad scan remains unchanged. Investigating a selected candidate is
a separate, explicitly consented operation. Rust ranks stored source excerpts by
identifier overlap and proximity, offers at most eight known excerpt IDs, and
allows Jev to inspect up to two of them before a terminal assessment. Each excerpt
is line-aligned and limited to 1 KiB; this is lexical retrieval, not a call graph
or guaranteed complete helper implementation.

Allowed model actions are to read one offered excerpt, stop with support, stop
without support, or stop unresolved. Round 1 also scores each catalogue
candidate's relevance with a cheap Noul; later rounds only offer excerpts the
model judged relevant enough. Reads and terminal verdicts chosen with low
action confidence resolve as unresolved rather than spending the evidence
budget on a coin flip. Claim support and evidence sufficiency are
separate judgments over the same current evidence. The output is **model-supported**,
**model-not-supported**, or **unresolved**. None means confirmed vulnerability or
proven safety, and original candidate scores/dismissals are never changed.

Supporting/rejecting outcomes additionally require the explicit 0.8 evidence
sufficiency policy and a support score >=0.8 / <=0.2 respectively. These numbers
are routing policies, not validated calibration. Agreement across rounds is not
independent proof. Unknown context and request-budget exhaustion remain unresolved.

Only same-scan snapshots are eligible: no live filesystem access, code execution,
external files, hidden/configuration files omitted from the scan, or shell actions.
Requests are capped at 30 KiB and three inference rounds, with up to four transport
attempts per round. The original target is never silently truncated; an oversized
target can be rejected before any API call. There is no cross-investigation cache.

Plans, validated completed-round requests/responses/hashes, selected evidence,
outcomes and failures are stored in SQLite and included in exports. Interrupted,
cancelled or failed investigations require new consent to start a new run; they
do not silently resume. Cancellation is available globally across app views;
an in-flight response can be saved, but accepted cancellation prevents further
actions and publishes an unresolved cancellation outcome atomically with the step.
One scan or investigation runs at a time. Key changes are blocked while either runs.

This workflow has offline transport/IPC fixture coverage, not a measured accuracy
improvement. No actual user repository or API key is used by its development tests.

## Scope and Limits

Version 0.4 supports these source files:

| Language | Files | Checks Per Region |
| --- | --- | --- |
| Java | `.java` | 14 |
| Python | `.py`, `.pyw`, `.pyi` | 14 |
| Go | `.go` | 14 |
| JavaScript | `.js`, `.jsx`, `.mjs`, `.cjs` | 15 |
| TypeScript | `.ts`, `.tsx`, `.mts`, `.cts` | 15 |
| PHP | `.php`, `.phtml`, `.php5`, `.php7`, `.php8` | 14 |
| Rust | `.rs` | 15 |
| Ruby | `.rb`, `.rake`, `.gemspec`, `Gemfile`, `Rakefile`, `config.ru` | 14 |

Each region also gets a missing-context Noul, an `impact` Score, and
`sink_pointer`/`source_pointer` Choices when call identifiers exist.
Multi-region files add a lexical `file_outline` of surrounding signatures.
Extensions are case-insensitive;
special Ruby filenames use their conventional spelling. Shebang-only scripts and
other languages/templates are not inferred. Mixed-language repositories are
supported. Other files are counted as unsupported.

Minified assets, source maps and TypeScript declaration-only files (`.d.ts`,
`.d.mts`, `.d.cts`) are explicitly skipped, along with Python virtual environments
and caches. These exclusions are reported rather than treated as reviewed files.
Files up to 24 KiB are read whole regardless of line count. Larger files use
byte-bounded regions up to 24 KiB with up to 30 overlapping lines (less when
necessary to make progress within the byte budget). The initial scan embeds bounded
same-repository context: a region that names another included source file's
stem (e.g. `helpers.Util`) or a configuration file's name (`.properties`,
`.xml`, `.yaml`, `.toml`, `.ini`, `.cfg`, `.conf`, `.json`; never lockfiles or
`.env`) receives that file's full text as `state.helpers` — at most 4 helpers,
16 KiB each, 48 KiB per request, deterministically selected and hashed into the
request. It is name-reference retrieval, not a resolved call graph: external
libraries, unreferenced files and anything excluded stay absent. **Cross-file
taint tracking is not supported yet** — helpers show referenced file text, but
nothing traces a value's flow from one file into a sink in another. Explicit
investigation can select partial excerpts from already captured source, but
never reads omitted files or resolves a complete call graph. Overlap may produce
overlapping same-category signals, which are linked to one primary candidate as
an overlap hint rather than removed or confirmed as duplicates; JAST does not
claim whole-program dataflow or exact vulnerable lines.

There is no cap on total files, regions or snapshot size: the pre-upload
manifest shows the full scope and the authorize action is the bound. Per-item
limits remain at 1 MiB per file, 24 KiB per region and 8 KiB per line, and
enumeration aborts past 100,000 entries. Excluded/unreadable entries are exposed
before upload. At most 100 exclusion examples are shown; totals count observed
entries, not every descendant inside pruned directories.

Local `.gitignore` and `.ignore` files are respected. Hidden, generated, dependency
and build-output paths are excluded. Symlink roots/files/directories are rejected
or skipped. No global Git config or external `.git` indirections are read.
Do not mutate a repository during inventory: path checks resist ordinary symlinks
but are not a sandbox against hostile concurrent filesystem changes.

Obvious long hardcoded credentials/private keys cause the entire file to be
excluded. This is a best-effort safeguard, **not a secret-removal guarantee**.
Inspect the source preview and apply exclusions before consenting.

Model scores are candidate signals, not calibrated exploit probabilities. Severity
is a static check label, not established impact. A missing-context score is a
separate warning, not proof that sufficient context exists or an abstention.
No findings does not prove security. Prior OWASP benchmark scores do not directly
measure this all-checks, region-only application workflow.
The added languages have functional fixture coverage, not measured per-language
vulnerability-detection accuracy. Language support does not imply compiler-level
analysis, a complete rule set, or a guarantee of finding unsafe code.

## Storage and Security

Settings use service `ai.jast.desktop` / account `jev-api-key` in the platform
credential store (macOS Keychain, Windows Credential Manager, Linux Secret Service).
Only macOS is built/launch-tested in this workspace. No plaintext fallback exists.

On macOS, local scan data is under
`~/Library/Application Support/ai.jast.desktop/`. This directory is mode 0700 and
contains source snapshots, raw responses and dismissals in `jast.sqlite` plus WAL
files. Source snapshots are not encrypted by JAST; protect your account/disk.
Exports also contain source snapshots. There is no UI history-deletion feature
yet; to remove local history, quit JAST and remove that specific app-data directory
yourself. Removing the API key in Settings does not remove scan history.

The UI has no filesystem/shell/HTTP plugins. Rust owns native dialogs, scoped
snapshot IDs, SQLite, keychain and HTTP. The fixed HTTPS endpoint does not follow
redirects. CSP blocks arbitrary frontend network connections. The app does not
automatically import an API key from the shell environment.

Only one app instance and one scan or investigation run at a time. SQLite publishes a chunk response,
cache entry and findings in one transaction. A crash after remote acceptance but
before local commit can repeat that request on resume: exactly-once billing is not
claimed. Changing/removing credentials while scanning is rejected. Export captures
summary, findings and raw chunks under one database lock for a coherent snapshot.

## Develop and Build

From the repository root:

```sh
npm ci
npm run tauri -- dev
./build.sh    # verify + macOS bundle, or npm run tauri -- build --bundles app
```

Requires Rust, Node, and platform Tauri prerequisites. The check catalogue and
language guidance live in `src-tauri/src/scanner/profiles.rs`; the app no longer
depends on the benchmark question file. The compiled desktop bundle is
self-contained. The macOS app uses
an ad-hoc signature for local development, not a Developer-ID/notarized signature
for distribution. The bundle can be checked with `codesign --verify --deep --strict`.

The v0.3 SQLite upgrade adds a nullable coverage column. Existing source requests,
responses and cache hashes are preserved. Historical scans show coverage unknown
rather than fabricated exclusion statistics. Resuming an old scan still uses its
original prompts and context; start a new preview/scan to use contextual-v5.

```sh
./build.sh --verify-only
# or individually:
cargo test --locked --manifest-path src-tauri/Cargo.toml --lib
cargo clippy --locked --manifest-path src-tauri/Cargo.toml --lib -- -D warnings
npm run build
npx --yes --package playwright -c 'node check-ui.cjs'
```

The browser test serves only local built assets and injects synthetic Tauri IPC
responses. It tests browser-mode gating, consent/source preview, key clearing,
escaped evidence, findings, dismissals, cancellation/resume, export and responsive
layout. Screenshots in `screenshots/` contain test fixtures, not real scan results.
Rust tests exercise real inventory/SQLite behavior and injected transport/cache
execution without cloud calls. Native keychain permission prompts and live API
authorization are exercised when you configure and use the app, not by these mocks.

An optional offline size audit can reconstruct the source already present in an
export, check overlapping lines for consistency, and run current inventory on a
temporary copy. It never reads the original repository or calls TypeSafe:

```sh
JAST_AUDIT_EXPORT=/path/to/jast-scan.json cargo test --manifest-path src-tauri/Cargo.toml --lib audit_export_context -- --ignored --nocapture
```

The audit measures bytes and region counts, not model tokens, accuracy or coverage
beyond the exported source. See `context-audit.md` for the measured example.
JAST does not base64-encode source: that expands the text and removes directly
readable code structure. Compression for transport would not reduce the model's
decoded context size. v0.4 adds an explicitly consented investigation loop, not
an automatic second pass and not a claim of independent vulnerability verification.

## License

MIT — see [LICENSE](LICENSE).
