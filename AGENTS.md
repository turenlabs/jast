# AGENTS.md — JAST Desktop

Guidance for AI agents working in this repository. Read this before editing.

## What this is

JAST is a multi-language, local-workspace desktop app for Jev-assisted security
triage: it snapshots source from a user-selected repository, sends consented
regions to `api.typesafe.ai` for model review, and presents candidate findings.
Tauri 2 + Rust backend, React 19 + TypeScript frontend. **No AST, no execution
of repository code, hooks or dependencies — ever.** "Local workspace" does not
mean offline inference; source leaves the machine only after explicit consent.

## Repository layout

- `src/` — React UI only. `api.ts` holds the typed IPC wrappers; `App.tsx`,
  `InvestigationPanel.tsx`, `PreviewSource.tsx` are the views. `src/CONTRACT.md`
  just points back to the root contract.
- `src-tauri/src/` — all privileged logic:
  - `backend.rs` — `AppState`, Tauri commands, SQLite (rusqlite, bundled),
    keychain (`keyring`), HTTP (`reqwest`, blocking), scan runner thread,
    single-instance file lock.
  - `backend/investigations.rs` — investigation IPC commands + persistence.
  - `scanner/` — offline-only, immutable upload preparation: inventory,
    gitignore/exclusion handling, region chunking, request building, strict
    response parsing. `profiles.rs` is the check catalogue + per-language
    guidance (`contextual-v4`).
  - `investigation/` — pure snapshot-only investigation engine (evidence
    ranking, round requests, decision parsing). No fs/net/db — keep it that way.
- `check-ui.cjs` — offline Playwright contract test; serves `dist/` locally and
  injects synthetic Tauri IPC. `screenshots/` hold fixtures, not real results.

## Non-negotiable invariants

Violating any of these is a product bug, not a style choice:

- **Consent gates uploads.** `start_scan`, `resume_scan` and
  `start_investigation` all require explicit `consent`. Preview snapshots are
  immutable and held by Rust; the UI only passes IDs.
- **API key lives only in the OS keychain** (`ai.jast.desktop` / `jev-api-key`).
  Never in SQLite, exports, logs, browser storage, or returned to the UI.
- **The frontend has no plugins.** No fs/shell/HTTP Tauri plugins; CSP in
  `tauri.conf.json` blocks frontend network. Rust owns dialogs, SQLite,
  keychain and the single fixed HTTPS endpoint (no redirects). Do not add a
  plugin or loosen CSP to make something work.
- **No repository code execution.** Initial-scan context is limited to bounded,
  deterministic same-repository helpers: a file-name index of included source
  plus eligible config files (`is_context_file`); a region that names one gets
  its full text embedded in `state.helpers` (≤4 files, ≤16 KiB each, ≤48 KiB
  total). No call-graph resolution and no cross-file taint tracking (not
  supported yet), no external libraries, no live filesystem reads during
  investigation (same-scan snapshots only).
- **Saved requests are immutable** and hashed (SHA-256 over code, questions,
  model, region boundaries). Responses must exactly match stored question keys
  and each answer must match the requested type (Noul/Choice/Score schemas are
  all strictly validated). No SQLite migrations — old scans stay
  readable/resumable with original prompts; additive columns land via guarded
  `ALTER TABLE` like `coverage_json`, and old rows keep NULLs (unknown), never
  fabricated values.
- **One scan OR investigation at a time.** Key changes are rejected while either
  runs. Cancellation stops new requests; an in-flight call may finish.
- **Findings are candidates, not verdicts.** Probability ≥ the scan's recorded
  threshold (Settings-configurable, default `scanner::THRESHOLD` = 0.5); severity
  is a static label; `context_missing` is a separate signal.
  Investigations end `model_supported` / `model_not_supported` / `unresolved` —
  never "confirmed" or "safe". Original scores/dismissals are never mutated.
- **Tests are offline.** Synthetic data and mocked transport/IPC only. Never
  use a real API key or real repository upload in tests.

## Conventions

- JSON is **snake_case**; Tauri invoke argument keys are **camelCase**.
- Contracts are documented and versioned: `CONTRACT.md` (IPC + types),
  `INVESTIGATION.md` (investigation semantics), `src-tauri/src/scanner/README.md`
  (scanning rules), `src-tauri/src/investigation/README.md`. **Update the
  relevant contract doc whenever you change the contract** — the README's
  feature list also mirrors user-visible guarantees.
- There is **no repository-scale cap** — any number of files/regions/bytes can
  be inventoried; the manifest and the authorize click are the protection.
  Per-item bounds remain as consts in `scanner/mod.rs` (24 KiB chunks, 1 MiB
  files, 8 KiB lines, 100k enumerated entries — the last aborts inventory;
  helper pack ≤4 files / ≤16 KiB each / ≤48 KiB total, context sources ≤512
  files / ≤64 KiB each). Skip reasons must be reported, never hidden.
- Errors surface as safe user-facing strings; terminal failures preserve
  completed work and remain resumable.
- Rust: `anyhow` for errors, `serde` snake_case structs, `rusqlite` transactions
  publish chunk+response+cache+findings atomically.
- Pinned model `jev-1.13.0` (`scanner::MODEL`). The candidate threshold is a
  persisted setting (`settings` table, `set_threshold`); each scan records the
  value it was created with in `scans.threshold` and commit/resume use that,
  not today's setting.
- TypeSafe usage: questions reference state with backticked paths
  (`` `state.code` ``); many atomic questions ride in one request; Nouls are
  yes/no only, Choices pick among code-enumerated options, Scores are ordered
  levels. `confidence` (Choice/Score) is a routing signal, never a truth
  probability — gate actions on it, don't display it as certainty. Composite
  scores (e.g. finding `priority`) are computed in Rust, never by the model.

## Build, test, verify

From the repository root:

```sh
npm ci                                                    # deps
npm run tauri -- dev                                      # dev app
./build.sh                                                # verify + macOS bundle (ad-hoc signed)
./build.sh --verify-only                                  # checks only, no bundle

cargo test   --locked --manifest-path src-tauri/Cargo.toml --lib
cargo clippy --locked --manifest-path src-tauri/Cargo.toml --lib -- -D warnings
npm run build                                             # tsc --noEmit && vite build
npx --yes --package playwright -c 'node check-ui.cjs'       # offline UI contract test
```

Run all four verification steps after changes that touch Rust or UI behavior.
Only macOS is build/launch-tested here. `codesign --verify --deep --strict`
checks the bundle; the signature is ad-hoc, not Developer-ID.

## When changing…

- **A check or language guidance** → `scanner/profiles.rs`; bump
  `check_pack_version` semantics per scanner README; request hashes change so
  the cache misses naturally.
- **An IPC command or shape** → `backend.rs`/`backend/investigations.rs`,
  `lib.rs` handler list, `src/api.ts`, `CONTRACT.md`, `check-ui.cjs` mocks.
- **Investigation flow** → keep `investigation/` pure (no I/O); bounds:
  3 rounds, 30 KiB requests, ≤8 offered excerpts, ≤2 reads, 1 KiB snippets.
  Round 1 adds a `relevance:<id>` Noul per candidate; `read:` offers are
  filtered by relevance ≥0.35 and every `read:`/terminal action needs
  `action_confidence` ≥0.35 or the outcome resolves `unresolved`.
