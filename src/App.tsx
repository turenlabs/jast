import { useEffect, useRef, useState } from "react";
import {
  ArrowDownToLine,
  ArrowRight,
  Check,
  ChevronRight,
  CircleHelp,
  Code2,
  FileCode2,
  FolderOpen,
  KeyRound,
  LoaderCircle,
  LockKeyhole,
  Search,
  Settings2,
  ShieldCheck,
  Square,
  TriangleAlert,
  X,
} from "lucide-react";
import {
  command,
  desktop,
  message,
  type Evidence,
  type FileView,
  type Finding,
  type Investigation,
  type Preview,
  type Scan,
  type ScanDetail,
  type Settings,
} from "./api";
import PreviewSource from "./PreviewSource";
import InvestigationPanel from "./InvestigationPanel";

const number = (n: number) => n.toLocaleString();
const date = (n: number) =>
  new Date(n * 1000).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
const percent = (n: number) => `${(n * 100).toFixed(1)}%`;
// Composite routing weight: probability x model impact x (1 - missing context).
const signalBand = (priority: number) =>
  priority >= 0.4 ? "high" : priority >= 0.15 ? "medium" : "low";
const IMPACT_LEVELS = ["None", "Limited", "Serious", "Critical"];
const impactLabel = (impact: number | null) =>
  impact == null
    ? "not assessed"
    : `${IMPACT_LEVELS[Math.min(3, Math.max(0, Math.round(impact)))]} · ${impact.toFixed(1)}`;
const statusLabel = (status: Scan["status"]) =>
  status === "completed" ? "Selected scope complete" : status;
// Lines where the candidate sink/source identifiers appear inside the finding's
// own reviewed region. Display heuristic only; pointers name identifiers, not lines.
function markedLines(f: Finding, regionId: string, code: string, startLine: number) {
  const sink = new Set<number>();
  const src = new Set<number>();
  if (f.chunk_id !== regionId) return { sink, src };
  code.split("\n").forEach((line, i) => {
    if (f.sink && line.includes(f.sink)) sink.add(startLine + i);
    if (f.source && line.includes(f.source)) src.add(startLine + i);
  });
  return { sink, src };
}
function CoverageDetails({ scan }: { scan: Scan }) {
  const coverage = scan.coverage;
  return (
    <div className="preview-detail coverage-summary">
      <p className="region-notice">
        Progress measures planned jobs only, not a whole-repository audit.
      </p>
      <p className="coverage-context">
        <strong>{number(scan.uncertain_regions)} / {number(scan.completed)}</strong>{" "}
        regions with model-reported missing context
      </p>
      {!coverage ? (
        <p className="warning-text">Coverage unknown: this scan predates saved inventory details</p>
      ) : (
        <>
          {coverage.limit_reached && (
            <div className="alert error" role="status">
              <TriangleAlert size={17} />
              <span><strong>Limited scope: inventory was cropped by limits.</strong>{" "}
                {coverage.limit_reasons.join(" · ")}
              </span>
            </div>
          )}
          <p className="coverage-counts">
            {number(coverage.included_files)} included files · {number(coverage.planned_regions)} planned regions · {number(coverage.excluded_count)} excluded entries · {number(coverage.unsupported_count)} unsupported files · {number(coverage.context_files)} context files
            {scan.threshold != null &&
              ` · threshold ${percent(scan.threshold)}`}
          </p>
          <details>
            <summary>Saved coverage, exclusions & warnings <ChevronRight size={13} /></summary>
            <p>{coverage.context_policy}</p>
            <ul className="exclusion-list">
              {Object.entries(coverage.exclusion_reasons).map(([reason, count]) => (
                <li key={reason}><span>{reason}</span><strong>{number(count)}</strong></li>
              ))}
              {coverage.exclusions.map((item, i) => (
                <li key={`${item.path}-${i}`}><code>{item.path}</code><span>{item.reason}</span></li>
              ))}
            </ul>
            {coverage.warnings.map((warning, i) => <p className="warning-text" key={i}>{warning}</p>)}
          </details>
        </>
      )}
    </div>
  );
}
function Busy({ active }: { active: boolean }) {
  return active ? <LoaderCircle size={15} className="spin" /> : null;
}
function Json({ value }: { value: string | null }) {
  let text = value || "No response recorded.";
  try {
    if (value) text = JSON.stringify(JSON.parse(value), null, 2);
  } catch {
    /* Preserve raw evidence. */
  }
  return <pre className="raw-json">{text}</pre>;
}

export default function App() {
  const [page, setPage] = useState<"workspace" | "findings" | "settings">(
    "workspace",
  );
  const [settings, setSettings] = useState<Settings | null>(null);
  const [history, setHistory] = useState<Scan[]>([]);
  const [preview, setPreview] = useState<Preview | null>(null);
  const [patterns, setPatterns] = useState("");
  const [key, setKey] = useState("");
  const [thresholdPct, setThresholdPct] = useState<number | null>(null);
  const [scanId, setScanId] = useState<string | null>(null);
  const [detail, setDetail] = useState<ScanDetail | null>(null);
  const [findingId, setFindingId] = useState<string | null>(null);
  const [evidence, setEvidence] = useState<Evidence | null>(null);
  const [evidenceLoading, setEvidenceLoading] = useState(false);
  const [fileView, setFileView] = useState<FileView | null>(null);
  const [fileViewLoading, setFileViewLoading] = useState(false);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [detailLoading, setDetailLoading] = useState(false);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState("all");
  const [showDismissed, setShowDismissed] = useState(false);
  const [activeInvestigation, setActiveInvestigation] = useState<Investigation | null>(null);
  const [investigationChecking, setInvestigationChecking] = useState(desktop);
  const [investigationError, setInvestigationError] = useState("");
  const [investigationRetry, setInvestigationRetry] = useState(0);
  const investigationRevision = useRef(0);
  const locked = useRef(false);
  const selected = useRef<string | null>(null);
  const focusRegion = useRef<HTMLDivElement | null>(null);
  const revision = useRef(0);
  const mounted = useRef(true);
  const running = history.find((s) => s.status === "running");
  const investigationRunning = activeInvestigation?.status === "running";
  const investigationBlocked = investigationChecking || investigationRunning;
  const scan = detail?.scan;
  const finding = detail?.findings.find((f) => f.id === findingId);
  const categories = [
    ...new Set(detail?.findings.map((f) => f.category) || []),
  ].sort();
  const visible = (detail?.findings || []).filter(
    (f) =>
      (showDismissed || !f.dismissed) &&
      (category === "all" || f.category === category) &&
      `${f.path} ${f.label} ${f.category} ${f.language}`
        .toLowerCase()
        .includes(query.toLowerCase()),
  );
  const signalGroups = (() => {
    const map = new Map<string, Finding[]>();
    for (const f of visible) {
      const list = map.get(f.path) || [];
      list.push(f);
      map.set(f.path, list);
    }
    return [...map.entries()];
  })();
  const view = fileView?.path === finding?.path ? fileView : null;
  const regions = view?.regions ?? [];
  const fileLo = regions.length
    ? Math.min(...regions.map((r) => r.start_line))
    : 0;
  const fileSpan = regions.length
    ? Math.max(1, Math.max(...regions.map((r) => r.end_line)) - fileLo + 1)
    : 1;

  function chooseScan(id: string) {
    setPage("findings");
    if (selected.current === id) return;
    selected.current = id;
    revision.current++;
    setScanId(id);
    setDetail(null);
    setFindingId(null);
    setEvidence(null);
    setFileView(null);
    setDrawerOpen(false);
    setCategory("all");
  }
  function mergeScan(value: Scan) {
    setHistory((items) =>
      [value, ...items.filter((s) => s.id !== value.id)].sort(
        (a, b) => b.created_at - a.created_at,
      ),
    );
  }
  async function action(name: string, run: () => Promise<void>) {
    if (locked.current) return;
    if (investigationBlocked && ["browse", "start", "resume", "save-key", "remove-key", "threshold"].includes(name)) return;
    locked.current = true;
    setBusy(name);
    setError("");
    setNotice("");
    try {
      await run();
    } catch (e) {
      if (mounted.current) setError(message(e));
    } finally {
      locked.current = false;
      if (mounted.current) setBusy("");
    }
  }
  useEffect(() => {
    if (settings) setThresholdPct(Math.round(settings.threshold * 100));
  }, [settings?.threshold]);
  useEffect(() => {
    let alive = true;
    mounted.current = true;
    if (desktop) {
      command<Settings>("get_settings")
        .then((s) => {
          if (alive) setSettings(s);
        })
        .catch((e) => {
          if (alive) setError(message(e));
        });
      command<Scan[]>("list_scans")
        .then((s) => {
          if (alive) setHistory(s);
        })
        .catch((e) => {
          if (alive) setError(message(e));
        });
    }
    return () => {
      alive = false;
      mounted.current = false;
    };
  }, []);
  useEffect(() => {
    if (!desktop) return;
    let alive = true;
    const version = investigationRevision.current;
    setInvestigationChecking(true);
    command<Investigation | null>("get_active_investigation").then((value) => {
      if (alive && version === investigationRevision.current) {
        setActiveInvestigation(value);
        setInvestigationChecking(false);
        setInvestigationError("");
      }
    }).catch((e) => {
      if (alive) setInvestigationError(`Could not check active investigation: ${message(e)}`);
    });
    return () => { alive = false; };
  }, [investigationRetry]);
  useEffect(() => {
    if (!desktop || !investigationRunning || !activeInvestigation) return;
    let alive = true;
    let timer: ReturnType<typeof setTimeout>;
    const id = activeInvestigation.id;
    async function pollInvestigation() {
      const version = investigationRevision.current;
      try {
        const value = await command<Investigation>("get_investigation", { investigationId: id });
        if (alive && version === investigationRevision.current) {
          setActiveInvestigation(value);
          setInvestigationError("");
        }
      } catch (e) {
        if (alive) setInvestigationError(`Investigation progress unavailable; cancellation remains available. ${message(e)}`);
      }
      if (alive) timer = setTimeout(pollInvestigation, 1500);
    }
    timer = setTimeout(pollInvestigation, 1500);
    return () => { alive = false; clearTimeout(timer); };
  }, [activeInvestigation?.id, investigationRunning]);
  function investigationStarted(value: Investigation) {
    investigationRevision.current++;
    if (!mounted.current) return;
    setActiveInvestigation(value);
    setInvestigationChecking(false);
    setInvestigationError("");
  }
  function cancelInvestigation() {
    if (!activeInvestigation || !investigationRunning) return;
    const id = activeInvestigation.id;
    void action("cancel-investigation", async () => {
      await command("cancel_investigation", { investigationId: id });
      investigationRevision.current++;
      setNotice("Investigation cancellation requested. An in-flight cloud request may still finish.");
      const value = await command<Investigation>("get_investigation", { investigationId: id });
      if (mounted.current) setActiveInvestigation(value);
    });
  }
  useEffect(() => {
    if (!scanId) return;
    let alive = true;
    const version = ++revision.current;
    setDetailLoading(true);
    command<ScanDetail>("get_scan", { scanId })
      .then((value) => {
        if (
          alive &&
          selected.current === scanId &&
          revision.current === version
        ) {
          setDetail(value);
          mergeScan(value.scan);
        }
      })
      .catch((e) => {
        if (alive) setError(message(e));
      })
      .finally(() => {
        if (alive) setDetailLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [scanId]);
  useEffect(() => {
    if (!running || !desktop) return;
    let alive = true;
    let timer: ReturnType<typeof setTimeout>;
    const id = running.id;
    async function poll() {
      if (locked.current) {
        timer = setTimeout(poll, 1500);
        return;
      }
      const version = revision.current;
      try {
        const value = await command<ScanDetail>("get_scan", { scanId: id });
        if (!alive) return;
        if (!locked.current && revision.current === version) {
          mergeScan(value.scan);
          if (selected.current === id) setDetail(value);
          if (value.scan.status === "running") {
            const items = await command<Scan[]>("list_scans");
            if (alive && !locked.current && revision.current === version)
              setHistory(items);
          }
        }
      } catch (e) {
        if (alive) setError(message(e));
      }
      if (alive) timer = setTimeout(poll, 1500);
    }
    timer = setTimeout(poll, 1500);
    return () => {
      alive = false;
      clearTimeout(timer);
    };
  }, [running?.id]);
  useEffect(() => {
    setEvidence(null);
    if (!scanId || !finding) {
      setEvidenceLoading(false);
      return;
    }
    let alive = true;
    setEvidenceLoading(true);
    command<Evidence>("get_evidence", { scanId, chunkId: finding.chunk_id })
      .then((value) => {
        if (alive) setEvidence(value);
      })
      .catch((e) => {
        if (alive) setError(message(e));
      })
      .finally(() => {
        if (alive) setEvidenceLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [scanId, finding?.chunk_id]);
  useEffect(() => {
    if (!scanId || !finding || !desktop) {
      setFileView(null);
      setFileViewLoading(false);
      return;
    }
    let alive = true;
    setFileViewLoading(true);
    command<FileView>("get_file_view", { scanId, path: finding.path })
      .then((value) => {
        if (alive) setFileView(value);
      })
      .catch((e) => {
        if (alive) setError(message(e));
      })
      .finally(() => {
        if (alive) setFileViewLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [scanId, finding?.path, scan?.completed]);
  useEffect(() => {
    if (fileView) focusRegion.current?.scrollIntoView({ block: "center" });
  }, [fileView, findingId]);
  useEffect(() => {
    if (page !== "settings") setKey("");
  }, [page]);

  function browse() {
    if (investigationBlocked) return;
    void action("browse", async () => {
      const value = await command<Preview | null>("select_repository", {
        excludedPatterns: patterns
          .split("\n")
          .map((s) => s.trim())
          .filter(Boolean),
      });
      if (value) {
        setPreview(value);
      }
    });
  }
  function start() {
    if (!preview || !settings?.key_configured || running || investigationBlocked) return;
    void action("start", async () => {
      const value = await command<Scan>("start_scan", {
        previewId: preview.id,
        consent: true,
      });
      setPreview(null);
      mergeScan(value);
      chooseScan(value.id);
    });
  }
  function resume() {
    if (!scan || !settings?.key_configured || running || investigationBlocked) return;
    void action("resume", async () => {
      const value = await command<Scan>("resume_scan", {
        scanId: scan.id,
        consent: true,
      });
      revision.current++;
      mergeScan(value);
      setDetail((d) => (d?.scan.id === value.id ? { ...d, scan: value } : d));
    });
  }
  function cancel() {
    if (!running) return;
    void action("cancel", async () => {
      const id = running.id;
      await command("cancel_scan", { scanId: id });
      revision.current++;
      const value = await command<ScanDetail>("get_scan", { scanId: id });
      mergeScan(value.scan);
      if (selected.current === id) setDetail(value);
      setNotice(
        "Cancellation requested. An in-flight cloud request may still finish.",
      );
    });
  }
  function dismiss(f: Finding) {
    if (!scanId) return;
    void action("dismiss", async () => {
      const id = scanId;
      revision.current++;
      await command("set_dismissed", {
        findingId: f.id,
        dismissed: !f.dismissed,
      });
      const version = ++revision.current;
      const value = await command<ScanDetail>("get_scan", { scanId: id });
      mergeScan(value.scan);
      if (selected.current === id && revision.current === version)
        setDetail(value);
    });
  }

  return (
    <div className="app">
      <header className="command-bar">
        <div className="mark">
          <span>
            JA<span className="mark-sel">ST</span>
          </span>
          <span className="mark-sub">Jev-assisted triage</span>
        </div>
        <nav className="cmd-tabs" aria-label="Main navigation">
          <button
            className={page === "workspace" ? "on" : ""}
            onClick={() => setPage("workspace")}
          >
            New scan
          </button>
          <button
            className={page === "findings" ? "on" : ""}
            onClick={() => setPage("findings")}
          >
            Signals<span className="n">{scan?.findings ?? 0}</span>
          </button>
          <button
            className={page === "settings" ? "on" : ""}
            onClick={() => setPage("settings")}
          >
            Settings{!settings?.key_configured && <span className="key-dot" />}
          </button>
        </nav>
      </header>
        {investigationRunning && activeInvestigation && (
          <div className="investigation-banner" role="status">
            <LoaderCircle size={16} className="spin" />
            <span>JAST is checking related code… round {Math.min(activeInvestigation.steps.length + 1, 3)}/3<br />{activeInvestigation.plan.target.label}</span>
            <button disabled={!!busy} onClick={cancelInvestigation}><Square size={13} />Cancel investigation</button>
          </div>
        )}
        {investigationError && <div className="alert error" role="alert"><span>{investigationError}</span>{investigationChecking && <button onClick={() => setInvestigationRetry((n) => n + 1)}>Retry active investigation check</button>}</div>}
        {!desktop && (
          <div className="desktop-banner">
            <TriangleAlert size={16} />
            <span>
              <strong>Desktop required.</strong> This browser preview cannot
              access repositories or your keychain. Open the JAST desktop app to
              scan. No sample results are shown.
            </span>
          </div>
        )}
        {error && (
          <div className="alert error" role="alert">
            <TriangleAlert size={17} />
            <span>{error}</span>
            <button aria-label="Dismiss error" onClick={() => setError("")}>
              <X size={16} />
            </button>
          </div>
        )}
        {notice && (
          <div className="alert success" role="status">
            <Check size={17} />
            <span>{notice}</span>
            <button
              aria-label="Dismiss notification"
              onClick={() => setNotice("")}
            >
              <X size={16} />
            </button>
          </div>
        )}
        <main>
          {page === "workspace" && (
            <div className="workspace page-content">
              <div className="page-heading">
                <div>
                  <h1>New scan</h1>
                  <p>
                    JAST scans your source code for security issues. Pick a
                    folder to see exactly what would be sent for review.
                    Nothing leaves this machine until you authorize it.
                  </p>
                </div>
              </div>
              <div className="repo-row">
                <div className="repo-field">
                  {preview ? (
                    <>
                      <strong>{preview.repo_name}</strong>
                      <span>{preview.repo_path}</span>
                    </>
                  ) : (
                    <span className="repo-placeholder">
                      No repository selected. Source stays on this machine
                      until you approve an upload.
                    </span>
                  )}
                </div>
                <button
                  disabled={
                    !desktop || !!busy || !!running || investigationBlocked
                  }
                  onClick={browse}
                >
                  <Busy active={busy === "browse"} />
                  <FolderOpen size={15} />
                  {busy === "browse"
                    ? "Building manifest…"
                    : preview
                      ? "Choose another folder…"
                      : "Choose folder…"}
                </button>
              </div>
              <details className="exclusions-fold">
                <summary>
                  Custom exclusions <span>optional</span>
                  <ChevronRight size={13} />
                </summary>
                <textarea
                  aria-label="Custom exclusion glob patterns"
                  value={patterns}
                  onChange={(e) => {
                    setPatterns(e.target.value);
                    setPreview(null);
                  }}
                  disabled={!!busy || !!running || investigationBlocked}
                  placeholder={"generated/**\n**/fixtures/**"}
                  rows={3}
                />
                <p>
                  One glob pattern per line. Changes require a new preview.
                </p>
              </details>
              {preview ? (
                <section className="manifest-block">
                  {preview.limit_reached && (
                    <div className="alert error" role="status">
                      <TriangleAlert size={17} />
                      <span>
                        <strong>
                          Limited scope: inventory was cropped by limits.
                        </strong>{" "}
                        {preview.limit_reasons.join(" · ")}
                      </span>
                    </div>
                  )}
                  <table className="manifest">
                    <thead>
                      <tr>
                        <th>Language</th>
                        <th className="num">Files</th>
                        <th className="num">Regions</th>
                        <th className="num">Requests</th>
                      </tr>
                    </thead>
                    <tbody>
                      {preview.languages.map((l) => (
                        <tr key={l.language}>
                          <td className="lang">{l.language}</td>
                          <td className="num">{number(l.files)}</td>
                          <td className="num">{number(l.chunks)}</td>
                          <td className="num">{number(l.chunks)}</td>
                        </tr>
                      ))}
                      <tr className="dim">
                        <td>excluded entries</td>
                        <td className="num">
                          {number(preview.excluded_count)}
                        </td>
                        <td className="num">-</td>
                        <td className="num">-</td>
                      </tr>
                      <tr className="dim">
                        <td>unsupported files</td>
                        <td className="num">
                          {number(preview.unsupported_count)}
                        </td>
                        <td className="num">-</td>
                        <td className="num">-</td>
                      </tr>
                      <tr className="dim">
                        <td>context files</td>
                        <td className="num">{number(preview.context_files)}</td>
                        <td className="num">-</td>
                        <td className="num">-</td>
                      </tr>
                      <tr className="total">
                        <td>Total upload</td>
                        <td className="num">{number(preview.files)}</td>
                        <td className="num">{number(preview.chunks)}</td>
                        <td className="num">{number(preview.chunks)}</td>
                      </tr>
                    </tbody>
                  </table>
                  <p className="manifest-note">
                    {number(preview.bytes)} source bytes · ~
                    {number(preview.estimated_tokens)} estimated tokens ·{" "}
                    {preview.checks.length} semantic criteria per region
                  </p>
                  {preview.languages.length === 0 && (
                    <p className="warning-text">
                      <TriangleAlert size={14} />
                      No supported source detected in this repository.
                    </p>
                  )}
                </section>
              ) : (
                <p className="manifest-empty">
                  Choose a folder to build its upload manifest: per-language
                  file, region and request counts, with exclusions spelled out
                  before anything is sent.
                </p>
              )}
              {preview && <PreviewSource key={preview.id} preview={preview} />}
              <section className="sign-off">
                <div className="sign-foot">
                  <button
                    className="primary"
                    disabled={
                      !desktop ||
                      !preview ||
                      !settings?.key_configured ||
                      !!running ||
                      investigationBlocked ||
                      !!busy ||
                      preview.chunks === 0
                    }
                    onClick={start}
                  >
                    <Busy active={busy === "start"} />
                    Authorize &amp; start scan
                    <ArrowRight size={15} />
                  </button>
                </div>
                {!settings?.key_configured && (
                  <button
                    className="text-button"
                    onClick={() => setPage("settings")}
                  >
                    <KeyRound size={13} />
                    Configure an API key in Settings before scanning
                    <ArrowRight size={13} />
                  </button>
                )}
                {running && (
                  <button
                    className="text-button"
                    onClick={() => chooseScan(running.id)}
                  >
                    A scan is already running. View progress
                    <ArrowRight size={13} />
                  </button>
                )}
              </section>
              <section className="history-ledger">
                <h2 className="ledger-title">
                  Scan history <span>{history.length}</span>
                </h2>
                {history.length === 0 ? (
                  <p className="ledger-empty">
                    Your repositories and scans will appear here.
                  </p>
                ) : (
                  history.map((item) => (
                    <button
                      key={item.id}
                      onClick={() => chooseScan(item.id)}
                      className={`ledger-row ${scanId === item.id ? "selected" : ""}`}
                    >
                      <span className={`status-dot ${item.status}`} />
                      <span className="ledger-repo">{item.repo_name}</span>
                      <span className="ledger-when">
                        {date(item.created_at)}
                      </span>
                      <span className="ledger-num">
                        {item.completed}/{item.total} regions
                      </span>
                      <span className="ledger-num">
                        {item.findings} signals
                      </span>
                      <span className={`ledger-status ${item.status}`}>
                        {statusLabel(item.status)}
                        {item.coverage?.limit_reached
                          ? " · limited scope"
                          : !item.coverage
                            ? " · coverage unknown"
                            : ""}
                      </span>
                    </button>
                  ))
                )}
              </section>
              <div className="workspace-footnote">
                <CircleHelp size={14} />
                <span>
                  A finding is a review signal, not proof of exploitability.
                  Always verify the surrounding context.
                </span>
              </div>
            </div>
          )}
          {page === "settings" && (
            <div className="page-content settings-page">
              <div className="page-heading">
                <div>
                  <h1>Settings</h1>
                  <p>
                    Your credential belongs in your operating system’s keychain.
                  </p>
                </div>
              </div>
              <section className="panel settings-panel">
                <div className="panel-heading">
                  <h2>
                    <KeyRound size={17} />
                    TypeSafe API key
                  </h2>
                  <span
                    className={
                      settings?.key_configured ? "tag teal" : "tag amber"
                    }
                  >
                    {settings?.key_configured ? "Configured" : "Not configured"}
                  </span>
                </div>
                <div className="settings-body">
                  <p>
                    The key is passed directly to the native app and stored in
                    the OS keychain. It is never written to browser storage or
                    included in scan exports.
                  </p>
                  {settings?.key_error && (
                    <p className="warning-text">{settings.key_error}</p>
                  )}
                  <form
                    onSubmit={(e) => {
                      e.preventDefault();
                      if (!key.trim() || running || investigationBlocked) return;
                      void action("save-key", async () => {
                        try {
                          setSettings(
                            await command<Settings>("save_api_key", {
                              key: key.trim(),
                            }),
                          );
                          setNotice("API key saved to the OS keychain.");
                        } finally {
                          setKey("");
                        }
                      });
                    }}
                  >
                    <label htmlFor="api-key">API key</label>
                    <input
                      id="api-key"
                      type="password"
                      autoComplete="off"
                      spellCheck={false}
                      value={key}
                      onChange={(e) => setKey(e.target.value)}
                      placeholder="Enter your TypeSafe API key"
                      disabled={!desktop || !!busy || !!running || investigationBlocked}
                    />
                    <div className="button-row">
                      <button
                        className="primary"
                        type="submit"
                        disabled={!desktop || !key.trim() || !!busy || !!running || investigationBlocked}
                      >
                        <Busy active={busy === "save-key"} />
                        <LockKeyhole size={15} />
                        Save to keychain
                      </button>
                      <button
                        type="button"
                        disabled={
                          !desktop ||
                          !settings?.key_configured ||
                          !!busy ||
                          !!running || investigationBlocked
                        }
                        onClick={() =>
                          void action("remove-key", async () => {
                            setSettings(
                              await command<Settings>("remove_api_key"),
                            );
                            setKey("");
                            setNotice("API key removed.");
                          })
                        }
                      >
                        <Busy active={busy === "remove-key"} />
                        Remove key
                      </button>
                    </div>
                  </form>
                </div>
              </section>
              <section className="panel settings-panel">
                <div className="panel-heading">
                  <h2>
                    <Settings2 size={17} />
                    Analysis protocol
                  </h2>
                </div>
                <div className="settings-body protocol">
                  <div>
                    <span>Model</span>
                    <strong>
                      {settings?.model || "Available in desktop app"}
                    </strong>
                  </div>
                  <div>
                    <span>Candidate signal threshold</span>
                    <span className="threshold-edit">
                      <input
                        type="number"
                        min={0}
                        max={100}
                        step={1}
                        aria-label="Candidate signal threshold percent"
                        disabled={
                          !desktop || !!running || investigationBlocked || !!busy
                        }
                        value={
                          thresholdPct ??
                          Math.round((settings?.threshold ?? 0.5) * 100)
                        }
                        onChange={(e) =>
                          setThresholdPct(
                            e.target.value === "" ? null : Number(e.target.value),
                          )
                        }
                      />
                      <span>%</span>
                      <button
                        type="button"
                        disabled={
                          !desktop ||
                          !!running ||
                          investigationBlocked ||
                          !!busy ||
                          thresholdPct === null ||
                          Number.isNaN(thresholdPct) ||
                          thresholdPct < 0 ||
                          thresholdPct > 100
                        }
                        onClick={() =>
                          void action("threshold", async () => {
                            setSettings(
                              await command<Settings>("set_threshold", {
                                threshold: (thresholdPct ?? 50) / 100,
                              }),
                            );
                            setNotice(
                              "Threshold updated; applies to the next scan.",
                            );
                          })
                        }
                      >
                        <Busy active={busy === "threshold"} />
                        Apply
                      </button>
                    </span>
                  </div>
                  <div>
                    <span>Supported languages</span>
                    <strong className="supported-languages">
                      {settings ? settings.supported_languages.join(" · ") : "Available in desktop app"}
                    </strong>
                  </div>
                  <div>
                    <span>Execution policy</span>
                    <strong>Never execute repository code</strong>
                  </div>
                </div>
              </section>
            </div>
          )}
          {page === "findings" && (
            <div className="findings-page">
              <div className="findings-header">
                <div>
                  <h1>{scan?.repo_name || "Candidate signals"}</h1>
                  <p className="repo-path">
                    {scan?.repo_path ||
                      "Select a scan from history to review its evidence."}
                  </p>
                </div>
                <div className="button-row">
                  {running && (
                    <button
                      className="danger-button"
                      disabled={!!busy}
                      onClick={cancel}
                    >
                      <Busy active={busy === "cancel"} />
                      <Square size={13} />
                      Cancel scan
                    </button>
                  )}
                  <button
                    disabled={!scan || !!busy}
                    onClick={() =>
                      scan &&
                      void action("export", async () => {
                        const path = await command<string | null>(
                          "export_scan",
                          { scanId: scan.id },
                        );
                        if (path) setNotice(`Export saved to ${path}`);
                      })
                    }
                  >
                    <Busy active={busy === "export"} />
                    <ArrowDownToLine size={15} />
                    Export JSON
                  </button>
                </div>
              </div>
              {detailLoading && (
                <div className="loading-line" role="status">
                  <LoaderCircle className="spin" size={16} />
                  Loading scan…
                </div>
              )}
              {scan && (
                <>
                  <div className="scan-summary">
                    <span
                      className={`tag ${scan.status === "running" || scan.status === "completed" ? "teal" : "amber"}`}
                    >
                      {scan.status === "running" && (
                        <LoaderCircle size={12} className="spin" />
                      )}
                      {statusLabel(scan.status)}
                    </span>
                    <span>
                      <strong>{number(scan.completed)}</strong> /{" "}
                      {number(scan.total)} planned regions
                    </span>
                    <span>
                      <strong>{number(scan.cached)}</strong> cached
                    </span>
                    <span>
                      <strong>{number(scan.findings)}</strong> candidate signals · unverified
                    </span>
                    <span className="scan-date">{date(scan.created_at)}</span>
                  </div>
                  <div
                    className="progress-track"
                    role="progressbar"
                    aria-label="Planned region progress"
                    aria-valuemin={0}
                    aria-valuemax={scan.total || 1}
                    aria-valuenow={scan.completed}
                  >
                    <div
                      style={{
                        width: `${scan.total ? Math.min(100, (scan.completed / scan.total) * 100) : 0}%`,
                      }}
                    />
                  </div>
                  <CoverageDetails scan={scan} />
                  {scan.error && (
                    <div className="alert error">
                      <TriangleAlert size={15} />
                      {scan.error}
                    </div>
                  )}
                  {["cancelled", "interrupted", "failed"].includes(
                    scan.status,
                  ) && (
                    <div className="resume-bar">
                      <span>
                        Uploads the remaining source regions to TypeSafe.
                        Completed work is reused.
                      </span>
                      <button
                        disabled={
                          !settings?.key_configured ||
                          !!busy ||
                          !!running || investigationBlocked
                        }
                        onClick={resume}
                      >
                        <Busy active={busy === "resume"} />
                        Authorize &amp; resume scan
                        <ArrowRight size={14} />
                      </button>
                    </div>
                  )}
                </>
              )}
              {!scan && !detailLoading ? (
                <div className="empty-state">
                  <ShieldCheck size={40} strokeWidth={1} />
                  <h2>No scan selected</h2>
                  <p>
                    Findings, source regions and model evidence will appear
                    here.
                    <br />
                    Start with a local repository or select a saved scan.
                  </p>
                  <button onClick={() => setPage("workspace")}>
                    <FolderOpen size={15} />
                    Open workspace
                  </button>
                </div>
              ) : (
                scan && (
                  <>
                    <div className="filters">
                      <label className="search-field">
                        <Search size={15} />
                        <input
                          aria-label="Search findings"
                          placeholder="Search files, findings or languages…"
                          value={query}
                          onChange={(e) => setQuery(e.target.value)}
                        />
                      </label>
                      <select
                        aria-label="Filter by category"
                        value={category}
                        onChange={(e) => setCategory(e.target.value)}
                      >
                        <option value="all">All categories</option>
                        {categories.map((c) => (
                          <option key={c} value={c}>
                            {c}
                          </option>
                        ))}
                      </select>
                      <label className="checkbox-label">
                        <input
                          type="checkbox"
                          checked={showDismissed}
                          onChange={(e) => setShowDismissed(e.target.checked)}
                        />
                        Show dismissed
                      </label>
                      <span className="result-count">
                        {visible.length} results
                      </span>
                    </div>
                    <div className="review-window">
                      <nav className="signal-rail" aria-label="Candidate signals">
                        <div className="rail-head">
                          Signals · {visible.length}
                        </div>
                        {visible.length === 0 && (
                          <div className="list-empty">
                            <Search size={24} />
                            <h3>
                              {detail?.findings.length
                                ? "No matching findings"
                                : scan.status === "running"
                                  ? "Analysis in progress"
                                  : "No candidate signals recorded"}
                            </h3>
                            <p>
                              {scan.status === "running"
                                ? "Signals will appear as regions are analyzed."
                                : "No reported signals is not a guarantee that this code is secure."}
                            </p>
                          </div>
                        )}
                        {signalGroups.map(([path, items]) => (
                          <div className="rail-group" key={path}>
                            <div className="rail-group-name">
                              <span>{path}</span>
                              <span>{items.length}</span>
                            </div>
                            {items.map((f) => (
                              <button
                                key={f.id}
                                className={`signal-row ${findingId === f.id ? "selected" : ""} ${f.dismissed ? "dismissed" : ""}`}
                                onClick={() => setFindingId(f.id)}
                              >
                                <span className="signal-row-cat">
                                  {f.label}
                                </span>
                                <span className="signal-row-meta">
                                  <span
                                    className={`band-dot ${signalBand(f.priority)}`}
                                  />
                                  <strong>{percent(f.probability)}</strong>
                                  <span>
                                    L{f.start_line}-{f.end_line}
                                  </span>
                                  {f.context_missing >= 0.5 && (
                                    <span className="signal-flag warn">ctx</span>
                                  )}
                                  {f.duplicate_of && (
                                    <span className="signal-flag">overlap</span>
                                  )}
                                  {f.dismissed && (
                                    <span className="signal-flag">
                                      dismissed
                                    </span>
                                  )}
                                </span>
                              </button>
                            ))}
                          </div>
                        ))}
                      </nav>
                      <section
                        className="source-window"
                        aria-label="Reviewed source"
                      >
                        {!finding ? (
                          <div className="window-empty">
                            <Code2 size={35} strokeWidth={1} />
                            <h3>Inspect the evidence</h3>
                            <p>
                              Select a signal to see the source the model
                              reviewed,
                              <br />
                              its evidence pointers and investigation state.
                            </p>
                            <span>HUMAN REVIEW REQUIRED</span>
                          </div>
                        ) : (
                          <>
                            <div className="file-head">
                              <FileCode2 size={14} />
                              <span className="file-path">{finding.path}</span>
                              <span className="file-meta">
                                {view
                                  ? `${regions.length} region${regions.length === 1 ? "" : "s"} reviewed · ${view.language || finding.language}`
                                  : fileViewLoading
                                    ? "Loading regions…"
                                    : "Recorded regions unavailable"}
                              </span>
                            </div>
                            <div className="source-scroll">
                              {view && regions.length > 0 ? (
                                regions.map((r, i) => {
                                  const marks = markedLines(
                                    finding,
                                    r.id,
                                    r.code,
                                    r.start_line,
                                  );
                                  const signalsHere =
                                    detail?.findings.filter(
                                      (x) => x.chunk_id === r.id,
                                    ).length || 0;
                                  const focused = r.id === finding.chunk_id;
                                  return (
                                    <div className="region-block" key={r.id}>
                                      <div
                                        className={`region-tag ${focused ? "focused" : ""}`}
                                        ref={focused ? focusRegion : undefined}
                                      >
                                        <span>
                                          region {i + 1}/{regions.length} · L
                                          {r.start_line}-{r.end_line} ·{" "}
                                          {r.status === "ok"
                                            ? "assessed"
                                            : scan.status === "running"
                                              ? "queued"
                                              : "not run"}
                                          {signalsHere > 0 &&
                                            ` · ${signalsHere} signal${signalsHere === 1 ? "" : "s"}`}
                                          {r.cache_hit && " · cached"}
                                        </span>
                                      </div>
                                      <pre
                                        className="source-code region-code"
                                        aria-label="Reviewed source code"
                                      >
                                        {r.code.split("\n").map((line, j) => {
                                          const ln = r.start_line + j;
                                          const cls = marks.sink.has(ln)
                                            ? " sink-line"
                                            : marks.src.has(ln)
                                              ? " src-line"
                                              : "";
                                          return (
                                            <div
                                              className={`code-line${cls}`}
                                              key={j}
                                            >
                                              <span className="line-number">
                                                {ln}
                                              </span>
                                              <code>{line || " "}</code>
                                            </div>
                                          );
                                        })}
                                      </pre>
                                    </div>
                                  );
                                })
                              ) : fileViewLoading ? (
                                <div className="loading-line">
                                  <LoaderCircle size={16} className="spin" />
                                  Loading reviewed regions…
                                </div>
                              ) : (
                                <p className="evidence-unavailable">
                                  No recorded regions for this file. Source
                                  evidence may be unavailable.
                                </p>
                              )}
                            </div>
                          </>
                        )}
                      </section>
                      {finding && regions.length > 0 && (
                        <div className="covmap" aria-hidden="true">
                          {regions.map((r) => {
                            const signaled = detail?.findings.some(
                              (x) => x.chunk_id === r.id,
                            );
                            const cls =
                              r.id === finding.chunk_id
                                ? "seg finding"
                                : signaled
                                  ? "seg signaled"
                                  : r.status !== "ok"
                                    ? "seg pending"
                                    : "seg reviewed";
                            return (
                              <div
                                key={r.id}
                                className={cls}
                                style={{
                                  top: `${((r.start_line - fileLo) / fileSpan) * 100}%`,
                                  height: `${Math.max(2, ((r.end_line - r.start_line + 1) / fileSpan) * 100)}%`,
                                }}
                              />
                            );
                          })}
                          <span className="covmap-cap">coverage</span>
                        </div>
                      )}
                    </div>
                    {finding && (
                      <div className="assessment-dock">
                        <div className="dock-id">
                          <span className="dock-cat">
                            {finding.label}
                            <span
                              className={`severity ${signalBand(finding.priority)}`}
                            >
                              {signalBand(finding.priority)}
                            </span>
                          </span>
                          <span className="dock-loc">
                            {finding.path} · L{finding.start_line}-
                            {finding.end_line}
                            {finding.dismissed ? " · dismissed" : ""}
                          </span>
                        </div>
                        <div className="dock-score">
                          <strong>{percent(finding.probability)}</strong>
                          <span>probability</span>
                        </div>
                        <div className="dock-score">
                          <strong>{impactLabel(finding.impact)}</strong>
                          <span>model impact</span>
                        </div>
                        <div className="dock-score">
                          <strong
                            className={
                              finding.context_missing >= 0.5 ? "amber-text" : ""
                            }
                          >
                            {percent(finding.context_missing)}
                          </strong>
                          <span>ctx missing</span>
                        </div>
                        <div className="dock-score">
                          <strong>{percent(finding.priority)}</strong>
                          <span>priority wt</span>
                        </div>
                        <div className="dock-chain">
                          {finding.source && (
                            <div className="dock-chain-row">
                              <span className="dock-role src">source</span>
                              <code>{finding.source}</code>
                            </div>
                          )}
                          {finding.sink && (
                            <div className="dock-chain-row">
                              <span className="dock-role sink">sink</span>
                              <code>{finding.sink}</code>
                            </div>
                          )}
                          {finding.duplicate_of && (
                            <div className="dock-chain-row">
                              <span className="dock-role">overlap</span>
                              <span>
                                shares evidence with another region
                              </span>
                            </div>
                          )}
                          {!finding.source &&
                            !finding.sink &&
                            !finding.duplicate_of && (
                              <div className="dock-chain-row">
                                <span className="dock-role">ptrs</span>
                                <span className="dock-none">
                                  no pointers reported
                                </span>
                              </div>
                            )}
                        </div>
                        <div className="dock-actions">
                          <button
                            className="small-button"
                            onClick={() => setDrawerOpen((v) => !v)}
                          >
                            {drawerOpen
                              ? "Hide evidence"
                              : "Evidence & investigation"}
                          </button>
                          <button
                            className="small-button"
                            disabled={!!busy}
                            onClick={() => dismiss(finding)}
                          >
                            <Busy active={busy === "dismiss"} />
                            {finding.dismissed ? "Restore" : "Dismiss"}
                          </button>
                        </div>
                      </div>
                    )}
                    {finding && drawerOpen && (
                      <div className="evidence-drawer">
                        <div className="region-notice">
                          <CircleHelp size={14} />
                          <span>
                            Lines {finding.start_line}-{finding.end_line} are
                            the <strong>reviewed region</strong>, not a
                            pinpointed vulnerability. Scores are model signals;
                            priority weight blends them for ordering, and
                            evidence pointers name candidate identifiers, none
                            are proven impact or exploitability.
                          </span>
                        </div>
                        {finding.context_missing >= 0.5 && (
                          <div className="context-notice">
                            <TriangleAlert size={15} />
                            Model-reported missing context, not proof of absent
                            metadata. Inspect callers, helpers and configuration
                            before deciding.
                          </div>
                        )}
                        {finding.duplicate_of && (
                          <div className="context-notice">
                            <TriangleAlert size={15} />
                            Overlapping regions flagged the same category; this
                            candidate shares evidence with another region and
                            is not counted twice.
                          </div>
                        )}
                        <InvestigationPanel
                          key={finding.id}
                          findingId={finding.id}
                          keyConfigured={!!settings?.key_configured}
                          disabled={
                            !!busy || !!running || investigationBlocked
                          }
                          activeInvestigation={activeInvestigation}
                          originalScore={finding.probability}
                          contextMissing={finding.context_missing}
                          onSetupKey={() => setPage("settings")}
                          onStarted={investigationStarted}
                        />
                        {evidenceLoading ? (
                          <div className="loading-line">
                            <LoaderCircle size={16} className="spin" />
                            Loading source evidence…
                          </div>
                        ) : evidence ? (
                          <div className="raw-evidence">
                            <details>
                              <summary>
                                Raw request <span>JSON</span>
                                <ChevronRight size={14} />
                              </summary>
                              <Json value={evidence.request_json} />
                            </details>
                            <details>
                              <summary>
                                Raw response <span>JSON</span>
                                <ChevronRight size={14} />
                              </summary>
                              <Json value={evidence.response_json} />
                            </details>
                          </div>
                        ) : (
                          <p className="evidence-unavailable">
                            Source evidence could not be loaded. Select another
                            signal to retry.
                          </p>
                        )}
                      </div>
                    )}
                  </>
                )
              )}
            </div>
          )}
        </main>
    </div>
  );
}
