import { useEffect, useRef, useState } from "react";
import { command, desktop, message, type Investigation, type InvestigationContext } from "./api";

const score = (value?: number) =>
  typeof value === "number" ? `${(value * 100).toFixed(1)}%` : "-";

const outcomeLabel = (value: Investigation["outcome"]) =>
  value === "model_supported"
    ? "Evidence supports this candidate"
    : value === "model_not_supported"
      ? "No support found in saved context"
      : value === "unresolved"
        ? "JAST could not decide"
        : "Assessment pending";

const friendlyError = (error: unknown) => {
  const text = message(error);
  return /HTTP 503|TypeSafe returned HTTP 503/i.test(text)
    ? "TypeSafe is temporarily unavailable (503). Try again in a moment."
    : text;
};

const relativeTime = (createdAt: number) => {
  const seconds = Math.max(0, Math.floor(Date.now() / 1000 - createdAt));
  if (seconds < 60) return "just now";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
};

const historyStatus = (item: Investigation) => {
  if (item.status === "running") return "In progress";
  if (item.status === "cancelled") return "Cancelled";
  if (item.status === "failed" || item.status === "interrupted") {
    return "Could not complete";
  }
  return outcomeLabel(item.outcome);
};

const resultTitle = (item: Investigation) => {
  if (item.status === "running") {
    return `JAST is checking related code… round ${Math.min(item.steps.length + 1, item.max_rounds)}/${item.max_rounds}`;
  }
  if (item.status === "failed" || item.status === "interrupted") {
    return "TypeSafe could not complete this check";
  }
  if (item.status === "cancelled") return "Investigation cancelled";
  return outcomeLabel(item.outcome);
};

const resultDetail = (item: Investigation) => {
  if (item.status === "running") {
    return "JAST is reviewing saved context. Your original scan score stays unchanged.";
  }
  if (item.status === "failed" || item.status === "interrupted") {
    return "No review result was recorded. You can start a new review when ready.";
  }
  if (item.status === "cancelled") {
    return "No review result was recorded. Start a new review when ready.";
  }
  if (item.outcome === "model_supported") {
    return "This assessment is based on saved context. Your original scan score stays unchanged.";
  }
  if (item.outcome === "model_not_supported") {
    return "This assessment found no supporting context. Your original scan score stays unchanged.";
  }
  return "The saved context was not enough for a decision. Your original scan score stays unchanged.";
};

const contextStatus = (value?: number) => {
  if (typeof value !== "number") return "Status unavailable";
  return value >= 0.5 ? "More context may help" : "No context gap flagged";
};

function Raw({ value }: { value: string }) {
  return <pre className="raw-json">{value || "No response recorded."}</pre>;
}

function ContextEvidence({ context }: { context: InvestigationContext }) {
  return (
    <div className="investigation-evidence">
      <p>
        {context.path}:L{context.start_line}-{context.end_line}
      </p>
      <p>
        Source chunk: <code>{context.source_chunk_id}</code>
      </p>
      <p>
        Request SHA-256: <code>{context.request_sha256}</code>
      </p>
      <Raw value={context.code} />
    </div>
  );
}

export default function InvestigationPanel({
  findingId,
  keyConfigured,
  disabled,
  activeInvestigation,
  onStarted,
  originalScore,
  contextMissing,
  onSetupKey,
}: {
  findingId: string;
  keyConfigured: boolean;
  disabled: boolean;
  activeInvestigation: Investigation | null;
  onStarted: (value: Investigation) => void;
  originalScore?: number;
  contextMissing?: number;
  onSetupKey?: () => void;
}) {
  const [consent, setConsent] = useState(false);
  const [starting, setStarting] = useState(false);
  const [history, setHistory] = useState<Investigation[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [reload, setReload] = useState(0);
  const alive = useRef(true);
  const startingRef = useRef(false);
  const consentInput = useRef<HTMLInputElement>(null);

  useEffect(() => {
    alive.current = true;
    return () => {
      alive.current = false;
    };
  }, []);

  useEffect(() => {
    let current = true;
    setConsent(false);
    setLoading(true);
    setError("");
    command<Investigation[]>("list_investigations", { findingId })
      .then((items) => {
        if (!current) return;
        setHistory(items);
        setSelectedId((id) =>
          items.some((item) => item.id === id) ? id : items[0]?.id || null,
        );
      })
      .catch((e) => {
        if (current) setError(`Review history could not be loaded: ${friendlyError(e)}`);
      })
      .finally(() => {
        if (current) setLoading(false);
      });
    return () => {
      current = false;
    };
  }, [findingId, reload]);

  const relevantActive =
    activeInvestigation?.finding_id === findingId ? activeInvestigation : null;

  useEffect(() => {
    if (relevantActive) {
      setHistory((items) => [
        relevantActive,
        ...items.filter((item) => item.id !== relevantActive.id),
      ]);
    }
  }, [relevantActive]);

  const items = relevantActive
    ? [relevantActive, ...history.filter((item) => item.id !== relevantActive.id)]
    : history;
  const selected = items.find((item) => item.id === selectedId) || items[0];
  const investigating = starting || relevantActive?.status === "running";
  const disabledReason = starting
    ? "JAST is preparing the review…"
    : !desktop
      ? "Open the JAST desktop app to review saved context."
      : !keyConfigured
        ? "Set up an API key before starting this review."
        : relevantActive?.status === "running"
          ? "JAST is already checking this candidate."
          : disabled
            ? "Another scan or review is in progress."
            : !consent
              ? "Check the consent box to continue."
              : "";

  async function start() {
    if (startingRef.current || disabled || !consent || !keyConfigured || !desktop) return;
    startingRef.current = true;
    setStarting(true);
    setError("");
    try {
      const value = await command<Investigation>("start_investigation", {
        findingId,
        consent: true,
      });
      // Root ownership survives panel unmount or a different selected finding.
      onStarted(value);
      if (alive.current) {
        setHistory((items) => [value, ...items.filter((item) => item.id !== value.id)]);
        setSelectedId(value.id);
        setConsent(false);
      }
    } catch (e) {
      if (alive.current) setError(friendlyError(e));
    } finally {
      startingRef.current = false;
      if (alive.current) setStarting(false);
    }
  }

  function retry() {
    setConsent(false);
    setError("");
    consentInput.current?.focus();
  }

  return (
    <section className="investigation-panel" aria-label="Candidate investigation">
      <div className="investigation-heading">
        <div>
          <p className="investigation-eyebrow">CANDIDATE REVIEW</p>
          <h2>Investigate candidate</h2>
        </div>
        <span className="investigation-tag">Review result</span>
      </div>

      <div className="investigation-flow" aria-label="Investigation steps">
        <section className="investigation-flow-step">
          <div className="investigation-step-heading">
            <span className="investigation-step-number">1</span>
            <div>
              <h3>Review candidate</h3>
              <p>Start with the score and context signal from the original scan.</p>
            </div>
          </div>
          <div className="investigation-review-grid">
            <div>
              <span>Original scan score</span>
              <strong>{score(originalScore)}</strong>
              <small>Stays unchanged</small>
            </div>
            <div>
              <span>Context status</span>
              <strong>{contextStatus(contextMissing)}</strong>
              <small>
                {typeof contextMissing === "number"
                  ? `Scan context signal: ${score(contextMissing)}`
                  : "From the original scan"}
              </small>
            </div>
          </div>
          <p className="investigation-helper">
            This review is separate from the scan result. It will not dismiss or
            rewrite this candidate.
          </p>
        </section>

        <section className="investigation-flow-step">
          <div className="investigation-step-heading">
            <span className="investigation-step-number">2</span>
            <div>
              <h3>Let JAST inspect saved context</h3>
              <p>
                This does not change the scan result. It asks Jev to inspect up
                to two related snippets already captured in this scan.
              </p>
            </div>
          </div>
          <label className="checkbox-label investigation-consent">
            <input
              ref={consentInput}
              type="checkbox"
              checked={consent}
              disabled={disabled || starting}
              aria-label="Authorize JAST to inspect saved context"
              onChange={(e) => setConsent(e.target.checked)}
            />
            <span>
              I authorize JAST to review those saved snippets for this candidate.
            </span>
          </label>
          <details className="investigation-info">
            <summary>What will JAST use?</summary>
            <p>
              Only related code already stored with this scan is used. JAST does
              not browse your repository, run code, or change the original scan.
            </p>
            <p>
              The review can make up to three short passes and produces an
              assessment for you to consider.
            </p>
          </details>
          <div className="investigation-actions">
            <button
              type="button"
              className="primary"
              disabled={!desktop || !keyConfigured || !consent || disabled || starting}
              aria-describedby={disabledReason ? "investigation-disabled-reason" : undefined}
              onClick={() => void start()}
            >
              {investigating ? "Investigating…" : "Authorize and investigate"}
            </button>
            {!keyConfigured && (
              <button
                type="button"
                className="investigation-setup"
                disabled={!onSetupKey}
                onClick={() => onSetupKey?.()}
              >
                Set up API key
              </button>
            )}
          </div>
          {disabledReason && (
            <p className="investigation-disabled" id="investigation-disabled-reason" role="status">
              {disabledReason}
            </p>
          )}
          {error && (
            <p className="warning-text investigation-error" role="alert">
              {friendlyError(error)}
            </p>
          )}
        </section>

        <section className="investigation-flow-step investigation-result-step">
          <div className="investigation-step-heading">
            <span className="investigation-step-number">3</span>
            <div>
              <h3>Read result</h3>
              <p>Use the assessment as another review signal, not a replacement for the scan.</p>
            </div>
          </div>
          {selected ? (
            <div
              className={`investigation-result ${
                selected.status === "completed" ? selected.outcome || "unresolved" : selected.status
              }`}
              role={selected.status === "failed" || selected.status === "interrupted" ? "alert" : "status"}
            >
              <strong>{resultTitle(selected)}</strong>
              <span>{resultDetail(selected)}</span>
              {(selected.status === "failed" ||
                selected.status === "interrupted" ||
                selected.status === "cancelled") && (
                <button type="button" className="investigation-retry" onClick={retry}>
                  Retry new investigation
                </button>
              )}
            </div>
          ) : (
            <div className="investigation-result empty">
              <strong>No review result yet</strong>
              <span>Authorize the review above to see an assessment here.</span>
            </div>
          )}
          {selected?.error && (
            <p className="warning-text investigation-error">{friendlyError(selected.error)}</p>
          )}
        </section>
      </div>

      <div className="investigation-history">
        <div className="investigation-history-heading">
          <h3>Review history</h3>
          <button
            type="button"
            className="small-button"
            disabled={loading || starting}
            onClick={() => setReload((n) => n + 1)}
          >
            Refresh history
          </button>
        </div>
        {loading && <p role="status">Loading review history…</p>}
        {!loading && !items.length && !error && <p>No reviews recorded for this candidate.</p>}
        <div className="investigation-runs">
          {items.map((item) => (
            <button
              key={item.id}
              type="button"
              className={selected?.id === item.id ? "selected" : ""}
              aria-pressed={selected?.id === item.id}
              onClick={() => setSelectedId(item.id)}
            >
              <span>{relativeTime(item.created_at)}</span>
              <span>{historyStatus(item)}</span>
            </button>
          ))}
        </div>
      </div>

      {selected && (
        <details className="technical-trace">
          <summary>Technical trace</summary>
          <div className="technical-trace-body">
            <p>
              Review record <code>{selected.id}</code> · Scan <code>{selected.scan_id}</code> ·
              Candidate <code>{selected.finding_id}</code>
            </p>
            <details>
              <summary>Saved source details</summary>
              <p>
                {selected.plan.target.chunk.path}:L{selected.plan.target.chunk.start_line}-
                {selected.plan.target.chunk.end_line}
              </p>
              <p>
                Chunk: <code>{selected.plan.target.chunk.id}</code> · Request SHA-256:{" "}
                <code>{selected.plan.target.chunk.request_sha256}</code>
              </p>
              <Raw value={selected.plan.target.chunk.code} />
              <details>
                <summary>Original scan request</summary>
                <Raw value={selected.plan.target.chunk.request_json} />
              </details>
            </details>
            <details>
              <summary>Related saved snippets ({selected.plan.candidates.length})</summary>
              <p>
                These are related snippets available from this scan. They are not a
                complete call graph.
              </p>
              {!selected.plan.candidates.length && <p>No related context was available.</p>}
              {selected.plan.candidates.map((context) => (
                <details key={context.id}>
                  <summary>
                    {context.id} · {context.path}:L{context.start_line}-{context.end_line}
                  </summary>
                  <ContextEvidence context={context} />
                </details>
              ))}
            </details>
            {selected.plan.warnings.map((warning, i) => (
              <p className="warning-text" key={i}>{warning}</p>
            ))}
            {!selected.steps.length && (
              <p>
                {selected.status === "running"
                  ? "No assessment rounds recorded yet."
                  : "No detailed rounds were recorded."}
              </p>
            )}
            {selected.steps.map((step) => {
              const context = step.action.startsWith("read:")
                ? selected.plan.candidates.find((item) => item.id === step.action.slice(5))
                : null;
              const evidenceSelected = step.action.startsWith("read:");
              return (
                <details key={step.round} open className="investigation-step">
                  <summary>
                    {evidenceSelected ? "Evidence selected" : "Final assessment"} · Round {step.round}/
                    {selected.max_rounds}
                  </summary>
                  <p>
                    {evidenceSelected
                      ? "JAST selected related saved context for this review pass."
                      : "JAST recorded the review assessment for this pass."}
                  </p>
                  <p>
                    Support signal: {score(step.claim_supported)} · Context fit: {score(step.evidence_sufficient)} ·
                    Confidence: {score(step.action_confidence)}
                  </p>
                  <p>
                    Technical action: <code>{step.action}</code> · Request SHA-256:{" "}
                    <code>{step.request_sha256}</code>
                  </p>
                  {context && (
                    <details>
                      <summary>Selected related snippet</summary>
                      <ContextEvidence context={context} />
                    </details>
                  )}
                  <details>
                    <summary>Request details</summary>
                    <Raw value={step.request_json} />
                  </details>
                  <details>
                    <summary>Response details</summary>
                    <Raw value={step.response_json} />
                  </details>
                </details>
              );
            })}
          </div>
        </details>
      )}
    </section>
  );
}
