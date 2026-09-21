import { useEffect, useState } from "react";
import { ChevronRight, FileCode2, LoaderCircle } from "lucide-react";
import { command, message, type Evidence, type Preview } from "./api";

export default function PreviewSource({ preview }: { preview: Preview }) {
  const [region, setRegion] = useState("");
  const [evidence, setEvidence] = useState<Evidence | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => {
    setEvidence(null);
    setError("");
    if (!region) return;
    let alive = true;
    setLoading(true);
    command<Evidence>("get_preview_evidence", {
      previewId: preview.id,
      chunkId: region,
    })
      .then((value) => {
        if (alive) setEvidence(value);
      })
      .catch((e) => {
        if (alive) setError(message(e));
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
  }, [preview.id, region]);
  return (
    <details className="preview-source">
      <summary>
        <FileCode2 size={15} />
        Inspect included source before uploading{" "}
        <span>{preview.regions.length} regions</span>
        <ChevronRight size={14} />
      </summary>
      <p>
        These are the exact snapshot regions available for upload: whole files
        where they fit, otherwise byte-bounded regions with overlap. Helpers and
        callers are not automatically retrieved.
      </p>
      <div className="preview-source-grid">
        <div className="region-list" aria-label="Included source regions">
          {preview.regions.map((item) => (
            <button
              key={item.id}
              className={region === item.id ? "selected" : ""}
              onClick={() => setRegion(item.id)}
            >
              <span>{item.path}</span>
              <small>
                {item.language} · L{item.start_line}-{item.end_line}
              </small>
            </button>
          ))}
        </div>
        <div className="preview-code">
          {loading ? (
            <div className="loading-line">
              <LoaderCircle className="spin" size={15} />
              Loading snapshot…
            </div>
          ) : error ? (
            <p className="warning-text" role="alert">
              {error}
            </p>
          ) : evidence ? (
            <>
              <div className="source-title">
                <FileCode2 size={14} />
                <span>{evidence.path}</span>
                <span>{evidence.language}</span>
              </div>
              <div
                className="source-code"
                tabIndex={0}
                aria-label="Preview source code"
              >
                {evidence.code.split("\n").map((line, i) => (
                  <div className="code-line" key={i}>
                    <span className="line-number">
                      {evidence.start_line + i}
                    </span>
                    <code>{line || " "}</code>
                  </div>
                ))}
              </div>
              <details>
                <summary>
                  Exact upload request <ChevronRight size={13} />
                </summary>
                <pre className="raw-json">{evidence.request_json}</pre>
              </details>
            </>
          ) : (
            <p>
              Select a region to inspect its source and exact request. Nothing
              is uploaded by previewing.
            </p>
          )}
        </div>
      </div>
    </details>
  );
}
