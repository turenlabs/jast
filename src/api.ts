import { invoke, isTauri } from "@tauri-apps/api/core";

export interface Settings {
  key_configured: boolean;
  key_error: string | null;
  model: string;
  threshold: number;
  check_count: number;
  supported_languages: string[];
  privacy_notice: string;
}
export interface Preview {
  id: string;
  repo_name: string;
  repo_path: string;
  files: number;
  chunks: number;
  bytes: number;
  estimated_tokens: number;
  exclusions: { path: string; reason: string }[];
  excluded_count: number;
  unsupported_count: number;
  limit_reached: boolean;
  limit_reasons: string[];
  exclusion_reasons: Record<string, number>;
  checks: string[];
  languages: { language: string; files: number; chunks: number; check_count: number }[];
  warnings: string[];
  regions: { id: string; path: string; start_line: number; end_line: number; language: string; check_count: number }[];
  context_files: number;
}
export interface Coverage {
  included_files: number;
  planned_regions: number;
  excluded_count: number;
  unsupported_count: number;
  limit_reached: boolean;
  limit_reasons: string[];
  exclusion_reasons: Record<string, number>;
  exclusions: { path: string; reason: string }[];
  context_files: number;
  warnings: string[];
  context_policy: string;
}
export interface Scan {
  id: string;
  repo_name: string;
  repo_path: string;
  status: "running" | "completed" | "cancelled" | "interrupted" | "failed";
  total: number;
  completed: number;
  cached: number;
  findings: number;
  coverage: Coverage | null;
  uncertain_regions: number;
  created_at: number;
  error: string | null;
  // null on scans that predate the configurable threshold; they ran 0.5.
  threshold: number | null;
}
export interface Finding {
  language: string;
  id: string;
  chunk_id: string;
  path: string;
  start_line: number;
  end_line: number;
  category: string;
  label: string;
  severity: "high" | "medium" | "low";
  probability: number;
  context_missing: number;
  sink: string | null;
  source: string | null;
  impact: number | null;
  priority: number;
  duplicate_of: string | null;
  dismissed: boolean;
}
export interface Evidence {
  language: string;
  path: string;
  start_line: number;
  end_line: number;
  code: string;
  request_json: string;
  response_json: string | null;
}
export interface ScanDetail {
  scan: Scan;
  findings: Finding[];
}
export interface FileRegion {
  id: string;
  start_line: number;
  end_line: number;
  code: string;
  status: string;
  cache_hit: boolean;
}
export interface FileView {
  path: string;
  language: string;
  regions: FileRegion[];
}
export interface InvestigationChunk {
  id: string;
  path: string;
  start_line: number;
  end_line: number;
  code: string;
  request_json: string;
  request_sha256: string;
}
export interface InvestigationContext {
  id: string;
  source_chunk_id: string;
  path: string;
  start_line: number;
  end_line: number;
  code: string;
  request_sha256: string;
}
export interface Investigation {
  id: string;
  scan_id: string;
  finding_id: string;
  status: "running" | "completed" | "cancelled" | "interrupted" | "failed";
  outcome: "model_supported" | "model_not_supported" | "unresolved" | null;
  created_at: number;
  max_rounds: 3;
  error: string | null;
  steps: {
    round: number;
    request_sha256: string;
    request_json: string;
    response_json: string;
    action: string;
    claim_supported: number;
    evidence_sufficient: number;
    action_confidence: number;
  }[];
  plan: {
    target: { finding_id: string; category: string; label: string; chunk: InvestigationChunk };
    candidates: InvestigationContext[];
    warnings: string[];
  };
}
export const desktop = isTauri();
export function command<T>(
  name: string,
  args?: Record<string, unknown>,
): Promise<T> {
  if (!desktop)
    return Promise.reject(
      new Error("Desktop required. Open JAST for native repository access."),
    );
  return invoke<T>(name, args);
}
export function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
