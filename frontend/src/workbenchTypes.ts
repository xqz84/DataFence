export interface KnowledgeStatus {
  version: string;
  document_count: number;
  sha256: string;
  retrieval: string;
  network_access: false;
  scope: string;
  grants_permissions: false;
}
export interface KnowledgeDocument {
  id: string;
  title: string;
  category: string;
  version: string;
  source_title: string;
  source_ref: string;
  source_kind: string;
  sha256: string;
  summary: string;
  content: string;
  tags: string[];
}
export interface KnowledgeHit
  extends Omit<KnowledgeDocument, "content" | "summary" | "tags"> {
  excerpt: string;
  score: number;
  match_reasons: string[];
}
export interface KnowledgeSearch {
  query: string;
  answered: boolean;
  answer: string | null;
  matches: KnowledgeHit[];
  reason:
    | "matched_project_policy"
    | "no_reliable_match"
    | "empty_query"
    | "out_of_scope";
  version: string;
}
export interface WorkbenchModule {
  id: string;
  name: string;
  implementation: string;
  execution_kind: "deterministic" | "local_ml";
  status: "evidence_available" | "no_observations";
  description: string;
  evaluated_events: number;
  evidence_event_ids: string[];
  findings: {
    event_id: string;
    summary: string;
    values: Record<string, string | number | boolean | null>;
    knowledge_ids: string[];
  }[];
}
export interface AgentWorkbenchData {
  version: string;
  scope: string;
  event_count: number;
  latest_event_id: string | null;
  selected_event_id: string | null;
  knowledge: KnowledgeStatus;
  modules: WorkbenchModule[];
  related_knowledge: KnowledgeHit[];
  limitations: string[];
  llm: {
    configured: boolean;
    provider: string | null;
    model: string | null;
    configuration_status: string;
    completed_calls: number;
    failed_calls: number;
    skipped_records: number;
    not_configured_records: number;
    last_status: string | null;
    call_records: {
      event_id: string;
      purpose: "semantic" | "advisory";
      status: string;
      provider: string | null;
      model: string | null;
      elapsed_ms: number | null;
      reason_code: string | null;
    }[];
  };
}
export type Disposition =
  | "confirmed_risk"
  | "false_positive"
  | "needs_investigation";
export interface EventReview {
  event_id: string;
  revision: number;
  current: ReviewEntry | null;
  history: ReviewEntry[];
}
export interface ReviewEntry {
  revision: number;
  disposition: Disposition;
  note: string;
  actor: string;
  created_at: string;
  event_evidence_hash: string;
  hash: string;
}
export interface Demo {
  id: string;
  status:
    | "running"
    | "awaiting_review"
    | "completed"
    | "failed"
    | "interrupted";
  created_at: string;
  finished_at: string | null;
  actor: string;
  employee_id: string;
  mode: "local";
  steps: {
    id: string;
    title: string;
    status: "queued" | "running" | "completed" | "failed" | "interrupted";
    run_id: string | null;
    passed: boolean | null;
    summary: string;
    blocked_events: number;
    processed_events: number;
    skipped_events: number;
    sink_records: number;
  }[];
  selected_event_id: string | null;
  checks: { id: string; title: string; passed: boolean; detail: string }[];
  audit: { valid: boolean; checked_events: number } | null;
  review_revision: number | null;
  error: string | null;
}
