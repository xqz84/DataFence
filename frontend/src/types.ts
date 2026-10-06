export type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type UserRole = "admin" | "analyst" | "viewer" | "business";
export interface AuthUser {
  username: string;
  role: UserRole;
  employee_id?: string | null;
}
export interface AuthSession {
  token: string;
  user: AuthUser;
}
export interface AuthStatus {
  authentication_required: boolean;
  initialized: boolean;
  bootstrap_allowed?: boolean;
}
export interface Employee {
  id: string;
  name: string;
  role: string;
  department: string;
  region: string;
  known_device: string;
  baseline_daily_records: number;
  baseline_daily_queries: number;
  synthetic: true;
}
export interface BusinessTask {
  id: string;
  employee_id: string;
  purpose: string;
  regions: string[];
  max_records: number;
  valid_from: string;
  valid_until: string;
  allowed_hours: number[];
  approved_channels: string[];
  allow_export: boolean;
}
export interface AccessTask extends BusinessTask {
  quota_scope: "task_lifetime";
  quota: Pick<
    QuotaDecision,
    | "scope"
    | "limit"
    | "reserved_records"
    | "confirmed_records"
    | "used_records"
    | "remaining_records"
    | "metric"
  >;
}
export interface AccessRequest {
  request_id: string;
  task_id: string;
  operation: "query" | "export";
  record_count: number;
  regions: string[];
}
export interface SyntheticCustomer {
  id: string;
  name: string;
  contact: string;
  identity_ref: string;
  region: string;
  employee_id: string;
  synthetic: true;
}
export interface AccessResult {
  request_id: string;
  actor: string;
  task_id: string;
  operation: "query" | "export";
  allowed: boolean;
  delivered_records: number;
  requested_records: number;
  synthetic: true;
  created_at: string;
  analysis: Analysis;
  quota: QuotaDecision;
  cloud_called: false;
  policy_version: string;
  evidence_hash: string;
  replayed?: boolean;
  rows?: SyntheticCustomer[];
  csv?: string;
}
export interface SecurityEvent {
  event_id: string;
  session_id: string;
  employee_id: string;
  timestamp: string;
  event_type: string;
  task_id: string | null;
  purpose: string;
  resource: string;
  record_count: number;
  regions: string[];
  device_id: string;
  sensitivity: number;
  channel: string;
  object_id: string | null;
  parent_object_id: string | null;
  prompt: string | null;
}
export interface Intent {
  role_match: number;
  purpose_match: number;
  scope_match: number;
  time_match: number;
  trust: number;
  status: "supported" | "mismatch" | "insufficient_evidence";
  evidence: string[];
}
export interface ChainNode {
  event_id: string;
  event_type: string;
  timestamp: string;
  risk_score: number;
  blocked: boolean;
}
export interface Analysis {
  event_id: string;
  risk_score: number;
  risk_level: RiskLevel;
  dimensions: Record<string, number>;
  intent: Intent;
  rules: string[];
  anomaly_score: number;
  explanation: string;
  actions: string[];
  blocked: boolean;
  chain: ChainNode[];
  analysis_source: string;
  processing_ms: number;
  model_version: string;
}
export interface EventRecord {
  event: SecurityEvent;
  analysis: Analysis;
  run_id: string;
  outcome: string;
  detected_at: string;
  responded_at: string;
  evidence_hash: string;
  previous_hash: string;
  executed_records?: number;
  receipt_hash?: string;
  response_actions?: { action: string; status: string }[];
  ai_analysis?: AiAnalysis;
  semantic_analysis?: SemanticAnalysis | null;
  execution_completed_at?: string | null;
  ai_completed_at?: string | null;
  persisted_at?: string | null;
  quota_decision?: QuotaDecision | null;
}
export interface QuotaDecision {
  allowed: boolean;
  applicable: boolean;
  status:
    | "reserved"
    | "confirmed"
    | "cancelled"
    | "rejected"
    | "not_applicable";
  reservation_id: string | null;
  event_id: string;
  task_id: string | null;
  employee_id: string;
  already_seen: boolean;
  requested_records: number;
  limit: number | null;
  reserved_records: number | null;
  confirmed_records: number | null;
  used_records: number | null;
  remaining_records: number | null;
  reason: string;
  metric: "accepted_request_records";
  scope: "session" | "task_lifetime" | null;
}
export interface SemanticAnalysis
  extends Omit<AiAnalysis, "evidence_event_ids" | "suggested_actions"> {
  verdict?: "unsafe" | "safe" | "uncertain";
  interpretation?: "execute" | "negated" | "quoted" | "summary" | "unknown";
  evidence_quote?: string;
  reason?: string;
}
export interface AiAnalysis {
  reused_semantic?: boolean;
  status:
    | "not_configured"
    | "skipped"
    | "completed"
    | "unavailable"
    | "invalid_response";
  summary: string;
  evidence_event_ids: string[];
  suggested_actions: string[];
  elapsed_ms: number;
  model: string | null;
  provider?: "sensenova" | "ollama";
  reason_code?: string | null;
  usage?: {
    prompt_tokens: number;
    completion_tokens: number;
    total_tokens: number;
  } | null;
}
export interface Run {
  id: string;
  scenario_id: string;
  employee_id: string;
  status: "running" | "completed" | "failed" | "interrupted";
  created_at: string;
  finished_at: string | null;
  planned_events: number;
  processed_events: number;
  blocked_events: number;
  skipped_events: number;
  sink_records: number;
  max_risk: number;
  error: string | null;
  phase?:
    | "queued"
    | "detecting"
    | "semantic_review"
    | "model_explanation"
    | "completed"
    | "failed";
  phase_started_at?: string | null;
  current_event_type?: string | null;
}
export interface Scenario {
  id: string;
  name: string;
  description: string;
  steps: string[];
}
export interface SimulationRequest {
  scenario_id: string;
  employee_id: string;
  record_count: number;
  interval_ms: number;
  seed: number;
  export: boolean;
  compress: boolean;
  upload: boolean;
}
export interface Overview {
  total_events: number;
  abnormal_events: number;
  high_risk_events: number;
  blocked_events: number;
  sensitive_records: number;
  active_runs: number;
  risk_distribution: Record<RiskLevel, number>;
  recent_events: EventRecord[];
  top_users: {
    employee_id: string;
    name: string;
    risk_score: number;
    event_count: number;
  }[];
  trend: { hour: string; events: number; risk: number }[];
  bank: Record<string, number>;
  synthetic: true;
}
export interface Health {
  status: string;
  version: string;
  synthetic: true;
  deployment?: { network_mode: string; authentication: string };
  llm: {
    enabled: boolean;
    status: string;
    model?: string | null;
    provider?: "sensenova" | "ollama";
    last_call?: {
      status: AiAnalysis["status"];
      reason_code: string | null;
      elapsed_ms: number;
      at: string;
    } | null;
    budget?: {
      date: string;
      requests: number;
      request_limit: number;
      charged_tokens: number;
      reserved_tokens: number;
      token_limit: number;
    } | null;
  };
  model: Record<string, unknown>;
}
export interface EmployeeDetail {
  employee: Employee;
  tasks: BusinessTask[];
  events: EventRecord[];
  baseline: { daily_records: number; daily_queries: number };
  current: {
    records: number;
    queries: number;
    regions: number;
    exports: number;
  };
  latest_intent: Intent | null;
}
export interface Metrics {
  precision: number | null;
  recall: number | null;
  f1: number | null;
  fpr: number | null;
  tp: number;
  fp: number;
  tn: number;
  fn: number;
}
export interface EvaluationReport {
  id: string;
  created_at: string;
  seed: number;
  sessions: number;
  event_count: number;
  attack_events: number;
  normal_events: number;
  metrics: Metrics;
  latency: {
    processing_ms_p50: number | null;
    processing_ms_p95: number | null;
    detection_delay_seconds_p50: number | null;
    missed_sessions: number;
    response_ms_p50?: number | null;
    response_ms_p95?: number | null;
  };
  per_scenario: {
    scenario_id: string;
    sessions: number;
    detected: number;
    recall: number | null;
    attack_sessions?: number;
    normal_sessions?: number;
    false_alert_sessions?: number;
    false_positive_rate?: number | null;
  }[];
  ablations: {
    mode: string;
    precision: number | null;
    recall: number | null;
    f1: number | null;
    fpr: number | null;
  }[];
  artifacts: Record<string, unknown>;
  limitations: string[];
  versions: Record<string, unknown>;
  [key: string]: unknown;
}
export interface EvaluationJob {
  id: string;
  status: string;
  report: EvaluationReport | null;
  error: string | null;
}
export interface Agent {
  id: string;
  name: string;
  status: string;
  description: string;
  implementation: string;
}
export interface Assets {
  manifest: Record<string, unknown>;
  assets: {
    name: string;
    label: string;
    count: number;
    sensitivity: string | number;
    synthetic: true;
  }[];
}
export interface Policies {
  version: string;
  weights: Record<string, number>;
  levels: { name: string; min: number; max: number; actions: string[] }[];
  llm_enabled: boolean;
}
