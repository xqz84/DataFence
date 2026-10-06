import { useEffect, useId, useRef, useState } from "react";
import { ArrowLeft, ArrowRight, CheckCircle2, ChevronLeft, ChevronRight, Clock3, FileCheck2, LoaderCircle, RefreshCw, Search, ShieldBan, SlidersHorizontal, X } from "lucide-react";
import type { PageProps } from "./App";
import type { Analysis, EventRecord, RiskLevel, SecurityEvent } from "./types";
import type { Disposition, EventReview, KnowledgeHit } from "./workbenchTypes";
import { api, ApiError } from "./api";
import { requestId } from "./requestId";
import { ACTION_NAMES, Badge, Empty, ErrorNotice, EVENT_NAMES, Loading, num, time, useApi } from "./ui";

type QueueStatus = "all" | "pending" | "investigating" | "resolved";
interface Observation {
  key: string;
  source: "simulation" | "gateway" | "import";
  source_id: string;
  source_label: string;
  control_mode: "enforced" | "simulated" | "observe";
  event_id: string;
  request_id: string | null;
  employee_id: string;
  employee_name: string;
  actor: string;
  task_id: string | null;
  operation: string;
  occurred_at: string;
  observed_at: string;
  risk_score: number;
  risk_level: RiskLevel;
  decision: "allowed" | "blocked" | "observed";
  requested_records: number;
  delivered_records: number;
  status: QueueStatus;
  review_revision: number;
  evidence_hash: string;
  summary: string;
  run_id: string | null;
  batch_id: string | null;
  requires_review: boolean;
}
interface QueueResponse {
  items: Observation[];
  total: number;
  limit: number;
  offset: number;
  counts: { all: number; pending: number; investigating: number; resolved: number; blocked: number; observed: number; high_risk: number };
}
interface ObservationDetail extends Observation {
  event: SecurityEvent;
  analysis: Analysis;
  record: EventRecord;
  evidence: Record<string, unknown>;
  related_knowledge: KnowledgeHit[];
  review: EventReview;
}
const DISPOSITIONS: Record<Disposition, string> = { needs_investigation: "继续调查", confirmed_risk: "确认风险", false_positive: "研判为误报" };
const QUEUE_TABS: { id: QueueStatus; label: string }[] = [{ id: "pending", label: "待研判" }, { id: "investigating", label: "调查中" }, { id: "resolved", label: "已研判" }, { id: "all", label: "全部" }];

function decisionName(item: Observation) {
  return item.decision === "observed" ? "仅观察" : item.decision === "blocked" ? "已拒绝" : "已放行";
}

export function ObservationQueue(p: PageProps & { home?: boolean }) {
  const [status, setStatus] = useState<QueueStatus>("pending");
  const [source, setSource] = useState("all");
  const [risk, setRisk] = useState("all");
  const [query, setQuery] = useState("");
  const [search, setSearch] = useState("");
  const [offset, setOffset] = useState(0);
  const [revision, setRevision] = useState(0);
  const [reviewNotice, setReviewNotice] = useState("");
  const [selectedKey, setSelectedKey] = useState(() => new URL(location.href).searchParams.get("observation") || (p.selectedEventId ? `simulation:${p.selectedEventId}` : ""));
  const [mobileDetail, setMobileDetail] = useState(false);
  const params = new URLSearchParams({ source, status, risk, q: search, attention_only: String(status !== "all"), limit: "20", offset: String(offset) });
  const summaryParams = new URLSearchParams({ source, status: "all", risk, q: search, attention_only: "true", limit: "1" });
  const summary = useApi<QueueResponse>(`/observations?${summaryParams}`, 4000, revision + p.revision);
  const queue = useApi<QueueResponse>(`/observations?${params}`, 4000, revision + p.revision);
  const selected = selectedKey || queue.data?.items[0]?.key || "";
  const detail = useApi<ObservationDetail>(selected ? `/observations/${encodeURIComponent(selected)}` : null, 0, revision + p.revision);
  const lastDetail = useRef<ObservationDetail | null>(null);
  if (detail.data?.key === selected) lastDetail.current = detail.data;
  useEffect(() => { const id = setTimeout(() => { setSearch(query); setOffset(0); }, 250); return () => clearTimeout(id); }, [query]);
  useEffect(() => { if (p.selectedEventId && !new URL(location.href).searchParams.has("observation")) setSelectedKey(`simulation:${p.selectedEventId}`); }, [p.selectedEventId]);
  function choose(item: Observation) {
    setSelectedKey(item.key); setMobileDetail(true); setReviewNotice("");
    const url = new URL(location.href); url.searchParams.set("observation", item.key); url.searchParams.delete("event"); url.searchParams.delete("run"); history.replaceState(null, "", url);
  }
  function resetSelection() { setSelectedKey(""); setMobileDetail(false); const url = new URL(location.href); url.searchParams.delete("observation"); url.searchParams.delete("event"); url.searchParams.delete("run"); history.replaceState(null, "", url); }
  function filterStatus(next: QueueStatus) { setStatus(next); setOffset(0); resetSelection(); }
  const refresh = () => { setRevision((r) => r + 1); p.refresh(); };
  function reviewed(disposition?: Disposition) {
    // Pin the investigated record before refreshed filtering can remove it.
    if (selected) {
      setSelectedKey(selected);
      const url = new URL(location.href);
      url.searchParams.set("observation", selected);
      url.searchParams.delete("event");
      url.searchParams.delete("run");
      history.replaceState(null, "", url);
    }
    if (disposition) {
      setStatus(disposition === "needs_investigation" ? "investigating" : "resolved");
      setOffset(0);
      setReviewNotice(`研判已保存 · ${DISPOSITIONS[disposition]}`);
    }
    refresh();
  }
  const data = detail.data?.key === selected ? detail.data : lastDetail.current?.key === selected ? lastDetail.current : null;
  return <div className={`security-queue ${mobileDetail ? "show-detail" : ""}`}>
    <div className="queue-titlebar"><div className="product-page-title"><h1>{p.home ? "安全工作台" : "风险事件"}</h1><span className="subtle-label">共 {num(queue.data?.total)} 条</span></div><div className="queue-status-tabs" role="tablist" aria-label="研判状态">{QUEUE_TABS.map((t) => <button role="tab" aria-selected={status === t.id} key={t.id} className={status === t.id ? "active" : ""} onClick={() => filterStatus(t.id)}>{t.label}</button>)}</div></div>
    {p.home && <div className="queue-summary" aria-label="当前来源和搜索条件下需关注的事件"><button onClick={() => filterStatus("pending")}><span>待研判</span><strong>{num(summary.data?.counts.pending)}</strong><Clock3 size={21} /></button><button onClick={() => { setRisk(risk === "high" ? "all" : "high"); setOffset(0); resetSelection(); }}><span>高风险事件</span><strong>{num(summary.data?.counts.high_risk)}</strong><ShieldBan size={21} /></button><div><span>已阻断请求</span><strong>{num(summary.data?.counts.blocked)}</strong><FileCheck2 size={21} /></div><div><span>已完成研判</span><strong>{num(summary.data?.counts.resolved)}</strong><CheckCircle2 size={21} /></div></div>}
    <div className="queue-toolbar"><div><label>数据来源<select aria-label="数据来源" value={source} onChange={(e) => { setSource(e.target.value); setOffset(0); resetSelection(); }}><option value="all">全部</option><option value="gateway">业务访问</option><option value="simulation">沙盒演练</option><option value="import">日志观察</option></select></label><button className={`button filter-risk ${risk === "high" ? "selected" : ""}`} onClick={() => { setRisk(risk === "high" ? "all" : "high"); setOffset(0); resetSelection(); }}><SlidersHorizontal size={15} />{risk === "high" ? "仅高风险" : "风险筛选"}</button><button className="button" onClick={refresh}><RefreshCw size={15} />刷新</button></div><label className="queue-search"><Search size={16} /><input placeholder="员工、工单或请求编号" aria-label="搜索风险事件" maxLength={100} value={query} onChange={(e) => { setQuery(e.target.value); resetSelection(); }} />{query && <button className="icon-button" aria-label="清空队列搜索" onClick={() => { setQuery(""); resetSelection(); }}><X size={14} /></button>}</label></div>
    <ErrorNotice message={queue.error || summary.error} />
    {reviewNotice && <div className="queue-review-notice" role="status"><CheckCircle2 size={17} /><span>{reviewNotice}</span><button className="icon-button" aria-label="关闭研判保存提示" onClick={() => setReviewNotice("")}><X size={15} /></button></div>}
    <div className="queue-layout"><section className="product-panel queue-list" aria-label="事件队列">
      {queue.loading ? <Loading /> : queue.data?.items.length ? <div className="table-wrap"><table className="observation-table"><thead><tr><th>发生时间</th><th>员工</th><th>来源 / 请求</th><th>风险</th></tr></thead><tbody>{queue.data.items.map((item) => <tr key={item.key} className={selected === item.key ? "selected" : ""} onClick={() => choose(item)}><td><button aria-label={`调查 ${item.employee_id} ${item.operation} ${item.key}`} className="row-open" onClick={(e) => { e.stopPropagation(); choose(item); }}><span>{time(item.occurred_at, true).split(" ")[0]}</span><small>{time(item.occurred_at)}</small></button></td><td><strong>{item.employee_id}</strong><small>{item.employee_name || item.actor}</small></td><td>{item.source_label}<small>{EVENT_NAMES[item.operation] || item.operation}</small></td><td><Badge level={item.risk_level} /><small className={`queue-decision ${item.decision}`}>{decisionName(item)}</small></td></tr>)}</tbody></table></div> : <Empty title="没有符合条件的事件" text="调整筛选条件或等待新的业务访问。" />}
      <div className="table-pagination"><span>共 {num(queue.data?.total)} 条</span><button className="button square" aria-label="上一页事件" disabled={offset === 0 || queue.loading} onClick={() => { setOffset((v) => Math.max(0, v - 20)); resetSelection(); }}><ChevronLeft size={16} /></button><span className="page-number">{offset / 20 + 1}</span><button className="button square" aria-label="下一页事件" disabled={!queue.data || offset + 20 >= queue.data.total || queue.loading} onClick={() => { setOffset((v) => v + 20); resetSelection(); }}><ChevronRight size={16} /></button></div>
    </section><section className="product-panel queue-investigation" aria-label="事件调查"><button className="button mobile-back" onClick={() => setMobileDetail(false)}><ArrowLeft size={15} />返回事件队列</button><ErrorNotice message={detail.error} />{detail.loading && selected && !data ? <Loading /> : data ? <Investigation key={data.key} item={data} canReview={p.canOperate} onReviewed={reviewed} onOpenAnalysis={data.source === "simulation" && data.record ? () => p.selectEvent(data.record, "agents") : undefined} /> : <Empty title={detail.error ? "事件读取失败" : "选择一条事件"} text={detail.error ? "请刷新后重试。" : "在左侧队列查看业务依据与处理结果。"} />}</section></div>
  </div>;
}

function EvidenceExcerpt({ text, label }: { text: string; label: string }) {
  const [expanded, setExpanded] = useState(false);
  const id = useId();
  const canExpand = text.length > 70;
  return <div className="evidence-excerpt"><p id={id} className={expanded || !canExpand ? "" : "collapsed"}>{text}</p>{canExpand && <button type="button" aria-controls={id} aria-expanded={expanded} aria-label={`${label}：${expanded ? "收起依据" : "查看完整依据"}`} onClick={() => setExpanded((value) => !value)}>{expanded ? "收起依据" : "查看完整依据"}</button>}</div>;
}

function Investigation({ item, canReview, onReviewed, onOpenAnalysis }: { item: ObservationDetail; canReview: boolean; onReviewed: (disposition?: Disposition) => void; onOpenAnalysis?: () => void }) {
  const [tab, setTab] = useState("evidence");
  return <><div className="investigation-heading"><div><h2>{EVENT_NAMES[item.operation] || item.operation}<span className={`decision-tag ${item.decision}`}>{decisionName(item)}</span></h2><p><span>员工 <strong>{item.employee_id} {item.employee_name}</strong></span><span>工单 <strong>{item.task_id || "无"}</strong></span></p></div><div className="investigation-volume"><span>请求数量 <strong>{num(item.requested_records)}</strong></span><span>返回数量 <strong>{item.control_mode === "observe" ? "未采集" : num(item.delivered_records)}</strong></span><small>{time(item.occurred_at, true)}</small></div></div>
    <div className="result-tabs"><button className={tab === "evidence" ? "active" : ""} onClick={() => setTab("evidence")}>业务证据</button><button className={tab === "history" ? "active" : ""} onClick={() => setTab("history")}>处置记录</button><button className={tab === "technical" ? "active" : ""} onClick={() => setTab("technical")}>技术详情</button>{onOpenAnalysis && <button className="analysis-link" onClick={onOpenAnalysis}>智能体分析<ArrowRight size={13} /></button>}</div>
    <div className="investigation-body">{tab === "evidence" ? <>
      <section className="evidence-section"><h3>业务信息</h3><dl className="business-evidence"><dt>业务目的</dt><dd>{item.event?.purpose || "未提供"}</dd><dt>工单核验</dt><dd><EvidenceExcerpt label="工单核验" text={item.analysis?.intent?.evidence?.join("；") || "缺少工单支持证据"} /></dd><dt>本次请求</dt><dd>{EVENT_NAMES[item.operation] || item.operation} {num(item.requested_records)} 条 · {item.event?.regions?.join("、") || "未指定区域"}</dd><dt>风险原因</dt><dd className={item.decision === "blocked" ? "risk-reason" : ""}><EvidenceExcerpt label="风险原因" text={item.summary || item.analysis?.explanation || "暂无解释"} /></dd></dl></section>
      <section className="evidence-section"><h3>已观测的行为</h3><ol className="observed-actions"><li><time>{time(item.occurred_at)}</time><p>{item.employee_id} 发起{EVENT_NAMES[item.operation] || item.operation}，请求 {num(item.requested_records)} 条。</p></li><li><time>{time(item.observed_at)}</time><p>{item.decision === "observed" ? "日志已完成观察分析，未执行访问控制。" : item.decision === "blocked" ? "策略拒绝该请求，返回记录为 0。" : `策略放行，已交付 ${num(item.delivered_records)} 条。`}</p></li></ol></section>
      {!!item.related_knowledge?.length && <details className="evidence-knowledge"><summary>相关策略依据 · {item.related_knowledge.length} 条</summary>{item.related_knowledge.map((hit) => <article key={hit.id}><strong>{hit.title}</strong><p>{hit.excerpt}</p><small>{hit.source_title} · {hit.version}</small></article>)}</details>}
      <QueueReview key={item.key} item={item} canReview={canReview} onReviewed={onReviewed} />
    </> : tab === "history" ? <><section className="evidence-section"><h3>策略处理</h3><div className="executed-actions">{item.analysis?.actions?.map((action) => <span key={action}>{ACTION_NAMES[action] || action}</span>)}</div><p className="workbench-muted">{item.control_mode === "observe" ? "仅观察，未执行策略动作。" : item.control_mode === "simulated" ? "沙盒响应" : `实际交付 ${num(item.delivered_records)} 条`}</p></section><section className="evidence-section"><h3>人工研判历史</h3>{item.review?.history.length ? <ol className="review-history">{item.review.history.map((r) => <li key={r.revision}><strong>{DISPOSITIONS[r.disposition]}</strong><p>{r.note}</p><small>{r.actor} · {time(r.created_at, true)} · 第 {r.revision} 版</small></li>)}</ol> : <Empty title="暂无人工研判" text="核对业务证据后记录处理结论。" />}</section></> : <section className="evidence-section"><h3>检测与存证</h3><dl className="business-evidence"><dt>风险评分</dt><dd><Badge level={item.risk_level} /> {num(item.risk_score)}</dd><dt>来源</dt><dd>{item.source_label}</dd><dt>行为模型</dt><dd>{item.analysis?.model_version || "—"}</dd><dt>命中规则</dt><dd>{item.analysis?.rules?.join("、") || "无"}</dd><dt>事件标识</dt><dd className="mono">{item.event_id}</dd><dt>证据摘要</dt><dd className="mono">{item.evidence_hash}</dd></dl><details className="model-details"><summary>查看原始检测记录</summary><pre className="json-view">{JSON.stringify({ event: item.event, analysis: item.analysis, evidence: item.evidence }, null, 2)}</pre></details></section>}</div>
  </>;
}

function QueueReview({ item, canReview, onReviewed }: { item: ObservationDetail; canReview: boolean; onReviewed: (disposition?: Disposition) => void }) {
  const [disposition, setDisposition] = useState<Disposition>("needs_investigation");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [saved, setSaved] = useState(false);
  const pending = useRef<{ key: string; id: string } | null>(null);
  async function save() {
    if (!canReview || busy || !note.trim()) return;
    setBusy(true); setError(""); setSaved(false);
    const body = { expected_revision: item.review.revision, disposition, note: note.trim() };
    const key = JSON.stringify(body); if (pending.current?.key !== key) pending.current = { key, id: requestId() };
    try { await api(`/observations/${encodeURIComponent(item.key)}/review`, { body: { ...body, request_id: pending.current.id } }); pending.current = null; setNote(""); setSaved(true); onReviewed(disposition); }
    catch (e) { setError(e instanceof Error ? e.message : "保存失败"); if (e instanceof ApiError && e.status === 409) { pending.current = null; onReviewed(); } }
    finally { setBusy(false); }
  }
  return <section className="evidence-section queue-review"><h3>人工研判</h3>{item.review?.current && <div className="current-disposition"><CheckCircle2 size={15} /><strong>{DISPOSITIONS[item.review.current.disposition]}</strong><span>{item.review.current.actor} · {time(item.review.current.created_at)}</span><p>{item.review.current.note}</p></div>}<ErrorNotice message={error} />{canReview ? <form onSubmit={(e) => { e.preventDefault(); void save(); }}><label>研判结论<select value={disposition} disabled={busy} onChange={(e) => setDisposition(e.target.value as Disposition)}>{Object.entries(DISPOSITIONS).map(([value, label]) => <option value={value} key={value}>{label}</option>)}</select></label><label>研判备注<textarea value={note} disabled={busy} required maxLength={1000} rows={3} placeholder="填写业务核验结果与判断依据" onChange={(e) => setNote(e.target.value)} /></label><div className="queue-review-submit"><span>{saved ? "研判已保存" : `${note.length} / 1000`}</span><button className="button primary" disabled={busy || !note.trim() || !item.review}>{busy && <LoaderCircle size={15} className="spin" />}{busy ? "保存中" : "保存研判"}</button></div></form> : <p className="workbench-muted">当前账号仅可查阅研判记录。</p>}</section>;
}
