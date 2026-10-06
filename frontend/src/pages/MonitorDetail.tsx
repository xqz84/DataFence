import { useEffect, useState } from "react";
import {
  ArrowRight,
  CheckCircle2,
  Clock3,
  FileCheck2,
  FlaskConical,
  GitBranch,
  LockKeyhole,
  Radio,
  ShieldCheck,
  UserRound,
} from "lucide-react";
import type { PageProps } from "../App";
import { EventReviewPanel } from "../EventReviewPanel";
import type { AiAnalysis, EventRecord, Run } from "../types";
import { analysisStatus, providerName, reasonLabel } from "../ai";
import { SemanticPanel } from "../SemanticPanel";
import { QuotaPanel } from "../QuotaPanel";
import { RunPhase } from "../RunPhase";
import {
  ActionList,
  Badge,
  Card,
  Chain,
  Empty,
  ErrorNotice,
  EVENT_NAMES,
  EventsTable,
  EventTimeline,
  Loading,
  Metric,
  PageHeading,
  ProgressBar,
  RiskChart,
  RiskRadar,
  Status,
  TextLink,
  num,
  short,
  time,
  useApi,
} from "../ui";

export function Monitor(p: PageProps) {
  const run = useApi<Run>(
    p.runId ? `/runs/${encodeURIComponent(p.runId)}` : null,
    800,
  );
  const events = useApi<EventRecord[]>(
    p.runId ? `/events?run_id=${encodeURIComponent(p.runId)}&limit=100` : null,
    800,
  );
  const receipts = useApi<
    {
      event_id: string;
      channel: string;
      record_count: number;
      received_at: string;
    }[]
  >(p.runId ? `/runs/${encodeURIComponent(p.runId)}/receipts` : null, 1500);
  const [selectedId, setSelectedId] = useState("");
  useEffect(() => setSelectedId(""), [p.runId]);
  const selected =
    events.data?.find((e) => e.event.event_id === selectedId) ||
    events.data?.[0];
  const ordered = [...(events.data || [])].reverse();
  const actions = [
    ...new Set(
      ordered.flatMap((e) =>
        (e.response_actions || [])
          .filter((a) => a.status === "simulated_completed")
          .map((a) => a.action),
      ),
    ),
  ];
  const r = run.data;
  return (
    <>
      <PageHeading
        eyebrow="LIVE SECURITY MONITOR"
        title="实时监控中心"
        description="逐条观察事件、风险与响应，所有检测结论均可回溯到当前已发生的行为。"
        action={
          <button className="button" onClick={() => p.navigate("lab")}>
            <FlaskConical size={16} />
            新建演练
          </button>
        }
      />
      <div className="run-selector">
        <div>
          <Radio size={17} />
          <strong>当前演练</strong>
          <select
            aria-label="选择演练"
            value={p.runId}
            onChange={(e) => {
              p.setRunId(e.target.value);
              const run = p.runs.find((r) => r.id === e.target.value);
              if (run) p.setEmployeeId(run.employee_id);
            }}
          >
            {!p.runs.length && <option value="">暂无演练</option>}
            {p.runs.map((r) => (
              <option key={r.id} value={r.id}>
                {p.scenarios.find((s) => s.id === r.scenario_id)?.name ||
                  r.scenario_id}{" "}
                · {r.employee_id} · {time(r.created_at, true)}
              </option>
            ))}
          </select>
        </div>
        {r && <Status run={r} />}
      </div>
      {r && <RunPhase run={r} />}
      <ErrorNotice message={run.error || events.error || receipts.error} />
      {!p.runId ? (
        <Card>
          <Empty
            title="等待启动第一场演练"
            text="选择异常场景或正常业务对照，监控中心将自动跟踪完整处理过程。"
            action={
              <button
                className="button primary"
                onClick={() => p.navigate("lab")}
              >
                前往攻击模拟实验室
                <ArrowRight size={15} />
              </button>
            }
          />
        </Card>
      ) : (
        <>
          {r && (
            <>
              <div className="metrics-grid four">
                <Metric
                  label="演练处理进度"
                  value={`${r.processed_events} / ${r.planned_events}`}
                  detail={`${r.skipped_events} 个后续步骤未执行`}
                  icon={<GitBranch size={18} />}
                />
                <Metric
                  label="最高风险分数"
                  value={num(r.max_risk)}
                  unit="/ 100"
                  detail="来自实际事件检测"
                  icon={<ShieldCheck size={18} />}
                  tone={r.max_risk >= 60 ? "red" : "blue"}
                />
                <Metric
                  label="阻断的操作"
                  value={num(r.blocked_events)}
                  detail="在沙盒执行前完成策略检查"
                  icon={<LockKeyhole size={18} />}
                  tone="green"
                />
                <Metric
                  label="模拟接收记录"
                  value={num(r.sink_records)}
                  unit="条"
                  detail={`${receipts.data?.length ?? 0} 条实际接收回执`}
                  icon={<FileCheck2 size={18} />}
                />
              </div>
              {r.skipped_events > 0 && (
                <div className="prevention-banner">
                  <ShieldCheck size={22} />
                  <div>
                    <strong>防护已截断后续操作</strong>
                    <p>
                      {r.skipped_events}{" "}
                      个计划步骤未执行。下方攻击链只呈现实际处理的事件和被阻断的尝试。
                    </p>
                  </div>
                  <span>模拟接收端 {num(r.sink_records)} 条</span>
                </div>
              )}
              {r.error && <ErrorNotice message={r.error} />}
            </>
          )}
          <div className="monitor-grid">
            <Card
              title="实时事件时间线"
              subtitle="最新事件在前"
              action={
                <span className="count-label">
                  {events.data?.length || 0} 条
                </span>
              }
              className="timeline-card"
            >
              <EventTimeline
                events={events.data || []}
                selectedId={selected?.event.event_id}
                onSelect={(e) => setSelectedId(e.event.event_id)}
              />
            </Card>
            <div className="monitor-middle">
              <Card
                title="动态风险变化"
                subtitle="横轴为当前演练实际事件发生时间"
                action={
                  r?.status === "running" ? (
                    <span className="live-label">
                      <i />
                      LIVE
                    </span>
                  ) : (
                    <span className="muted small">演练记录</span>
                  )
                }
              >
                <RiskChart
                  points={ordered.map((e) => e.analysis.risk_score)}
                  labels={ordered.map((e) => time(e.event.timestamp))}
                  height={230}
                />
                <div className="monitor-progress">
                  <span>处理进度</span>
                  <ProgressBar
                    value={
                      r?.planned_events
                        ? ((r.processed_events + r.skipped_events) /
                            r.planned_events) *
                          100
                        : 0
                    }
                  />
                  <strong>
                    {r?.planned_events
                      ? Math.round(
                          ((r.processed_events + r.skipped_events) /
                            r.planned_events) *
                            100,
                        )
                      : 0}
                    %
                  </strong>
                </div>
              </Card>
              <Card
                title="所选已处理事件"
                subtitle={
                  selected ? short(selected.event.event_id) : "等待事件"
                }
              >
                {selected ? (
                  <>
                    <div className="event-summary">
                      <span className="agent-icon">
                        <GitBranch size={20} />
                      </span>
                      <div>
                        <h3>{EVENT_NAMES[selected.event.event_type]}</h3>
                        <p>
                          {selected.event.employee_id} ·{" "}
                          {selected.event.purpose}
                        </p>
                      </div>
                      <Badge level={selected.analysis.risk_level} />
                    </div>
                    <dl className="facts-grid">
                      <div>
                        <dt>请求 / 实际处理规模</dt>
                        <dd>
                          {num(selected.event.record_count)} /{" "}
                          {num(selected.executed_records)} 条
                        </dd>
                      </div>
                      <div>
                        <dt>访问区域</dt>
                        <dd>{selected.event.regions.join("、") || "—"}</dd>
                      </div>
                      <div>
                        <dt>数据渠道</dt>
                        <dd>{selected.event.channel}</dd>
                      </div>
                      <div>
                        <dt>处置结果</dt>
                        <dd>
                          {selected.outcome === "blocked" ? "已阻断" : "已执行"}
                        </dd>
                      </div>
                    </dl>
                    <TextLink onClick={() => p.selectEvent(selected)}>
                      查看事件完整证据
                    </TextLink>
                  </>
                ) : (
                  <Empty />
                )}
              </Card>
            </div>
            <Card
              title="风险研判"
              subtitle="规则 / 行为模型 / 业务意图"
              className="analysis-card"
            >
              {selected ? (
                <>
                  <div className="score-panel">
                    <span>所选事件风险分数</span>
                    <strong
                      className={
                        selected.analysis.risk_score >= 60 ? "danger" : ""
                      }
                    >
                      {num(selected.analysis.risk_score)}
                      <small>/ 100</small>
                    </strong>
                    <Badge level={selected.analysis.risk_level} />
                  </div>
                  <div className="explanation-box">
                    <BotLabel analysis={selected.ai_analysis} />
                    <p>{selected.analysis.explanation}</p>
                  </div>
                  <SemanticPanel record={selected} />
                  <AIAnalysisPanel analysis={selected.ai_analysis} />
                  <div className="intent-mini">
                    <span>Intent Trust</span>
                    <strong>
                      {num(selected.analysis.intent.trust)}
                      <small>/100</small>
                    </strong>
                  </div>
                  <ProgressBar
                    value={selected.analysis.intent.trust}
                    color={
                      selected.analysis.intent.trust >= 60
                        ? "#239d7d"
                        : "#d58a17"
                    }
                  />
                  <div className="evidence-list">
                    {selected.analysis.intent.evidence
                      .slice(0, 4)
                      .map((v, i) => (
                        <p key={i}>
                          <span />
                          {v}
                        </p>
                      ))}
                  </div>
                  <TextLink onClick={() => p.selectEvent(selected, "intent")}>
                    查看访问意图分析
                  </TextLink>
                </>
              ) : (
                <Empty title="等待研判" text="事件到达后展示分析依据。" />
              )}
            </Card>
          </div>
          <Card
            title="安全响应记录"
            subtitle="动作由策略与编排器决定，仅影响本地合成沙盒"
            action={
              <span className="outline-label">
                <CheckCircle2 size={14} />
                模拟执行
              </span>
            }
          >
            <ActionList actions={actions} />
          </Card>
        </>
      )}
    </>
  );
}
export function BotLabel({ analysis }: { analysis?: AiAnalysis }) {
  return (
    <span className="analysis-label">
      <span />
      检测与策略分析 · {analysisStatus(analysis)}
    </span>
  );
}

export function AIAnalysisPanel({ analysis }: { analysis?: AiAnalysis }) {
  if (
    !analysis ||
    analysis.status === "not_configured" ||
    analysis.status === "skipped"
  )
    return null;
  if (analysis.status !== "completed")
    return (
      <div className="ai-fallback">
        <strong>
          {providerName(analysis.provider)} ·{" "}
          {analysis.model || "未提供模型名称"}
        </strong>
        <p>
          {analysis.summary ||
            "本次模型分析未成功，规则解释和沙盒策略响应保持有效。"}
        </p>
        {analysis.reason_code && (
          <small title={analysis.reason_code}>
            {reasonLabel(analysis.reason_code)}
          </small>
        )}
        {analysis.usage && (
          <small>本次计量 {num(analysis.usage.total_tokens)} tokens</small>
        )}
      </div>
    );
  return (
    <div className="ai-analysis-panel">
      <div className="ai-analysis-heading">
        <strong>{providerName(analysis.provider)} · 补充分析</strong>
        <span>
          {analysis.model || "未提供模型名称"} · {num(analysis.elapsed_ms)} ms
        </span>
      </div>
      <p>{analysis.summary}</p>
      {analysis.reused_semantic && (
        <p className="ai-reused-note">
          复用本次执行前语义核验结果，未额外调用云模型；下列 token
          计量与上方核验是同一次调用，不能相加。
        </p>
      )}
      <div className="ai-token-usage">
        {analysis.usage ? (
          <>
            <span>
              输入 <strong>{num(analysis.usage.prompt_tokens)}</strong>
            </span>
            <span>
              输出 <strong>{num(analysis.usage.completion_tokens)}</strong>
            </span>
            <span>
              合计 <strong>{num(analysis.usage.total_tokens)}</strong> tokens
            </span>
          </>
        ) : (
          <span>本次调用未提供 token 计量</span>
        )}
      </div>
      {analysis.evidence_event_ids.length > 0 && (
        <div className="ai-evidence">
          <small>引用事件</small>
          {analysis.evidence_event_ids.map((id) => (
            <span className="mono" title={id} key={id}>
              {short(id)}
            </span>
          ))}
        </div>
      )}
      <div className="ai-suggestions">
        <strong>模型建议 · 仅供参考，不触发执行</strong>
        {analysis.suggested_actions.length ? (
          <div className="rule-chips">
            {analysis.suggested_actions.map((action, i) => (
              <span key={`${action}-${i}`}>{action}</span>
            ))}
          </div>
        ) : (
          <small>未提出额外动作建议</small>
        )}
      </div>
      <small className="ai-boundary">
        {analysis.reused_semantic
          ? "此处复用执行前核验；最终风险与动作由本地策略融合决定，模型不直接执行控制。"
          : "补充解释不修改风险分数，不直接执行冻结、阻断或数据库操作。"}
        {analysis.provider === "sensenova" &&
          "商汤模型通过云 API 调用，不是本项目训练的大模型。"}
      </small>
    </div>
  );
}

export function EventDetail(p: PageProps) {
  const records = useApi<EventRecord[]>("/events?limit=100", 3000, p.revision);
  const [filter, setFilter] = useState("all");
  const [eventPage, setEventPage] = useState(0);
  const selected =
    p.selected ||
    (p.selectedEventId
      ? records.data?.find(
          (record) => record.event.event_id === p.selectedEventId,
        )
      : p.runId
        ? records.data?.find((record) => record.run_id === p.runId)
        : records.data?.[0]);
  const run = useApi<Run>(
    selected ? `/runs/${encodeURIComponent(selected.run_id)}` : null,
    2000,
  );
  const events = (records.data || []).filter(
    (e) => filter === "all" || e.analysis.risk_level === filter,
  );
  useEffect(() => {
    if (p.selected)
      document
        .getElementById("investigation-detail")
        ?.scrollIntoView({ block: "start", behavior: "smooth" });
  }, [p.selected?.event.event_id]);
  return (
    <>
      <PageHeading
        eyebrow="RISK INVESTIGATION"
        title="风险事件调查"
        description="围绕同一事件，连接业务证据、行为链路、风险判断与实际处置。"
        action={
          selected && (
            <button
              className="button"
              onClick={() => p.selectEvent(selected, "monitor")}
            >
              <Radio size={15} />
              查看关联演练
            </button>
          )
        }
      />
      <ErrorNotice message={records.error} />
      <Card
        title="事件列表"
        action={
          <select
            className="compact-select"
            aria-label="筛选风险等级"
            value={filter}
            onChange={(e) => {
              setFilter(e.target.value);
              setEventPage(0);
            }}
          >
            <option value="all">全部风险等级</option>
            <option value="CRITICAL">严重风险</option>
            <option value="HIGH">高风险</option>
            <option value="MEDIUM">中风险</option>
            <option value="LOW">低风险</option>
          </select>
        }
      >
        {records.loading ? (
          <Loading />
        ) : (
          <EventsTable
            events={events.slice(eventPage * 6, eventPage * 6 + 6)}
            onSelect={(r) => p.selectEvent(r)}
            limit={6}
          />
        )}
        <div className="table-pagination">
          <p className="table-note">
            最近 100 条中有 {events.length} 条匹配事件 · 第 {eventPage + 1} /{" "}
            {Math.max(1, Math.ceil(events.length / 6))} 页
          </p>
          <div>
            <button
              className="button"
              disabled={eventPage === 0}
              onClick={() => setEventPage((v) => v - 1)}
            >
              上一页
            </button>
            <button
              className="button"
              disabled={(eventPage + 1) * 6 >= events.length}
              onClick={() => setEventPage((v) => v + 1)}
            >
              下一页
            </button>
          </div>
        </div>
      </Card>
      {selected && (
        <div id="investigation-detail" className="detail-section">
          <div className="detail-heading">
            <span className="detail-icon">
              <ShieldCheck size={25} />
            </span>
            <div>
              <div className="eyebrow">EVENT INVESTIGATION</div>
              <h2>
                {EVENT_NAMES[selected.event.event_type]} ·{" "}
                {selected.event.employee_id}
              </h2>
              <span className="mono small muted">
                {selected.event.event_id}
              </span>
            </div>
            <Badge level={selected.analysis.risk_level} />
            <div className="detail-score">
              {num(selected.analysis.risk_score)}
              <small>风险分数 / 100</small>
            </div>
          </div>
          <div className="detail-metadata">
            <span>
              <UserRound size={15} />
              {p.employees.find((e) => e.id === selected.event.employee_id)
                ?.name || selected.event.employee_id}
            </span>
            <span>
              <Clock3 size={15} />
              首次检测 {time(selected.detected_at, true)}
            </span>
            <span>
              <FileCheck2 size={15} />
              {num(selected.event.record_count)} 条记录
            </span>
            <span
              className={selected.outcome === "blocked" ? "text-green" : ""}
            >
              <ShieldCheck size={15} />
              {selected.outcome === "blocked" ? "已阻断操作" : "已执行操作"}
            </span>
          </div>
          <QuotaPanel decision={selected.quota_decision} />
          <Card
            title="已观测行为关联链"
            subtitle="展示截至当前事件的已处理前缀；包含被阻断的操作请求"
          >
            <Chain record={selected} />
            {!!run.data?.skipped_events && (
              <div className="info-note">
                <ShieldCheck size={16} />
                <p>
                  本次演练有 {run.data.skipped_events}{" "}
                  个后续步骤因防护策略未执行，不纳入已发生的行为链。
                </p>
              </div>
            )}
          </Card>
          <div className="detail-grid">
            <Card title="五维风险分析" subtitle="初始策略权重 · 分数范围 0–100">
              <RiskRadar dimensions={selected.analysis.dimensions} />
            </Card>
            <Card
              title="判断依据与业务证据"
              action={
                <TextLink onClick={() => p.selectEvent(selected, "intent")}>
                  访问意图
                </TextLink>
              }
            >
              <BotLabel analysis={selected.ai_analysis} />
              <p className="explanation-text">
                {selected.analysis.explanation}
              </p>
              <SemanticPanel record={selected} />
              <AIAnalysisPanel analysis={selected.ai_analysis} />
              <div className="rule-chips">
                {selected.analysis.rules.map((rule, i) => (
                  <span key={i}>{rule}</span>
                ))}
              </div>
              <div className="evidence-list">
                {selected.analysis.intent.evidence.map((v, i) => (
                  <p key={i}>
                    <span />
                    {v}
                  </p>
                ))}
              </div>
              <dl className="facts-grid compact">
                <div>
                  <dt>业务工单</dt>
                  <dd>{selected.event.task_id || "未关联工单"}</dd>
                </div>
                <div>
                  <dt>申报目的</dt>
                  <dd>{selected.event.purpose}</dd>
                </div>
                <div>
                  <dt>会话标识</dt>
                  <dd className="mono">{short(selected.event.session_id)}</dd>
                </div>
                <div>
                  <dt>模型处理耗时</dt>
                  <dd>{num(selected.analysis.processing_ms)} ms</dd>
                </div>
              </dl>
              {selected.event.prompt && (
                <div className="prompt-block">
                  <strong>待分析的 AI 请求文本</strong>
                  <p>{selected.event.prompt}</p>
                </div>
              )}
            </Card>
          </div>
          <div className="detail-grid">
            <Card title="系统自动响应" subtitle="本地沙盒动作记录">
              <ActionList
                actions={(selected.response_actions || [])
                  .filter((a) => a.status === "simulated_completed")
                  .map((a) => a.action)}
              />
              <div className="manual-controls">
                <button
                  className="button"
                  onClick={() => p.selectEvent(selected, "agents")}
                >
                  查看模块依据与知识条款
                </button>
                <button
                  className="button"
                  disabled
                  title="当前版本不支持人工解除冻结"
                >
                  解除冻结 · 待建设
                </button>
              </div>
            </Card>
            <Card title="证据留存" subtitle="哈希链关联事件与前一条证据">
              <dl className="evidence-hashes">
                <dt>当前证据 SHA-256</dt>
                <dd>{selected.evidence_hash}</dd>
                <dt>前一条证据哈希</dt>
                <dd>{selected.previous_hash || "创世节点"}</dd>
                <dt>控制执行完成时间</dt>
                <dd>
                  {time(
                    selected.execution_completed_at || selected.responded_at,
                    true,
                  )}
                </dd>
                {selected.ai_completed_at && (
                  <>
                    <dt>模型分析完成时间</dt>
                    <dd>{time(selected.ai_completed_at, true)}</dd>
                  </>
                )}
                {selected.persisted_at && (
                  <>
                    <dt>证据持久化时间</dt>
                    <dd>{time(selected.persisted_at, true)}</dd>
                  </>
                )}
              </dl>
              <TextLink onClick={() => p.navigate("audit")}>
                审计与完整性校验
              </TextLink>
            </Card>
          </div>
          <EventReviewPanel
            key={selected.event.event_id}
            eventId={selected.event.event_id}
            canReview={p.canOperate}
          />
        </div>
      )}
    </>
  );
}
