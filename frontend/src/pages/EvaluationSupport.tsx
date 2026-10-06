import { useEffect, useState } from "react";
import {
  Activity,
  ArrowRight,
  CheckCircle2,
  ClipboardCheck,
  Database,
  Download,
  FileCheck2,
  FileSearch,
  GitBranch,
  Info,
  LoaderCircle,
  Play,
  Shield,
  ShieldCheck,
} from "lucide-react";
import type { PageProps } from "../App";
import { api } from "../api";
import { LanguageModelStatus, TrainingInfo } from "../ModelStatus";
import { ModelExperiments } from "../ModelExperiments";
import { AccountPanel } from "../AccountPanel";
import { EventImports, PublicData } from "../DataSources";
import { UserManagement } from "../UserManagement";
import { AccessGateway } from "../AccessGateway";
import type {
  Assets,
  EvaluationJob,
  EvaluationReport,
  EventRecord,
  Policies,
  RiskLevel,
} from "../types";
import {
  Badge,
  Card,
  Chain,
  DIMENSIONS,
  Empty,
  ErrorNotice,
  Loading,
  Metric,
  PageHeading,
  ProgressBar,
  SandboxNotice,
  TextLink,
  num,
  pct,
  short,
  time,
  useApi,
} from "../ui";

function downloadReport(report: EvaluationReport) {
  const blob = new Blob([JSON.stringify(report, null, 2)], {
    type: "application/json;charset=utf-8",
  });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `DataFence-evaluation-${report.seed}.json`;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
export function Evaluation(p: PageProps) {
  const latest = useApi<EvaluationReport>("/evaluations/latest", 3000);
  const jobs = useApi<EvaluationJob[]>("/evaluations", 3000);
  const [jobId, setJobId] = useState("");
  const job = useApi<EvaluationJob>(
    jobId ? `/evaluations/${encodeURIComponent(jobId)}` : null,
    1000,
  );
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState("");
  const [seed, setSeed] = useState(20260919);
  const [sessions, setSessions] = useState(80);
  useEffect(() => {
    const running = jobs.data?.find((j) => j.status === "running");
    if (running && !jobId) setJobId(running.id);
  }, [jobs.data, jobId]);
  const busy =
    starting ||
    job.data?.status === "running" ||
    !!jobs.data?.some((j) => j.status === "running");
  const report =
    job.data?.status === "completed" ? job.data.report : latest.data;
  async function start() {
    if (!p.canOperate || busy) return;
    setStarting(true);
    setError("");
    try {
      const result = await api<{ id: string }>("/evaluations", {
        body: { seed, sessions },
      });
      setJobId(result.id);
    } catch (e) {
      setError(e instanceof Error ? e.message : "评测启动失败");
    } finally {
      setStarting(false);
    }
  }
  const modes: Record<string, string> = {
    rules: "仅规则",
    behavior: "仅行为模型",
    full: "完整检测（含意图与关联）",
  };
  return (
    <>
      <PageHeading
        eyebrow="EVALUATION & EVIDENCE"
        title="评测与报告"
        description="分开查看固定模板离线评测与商汤语义开发诊断，所有指标对应已保存记录。"
        action={
          report && (
            <button className="button" onClick={() => downloadReport(report)}>
              <Download size={16} />
              导出离线检测报告
            </button>
          )
        }
      />
      <SandboxNotice compact />
      <ModelExperiments revision={p.revision} />
      <div className="info-note">
        <Info size={17} />
        <p>
          <strong>固定合成模板检测评测，结果不代表未见场景表现。</strong>{" "}
          当前测试使用已定义的六类异常场景与两类正常业务对照，不包含可选语言模型的效果；独立挑战测试另行记录于项目
          CHALLENGE_REPORT.md。
        </p>
      </div>
      <Card
        title="运行可重复评测"
        subtitle="六类异常场景与两类正常业务对照 · 完整离线事件流"
        className="evaluation-config"
      >
        <form
          onSubmit={(e) => {
            e.preventDefault();
            void start();
          }}
        >
          <label className="form-field">
            评测会话数
            <input
              type="number"
              min="24"
              max="1000"
              required
              value={sessions}
              onChange={(e) => setSessions(Number(e.target.value))}
              disabled={busy || !p.canOperate}
            />
          </label>
          <label className="form-field">
            固定随机种子
            <input
              type="number"
              min="0"
              max="2147483647"
              required
              value={seed}
              onChange={(e) => setSeed(Number(e.target.value))}
              disabled={busy || !p.canOperate}
            />
          </label>
          <div className="evaluation-run-copy">
            <strong>重新生成 → 检测 → 对照标签 → 保存产物</strong>
            <span>
              {p.canOperate
                ? "训练基线固定，测试数据不参与模型拟合。"
                : "当前账号为只读角色，可以查看已有结果，不能启动评测。"}
            </span>
          </div>
          <button
            className="button primary"
            disabled={busy || !p.canOperate}
            type="submit"
          >
            {busy ? (
              <LoaderCircle className="spin" size={17} />
            ) : (
              <Play size={17} />
            )}{" "}
            {busy ? "正在运行评测…" : "运行离线检测评测"}
          </button>
        </form>
      </Card>
      <ErrorNotice
        message={
          error ||
          job.error ||
          latest.error ||
          (job.data?.status === "failed" || job.data?.status === "interrupted"
            ? job.data.error || "评测未完成，请重新运行"
            : "")
        }
      />
      {busy && (
        <div className="evaluation-running">
          <LoaderCircle className="spin" size={18} />
          <div>
            <strong>评测正在后台执行</strong>
            <span>
              页面将自动更新结果；离开此页不会中断实验。
              {report ? " 下方保留上一份已完成报告。" : ""}
            </span>
          </div>
        </div>
      )}
      {!report ? (
        <Card>
          {latest.loading ? (
            <Loading />
          ) : (
            <Empty
              title="尚未产生实测报告"
              text="运行评测后，系统将展示真实混淆矩阵、配置对照和逐场景检测结果。"
            />
          )}
        </Card>
      ) : (
        <>
          <div className="report-meta">
            <span>
              <FileCheck2 size={15} />
              已完成实测
            </span>
            <strong>{time(report.created_at, true)}</strong>
            <span className="mono">{short(report.id)}</span>
            <span>种子 {report.seed}</span>
            <span>{num(report.sessions)} 个会话</span>
          </div>
          <div className="metrics-grid four">
            <Metric
              label="Precision · 精确率"
              value={pct(report.metrics.precision)}
              detail="TP / (TP + FP)"
              icon={<ShieldCheck size={18} />}
              tone="green"
            />
            <Metric
              label="Recall · 召回率"
              value={pct(report.metrics.recall)}
              detail="TP / (TP + FN)"
              icon={<Activity size={18} />}
            />
            <Metric
              label="F1 Score"
              value={pct(report.metrics.f1)}
              detail="精确率与召回率的调和平均"
              icon={<ClipboardCheck size={18} />}
              tone="purple"
            />
            <Metric
              label="False Positive Rate · 误报率"
              value={pct(report.metrics.fpr)}
              detail="FP / (FP + TN)"
              icon={<Shield size={18} />}
              tone="orange"
            />
          </div>
          <div className="evaluation-grid">
            <Card
              title="混淆矩阵"
              subtitle="事件级判定 · 行为真实标签，列为检测结果"
            >
              <div className="confusion-matrix">
                <span />
                <span>预测正常</span>
                <span>预测攻击</span>
                <span>真实正常</span>
                <div className="matrix-good">
                  <small>TN · 正确放行</small>
                  <strong>{num(report.metrics.tn)}</strong>
                </div>
                <div className="matrix-error">
                  <small>FP · 误报</small>
                  <strong>{num(report.metrics.fp)}</strong>
                </div>
                <span>真实攻击</span>
                <div className="matrix-error">
                  <small>FN · 漏检</small>
                  <strong>{num(report.metrics.fn)}</strong>
                </div>
                <div className="matrix-good">
                  <small>TP · 正确告警</small>
                  <strong>{num(report.metrics.tp)}</strong>
                </div>
              </div>
              <p className="table-note">
                风险分数达到 60 视为检测到风险；零分母指标显示“未定义”。
              </p>
            </Card>
            <Card
              title="测试集构成与延迟"
              subtitle="区分合成时间与本机计算耗时"
            >
              <div className="dataset-summary">
                <div>
                  <strong>{num(report.event_count)}</strong>
                  <span>总事件数</span>
                </div>
                <div>
                  <strong>{num(report.attack_events)}</strong>
                  <span>攻击事件</span>
                </div>
                <div>
                  <strong>{num(report.normal_events)}</strong>
                  <span>正常事件</span>
                </div>
              </div>
              <dl className="latency-list">
                <div>
                  <dt>本机检测处理 P50 / P95</dt>
                  <dd>
                    {num(report.latency.processing_ms_p50)} /{" "}
                    {num(report.latency.processing_ms_p95)} ms
                  </dd>
                </div>
                <div>
                  <dt>首次检测延迟 P50</dt>
                  <dd>
                    {num(report.latency.detection_delay_seconds_p50)} 秒{" "}
                    <small>合成事件时间</small>
                  </dd>
                </div>
                <div>
                  <dt>漏检会话数</dt>
                  <dd>{num(report.latency.missed_sessions)}</dd>
                </div>
                <div>
                  <dt>响应完成时间</dt>
                  <dd className="muted">离线评测未测量</dd>
                </div>
              </dl>
            </Card>
          </div>
          <div className="evaluation-grid">
            <Card
              title="按场景检测效果"
              subtitle="攻击场景为召回率；正常场景展示误报会话数"
            >
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>场景</th>
                      <th>会话数</th>
                      <th>告警会话</th>
                      <th>召回率</th>
                    </tr>
                  </thead>
                  <tbody>
                    {report.per_scenario.map((s) => (
                      <tr key={s.scenario_id}>
                        <td>
                          {p.scenarios.find((x) => x.id === s.scenario_id)
                            ?.name || s.scenario_id}
                        </td>
                        <td>{s.sessions}</td>
                        <td>
                          {s.recall === null
                            ? (s.false_alert_sessions ?? 0)
                            : s.detected}
                          {s.recall === null ? " 次误报" : ""}
                        </td>
                        <td>
                          {s.recall === null
                            ? "不适用（正常对照）"
                            : pct(s.recall)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>
            <Card
              title="检测配置对照"
              subtitle="三种配置的整体表现，尚不能单独归因到某一模块"
            >
              <div className="ablation-list">
                {report.ablations.map((a) => (
                  <div key={a.mode}>
                    <div>
                      <strong>{modes[a.mode] || a.mode}</strong>
                      <b>F1 {pct(a.f1)}</b>
                    </div>
                    <ProgressBar
                      value={(a.f1 || 0) * 100}
                      color={a.mode === "full" ? "#2670da" : "#a6bddc"}
                    />
                    <p>
                      <span>Precision {pct(a.precision)}</span>
                      <span>Recall {pct(a.recall)}</span>
                      <span>FPR {pct(a.fpr)}</span>
                    </p>
                  </div>
                ))}
              </div>
            </Card>
          </div>
          <Card
            title="实验产物与适用范围"
            subtitle="每一份正式报告都需要关联原始输入、独立标签与预测记录"
          >
            <div className="artifact-grid">
              {Object.entries(report.artifacts).map(([key, value]) => {
                const object =
                  typeof value === "object" && value !== null
                    ? (value as Record<string, unknown>)
                    : null;
                return (
                  <div key={key}>
                    <FileSearch size={20} />
                    <span>
                      <strong>
                        {object && typeof object.file === "string"
                          ? object.file
                          : key}
                      </strong>
                      <small className="mono">
                        {object && typeof object.sha256 === "string"
                          ? short(object.sha256)
                          : typeof value === "string"
                            ? value
                            : "已保存"}
                      </small>
                    </span>
                    <CheckCircle2 size={15} />
                  </div>
                );
              })}
            </div>
            <div className="limitations">
              <strong>
                <Info size={16} />
                结果适用范围
              </strong>
              <ul>
                {report.limitations.map((s, i) => (
                  <li key={i}>{s}</li>
                ))}
              </ul>
            </div>
          </Card>
        </>
      )}
    </>
  );
}

export function SupportPage(p: PageProps & { page: string }) {
  const assets = useApi<Assets>(p.page === "assets" ? "/assets" : null);
  const policies = useApi<Policies>(p.page === "policies" ? "/policies" : null);
  const records = useApi<EventRecord[]>(
    p.page === "audit" || p.page === "flow"
      ? `/events?limit=100${p.page === "flow" && p.runId ? `&run_id=${encodeURIComponent(p.runId)}` : ""}`
      : null,
    2500,
  );
  const [audit, setAudit] = useState<{
    valid: boolean;
    checked_events: number;
    broken_event: string | null;
  } | null>(null);
  const [checking, setChecking] = useState(false);
  const [error, setError] = useState("");
  async function verify() {
    setChecking(true);
    setError("");
    try {
      setAudit(await api("/audit/verify"));
    } catch (e) {
      setError(e instanceof Error ? e.message : "完整性校验失败");
    } finally {
      setChecking(false);
    }
  }
  const selected =
    (p.selected &&
      records.data?.find(
        (r) => r.event.event_id === p.selected?.event.event_id,
      )) ||
    records.data?.[0];
  const headings: Record<string, [string, string, string]> = {
    assets: [
      "DATA ASSET INVENTORY",
      "数据资产",
      "分别查看合成沙盒资产、公开业务数据来源与合成安全日志的观察分析。",
    ],
    agents: [
      "SECURITY CAPABILITIES",
      "AI安全智能体",
      "六个安全能力模块协同工作，具体实现与模型接入状态清晰可见。",
    ],
    policies: [
      "POLICY & RESPONSE",
      "策略与响应",
      "执行前语义核验结果由本地策略处理，普通事后解释不授权动作。",
    ],
    audit: [
      "AUDIT & FORENSICS",
      "审计与取证",
      "校验持久化证据的哈希链，追溯每一次检测与响应。",
    ],
    flow: [
      "DATA FLOW TRACE",
      "数据流追踪",
      "通过同一会话与数据对象关系，查看实际发生的数据流动。",
    ],
    settings: [
      "SYSTEM STATUS",
      "系统管理",
      "本地概念验证环境的运行状态与能力边界。",
    ],
  };
  const [eyebrow, title, description] = headings[p.page] || headings.settings;
  return (
    <>
      <PageHeading eyebrow={eyebrow} title={title} description={description} />
      <ErrorNotice
        message={error || assets.error || policies.error || records.error}
      />
      {p.page === "assets" && (
        <>
          <SandboxNotice />
          <div className="assets-grid">
            {assets.data?.assets.map((a) => (
              <Card key={a.name}>
                <div className="asset-top">
                  <span className="agent-icon">
                    <Database size={21} />
                  </span>
                  <span className="outline-label">合成数据</span>
                </div>
                <h3>{a.label}</h3>
                <strong className="asset-count">{num(a.count)}</strong>
                <div className="asset-bottom">
                  <span className="mono">{a.name}</span>
                  <span>敏感度 {a.sensitivity}</span>
                </div>
              </Card>
            )) || <Loading />}
          </div>
          <Card title="数据来源清单" subtitle="由本地沙盒生成器生成">
            <details className="model-details">
              <summary>展开生成参数、数据版本与清单</summary>
              <pre className="json-view">
                {JSON.stringify(assets.data?.manifest, null, 2)}
              </pre>
            </details>
          </Card>
          <AccessGateway canAccess={p.canOperate} />
          <PublicData revision={p.revision} />
          <EventImports canImport={p.canOperate} />
        </>
      )}
      {p.page === "policies" && policies.data && (
        <>
          <Card
            title="五维风险融合"
            subtitle={`策略版本 ${policies.data.version} · PoC 初始权重，未经生产校准`}
          >
            <div className="weight-grid">
              {DIMENSIONS.map((d) => (
                <div key={d.key}>
                  <span>{d.key}</span>
                  <strong>{d.name}</strong>
                  <b>{pct(policies.data!.weights[d.key])}</b>
                </div>
              ))}
            </div>
          </Card>
          <Card
            title="风险等级与响应动作"
            subtitle="操作禁止策略可以覆盖加权评分；响应仅执行于沙盒"
          >
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>风险等级</th>
                    <th>分数范围</th>
                    <th>初始响应策略</th>
                  </tr>
                </thead>
                <tbody>
                  {policies.data.levels.map((l) => (
                    <tr key={l.name}>
                      <td>
                        <Badge level={l.name as RiskLevel} />
                      </td>
                      <td>
                        {l.min}–{l.max}
                      </td>
                      <td>
                        <div className="rule-chips">
                          {l.actions.map((a) => (
                            <span key={a}>{a}</span>
                          ))}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
          <div className="info-note">
            <ShieldCheck size={17} />
            <p>
              策略编辑、审批和版本发布流程尚未建设。当前策略以受版本管理的代码配置为准。
            </p>
          </div>
        </>
      )}
      {p.page === "audit" && (
        <>
          <Card
            title="证据完整性校验"
            subtitle="重新计算已保存事件的哈希，检查相邻证据链接"
            action={
              <button
                className="button primary"
                disabled={checking}
                onClick={() => void verify()}
              >
                {checking ? (
                  <LoaderCircle size={16} className="spin" />
                ) : (
                  <ShieldCheck size={16} />
                )}{" "}
                {checking ? "正在校验…" : "校验哈希链"}
              </button>
            }
          >
            {audit ? (
              <div
                className={`audit-result ${audit.valid ? "valid" : "invalid"}`}
              >
                <ShieldCheck size={32} />
                <div>
                  <strong>
                    {audit.valid ? "已保存证据的哈希链完整" : "发现证据链异常"}
                  </strong>
                  <p>
                    已检查 {num(audit.checked_events)} 条事件
                    {audit.broken_event
                      ? ` · 异常节点 ${audit.broken_event}`
                      : ""}
                    。这是本地一致性校验，不等同于外部可信存证。
                  </p>
                </div>
              </div>
            ) : (
              <div className="info-note">
                <FileCheck2 size={18} />
                <p>
                  点击校验按钮取得实时校验结果。未运行校验前不宣称证据链完整。
                </p>
              </div>
            )}
          </Card>
          <Card title="最近证据记录" subtitle="只展示实际处理事件的证据哈希">
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>事件标识</th>
                    <th>员工</th>
                    <th>检测时间</th>
                    <th>SHA-256</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {records.data?.map((r) => (
                    <tr key={r.event.event_id}>
                      <td className="mono">{short(r.event.event_id)}</td>
                      <td>{r.event.employee_id}</td>
                      <td>{time(r.detected_at, true)}</td>
                      <td className="mono" title={r.evidence_hash}>
                        {short(r.evidence_hash)}
                      </td>
                      <td>
                        <TextLink onClick={() => p.selectEvent(r)}>
                          调查
                        </TextLink>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {!records.data?.length && <Empty />}
            </div>
          </Card>
        </>
      )}
      {p.page === "flow" && (
        <>
          <div className="run-selector">
            <div>
              <GitBranch size={18} />
              <strong>关联演练</strong>
              <select
                aria-label="选择数据流演练"
                value={p.runId}
                onChange={(e) => p.setRunId(e.target.value)}
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
          </div>
          <Card
            title="当前已观测数据流"
            subtitle="通过实际事件关联，不补画未执行的计划步骤"
          >
            {selected ? <Chain record={selected} /> : <Empty />}
          </Card>
          {selected && (
            <Card title="数据对象关系" subtitle="导出与压缩对象均保留来源标识">
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>事件</th>
                      <th>数据对象</th>
                      <th>父对象</th>
                      <th>数据渠道</th>
                      <th>结果</th>
                    </tr>
                  </thead>
                  <tbody>
                    {records.data
                      ?.slice()
                      .reverse()
                      .map((r) => (
                        <tr key={r.event.event_id}>
                          <td>{r.event.event_type}</td>
                          <td className="mono">
                            {r.event.object_id ? short(r.event.object_id) : "—"}
                          </td>
                          <td className="mono">
                            {r.event.parent_object_id
                              ? short(r.event.parent_object_id)
                              : "—"}
                          </td>
                          <td>{r.event.channel}</td>
                          <td>
                            {r.outcome === "blocked" ? "已阻断" : "已执行"}
                          </td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>
            </Card>
          )}
        </>
      )}
      {p.page === "settings" && (
        <>
          <SandboxNotice />
          <AccountPanel user={p.user} onLogout={p.onLogout} />
          {p.user.role === "admin" &&
            p.health?.deployment?.authentication === "required" && (
              <UserManagement currentUser={p.user} />
            )}
          <LanguageModelStatus health={p.health} />
          <div className="settings-grid">
            <Card title="系统状态">
              <dl className="latency-list">
                <div>
                  <dt>服务状态</dt>
                  <dd>{p.health?.status === "ok" ? "运行正常" : "等待连接"}</dd>
                </div>
                <div>
                  <dt>应用版本</dt>
                  <dd>{p.health?.version || "—"}</dd>
                </div>
                <div>
                  <dt>数据环境</dt>
                  <dd>合成沙盒 + 独立公开数据目录</dd>
                </div>
                <div>
                  <dt>部署方式</dt>
                  <dd>
                    {p.health?.deployment?.network_mode === "lan"
                      ? "内网访问"
                      : p.health?.deployment?.network_mode === "local"
                        ? "本机访问"
                        : "未提供"}
                  </dd>
                </div>
                <div>
                  <dt>LLM 配置（非在线探测）</dt>
                  <dd>{p.health?.llm.enabled ? "已配置" : "未配置"}</dd>
                </div>
                <div>
                  <dt>操作保护</dt>
                  <dd>
                    {p.health?.deployment?.authentication === "local_demo"
                      ? "显式本机演示身份 + 操作令牌"
                      : "账号会话 + 角色权限 + CSRF 校验"}
                  </dd>
                </div>
              </dl>
            </Card>
            <TrainingInfo model={p.health?.model} />
          </div>
          <Card title="当前版本范围">
            <div className="info-note">
              <Info size={18} />
              <p>
                已提供账号登录与角色权限、沙盒演练、检测、可解释意图、链路关联、模拟阻断和离线评测。真实银行数据接入、企业统一身份集成与策略审批不属于当前已实现能力。
              </p>
            </div>
            <button className="button" onClick={() => p.navigate("lab")}>
              进入沙盒验证
              <ArrowRight size={15} />
            </button>
          </Card>
        </>
      )}
    </>
  );
}
