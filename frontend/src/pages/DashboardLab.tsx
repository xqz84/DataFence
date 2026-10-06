import { useState } from "react";
import {
  Activity,
  ArrowRight,
  Bot,
  Boxes,
  Check,
  ChevronRight,
  Database,
  FileDown,
  FlaskConical,
  Layers,
  LoaderCircle,
  Play,
  Radio,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Users,
} from "lucide-react";
import type { PageProps } from "../App";
import { api } from "../api";
import { providerName } from "../ai";
import { RunPhase } from "../RunPhase";
import { DemoGuide } from "../DemoGuide";
import type { Agent, Run, SimulationRequest } from "../types";
import {
  Badge,
  CAPABILITY_NAMES,
  Card,
  Empty,
  ErrorNotice,
  EventsTable,
  Loading,
  Metric,
  PageHeading,
  ProgressBar,
  RISK_COLORS,
  RISK_NAMES,
  RiskChart,
  SandboxNotice,
  TextLink,
  num,
  useApi,
} from "../ui";

export function Dashboard(p: PageProps) {
  const agents = useApi<Agent[]>("/agents");
  const o = p.overview;
  const total = o
    ? Object.values(o.risk_distribution).reduce((a, b) => a + b, 0)
    : 0;
  return (
    <>
      <PageHeading
        eyebrow="SECURITY OVERVIEW"
        title="安全态势总览"
        description="从访问身份到业务意图，持续追踪敏感数据的每一次流动。"
        action={
          <>
            <span className="period-label">
              <Radio size={14} />
              今日事件 · 自动更新
            </span>
            <button
              className="button primary"
              onClick={() => p.navigate("lab")}
            >
              <FlaskConical size={16} />
              体验完整演示
              <ArrowRight size={15} />
            </button>
          </>
        }
      />
      <SandboxNotice compact />
      <div className="metrics-grid five">
        <Metric
          label="今日数据访问事件"
          value={num(o?.total_events)}
          detail="北京时间今日已处理事件"
          icon={<Activity size={19} />}
        />
        <Metric
          label="异常访问"
          value={num(o?.abnormal_events)}
          detail="风险评分达到告警阈值"
          icon={<ShieldAlert size={19} />}
          tone="orange"
        />
        <Metric
          label="高危事件"
          value={num(o?.high_risk_events)}
          detail="HIGH / CRITICAL"
          icon={<Shield size={19} />}
          tone="red"
        />
        <Metric
          label="自动阻断"
          value={num(o?.blocked_events)}
          detail="沙盒实际阻断的操作"
          icon={<ShieldCheck size={19} />}
          tone="green"
        />
        <Metric
          label="涉敏请求记录"
          value={num(o?.sensitive_records)}
          unit="条"
          detail="含阻断请求与重复流转"
          icon={<Database size={19} />}
          tone="purple"
        />
      </div>
      <div className="overview-grid">
        <Card
          title="24 小时风险趋势"
          subtitle="按真实事件聚合 · 纵轴为风险分数"
          action={
            <span className="chart-legend">
              <i />
              风险评分
            </span>
          }
        >
          <RiskChart
            points={o?.trend.map((t) => t.risk) || []}
            labels={o?.trend.map((t) =>
              t.hour.length > 10 ? t.hour.slice(11, 16) : t.hour,
            )}
          />
        </Card>
        <Card title="风险等级分布" subtitle="北京时间今日处理事件">
          <div className="distribution">
            <div className="donut">
              <svg viewBox="0 0 140 140" aria-label="风险等级分布" role="img">
                <circle
                  cx="70"
                  cy="70"
                  r="52"
                  fill="none"
                  stroke="#edf1f6"
                  strokeWidth="14"
                />
                {o &&
                  Object.entries(o.risk_distribution).map(
                    ([level, count], i, all) => {
                      const offset = all
                        .slice(0, i)
                        .reduce((s, a) => s + a[1], 0);
                      return (
                        <circle
                          key={level}
                          cx="70"
                          cy="70"
                          r="52"
                          fill="none"
                          stroke={
                            RISK_COLORS[level as keyof typeof RISK_COLORS]
                          }
                          strokeWidth="14"
                          strokeDasharray={`${total ? (count / total) * 326.7 : 0} 326.7`}
                          strokeDashoffset={
                            total ? (-offset / total) * 326.7 : 0
                          }
                          transform="rotate(-90 70 70)"
                        />
                      );
                    },
                  )}
              </svg>
              <div>
                <strong>{num(total)}</strong>
                <span>事件总数</span>
              </div>
            </div>
            <div className="distribution-list">
              {Object.entries(RISK_NAMES).map(([level, name]) => (
                <div key={level}>
                  <i
                    style={{
                      background:
                        RISK_COLORS[level as keyof typeof RISK_COLORS],
                    }}
                  />
                  <span>{name}</span>
                  <strong>
                    {o?.risk_distribution[level as keyof typeof RISK_COLORS] ??
                      "—"}
                  </strong>
                </div>
              ))}
            </div>
          </div>
        </Card>
      </div>
      <div className="overview-grid">
        <Card
          title="实时安全事件"
          subtitle="最新事件与实际策略处置结果"
          action={
            <TextLink onClick={() => p.navigate("events")}>查看全部</TextLink>
          }
        >
          {o ? (
            <EventsTable
              events={o.recent_events}
              onSelect={p.selectEvent}
              limit={5}
            />
          ) : (
            <Loading />
          )}
        </Card>
        <Card
          title="当前最高风险用户"
          action={
            <TextLink onClick={() => p.navigate("behavior")}>用户画像</TextLink>
          }
        >
          <div className="top-users">
            {o?.top_users.length ? (
              o.top_users.slice(0, 4).map((u, i) => (
                <button
                  key={u.employee_id}
                  onClick={() => {
                    p.setEmployeeId(u.employee_id);
                    p.navigate("behavior");
                  }}
                >
                  <span className="user-rank">{i + 1}</span>
                  <span className="avatar">{u.name.slice(-2)}</span>
                  <span className="user-info">
                    <strong>{u.name}</strong>
                    <small>
                      {u.employee_id} · {u.event_count} 条事件
                    </small>
                  </span>
                  <strong
                    className={`risk-number ${u.risk_score >= 60 ? "danger" : ""}`}
                  >
                    {num(u.risk_score)}
                  </strong>
                  <ChevronRight size={14} />
                </button>
              ))
            ) : (
              <Empty
                title="尚无风险用户"
                text="演练运行后自动形成用户风险排序。"
              />
            )}
          </div>
        </Card>
      </div>
      <Card
        title="安全能力运行状态"
        subtitle="规则、模型与意图核验协同工作；大模型接入状态单独标明"
        action={
          <TextLink onClick={() => p.navigate("agents")}>查看能力详情</TextLink>
        }
      >
        <div className="agent-strip">
          {agents.data?.map((a) => (
            <div key={a.id}>
              <span className="agent-icon">
                <Bot size={19} />
              </span>
              <strong>{CAPABILITY_NAMES[a.id] || a.name}</strong>
              <small>
                <i className={a.status === "not_configured" ? "pending" : ""} />
                {a.status === "not_configured"
                  ? "未配置"
                  : a.status === "ready" || a.status === "active"
                    ? "可用"
                    : a.status}
              </small>
            </div>
          )) || <Loading />}
        </div>
      </Card>
      <div className="overview-footnote">
        <Boxes size={14} />
        <span>合成沙盒规模</span>
        <strong>{num(o?.bank.employees)} 员工</strong>
        <strong>{num(o?.bank.customers)} 客户</strong>
        <strong>{num(o?.bank.accounts)} 账户</strong>
        <strong>{num(o?.bank.transactions)} 交易</strong>
        <span className="ml-auto">
          {p.health?.llm.enabled
            ? `${providerName(p.health.llm.provider)}已配置 · 调用结果以事件记录为准`
            : "LLM 未配置 · 当前使用可解释的规则 / 模型分析"}
        </span>
      </div>
    </>
  );
}

const scenarioIcons = [Users, Shield, FileDown, Activity, Bot, Layers];
export function Lab(p: PageProps) {
  const [form, setForm] = useState<SimulationRequest>({
    scenario_id: "combined",
    employee_id: p.employeeId,
    record_count: 18000,
    interval_ms: 800,
    seed: 42,
    export: true,
    compress: true,
    upload: true,
  });
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState("");
  const selected = p.scenarios.find((s) => s.id === form.scenario_id);
  const normal =
    form.scenario_id === "normal" || form.scenario_id === "approved_batch";
  const field = <K extends keyof SimulationRequest>(
    key: K,
    value: SimulationRequest[K],
  ) => setForm((old) => ({ ...old, [key]: value }));
  async function start() {
    if (!p.canOperate || starting) return;
    setStarting(true);
    setError("");
    try {
      const run = await api<Run>("/runs", { body: form });
      p.setRunId(run.id);
      p.setEmployeeId(form.employee_id);
      p.refresh();
      p.navigate("monitor");
    } catch (e) {
      setError(e instanceof Error ? e.message : "启动失败，请重试");
    } finally {
      setStarting(false);
    }
  }
  return (
    <>
      <PageHeading
        eyebrow="RED TEAM LAB"
        title="攻击模拟实验室"
        description="用可控的业务事件验证检测、关联与阻断，形成可追溯的防护闭环。"
        action={
          <span className="outline-label">
            <FlaskConical size={15} />
            本地隔离演练
          </span>
        }
      />
      <SandboxNotice />
      <details className="demo-assistant"><summary>辅助验证 · 完整演示</summary><DemoGuide {...p} /></details>
      {p.runs.some((run) => run.status === "running") && (
        <Card
          title="进行中的演练"
          subtitle="云模型调用可能需要数十秒，阶段与事件会自动更新"
        >
          <div className="lab-active-runs">
            {p.runs
              .filter((run) => run.status === "running")
              .map((run) => (
                <div key={run.id}>
                  <div>
                    <strong>
                      {p.scenarios.find((s) => s.id === run.scenario_id)
                        ?.name || run.scenario_id}{" "}
                      · {run.employee_id}
                    </strong>
                    <RunPhase run={run} compact />
                  </div>
                  <button
                    className="button"
                    onClick={() => {
                      p.setRunId(run.id);
                      p.setEmployeeId(run.employee_id);
                      p.navigate("monitor");
                    }}
                  >
                    查看监控
                    <ArrowRight size={14} />
                  </button>
                </div>
              ))}
          </div>
        </Card>
      )}
      <div className="lab-grid">
        <div>
          <Card title="选择演练场景" subtitle="六类异常场景 + 正常业务对照">
            <div className="scenario-grid">
              {p.scenarios
                .filter((s) => !["normal", "approved_batch"].includes(s.id))
                .map((s, i) => {
                  const Icon = scenarioIcons[i] || Layers;
                  return (
                    <button
                      key={s.id}
                      className={`scenario-card ${form.scenario_id === s.id ? "selected" : ""}`}
                      onClick={() => field("scenario_id", s.id)}
                    >
                      <div className="scenario-top">
                        <span>
                          <Icon size={21} />
                        </span>
                        <small>SCENARIO {String(i + 1).padStart(2, "0")}</small>
                        {form.scenario_id === s.id && <Check size={15} />}
                      </div>
                      <strong>{s.name}</strong>
                      <p>{s.description}</p>
                    </button>
                  );
                })}
            </div>
            <div className="normal-scenarios">
              <span>业务对照</span>
              {p.scenarios
                .filter((s) => ["normal", "approved_batch"].includes(s.id))
                .map((s) => (
                  <button
                    key={s.id}
                    className={form.scenario_id === s.id ? "selected" : ""}
                    onClick={() =>
                      setForm((old) => ({
                        ...old,
                        scenario_id: s.id,
                        record_count: s.id === "normal" ? 20 : 2000,
                      }))
                    }
                  >
                    <ShieldCheck size={16} />
                    {s.name}
                    {form.scenario_id === s.id && <Check size={14} />}
                  </button>
                ))}
            </div>
          </Card>
          <Card
            title="演练路径"
            subtitle="以下为计划步骤；实际执行以策略阻断点为准"
            className="mt-20"
          >
            <div className="planned-path">
              {selected?.steps.map((step, i) => (
                <div key={`${step}-${i}`}>
                  <span>{i + 1}</span>
                  <strong>{step}</strong>
                  {i < selected.steps.length - 1 && <ArrowRight size={15} />}
                </div>
              ))}
            </div>
            <div className="info-note">
              <ShieldCheck size={16} />
              <p>
                策略可以提前冻结会话。被截断的后续步骤显示为“未执行”，不会被记作已经发生的攻击链。
              </p>
            </div>
          </Card>
        </div>
        <Card
          title="演练参数"
          subtitle="参数仅用于合成事件生成"
          className="config-card"
        >
          <form
            onSubmit={(e) => {
              e.preventDefault();
              void start();
            }}
          >
            <label className="form-field">
              目标员工
              <select
                value={form.employee_id}
                onChange={(e) => field("employee_id", e.target.value)}
                required
              >
                {p.employees.map((e) => (
                  <option value={e.id} key={e.id}>
                    {e.id} · {e.name} · {e.role}
                  </option>
                ))}
              </select>
            </label>
            <div className="field-pair">
              <label className="form-field">
                目标数据
                <div className="read-only-field">
                  <Database size={15} />
                  合成客户信息
                </div>
              </label>
              <label className="form-field">
                数据级别
                <div className="read-only-field">
                  <span className="sensitivity">敏感数据</span>
                </div>
              </label>
            </div>
            <label className="form-field">
              访问数量 <span className="field-hint">1–50,000 条</span>
              <input
                type="number"
                min="1"
                max="50000"
                required
                value={form.record_count}
                onChange={(e) => field("record_count", Number(e.target.value))}
              />
            </label>
            <label className="form-field">
              攻击强度
              <select
                value={
                  form.record_count <= 100
                    ? "low"
                    : form.record_count <= 5000
                      ? "medium"
                      : "high"
                }
                onChange={(e) =>
                  field(
                    "record_count",
                    e.target.value === "low"
                      ? 100
                      : e.target.value === "medium"
                        ? 3000
                        : 18000,
                  )
                }
              >
                <option value="low">低 · 小规模访问</option>
                <option value="medium">中 · 批量访问</option>
                <option value="high">高 · 大规模访问</option>
              </select>
            </label>
            <div className="toggle-group">
              {(
                [
                  {
                    key: "export",
                    name: "文件导出",
                    hint: "请求生成 CSV 文件",
                  },
                  {
                    key: "compress",
                    name: "文件压缩",
                    hint: "仅在导出成功后执行",
                  },
                  {
                    key: "upload",
                    name: "外部上传",
                    hint: "仅写入本地模拟接收账本",
                  },
                ] as const
              ).map((t) => (
                <label className="toggle-row" key={t.key}>
                  <span>
                    <strong>{t.name}</strong>
                    <small>{t.hint}</small>
                  </span>
                  <input
                    type="checkbox"
                    checked={form[t.key]}
                    onChange={(e) => field(t.key, e.target.checked)}
                  />
                  <span className="toggle-switch" />
                </label>
              ))}
            </div>
            <label className="form-field">
              事件间隔
              <select
                value={form.interval_ms}
                onChange={(e) => field("interval_ms", Number(e.target.value))}
              >
                <option value="1500">慢速 · 1.5 秒 / 步</option>
                <option value="800">标准 · 0.8 秒 / 步</option>
                <option value="200">快速 · 0.2 秒 / 步</option>
                <option value="0">即时执行</option>
              </select>
            </label>
            <label className="form-field">
              随机种子
              <input
                type="number"
                min="0"
                max="2147483647"
                required
                value={form.seed}
                onChange={(e) => field("seed", Number(e.target.value))}
              />
            </label>
            <ErrorNotice message={error} />
            <button
              type="submit"
              className="button primary full-width start-button"
              disabled={
                !p.canOperate || starting || !p.employees.length || !selected
              }
            >
              {starting ? (
                <LoaderCircle size={17} className="spin" />
              ) : (
                <Play size={17} />
              )}{" "}
              {starting
                ? "正在启动演练…"
                : normal
                  ? "启动正常业务对照"
                  : "启动攻击演练"}
            </button>
            <p className="form-footer">
              {p.canOperate
                ? "启动后自动进入实时监控中心"
                : "当前账号为只读角色，不能启动演练。"}
            </p>
          </form>
        </Card>
      </div>
      {p.runs.length > 0 && (
        <Card title="最近演练" subtitle="持久化演练记录">
          <div className="recent-runs">
            {p.runs.slice(0, 4).map((r) => (
              <button
                key={r.id}
                onClick={() => {
                  p.setRunId(r.id);
                  p.setEmployeeId(r.employee_id);
                  p.navigate("monitor");
                }}
              >
                <span className="agent-icon">
                  <FlaskConical size={18} />
                </span>
                <span>
                  <strong>
                    {p.scenarios.find((s) => s.id === r.scenario_id)?.name ||
                      r.scenario_id}
                  </strong>
                  <small>
                    {r.employee_id} · 已处理 {r.processed_events}/
                    {r.planned_events}
                  </small>
                </span>
                <Badge
                  level={
                    r.max_risk >= 90
                      ? "CRITICAL"
                      : r.max_risk >= 60
                        ? "HIGH"
                        : r.max_risk >= 30
                          ? "MEDIUM"
                          : "LOW"
                  }
                />
                <ProgressBar
                  value={
                    r.planned_events
                      ? ((r.processed_events + r.skipped_events) /
                          r.planned_events) *
                        100
                      : 0
                  }
                />
                <ChevronRight size={16} />
              </button>
            ))}
          </div>
        </Card>
      )}
    </>
  );
}
