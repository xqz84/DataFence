import {
  ArrowRight,
  BriefcaseBusiness,
  CalendarClock,
  CheckCircle2,
  ClipboardList,
  FileSearch,
  Fingerprint,
  MapPin,
  UserRound,
} from "lucide-react";
import type { PageProps } from "../App";
import type { EmployeeDetail, Intent } from "../types";
import {
  Badge,
  Card,
  Empty,
  ErrorNotice,
  EventTimeline,
  Loading,
  Metric,
  PageHeading,
  ProgressBar,
  RiskRadar,
  TextLink,
  num,
  short,
  time,
  useApi,
} from "../ui";
import { AIAnalysisPanel, BotLabel } from "./MonitorDetail";
import { SemanticPanel } from "../SemanticPanel";

function EmployeeSelect(p: PageProps) {
  return (
    <select
      className="employee-select"
      aria-label="选择员工"
      value={p.employeeId}
      onChange={(e) => p.setEmployeeId(e.target.value)}
    >
      {p.employees.map((e) => (
        <option key={e.id} value={e.id}>
          {e.id} · {e.name} · {e.role}
        </option>
      ))}
    </select>
  );
}
export function Behavior(p: PageProps) {
  const profile = useApi<EmployeeDetail>(
    `/employees/${encodeURIComponent(p.employeeId)}`,
    2500,
  );
  const d = profile.data;
  const latest = d?.events[0];
  const employee = d?.employee;
  return (
    <>
      <PageHeading
        eyebrow="USER & BEHAVIOR ANALYTICS"
        title="员工行为画像"
        description="比较日常业务基线与当前访问，解释员工为什么在此刻偏离正常行为。"
        action={<EmployeeSelect {...p} />}
      />
      <ErrorNotice message={profile.error} />
      {profile.loading ? (
        <Loading />
      ) : d && employee ? (
        <>
          <div className="profile-banner card">
            <div className="profile-avatar">{employee.name.slice(-2)}</div>
            <div className="profile-identity">
              <h2>
                {employee.name}
                <span>{employee.id}</span>
              </h2>
              <p>
                <BriefcaseBusiness size={14} />
                {employee.role}
                <span /> {employee.department}
                <span />
                <MapPin size={14} />
                {employee.region}
              </p>
            </div>
            <div className="profile-fact">
              <span>可信设备</span>
              <strong className="mono">{employee.known_device}</strong>
            </div>
            <div className="profile-fact">
              <span>当前最高风险</span>
              <strong>
                {d.events.length
                  ? num(Math.max(...d.events.map((e) => e.analysis.risk_score)))
                  : "—"}
                <small>/ 100</small>
              </strong>
            </div>
            <span className="outline-label">合成员工</span>
          </div>
          <div className="metrics-grid four">
            <Metric
              label="基线日访问量"
              value={num(d.baseline.daily_records)}
              unit="条"
              detail="来自固定合成正常业务基线"
            />
            <Metric
              label="今日请求访问记录"
              value={num(d.current.records)}
              unit="条"
              detail="按今日处理的查询与 API 请求累计"
            />
            <Metric
              label="今日查询次数"
              value={num(d.current.queries)}
              unit="次"
              detail={`基线 ${num(d.baseline.daily_queries)} 次 / 日`}
            />
            <Metric
              label="今日涉及区域"
              value={num(d.current.regions)}
              unit="个"
              detail={`${num(d.current.exports)} 次导出行为`}
            />
          </div>
          <div className="profile-grid">
            <Card
              title="正常基线与当前行为"
              subtitle="当前值为北京时间今日处理的请求，包含被阻断请求；日基线为参考值"
            >
              <div className="comparison-legend">
                <span>
                  <i />
                  固定基线
                </span>
                <span>
                  <i />
                  当前行为
                </span>
              </div>
              <div className="behavior-comparison">
                {[
                  {
                    label: "访问记录数",
                    baseline: d.baseline.daily_records,
                    current: d.current.records,
                  },
                  {
                    label: "查询次数",
                    baseline: d.baseline.daily_queries,
                    current: d.current.queries,
                  },
                ].map((v) => {
                  const max = Math.max(v.baseline, v.current, 1);
                  return (
                    <div className="comparison-group" key={v.label}>
                      <div>
                        <strong>{v.label}</strong>
                        <span>
                          {v.baseline
                            ? `${(v.current / v.baseline).toFixed(1)} 倍基线`
                            : "无可比基线"}
                        </span>
                      </div>
                      <div className="comparison-row">
                        <span>基线</span>
                        <ProgressBar
                          value={(v.baseline / max) * 100}
                          color="#b4c9e9"
                        />
                        <strong>{num(v.baseline)}</strong>
                      </div>
                      <div className="comparison-row">
                        <span>当前</span>
                        <ProgressBar value={(v.current / max) * 100} />
                        <strong>{num(v.current)}</strong>
                      </div>
                    </div>
                  );
                })}
              </div>
              <div className="info-note">
                <FileSearch size={16} />
                <p>
                  数量偏离只是一项信号。是否有有效工单、授权范围和合理渠道，需要结合访问意图进一步核验。
                </p>
              </div>
            </Card>
            <Card
              title="最新事件风险维度"
              subtitle={
                latest
                  ? `${time(latest.event.timestamp)} · ${short(latest.event.event_id)}`
                  : "等待访问事件"
              }
            >
              {latest ? (
                <RiskRadar dimensions={latest.analysis.dimensions} />
              ) : (
                <Empty />
              )}
            </Card>
          </div>
          <div className="profile-grid">
            <Card
              title="员工行为时间线"
              subtitle="当前员工最近的已处理事件"
              action={<span className="count-label">{d.events.length} 条</span>}
            >
              <EventTimeline
                events={d.events.slice(0, 8)}
                onSelect={p.selectEvent}
              />
            </Card>
            <Card title="业务工单与授权" subtitle="意图核验的业务证据">
              <div className="task-list">
                {d.tasks.length ? (
                  d.tasks.map((task) => (
                    <div className="task-item" key={task.id}>
                      <span className="agent-icon">
                        <ClipboardList size={18} />
                      </span>
                      <div>
                        <strong>{task.purpose}</strong>
                        <small className="mono">{task.id}</small>
                        <p>
                          授权 {num(task.max_records)} 条 ·{" "}
                          {task.regions.join("、")}
                        </p>
                        <p>
                          {task.allow_export ? "允许导出" : "不含导出授权"} ·{" "}
                          {task.approved_channels.join(" / ")}
                        </p>
                      </div>
                    </div>
                  ))
                ) : (
                  <Empty
                    title="没有关联业务工单"
                    text="证据不足将在访问意图分析中明确标记。"
                  />
                )}
              </div>
              {latest && (
                <TextLink onClick={() => p.selectEvent(latest, "intent")}>
                  分析最新访问意图
                </TextLink>
              )}
            </Card>
          </div>
        </>
      ) : null}
    </>
  );
}

const intentDimensions = [
  {
    key: "role_match",
    name: "角色匹配",
    english: "Role Match",
    icon: UserRound,
  },
  {
    key: "purpose_match",
    name: "业务目的匹配",
    english: "Purpose Match",
    icon: BriefcaseBusiness,
  },
  {
    key: "scope_match",
    name: "数据范围匹配",
    english: "Scope Match",
    icon: Fingerprint,
  },
  {
    key: "time_match",
    name: "时间匹配",
    english: "Time Match",
    icon: CalendarClock,
  },
] as const;
export function IntentPage(p: PageProps) {
  const profile = useApi<EmployeeDetail>(
    `/employees/${encodeURIComponent(p.employeeId)}`,
    2500,
  );
  const events = profile.data?.events || [];
  const selected =
    events.find((e) => e.event.event_id === p.selected?.event.event_id) ||
    events[0];
  const task = profile.data?.tasks.find(
    (t) => t.id === selected?.event.task_id,
  );
  const intent = selected?.analysis.intent;
  return (
    <>
      <PageHeading
        eyebrow="PURPOSE-AWARE ACCESS"
        title="访问意图分析"
        description="有访问权限，还需要有合理的业务目的。让每一次访问都能回到可验证的业务依据。"
        action={<EmployeeSelect {...p} />}
      />
      <ErrorNotice message={profile.error} />
      {profile.loading ? (
        <Loading />
      ) : !selected ? (
        <Card>
          <Empty
            title="尚无可分析的访问"
            text="为当前员工运行一次演练，系统将结合业务工单给出意图匹配证据。"
            action={
              <button
                className="button primary"
                onClick={() => p.navigate("lab")}
              >
                前往演练
                <ArrowRight size={15} />
              </button>
            }
          />
        </Card>
      ) : (
        <>
          <div className="intent-event-selector">
            <span>
              <FileSearch size={16} />
              分析事件
            </span>
            <select
              aria-label="选择访问意图事件"
              value={selected.event.event_id}
              onChange={(e) => {
                const record = events.find(
                  (r) => r.event.event_id === e.target.value,
                );
                if (record) p.selectEvent(record, "intent");
              }}
            >
              {events.map((e) => (
                <option key={e.event.event_id} value={e.event.event_id}>
                  {time(e.event.timestamp)} · {e.event.event_type} ·{" "}
                  {num(e.event.record_count)} 条 · 风险 {e.analysis.risk_score}
                </option>
              ))}
            </select>
            <Badge level={selected.analysis.risk_level} />
          </div>
          <div className="intent-context-grid">
            <Card title="访问主体" className="context-card">
              <div className="context-icon">
                <UserRound size={21} />
              </div>
              <h3>
                {profile.data?.employee.name} <span>{p.employeeId}</span>
              </h3>
              <p>
                {profile.data?.employee.role} ·{" "}
                {profile.data?.employee.department}
              </p>
              <small>{profile.data?.employee.region}</small>
            </Card>
            <Card title="当前业务工单" className="context-card">
              <div className="context-icon">
                <ClipboardList size={21} />
              </div>
              <h3>{task?.purpose || "未匹配有效工单"}</h3>
              <p>
                {task?.id || selected.event.task_id || "当前事件没有提供工单"}
              </p>
              <small>
                {task
                  ? `额度 ${num(task.max_records)} 条 · ${task.regions.join("、")}`
                  : "以证据不足参与意图核验"}
              </small>
            </Card>
            <Card title="当前访问数据" className="context-card">
              <div className="context-icon">
                <Fingerprint size={21} />
              </div>
              <h3>
                {selected.event.resource}
                <span>{num(selected.event.record_count)} 条</span>
              </h3>
              <p>{selected.event.regions.join("、") || "未提供区域"}</p>
              <small>
                {time(selected.event.timestamp, true)} ·{" "}
                {selected.event.channel}
              </small>
            </Card>
          </div>
          {intent && <IntentScores intent={intent} />}
          <div className="intent-bottom-grid">
            <Card
              title="意图判断依据"
              subtitle="以当前事件和已存在的业务工单为证据"
            >
              <BotLabel analysis={selected.ai_analysis} />
              <p className="explanation-text">
                {selected.analysis.explanation}
              </p>
              <SemanticPanel record={selected} />
              <AIAnalysisPanel analysis={selected.ai_analysis} />
              <div className="evidence-checks">
                {intent?.evidence.map((e, i) => (
                  <div key={i}>
                    <span>{i + 1}</span>
                    <p>{e}</p>
                  </div>
                ))}
              </div>
            </Card>
            <Card title="风险与建议动作" subtitle="建议经策略编排后执行">
              <div className="intent-risk-score">
                <strong>
                  {num(selected.analysis.risk_score)}
                  <small>/ 100</small>
                </strong>
                <Badge level={selected.analysis.risk_level} />
              </div>
              <div className="rule-chips">
                {selected.analysis.rules.length ? (
                  selected.analysis.rules.map((r, i) => (
                    <span key={i}>{r}</span>
                  ))
                ) : (
                  <span>未命中风险规则</span>
                )}
              </div>
              <div className="suggested-actions">
                {selected.analysis.actions.map((a) => (
                  <div key={a}>
                    <ShieldAction />
                    <span>{a}</span>
                  </div>
                ))}
              </div>
              <TextLink onClick={() => p.selectEvent(selected)}>
                进入完整事件调查
              </TextLink>
            </Card>
          </div>
          <div className="info-note purpose-note">
            <FileSearch size={17} />
            <p>
              Intent Trust
              是业务证据的匹配评分，不代表识别员工真实心理意图。意图分数由工单与范围规则核验；涉敏
              AI
              请求的商汤执行前语义核验结果由本地策略决定风险与处置，普通事后解释不修改分数或授权动作。具体结果以上方事件状态为准。
            </p>
          </div>
        </>
      )}
    </>
  );
}
function ShieldAction() {
  return <CheckCircle2 size={15} />;
}
function IntentScores({ intent }: { intent: Intent }) {
  const status =
    intent.status === "supported"
      ? "业务目的有证据支持"
      : intent.status === "mismatch"
        ? "访问与业务目的不匹配"
        : "业务证据不足";
  return (
    <Card
      title="意图可信度评估"
      subtitle="角色、业务目的、数据范围与访问时间四维核验"
      className="intent-score-card"
    >
      <div className="intent-score-layout">
        <div
          className={`trust-gauge ${intent.trust >= 60 ? "supported" : "mismatch"}`}
        >
          <svg
            viewBox="0 0 180 180"
            role="img"
            aria-label={`意图可信度 ${intent.trust}`}
          >
            <circle
              cx="90"
              cy="90"
              r="74"
              fill="none"
              stroke="#edf1f6"
              strokeWidth="10"
            />
            <circle
              cx="90"
              cy="90"
              r="74"
              fill="none"
              stroke={intent.trust >= 60 ? "#239d7d" : "#d58a17"}
              strokeWidth="10"
              strokeLinecap="round"
              strokeDasharray={`${(intent.trust / 100) * 464.9} 464.9`}
              transform="rotate(-90 90 90)"
            />
          </svg>
          <div>
            <span>Intent Trust</span>
            <strong>
              {num(intent.trust)}
              <small>/100</small>
            </strong>
          </div>
          <p>{status}</p>
        </div>
        <div className="intent-dimensions">
          {intentDimensions.map(({ key, name, english, icon: Icon }) => (
            <div className="intent-dimension" key={key}>
              <span className="intent-dimension-icon">
                <Icon size={21} />
              </span>
              <div>
                <strong>{name}</strong>
                <small>{english}</small>
                <ProgressBar
                  value={intent[key]}
                  color={intent[key] >= 60 ? "#2670da" : "#d58a17"}
                />
              </div>
              <b>
                {num(intent[key])}
                <small>%</small>
              </b>
            </div>
          ))}
        </div>
      </div>
    </Card>
  );
}
