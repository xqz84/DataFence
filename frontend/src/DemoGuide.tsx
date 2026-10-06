import { useEffect, useRef, useState } from "react";
import {
  ArrowRight,
  Check,
  Circle,
  ClipboardCheck,
  LoaderCircle,
  Play,
  RotateCcw,
  ShieldCheck,
} from "lucide-react";
import type { PageProps } from "./App";
import type { EventRecord } from "./types";
import type { AgentWorkbenchData, Demo, EventReview } from "./workbenchTypes";
import { api } from "./api";
import {
  Badge,
  Card,
  ErrorNotice,
  Loading,
  num,
  short,
  time,
  useApi,
} from "./ui";
import { KnowledgePanel } from "./KnowledgePanel";
import { EventReviewPanel } from "./EventReviewPanel";

const DEMO_STATUS: Record<Demo["status"], string> = {
  running: "真实演练进行中",
  awaiting_review: "等待人工研判",
  completed: "演示闭环已确认",
  failed: "演示未通过",
  interrupted: "演示已中断",
};
const STEP_STATUS: Record<string, string> = {
  queued: "等待执行",
  running: "正在执行",
  completed: "执行完成",
  failed: "执行失败",
  interrupted: "已中断",
};
function initialDemo() {
  return new URL(window.location.href).searchParams.get("demo") || "";
}

export function DemoGuide(p: PageProps) {
  const [demoId, setDemoId] = useState(initialDemo);
  const [revision, setRevision] = useState(0);
  const [starting, setStarting] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [error, setError] = useState("");
  const [review, setReview] = useState<EventReview | null>(null);
  const [documentId, setDocumentId] = useState("");
  const [employeeId, setEmployeeId] = useState(p.employeeId);
  const pendingRequest = useRef<{ id: string; employee: string } | null>(null);
  const latest = useApi<Demo[]>("/demos", 5000, revision);
  const detail = useApi<Demo>(
    demoId ? `/demos/${encodeURIComponent(demoId)}` : null,
    1200,
    revision,
  );
  const demo = detail.data;
  const event = useApi<EventRecord>(
    demo?.selected_event_id
      ? `/events/${encodeURIComponent(demo.selected_event_id)}`
      : null,
  );
  const evidence = useApi<AgentWorkbenchData>(
    demo?.selected_event_id
      ? `/agents/workbench?event_id=${encodeURIComponent(demo.selected_event_id)}`
      : null,
  );
  const active = starting || demo?.status === "running";
  const eventId = demo?.selected_event_id;
  useEffect(() => {
    setReview(null);
    setDocumentId("");
  }, [eventId]);
  function selectDemo(id: string) {
    setDemoId(id);
    setError("");
    setReview(null);
    setDocumentId("");
    const url = new URL(window.location.href);
    if (id) url.searchParams.set("demo", id);
    else url.searchParams.delete("demo");
    window.history.replaceState(null, "", url.toString());
  }
  async function start() {
    if (!p.canOperate || active || !employeeId) return;
    setStarting(true);
    setError("");
    if (
      !pendingRequest.current ||
      pendingRequest.current.employee !== employeeId
    )
      pendingRequest.current = {
        id: crypto.randomUUID(),
        employee: employeeId,
      };
    try {
      const created = await api<Demo>("/demos", {
        body: {
          request_id: pendingRequest.current.id,
          employee_id: pendingRequest.current.employee,
        },
      });
      selectDemo(created.id);
      setRevision((value) => value + 1);
      pendingRequest.current = null;
      p.refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "演示启动失败");
    } finally {
      setStarting(false);
    }
  }
  async function confirm() {
    if (
      !demo ||
      !review?.current ||
      review.current.disposition === "needs_investigation" ||
      !p.canOperate ||
      confirming
    )
      return;
    setConfirming(true);
    setError("");
    try {
      await api<Demo>(`/demos/${encodeURIComponent(demo.id)}/confirm`, {
        body: { review_revision: review.revision },
      });
      setRevision((value) => value + 1);
      p.refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "演示确认失败");
    } finally {
      setConfirming(false);
    }
  }
  const businessSteps =
    demo?.steps.filter((step) => step.id !== "combined") || [];
  const riskStep = demo?.steps.find((step) => step.id === "combined");
  const stages = [
    {
      label: "业务对照",
      detail: "正常访问与工单内批量",
      done:
        !!businessSteps.length &&
        businessSteps.every(
          (step) => step.status === "completed" && step.passed,
        ),
      running: businessSteps.some((step) => step.status === "running"),
    },
    {
      label: "风险阻断",
      detail: "观察真实响应与接收量",
      done: riskStep?.status === "completed" && riskStep.passed,
      running: riskStep?.status === "running",
    },
    {
      label: "证据与条款",
      detail: "解释为何产生该判断",
      done: !!event.data && !!evidence.data,
      running: event.loading && !!eventId,
    },
    {
      label: "审计校验",
      detail: "核对持久化证据链",
      done: demo?.audit?.valid === true,
      running: false,
    },
    {
      label: "人工确认",
      detail: "记录结论并完成闭环",
      done: demo?.status === "completed",
      running: demo?.status === "awaiting_review",
    },
  ];
  const canConfirm =
    demo?.status === "awaiting_review" &&
    demo.audit?.valid &&
    demo.checks.length > 0 &&
    demo.checks.every((check) => check.passed) &&
    review &&
    review.event_id === eventId &&
    review.current &&
    review.current.disposition !== "needs_investigation";
  return (
    <Card
      title="完整演示 · 从正常业务到风险研判"
      subtitle="一次串联业务对照、真实阻断、证据解释、审计与人工结论"
      className="demo-guide"
      action={
        <span className="outline-label">
          <ShieldCheck size={14} />
          本地检测 · 不调用云模型
        </span>
      }
    >
      <p className="workbench-muted">
        此引导验证合成沙盒中的本地防护闭环，不代表银行生产效果。商汤的实际语义实验可在
        <button
          className="inline-action"
          onClick={() => p.navigate("evaluation")}
        >
          评测与报告
        </button>
        查看。
      </p>
      <div className="demo-stages">
        {stages.map((stage, index) => (
          <div
            key={stage.label}
            className={`${stage.done ? "done" : ""} ${stage.running ? "current" : ""}`}
          >
            <span className="demo-stage-icon">
              {stage.done ? (
                <Check size={17} />
              ) : stage.running ? (
                <LoaderCircle size={17} className="spin" />
              ) : (
                index + 1
              )}
            </span>
            <strong>{stage.label}</strong>
            <small>{stage.detail}</small>
          </div>
        ))}
      </div>
      <div className="demo-controls">
        <label>
          演示员工
          <select
            value={employeeId}
            onChange={(e) => setEmployeeId(e.target.value)}
            disabled={!p.canOperate || active}
          >
            {p.employees.map((employee) => (
              <option key={employee.id} value={employee.id}>
                {employee.name} · {employee.id}
              </option>
            ))}
          </select>
        </label>
        <button
          className="button primary"
          onClick={() => void start()}
          disabled={
            !p.canOperate ||
            active ||
            !p.employees.some((employee) => employee.id === employeeId)
          }
        >
          {starting ? (
            <LoaderCircle size={16} className="spin" />
          ) : (
            <Play size={16} />
          )}
          {starting ? "正在创建" : demo ? "开始新完整演示" : "开始完整演示"}
        </button>
        <label className="demo-history-select">
          继续已有演示
          <select
            aria-label="选择完整演示记录"
            value={demoId}
            onChange={(e) => selectDemo(e.target.value)}
            disabled={starting}
          >
            <option value="">选择持久化演示记录</option>
            {demoId && !latest.data?.some((item) => item.id === demoId) && (
              <option value={demoId}>{short(demoId)}</option>
            )}
            {latest.data?.map((item) => (
              <option key={item.id} value={item.id}>
                {time(item.created_at, true)} · {DEMO_STATUS[item.status]} ·{" "}
                {item.employee_id}
              </option>
            ))}
          </select>
        </label>
      </div>
      {!p.canOperate && (
        <p className="table-note">
          当前账号可以查阅演示证据；创建演示与人工确认需要分析员或管理员权限。
        </p>
      )}
      <ErrorNotice
        message={
          error || detail.error || latest.error || event.error || evidence.error
        }
      />
      {detail.error && (
        <button
          className="button"
          onClick={() => setRevision((value) => value + 1)}
        >
          <RotateCcw size={14} />
          重新读取演示
        </button>
      )}
      {demoId && detail.loading && <Loading />}
      {demo && (
        <div className="demo-results">
          <div className="demo-result-heading">
            <div>
              <span
                className={`status ${demo.status === "completed" ? "completed" : demo.status === "running" ? "running" : ""}`}
              >
                <i />
                {DEMO_STATUS[demo.status]}
              </span>
              <p>
                {demo.actor} · {time(demo.created_at, true)} · 员工{" "}
                {demo.employee_id}
              </p>
            </div>
            <code>{short(demo.id)}</code>
          </div>
          {demo.status === "running" && (
            <div className="info-note">
              <LoaderCircle size={17} className="spin" />
              <p>
                后台正在执行真实沙盒事件。步骤、接收记录与检查结果会自动更新；刷新页面可继续查看这一次演示。
              </p>
            </div>
          )}
          {demo.error && <ErrorNotice message={demo.error} />}
          <div className="demo-run-results">
            {demo.steps.map((step) => (
              <div key={step.id}>
                <div className="demo-run-title">
                  <strong>{step.title}</strong>
                  <span
                    className={
                      step.passed === false
                        ? "text-danger"
                        : step.passed
                          ? "text-green"
                          : ""
                    }
                  >
                    {step.passed === false
                      ? "检查未通过"
                      : STEP_STATUS[step.status]}
                  </span>
                </div>
                <p>{step.summary || "等待执行结果，不预填通过状态。"}</p>
                <div className="demo-run-facts">
                  <span>
                    已处理 <b>{num(step.processed_events)}</b>
                  </span>
                  <span>
                    阻断 <b>{num(step.blocked_events)}</b>
                  </span>
                  <span>
                    依赖跳过 <b>{num(step.skipped_events)}</b>
                  </span>
                  <span>
                    接收 <b>{num(step.sink_records)} 条</b>
                  </span>
                </div>
                {step.run_id && (
                  <button
                    className="inline-action"
                    onClick={() => {
                      p.setRunId(step.run_id!);
                      p.setEmployeeId(demo.employee_id);
                      p.navigate("monitor");
                    }}
                  >
                    查看此步监控
                    <ArrowRight size={13} />
                  </button>
                )}
              </div>
            ))}
          </div>
          {!!demo.checks.length && (
            <div className="demo-checks">
              {demo.checks.map((check) => (
                <div key={check.id}>
                  {check.passed ? (
                    <Check size={16} className="text-green" />
                  ) : (
                    <Circle size={16} className="text-danger" />
                  )}
                  <span>
                    <strong>{check.title}</strong>
                    <small>{check.detail}</small>
                  </span>
                </div>
              ))}
            </div>
          )}
          {event.data && (
            <div className="demo-bound-event">
              <div>
                <span className="section-caption">本次演示绑定证据</span>
                <h3>
                  {event.data.outcome === "blocked"
                    ? "风险请求已被实际阻断"
                    : "已记录实际处置结果"}
                </h3>
                <p>
                  工单 {event.data.event.task_id || "未关联"} · 请求{" "}
                  {num(event.data.event.record_count)} 条 / 实际执行{" "}
                  {num(event.data.executed_records)} 条
                </p>
                <details className="model-details">
                  <summary>查看检测原文</summary>
                  <p>{event.data.analysis.explanation}</p>
                </details>
                <Badge level={event.data.analysis.risk_level} />
              </div>
              <button
                className="button"
                onClick={() => p.selectEvent(event.data!, "agents")}
              >
                进入智能体分析工作台
                <ArrowRight size={15} />
              </button>
            </div>
          )}
          {evidence.data && (
            <KnowledgePanel
              related={evidence.data.related_knowledge}
              documentId={documentId}
              onDocumentChange={setDocumentId}
            />
          )}
          <div className="demo-audit">
            <ShieldCheck size={21} />
            <div>
              <strong>
                {demo.audit
                  ? demo.audit.valid
                    ? "审计证据链校验通过"
                    : "审计证据链校验失败"
                  : "等待审计校验结果"}
              </strong>
              <p>
                {demo.audit
                  ? `实际核验 ${num(demo.audit.checked_events)} 条持久化事件；完整性校验不等同于业务判断正确。`
                  : "后台执行完成后提供实际校验结果。"}
              </p>
            </div>
          </div>
          {eventId && (
            <EventReviewPanel
              key={eventId}
              eventId={eventId}
              canReview={p.canOperate}
              onReviewed={setReview}
            />
          )}
          <div className="demo-confirm">
            <div>
              <strong>
                {demo.status === "completed"
                  ? "本次演示已完成人工确认"
                  : "完成前，由操作员确认结论"}
              </strong>
              <p>
                {demo.status === "completed"
                  ? `已关联研判第 ${demo.review_revision} 版。原始风险评分、阻断记录与额度保持不变。`
                  : review?.current?.disposition === "needs_investigation"
                    ? "当前结论为继续调查，请完成核验并追加明确结论后再确认。"
                    : "只有自动检查通过、审计有效且已保存明确人工结论，才能确认完成。"}
              </p>
            </div>
            <button
              className="button primary"
              disabled={!p.canOperate || !canConfirm || confirming}
              onClick={() => void confirm()}
            >
              {confirming ? (
                <LoaderCircle size={16} className="spin" />
              ) : (
                <ClipboardCheck size={16} />
              )}
              {demo.status === "completed" ? "已完成确认" : "确认本次演示结论"}
            </button>
          </div>
        </div>
      )}
    </Card>
  );
}
