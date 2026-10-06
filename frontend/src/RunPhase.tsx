import { useEffect, useState } from "react";
import { LoaderCircle } from "lucide-react";
import type { Run } from "./types";
import { EVENT_NAMES } from "./ui";

const PHASES = {
  queued: { title: "等待调度", note: "演练已提交，等待后台开始处理。" },
  detecting: {
    title: "事件检测与策略核验",
    note: "正在处理当前事件，随后更新真实风险与处置记录。",
  },
  semantic_review: {
    title: "执行前语义核验",
    note: "当前涉敏 AI 请求正在执行前核验。云模型调用可能需要数十秒，核验结果与实际处置将自动更新。",
  },
  model_explanation: {
    title: "事后附加解释",
    note: "正在等待模型补充解释，可能需要数十秒。实际控制结果以随后显示的事件处置记录为准。",
  },
  completed: { title: "已完成", note: "" },
  failed: { title: "执行失败", note: "" },
};

export function RunPhase({
  run,
  compact = false,
}: {
  run: Run;
  compact?: boolean;
}) {
  const [now, setNow] = useState(Date.now);
  useEffect(() => {
    if (run.status !== "running") return;
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, [run.status]);
  if (run.status !== "running") return null;
  const phase = run.phase
    ? PHASES[run.phase]
    : { title: "正在处理演练", note: "页面将自动刷新真实事件与处置结果。" };
  const started = run.phase_started_at ? Date.parse(run.phase_started_at) : NaN;
  const elapsed = Number.isFinite(started)
    ? Math.max(0, Math.floor((now - started) / 1000))
    : null;
  const isModel =
    run.phase === "semantic_review" || run.phase === "model_explanation";
  if (compact)
    return (
      <span className="run-phase-compact">
        <LoaderCircle className="spin" size={12} />
        <span>
          {phase.title}
          {elapsed !== null ? ` · 已等待 ${elapsed} 秒` : ""}
          {isModel && <small>模型调用进行中，自动更新</small>}
        </span>
      </span>
    );
  return (
    <section className={`run-phase-panel ${isModel ? "model-wait" : ""}`}>
      <span className="run-phase-icon">
        <LoaderCircle className="spin" size={22} />
      </span>
      <div>
        <strong>
          {phase.title}
          {run.current_event_type && (
            <span>
              {EVENT_NAMES[run.current_event_type] || run.current_event_type}
            </span>
          )}
        </strong>
        <p>{phase.note}</p>
      </div>
      {elapsed !== null && (
        <span className="run-phase-elapsed">
          当前阶段 <b>{elapsed}</b> 秒
        </span>
      )}
    </section>
  );
}
