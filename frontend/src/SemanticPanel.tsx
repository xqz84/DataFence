import { MessageSquareText } from "lucide-react";
import type { EventRecord } from "./types";
import { analysisStatus, providerName, reasonLabel } from "./ai";
import { num } from "./ui";

export function SemanticPanel({ record }: { record: EventRecord }) {
  const analysis = record.semantic_analysis;
  if (!analysis) return null;
  const complete = analysis.status === "completed";
  const verdicts = {
    unsafe: "存在敏感数据处理风险",
    safe: "未发现该类语义风险",
    uncertain: "证据不足，待进一步核验",
  };
  const interpretations = {
    execute: "要求执行",
    negated: "否定指令",
    quoted: "引用文本",
    summary: "概述讨论",
    unknown: "无法确定",
  };
  return (
    <section
      className={`semantic-panel ${complete ? analysis.verdict || "uncertain" : "unavailable"}`}
      aria-label="执行前语义核验"
    >
      <div className="semantic-heading">
        <MessageSquareText size={17} />
        <div>
          <strong>执行前语义核验</strong>
          <small>在涉敏 AI 请求执行前，由策略编排器使用核验结果</small>
        </div>
        <span>
          {record.outcome === "blocked" ? "当前请求已阻断" : "当前请求已执行"}
        </span>
      </div>
      <div className="semantic-result">
        <strong>
          {complete && analysis.verdict
            ? verdicts[analysis.verdict]
            : analysisStatus(analysis)}
        </strong>
        {complete && analysis.interpretation && (
          <span>语义类型：{interpretations[analysis.interpretation]}</span>
        )}
      </div>
      <p>{analysis.reason || analysis.summary}</p>
      {!complete && analysis.status !== "skipped" && (
        <p className="semantic-failure-note">
          核验未完成{record.outcome === "blocked" ? "，本次 AI 请求已暂停" : ""}
          ；不能据此认定请求者存在恶意。
          {analysis.reason_code ? reasonLabel(analysis.reason_code) : ""}
        </p>
      )}
      {complete && analysis.evidence_quote && (
        <blockquote>
          <span>判定依据 · 原文引用</span>
          <p>{analysis.evidence_quote}</p>
        </blockquote>
      )}
      <div className="semantic-model-meta">
        <span>{providerName(analysis.provider)}</span>
        <span>{analysis.model || "未提供模型名称"}</span>
        <span>{num(analysis.elapsed_ms)} ms</span>
        {analysis.usage ? (
          <span>
            输入 {num(analysis.usage.prompt_tokens)} / 输出{" "}
            {num(analysis.usage.completion_tokens)} / 合计{" "}
            {num(analysis.usage.total_tokens)} tokens
          </span>
        ) : (
          <span>无 token 计量</span>
        )}
      </div>
      <small className="semantic-boundary">
        此处是执行前核验；补充分析若复用同一结果会单独标注。模型不直接执行数据库修改、冻结或阻断动作；最终风险和控制结果由本地策略融合决定，以本次请求实际状态为准。
      </small>
    </section>
  );
}
