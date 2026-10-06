import { useState } from "react";
import {
  ArrowRight,
  BookOpen,
  Bot,
  BrainCircuit,
  FileSearch,
  ShieldCheck,
} from "lucide-react";
import type { PageProps } from "./App";
import type { EventRecord } from "./types";
import type {
  AgentWorkbenchData,
  KnowledgeHit,
  WorkbenchModule,
} from "./workbenchTypes";
import {
  Badge,
  CAPABILITY_NAMES,
  INTENT_NAMES,
  Card,
  Empty,
  ErrorNotice,
  EVENT_NAMES,
  Loading,
  PageHeading,
  num,
  short,
  time,
  useApi,
} from "./ui";
import { KnowledgePanel } from "./KnowledgePanel";
import { EventReviewPanel } from "./EventReviewPanel";
import { LanguageModelStatus, TrainingInfo } from "./ModelStatus";
import { providerName, reasonLabel } from "./ai";
import { AIAnalysisPanel } from "./pages/MonitorDetail";
import { SemanticPanel } from "./SemanticPanel";

export function AgentWorkbench(p: PageProps) {
  const records = useApi<EventRecord[]>("/events?limit=100", 5000, p.revision);
  const selected =
    p.selected ||
    (p.selectedEventId
      ? records.data?.find(
          (record) => record.event.event_id === p.selectedEventId,
        )
      : records.data?.[0]) ||
    null;
  const data = useApi<AgentWorkbenchData>(
    p.selectedEventId && !selected
      ? null
      : `/agents/workbench${selected ? `?event_id=${encodeURIComponent(selected.event.event_id)}` : ""}`,
    5000,
    p.revision,
  );
  const [documentId, setDocumentId] = useState("");
  const options = records.data ? [...records.data] : [];
  if (
    selected &&
    !options.some((r) => r.event.event_id === selected.event.event_id)
  )
    options.unshift(selected);
  const llm = data.data?.llm;
  function openDocument(id: string) {
    setDocumentId(id);
    document
      .getElementById("workbench-knowledge")
      ?.scrollIntoView({ behavior: "smooth", block: "start" });
  }
  return (
    <>
      <PageHeading
        eyebrow="EVIDENCE WORKBENCH"
        title="AI安全智能体"
        description="从实际事件出发，查看六个能力模块如何形成判断，并用项目条款核对依据。"
        action={
          <button className="button" onClick={() => p.navigate("lab")}>
            完整演示
            <ArrowRight size={16} />
          </button>
        }
      />
      <div className="workbench-intro">
        <span className="agent-icon">
          <ShieldCheck size={24} />
        </span>
        <div>
          <strong>解决“有权限，却偏离业务目的”的访问风险</strong>
          <p>
            规则核验工单与数据边界，本地模型识别行为偏离，关联模块还原流转链路。商汤可核验涉敏
            AI 请求；最终动作由本地策略执行。
          </p>
        </div>
        <span className="outline-label">六能力协同 · 非六个大模型</span>
      </div>
      <ErrorNotice message={records.error || data.error} />
      <Card
        title="选择调查对象"
        subtitle="模块证据来自所选事件关联演练中已持久化的记录，最多 500 条"
      >
        <label className="workbench-event-select">
          真实处理事件
          <select
            aria-label="选择工作台事件"
            value={selected?.event.event_id || ""}
            onChange={(e) => {
              const record = options.find(
                (r) => r.event.event_id === e.target.value,
              );
              if (record) p.selectEvent(record, "");
            }}
          >
            <option value="" disabled>
              选择已处理事件
            </option>
            {options.map((record) => (
              <option key={record.event.event_id} value={record.event.event_id}>
                {time(record.event.timestamp, true)} ·{" "}
                {record.event.employee_id} ·{" "}
                {EVENT_NAMES[record.event.event_type] ||
                  record.event.event_type}{" "}
                · {record.outcome === "blocked" ? "已阻断" : "已执行"} ·{" "}
                {short(record.event.event_id)}
              </option>
            ))}
          </select>
        </label>
        {records.loading && !selected && <Loading />}
        {selected ? (
          <div className="workbench-decision">
            <div>
              <span
                className={`decision-symbol ${selected.outcome === "blocked" ? "blocked" : ""}`}
              >
                <ShieldCheck size={25} />
              </span>
              <div>
                <span className="section-caption">实际执行结果</span>
                <h3>
                  {selected.outcome === "blocked" ? "请求已阻断" : "操作已执行"}
                </h3>
                <p>
                  工单 {selected.event.task_id || "未关联"} · 目的核验{" "}
                  {INTENT_NAMES[selected.analysis.intent.status] ||
                    selected.analysis.intent.status}{" "}
                  · {selected.event.purpose}
                </p>
                <details className="model-details">
                  <summary>查看检测原文</summary>
                  <p>{selected.analysis.explanation}</p>
                </details>
              </div>
            </div>
            <div className="decision-facts">
              <Badge level={selected.analysis.risk_level} />
              <span>
                风险分 <strong>{num(selected.analysis.risk_score)}</strong>
              </span>
              <span>
                请求 / 执行{" "}
                <strong>
                  {num(selected.event.record_count)} /{" "}
                  {num(selected.executed_records)} 条
                </strong>
              </span>
              <button
                className="button"
                onClick={() => p.selectEvent(selected)}
              >
                <FileSearch size={15} />
                查看完整事件
              </button>
            </div>
          </div>
        ) : (
          !records.loading && (
            <Empty
              title="先运行一次演示，再查看判断依据"
              text="没有真实事件时，不生成示例证据或虚构模型调用。知识库仍可检索。"
              action={
                <button
                  className="button primary"
                  onClick={() => p.navigate("lab")}
                >
                  前往完整演示
                  <ArrowRight size={15} />
                </button>
              }
            />
          )
        )}
      </Card>
      <div className="workbench-section-heading">
        <div>
          <h2>六个模块，各自提供了什么依据</h2>
          <p>展示实际已观测记录；未命中规则也会保留核验结果。</p>
        </div>
        <span className="outline-label">
          本次分析范围 {num(data.data?.event_count)} 条事件
        </span>
      </div>
      {data.loading && <Loading />}
      <div className="workbench-modules">
        {data.data?.modules.map((module, i) => (
          <Card key={module.id} className="workbench-module">
            <div className="module-heading">
              <span className="module-number">
                {String(i + 1).padStart(2, "0")}
              </span>
              <span className="outline-label">
                {module.execution_kind === "local_ml" ? (
                  <BrainCircuit size={13} />
                ) : (
                  <ShieldCheck size={13} />
                )}
                {module.execution_kind === "local_ml"
                  ? "本地行为模型"
                  : "确定性规则与关联"}
              </span>
            </div>
            <h3>{CAPABILITY_NAMES[module.id] || module.name}</h3>
            <p className="module-description">{module.description}</p>
            {module.status === "no_observations" ? (
              <p className="module-no-evidence">尚无已观测证据</p>
            ) : (
              <div className="module-findings">
                {module.findings.slice(0, 1).map((finding) => (
                  <FindingEvidence
                    key={finding.event_id}
                    finding={finding}
                    related={data.data?.related_knowledge || []}
                    openDocument={openDocument}
                  />
                ))}
                {module.findings.length > 1 && (
                  <details className="additional-findings">
                    <summary>
                      同演练其他证据（{module.findings.length - 1}）
                    </summary>
                    {module.findings.slice(1).map((finding, index) => (
                      <FindingEvidence
                        key={`${finding.event_id}-${index}`}
                        finding={finding}
                        related={data.data?.related_knowledge || []}
                        openDocument={openDocument}
                      />
                    ))}
                  </details>
                )}
              </div>
            )}
            <div className="module-footer">
              <span>核验 {module.evaluated_events} 条</span>
              <details>
                <summary>实现说明</summary>
                <p>{module.implementation}</p>
              </details>
            </div>
          </Card>
        ))}
      </div>
      <Card
        title="商汤与其他语言模型实际参与情况"
        subtitle="执行前语义核验与事后解释分开展示；配置成功不等于调用完成"
      >
        <div className="llm-evidence-summary">
          <Bot size={25} />
          <div>
            <strong>
              {llm?.configured
                ? `${providerName(llm.provider || undefined)}已配置`
                : "语言模型未配置"}
            </strong>
            <p>
              {llm?.model || "无模型信息"} ·
              仅统计当前分析范围，语义结果复用不重复计次。
            </p>
          </div>
          <span>
            完成 <b>{num(llm?.completed_calls)}</b> 次
          </span>
          <span>
            失败 <b>{num(llm?.failed_calls)}</b> 次
          </span>
        </div>
        {selected && (
          <>
            <SemanticPanel record={selected} />
            <AIAnalysisPanel analysis={selected.ai_analysis} />
          </>
        )}
        {llm && !llm.call_records.length && (
          <p className="table-note">
            当前范围没有模型处理状态记录。以上六模块证据不能作为商汤已参与的证明。
          </p>
        )}
        {!!llm?.call_records.length && (
          <details className="model-details">
            <summary>模型处理状态记录 ({llm.call_records.length})</summary>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>事件</th>
                    <th>用途</th>
                    <th>结果</th>
                    <th>耗时</th>
                  </tr>
                </thead>
                <tbody>
                  {llm.call_records.map((call, index) => (
                    <tr key={`${call.event_id}-${index}`}>
                      <td className="mono">{short(call.event_id)}</td>
                      <td>
                        {call.purpose === "semantic"
                          ? "执行前语义核验"
                          : "事后辅助解释"}
                      </td>
                      <td>
                        {call.status === "completed"
                          ? "已完成"
                          : reasonLabel(call.reason_code || call.status)}
                      </td>
                      <td>{num(call.elapsed_ms)} ms</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </details>
        )}
      </Card>
      <div id="workbench-knowledge">
        <KnowledgePanel
          related={data.data?.related_knowledge || []}
          documentId={documentId}
          onDocumentChange={setDocumentId}
        />
      </div>
      {selected && (
        <EventReviewPanel
          key={selected.event.event_id}
          eventId={selected.event.event_id}
          canReview={p.canOperate}
        />
      )}
      <details className="advanced-section">
        <summary>模型服务、训练信息与能力边界</summary>
        <LanguageModelStatus health={p.health} />
        <TrainingInfo model={p.health?.model} />
        {data.data?.limitations.map((text) => (
          <p key={text} className="table-note">
            {text}
          </p>
        ))}
      </details>
    </>
  );
}

function FindingEvidence({
  finding,
  related,
  openDocument,
}: {
  finding: WorkbenchModule["findings"][number];
  related: KnowledgeHit[];
  openDocument: (id: string) => void;
}) {
  return (
    <div className="finding-evidence">
      <p>{finding.summary}</p>
      <span className="evidence-source">事件 {short(finding.event_id)}</span>
      <div className="citation-links">
        {finding.knowledge_ids.map((id) => (
          <button key={id} onClick={() => openDocument(id)}>
            <BookOpen size={12} />
            {related.find((hit) => hit.id === id)?.title || id}
          </button>
        ))}
      </div>
      <details className="model-details">
        <summary>核对原始证据字段</summary>
        <dl className="evidence-values">
          {Object.entries(finding.values).map(([key, value]) => (
            <div key={key}>
              <dt>{key}</dt>
              <dd>
                {value === null
                  ? "未提供"
                  : typeof value === "boolean"
                    ? value
                      ? "是"
                      : "否"
                    : String(value)}
              </dd>
            </div>
          ))}
        </dl>
      </details>
    </div>
  );
}
