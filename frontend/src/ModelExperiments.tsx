import { CircleAlert, FileCheck2, FlaskConical, Info } from "lucide-react";
import type { Metrics } from "./types";
import {
  Card,
  Empty,
  ErrorNotice,
  Loading,
  num,
  pct,
  time,
  useApi,
} from "./ui";

interface ModelExperiment {
  id: string;
  created_at: string | null;
  protocol: string | null;
  status: string | null;
  model: string | null;
  provider: "sensenova";
  kind: "development_diagnostic";
  artifact_digests_valid: boolean;
  summary: {
    planned_cases: number | null;
    attempted_cases: number | null;
    completed_reviews: number | null;
    review_coverage: number | null;
    status_counts: Record<string, number> | null;
    baseline_metrics: Metrics | null;
    final_metrics: Metrics | null;
    request_blocking_metrics: Metrics | null;
    usage: {
      reported_calls: number | null;
      missing_calls: number | null;
      prompt_tokens: number | null;
      completion_tokens: number | null;
      total_tokens: number | null;
    } | null;
    review_wall_ms: {
      samples: number | null;
      p50: number | null;
      p95: number | null;
      maximum: number | null;
    } | null;
    cost: unknown;
    ai_output_block_effectiveness_measured: boolean | null;
  };
  limitations: string[];
}

const CALL_STATUSES: Record<string, string> = {
  completed: "核验完成",
  unavailable: "调用不可用 / 超时 / 预算限制",
  invalid_response: "输出校验失败",
  not_configured: "未配置",
  skipped: "未触发核验",
};
const REPORT_STATUSES: Record<string, string> = {
  completed: "已完成",
  stopped: "提前停止",
  interrupted: "已中断",
  running: "记录中",
};
const seconds = (milliseconds?: number | null) =>
  milliseconds == null ? "—" : `${(milliseconds / 1000).toFixed(2)} 秒`;

function ExperimentReport({ experiment }: { experiment: ModelExperiment }) {
  const s = experiment.summary;
  const blocking = s.request_blocking_metrics;
  const legitimate = blocking ? blocking.fp + blocking.tn : null;
  const abnormal = blocking ? blocking.tp + blocking.fn : null;
  const heldRate = blocking && legitimate ? blocking.fp / legitimate : null;
  return (
    <article
      className={`diagnostic-report ${experiment.artifact_digests_valid ? "" : "untrusted"}`}
    >
      <header>
        <div>
          <strong className="mono">{experiment.id}</strong>
          <span>
            {time(experiment.created_at, true)} ·{" "}
            {experiment.status
              ? REPORT_STATUSES[experiment.status] || experiment.status
              : "状态未标记"}
          </span>
        </div>
        <span
          className={`diagnostic-integrity ${experiment.artifact_digests_valid ? "valid" : "invalid"}`}
        >
          {experiment.artifact_digests_valid ? (
            <FileCheck2 size={14} />
          ) : (
            <CircleAlert size={14} />
          )}{" "}
          {experiment.artifact_digests_valid ? "产物摘要校验通过" : "不可采信"}
        </span>
      </header>
      <div className="diagnostic-model">
        <span>商汤 SenseNova · {experiment.model || "模型未记录"}</span>
        <span>{experiment.protocol || "协议未记录"}</span>
      </div>
      {!experiment.artifact_digests_valid ? (
        <div className="error-notice" role="alert">
          <CircleAlert size={17} />
          <span>
            产物摘要校验未通过，本条报告不可采信。指标不作为有效实验结果展示。
          </span>
        </div>
      ) : (
        <>
          <div className="diagnostic-metrics">
            <div>
              <span>语义核验完成覆盖率</span>
              <strong>{pct(s.review_coverage)}</strong>
              <small>
                {num(s.completed_reviews)} / {num(s.planned_cases)} 个计划样例
              </small>
            </div>
            <div>
              <span>风险评分分类 F1</span>
              <strong>{pct(s.final_metrics?.f1)}</strong>
              <small>旧版综合初筛 F1（iforest-v1）{pct(s.baseline_metrics?.f1)}</small>
            </div>
            <div className="business-impact">
              <span>合法请求误暂缓</span>
              <strong>
                {num(blocking?.fp)}
                <small> / {num(legitimate)}</small>
              </strong>
              <small>FP / (FP + TN) · {pct(heldRate)}</small>
            </div>
            <div>
              <span>异常请求被控制</span>
              <strong>
                {num(blocking?.tp)}
                <small> / {num(abnormal)}</small>
              </strong>
              <small>TP / (TP + FN)，仅请求级</small>
            </div>
          </div>
          <div className="diagnostic-outcome-note">
            <strong>合法业务影响同时计入</strong>
            <span>
              合法请求：误暂缓 FP {num(blocking?.fp)}，正常放行 TN{" "}
              {num(blocking?.tn)}，分母 {num(legitimate)}。异常请求未被控制 FN{" "}
              {num(blocking?.fn)}。
            </span>
          </div>
          <dl className="diagnostic-facts">
            <div>
              <dt>已尝试 / 计划样例</dt>
              <dd>
                {num(s.attempted_cases)} / {num(s.planned_cases)}
              </dd>
            </div>
            <div>
              <dt>分类 TP / FP / TN / FN</dt>
              <dd>
                {num(s.final_metrics?.tp)} / {num(s.final_metrics?.fp)} /{" "}
                {num(s.final_metrics?.tn)} / {num(s.final_metrics?.fn)}
              </dd>
            </div>
            <div>
              <dt>语义核验耗时 P50 / P95</dt>
              <dd>
                {seconds(s.review_wall_ms?.p50)} /{" "}
                {seconds(s.review_wall_ms?.p95)}
              </dd>
            </div>
            <div>
              <dt>延迟计量样本数</dt>
              <dd>{num(s.review_wall_ms?.samples)}</dd>
            </div>
            <div>
              <dt>已报告输入 / 输出 tokens</dt>
              <dd>
                {num(s.usage?.prompt_tokens)} /{" "}
                {num(s.usage?.completion_tokens)}
              </dd>
            </div>
            <div>
              <dt>已报告 tokens 合计</dt>
              <dd>{num(s.usage?.total_tokens)}</dd>
            </div>
            <div>
              <dt>有计量 / 未知计量次数</dt>
              <dd>
                {num(s.usage?.reported_calls)} /{" "}
                <strong
                  className={s.usage?.missing_calls ? "metering-missing" : ""}
                >
                  {num(s.usage?.missing_calls)}
                </strong>
              </dd>
            </div>
          </dl>
          <div className="diagnostic-statuses">
            <strong>核验结果与失败类别</strong>
            <div>
              {s.status_counts ? (
                Object.entries(s.status_counts).map(([status, count]) => (
                  <span
                    key={status}
                    className={status === "completed" ? "completed" : "failed"}
                  >
                    {CALL_STATUSES[status] || status}
                    <b>{num(count)}</b>
                  </span>
                ))
              ) : (
                <span>未提供调用类别统计</span>
              )}
            </div>
          </div>
          <p className="diagnostic-counting-note">
            分类与请求控制按已尝试样例计数。调用失败导致的请求暂缓不等于识别出攻击；未报告
            token 计量的调用不按零消耗计算。
          </p>
        </>
      )}
    </article>
  );
}

export function ModelExperiments({ revision = 0 }: { revision?: number }) {
  const results = useApi<ModelExperiment[]>("/model-experiments", 0, revision);
  const reports = [...(results.data || [])].sort((a, b) =>
    (a.created_at || "").localeCompare(b.created_at || ""),
  );
  const limitations = [
    ...new Set(reports.flatMap((report) => report.limitations)),
  ];
  return (
    <Card
      title="商汤语义开发诊断"
      subtitle="只读展示已保存的真实调用聚合结果；打开此页不会发起云模型请求"
      action={
        <span className="outline-label">
          <FlaskConical size={14} />
          {reports.length ? `${reports.length} 份已保存记录` : "开发诊断"}
        </span>
      }
    >
      <div className="diagnostic-scope">
        <Info size={17} />
        <p>
          <strong>同样例开发回归，不是未见场景测试，也不是大模型训练。</strong>{" "}
          商汤 API 提供语义核验，分类结论与请求级控制分开统计。实验没有生成下游
          AI
          输出，不能据此报告实际输出外泄阻断率；历史实验参数可能与当前部署不同。
        </p>
      </div>
      <ErrorNotice message={results.error} />
      {results.loading ? (
        <Loading />
      ) : reports.length ? (
        <>
          <div className="model-experiments-grid">
            {reports.map((experiment) => (
              <ExperimentReport key={experiment.id} experiment={experiment} />
            ))}
          </div>
          {limitations.length > 0 && (
            <details className="model-details diagnostic-limitations">
              <summary>查看存档报告的适用范围</summary>
              <ul>
                {limitations.map((item, i) => (
                  <li key={i}>{item}</li>
                ))}
              </ul>
            </details>
          )}
        </>
      ) : (
        !results.error && (
          <Empty
            title="暂无已保存的商汤语义诊断"
            text="此区域仅展示后端已保存且可核验的聚合报告，不会启动新的付费实验。"
          />
        )
      )}
    </Card>
  );
}
