import {
  Bot,
  BrainCircuit,
  CircleCheck,
  CircleDashed,
  Timer,
} from "lucide-react";
import type { Health } from "./types";
import { analysisStatus, providerName, reasonLabel } from "./ai";
import { Card, ProgressBar, num, pct, short, time } from "./ui";

export function LanguageModelStatus({ health }: { health: Health | null }) {
  const llm = health?.llm;
  const last = llm?.last_call;
  const budget = llm?.budget;
  const remaining = budget
    ? Math.max(
        0,
        budget.token_limit - budget.charged_tokens - budget.reserved_tokens,
      )
    : null;
  return (
    <Card
      title="语言模型服务与调用计量"
      subtitle="配置状态与实际调用结果分别展示"
    >
      <div className="model-service-grid">
        <div>
          <span className="model-status-icon">
            <Bot size={21} />
          </span>
          <small>提供商与配置</small>
          <strong>{llm ? providerName(llm.provider) : "等待服务信息"}</strong>
          <span>{llm?.enabled ? "已配置 · 不代表最近调用成功" : "未配置"}</span>
        </div>
        <div>
          <span className="model-status-icon">
            <BrainCircuit size={21} />
          </span>
          <small>调用模型</small>
          <strong className="mono">{llm?.model || "—"}</strong>
          <span>
            {llm?.provider === "sensenova"
              ? "商汤云 API · 第三方预训练模型"
              : llm?.provider === "ollama"
                ? "通过本地 Ollama 服务运行"
                : "以服务端实际配置为准"}
          </span>
        </div>
        <div>
          <span
            className={`model-status-icon ${last?.status === "completed" ? "success" : last?.status === "unavailable" || last?.status === "invalid_response" ? "failure" : ""}`}
          >
            {last?.status === "completed" ? (
              <CircleCheck size={21} />
            ) : (
              <CircleDashed size={21} />
            )}
          </span>
          <small>最近一次调用结果</small>
          <strong>
            {last
              ? analysisStatus({
                  status: last.status,
                  provider: llm?.provider,
                  reason_code: last.reason_code,
                })
              : "尚无调用结果"}
          </strong>
          <span>
            {last
              ? `${time(last.at, true)} · ${num(last.elapsed_ms)} ms`
              : "未取得结果前不认定服务可用"}
          </span>
          {last?.reason_code && (
            <span className="model-reason" title={last.reason_code}>
              {reasonLabel(last.reason_code)}
            </span>
          )}
        </div>
      </div>
      {budget ? (
        <div className="model-budget">
          <div className="model-budget-heading">
            <strong>
              <Timer size={15} />
              本地调用预算
            </strong>
            <span>计量日期 {budget.date}（UTC）</span>
          </div>
          <div className="budget-stat-grid">
            <div>
              <span>当前可用 tokens</span>
              <strong>{num(remaining)}</strong>
              <small>上限 − 已计量 − 已预留</small>
            </div>
            <div>
              <span>已计量 tokens</span>
              <strong>{num(budget.charged_tokens)}</strong>
              <small>当前 UTC 计量日</small>
            </div>
            <div>
              <span>已预留 tokens</span>
              <strong>{num(budget.reserved_tokens)}</strong>
              <small>在途或结果未知调用的保守额度</small>
            </div>
            <div>
              <span>已申请调用 / 日上限</span>
              <strong>
                {num(budget.requests)}
                <small> / {num(budget.request_limit)}</small>
              </strong>
              <small>tokens 上限 {num(budget.token_limit)}</small>
            </div>
          </div>
          <ProgressBar
            value={
              budget.token_limit
                ? ((budget.charged_tokens + budget.reserved_tokens) /
                    budget.token_limit) *
                  100
                : 0
            }
          />
          <p>
            这是 DataFence
            在本地持久化的调用预算，不是商汤账户余额。请求失败或超时也可能保留额度，避免重复消耗未知预算。
          </p>
        </div>
      ) : (
        <div className="model-no-meter">
          当前服务未提供 token 预算统计；不推算供应商账户余额。
        </div>
      )}
      {llm?.provider === "sensenova" && (
        <p className="model-origin-note">
          商汤预训练大模型通过云 API 提供涉敏 AI
          请求的执行前语义核验，以及普通事件的事后解释；最终风险与控制由本地策略决定。本项目自行训练的是下方本地行为模型，两者的训练来源、能力和评测结果分别记录。
        </p>
      )}
    </Card>
  );
}

const objectInfo = (value: unknown): Record<string, unknown> | null =>
  value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
const numericInfo = (
  record: Record<string, unknown> | null,
  key: string,
): number | null =>
  typeof record?.[key] === "number" ? (record[key] as number) : null;

export function TrainingInfo({ model }: { model?: Record<string, unknown> }) {
  const holdout =
    model?.holdout_metrics &&
    typeof model.holdout_metrics === "object" &&
    !Array.isArray(model.holdout_metrics)
      ? (model.holdout_metrics as Record<string, unknown>)
      : null;
  const metric = (key: string) =>
    typeof holdout?.[key] === "number" ? (holdout[key] as number) : null;
  const baseline = objectInfo(model?.baseline_holdout_metrics);
  const splits = objectInfo(model?.training_splits);
  const probes = Array.isArray(model?.per_probe)
    ? model.per_probe
        .map(objectInfo)
        .filter((probe): probe is Record<string, unknown> => probe !== null)
    : [];
  const inference = objectInfo(model?.inference_ms);
  const splitNames: Record<string, string> = {
    train: "拟合 · 正常样本",
    calibration: "独立校准 · 正常样本",
    holdout_normal: "留出 · 正常样本",
    holdout_probes: "留出 · 偏离探针",
  };
  const probeNames: Record<string, string> = {
    bulk_new_device_night: "新设备 / 夜间批量访问",
    api_burst: "API 高频访问",
    unusual_external_flow: "异常外部数据流",
  };
  const featureList = Array.isArray(model?.features)
    ? model.features.filter((f): f is string => typeof f === "string")
    : [];
  const text = (key: string) =>
    typeof model?.[key] === "string" || typeof model?.[key] === "number"
      ? String(model[key])
      : "未提供";
  return (
    <Card
      title="本地行为模型训练信息"
      subtitle="独立于云语言模型 API 的异常检测能力"
    >
      {typeof model?.load_warning === "string" && (
        <div className="error-notice" role="status">
          {model.load_warning}
        </div>
      )}
      <div className="training-model-state">
        <span
          className={`status ${model?.quality_gate_passed === true ? "completed" : ""}`}
        >
          <i />
          {model?.quality_gate_passed === true
            ? "已加载通过质量门禁的模型"
            : "当前模型未提供晋升门禁记录"}
        </span>
        <span>
          {model?.model_source === "validated_json_artifact"
            ? "已校验 JSON 模型产物"
            : model?.model_source === "legacy_in_memory_fit"
              ? "旧版内存训练基线"
              : "以服务端模型信息为准"}
        </span>
      </div>
      <div className="training-summary">
        <div>
          <span>模型算法</span>
          <strong>{text("algorithm")}</strong>
        </div>
        <div>
          <span>版本</span>
          <strong className="mono">{text("version")}</strong>
        </div>
        <div>
          <span>训练样本数</span>
          <strong>
            {typeof model?.training_samples === "number"
              ? num(model.training_samples)
              : "—"}
          </strong>
        </div>
        <div>
          <span>随机种子</span>
          <strong>{text("training_seed")}</strong>
        </div>
      </div>
      {typeof model?.calibration_samples === "number" && (
        <div className="training-calibration">
          <span>
            独立正常校准样本 <strong>{num(model.calibration_samples)}</strong>
          </span>
          <span>校准阈值与模型拟合分区分开</span>
        </div>
      )}
      {holdout && (
        <div className="training-holdout">
          <strong>独立留出特征测试</strong>
          <p>
            正常样本来自同一生成器家族的未见样本；偏移样本是人工构造的特征分布变化，不是银行真实攻击。
          </p>
          <div className="training-holdout-grid">
            <div>
              <span>未见正常误报率</span>
              <strong>{pct(metric("normal_fpr"))}</strong>
            </div>
            <div>
              <span>人工分布偏移召回率</span>
              <strong>{pct(metric("recall"))}</strong>
            </div>
            <div>
              <span>偏移测试 F1</span>
              <strong>{pct(metric("f1"))}</strong>
            </div>
            <div>
              <span>正常误报率 Wilson 上界</span>
              <strong>{pct(metric("normal_fpr_wilson_upper"))}</strong>
            </div>
          </div>
          <small>
            这些是行为异常模型的特征测试指标，不等于整个系统在真实银行业务中的检测准确率。
          </small>
        </div>
      )}
      {baseline && holdout && (
        <div className="training-comparison">
          <h3>同一留出特征集 · 与旧版基线对照</h3>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>配置</th>
                  <th>正常误报率</th>
                  <th>偏离探针召回率</th>
                  <th>F1</th>
                </tr>
              </thead>
              <tbody>
                <tr>
                  <td>旧版基线</td>
                  <td>{pct(numericInfo(baseline, "normal_fpr"))}</td>
                  <td>{pct(numericInfo(baseline, "recall"))}</td>
                  <td>{pct(numericInfo(baseline, "f1"))}</td>
                </tr>
                <tr>
                  <td>当前已加载模型</td>
                  <td>{pct(metric("normal_fpr"))}</td>
                  <td>{pct(metric("recall"))}</td>
                  <td>{pct(metric("f1"))}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      )}
      {probes.length > 0 && (
        <div className="training-comparison">
          <h3>各类偏离探针 · 保留可见的薄弱项</h3>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>人工偏离特征</th>
                  <th>样本量</th>
                  <th>旧版召回率</th>
                  <th>当前召回率</th>
                </tr>
              </thead>
              <tbody>
                {probes.map((probe, i) => (
                  <tr key={typeof probe.name === "string" ? probe.name : i}>
                    <td>
                      {typeof probe.name === "string"
                        ? probeNames[probe.name] || probe.name
                        : "未提供"}
                    </td>
                    <td>{num(numericInfo(probe, "rows"))}</td>
                    <td>{pct(numericInfo(probe, "legacy_recall"))}</td>
                    <td>{pct(numericInfo(probe, "candidate_recall"))}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
      {splits && Object.keys(splits).length > 0 && (
        <div className="training-comparison">
          <h3>固定数据分区</h3>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>分区用途</th>
                  <th>样本量</th>
                  <th>特征数</th>
                  <th>随机种子</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(splits).map(([key, value]) => {
                  const split = objectInfo(value);
                  return (
                    <tr key={key}>
                      <td>{splitNames[key] || key}</td>
                      <td>{num(numericInfo(split, "rows"))}</td>
                      <td>{num(numericInfo(split, "features"))}</td>
                      <td className="mono">
                        {num(numericInfo(split, "seed"))}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
      {inference && (
        <p className="training-source">
          本机单条推理 P50 / P95：{num(numericInfo(inference, "p50"))} /{" "}
          {num(numericInfo(inference, "p95"))}{" "}
          ms。该统计不包含云模型或生产网络延迟。
        </p>
      )}
      <details className="model-details training-feature-details">
        <summary>
          输入特征与训练来源
          {featureList.length > 0 ? ` · ${featureList.length} 项特征` : ""}
        </summary>
        {featureList.length > 0 && (
          <div className="training-features">
            <span>输入特征 · {featureList.length} 项</span>
            <div className="rule-chips">
              {featureList.map((feature) => (
                <span key={feature} className="mono">
                  {feature}
                </span>
              ))}
            </div>
          </div>
        )}
        <p className="training-source">训练数据：{text("training_data")}</p>
      </details>
      {typeof model?.artifact_sha256 === "string" && (
        <p className="training-artifact" title={model.artifact_sha256}>
          已加载产物 SHA-256：
          <span className="mono">{short(model.artifact_sha256)}</span>
        </p>
      )}
      <details className="model-details">
        <summary>查看服务端训练元数据</summary>
        <pre className="json-view">{JSON.stringify(model || {}, null, 2)}</pre>
      </details>
    </Card>
  );
}
