import { useRef, useState } from "react";
import {
  ArrowLeft,
  ArrowRight,
  CheckCircle2,
  Download,
  ExternalLink,
  FileUp,
  Info,
  LoaderCircle,
  ShieldCheck,
} from "lucide-react";
import { api } from "./api";
import type { Analysis, SecurityEvent } from "./types";
import {
  ACTION_NAMES,
  Badge,
  Card,
  Empty,
  ErrorNotice,
  EVENT_NAMES,
  Loading,
  num,
  short,
  time,
  useApi,
} from "./ui";

interface PublicDataset {
  id: string;
  name: string;
  status: string;
  source_url: string;
  license: { id: string; url: string; attribution: string };
  synthetic: false;
  origin: string;
  row_count: number;
  column_count: number;
  imported_at: string;
  sha256: string;
  source_integrity?: boolean;
  quality: {
    valid_rows: number;
    invalid_rows: number;
    duplicate_rows: number;
    missing_cells: number;
    unknown_cells: number;
  };
  security_labels_available: boolean;
  used_for_detection_training: boolean;
  llm_access: boolean;
  limitations: string[];
}

function sourceLink(value: string) {
  try {
    const url = new URL(value);
    return url.protocol === "https:" && !url.username && !url.password
      ? url.href
      : undefined;
  } catch {
    return undefined;
  }
}

export function PublicData({ revision }: { revision: number }) {
  const catalog = useApi<PublicDataset[]>("/datasets", 0, revision);
  return (
    <Card
      title="公开业务数据"
      subtitle="公开来源的业务属性与质量汇总，与合成沙盒分别管理"
    >
      <div className="info-note">
        <Info size={18} />
        <p>
          公开业务数据不是安全攻击标签，不用于当前检测训练，也不发送给云模型。此处仅展示来源与聚合质量，不展示客户原始行。
        </p>
      </div>
      <ErrorNotice message={catalog.error} />
      {catalog.loading ? (
        <Loading />
      ) : catalog.data?.length ? (
        <div className="public-datasets">
          {catalog.data.map((dataset) => (
            <article className="public-dataset" key={dataset.id}>
              <header>
                <div>
                  <h3>{dataset.name}</h3>
                  <span>公开数据 · 非合成沙盒资产</span>
                </div>
                <span
                  className={`source-integrity ${dataset.status === "imported" && dataset.source_integrity !== false ? "valid" : "invalid"}`}
                >
                  {dataset.status === "imported" &&
                  dataset.source_integrity !== false
                    ? "来源摘要校验通过"
                    : "来源完整性异常"}
                </span>
              </header>
              {dataset.source_integrity === false && (
                <ErrorNotice message="源文件完整性校验失败，请在服务器核查；以下为已存档的历史汇总，不能作为当前数据完整性证明。" />
              )}
              <div className="source-metrics">
                <div>
                  <span>源记录数</span>
                  <strong>{num(dataset.row_count)}</strong>
                  <small>不是去重客户数</small>
                </div>
                <div>
                  <span>字段数</span>
                  <strong>{num(dataset.column_count)}</strong>
                </div>
                <div>
                  <span>有效 / 无效记录</span>
                  <strong>
                    {num(dataset.quality.valid_rows)} /{" "}
                    {num(dataset.quality.invalid_rows)}
                  </strong>
                </div>
                <div>
                  <span>完整重复行</span>
                  <strong>{num(dataset.quality.duplicate_rows)}</strong>
                  <small>保持源记录，未擅自去重</small>
                </div>
              </div>
              <dl className="source-details">
                <div>
                  <dt>空值单元格 / 显式 unknown</dt>
                  <dd>
                    {num(dataset.quality.missing_cells)} /{" "}
                    {num(dataset.quality.unknown_cells)}
                  </dd>
                </div>
                <div>
                  <dt>导入时间</dt>
                  <dd>{time(dataset.imported_at, true)}</dd>
                </div>
                <div>
                  <dt>数据许可</dt>
                  <dd>
                    <a
                      href={sourceLink(dataset.license.url)}
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      {dataset.license.id}
                      <ExternalLink size={12} />
                    </a>
                  </dd>
                </div>
                <div>
                  <dt>公开来源</dt>
                  <dd>
                    <a
                      href={sourceLink(dataset.source_url)}
                      target="_blank"
                      rel="noopener noreferrer"
                    >
                      查看发布方说明
                      <ExternalLink size={12} />
                    </a>
                  </dd>
                </div>
              </dl>
              <details className="model-details">
                <summary>来源署名、校验摘要与适用范围</summary>
                <p>{dataset.license.attribution}</p>
                <p className="mono source-hash">SHA-256: {dataset.sha256}</p>
                <ul>
                  {dataset.limitations.map((item, i) => (
                    <li key={i}>{item}</li>
                  ))}
                </ul>
              </details>
            </article>
          ))}
        </div>
      ) : (
        !catalog.error && (
          <Empty
            title="尚未导入公开数据"
            text="部署管理员可在服务器导入已核验来源的数据包；此页只读取已存档的聚合目录。"
          />
        )
      )}
    </Card>
  );
}

interface ImportSummary {
  id: string;
  source_name: string;
  status: "completed";
  mode: "observe";
  row_count: number;
  alert_count: number;
  high_risk_count: number;
  executed_actions: number;
  created_at: string;
  actor: string;
  source_sha256: string;
  fingerprint: string;
  model_version: string;
  replayed: boolean;
  limitations: string[];
}
interface ImportDetail extends ImportSummary {
  observations: {
    event: SecurityEvent;
    analysis: Analysis;
    mode: "observe";
    actions_executed: boolean;
    cloud_called: boolean;
  }[];
}

const MAX_IMPORT_BYTES = 1024 * 1024;
const PAGE_SIZE = 25;

export function EventImports({ canImport }: { canImport: boolean }) {
  const [revision, setRevision] = useState(0);
  const batches = useApi<ImportSummary[]>("/imports", 0, revision);
  const [selectedId, setSelectedId] = useState("");
  const [offset, setOffset] = useState(0);
  const activeId = selectedId || batches.data?.[0]?.id || "";
  const detail = useApi<ImportDetail>(
    activeId
      ? `/imports/${encodeURIComponent(activeId)}?limit=${PAGE_SIZE}&offset=${offset}`
      : null,
    0,
    revision,
  );
  const [sourceName, setSourceName] = useState("");
  const [format, setFormat] = useState<"jsonl" | "csv">("jsonl");
  const [content, setContent] = useState("");
  const [fileName, setFileName] = useState("");
  const [fileBytes, setFileBytes] = useState(0);
  const [reading, setReading] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [downloading, setDownloading] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const fileInput = useRef<HTMLInputElement>(null);
  const fileReadSequence = useRef(0);
  const summary =
    detail.data || batches.data?.find((batch) => batch.id === activeId);

  async function readFile(file?: File) {
    const sequence = ++fileReadSequence.current;
    setContent("");
    setError("");
    setNotice("");
    setFileName("");
    setFileBytes(0);
    if (!file) return;
    if (!file.size || file.size > MAX_IMPORT_BYTES) {
      setError("请选择非空的 UTF-8 文件，每批不超过 1 MiB。");
      if (fileInput.current) fileInput.current.value = "";
      return;
    }
    setReading(true);
    try {
      const data = new TextDecoder("utf-8", { fatal: true }).decode(
        await file.arrayBuffer(),
      );
      if (sequence !== fileReadSequence.current) return;
      if (!data.trim()) throw new Error("文件没有可导入内容");
      setContent(data);
      setFileName(file.name);
      setFileBytes(file.size);
      if (/\.csv$/i.test(file.name)) setFormat("csv");
      else setFormat("jsonl");
    } catch (e) {
      if (sequence === fileReadSequence.current)
        setError(
          e instanceof TypeError
            ? "文件编码无效，请保存为 UTF-8 后重试。"
            : e instanceof Error
              ? e.message
              : "文件读取失败",
        );
    } finally {
      if (sequence === fileReadSequence.current) setReading(false);
    }
  }

  async function importEvents() {
    if (!canImport || submitting || reading || !content) return;
    const source = sourceName.trim();
    if (!/^[\w .\-\u4e00-\u9fff]{1,100}$/.test(source)) {
      setError(
        "来源名称限 1–100 位中文、英文字母、数字、空格、下划线、点或短横线。",
      );
      return;
    }
    if (new TextEncoder().encode(content).length > MAX_IMPORT_BYTES) {
      setError("导入内容超过 1 MiB");
      return;
    }
    if (format === "jsonl" && content.trimEnd().split(/\r?\n/).length > 2000) {
      setError("每批最多 2,000 行，请拆分文件后重试。");
      return;
    }
    setSubmitting(true);
    setError("");
    setNotice("");
    try {
      const batch = await api<ImportSummary>("/imports", {
        body: { source_name: source, format, content },
      });
      setSelectedId(batch.id);
      setOffset(0);
      setRevision((n) => n + 1);
      setNotice(
        batch.replayed
          ? "该批内容已导入，已返回原观察结果；没有重复处理。"
          : `已通过整批校验并完成 ${num(batch.row_count)} 条观察分析，没有执行响应动作或调用云模型。`,
      );
      setContent("");
      setFileName("");
      setFileBytes(0);
      if (fileInput.current) fileInput.current.value = "";
    } catch (e) {
      setError(e instanceof Error ? e.message : "导入失败，请检查文件后重试");
    } finally {
      setSubmitting(false);
    }
  }

  async function downloadTemplate() {
    setDownloading(true);
    setError("");
    try {
      const template = await api<{ content: string }>("/import-template");
      const url = URL.createObjectURL(
        new Blob([template.content], {
          type: "application/x-ndjson;charset=utf-8",
        }),
      );
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = "datafence-synthetic-events.jsonl";
      anchor.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (e) {
      setError(e instanceof Error ? e.message : "样例下载失败");
    } finally {
      setDownloading(false);
    }
  }

  return (
    <Card
      title="合成安全日志导入"
      subtitle="JSONL / CSV · 每批最多 1 MiB、2,000 行 · 全批校验后入库"
      action={
        <button
          className="button"
          onClick={() => void downloadTemplate()}
          disabled={downloading}
        >
          {downloading ? (
            <LoaderCircle className="spin" size={15} />
          ) : (
            <Download size={15} />
          )}
          下载 JSONL 样例
        </button>
      }
    >
      <div className="info-note">
        <ShieldCheck size={19} />
        <p>
          <strong>仅观察分析：不执行阻断，不修改额度，不调用云模型。</strong>{" "}
          每行必须明确声明
          synthetic=true，员工与工单需映射到当前沙盒目录；不接受
          ground_truth、attack_type
          等答案字段或真实业务日志。公开业务数据不能直接作为此处的安全事件导入。
        </p>
      </div>
      <form
        className="import-form"
        onSubmit={(e) => {
          e.preventDefault();
          void importEvents();
        }}
      >
        <label className="form-field">
          日志来源名称
          <input
            required
            maxLength={100}
            placeholder="例如：合成日志回归集"
            value={sourceName}
            onChange={(e) => setSourceName(e.target.value)}
            disabled={!canImport || submitting}
          />
        </label>
        <label className="form-field">
          文件格式
          <select
            value={format}
            onChange={(e) => setFormat(e.target.value as "jsonl" | "csv")}
            disabled={!canImport || submitting || reading}
          >
            <option value="jsonl">JSONL（每行一个事件）</option>
            <option value="csv">CSV（含表头）</option>
          </select>
        </label>
        <label className="form-field import-file">
          UTF-8 日志文件
          <input
            ref={fileInput}
            type="file"
            accept=".jsonl,.ndjson,.csv"
            onChange={(e) => void readFile(e.target.files?.[0])}
            disabled={!canImport || submitting || reading}
          />
        </label>
        <button
          className="button primary"
          type="submit"
          disabled={
            !canImport ||
            submitting ||
            reading ||
            !content ||
            !sourceName.trim()
          }
        >
          {submitting || reading ? (
            <LoaderCircle size={16} className="spin" />
          ) : (
            <FileUp size={16} />
          )}
          {reading
            ? "读取文件…"
            : submitting
              ? "正在校验与分析…"
              : "导入并观察分析"}
        </button>
      </form>
      {!canImport && (
        <p className="import-help">
          当前账号为只读角色，可查看已导入批次，不能上传或导入文件。
        </p>
      )}
      {fileName && (
        <p className="import-help">
          已读取 {fileName} · {num(fileBytes / 1024)}{" "}
          KiB。只有提交后才会发送至服务器；字段、映射与时间顺序由服务器统一校验。
        </p>
      )}
      <ErrorNotice message={error || batches.error || detail.error} />
      {notice && (
        <div className="import-success" role="status">
          <CheckCircle2 size={17} />
          {notice}
        </div>
      )}
      {batches.loading ? (
        <Loading />
      ) : batches.data?.length ? (
        <>
          <div className="import-batch-select">
            <label>
              查看导入批次
              <select
                value={activeId}
                onChange={(e) => {
                  setSelectedId(e.target.value);
                  setOffset(0);
                }}
              >
                {batches.data.map((batch) => (
                  <option key={batch.id} value={batch.id}>
                    {batch.source_name} · {time(batch.created_at, true)} ·{" "}
                    {num(batch.row_count)} 条
                  </option>
                ))}
              </select>
            </label>
            <span>最近 {num(batches.data.length)} 批</span>
          </div>
          {summary && (
            <div className="import-summary">
              <div>
                <span>通过校验的事件</span>
                <strong>{num(summary.row_count)}</strong>
              </div>
              <div>
                <span>分析告警事件</span>
                <strong>{num(summary.alert_count)}</strong>
              </div>
              <div>
                <span>高风险事件</span>
                <strong>{num(summary.high_risk_count)}</strong>
              </div>
              <div>
                <span>实际执行动作</span>
                <strong>{num(summary.executed_actions)}</strong>
                <small>观察模式</small>
              </div>
            </div>
          )}
          {detail.loading ? (
            <Loading />
          ) : (
            detail.data && (
              <>
                <div className="table-wrap">
                  <table className="import-observations">
                    <thead>
                      <tr>
                        <th>时间 / 事件</th>
                        <th>员工 / 类型</th>
                        <th>风险</th>
                        <th>分析与建议（未执行）</th>
                      </tr>
                    </thead>
                    <tbody>
                      {detail.data.observations.map(
                        ({
                          event,
                          analysis,
                          actions_executed,
                          cloud_called,
                        }) => (
                          <tr key={event.event_id}>
                            <td>
                              {time(event.timestamp, true)}
                              <small className="mono">
                                {short(event.event_id)}
                              </small>
                            </td>
                            <td>
                              {event.employee_id}
                              <small>
                                {EVENT_NAMES[event.event_type] ||
                                  event.event_type}{" "}
                                · {num(event.record_count)} 条
                              </small>
                            </td>
                            <td>
                              <Badge level={analysis.risk_level} />
                              <small>评分 {analysis.risk_score} / 100</small>
                            </td>
                            <td>
                              <p>
                                {analysis.actions
                                  .map(
                                    (action) => ACTION_NAMES[action] || action,
                                  )
                                  .join("、") || "无建议动作"}
                              </p>
                              <details>
                                <summary>查看分析依据</summary>
                                <p>{analysis.explanation}</p>
                                <p>
                                  访问意图可信度：{analysis.intent.trust} / 100
                                </p>
                                <p>{analysis.intent.evidence.join("；")}</p>
                                <p>
                                  {actions_executed
                                    ? "存在已执行动作"
                                    : "响应动作未执行"}{" "}
                                  ·{" "}
                                  {cloud_called ? "存在云调用" : "未调用云模型"}
                                </p>
                              </details>
                            </td>
                          </tr>
                        ),
                      )}
                    </tbody>
                  </table>
                </div>
                <div className="import-pagination">
                  <span>
                    第 {num(offset + 1)}–
                    {num(Math.min(offset + PAGE_SIZE, detail.data.row_count))}{" "}
                    条 / 共 {num(detail.data.row_count)} 条
                  </span>
                  <button
                    className="button"
                    disabled={offset === 0}
                    onClick={() => setOffset((n) => Math.max(0, n - PAGE_SIZE))}
                  >
                    <ArrowLeft size={14} />
                    上一页
                  </button>
                  <button
                    className="button"
                    disabled={offset + PAGE_SIZE >= detail.data.row_count}
                    onClick={() => setOffset((n) => n + PAGE_SIZE)}
                  >
                    下一页
                    <ArrowRight size={14} />
                  </button>
                </div>
                <details className="model-details">
                  <summary>批次来源与分析边界</summary>
                  <p>
                    导入账号：{detail.data.actor} · 模型：
                    {detail.data.model_version}
                  </p>
                  <p className="mono source-hash">
                    源内容 SHA-256：{detail.data.source_sha256}
                  </p>
                  <ul>
                    {detail.data.limitations.map((limitation, i) => (
                      <li key={i}>{limitation}</li>
                    ))}
                  </ul>
                </details>
              </>
            )
          )}
        </>
      ) : (
        !batches.error && (
          <Empty
            title="暂无导入批次"
            text="下载合成事件样例并按字段约定准备文件；导入结果独立于沙盒演练，不计作已执行的安全响应。"
          />
        )
      )}
    </Card>
  );
}
