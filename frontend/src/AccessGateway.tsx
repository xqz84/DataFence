import { useEffect, useRef, useState } from "react";
import {
  CheckCircle2,
  Database,
  Download,
  FileCheck2,
  Info,
  LoaderCircle,
  RefreshCw,
  ShieldBan,
  ShieldCheck,
} from "lucide-react";
import { api, ApiError, executeAccess } from "./api";
import { QuotaPanel } from "./QuotaPanel";
import type { AccessRequest, AccessResult, AccessTask } from "./types";
import {
  ACTION_NAMES,
  Badge,
  Card,
  Empty,
  ErrorNotice,
  Loading,
  num,
  short,
  time,
  useApi,
} from "./ui";

function requestId() {
  if (typeof crypto.randomUUID === "function") return crypto.randomUUID();
  // Web Crypto random bytes also work on an HTTP LAN origin.
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = [...bytes]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export function AccessGateway({ canAccess }: { canAccess: boolean }) {
  const [revision, setRevision] = useState(0);
  const tasks = useApi<AccessTask[]>("/access/tasks", 0, revision);
  const operations = useApi<AccessResult[]>("/access/operations", 0, revision);
  const [taskId, setTaskId] = useState("");
  const task =
    tasks.data?.find((item) => item.id === taskId) ||
    tasks.data?.find(
      (item) => item.employee_id === "E0038" && item.allow_export,
    ) ||
    tasks.data?.find((item) => item.allow_export) ||
    tasks.data?.[0];
  const [operation, setOperation] =
    useState<AccessRequest["operation"]>("query");
  const [recordCount, setRecordCount] = useState(5);
  const [regions, setRegions] = useState<string[]>([]);
  const lastValidTaskId = useRef<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [pendingRequest, setPendingRequest] = useState<AccessRequest | null>(
    null,
  );
  const [retryAvailable, setRetryAvailable] = useState(false);
  const [result, setResult] = useState<AccessResult | null>(null);
  const [rowPage, setRowPage] = useState(0);
  const [verifying, setVerifying] = useState(false);
  const [verification, setVerification] = useState<{
    valid: boolean;
    checked_operations: number;
  } | null>(null);
  const [verifyError, setVerifyError] = useState("");
  useEffect(() => {
    if (!task) return;
    if (lastValidTaskId.current !== task.id) {
      lastValidTaskId.current = task.id;
      setRegions([...task.regions]);
      return;
    }
    // A refresh may narrow the grant, but must never expand the user's choice.
    setRegions((selected) => {
      const permitted = selected.filter((region) => task.regions.includes(region));
      return permitted.length === selected.length ? selected : permitted;
    });
  }, [task?.id, task?.regions]);

  async function submit(request?: AccessRequest) {
    if (!canAccess || busy || (!request && (!task || !regions.length))) return;
    setError("");
    if (
      !request &&
      (!Number.isInteger(recordCount) || recordCount < 1 || recordCount > 5000)
    ) {
      setError("请求记录数必须是 1–5,000 的整数。");
      return;
    }
    const next = request || {
      request_id: requestId(),
      task_id: task!.id,
      operation,
      record_count: recordCount,
      regions: [...regions],
    };
    setPendingRequest(next);
    setRetryAvailable(false);
    setBusy(true);
    setResult(null);
    setVerification(null);
    try {
      const response = await executeAccess(next);
      setResult(response);
      setRowPage(0);
      setRevision((n) => n + 1);
    } catch (e) {
      setError(e instanceof Error ? e.message : "无法确认请求结果");
      setRetryAvailable(!(e instanceof ApiError) || e.status >= 500);
    } finally {
      setBusy(false);
    }
  }

  function downloadCsv() {
    if (
      !result?.allowed ||
      result.operation !== "export" ||
      typeof result.csv !== "string"
    )
      return;
    const url = URL.createObjectURL(
      new Blob([result.csv], { type: "text/csv;charset=utf-8" }),
    );
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `DataFence-synthetic-${result.request_id}.csv`;
    anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  async function verify() {
    setVerifying(true);
    setVerifyError("");
    try {
      setVerification(await api("/access/verify"));
    } catch (e) {
      setVerifyError(e instanceof Error ? e.message : "访问记录校验失败");
    } finally {
      setVerifying(false);
    }
  }

  const rows = result?.allowed ? result.rows || [] : [];
  return (
    <Card
      title="受控合成数据访问"
      subtitle="真实 HTTP 查询 / CSV 交付 · 先核验工单、规则与额度，再返回合成客户记录"
    >
      <div className="info-note">
        <ShieldCheck size={18} />
        <p>
          <strong>仅授权平台操作员可访问合成资产，未接入银行 IAM。</strong>{" "}
          公开业务数据不进入此网关；本入口不调用云模型。额度按工单生命周期累计，使用独立账本，与沙盒演练分开。
        </p>
      </div>
      <ErrorNotice message={tasks.error || operations.error} />
      {tasks.loading ? (
        <Loading />
      ) : tasks.data?.length ? (
        <>
          <form
            className="gateway-form"
            onSubmit={(e) => {
              e.preventDefault();
              void submit();
            }}
          >
            <label className="form-field gateway-task">
              业务工单
              <select
                value={task?.id || ""}
                onChange={(e) => setTaskId(e.target.value)}
                disabled={busy || !canAccess}
              >
                {tasks.data.map((item) => (
                  <option value={item.id} key={item.id}>
                    {item.id} · {item.employee_id} · {item.purpose} ·{" "}
                    {item.allow_export ? "允许导出" : "不允许导出"}
                  </option>
                ))}
              </select>
            </label>
            <label className="form-field">
              操作
              <select
                value={operation}
                onChange={(e) =>
                  setOperation(e.target.value as AccessRequest["operation"])
                }
                disabled={busy || !canAccess}
              >
                <option value="query">查询并查看 JSON 记录</option>
                <option value="export">请求 CSV 导出</option>
              </select>
            </label>
            <label className="form-field">
              请求记录数
              <input
                type="number"
                required
                min={1}
                max={5000}
                value={recordCount}
                onChange={(e) => setRecordCount(Number(e.target.value))}
                disabled={busy || !canAccess}
              />
            </label>
            <button
              type="submit"
              className="button primary"
              disabled={busy || !canAccess || !regions.length}
            >
              {busy ? (
                <LoaderCircle size={16} className="spin" />
              ) : (
                <Database size={16} />
              )}
              {busy ? "正在核验与交付…" : "提交新操作"}
            </button>
          </form>
          <div className="gateway-regions">
            <span>工单授权区域</span>
            {task?.regions.map((region) => (
              <label key={region}>
                <input
                  type="checkbox"
                  checked={regions.includes(region)}
                  onChange={(e) =>
                    setRegions((old) =>
                      e.target.checked
                        ? [...old, region]
                        : old.filter((item) => item !== region),
                    )
                  }
                  disabled={busy || !canAccess}
                />
                {region}
              </label>
            ))}
          </div>
          {task && (
            <div className="gateway-task-summary">
              <span>
                工单上限 <strong>{num(task.quota.limit)}</strong> 条
              </span>
              <span>
                已确认 <strong>{num(task.quota.confirmed_records)}</strong> ·
                预留 <strong>{num(task.quota.reserved_records)}</strong>
              </span>
              <span>
                剩余 <strong>{num(task.quota.remaining_records)}</strong> 条
              </span>
              <span>
                有效期 {time(task.valid_from, true)} 至{" "}
                {time(task.valid_until, true)}
              </span>
              <span>
                允许时段（上海时间）：{task.allowed_hours.join("、")} 时
              </span>
            </div>
          )}
          <p className="gateway-operation-note">
            {canAccess
              ? "每次“提交新操作”使用新请求编号，获准时会占用新的读取额度。导出包含一次读取，不重复计量导出步骤；额度不是去重客户数，也不是实际返回量。"
              : "当前账号为只读角色，不能提交客户查询或导出。"}
          </p>
        </>
      ) : (
        !tasks.error && (
          <Empty
            title="暂无可用业务工单"
            text="需先在服务器配置合成业务工单与员工映射。"
          />
        )
      )}
      <ErrorNotice message={error} />
      {retryAvailable && pendingRequest && (
        <div className="gateway-retry">
          <Info size={17} />
          <div>
            <strong>尚未确认服务器结果</strong>
            <p>
              原请求可能已经处理。重试会复用编号和原参数，不创建第二次额度消耗。
            </p>
            <span className="mono">{pendingRequest.request_id}</span>
          </div>
          <button
            className="button"
            disabled={busy || !canAccess}
            onClick={() => void submit(pendingRequest)}
          >
            <RefreshCw size={15} />
            重试同一请求
          </button>
        </div>
      )}
      {result && (
        <section
          className={`gateway-result ${result.allowed ? "allowed" : "denied"}`}
        >
          <header>
            {result.allowed ? (
              <CheckCircle2 size={21} />
            ) : (
              <ShieldBan size={21} />
            )}
            <div>
              <h3>
                {result.allowed
                  ? "已获准并交付合成数据"
                  : "请求已拒绝 · 未返回客户行"}
              </h3>
              <p>
                {result.actor} · 工单 {result.task_id} ·{" "}
                {result.operation === "export" ? "CSV 导出" : "JSON 查询"} ·{" "}
                {time(result.created_at, true)}
              </p>
            </div>
            {result.allowed &&
              result.operation === "export" &&
              typeof result.csv === "string" && (
                <button className="button" onClick={downloadCsv}>
                  <Download size={15} />
                  下载本次 CSV
                </button>
              )}
          </header>
          <div className="gateway-result-stats">
            <span>
              请求 <b>{num(result.requested_records)}</b> 条
            </span>
            <span>
              实际交付 <b>{num(result.delivered_records)}</b> 条
            </span>
            <Badge level={result.analysis.risk_level} />
            <span>评分 {num(result.analysis.risk_score)}</span>
            {result.replayed && (
              <span className="gateway-replayed">复用原回执 · 未重复扣额</span>
            )}
          </div>
          <p className="gateway-explanation">{result.analysis.explanation}</p>
          <p className="gateway-rule-note">
            策略动作：
            {result.analysis.actions
              .map((action) => ACTION_NAMES[action] || action)
              .join("、")}
            。客户行是否返回以本次交付状态为准。
          </p>
          <div className="gateway-evidence">
            <span>
              请求编号 <code>{result.request_id}</code>
            </span>
            <span>
              证据摘要 <code>{result.evidence_hash}</code>
            </span>
            <span>策略 {result.policy_version} · 无云调用</span>
          </div>
          <QuotaPanel decision={result.quota} />
          {result.allowed &&
            (rows.length ? (
              <>
                <div className="gateway-rows-heading">
                  <strong>本次实际返回的合成客户记录</strong>
                  <span>{num(rows.length)} 行 JSON · 明确标识 SYN</span>
                </div>
                <div className="table-wrap">
                  <table className="gateway-rows">
                    <thead>
                      <tr>
                        <th>客户标识</th>
                        <th>合成姓名</th>
                        <th>合成联系方式</th>
                        <th>合成身份引用</th>
                        <th>区域 / 员工</th>
                      </tr>
                    </thead>
                    <tbody>
                      {rows
                        .slice(rowPage * 25, (rowPage + 1) * 25)
                        .map((row) => (
                          <tr key={row.id}>
                            <td className="mono">{row.id}</td>
                            <td>{row.name}</td>
                            <td>{row.contact}</td>
                            <td className="mono">{row.identity_ref}</td>
                            <td>
                              {row.region}
                              <small>{row.employee_id}</small>
                            </td>
                          </tr>
                        ))}
                    </tbody>
                  </table>
                </div>
                {rows.length > 25 && (
                  <div className="import-pagination">
                    <span>
                      第 {num(rowPage * 25 + 1)}–
                      {num(Math.min((rowPage + 1) * 25, rows.length))} 条 / 共{" "}
                      {num(rows.length)} 条
                    </span>
                    <button
                      className="button"
                      onClick={() => setRowPage((n) => n - 1)}
                      disabled={rowPage === 0}
                    >
                      上一页
                    </button>
                    <button
                      className="button"
                      onClick={() => setRowPage((n) => n + 1)}
                      disabled={(rowPage + 1) * 25 >= rows.length}
                    >
                      下一页
                    </button>
                  </div>
                )}
              </>
            ) : (
              <Empty
                title="核验通过，当前区域没有可返回记录"
                text="实际返回行数以服务端回执为准，读取额度仍按获准请求数计量。"
              />
            ))}
        </section>
      )}
      <div className="gateway-audit-heading">
        <div>
          <strong>最近访问交付记录</strong>
          <small>仅元信息，历史列表不重复展示客户行</small>
        </div>
        <button
          className="button"
          disabled={verifying}
          onClick={() => void verify()}
        >
          {verifying ? (
            <LoaderCircle size={15} className="spin" />
          ) : (
            <FileCheck2 size={15} />
          )}
          校验访问记录
        </button>
      </div>
      <ErrorNotice message={verifyError} />
      {verification && (
        <p
          className={`gateway-verification ${verification.valid ? "valid" : "invalid"}`}
        >
          {verification.valid
            ? "访问证据链校验通过"
            : "访问证据链校验失败，不可依赖该链作为完整证据"}{" "}
          · 已检查 {num(verification.checked_operations)} 条记录
        </p>
      )}
      {operations.loading ? (
        <Loading />
      ) : operations.data?.length ? (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>时间</th>
                <th>请求 / 工单</th>
                <th>操作员</th>
                <th>操作</th>
                <th>请求 / 交付</th>
                <th>实际交付状态</th>
              </tr>
            </thead>
            <tbody>
              {operations.data.slice(0, 10).map((item) => (
                <tr key={`${item.actor}-${item.request_id}`}>
                  <td>{time(item.created_at, true)}</td>
                  <td>
                    <span className="mono" title={item.request_id}>
                      {short(item.request_id)}
                    </span>
                    <small className="gateway-cell-sub">{item.task_id}</small>
                  </td>
                  <td>{item.actor}</td>
                  <td>
                    {item.operation === "export" ? "CSV 导出" : "JSON 查询"}
                  </td>
                  <td>
                    {num(item.requested_records)} /{" "}
                    {num(item.delivered_records)}
                  </td>
                  <td>{item.allowed ? "已获准交付" : "已拒绝 · 无客户行"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        !operations.error && (
          <Empty
            title="暂无受控访问记录"
            text="成功与拒绝的请求均会留下独立证据记录。"
          />
        )
      )}
    </Card>
  );
}
