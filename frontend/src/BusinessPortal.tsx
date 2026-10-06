import { useEffect, useRef, useState } from "react";
import { ArrowLeftRight, Box, CheckCircle2, ChevronLeft, ChevronRight, Database, Download, FileClock, LoaderCircle, Menu, RefreshCw, Search, Shield, ShieldBan, UserRound, X } from "lucide-react";
import { api, ApiError, executeAccess } from "./api";
import { AccountPanel, ROLE_NAMES } from "./AccountPanel";
import { requestId } from "./requestId";
import type { AccessRequest, AccessResult, AccessTask, AuthUser } from "./types";
import { Empty, ErrorNotice, Loading, num, short, time, useApi } from "./ui";

const BUSINESS_NAV = [
  { id: "business", label: "客户数据", icon: Database },
  { id: "business-history", label: "操作记录", icon: FileClock },
  { id: "business-account", label: "我的账号", icon: UserRound },
];

export function WorkspaceSwitch({ active, user }: { active: "business" | "security"; user: AuthUser }) {
  if (user.role === "business" || user.role === "viewer") return <span className="workspace-name">{active === "business" ? "业务空间" : "安全空间"}</span>;
  return <div className="workspace-switch" aria-label="切换工作空间">
    <a href="#business" className={active === "business" ? "active" : ""}><Box size={17} />业务空间</a>
    <a href="#overview" className={active === "security" ? "active" : ""}><Shield size={17} />安全空间</a>
  </div>;
}

export function BusinessPortal({ user, onLogout }: { user: AuthUser; onLogout: () => Promise<void> }) {
  const [page, setPage] = useState(() => BUSINESS_NAV.some((n) => `#${n.id}` === location.hash) ? location.hash.slice(1) : "business");
  const [navOpen, setNavOpen] = useState(false);
  useEffect(() => { const change = () => { setPage(BUSINESS_NAV.some((n) => `#${n.id}` === location.hash) ? location.hash.slice(1) : "business"); setNavOpen(false); }; window.addEventListener("hashchange", change); return () => window.removeEventListener("hashchange", change); }, []);
  return <div className="app-shell business-shell">
    {navOpen && <button className="sidebar-backdrop" aria-label="关闭导航" onClick={() => setNavOpen(false)} />}
    <aside className={`sidebar ${navOpen ? "open" : ""}`}>
      <a className="brand" href="#business"><span className="product-mark"><Shield size={28} /></span><span><strong>工银数界</strong><small>DataFence</small></span></a>
      <nav aria-label="业务导航">{BUSINESS_NAV.map(({ id, label, icon: Icon }) => <a key={id} href={`#${id}`} className={`nav-item ${page === id ? "active" : ""}`} aria-current={page === id ? "page" : undefined}><Icon size={19} /><span>{label}</span></a>)}</nav>
      <div className="sidebar-bottom"><div className="sandbox-symbol"><Box size={19} /><span>合成沙盒</span></div></div>
    </aside>
    <div className="workspace">
      <header className="topbar"><button className="icon-button mobile-menu" aria-label="打开导航" onClick={() => setNavOpen(true)}><Menu size={21} /></button><WorkspaceSwitch active="business" user={user} /><button className="admin" onClick={() => { location.hash = "business-account"; }}><span><UserRound size={19} /></span><div>{user.username}<small>{ROLE_NAMES[user.role]}</small></div></button></header>
      <main><div className="product-page-title"><h1>{BUSINESS_NAV.find((n) => n.id === page)?.label}</h1><span className="subtle-label">合成客户信息</span></div>
        {page === "business-account" ? <AccountPanel user={user} onLogout={onLogout} /> : <BusinessAccess key={page} historyOnly={page === "business-history"} />}
      </main>
    </div>
  </div>;
}

function HistoryTable({ records, compact = false, loading = false, onSelect }: { records: AccessResult[]; compact?: boolean; loading?: boolean; onSelect?: (record: AccessResult) => void }) {
  if (loading && !records.length) return <Loading />;
  return records.length ? <div className="table-wrap"><table className="business-table"><thead><tr><th>操作时间</th><th>工单编号</th><th>操作类型</th><th>请求 / 返回</th><th>状态</th>{!compact && <th />}</tr></thead><tbody>{records.slice(0, compact ? 5 : 100).map((record) => <tr key={`${record.actor}-${record.request_id}`}><td>{time(record.created_at, true)}</td><td className="mono">{record.task_id}</td><td>{record.operation === "export" ? "导出 CSV" : "查询"}</td><td>{num(record.requested_records)} / {num(record.delivered_records)}</td><td><span className={`delivery-status ${record.allowed ? "allowed" : "denied"}`}><i />{record.allowed ? "已交付" : "已拒绝"}</span></td>{!compact && <td><button className="text-link" onClick={() => onSelect?.(record)}>查看回执<ChevronRight size={13} /></button></td>}</tr>)}</tbody></table></div> : <Empty title="暂无操作记录" text="查询或导出后，操作记录会显示在这里。" />;
}

function Receipt({ result }: { result: AccessResult }) {
  return <div className={`business-receipt ${result.allowed ? "allowed" : "denied"}`} role="status">
    <div>{result.allowed ? <CheckCircle2 size={20} /> : <ShieldBan size={20} />}<strong>{result.allowed ? `操作完成 · 已返回 ${num(result.delivered_records)} 条合成数据` : "请求已拒绝 · 未返回客户数据"}</strong></div>
    {!result.allowed && <p>{result.analysis.explanation}</p>}
    {result.replayed && <small>已恢复原请求回执，未重复扣额。</small>}
  </div>;
}

function BusinessAccess({ historyOnly }: { historyOnly: boolean }) {
  const [revision, setRevision] = useState(0);
  const tasks = useApi<AccessTask[]>(historyOnly ? null : "/access/tasks", 0, revision);
  const history = useApi<AccessResult[]>("/access/operations", 0, revision);
  const historyCache = useRef<AccessResult[]>([]);
  if (history.data) historyCache.current = history.data;
  const historyRecords = history.data || historyCache.current;
  const [taskId, setTaskId] = useState("");
  const task = tasks.data?.find((t) => t.id === taskId) || tasks.data?.[0];
  const previousTask = useRef("");
  const [regions, setRegions] = useState<string[]>([]);
  const [operation, setOperation] = useState<"query" | "export">("query");
  const [count, setCount] = useState(5);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<AccessResult | null>(null);
  const [receipt, setReceipt] = useState<AccessResult | null>(null);
  const [pending, setPending] = useState<AccessRequest | null>(null);
  const [canRetry, setCanRetry] = useState(false);
  const [rowPage, setRowPage] = useState(0);
  const [filter, setFilter] = useState("");
  const [tab, setTab] = useState<"result" | "history">("result");
  useEffect(() => { if (!task) return; if (previousTask.current !== task.id) { previousTask.current = task.id; setRegions([...task.regions]); } else { setRegions((old) => old.filter((r) => task.regions.includes(r))); } }, [task?.id, task?.regions]);
  async function submit(retry?: AccessRequest) {
    if (busy || (!retry && (!task || !regions.length))) return;
    if (!retry && (!Number.isInteger(count) || count < 1 || count > 5000)) { setError("查询数量需为 1–5,000 的整数。"); return; }
    const body = retry || { request_id: requestId(), task_id: task!.id, operation, record_count: count, regions: [...regions] };
    setBusy(true); setError(""); setCanRetry(false); setPending(body); setResult(null); setTab("result");
    try { setResult(await executeAccess(body)); setRowPage(0); setRevision((r) => r + 1); }
    catch (e) { setError(e instanceof Error ? e.message : "未能确认操作结果"); setCanRetry(!(e instanceof ApiError) || e.status >= 500); }
    finally { setBusy(false); }
  }
  function download() {
    if (!result?.allowed || typeof result.csv !== "string") return;
    const url = URL.createObjectURL(new Blob([result.csv], { type: "text/csv;charset=utf-8" }));
    const a = document.createElement("a"); a.href = url; a.download = `DataFence-synthetic-${result.request_id}.csv`; a.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  async function openReceipt(record: AccessResult) {
    setError(""); setReceipt(null);
    try { setReceipt(await api<AccessResult>(`/access/operations/${encodeURIComponent(record.request_id)}`)); }
    catch (e) { setError(e instanceof Error ? e.message : "回执读取失败"); }
  }
  const rows = result?.allowed ? result.rows || [] : [];
  const records = historyRecords.filter((r) => `${r.task_id} ${r.request_id} ${r.actor}`.toLowerCase().includes(filter.toLowerCase()));
  return <><ErrorNotice message={error || tasks.error || history.error} />{historyOnly ? <section className="business-results product-panel"><div className="panel-toolbar"><label className="queue-search"><Search size={16} /><input aria-label="搜索操作记录" placeholder="搜索工单或请求编号" value={filter} onChange={(e) => setFilter(e.target.value)} /></label><button className="button" onClick={() => setRevision((r) => r + 1)}><RefreshCw size={15} />刷新</button></div>{history.loading ? <Loading /> : <HistoryTable records={records} onSelect={(r) => void openReceipt(r)} />}</section> : <div className="business-layout">
      <section className="product-panel business-form-panel"><h2>工单与范围</h2>{tasks.loading ? <Loading /> : task ? <form onSubmit={(e) => { e.preventDefault(); void submit(); }}>
        <label className="form-field">选择工单<select value={task.id} onChange={(e) => setTaskId(e.target.value)} disabled={busy}>{tasks.data?.map((t) => <option key={t.id} value={t.id}>{t.purpose} · {t.id}</option>)}</select></label>
        <label className="form-field">申请员工<input readOnly value={task.employee_id} /></label>
        <fieldset className="region-field"><legend>查询地区</legend><details><summary>{regions.length === task.regions.length ? `全部授权区域（${regions.length}）` : `已选 ${regions.length} 个区域`}</summary><div className="region-options">{task.regions.map((r) => <label key={r}><input type="checkbox" checked={regions.includes(r)} disabled={busy} onChange={(e) => setRegions((old) => e.target.checked ? [...old, r] : old.filter((v) => v !== r))} />{r}</label>)}</div></details></fieldset>
        <label className="form-field">查询数量<div className="number-unit"><input type="number" min={1} max={5000} required value={count} disabled={busy} onChange={(e) => setCount(Number(e.target.value))} /><span>条</span></div><small>单次最多 5,000 条</small></label>
        <fieldset className="operation-field"><legend>操作类型</legend><div className="segmented"><button type="button" className={operation === "query" ? "active" : ""} onClick={() => setOperation("query")} disabled={busy}>查询</button><button type="button" className={operation === "export" ? "active" : ""} onClick={() => setOperation("export")} disabled={busy}>导出 CSV</button></div></fieldset>
        <button className="button primary full-width business-submit" disabled={busy || !regions.length}>{busy ? <LoaderCircle className="spin" size={17} /> : operation === "query" ? <Search size={17} /> : <Download size={17} />}{busy ? "正在处理" : operation === "query" ? "查询数据" : "请求导出"}</button>
        <div className="task-quota"><span>工单剩余额度</span><div><strong>{num(task.quota.remaining_records)}</strong><span>条</span></div><small>上限 {num(task.quota.limit)} · 已使用 {num(task.quota.used_records)}</small></div>
        <details className="task-facts"><summary>查看工单授权</summary><p>{task.allow_export ? "允许导出" : "仅允许查询"}</p><p>{time(task.valid_from, true)} 至 {time(task.valid_until, true)}</p><p>授权时段 {task.allowed_hours.join("、")} 时</p></details>
      </form> : <Empty title="暂无授权工单" text="请联系管理员核对员工绑定。" />}</section>
      <section className="product-panel business-results"><div className="result-tabs"><button className={tab === "result" ? "active" : ""} onClick={() => setTab("result")}>查询结果{result?.allowed ? `（${num(rows.length)}）` : ""}</button><button className={tab === "history" ? "active" : ""} onClick={() => setTab("history")}>操作记录</button>{result?.allowed && result.csv && <button className="button download-result" onClick={download}><Download size={15} />下载 CSV</button>}</div>
        {tab === "history" ? <HistoryTable records={historyRecords} loading={history.loading} onSelect={(r) => void openReceipt(r)} /> : <>
          {busy ? <Loading /> : result ? <><Receipt result={result} />{result.allowed && (rows.length ? <><div className="table-wrap"><table className="business-table customer-table"><thead><tr><th>客户编号</th><th>姓名</th><th>地区</th><th>联系方式</th><th>身份引用</th></tr></thead><tbody>{rows.slice(rowPage * 10, (rowPage + 1) * 10).map((r) => <tr key={r.id}><td className="mono">{r.id}</td><td>{r.name}</td><td>{r.region}</td><td>{r.contact}</td><td className="mono">{r.identity_ref}</td></tr>)}</tbody></table></div><div className="table-pagination"><span>共 {num(rows.length)} 条</span><button className="button square" aria-label="上一页客户" disabled={rowPage === 0} onClick={() => setRowPage((p) => p - 1)}><ChevronLeft size={16} /></button><span className="page-number">{rowPage + 1}</span><button className="button square" aria-label="下一页客户" disabled={(rowPage + 1) * 10 >= rows.length} onClick={() => setRowPage((p) => p + 1)}><ChevronRight size={16} /></button></div></> : <Empty title="没有符合范围的客户" text="请核对所选区域。" />)}</> : <Empty title="等待查询" text="选择工单与范围，查看获准返回的客户数据。" />}
          {canRetry && pending && <div className="request-retry"><span>结果尚未确认，请恢复原请求。</span><button className="button" disabled={busy} onClick={() => void submit(pending)}><ArrowLeftRight size={15} />重试同一请求</button></div>}
          <div className="recent-history"><div className="minor-heading"><h3>最近操作记录</h3><a href="#business-history">查看更多</a></div><HistoryTable records={historyRecords} loading={history.loading} compact /></div>
        </>}
      </section>
    </div>}
    {receipt && <div className="receipt-backdrop" onClick={() => setReceipt(null)}><section className="receipt-dialog product-panel" role="dialog" aria-modal="true" aria-label="操作回执" onClick={(e) => e.stopPropagation()}><div className="panel-toolbar"><h2>操作回执</h2><button className="icon-button" aria-label="关闭回执" onClick={() => setReceipt(null)}><X size={19} /></button></div><Receipt result={receipt} /><dl className="receipt-facts"><dt>工单</dt><dd>{receipt.task_id}</dd><dt>请求编号</dt><dd>{receipt.request_id}</dd><dt>实际交付</dt><dd>{num(receipt.delivered_records)} 条</dd><dt>时间</dt><dd>{time(receipt.created_at, true)}</dd><dt>证据摘要</dt><dd title={receipt.evidence_hash}>{short(receipt.evidence_hash)}</dd></dl></section></div>}
  </>;
}
