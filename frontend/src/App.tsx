import { useEffect, useState, type ComponentType } from "react";
import {
  Activity,
  Bell,
  Bot,
  Boxes,
  ChevronDown,
  ChevronRight,
  CircleHelp,
  ClipboardCheck,
  FileSearch,
  FlaskConical,
  Gauge,
  GitBranch,
  LayoutDashboard,
  Menu,
  Search,
  Settings,
  Shield,
  ShieldAlert,
  SlidersHorizontal,
  Users,
  X,
} from "lucide-react";
import type {
  Employee,
  EventRecord,
  Health,
  Overview,
  Run,
  Scenario,
  AuthUser,
} from "./types";
import { ROLE_NAMES, canOperate } from "./AccountPanel";
import { useApi, time, short, Card, Empty, Loading } from "./ui";
import { Lab } from "./pages/DashboardLab";
import { Monitor } from "./pages/MonitorDetail";
import { Behavior, IntentPage } from "./pages/BehaviorIntent";
import { Evaluation, SupportPage } from "./pages/EvaluationSupport";
import { AgentWorkbench } from "./AgentWorkbench";
import { BusinessPortal, WorkspaceSwitch } from "./BusinessPortal";
import { ObservationQueue } from "./ObservationQueue";

export const NAV = [
  { id: "overview", label: "首页 · 安全态势", icon: LayoutDashboard },
  { id: "monitor", label: "实时监控", icon: Activity },
  { id: "assets", label: "数据资产", icon: Boxes },
  { id: "behavior", label: "用户与行为", icon: Users },
  { id: "intent", label: "访问意图", icon: Gauge },
  { id: "flow", label: "数据流追踪", icon: GitBranch },
  { id: "events", label: "风险事件", icon: ShieldAlert },
  { id: "agents", label: "AI安全智能体", icon: Bot },
  { id: "lab", label: "攻击模拟实验室", icon: FlaskConical },
  { id: "policies", label: "策略与响应", icon: SlidersHorizontal },
  { id: "audit", label: "审计与取证", icon: FileSearch },
  { id: "evaluation", label: "评测与报告", icon: ClipboardCheck },
  { id: "settings", label: "系统管理", icon: Settings },
];
export interface PageProps {
  user: AuthUser;
  canOperate: boolean;
  onLogout: () => Promise<void>;
  navigate: (page: string) => void;
  employees: Employee[];
  scenarios: Scenario[];
  health: Health | null;
  overview: Overview | null;
  runId: string;
  runs: Run[];
  setRunId: (id: string) => void;
  employeeId: string;
  setEmployeeId: (id: string) => void;
  selected: EventRecord | null;
  selectedEventId: string;
  selectEvent: (r: EventRecord, destination?: string) => void;
  refresh: () => void;
  revision: number;
}
const currentPage = () =>
  NAV.some((n) => n.id === window.location.hash.slice(1))
    ? window.location.hash.slice(1)
    : "overview";
const OverviewQueue = (p: PageProps) => <ObservationQueue {...p} home />;
export default function App({
  user,
  onLogout,
}: {
  user: AuthUser;
  onLogout: () => Promise<void>;
}) {
  const [hash, setHash] = useState(() => window.location.hash);
  useEffect(() => {
    const change = () => setHash(window.location.hash);
    window.addEventListener("hashchange", change);
    return () => window.removeEventListener("hashchange", change);
  }, []);
  const business = user.role === "business" || (canOperate(user) && hash.startsWith("#business"));
  return business ? <BusinessPortal user={user} onLogout={onLogout} /> : <SecurityApp user={user} onLogout={onLogout} />;
}

function SecurityApp({ user, onLogout }: { user: AuthUser; onLogout: () => Promise<void> }) {
  const [page, setPage] = useState(currentPage);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [clock, setClock] = useState(new Date());
  const [runId, updateRunId] = useState(
    () => new URL(window.location.href).searchParams.get("run") || "",
  );
  const [employeeId, setEmployeeId] = useState("E0038");
  const [selected, setSelected] = useState<EventRecord | null>(null);
  const [selectedEventId, setSelectedEventId] = useState(
    () => new URL(window.location.href).searchParams.get("event") || "",
  );
  function rememberSelection(id: string, eventId = "") {
    const url = new URL(window.location.href);
    url.searchParams.delete("observation");
    if (id) url.searchParams.set("run", id);
    else url.searchParams.delete("run");
    if (eventId) url.searchParams.set("event", eventId);
    else url.searchParams.delete("event");
    window.history.replaceState(null, "", url.toString());
  }
  const setRunId = (id: string) => {
    updateRunId(id);
    const retained = selected?.run_id === id ? selected : null;
    setSelected(retained);
    setSelectedEventId(retained?.event.event_id || "");
    rememberSelection(id, retained?.event.event_id);
  };
  const [revision, setRevision] = useState(0);
  const restoredEvent = useApi<EventRecord>(
    selectedEventId ? `/events/${encodeURIComponent(selectedEventId)}` : null,
    0,
    revision,
  );
  const [search, setSearch] = useState("");
  const [alertsOpen, setAlertsOpen] = useState(false);
  const health = useApi<Health>("/health", 10000, revision);
  const employees = useApi<Employee[]>("/employees", 0, revision);
  const scenarios = useApi<Scenario[]>("/scenarios", 0, revision);
  const overview = useApi<Overview>("/overview", 3000, revision);
  const runs = useApi<Run[]>("/runs", 1500, revision);
  useEffect(() => {
    const fn = () => {
      setPage(currentPage());
      setSidebarOpen(false);
    };
    window.addEventListener("hashchange", fn);
    return () => window.removeEventListener("hashchange", fn);
  }, []);
  useEffect(() => {
    const id = setInterval(() => setClock(new Date()), 1000);
    return () => clearInterval(id);
  }, []);
  useEffect(() => {
    if (!runId && !selectedEventId && !new URL(location.href).searchParams.has("observation") && runs.data?.length)
      setRunId(runs.data[0].id);
  }, [runs.data, runId, selectedEventId]);
  useEffect(() => {
    const record = restoredEvent.data;
    if (
      record &&
      record.event.event_id === selectedEventId &&
      (!runId || record.run_id === runId)
    ) {
      setSelected(record);
      updateRunId(record.run_id);
      setEmployeeId(record.event.employee_id);
    }
  }, [restoredEvent.data, selectedEventId, runId]);
  const navigate = (id: string) => {
    window.location.hash = id;
    setPage(id);
    setSearch("");
    setAlertsOpen(false);
    setSidebarOpen(false);
    window.scrollTo({ top: 0, behavior: "instant" });
  };
  const selectEvent = (r: EventRecord, destination = "events") => {
    setSelected(r);
    updateRunId(r.run_id);
    setSelectedEventId(r.event.event_id);
    rememberSelection(r.run_id, r.event.event_id);
    setEmployeeId(r.event.employee_id);
    if (destination) navigate(destination);
  };
  const props: PageProps = {
    user,
    canOperate: canOperate(user),
    onLogout,
    navigate,
    employees: employees.data || [],
    scenarios: scenarios.data || [],
    health: health.data,
    overview: overview.data,
    runId,
    runs: runs.data || [],
    setRunId,
    employeeId,
    setEmployeeId,
    selected,
    selectedEventId,
    selectEvent,
    refresh: () => setRevision((r) => r + 1),
    revision,
  };
  const pageMap: Record<string, ComponentType<PageProps>> = {
    overview: OverviewQueue,
    lab: Lab,
    monitor: Monitor,
    events: ObservationQueue,
    behavior: Behavior,
    intent: IntentPage,
    evaluation: Evaluation,
    agents: AgentWorkbench,
  };
  const Page = pageMap[page];
  const matchedEmployees = search.trim()
    ? (employees.data || [])
        .filter((e) =>
          `${e.id} ${e.name} ${e.department}`
            .toLowerCase()
            .includes(search.toLowerCase()),
        )
        .slice(0, 5)
    : [];
  const matchedEvents = search.trim()
    ? (overview.data?.recent_events || [])
        .filter((e) =>
          `${e.event.event_id} ${e.event.employee_id}`
            .toLowerCase()
            .includes(search.toLowerCase()),
        )
        .slice(0, 4)
    : [];
  const connected = health.data?.status === "ok" && !health.error;
  const mismatchedSelection = !!(
    restoredEvent.data &&
    runId &&
    restoredEvent.data.event.event_id === selectedEventId &&
    restoredEvent.data.run_id !== runId
  );
  const selectionUnresolved =
    !!selectedEventId &&
    (!selected ||
      selected.event.event_id !== selectedEventId ||
      selected.run_id !== runId ||
      mismatchedSelection);
  const gateSelection =
    selectionUnresolved &&
    ["agents", "events", "intent", "flow", "monitor"].includes(page);
  const selectionError = mismatchedSelection
    ? "链接中的演练与事件不属于同一条证据链，请清除选择后重新打开事件。"
    : restoredEvent.error;
  return (
    <div className="app-shell security-shell">
      {sidebarOpen && (
        <button
          aria-label="关闭导航"
          className="sidebar-backdrop"
          onClick={() => setSidebarOpen(false)}
        />
      )}
      <aside className={`sidebar ${sidebarOpen ? "open" : ""}`}>
        <button className="brand" onClick={() => navigate("overview")}>
          <span className="brand-mark">
            <Shield size={23} strokeWidth={1.8} />
            <span />
          </span>
          <span>
            <strong>工银数界</strong>
            <small>DataFence</small>
          </span>
          <span className="brand-poc">PoC</span>
        </button>
        <nav aria-label="主导航">
          {NAV.map(({ id, label, icon: Icon }, i) => (
            <div key={id}>
              {i === 8 && <div className="nav-divider" />}
              <button
                className={`nav-item ${page === id ? "active" : ""}`}
                onClick={() => navigate(id)}
                aria-current={page === id ? "page" : undefined}
              >
                <Icon size={18} strokeWidth={1.7} />
                <span>{label}</span>
                {id === "monitor" && !!overview.data?.active_runs && (
                  <span className="nav-live" />
                )}
              </button>
            </div>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="sandbox-symbol">
            <Shield size={17} />
            <span>隔离沙盒 · 合成数据</span>
            <i />
          </div>
        </div>
      </aside>
      <div className="workspace">
        <header className="topbar">
          <button
            className="icon-button mobile-menu"
            aria-label="打开导航"
            onClick={() => setSidebarOpen(true)}
          >
            <Menu size={21} />
          </button>
          <WorkspaceSwitch active="security" user={user} />
          <div className="topbar-right">
            <div className="global-search">
              <Search size={15} />
              <input
                aria-label="搜索员工或最近事件"
                placeholder="搜索员工 / 最近事件"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Escape") setSearch("");
                }}
              />
              {search && (
                <button
                  className="icon-button"
                  aria-label="清空搜索"
                  onClick={() => setSearch("")}
                >
                  <X size={13} />
                </button>
              )}
              {search.trim() && (
                <div className="search-results">
                  <small>员工与最近事件</small>
                  {matchedEmployees.map((e) => (
                    <button
                      key={e.id}
                      onClick={() => {
                        setEmployeeId(e.id);
                        navigate("behavior");
                      }}
                    >
                      <Users size={15} />
                      <span>
                        {e.name}
                        <small>
                          {e.id} · {e.department}
                        </small>
                      </span>
                      <ChevronRight size={13} />
                    </button>
                  ))}
                  {matchedEvents.map((e) => (
                    <button
                      key={e.event.event_id}
                      onClick={() => selectEvent(e)}
                    >
                      <ShieldAlert size={15} />
                      <span>
                        {short(e.event.event_id)}
                        <small>
                          {e.event.employee_id} · 风险 {e.analysis.risk_score}
                        </small>
                      </span>
                    </button>
                  ))}
                  {!matchedEmployees.length && !matchedEvents.length && (
                    <p>未找到匹配项</p>
                  )}
                </div>
              )}
            </div>
            <span className={`connection ${connected ? "" : "offline"}`}>
              <i />
              {connected ? "系统运行正常" : "服务连接中"}
            </span>
            <span className="topbar-time mono">
              {clock.toLocaleTimeString("zh-CN", { hour12: false })}
            </span>
            <div className="notification-container">
              <button
                className="icon-button bell-button"
                aria-label="查看最近风险提醒"
                onClick={() => setAlertsOpen(!alertsOpen)}
              >
                <Bell size={18} />
                {!!overview.data?.high_risk_events && <i />}
              </button>
              {alertsOpen && (
                <div className="notification-panel">
                  <strong>最近风险提醒</strong>
                  {overview.data?.recent_events
                    .filter((r) => r.analysis.risk_score >= 60)
                    .slice(0, 4)
                    .map((r) => (
                      <button
                        key={r.event.event_id}
                        onClick={() => selectEvent(r)}
                      >
                        <span>
                          {r.event.employee_id} · 风险 {r.analysis.risk_score}
                        </span>
                        <small>{time(r.detected_at)}</small>
                      </button>
                    ))}
                  {!overview.data?.recent_events.some(
                    (r) => r.analysis.risk_score >= 60,
                  ) && <p>最近事件中暂无高风险提醒</p>}
                </div>
              )}
            </div>
            <button
              className="admin"
              onClick={() => navigate("settings")}
              aria-label={`当前账号 ${user.username}，打开系统管理`}
            >
              <span>{user.username.slice(0, 2).toUpperCase()}</span>
              <div>
                {user.username}
                <small>{ROLE_NAMES[user.role]}</small>
              </div>
              <ChevronDown size={13} />
            </button>
          </div>
        </header>
        <main>
          {(health.error || employees.error || scenarios.error) && (
            <div className="connection-warning">
              <CircleHelp size={17} />
              <span>{health.error || employees.error || scenarios.error}</span>
              <button onClick={() => setRevision((v) => v + 1)}>
                重新连接
              </button>
            </div>
          )}
          {gateSelection ? (
            <Card
              title={selectionError ? "无法恢复指定事件" : "正在恢复指定事件"}
              subtitle="当前页面只展示链接指定的证据，恢复完成后才能继续调查或研判。"
            >
              {selectionError ? (
                <Empty
                  title="指定事件暂不可用"
                  text={selectionError}
                  action={
                    <>
                      <button
                        className="button"
                        onClick={() => setRevision((value) => value + 1)}
                      >
                        重新读取
                      </button>
                      <button
                        className="button primary"
                        onClick={() => {
                          setSelected(null);
                          setSelectedEventId("");
                          updateRunId("");
                          rememberSelection("");
                        }}
                      >
                        清除失效选择
                      </button>
                    </>
                  }
                />
              ) : (
                <Loading />
              )}
            </Card>
          ) : Page ? (
            <Page {...props} />
          ) : (
            <SupportPage {...props} page={page} />
          )}
        </main>
      </div>
    </div>
  );
}
