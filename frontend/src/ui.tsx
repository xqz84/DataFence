import { useEffect, useState, type ReactNode } from "react";
import {
  AlertCircle,
  ArrowUpRight,
  Check,
  ChevronRight,
  Clock3,
  Database,
  LoaderCircle,
  ShieldCheck,
} from "lucide-react";
import { api } from "./api";
import type { EventRecord, RiskLevel, Run } from "./types";

export const RISK_NAMES: Record<RiskLevel, string> = {
  LOW: "低风险",
  MEDIUM: "中风险",
  HIGH: "高风险",
  CRITICAL: "严重风险",
};
export const RISK_COLORS: Record<RiskLevel, string> = {
  LOW: "#2670da",
  MEDIUM: "#d58a17",
  HIGH: "#dc6036",
  CRITICAL: "#b73549",
};
export const EVENT_NAMES: Record<string, string> = {
  LOGIN: "账号登录",
  QUERY: "数据查询",
  EXPORT: "文件导出",
  COMPRESS: "文件压缩",
  API: "API 访问",
  UPLOAD: "上传请求",
  AI_PROMPT: "AI 数据调用",
};
export const CAPABILITY_NAMES: Record<string, string> = {
  classification: "数据分级识别",
  behavior: "用户行为分析",
  intent: "访问意图核验",
  flow: "数据流追踪",
  correlation: "威胁关联研判",
  response: "响应编排",
};
export const INTENT_NAMES: Record<string, string> = {
  supported: "工单证据支持",
  mismatch: "偏离工单范围",
  insufficient_evidence: "核验依据不足",
};
export const ACTION_NAMES: Record<string, string> = {
  ALLOW: "放行",
  WARN: "风险提示",
  REQUIRE_REAUTHENTICATION: "要求二次认证",
  BLOCK_EXPORT: "阻断导出",
  BLOCK_UPLOAD: "阻断上传",
  FREEZE_SESSION: "冻结沙盒会话",
  NOTIFY_SOC: "模拟通知 SOC",
  PRESERVE_EVIDENCE: "保留证据",
  BLOCK_AI: "阻断 AI 调用",
  BLOCK_AI_PROMPT: "阻断当前 AI 请求",
  BLOCK_READ: "阻断读取",
  BLOCK_REQUEST: "阻断请求",
};
export const DIMENSIONS = [
  { key: "D", name: "数据敏感" },
  { key: "B", name: "行为异常" },
  { key: "I", name: "身份设备" },
  { key: "P", name: "目的偏离" },
  { key: "C", name: "渠道风险" },
];
export const num = (v: number | null | undefined) =>
  v == null
    ? "—"
    : new Intl.NumberFormat("zh-CN", { maximumFractionDigits: 1 }).format(v);
export const pct = (v: number | null | undefined) =>
  v == null ? "未定义" : `${(v * 100).toFixed(1)}%`;
export const time = (v?: string | null, full = false) =>
  v
    ? new Date(v).toLocaleString(
        "zh-CN",
        full
          ? {
              month: "2-digit",
              day: "2-digit",
              hour: "2-digit",
              minute: "2-digit",
              second: "2-digit",
              hour12: false,
            }
          : {
              hour: "2-digit",
              minute: "2-digit",
              second: "2-digit",
              hour12: false,
            },
      )
    : "—";
export const short = (v: string) =>
  v.length > 16 ? `${v.slice(0, 8)}…${v.slice(-4)}` : v;

export function useApi<T>(path: string | null, pollMs = 0, revision = 0) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    if (!path) {
      setData(null);
      setLoading(false);
      return;
    }
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    let active = true;
    setData(null);
    setLoading(true);
    setError("");
    const load = async () => {
      try {
        const value = await api<T>(path, { signal: controller.signal });
        if (active) {
          setData(value);
          setError("");
        }
      } catch (e) {
        if (active && !(e instanceof DOMException && e.name === "AbortError"))
          setError(e instanceof Error ? e.message : "无法连接本地服务");
      } finally {
        if (active) {
          setLoading(false);
          if (pollMs) timer = setTimeout(load, pollMs);
        }
      }
    };
    void load();
    return () => {
      active = false;
      controller.abort();
      clearTimeout(timer);
    };
  }, [path, pollMs, revision]);
  return { data, error, loading };
}
export function Badge({ level }: { level: RiskLevel }) {
  return (
    <span className={`badge ${level.toLowerCase()}`}>
      <i />
      {RISK_NAMES[level]}
    </span>
  );
}
export function Status({ run }: { run: Run }) {
  return (
    <span className={`status ${run.status}`}>
      <i />
      {
        {
          running: "运行中",
          completed: "已完成",
          failed: "执行失败",
          interrupted: "已中断",
        }[run.status]
      }
    </span>
  );
}
export function Card({
  title,
  subtitle,
  action,
  children,
  className = "",
}: {
  title?: string;
  subtitle?: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`card ${className}`}>
      {title && (
        <div className="card-heading">
          <div>
            <h2>{title}</h2>
            {subtitle && <p>{subtitle}</p>}
          </div>
          {action}
        </div>
      )}
      {children}
    </section>
  );
}
export function Empty({
  title = "暂无事件记录",
  text = "启动一次沙盒演练后，这里将显示实际处理的数据。",
  action,
}: {
  title?: string;
  text?: string;
  action?: ReactNode;
}) {
  return (
    <div className="empty">
      <div className="empty-icon">
        <Database size={26} strokeWidth={1.4} />
      </div>
      <h3>{title}</h3>
      <p>{text}</p>
      {action}
    </div>
  );
}
export function Loading() {
  return (
    <div className="loading">
      <LoaderCircle className="spin" size={20} />
      正在读取本地数据…
    </div>
  );
}
export function ErrorNotice({ message }: { message: string }) {
  return message ? (
    <div className="error-notice" role="alert">
      <AlertCircle size={17} />
      <span>{message}</span>
    </div>
  ) : null;
}
export function PageHeading({
  eyebrow,
  title,
  description,
  action,
}: {
  eyebrow: string;
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="page-heading">
      <div>
        <div className="eyebrow">{eyebrow}</div>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {action && <div className="page-actions">{action}</div>}
    </div>
  );
}
export function SandboxNotice({ compact = false }: { compact?: boolean }) {
  return (
    <div className={`sandbox-notice ${compact ? "compact" : ""}`}>
      <ShieldCheck size={18} />
      <span>
        <strong>合成银行沙盒</strong>
        　沙盒业务与安全日志均为合成测试数据，安全动作仅在本地沙盒中执行。
      </span>
      <span className="notice-tag">PoC 环境</span>
    </div>
  );
}
export function Metric({
  label,
  value,
  unit,
  detail,
  icon,
  tone = "blue",
}: {
  label: string;
  value: ReactNode;
  unit?: string;
  detail?: string;
  icon?: ReactNode;
  tone?: string;
}) {
  return (
    <div className="metric card">
      <div className="metric-top">
        <span>{label}</span>
        {icon && <span className={`metric-icon ${tone}`}>{icon}</span>}
      </div>
      <div className="metric-value">
        {value}
        <small>{unit}</small>
      </div>
      {detail && <p>{detail}</p>}
    </div>
  );
}
export function ProgressBar({
  value,
  color = "#2670da",
}: {
  value: number;
  color?: string;
}) {
  return (
    <div className="progress-track">
      <span
        style={{
          width: `${Math.max(0, Math.min(value, 100))}%`,
          backgroundColor: color,
        }}
      />
    </div>
  );
}
export function EventsTable({
  events,
  onSelect,
  limit = 8,
}: {
  events: EventRecord[];
  onSelect: (event: EventRecord) => void;
  limit?: number;
}) {
  if (!events.length) return <Empty />;
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>发生时间</th>
            <th>事件 / 主体</th>
            <th>访问规模</th>
            <th>风险等级</th>
            <th>处置结果</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {events.slice(0, limit).map((r) => (
            <tr key={r.event.event_id}>
              <td className="mono muted">{time(r.event.timestamp)}</td>
              <td>
                <button className="table-link" onClick={() => onSelect(r)}>
                  {EVENT_NAMES[r.event.event_type] || r.event.event_type}
                </button>
                <small className="cell-sub">
                  {r.event.employee_id} · {short(r.event.event_id)}
                </small>
              </td>
              <td>
                {num(r.event.record_count)} <span className="muted">条</span>
              </td>
              <td>
                <Badge level={r.analysis.risk_level} />
              </td>
              <td>
                <span
                  className={`outcome ${r.outcome === "blocked" ? "blocked" : ""}`}
                >
                  {r.outcome === "blocked" ? "已阻断" : "已执行"}
                </span>
              </td>
              <td>
                <button
                  className="icon-button"
                  title="查看事件详情"
                  aria-label="查看事件详情"
                  onClick={() => onSelect(r)}
                >
                  <ChevronRight size={16} />
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
export function RiskChart({
  points,
  labels,
  height = 200,
}: {
  points: number[];
  labels?: string[];
  height?: number;
}) {
  if (!points.length)
    return <Empty title="等待风险数据" text="风险曲线由实际检测结果生成。" />;
  const width = 640,
    left = 36,
    right = 12,
    top = 16,
    bottom = 30;
  const plotHeight = height - top - bottom;
  const positions = points.map((p, i) => [
    left + (i * (width - left - right)) / Math.max(points.length - 1, 1),
    top + ((100 - p) / 100) * plotHeight,
  ]);
  const path = positions
    .map(([x, y], i) => `${i ? "L" : "M"}${x},${y}`)
    .join(" ");
  const area = `${path} L${positions[positions.length - 1][0]},${height - bottom} L${left},${height - bottom} Z`;
  return (
    <svg
      className="risk-chart"
      viewBox={`0 0 ${width} ${height}`}
      role="img"
      aria-label={`风险趋势：${points.map((p) => p.toFixed(1)).join("，")}`}
    >
      {[0, 30, 60, 90].map((v) => (
        <g key={v}>
          <line
            x1={left}
            y1={top + ((100 - v) / 100) * plotHeight}
            x2={width - right}
            y2={top + ((100 - v) / 100) * plotHeight}
            stroke="#e7edf4"
            strokeDasharray={v ? "4 4" : undefined}
          />
          <text
            x={0}
            y={top + ((100 - v) / 100) * plotHeight + 4}
            fill="#8996a9"
            fontSize="11"
          >
            {v}
          </text>
        </g>
      ))}
      <path d={area} fill="#edf4ff" />
      <path
        d={path}
        fill="none"
        stroke="#2670da"
        strokeWidth="2.7"
        strokeLinejoin="round"
      />
      {positions.map(([x, y], i) => (
        <g key={i}>
          <circle
            cx={x}
            cy={y}
            r="4"
            fill={
              points[i] >= 90
                ? RISK_COLORS.CRITICAL
                : points[i] >= 60
                  ? RISK_COLORS.HIGH
                  : "#2670da"
            }
            stroke="white"
            strokeWidth="2"
          />
          {(points.length <= 8 ||
            i === 0 ||
            i === points.length - 1 ||
            i % Math.ceil(points.length / 6) === 0) && (
            <text
              x={x}
              y={height - 7}
              textAnchor={
                i === 0 ? "start" : i === points.length - 1 ? "end" : "middle"
              }
              fill="#8996a9"
              fontSize="10"
            >
              {labels?.[i] || `${i + 1}`}
            </text>
          )}
        </g>
      ))}
    </svg>
  );
}
export function RiskRadar({
  dimensions,
}: {
  dimensions: Record<string, number>;
}) {
  const polar = (i: number, r: number) => [
    150 + Math.sin((i * 2 * Math.PI) / 5) * r,
    130 - Math.cos((i * 2 * Math.PI) / 5) * r,
  ];
  const polygon = (r: number) =>
    DIMENSIONS.map((_, i) => polar(i, r).join(",")).join(" ");
  return (
    <div className="radar-wrap">
      <svg viewBox="0 0 300 270" role="img" aria-label="五维风险评分雷达图">
        {[25, 50, 75, 100].map((r) => (
          <polygon
            key={r}
            points={polygon(r * 0.86)}
            fill={r === 100 ? "#f9fbfe" : "none"}
            stroke="#e3eaf3"
          />
        ))}
        {DIMENSIONS.map((d, i) => {
          const [x, y] = polar(i, 86);
          const [tx, ty] = polar(i, 113);
          return (
            <g key={d.key}>
              <line x1="150" y1="130" x2={x} y2={y} stroke="#e3eaf3" />
              <text
                x={tx}
                y={ty}
                textAnchor="middle"
                fill="#748299"
                fontSize="11"
              >
                {d.name}
              </text>
              <text
                x={tx}
                y={ty + 17}
                textAnchor="middle"
                fill="#25374e"
                fontWeight="600"
                fontSize="12"
              >
                {num(dimensions[d.key] ?? 0)}
              </text>
            </g>
          );
        })}
        <polygon
          points={DIMENSIONS.map((d, i) =>
            polar(
              i,
              Math.max(0, Math.min(100, dimensions[d.key] ?? 0)) * 0.86,
            ).join(","),
          ).join(" ")}
          fill="#2670da24"
          stroke="#2670da"
          strokeWidth="2"
        />
        {DIMENSIONS.map((d, i) => {
          const [x, y] = polar(
            i,
            Math.max(0, Math.min(100, dimensions[d.key] ?? 0)) * 0.86,
          );
          return <circle key={d.key} cx={x} cy={y} r="3" fill="#2670da" />;
        })}
      </svg>
    </div>
  );
}
export function ActionList({ actions }: { actions: string[] }) {
  return (
    <div className="action-list">
      {actions.length ? (
        actions.map((action, i) => (
          <div key={`${action}-${i}`} className="action-item">
            <span className="action-check">
              <Check size={14} />
            </span>
            <span>
              {ACTION_NAMES[action] || action}
              <small>{action}</small>
            </span>
            <span className="simulated">模拟响应</span>
          </div>
        ))
      ) : (
        <p className="muted">当前未产生响应动作</p>
      )}
    </div>
  );
}
export function Chain({ record }: { record: EventRecord }) {
  return (
    <div className="chain">
      {record.analysis.chain.map((node, i) => (
        <div
          className={`chain-node ${node.blocked ? "is-blocked" : ""}`}
          key={node.event_id}
        >
          <div className="chain-node-number">
            {node.blocked ? <ShieldCheck size={18} /> : i + 1}
          </div>
          <strong>{EVENT_NAMES[node.event_type] || node.event_type}</strong>
          <span className="mono">{time(node.timestamp)}</span>
          <small>
            风险 {num(node.risk_score)} · {node.blocked ? "已阻断" : "已处理"}
          </small>
          {i < record.analysis.chain.length - 1 && (
            <ChevronRight className="chain-arrow" size={18} />
          )}
        </div>
      ))}
    </div>
  );
}
export function EventTimeline({
  events,
  selectedId,
  onSelect,
}: {
  events: EventRecord[];
  selectedId?: string;
  onSelect: (r: EventRecord) => void;
}) {
  if (!events.length)
    return <Empty title="监听已就绪" text="等待沙盒产生第一条事件。" />;
  return (
    <div className="timeline">
      {events.map((r) => (
        <button
          onClick={() => onSelect(r)}
          key={r.event.event_id}
          className={`timeline-item ${selectedId === r.event.event_id ? "selected" : ""}`}
        >
          <span
            className={`timeline-dot ${r.analysis.risk_level.toLowerCase()}`}
          />
          <span className="timeline-main">
            <span className="timeline-title">
              {EVENT_NAMES[r.event.event_type]}
              <span>{num(r.analysis.risk_score)}</span>
            </span>
            <span className="timeline-description">
              {r.event.employee_id} · {num(r.event.record_count)} 条记录
            </span>
            <span className="timeline-time">
              <Clock3 size={11} />
              {time(r.event.timestamp)}
              {r.outcome === "blocked" && <b>已阻断</b>}
            </span>
          </span>
        </button>
      ))}
    </div>
  );
}
export function TextLink({
  children,
  onClick,
}: {
  children: ReactNode;
  onClick: () => void;
}) {
  return (
    <button className="text-link" onClick={onClick}>
      {children}
      <ArrowUpRight size={14} />
    </button>
  );
}
