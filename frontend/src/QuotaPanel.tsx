import { CircleCheck, ClipboardList, Clock3, ShieldBan } from "lucide-react";
import type { QuotaDecision } from "./types";
import { Card, num, short } from "./ui";

const REASONS: Record<string, string> = {
  capacity_reserved: "已为当前请求预留容量，等待后续确认",
  accepted_request: "请求已获准，额度消耗已确认",
  quota_exceeded: "当前请求将超过工单可用额度，已拒绝预留",
  policy_blocked: "已被其他安全策略阻断，不新增额度消耗",
  execution_failed: "执行未完成，未确认的预留已取消",
  non_read_operation: "当前不是 QUERY / API 读取操作，不重复计量",
  no_verified_business_task: "当前没有可核验的业务工单",
  business_task_binding_mismatch: "事件与业务工单的主体绑定不匹配",
};
const STATUSES: Record<QuotaDecision["status"], string> = {
  reserved: "已预留",
  confirmed: "已确认",
  cancelled: "已取消",
  rejected: "额度拒绝",
  not_applicable: "未适用",
};

export function QuotaPanel({ decision }: { decision?: QuotaDecision | null }) {
  if (!decision) return null;
  const reason = REASONS[decision.reason] || decision.reason;
  if (!decision.applicable)
    return (
      <div className="quota-not-applicable">
        <ClipboardList size={15} />
        <span>额度账本未适用：{reason || "服务端未提供原因"}。</span>
      </div>
    );
  const Icon =
    decision.status === "confirmed"
      ? CircleCheck
      : decision.status === "rejected"
        ? ShieldBan
        : Clock3;
  const scope =
    decision.scope === "task_lifetime"
      ? "工单生命周期 · 跨会话累计"
      : decision.scope === "session"
        ? "单会话 · 同一工单与员工"
        : "未提供计量范围";
  return (
    <Card
      title="业务工单额度核验"
      subtitle="额度账本在该事件处理时的快照"
      action={
        <span className={`quota-status ${decision.status}`}>
          <Icon size={14} />
          {STATUSES[decision.status]}
        </span>
      }
    >
      <div className="quota-scope">
        <span>
          <ClipboardList size={15} />
          {scope}
        </span>
        <span>
          工单 {decision.task_id || "未关联"} · 员工 {decision.employee_id}
        </span>
      </div>
      <div className="quota-values">
        <div>
          <span>本次请求</span>
          <strong>
            {num(decision.requested_records)}
            <small>条</small>
          </strong>
        </div>
        <div>
          <span>范围内额度上限</span>
          <strong>
            {num(decision.limit)}
            <small>条</small>
          </strong>
        </div>
        <div>
          <span>当前已占用</span>
          <strong>
            {num(decision.used_records)}
            <small>条</small>
          </strong>
          <p>
            确认 {num(decision.confirmed_records)} + 预留{" "}
            {num(decision.reserved_records)}
          </p>
        </div>
        <div>
          <span>当前剩余容量</span>
          <strong>
            {num(decision.remaining_records)}
            <small>条</small>
          </strong>
        </div>
      </div>
      <div
        className={`quota-decision ${decision.allowed ? "allowed" : "denied"}`}
      >
        <strong>
          {decision.allowed
            ? "当前额度记录允许占用容量"
            : "当前额度记录未允许占用容量"}
        </strong>
        <span>{reason}</span>
      </div>
      {decision.already_seen && (
        <p className="quota-replay-note">
          该事件标识已有额度记录，当前结果沿用原记录，不代表同一请求再次获准执行。
        </p>
      )}
      <p className="quota-metric-note">
        计量口径：成功获准 QUERY / API 请求的
        record_count，预留同样占用容量。导出、压缩和上传不重复扣减；该额度不是去重客户数，也不是实际返回记录数。预留在服务重启后保留，只有明确取消才能释放未确认额度。
      </p>
      {decision.reservation_id && (
        <p className="quota-record-id" title={decision.reservation_id}>
          额度记录{" "}
          <span className="mono">{short(decision.reservation_id)}</span>
        </p>
      )}
    </Card>
  );
}
