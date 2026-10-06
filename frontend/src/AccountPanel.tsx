import { useState } from "react";
import { LoaderCircle, LogOut, UserRound } from "lucide-react";
import type { AuthUser, UserRole } from "./types";
import { Card, ErrorNotice } from "./ui";

export const ROLE_NAMES: Record<UserRole, string> = {
  admin: "管理员",
  analyst: "安全分析员",
  viewer: "只读观察员",
  business: "业务员工",
};
export const canOperate = (user: AuthUser) =>
  user.role === "admin" || user.role === "analyst";

export function AccountPanel({
  user,
  onLogout,
}: {
  user: AuthUser;
  onLogout: () => Promise<void>;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function signOut() {
    setBusy(true);
    setError("");
    try {
      await onLogout();
    } catch (e) {
      setError(e instanceof Error ? e.message : "退出失败，请重试");
    } finally {
      setBusy(false);
    }
  }
  return (
    <Card title="当前账号">
      <div className="account-panel">
        <span className="account-avatar">
          <UserRound size={24} />
        </span>
        <div>
          <strong>{user.username}</strong>
          <span>{ROLE_NAMES[user.role]}</span>
          {user.employee_id && <span>员工 {user.employee_id}</span>}
        </div>
        <button
          className="button"
          disabled={busy}
          onClick={() => void signOut()}
        >
          {busy ? (
            <LoaderCircle size={16} className="spin" />
          ) : (
            <LogOut size={16} />
          )}
          {busy ? "正在退出…" : "退出登录"}
        </button>
      </div>
      <p className="account-permissions">
        {user.role === "business" ? "可使用已绑定员工的授权业务工单。" :
        canOperate(user)
          ? "可以查看安全数据、启动沙盒演练、运行离线评测及导入允许的数据。"
          : "只读访问安全工作台。"}
      </p>
      <ErrorNotice message={error} />
    </Card>
  );
}
