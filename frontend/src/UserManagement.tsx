import { useState } from "react";
import {
  CheckCircle2,
  KeyRound,
  LoaderCircle,
  Save,
  UserPlus,
} from "lucide-react";
import { api } from "./api";
import { ROLE_NAMES } from "./AccountPanel";
import type { AuthUser, UserRole, Employee } from "./types";
import { Card, ErrorNotice, Loading, time, useApi } from "./ui";

interface ManagedUser extends AuthUser {
  id: string;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}
type UserChange =
  | { role: UserRole }
  | { enabled: boolean }
  | { employee_id: string }
  | { password: string };
const passwordValid = (value: string) =>
  [...value].length >= 15 &&
  [...value].length <= 128 &&
  new TextEncoder().encode(value).length <= 512;

function UserRow({
  user,
  currentUsername,
  busy,
  update,
  employees,
}: {
  user: ManagedUser;
  currentUsername: string;
  busy: boolean;
  update: (user: ManagedUser, change: UserChange) => Promise<boolean>;
  employees: Employee[];
}) {
  const [role, setRole] = useState<UserRole>(user.role);
  const [employeeId, setEmployeeId] = useState(user.employee_id || "");
  const [resetting, setResetting] = useState(false);
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [error, setError] = useState("");
  async function resetPassword() {
    setError("");
    if (!passwordValid(password)) {
      setError("密码需 15–128 个字符，UTF-8 不超过 512 字节。");
      return;
    }
    if (password !== confirmation) {
      setError("两次输入的密码不一致。");
      return;
    }
    if (await update(user, { password })) {
      setPassword("");
      setConfirmation("");
      setResetting(false);
    }
  }
  return (
    <>
      <tr>
        <td>
          <strong>{user.username}</strong>
          {user.username === currentUsername && <small>当前账号</small>}
        </td>
        <td>
          <div className="user-role-control">
            <select
              aria-label={`${user.username} 的角色`}
              value={role}
              onChange={(e) => setRole(e.target.value as UserRole)}
              disabled={busy}
            >
              {Object.entries(ROLE_NAMES).map(([id, name]) => (
                <option key={id} value={id}>
                  {name}
                </option>
              ))}
            </select>
            <button
              className="button"
              onClick={() => void update(user, { role })}
              disabled={busy || role === user.role || (role === "business" && !user.employee_id)}
            >
              <Save size={13} />
              保存角色
            </button>
          </div>
        </td>
        <td><div className="user-role-control"><select aria-label={`${user.username} 的员工绑定`} value={employeeId} disabled={busy} onChange={(e) => setEmployeeId(e.target.value)}><option value="">未绑定员工</option>{employees.map((employee) => <option key={employee.id} value={employee.id}>{employee.id} · {employee.name}</option>)}</select><button className="button" disabled={busy || !employeeId || employeeId === user.employee_id} onClick={() => void update(user, { employee_id: employeeId })}>保存绑定</button></div></td>
        <td>
          <span
            className={`user-enabled ${user.enabled ? "enabled" : "disabled"}`}
          >
            {user.enabled ? "已启用" : "已停用"}
          </span>
        </td>
        <td>{time(user.created_at, true)}</td>
        <td>
          <div className="user-row-actions">
            <button
              className="button"
              onClick={() => void update(user, { enabled: !user.enabled })}
              disabled={busy}
            >
              {user.enabled ? "停用账号" : "启用账号"}
            </button>
            <button
              className="button"
              onClick={() => {
                setResetting((v) => !v);
                setPassword("");
                setConfirmation("");
                setError("");
              }}
              disabled={busy}
            >
              <KeyRound size={13} />
              {resetting ? "取消重置" : "重置密码"}
            </button>
          </div>
        </td>
      </tr>
      {resetting && (
        <tr className="user-reset-row">
          <td colSpan={6}>
            <form
              className="user-reset-form"
              onSubmit={(e) => {
                e.preventDefault();
                void resetPassword();
              }}
            >
              <label className="form-field">
                {user.username} 的新密码
                <input
                  type="password"
                  autoComplete="new-password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  disabled={busy}
                />
              </label>
              <label className="form-field">
                确认新密码
                <input
                  type="password"
                  autoComplete="new-password"
                  required
                  value={confirmation}
                  onChange={(e) => setConfirmation(e.target.value)}
                  disabled={busy}
                />
              </label>
              <button
                className="button primary"
                type="submit"
                disabled={busy || !password || !confirmation}
              >
                保存新密码
              </button>
            </form>
            <p className="user-management-note">
              保存后撤销该账号的全部旧会话；修改当前账号后需要重新登录。
            </p>
            <ErrorNotice message={error} />
          </td>
        </tr>
      )}
    </>
  );
}

export function UserManagement({ currentUser }: { currentUser: AuthUser }) {
  const [revision, setRevision] = useState(0);
  const users = useApi<ManagedUser[]>("/auth/users", 0, revision);
  const employees = useApi<Employee[]>("/employees");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<UserRole>("viewer");
  const [employeeId, setEmployeeId] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  async function createUser() {
    if (busy) return;
    setError("");
    setNotice("");
    if (!/^[a-z0-9][a-z0-9_.-]{2,63}$/i.test(username.trim())) {
      setError(
        "账号需 3–64 位英文字母、数字、下划线、点或短横线，以字母或数字开头。",
      );
      return;
    }
    if (!passwordValid(password)) {
      setError("密码需 15–128 个字符，UTF-8 不超过 512 字节。");
      return;
    }
    if (role === "business" && !employeeId) { setError("请为业务员工选择绑定的员工。" ); return; }
    setBusy(true);
    try {
      const created = await api<ManagedUser>("/auth/users", {
        body: { username: username.trim(), password, role, ...(employeeId ? { employee_id: employeeId } : {}) },
      });
      setPassword("");
      setUsername("");
      setRole("viewer");
      setEmployeeId("");
      setRevision((n) => n + 1);
      setNotice(
        `账号 ${created.username} 已创建，角色为${ROLE_NAMES[created.role]}。`,
      );
    } catch (e) {
      setPassword("");
      setError(e instanceof Error ? e.message : "账号创建失败");
    } finally {
      setBusy(false);
    }
  }

  async function updateUser(user: ManagedUser, change: UserChange) {
    if (busy) return false;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await api<ManagedUser>(
        `/auth/users/${encodeURIComponent(user.username)}`,
        { body: change },
      );
      setNotice(`${user.username} 的账号设置已更新，旧会话已撤销。`);
      setRevision((n) => n + 1);
      if (user.username === currentUser.username) await api("/session");
      return true;
    } catch (e) {
      setError(e instanceof Error ? e.message : "账号更新失败");
      return false;
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card
      title="账号管理"
      subtitle="仅已登录管理员可管理账号；每次变更撤销目标账号的旧会话"
    >
      <form
        className="user-create-form"
        onSubmit={(e) => {
          e.preventDefault();
          void createUser();
        }}
      >
        <label className="form-field">
          新账号
          <input
            autoComplete="off"
            autoCapitalize="none"
            spellCheck={false}
            required
            minLength={3}
            maxLength={64}
            placeholder="3–64 位英文字母或数字等"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            disabled={busy}
          />
        </label>
        <label className="form-field">
          初始密码
          <input
            type="password"
            autoComplete="new-password"
            required
            placeholder="至少 15 个字符"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            disabled={busy}
          />
        </label>
        <label className="form-field">
          角色
          <select
            value={role}
            onChange={(e) => setRole(e.target.value as UserRole)}
            disabled={busy}
          >
            {Object.entries(ROLE_NAMES).map(([id, name]) => (
              <option key={id} value={id}>
                {name}
              </option>
            ))}
          </select>
        </label>
        {role === "business" && <label className="form-field">绑定员工<select value={employeeId} required onChange={(e) => setEmployeeId(e.target.value)} disabled={busy}><option value="">选择员工</option>{employees.data?.map((employee) => <option key={employee.id} value={employee.id}>{employee.id} · {employee.name}</option>)}</select></label>}
        <button
          type="submit"
          className="button primary"
          disabled={busy || !username.trim() || !password}
        >
          {busy ? (
            <LoaderCircle className="spin" size={16} />
          ) : (
            <UserPlus size={16} />
          )}
          创建账号
        </button>
      </form>
      <p className="user-management-note">
        密码为 15–128 个字符，允许空格和中文，UTF-8 不超过 512
        字节。只读角色不能演练、评测或导入；分析员可以操作；管理员另可管理账号。系统必须保留至少一名可用管理员。
      </p>
      <ErrorNotice message={error || users.error || employees.error} />
      {notice && (
        <div className="import-success" role="status">
          <CheckCircle2 size={17} />
          {notice}
        </div>
      )}
      {users.loading ? (
        <Loading />
      ) : (
        users.data && (
          <div className="table-wrap user-table">
            <table>
              <thead>
                <tr>
                  <th>账号</th>
                  <th>角色</th>
                  <th>员工绑定</th>
                  <th>状态</th>
                  <th>创建时间</th>
                  <th>账号操作</th>
                </tr>
              </thead>
              <tbody>
                {users.data.map((user) => (
                  <UserRow
                    key={`${user.id}-${user.updated_at}`}
                    user={user}
                    currentUsername={currentUser.username}
                    busy={busy}
                    update={updateUser}
                    employees={employees.data || []}
                  />
                ))}
              </tbody>
            </table>
          </div>
        )
      )}
    </Card>
  );
}
