import { useEffect, useRef, useState } from "react";
import {
  ArrowRight,
  KeyRound,
  LoaderCircle,
  LockKeyhole,
  RefreshCw,
  Shield,
  ShieldCheck,
} from "lucide-react";
import App from "./App";
import {
  acceptSession,
  ApiError,
  api,
  clearSession,
  login,
  onSessionExpired,
  readAuthStatus,
  readSession,
} from "./api";
import type { AuthSession, AuthStatus, AuthUser } from "./types";
import { ErrorNotice } from "./ui";

export default function AuthGate() {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [status, setStatus] = useState<AuthStatus | null>(null);
  const [checking, setChecking] = useState(true);
  const [revision, setRevision] = useState(0);
  const [epoch, setEpoch] = useState(0);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const currentUser = useRef<AuthUser | null>(null);
  const currentToken = useRef("");
  const setup =
    status?.authentication_required === true &&
    status.initialized === false &&
    status.bootstrap_allowed === true;

  function establish(session: AuthSession) {
    acceptSession(session);
    currentUser.current = session.user;
    currentToken.current = session.token;
    setUser(session.user);
    setEpoch((n) => n + 1);
    setPassword("");
    setConfirmation("");
    setError("");
    setNotice("");
    setStatus((old) =>
      old ? { ...old, initialized: true, bootstrap_allowed: false } : old,
    );
  }

  useEffect(
    () =>
      onSessionExpired(() => {
        const wasSignedIn = !!currentUser.current;
        currentUser.current = null;
        currentToken.current = "";
        setUser(null);
        setPassword("");
        setConfirmation("");
        setChecking(false);
        if (wasSignedIn) setNotice("登录会话已失效，请重新登录。");
      }),
    [],
  );

  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    setChecking(true);
    setError("");
    void (async () => {
      try {
        const auth = await readAuthStatus(controller.signal);
        if (!active) return;
        setStatus(auth);
        if (!auth.initialized && auth.authentication_required) return;
        try {
          const session = await readSession(controller.signal);
          if (active) establish(session);
        } catch (e) {
          if (!(e instanceof ApiError && e.status === 401)) throw e;
          if (active) {
            clearSession();
            setUser(null);
            currentUser.current = null;
          }
        }
      } catch (e) {
        if (active)
          setError(e instanceof Error ? e.message : "无法连接身份认证服务");
      } finally {
        if (active) setChecking(false);
      }
    })();
    return () => {
      active = false;
      controller.abort();
    };
  }, [revision]);

  useEffect(() => {
    if (!user) return;
    const controller = new AbortController();
    let active = true;
    let pending = false;
    const revalidate = async () => {
      if (pending) return;
      pending = true;
      try {
        const session = await api<AuthSession>("/session", {
          signal: controller.signal,
        });
        if (
          active &&
          (session.user.username !== currentUser.current?.username ||
            session.user.role !== currentUser.current?.role ||
            session.token !== currentToken.current)
        )
          establish(session);
      } catch {
        /* A protected 401 is handled centrally; transient network errors keep the current view. */
      } finally {
        pending = false;
      }
    };
    const onFocus = () => {
      void revalidate();
    };
    const timer = setInterval(onFocus, 60000);
    window.addEventListener("focus", onFocus);
    return () => {
      active = false;
      controller.abort();
      clearInterval(timer);
      window.removeEventListener("focus", onFocus);
    };
  }, [user]);

  async function signIn() {
    if (submitting || !status || (!status.initialized && !setup)) return;
    if (setup && password !== confirmation) {
      setError("两次输入的密码不一致");
      return;
    }
    if (
      setup &&
      ([...password].length < 15 ||
        [...password].length > 128 ||
        new TextEncoder().encode(password).length > 512)
    ) {
      setError("密码需为 15–128 个字符，UTF-8 编码不超过 512 字节。");
      return;
    }
    setSubmitting(true);
    setError("");
    setNotice("");
    try {
      establish(await login(username.trim(), password, setup));
    } catch (e) {
      if (e instanceof ApiError && e.status === 409 && setup)
        setStatus((old) =>
          old ? { ...old, initialized: true, bootstrap_allowed: false } : old,
        );
      setPassword("");
      setConfirmation("");
      setError(e instanceof Error ? e.message : "登录失败，请重试");
    } finally {
      setSubmitting(false);
    }
  }

  async function signOut() {
    await api("/auth/logout", { body: {} });
    clearSession();
    currentUser.current = null;
    currentToken.current = "";
    setUser(null);
    setPassword("");
    setConfirmation("");
    setNotice("已退出登录。");
    window.location.hash = "overview";
  }

  if (user) return <App key={epoch} user={user} onLogout={signOut} />;

  return (
    <main className="auth-shell">
      <section className="auth-intro">
        <div className="auth-brand">
          <Shield size={27} />
          <span>
            工银数界 <b>DataFence</b>
          </span>
          <small>PoC</small>
        </div>
        <div className="auth-intro-copy">
          <span className="auth-eyebrow">DATA SECURITY WORKSPACE</span>
          <h1>
            让每一次数据访问
            <br />
            都有合理的业务依据。
          </h1>
          <p>
            业务员工按工单访问数据，安全人员处理异常请求。
          </p>
          <div className="auth-feature">
            <ShieldCheck size={20} />
            <span>身份验证与角色权限</span>
          </div>
          <div className="auth-feature">
            <LockKeyhole size={20} />
            <span>业务访问与安全研判</span>
          </div>
        </div>
        <p className="auth-boundary">
          面向大型商业银行场景的概念验证系统。沙盒业务数据为合成数据，未连接真实银行系统。
        </p>
      </section>
      <section className="auth-entry">
        <div className="auth-card">
          <span className="auth-lock">
            <KeyRound size={24} />
          </span>
          <h2>
            {setup
              ? "创建首个管理员"
              : status?.initialized === false
                ? "等待服务器初始化"
                : "登录 DataFence"}
          </h2>
          <p className="auth-subtitle">
            {setup
              ? "仅首次在服务器本机开放，请设置自己的账号与密码。"
              : status?.initialized === false
                ? "管理员需要先在服务器上创建初始账号。"
                : "使用管理员分配的账号继续访问。"}
          </p>
          {checking ? (
            <div className="auth-checking" role="status">
              <LoaderCircle size={21} className="spin" />
              正在检查登录状态…
            </div>
          ) : (
            <>
              <ErrorNotice message={error} />
              {notice && (
                <p className="auth-notice" role="status">
                  {notice}
                </p>
              )}
              {status?.initialized === false && !setup ? (
                <div className="auth-setup">
                  <p>
                    系统不提供默认密码。请联系部署管理员在服务器使用{" "}
                    <code>scripts/manage_users.py</code>{" "}
                    完成账号初始化，然后重新检查。
                  </p>
                  <button
                    className="button primary full-width"
                    onClick={() => setRevision((n) => n + 1)}
                  >
                    <RefreshCw size={16} />
                    重新检查
                  </button>
                </div>
              ) : status ? (
                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    void signIn();
                  }}
                >
                  <label className="form-field">
                    {setup ? "管理员账号" : "账号"}
                    <input
                      name="username"
                      autoComplete="username"
                      autoCapitalize="none"
                      spellCheck={false}
                      required
                      maxLength={64}
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                      disabled={submitting}
                      autoFocus
                    />
                  </label>
                  <label className="form-field">
                    密码
                    <input
                      name="password"
                      type="password"
                      autoComplete={setup ? "new-password" : "current-password"}
                      required
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      disabled={submitting}
                    />
                    {setup && (
                      <small>
                        15–128 个字符，允许空格与中文；不超过 512 UTF-8 字节。
                      </small>
                    )}
                  </label>
                  {setup && (
                    <label className="form-field">
                      确认密码
                      <input
                        name="confirmation"
                        type="password"
                        autoComplete="new-password"
                        required
                        value={confirmation}
                        onChange={(e) => setConfirmation(e.target.value)}
                        disabled={submitting}
                      />
                    </label>
                  )}
                  <button
                    type="submit"
                    className="button primary full-width auth-submit"
                    disabled={
                      submitting ||
                      !username.trim() ||
                      !password ||
                      (setup && !confirmation)
                    }
                  >
                    {submitting ? (
                      <LoaderCircle size={17} className="spin" />
                    ) : (
                      <ArrowRight size={17} />
                    )}
                    {submitting
                      ? "正在验证…"
                      : setup
                        ? "创建管理员并登录"
                        : "登录工作台"}
                  </button>
                </form>
              ) : (
                <button
                  className="button full-width"
                  onClick={() => setRevision((n) => n + 1)}
                >
                  <RefreshCw size={16} />
                  重新连接
                </button>
              )}
            </>
          )}
          <p className="auth-footer">
            账号权限由部署管理员分配。登录过期后需要重新验证身份。
          </p>
        </div>
      </section>
    </main>
  );
}
