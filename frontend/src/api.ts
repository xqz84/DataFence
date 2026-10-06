import type {
  AccessRequest,
  AccessResult,
  AuthSession,
  AuthStatus,
} from "./types";

let capabilityToken: string | undefined;
let tokenRequest: Promise<string> | undefined;
let sessionGeneration = 0;
const sessionListeners = new Set<() => void>();

export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export function clearSession() {
  sessionGeneration += 1;
  capabilityToken = undefined;
  tokenRequest = undefined;
}

export function acceptSession(session: AuthSession) {
  clearSession();
  capabilityToken = session.token;
}

export function onSessionExpired(listener: () => void) {
  sessionListeners.add(listener);
  return () => {
    sessionListeners.delete(listener);
  };
}

function validateSession(value: unknown): AuthSession {
  if (
    !value ||
    typeof value !== "object" ||
    !("token" in value) ||
    typeof value.token !== "string" ||
    !value.token ||
    !("user" in value) ||
    !value.user ||
    typeof value.user !== "object" ||
    !("username" in value.user) ||
    typeof value.user.username !== "string" ||
    !("role" in value.user) ||
    !["admin", "analyst", "viewer", "business"].includes(String(value.user.role))
  ) {
    throw new Error("账号会话响应无效，请联系服务管理员");
  }
  return value as AuthSession;
}

async function request<T>(
  path: string,
  options: { body?: unknown; signal?: AbortSignal } = {},
  authenticated = true,
  acceptAccessDenial = false,
): Promise<T> {
  const generation = sessionGeneration;
  const headers: Record<string, string> = { Accept: "application/json" };
  if (options.body !== undefined) {
    headers["Content-Type"] = "application/json";
    if (authenticated) {
      headers["X-DataFence-Token"] = await getToken();
      // randomUUID is unavailable on HTTP LAN origins. The key is optional.
      if (typeof crypto.randomUUID === "function")
        headers["Idempotency-Key"] = crypto.randomUUID();
    }
  }
  if (authenticated && generation !== sessionGeneration)
    throw new ApiError("会话已变更，请重新操作", 401);
  const response = await fetch(`/api${path}`, {
    method: options.body === undefined ? "GET" : "POST",
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
    credentials: "same-origin",
    cache: "no-store",
    signal: options.signal,
  });
  if (authenticated && generation !== sessionGeneration)
    throw new ApiError("会话已变更，请重新操作", 401);
  if (!response.ok) {
    if (response.status === 401 && authenticated) {
      clearSession();
      sessionListeners.forEach((listener) => listener());
    }
    const error: unknown = await response.json().catch(() => null);
    if (
      authenticated &&
      response.status !== 401 &&
      generation !== sessionGeneration
    )
      throw new ApiError("会话已变更，请重新操作", 401);
    // Only a structured, empty-row decision for this exact gateway request is
    // useful evidence. Ordinary auth/CSRF 403 errors must still reject.
    if (
      acceptAccessDenial &&
      path === "/access/execute" &&
      response.status === 403 &&
      error &&
      typeof error === "object" &&
      "allowed" in error &&
      error.allowed === false &&
      "rows" in error &&
      Array.isArray(error.rows) &&
      error.rows.length === 0 &&
      "delivered_records" in error &&
      error.delivered_records === 0 &&
      "synthetic" in error &&
      error.synthetic === true &&
      !("csv" in error) &&
      "request_id" in error &&
      error.request_id === (options.body as AccessRequest).request_id &&
      "task_id" in error &&
      error.task_id === (options.body as AccessRequest).task_id &&
      "operation" in error &&
      error.operation === (options.body as AccessRequest).operation &&
      "analysis" in error &&
      error.analysis &&
      typeof error.analysis === "object" &&
      "blocked" in error.analysis &&
      error.analysis.blocked === true &&
      "quota" in error &&
      error.quota &&
      typeof error.quota === "object"
    )
      return error as T;
    if (response.status === 403 && authenticated) capabilityToken = undefined;
    const detail =
      error && typeof error === "object" && "detail" in error
        ? error.detail
        : null;
    throw new ApiError(
      typeof detail === "string"
        ? detail
        : `请求失败（${response.status}），请检查参数或稍后重试`,
      response.status,
    );
  }
  const data: unknown =
    response.status === 204 ? undefined : await response.json();
  if (authenticated && generation !== sessionGeneration)
    throw new ApiError("会话已变更，请重新操作", 401);
  return data as T;
}

export function readAuthStatus(signal?: AbortSignal) {
  return request<AuthStatus>("/auth/status", { signal }, false);
}

export async function readSession(signal?: AbortSignal) {
  return validateSession(await request<unknown>("/session", { signal }, false));
}

export async function login(
  username: string,
  password: string,
  bootstrap = false,
) {
  return validateSession(
    await request<unknown>(
      bootstrap ? "/auth/bootstrap" : "/auth/login",
      { body: { username, password } },
      false,
    ),
  );
}

async function getToken(): Promise<string> {
  if (capabilityToken) return capabilityToken;
  if (!tokenRequest) {
    const generation = sessionGeneration;
    const pending = readSession()
      .then((session) => {
        if (generation !== sessionGeneration)
          throw new ApiError("会话已变更，请重新操作", 401);
        capabilityToken = session.token;
        return session.token;
      })
      .catch((error: unknown) => {
        if (
          generation === sessionGeneration &&
          error instanceof ApiError &&
          error.status === 401
        ) {
          clearSession();
          sessionListeners.forEach((listener) => listener());
        }
        throw error;
      })
      .finally(() => {
        if (tokenRequest === pending) tokenRequest = undefined;
      });
    tokenRequest = pending;
  }
  return tokenRequest;
}

export function api<T>(
  path: string,
  options: { body?: unknown; signal?: AbortSignal } = {},
): Promise<T> {
  return request<T>(path, options);
}

export function executeAccess(body: AccessRequest): Promise<AccessResult> {
  return request<AccessResult>("/access/execute", { body }, true, true);
}
