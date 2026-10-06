"""Authenticated private deployment; synthetic execution and isolated public data."""

import asyncio
from contextlib import asynccontextmanager
import json
import ipaddress
import os
import re
from pathlib import Path
import secrets
import threading
from urllib.parse import urlsplit
from uuid import uuid4
from typing import Literal

from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from . import __version__
from .models import Employee, EvaluationRequest, SimulationRequest
from .scenarios import SCENARIOS
from .service import Service
from .storage import digest, now
from .auth import AuthStore, AuthError
from .deployment import Deployment
from .ingestion import ImportStore, ImportRequest
from .models import Contract
from .runtime_lock import RuntimeLock
from .gateway import AccessGateway, AccessRequest, GatewayError
from .workflows import WorkflowStore, WorkflowError, ReviewRequest, DemoRequest, DemoConfirmRequest, execute_demo
from .knowledge import KnowledgeBase
from .agent_workbench import build_agent_workbench
from .models import SecurityEvent, Analysis
from .security_queue import SecurityQueue
from .observation_reviews import ObservationReviews
from pydantic import Field

PROJECT_ROOT = Path(__file__).resolve().parents[2]


class LoginRequest(Contract):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


class UserCreateRequest(LoginRequest):
    role: Literal["admin", "analyst", "viewer", "business"] = "viewer"
    employee_id: str | None = Field(default=None, pattern=r"^E\d{4}$")


class UserUpdateRequest(Contract):
    role: Literal["admin", "analyst", "viewer", "business"] | None = None
    employee_id: str | None = Field(default=None, pattern=r"^E\d{4}$")
    enabled: bool | None = None
    password: str | None = Field(default=None, min_length=15, max_length=128)


def create_app(data_dir: Path | None = None, customer_count: int = 50000, *, auth_mode: str | None = None) -> FastAPI:
    directory = data_dir or Path(os.environ.get("DATAFENCE_DATA_DIR", PROJECT_ROOT / "runtime"))
    deployment = Deployment.load(auth_mode)
    capability = secrets.token_urlsafe(32)
    bootstrap_lock = threading.Lock()

    @asynccontextmanager
    async def lifespan(app):
        ownership = RuntimeLock(directory)
        try:
            app.state.auth = await asyncio.to_thread(AuthStore, directory / "auth.sqlite3")
            if deployment.network_mode == "lan" and not app.state.auth.initialized():
                raise RuntimeError("Initialize an administrator locally before LAN deployment")
            app.state.imports = await asyncio.to_thread(ImportStore, directory / "imports.sqlite3")
            app.state.service = await asyncio.to_thread(Service, directory, customer_count)
            app.state.workflows = WorkflowStore(app.state.service.store)
            app.state.gateway = AccessGateway(directory, app.state.service.employees, app.state.service.tasks,
                                               app.state.service.customers)
            app.state.observation_reviews = ObservationReviews(app.state.service.store)
            app.state.security_queue = SecurityQueue(app.state.service.store, app.state.gateway, app.state.imports)
            if os.environ.get("DATAFENCE_SERVER_PORT"):
                (directory / "server-state.json").write_text(json.dumps({
                    "pid": os.getpid(), "data_dir": str(directory.resolve()),
                    "port": int(os.environ["DATAFENCE_SERVER_PORT"]), "network_mode": deployment.network_mode}), encoding="utf-8")
            yield
        finally:
            state_path = directory / "server-state.json"
            if os.environ.get("DATAFENCE_SERVER_PORT") and state_path.is_file():
                try:
                    if json.loads(state_path.read_text(encoding="utf-8")).get("pid") == os.getpid():
                        state_path.unlink()
                except (OSError, ValueError):
                    pass
            ownership.close()

    app = FastAPI(title="DataFence 合成银行安全沙盒", version=__version__, lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url="/api/openapi.json")
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(deployment.hosts))

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        # Pydantic's default response can echo passwords or imported raw content.
        return JSONResponse({"detail": [{"loc": error["loc"], "type": error["type"],
                                         "msg": "字段校验失败"} for error in exc.errors()]}, status_code=422)

    def authenticated_session(request: Request):
        """Read current authorization, including revocation, without cached roles."""
        try:
            current = app.state.auth.authenticate(request.cookies.get("df_session", ""))
        except Exception:
            raise HTTPException(503, "认证服务暂不可用") from None
        if not current:
            raise HTTPException(401, "请先登录")
        request.state.user = current["user"]
        return current

    @app.middleware("http")
    async def local_boundary(request: Request, call_next):
        try:
            local_client = request.client is not None and ipaddress.ip_address(request.client.host).is_loopback
            if deployment.network_mode == "local" and not local_client:
                return JSONResponse({"detail": "本版本仅允许本机连接"}, status_code=403)
        except ValueError:
            return JSONResponse({"detail": "无法确认本机连接"}, status_code=403)
        if deployment.network_mode == "lan" and request.url.scheme != "https":
            return JSONResponse({"detail": "内网部署只接受 HTTPS；不信任转发协议头"}, status_code=403)
        origin = request.headers.get("origin")
        if origin:
            if not deployment.origin_allowed(origin):
                return JSONResponse({"detail": "仅允许本机演示来源"}, status_code=403)
        if request.headers.get("sec-fetch-site") == "cross-site":
            return JSONResponse({"detail": "拒绝跨站访问本机沙盒"}, status_code=403)
        path = request.url.path
        public = path in {"/api/auth/status", "/api/auth/login", "/api/auth/bootstrap", "/api/health/live"}
        session = None
        if path.startswith("/api") and not public:
            if deployment.auth_mode == "required":
                try:
                    session = await asyncio.to_thread(authenticated_session, request)
                except HTTPException as error:
                    return JSONResponse({"detail": error.detail}, status_code=error.status_code)
            else:
                request.state.user = dict(username="local-demo", role="admin", enabled=True)
            if request.state.user["role"] == "business" and not business_route(request.method, path):
                return JSONResponse({"detail": "业务账号只能访问本人业务工作区"}, status_code=403)
        if path.startswith("/api") and request.method in {"POST", "PUT", "PATCH", "DELETE"}:
            if not public and deployment.auth_mode == "required" and session["user"]["role"] == "viewer" and path != "/api/auth/logout":
                return JSONResponse({"detail": "只读账号不能执行此操作"}, status_code=403)
            expected = session["csrf_token"] if session else capability
            if not public and not secrets.compare_digest(request.headers.get("x-datafence-token", "").encode("utf-8"), expected.encode("ascii")):
                return JSONResponse({"detail": "本机操作令牌缺失或已失效，请刷新页面"}, status_code=403)
            if request.headers.get("content-type", "").split(";")[0] != "application/json":
                return JSONResponse({"detail": "请求必须为 JSON"}, status_code=415)
            payload = bytearray()
            body_limit = 2 * 1024 * 1024 if path == "/api/imports" else 16384
            async for chunk in request.stream():
                payload.extend(chunk)
                if len(payload) > body_limit:
                    return JSONResponse({"detail": "请求体超过接口大小限制"}, status_code=413)
            request._body = bytes(payload)
            if not public and deployment.auth_mode == "required":
                # A caller can hold an upload open while its account is revoked.
                # The entry check is not a lease to execute a later complete body.
                try:
                    session = await asyncio.to_thread(authenticated_session, request)
                except HTTPException as error:
                    return JSONResponse({"detail": error.detail}, status_code=error.status_code)
                if session["user"]["role"] == "viewer" and path != "/api/auth/logout":
                    return JSONResponse({"detail": "只读账号不能执行此操作"}, status_code=403)
                if session["user"]["role"] == "business" and not business_route(request.method, path):
                    return JSONResponse({"detail": "业务账号只能访问本人业务工作区"}, status_code=403)
        return await call_next(request)

    @app.middleware("http")
    async def response_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")
        if request.url.path.startswith("/api"):
            response.headers["Cache-Control"] = "no-store"
        return response

    def service() -> Service:
        return app.state.service

    def business_route(method: str, path: str) -> bool:
        if method == "GET":
            return path in {"/api/session", "/api/access/tasks", "/api/access/operations"} or bool(
                re.fullmatch(r"/api/access/operations/[0-9a-fA-F-]{36}", path))
        return method == "POST" and path in {"/api/access/execute", "/api/auth/logout"}

    def workflow_authorizer(request: Request):
        actor = dict(request.state.user)
        def authorize():
            if deployment.auth_mode == "required":
                current = authenticated_session(request)["user"]
                if current["id"] != actor["id"] or current["role"] not in {"admin", "analyst"}:
                    raise HTTPException(403, "当前账号无权修改研判或演示")
        return authorize

    def required(table: str, resource_id: str) -> dict:
        result = service().store.get(table, resource_id)
        if result is None:
            raise HTTPException(404, "记录不存在")
        return result

    @app.get("/api/session")
    def session(request: Request):
        if deployment.auth_mode == "local_demo":
            return {"token": capability, "user": request.state.user}
        current = app.state.auth.authenticate(request.cookies.get("df_session", ""))
        if not current:
            raise HTTPException(401, "请先登录")
        return {"token": current["csrf_token"], "user": current["user"]}

    @app.get("/api/auth/status")
    def auth_status(request: Request):
        local = request.client and ipaddress.ip_address(request.client.host).is_loopback
        return {"authentication_required": deployment.auth_mode == "required",
                "initialized": app.state.auth.initialized(),
                "bootstrap_allowed": bool(local and deployment.network_mode == "local"),
                "network_mode": deployment.network_mode}

    def issue_session(payload: LoginRequest, request: Request):
        try:
            result = app.state.auth.login(payload.username, payload.password, request.client.host)
        except AuthError as error:
            if error.code == "auth_unavailable":
                raise HTTPException(503, "认证服务暂不可用") from None
            limited = error.code == "rate_limited"
            raise HTTPException(429 if limited else 401, "尝试过于频繁，请稍后重试" if limited else "账号或密码错误",
                                headers={"Retry-After": str(error.retry_after or 60)} if limited else None) from None
        response = JSONResponse({"user": result["user"], "token": result["csrf_token"]})
        response.set_cookie("df_session", result["token"], max_age=28800, path="/", httponly=True,
                            secure=deployment.secure_cookie, samesite="strict")
        return response

    @app.post("/api/auth/login")
    def login(payload: LoginRequest, request: Request):
        return issue_session(payload, request)

    @app.post("/api/auth/bootstrap")
    def bootstrap(payload: LoginRequest, request: Request):
        if deployment.network_mode != "local" or not ipaddress.ip_address(request.client.host).is_loopback:
            raise HTTPException(403, "请在服务器本机初始化管理员")
        with bootstrap_lock:
            if app.state.auth.initialized():
                raise HTTPException(409, "管理员已初始化，请登录")
            try:
                app.state.auth.create_user(payload.username, payload.password, "admin", require_uninitialized=True)
            except AuthError:
                raise HTTPException(422, "账号需为合法字符，密码需15至128位且UTF-8不超过512字节") from None
        return issue_session(payload, request)

    @app.post("/api/auth/logout")
    def logout(request: Request):
        app.state.auth.logout(request.cookies.get("df_session", ""))
        response = JSONResponse({"logged_out": True})
        response.delete_cookie("df_session", path="/", httponly=True, secure=deployment.secure_cookie, samesite="strict")
        return response

    def require_admin(request):
        if deployment.auth_mode != "required" or request.state.user["role"] != "admin":
            raise HTTPException(403, "此操作需要已登录管理员")

    @app.get("/api/auth/users")
    def users(request: Request):
        require_admin(request)
        return app.state.auth.list_users()

    @app.post("/api/auth/users", status_code=201)
    def create_user(payload: UserCreateRequest, request: Request):
        require_admin(request)
        if payload.employee_id is not None and payload.employee_id not in {e.id for e in service().employees}:
            raise HTTPException(422, "请选择已登记的合成员工")
        try:
            return app.state.auth.create_user(payload.username, payload.password, payload.role, employee_id=payload.employee_id)
        except AuthError as error:
            raise HTTPException(409 if error.code == "username_taken" else 422,
                                "账号已存在或输入无效；密码需15至128位") from None

    @app.post("/api/auth/users/{username}")
    def update_user(username: str, payload: UserUpdateRequest, request: Request):
        require_admin(request)
        # Exactly one change per call prevents partial multi-field updates.
        changes = payload.model_dump(exclude_none=True)
        if len(changes) != 1:
            raise HTTPException(422, "每次只能修改一项账号设置")
        try:
            if payload.employee_id is not None:
                if payload.employee_id not in {e.id for e in service().employees}:
                    raise HTTPException(422, "请选择已登记的合成员工")
                return app.state.auth.set_employee_id(username, payload.employee_id)
            if payload.role is not None:
                return app.state.auth.set_role(username, payload.role)
            if payload.enabled is not None:
                return app.state.auth.set_enabled(username, payload.enabled)
            return app.state.auth.set_password(username, payload.password)
        except AuthError as error:
            raise HTTPException(409 if error.code == "last_admin_required" else 422,
                                "操作未完成：必须保留可用管理员，且账号与参数必须有效") from None

    @app.get("/api/health/live")
    def liveness():
        return {"status": "ok"}

    @app.get("/api/health")
    def health():
        return {"status": "ok", "version": __version__, "synthetic": True,
                "llm": service().analyst.info, "model": service().model_info,
                "deployment": {"network_mode": deployment.network_mode, "authentication": deployment.auth_mode}}

    @app.get("/api/datasets")
    def datasets():
        from .public_data import list_datasets, PublicDataError
        try:
            return list_datasets(directory / "public-data")
        except PublicDataError:
            raise HTTPException(503, "公开数据目录暂不可用，请在服务器核查导入产物") from None

    @app.get("/api/import-template")
    def import_template():
        from .scenarios import generate_scenario
        from .storage import dump
        events, _ = generate_scenario(SimulationRequest(scenario_id="normal", record_count=5),
                                      service().employees, service().tasks)
        return {"format": "jsonl", "source_name": "synthetic-example",
                "content": "".join(dump(event.model_dump(mode="json")) + "\n" for event in events)}

    @app.get("/api/imports")
    def imports():
        return app.state.imports.list()

    @app.get("/api/imports/{batch_id}")
    def import_detail(batch_id: str, limit: int = Query(100, ge=1, le=200), offset: int = Query(0, ge=0)):
        result = app.state.imports.detail(batch_id, limit, offset)
        if result is None:
            raise HTTPException(404, "导入批次不存在")
        return result

    @app.post("/api/imports", status_code=201)
    def import_events(payload: ImportRequest, request: Request):
        try:
            return app.state.imports.ingest(payload, service().employees, service().tasks, request.state.user["username"])
        except ValueError as error:
            raise HTTPException(422, str(error)) from None

    @app.get("/api/access/tasks")
    def access_tasks(request: Request):
        return app.state.gateway.available_tasks(request.state.user)

    @app.get("/api/access/operations")
    def access_operations(request: Request):
        return app.state.gateway.recent(request.state.user)

    @app.get("/api/access/operations/{request_id}")
    def access_operation(request_id: str, request: Request):
        try:
            result = app.state.gateway.operation(request_id, request.state.user)
        except GatewayError:
            raise HTTPException(409, "存在多个同编号操作，请在安全工作区按来源记录查看") from None
        if result is None:
            raise HTTPException(404, "操作记录不存在")
        return result

    @app.get("/api/access/verify")
    def access_verify():
        return app.state.gateway.verify()

    @app.post("/api/access/execute")
    def access_execute(payload: AccessRequest, request: Request):
        actor = request.state.user
        def authorize_delivery():
            if deployment.auth_mode != "required":
                return
            current = authenticated_session(request)
            if current["user"]["id"] != actor["id"] or current["user"]["role"] not in {"admin", "analyst", "business"}:
                raise HTTPException(403, "当前账号无权交付数据")
            return current["user"]
        try:
            result = app.state.gateway.execute(payload, actor, authorize=authorize_delivery)
        except GatewayError as error:
            code = str(error)
            raise HTTPException(409 if code in {"idempotency_conflict", "unresolved_reservation", "task_operation_limit"} else 403,
                                "请求未执行：" + code) from None
        return JSONResponse(result, status_code=200 if result["allowed"] else 403)

    @app.get("/api/overview")
    def overview():
        return service().overview()

    @app.get("/api/employees", response_model=list[Employee])
    def employees():
        return service().employees

    @app.get("/api/employees/{employee_id}")
    def employee(employee_id: str):
        result = service().employee_detail(employee_id)
        if result is None:
            raise HTTPException(404, "员工不存在")
        return result

    @app.get("/api/scenarios")
    def scenarios():
        return SCENARIOS

    @app.get("/api/runs")
    def runs():
        return service().store.list("runs")

    @app.post("/api/runs", status_code=202)
    def create_run(payload: SimulationRequest, background: BackgroundTasks,
                   idempotency_key: str | None = Header(None, max_length=100)):
        worker = service()
        with worker.schedule_lock:
            key = "run:" + idempotency_key if idempotency_key else None
            fingerprint = digest(payload.model_dump(mode="json"))
            if key:
                try:
                    prior = worker.store.idempotent(key, fingerprint)
                except ValueError as error:
                    raise HTTPException(409, str(error)) from error
                if prior:
                    return required("runs", prior)
            if sum(item["status"] == "running" for item in worker.store.list("runs", 1000)) >= 3:
                raise HTTPException(429, "最多同时运行三个演练，请等待完成")
            try:
                result = worker.create_run(payload)
            except ValueError as error:
                raise HTTPException(422, str(error)) from error
            if key:
                worker.store.remember(key, fingerprint, result["id"])
            background.add_task(worker.execute_run, result["id"], payload)
            return result

    @app.get("/api/runs/{run_id}")
    def run_detail(run_id: str):
        return required("runs", run_id)

    @app.get("/api/runs/{run_id}/receipts")
    def receipts(run_id: str):
        required("runs", run_id)
        return [{"event_id": item["event_id"], "channel": item["channel"],
                 "record_count": len(item["customer_ids"]), "received_at": item["received_at"], "synthetic": True}
                for item in service().store.sink_receipts(run_id)]

    @app.get("/api/runs/{run_id}/stream")
    async def stream(run_id: str, request: Request):
        required("runs", run_id)

        async def updates():
            last = None
            for _ in range(120):
                if await request.is_disconnected():
                    break
                if deployment.auth_mode == "required":
                    try:
                        await asyncio.to_thread(authenticated_session, request)
                    except HTTPException:
                        # Headers may already be sent: terminate the stream,
                        # rather than emitting any new data after revocation.
                        break
                result = {"run": required("runs", run_id), "events": service().store.events(run_id=run_id, limit=500)}
                encoded = json.dumps(result, ensure_ascii=False)
                if encoded != last:
                    yield "event: update\ndata: " + encoded + "\n\n"
                    last = encoded
                if result["run"]["status"] != "running":
                    break
                await asyncio.sleep(0.5)
        return StreamingResponse(updates(), media_type="text/event-stream", headers={"X-Accel-Buffering": "no"})

    @app.get("/api/events")
    def events(run_id: str | None = None, limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
        return service().store.events(run_id=run_id, limit=limit, offset=offset)

    @app.get("/api/events/{event_id}")
    def event_detail(event_id: str):
        record = service().store.event(event_id)
        if record is None:
            raise HTTPException(404, "事件不存在")
        return record

    @app.get("/api/observations")
    def observations(source: Literal["all", "gateway", "simulation", "import"] = "all",
                     status: Literal["all", "pending", "investigating", "resolved"] = "all",
                     decision: Literal["all", "allowed", "blocked", "observed"] = "all",
                     risk: Literal["all", "high"] = "all", q: str = Query("", max_length=100),
                     attention_only: bool = False,
                     limit: int = Query(25, ge=1, le=100), offset: int = Query(0, ge=0)):
        return app.state.security_queue.list(source=source, status=status, decision=decision, risk=risk,
                                             q=q, limit=limit, offset=offset, attention_only=attention_only)

    def get_observation(key):
        result = app.state.security_queue.detail(key)
        if result is None:
            raise HTTPException(404, "观察记录不存在")
        return result

    def observation_review_value(key):
        if key.startswith("simulation:"):
            value = app.state.workflows.review(key.split(":", 1)[1])
            return dict(value, event_id=key)
        return app.state.observation_reviews.get(key)

    @app.get("/api/observations/{key}")
    def observation_detail(key: str):
        result = get_observation(key)
        result["related_knowledge"] = KnowledgeBase().related(SecurityEvent.model_validate(result["event"]),
                                                               Analysis.model_validate(result["analysis"]))
        result["review"] = observation_review_value(key)
        return result

    @app.get("/api/observations/{key}/review")
    def observation_review(key: str):
        get_observation(key)
        return observation_review_value(key)

    @app.post("/api/observations/{key}/review")
    def review_observation(key: str, payload: ReviewRequest, request: Request):
        observation = get_observation(key)
        authorize_user = workflow_authorizer(request)
        def authorize():
            authorize_user()
            app.state.security_queue.assert_evidence(key, observation["evidence_hash"])
            if key.startswith("simulation:") and not app.state.workflows.verify_reviews()["valid"]:
                raise WorkflowError("研判历史校验失败，不能追加结论")
        try:
            if key.startswith("simulation:"):
                result = app.state.workflows.append_review(event_detail(key.split(":", 1)[1]), payload,
                                                           request.state.user["username"], authorize=authorize)
                return dict(result, event_id=key)
            return app.state.observation_reviews.append(key, observation, payload, request.state.user["username"],
                                                        authorize=authorize)
        except WorkflowError as error:
            raise HTTPException(409, str(error)) from None

    @app.get("/api/knowledge/status")
    def knowledge_status():
        return KnowledgeBase().status()

    @app.get("/api/knowledge/documents")
    def knowledge_documents():
        return KnowledgeBase().list_documents()

    @app.get("/api/knowledge/documents/{document_id}")
    def knowledge_document(document_id: str):
        result = KnowledgeBase().get_document(document_id)
        if result is None:
            raise HTTPException(404, "知识条目不存在")
        return result

    @app.get("/api/knowledge/search")
    def knowledge_search(q: str = Query(min_length=1, max_length=300), limit: int = Query(5, ge=1, le=8)):
        return KnowledgeBase().search(q, limit)

    @app.get("/api/agents/workbench")
    def agent_workbench(event_id: str | None = None):
        selected = event_detail(event_id) if event_id else None
        records = service().store.events(run_id=selected["run_id"] if selected else None, limit=499 if selected else 100)
        if selected:
            records = [selected] + [r for r in records if r["event"]["event_id"] != event_id]
        result = build_agent_workbench(records, model_info=service().model_info, llm_info=service().analyst.info)
        selected = selected or (records[0] if records else None)
        result["selected_event_id"] = selected["event"]["event_id"] if selected else None
        result["related_knowledge"] = KnowledgeBase().related(SecurityEvent.model_validate(selected["event"]),
                                                               Analysis.model_validate(selected["analysis"])) if selected else []
        return result

    @app.get("/api/events/{event_id}/review")
    def event_review(event_id: str):
        event_detail(event_id)
        return app.state.workflows.review(event_id)

    @app.post("/api/events/{event_id}/review")
    def review_event(event_id: str, payload: ReviewRequest, request: Request):
        record = event_detail(event_id)
        authorize_user = workflow_authorizer(request)
        def authorize():
            authorize_user()
            app.state.security_queue.assert_evidence("simulation:" + event_id, record["evidence_hash"])
            if not app.state.workflows.verify_reviews()["valid"]:
                raise WorkflowError("研判历史校验失败，不能追加结论")
        try:
            return app.state.workflows.append_review(record, payload, request.state.user["username"],
                                                     authorize=authorize)
        except WorkflowError as error:
            raise HTTPException(409, str(error)) from None

    @app.get("/api/reviews/verify")
    def verify_reviews():
        simulation = app.state.workflows.verify_reviews()
        observations = app.state.observation_reviews.verify(app.state.security_queue)
        try:
            simulation_evidence_valid = service().store.verify()["valid"]
        except (ValueError, KeyError, TypeError):
            simulation_evidence_valid = False
        return dict(valid=simulation["valid"] and observations["valid"] and simulation_evidence_valid,
                    checked_reviews=simulation["checked_reviews"] + observations["checked_reviews"])

    @app.get("/api/demos")
    def demos():
        return app.state.workflows.demos()

    @app.get("/api/demos/{demo_id}")
    def demo_detail(demo_id: str):
        result = app.state.workflows.demo(demo_id)
        if result is None:
            raise HTTPException(404, "演示不存在")
        return result

    @app.post("/api/demos", status_code=202)
    def create_demo(payload: DemoRequest, request: Request, background: BackgroundTasks):
        worker = service()
        authorize = workflow_authorizer(request)
        with worker.schedule_lock:
            try:
                result, created = app.state.workflows.create_demo(worker, payload, request.state.user["username"],
                                                                 authorize=authorize)
            except WorkflowError as error:
                raise HTTPException(409, str(error)) from None
            except ValueError as error:
                raise HTTPException(422, str(error)) from None
            if created:
                background.add_task(execute_demo, worker, app.state.workflows, result["id"])
            return result

    @app.post("/api/demos/{demo_id}/confirm")
    def confirm_demo(demo_id: str, payload: DemoConfirmRequest, request: Request):
        demo_detail(demo_id)
        try:
            return app.state.workflows.confirm(demo_id, payload.review_revision, request.state.user["username"],
                                               authorize=workflow_authorizer(request))
        except WorkflowError as error:
            raise HTTPException(409, str(error)) from None

    @app.get("/api/evaluations")
    def evaluations():
        return [{key: value for key, value in job.items() if key != "report"}
                for job in service().store.list("evaluations")]

    @app.get("/api/evaluations/latest")
    def latest_evaluation():
        return next((job["report"] for job in service().store.list("evaluations", 1000)
                     if job["status"] == "completed"), None)

    @app.get("/api/model-experiments")
    def model_experiments():
        """Aggregate-only saved cloud diagnostics; never expose case truth/keys."""
        import hashlib
        experiments = []
        root = service().store.directory / "evaluations"
        if not root.is_dir():
            return []
        for folder in sorted(root.iterdir(), key=lambda item: item.name):
            report_file = folder / "report.json"
            if not folder.is_dir() or not report_file.is_file() or report_file.stat().st_size > 1000000:
                continue
            try:
                report = json.loads(report_file.read_text(encoding="utf-8"))
                if report.get("provider") != "sensenova" or not isinstance(report.get("summary"), dict):
                    continue
                integrity = True
                for filename, key in (("responses.jsonl", "responses_sha256"), ("plan.json", "plan_sha256"),
                                      ("dataset.json", "dataset_sha256"), ("labels.jsonl", "labels_sha256")):
                    path = folder / filename
                    if not path.is_file() or path.stat().st_size > 8000000 or hashlib.sha256(path.read_bytes()).hexdigest() != report.get(key):
                        integrity = False
                        break
                summary = report["summary"]
                experiments.append({"id": folder.name, "created_at": report.get("created_at"),
                                    "protocol": report.get("version"), "status": report.get("status"),
                                    "model": report.get("model"), "provider": "sensenova",
                                    "artifact_digests_valid": integrity, "kind": "development_diagnostic",
                                    "summary": {key: summary.get(key) for key in (
                                        "planned_cases", "attempted_cases", "completed_reviews", "review_coverage",
                                        "status_counts", "baseline_metrics", "final_metrics", "request_blocking_metrics",
                                        "usage", "review_wall_ms", "cost", "ai_output_block_effectiveness_measured")},
                                    "limitations": ["合成开发诊断及同样例回归，不是未见泛化测试。",
                                                    "API调用不训练商汤权重；请求暂缓不等于成功识别攻击。",
                                                    "该实验未生成下游AI输出，未测真实输出外泄阻断率。",
                                                    "保存的实验参数与当前部署可能不同，不能当作实时模型质量保证。"]})
            except (OSError, ValueError, TypeError, AttributeError):
                continue
        return sorted(experiments, key=lambda item: item["created_at"] or "", reverse=True)[:10]

    @app.post("/api/evaluations", status_code=202)
    def evaluate(payload: EvaluationRequest, background: BackgroundTasks):
        worker = service()
        with worker.schedule_lock:
            if any(job["status"] == "running" for job in worker.store.list("evaluations", 1000)):
                raise HTTPException(429, "已有评测正在运行")
            job = dict(id=str(uuid4()), status="running", report=None, error=None,
                       created_at=now(), seed=payload.seed, sessions=payload.sessions)
            worker.store.save("evaluations", job)
            background.add_task(worker.execute_evaluation, job["id"], payload.seed, payload.sessions)
            return {"id": job["id"], "status": job["status"]}

    @app.get("/api/evaluations/{job_id}")
    def evaluation(job_id: str):
        return required("evaluations", job_id)

    @app.get("/api/assets")
    def assets():
        counts = service().bank_counts
        labels = {"employees": "合成员工", "customers": "合成客户", "accounts": "合成账户",
                  "transactions": "合成交易", "loans": "合成贷款", "tasks": "业务工单"}
        return {"manifest": service().store.manifest(), "assets": [
            {"name": key, "label": label, "count": counts.get(key, 0), "sensitivity": 85 if key != "tasks" else 50,
             "synthetic": True} for key, label in labels.items()]}

    @app.get("/api/agents")
    def agents():
        return [
            dict(id="classification", name="Data Classification Agent", status="active", description="读取事件声明的资产敏感度并形成D维度；未扫描客户原始行", implementation="资产敏感度契约与规则"),
            dict(id="behavior", name="User Behavior Agent", status="active", description="对比正常行为分布", implementation="Isolation Forest"),
            dict(id="intent", name="Access Intent Agent", status="active", description="核验工单与角色、目的、范围和时间", implementation="工单核验与可选涉敏AI语义审查；模型配置状态：" + service().analyst.info["status"]),
            dict(id="flow", name="Data Flow Agent", status="active", description="追踪会话内数据对象来源", implementation="对象关联"),
            dict(id="correlation", name="Threat Correlation Agent", status="active", description="关联当前已处理事件前缀", implementation="会话与对象证据关联"),
            dict(id="response", name="Response Agent", status="active", description="按策略执行沙盒响应", implementation="确定性编排器；无模型执行权限"),
        ]

    @app.get("/api/policies")
    def policies():
        return {"version": "poc-policy-v1", "weights": {"D": .25, "B": .25, "I": .15, "P": .20, "C": .15},
                "llm_enabled": service().analyst.info["enabled"], "levels": [
                    {"name": "LOW", "min": 0, "max": 29, "actions": ["ALLOW"]},
                    {"name": "MEDIUM", "min": 30, "max": 59, "actions": ["WARN"]},
                    {"name": "HIGH", "min": 60, "max": 89, "actions": ["WARN", "BLOCK_EXPORT", "NOTIFY_SOC", "PRESERVE_EVIDENCE"]},
                    {"name": "CRITICAL", "min": 90, "max": 100, "actions": ["BLOCK_UPLOAD", "FREEZE_SESSION", "NOTIFY_SOC", "PRESERVE_EVIDENCE"]},
                ]}

    @app.get("/api/audit/verify")
    def audit():
        return service().store.verify()

    frontend = PROJECT_ROOT / "frontend" / "dist"
    if (frontend / "assets").is_dir():
        app.mount("/assets", StaticFiles(directory=frontend / "assets"), name="assets")

    @app.get("/")
    def index():
        if (frontend / "index.html").is_file():
            return FileResponse(frontend / "index.html")
        return JSONResponse({"message": "请先运行 frontend 中的 npm run build，或启动本地 Vite 开发服务。"})

    @app.get("/favicon.svg")
    def favicon():
        if (frontend / "favicon.svg").is_file():
            return FileResponse(frontend / "favicon.svg", media_type="image/svg+xml")
        raise HTTPException(404, "图标尚未构建")

    return app


app = create_app()
