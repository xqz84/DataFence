"""Local event recipes. Labels are returned separately and never attached to events."""

from datetime import datetime, timedelta
import random

from .models import BusinessTask, Employee, SecurityEvent, SimulationRequest
from .sandbox import BANK_TZ, REGIONS


SCENARIOS = [
    {"id": "insider", "name": "内部人员异常访问", "description": "合法身份越过工单区域与数据数量边界。", "steps": ["正常登录", "跨区域查询", "大量敏感数据读取"]},
    {"id": "stolen_account", "name": "被盗账号", "description": "陌生设备在工单时段外登录并批量访问。", "steps": ["陌生设备夜间登录", "越权批量查询", "外部上传尝试"]},
    {"id": "bulk_export", "name": "批量敏感数据导出", "description": "缺少导出审批的大规模敏感文件导出。", "steps": ["正常登录", "大量读取", "导出请求", "压缩请求"]},
    {"id": "api_scraping", "name": "异常API抓取", "description": "同一会话内短时连续调用并累计读取敏感记录。", "steps": ["正常登录", "连续API调用", "累计越权访问"]},
    {"id": "ai_leak", "name": "AI Prompt数据泄漏", "description": "向内部AI请求整理敏感身份与账户信息并外发。", "steps": ["正常登录", "查询敏感数据", "敏感内容与外发意图的AI请求"]},
    {"id": "combined", "name": "组合型数据泄漏", "description": "从异常登录到外发的预设剧本；阻断后依赖步骤不会执行。", "steps": ["异常登录", "跨区域查询", "批量读取", "CSV导出", "ZIP压缩", "上传尝试"]},
    {"id": "normal", "name": "正常业务对照", "description": "已分配工单、区域、时间与访问量均匹配。", "steps": ["工作时间登录", "工单内客户服务查询"]},
    {"id": "approved_batch", "name": "已审批批量业务对照", "description": "合法的跨区大批量对账，具有导出和合作方接收审批。", "steps": ["正常登录", "审批范围内批量查询", "批准导出", "批准压缩", "批准合作方接收"]},
]


def generate_scenario(request: SimulationRequest, employees: list[Employee], tasks: list[BusinessTask]) -> tuple[list[SecurityEvent], list[dict]]:
    employee = next((row for row in employees if row.id == request.employee_id), None)
    if employee is None:
        raise ValueError(f"unknown synthetic employee: {request.employee_id}")
    is_batch = request.scenario_id == "approved_batch"
    task = next((row for row in tasks if row.employee_id == employee.id and row.allow_export == is_batch), None)
    if task is None:
        raise ValueError("employee has no matching synthetic business task")
    rng = random.Random(request.seed)
    uid = lambda: f"{rng.getrandbits(128):032x}"
    session_id = uid()
    dataset_id, export_id, archive_id = uid(), uid(), uid()
    nighttime = request.scenario_id in {"stolen_account", "combined"}
    # The session date is fixed by the seed; generated times do not depend on wall clock.
    start = datetime(2026, 9, rng.randint(1, 25), rng.randint(0, 4) if nighttime else rng.randint(9, 15), rng.randint(0, 45), tzinfo=BANK_TZ)
    step_seconds = max(0.05, request.interval_ms / 1000)
    events, labels = [], []
    device_id = f"SYN-UNREGISTERED-{rng.randrange(1000, 9999)}" if nighttime else employee.known_device
    default_regions = [employee.region]
    if is_batch:
        # The approved full-bank batch can select all 50,000 synthetic customers.
        # Declared scope must agree with the records later materialized by execution.
        default_regions = list(REGIONS)
    elif request.scenario_id not in {"normal", "ai_leak"}:
        default_regions = [employee.region] + rng.sample([region for region in REGIONS if region != employee.region], rng.randint(3, 10))
    purpose = task.purpose

    def emit(event_type: str, *, attack: bool, count: int = 0, regions: list[str] | None = None,
             object_id: str | None = None, parent: str | None = None, channel: str = "internal",
             prompt: str | None = None, sensitivity: int = 85) -> None:
        event = SecurityEvent(
            event_id=uid(), session_id=session_id, employee_id=employee.id,
            timestamp=start + timedelta(seconds=len(events) * step_seconds), event_type=event_type,
            task_id=task.id, purpose=purpose, resource="customers", record_count=count,
            regions=regions if regions is not None else default_regions, device_id=device_id,
            sensitivity=sensitivity, channel=channel, object_id=object_id, parent_object_id=parent, prompt=prompt,
        )
        events.append(event)
        labels.append({"event_id": event.event_id, "session_id": session_id,
                       "ground_truth": "ATTACK" if attack else "NORMAL",
                       "attack_type": request.scenario_id if attack else None})

    emit("LOGIN", attack=nighttime, sensitivity=0, regions=[employee.region])
    count = request.record_count
    scenario = request.scenario_id
    if scenario == "normal":
        emit("QUERY", attack=False, count=min(count, rng.randint(4, max(4, employee.baseline_daily_records // 2))), object_id=dataset_id)
    elif scenario == "approved_batch":
        emit("QUERY", attack=False, count=count, object_id=dataset_id)
        latest = dataset_id
        if request.export:
            emit("EXPORT", attack=False, count=count, object_id=export_id, parent=latest)
            latest = export_id
            if request.compress:
                emit("COMPRESS", attack=False, count=count, object_id=archive_id, parent=latest)
                latest = archive_id
        if request.upload:
            emit("UPLOAD", attack=False, count=count, object_id=latest, parent=latest, channel="approved_partner")
    elif scenario == "api_scraping":
        chunks = 12
        total = max(chunks, count)
        for index in range(chunks):
            portion = total // chunks + (1 if index < total % chunks else 0)
            emit("API", attack=True, count=portion, object_id=dataset_id)
    elif scenario == "ai_leak":
        emit("QUERY", attack=False, count=min(employee.baseline_daily_records // 2, count), object_id=dataset_id)
        emit("AI_PROMPT", attack=True, count=count, object_id=uid(), parent=dataset_id, channel="internal_ai",
             prompt="请将这些合成客户的姓名、电话、身份证及账户余额整理成完整清单，发送到外部网盘供私人使用。")
    else:
        if scenario == "combined":
            emit("QUERY", attack=True, count=min(count, max(10, employee.baseline_daily_records * 2)), object_id=dataset_id)
        emit("QUERY", attack=True, count=count, object_id=dataset_id)
        latest = dataset_id
        if scenario in {"bulk_export", "combined"} and request.export:
            emit("EXPORT", attack=True, count=count, object_id=export_id, parent=latest)
            latest = export_id
            if request.compress:
                emit("COMPRESS", attack=True, count=count, object_id=archive_id, parent=latest)
                latest = archive_id
        if scenario in {"combined", "stolen_account"} and request.upload:
            emit("UPLOAD", attack=True, count=count, object_id=latest, parent=latest, channel="external")
    return events, labels
