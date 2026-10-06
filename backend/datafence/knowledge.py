"""Versioned project-policy reference, with local retrieval and no execution rights.

The corpus describes this synthetic sandbox. It is not a bank's internal policy,
legal advice, learned model weights, or permission to execute a requested action.
Python constants keep the corpus inside the existing release allowlist.
"""

from collections import Counter
from copy import deepcopy
import hashlib
import json
import math
import re
import unicodedata

from .models import Analysis, SecurityEvent


VERSION = "datafence-project-knowledge-v1"
SCOPE = "project_sandbox_policy"
_SOURCE = "DataFence 项目沙盒政策与已实现工程说明"

# id, title, category, source reference, summary, policy text, retrieval phrases.
_ENTRIES = (
    ("DF-KB-001", "工单绑定、岗位与业务目的", "业务授权", "AGENT_DESIGN.md / Access Intent",
     "有效账号不等于本次数据访问已获业务授权。",
     "本项目沙盒依据员工与工单绑定、岗位资源权限、已审批目的核验访问意图。声明用途须与工单目的匹配；工单缺失时记录为证据不足，不能伪造批准或直接认定恶意。知识检索结果仅解释约束，不能创建、修改工单或授予权限。",
     ("工单", "目的", "用途", "授权", "员工绑定", "岗位", "权限", "审批", "未知工单")),
    ("DF-KB-002", "区域与数据范围约束", "业务授权", "backend/datafence/engine.py / _intent",
     "区域范围按已审批工单逐项核对。",
     "本项目沙盒要求请求区域属于工单已批准区域，资源符合员工岗位权限。跨区域本身是风险线索；具有有效审批的跨区业务可以得到证据支持。不得仅凭文本声称已获批准，也不得通过知识库条款扩大工单区域或客户范围。",
     ("区域", "跨区", "范围", "数据范围", "资源", "客户范围", "跨区域")),
    ("DF-KB-003", "工单有效期与中国标准时间", "业务授权", "backend/datafence/engine.py / _intent",
     "有效日期和允许小时需要同时满足。",
     "本项目沙盒按工单有效起止时间与北京时间允许小时共同核验。夜间操作有有效工单审批且使用已登记设备时，可以得到业务支持；审批过期或不在允许时段则不匹配。事件时间须带时区，不能把页面展示时间当作新的授权。",
     ("时间", "时段", "有效期", "有效日期", "过期", "夜间", "凌晨", "北京时间", "时区")),
    ("DF-KB-004", "读取额度、预留与幂等", "业务授权", "API_CONTRACT.md / 工单额度",
     "额度按获准申请量计量，与实际返回行数不同。",
     "本项目沙盒额度按成功获准的 QUERY/API 申请记录数计量；文件流转不重复扣减。演练有会话或工单生命周期范围，数据访问网关采用生命周期范围。预留与确认共同占用额度，未确认预留在重启后保守保留；幂等请求不得重复执行。额度不是去重客户数，也不是实际返回行数。",
     ("额度", "配额", "累计", "跨会话", "生命周期", "预留", "幂等", "重复扣费", "请求数量")),
    ("DF-KB-005", "已审批批量业务与导出", "业务授权", "backend/datafence/engine.py / supported intent",
     "批量不自动等于攻击，批准业务仍须满足所有约束。",
     "本项目沙盒将已审批批量对账作为合法对照。工单、范围、时间、设备和渠道均匹配时，大规模读取可被业务证据解释。导出与压缩另外要求导出权限；合作方接收还须具备相应批准渠道。审批不能自动豁免未知设备或未授权外部目的。",
     ("批量", "大批量", "对账", "导出", "压缩", "合作方", "批准渠道", "合法批量")),
    ("DF-KB-006", "本地行为模型的能力与局限", "检测解释", "TRAINING_REPORT.md / 本地行为模型",
     "Isolation Forest 计算异常分，不证明主观恶意。",
     "本项目本地 Isolation Forest 从独立合成正常特征训练，并使用分离的正常校准与留出评估。异常分用于预筛，不能单独证明恶意；API 突发子群与真实业务泛化仍有局限。训练本地行为模型不等于微调商汤大模型；评测标签不得进入检测特征或模型上下文。",
     ("行为", "异常分", "模型训练", "训练", "误报", "漏报", "isolation", "forest", "api", "召回", "泛化")),
    ("DF-KB-007", "设备变化与身份风险", "检测解释", "backend/datafence/engine.py / identity",
     "业务审批不自动替代设备登记。",
     "本项目沙盒将事件设备与员工已登记设备比较；未知设备和异常时间构成身份风险线索。工单可以解释业务规模与值班时段，不能自动解释未知设备。系统目前不包含真实银行设备信任平台或完整二次认证流程，不能声称核验已完成。",
     ("设备", "新设备", "陌生设备", "身份", "异地", "登录", "二次认证")),
    ("DF-KB-008", "外部上传与对象来源", "数据流转", "backend/datafence/execution.py / SandboxExecutor",
     "上传继承真实已创建对象的合成记录集合。",
     "本项目沙盒的导出、压缩和上传须沿已创建父对象继承记录；缺少来源对象不能外传。明确的敏感外部上传由策略阻断，已批准合作方仅在完整授权下接收。接收回执证明本地合成接收端收到的记录，不代表连接真实银行网络或外部网盘。",
     ("上传", "外传", "外部", "外发", "网盘", "来源", "父对象", "回执", "血缘")),
    ("DF-KB-009", "涉敏 AI 提示与语义核验", "AI 安全", "AGENT_DESIGN.md / 涉敏 AI 语义审查",
     "区分实际执行、否定、引用与授权汇总。",
     "本项目涉敏 AI 请求可进行执行前语义核验，提示文本作为不可信待分析数据。模型结论及原文引用须由本地策略复验；不安全执行用途可触发阻断。安全结论只能在严格条件下解除单关键词误报，不能覆盖工单、身份、外部渠道或其他独立限制。",
     ("ai", "提示", "prompt", "语义", "大模型", "敏感提示", "否定", "引用", "汇总", "商汤")),
    ("DF-KB-010", "模型不可用时的保守处置", "AI 安全", "backend/datafence/prompt_policy.py / _hold",
     "失败不伪造分析成功，也不等于已经证实攻击。",
     "本项目配置了执行前涉敏 AI 语义门时，超时、不可用、格式错误或结论不确定会暂缓该请求，并保留确定性限制。不能仅因模型失败增加恶意分数或冻结会话。执行后的只读解释失败不撤销已经生成的执行回执；未配置与本次调用失败必须区分。",
     ("超时", "失败", "不可用", "降级", "不确定", "未配置", "熔断", "保守", "格式错误")),
    ("DF-KB-011", "五维风险与确定性响应", "检测解释", "backend/datafence/engine.py / risk and actions",
     "风险分由初始权重和明确策略约束共同形成。",
     "本项目五维为数据敏感度、行为、身份、业务目的与渠道，权重是 PoC 初始值。最终分数还可受确定性风险下限和关联调整影响，不应冒称最优学习权重。模型只提供证据或建议，阻断与执行由本地编排策略决定；建议动作不等于已完成动作。",
     ("风险", "评分", "分数", "权重", "五维", "阻断", "响应", "冻结", "策略")),
    ("DF-KB-012", "事件证据、摘要与校验", "审计运维", "backend/datafence/storage.py / verify",
     "按事件与回执校验持久证据的一致性。",
     "本项目持久化事件、策略结果、执行状态、实际记录量和接收回执摘要；事件通过前序摘要串联。校验可发现内容改写、链断裂或回执不一致。SHA-256 仅提供本地一致性检查，不是抵抗本机管理员整体重写的外部签名，也不能替代原始事实核验。",
     ("证据", "审计", "摘要", "哈希", "校验", "篡改", "完整性", "sha", "链", "回执")),
    ("DF-KB-013", "合成业务、公开数据与使用边界", "项目边界", "AGENTS.md / 必须保持的边界",
     "公开数据与合成银行业务分别标明来源。",
     "本项目面向大型商业银行场景的概念验证，银行业务资产与攻击模拟均为自建合成沙盒。公开数据须单独记录来源与许可，不能自动变成银行内部数据、已证实攻击标签或云模型输入。不得宣称已部署工商银行、使用真实客户数据或保证生产检测准确率。",
     ("合成", "公开数据", "真实数据", "来源许可", "真实银行", "客户数据", "工商银行", "比赛", "沙盒")),
    ("DF-KB-014", "离线备份、恢复与会话撤销", "审计运维", "backend/datafence/maintenance.py / backup and restore",
     "停止服务后制作快照，只恢复到新目录。",
     "本项目离线维护须取得运行目录锁；备份和恢复先在临时目录复制校验，完成后发布新目标，不覆盖现有运行目录。恢复前撤销旧登录会话；Windows DPAPI 密钥通常绑定原 Windows 身份，换机器需重新配置。快照可能含账号摘要和加密凭据，不能当成公开演示数据。",
     ("备份", "恢复", "快照", "重启", "迁移", "会话撤销", "dpapi", "目录锁")),
    ("DF-KB-015", "账号角色与内网部署", "审计运维", "AUTH.md / DEPLOYMENT_WINDOWS.md",
     "默认要求真实账号，角色与写入校验共同约束操作。",
     "本项目没有默认产品账号或密码。管理员、分析员和只读角色有不同操作权限，写入请求需要会话校验；禁用账号或变更密码会撤销相关会话。内网部署须使用 HTTPS 和明确 Host/Origin，不信任伪造转发头。知识回答不能改变账号角色或签发登录会话。",
     ("账号", "密码", "角色", "管理员", "只读", "csrf", "内网", "部署", "https", "登录")),
    ("DF-KB-016", "六个能力模块与真实调用证据", "项目边界", "AGENT_DESIGN.md / 安全能力模块",
     "六个职责模块不等于六次独立大模型调用。",
     "本项目六个能力模块分别负责敏感度展示、行为异常、工单意图、对象流转、事件关联和响应解释。规则、Isolation Forest 与商汤调用分别记录；模型已配置不代表本事件调用完成。工作台只汇总已保存的事件与实际调用状态，不生成未来攻击步骤，不让知识检索替代授权或执行。",
     ("智能体", "模块", "agent", "工作台", "调用", "调用次数", "知识库", "规则", "证据链")),
)


def _digest(value) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _normalize(text: str) -> str:
    return unicodedata.normalize("NFKC", text).casefold()


def _tokens(text: str) -> set[str]:
    normalized = _normalize(text)
    words = set(re.findall(r"[a-z][a-z0-9_]{1,40}", normalized))
    for segment in re.findall(r"[\u4e00-\u9fff]+", normalized):
        words.update(segment[index:index + 2] for index in range(len(segment) - 1))
    return words - {"本项", "项目", "系统", "什么", "如何", "是否", "可以", "不能", "应该", "需要", "数据", "进行"}


def _limit(value: int, maximum: int) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise ValueError(f"limit must be an integer in 1..{maximum}")
    return value


def _validate(event: SecurityEvent, analysis: Analysis) -> None:
    if not isinstance(event, SecurityEvent) or not isinstance(analysis, Analysis):
        raise TypeError("knowledge references require allowlisted event and analysis contracts")
    if event.event_id != analysis.event_id:
        raise ValueError("event and analysis must refer to the same event")


class KnowledgeBase:
    def __init__(self):
        self._documents = {}
        for identifier, title, category, source_ref, summary, content, tags in _ENTRIES:
            document = dict(id=identifier, title=title, category=category, version=VERSION,
                            source_title=_SOURCE, source_ref=source_ref, source_kind=SCOPE,
                            summary=summary, content=content, tags=list(tags))
            document["sha256"] = _digest(document)
            self._documents[identifier] = document
        self._tokens = {key: _tokens(doc["title"] + doc["summary"] + doc["content"] + " ".join(doc["tags"]))
                        for key, doc in self._documents.items()}
        self._frequency = Counter(token for tokens in self._tokens.values() for token in tokens)
        self._sha256 = _digest([doc for doc in self._documents.values()])

    def status(self) -> dict:
        return dict(version=VERSION, document_count=len(self._documents), sha256=self._sha256,
                    retrieval="local_lexical_zh_v1", network_access=False, scope=SCOPE, grants_permissions=False)

    def list_documents(self) -> list[dict]:
        return [deepcopy({key: value for key, value in document.items() if key != "content"})
                for document in self._documents.values()]

    def get_document(self, doc_id: str) -> dict | None:
        if not isinstance(doc_id, str):
            raise TypeError("document id must be a string")
        return deepcopy(self._documents.get(doc_id))

    def _hit(self, identifier: str, score: float, reasons: list[str]) -> dict:
        document = self._documents[identifier]
        fields = ("id", "title", "category", "version", "source_title", "source_ref", "source_kind", "sha256")
        return {**{field: document[field] for field in fields}, "excerpt": document["content"][:200],
                "score": round(score, 3), "match_reasons": list(reasons)}

    def search(self, query: str, limit: int = 5) -> dict:
        _limit(limit, 8)
        if not isinstance(query, str) or len(query) > 512:
            raise ValueError("query must be a string of at most 512 characters")
        normalized = _normalize(query).strip()
        result = dict(query=query, answered=False, answer=None, matches=[], reason="no_reliable_match", version=VERSION)
        if not normalized:
            result["reason"] = "empty_query"
            return result
        if any(term in normalized for term in ("真实客户名单", "工商银行内部制度", "真实银行制度", "银行内部密码",
                                               "密钥是什么", "今天的股价", "今日股价", "贷款利率", "收益率", "天气预报",
                                               "电话号码", "联系电话", "身份证号码", "余额是多少", "审批人是谁", "谁批准")):
            result["reason"] = "out_of_scope"
            return result
        tokens = _tokens(query)
        matches = []
        for identifier, document in self._documents.items():
            phrases = [tag for tag in document["tags"] if _normalize(tag) in normalized]
            overlap = tokens & self._tokens[identifier]
            rare = {token for token in overlap if self._frequency[token] <= 2}
            # Generic shared characters are not sufficient grounds for an answer.
            if not phrases and len(rare) < 2:
                continue
            score = 5 * len(phrases) + sum(math.log(1 + len(self._documents) / self._frequency[token]) for token in overlap)
            if score < 5:
                continue
            reasons = ["匹配词：" + "、".join(phrases[:5])] if phrases else ["正文词组匹配：" + "、".join(sorted(rare)[:5])]
            matches.append(self._hit(identifier, score, reasons))
        matches.sort(key=lambda row: (-row["score"], row["id"]))
        result["matches"] = matches[:limit]
        if result["matches"]:
            result.update(answered=True, reason="matched_project_policy", answer="项目沙盒资料摘录（不构成新的授权）：\n" +
                          "\n".join(f"[{row['id']}] {row['excerpt']}" for row in result["matches"][:2]))
        return result

    def related(self, event: SecurityEvent, analysis: Analysis, limit: int = 4) -> list[dict]:
        _validate(event, analysis)
        _limit(limit, 8)
        selected: dict[str, tuple[float, list[str]]] = {}

        def add(number: int, score: float, reason: str):
            key = f"DF-KB-{number:03d}"
            if key not in selected:
                selected[key] = (score, [reason])
            else:
                old_score, reasons = selected[key]
                selected[key] = (max(old_score, score), [*reasons, reason])

        intent = analysis.intent
        if intent.status == "insufficient_evidence":
            add(1, 90, "当前工单证据不足；检索不能补造批准。")
        elif intent.status == "mismatch":
            add(1, 75, "本事件的工单核验结果为不匹配。")
        elif event.task_id:
            add(1, 35, "本事件具有工单支持，引用授权核验口径。")
        if intent.scope_match < 100 and intent.status != "insufficient_evidence":
            add(2, 85, f"当前范围匹配分为 {intent.scope_match:g}/100。")
        if intent.time_match < 100 and intent.status != "insufficient_evidence":
            add(3, 95, f"当前时间匹配分为 {intent.time_match:g}/100。")
        if any("QUOTA" in rule for rule in analysis.rules):
            add(4, 110, "当前确定性策略记录了工单额度限制。")
        if intent.status == "supported" and event.record_count > 100:
            add(5, 70, "本次批量请求得到工单证据支持。")
        if analysis.anomaly_score >= 60 or "API_FREQUENCY_SPIKE" in analysis.rules:
            add(6, 65, "存在行为异常分或 API 频率线索；异常不单独等于恶意。")
        if "UNRECOGNIZED_DEVICE" in analysis.rules:
            add(7, 85, "当前规则识别了未登记设备。")
        if event.event_type in {"EXPORT", "COMPRESS", "UPLOAD"} or event.parent_object_id:
            add(8, 75, "当前事件涉及对象来源或文件流转。")
        if event.channel == "external":
            add(8, 105, "本事件声明的渠道为外部。")
        if event.event_type == "AI_PROMPT":
            add(9, 100, "当前事件为 AI 提示请求；文本须作为不可信数据核验。")
        if any(rule in {"SEMANTIC_REVIEW_UNAVAILABLE", "SEMANTIC_REVIEW_UNCERTAIN"} for rule in analysis.rules):
            add(10, 115, "本事件记录了语义核验不可用或不确定。")
        if analysis.risk_score >= 60 or analysis.blocked:
            add(11, 40, "本事件存在高风险或阻断决定，需区分证据与执行动作。")
        if "PRESERVE_EVIDENCE" in analysis.actions:
            add(12, 30, "本事件的策略建议包含保留证据。")
        add(13, 5, "事件契约明确属于合成业务沙盒。")
        hits = [self._hit(identifier, score, reasons) for identifier, (score, reasons) in selected.items()]
        return sorted(hits, key=lambda row: (-row["score"], row["id"]))[:limit]


_DEFAULT = KnowledgeBase()


def build_knowledge_context(event: SecurityEvent, analysis: Analysis) -> dict:
    """Static policy excerpts only: never include raw prompts, rows or labels."""
    hits = _DEFAULT.related(event, analysis, limit=4)
    return {"version": VERSION, "scope": SCOPE, "grants_permissions": False,
            "citations": [{key: row[key] for key in ("id", "title", "sha256", "excerpt")} for row in hits]}
