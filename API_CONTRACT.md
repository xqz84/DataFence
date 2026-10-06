# DataFence 共享接口契约：Windows 私有部署版

本契约于2026-09-19按当前 `api.py`、`auth.py`、`deployment.py`、`ingestion.py`、`gateway.py` 核对。此前v0.1“默认无账号认证、进程令牌重启即失效、仅能本机演示”的访问契约已被替代（superseded）；历史实验结果仍按各自当时的配置解释。当前默认真实账号认证，内网模式必须显式配置HTTPS。合成银行、公开业务数据聚合、导入观察、实际网关交付是独立路径。

下文HTTP路径统一省略 `/api` 前缀。开发端由Vite代理，构建后由FastAPI同源提供；JSON UTF-8，时间ISO 8601带时区。一般错误为 `{detail:string}` 或422的 `{detail:[{loc,type,msg}]}`，字段验证不回显输入值；**网关策略拒绝也可能返回完整裁定对象和HTTP 403**，见网关节。空状态返回空列表或null，不补造指标。

## 部署与认证

`Deployment.load` 默认 `network_mode=local`、`auth_mode=required`。推荐启动器 `python -m datafence.server` 强制required，默认绑定127.0.0.1:8765、单进程；LAN需先在本机初始化管理员，配置明确Host、精确HTTPS Origin、TLS证书和私钥。缺少这些条件启动失败，LAN中的HTTP请求拒绝；不信任代理转发头，不提供通配CORS。`local_demo` 仅为显式本机测试兼容模式，LAN禁止，不能解释为默认部署策略。

无需登录的HTTP范围包括登录页静态资源及以下API：`GET /auth/status`、`POST /auth/login`、`POST /auth/bootstrap`、`GET /health/live`。这些仍受部署连接、Host/Origin、跨站和请求体限制；“无需登录”不表示服务可公开部署。其余API（包括 `/openapi.json`、`/health`、`/session` 和SSE）需有效会话，否则401；认证存储不可用时503。

| 接口 | 请求 / 返回与约束 |
| --- | --- |
| `GET /auth/status` | `{authentication_required,initialized,bootstrap_allowed,network_mode}`；`bootstrap_allowed`表示当前连接/网络允许本机初始化，**不保证尚未初始化**，需同时检查initialized |
| `POST /auth/bootstrap` | `{username,password}`；仅local回环且账号库为空时创建首个admin并登录；已有账号409、非本机初始化403 |
| `POST /auth/login` | `{username,password}`；成功200 `{user,token}` 并设置 `df_session`；错误401，频繁尝试429及 `Retry-After` |
| `GET /session` | `{user,token}`；token是当前登录会话的独立写入校验值，不是会话cookie |
| `POST /auth/logout` | JSON `{}`，携带会话及写入校验值；返回 `{logged_out:true}`、撤销当前会话并清cookie；viewer也可调用 |
| `GET /auth/users` | 仅已登录admin；返回 `User[]` |
| `POST /auth/users` | 仅admin；`{username,password,role?:'admin'|'analyst'|'viewer'}`，默认viewer；201返回User；账号重复409，无效422 |
| `POST /auth/users/{username}` | 仅admin；每次只改一个非null字段：`{role}`、`{enabled:boolean}` 或 `{password}`；返回User；试图禁用/降级最后一个可用admin为409，多字段或其他无效输入422 |
| `GET /health/live` | `{status:'ok'}`，只表明进程可响应，不代表数据库、模型或所有功能健康 |

`User={id,username,role,enabled,created_at,updated_at}`，不返回密码哈希。用户名去首尾空白、转小写后匹配 `[a-z0-9][a-z0-9_.-]{2,63}`；创建和改密须15–128字符、UTF-8不超过512字节，密码不去空白或截断。没有默认产品账号或默认密码。

登录会话默认8小时，cookie为HttpOnly、SameSite=Strict、Path=/；LAN额外Secure。会话摘要保存在SQLite，普通服务重启**不会主动撤销仍有效会话**。改密、角色实际变化、启用状态实际变化会撤销该用户已有会话，重新启用不会恢复旧会话；退出只撤销当前会话。离线快照恢复会清除恢复库的旧会话。`local_demo` 的进程能力令牌才沿用重启失效行为。

写请求完整body到齐后重新验证当前会话；网关另在取得执行锁后、检测结束后及保存最终交付裁定前验证，覆盖上传和排队期间的撤销。SSE在读取下一批推送数据前重新验证，失效或认证不可用就结束流。最终交付裁定前的成功校验是该次网关交付的授权点；之后已批准的在途响应不保证能追回，不宣称撤销可收回浏览器已经收到的数据。

除登录/初始化外，API写请求须携带cookie和 `X-DataFence-Token`，通过 `/session` 或登录响应取得；不要记录或持久化浏览器端写入值。所有API写请求要求 `Content-Type: application/json`，否则415；一般请求体最多16KiB，`POST /imports` 的JSON外层最多2MiB，超限413。Pydantic额外字段拒绝。

| 能力 | admin | analyst | viewer |
| --- | --- | --- | --- |
| 读取事件、工单、导入、公开资产聚合、网关摘要、评测 | 是 | 是 | 是 |
| 查看/创建/修改平台账号 | 是 | 否 | 否 |
| 创建演练、离线评测、导入日志 | 是 | 是 | 否 |
| 受控query/export | 是 | 是 | 否 |
| 注销自身会话 | 是 | 是 | 是 |

这是共享平台角色权限：当前没有租户隔离、账号到合成员工的绑定或逐工单ACL；admin/analyst可以选择共享目录中的工单，viewer仍能读取平台安全分析摘要。不得将其描述为已对接银行IAM或实现真实员工的数据对象授权。

## 合成日志导入：观察路径

| 接口 | 契约 |
| --- | --- |
| `GET /import-template` | `{format:'jsonl',source_name:'synthetic-example',content:string}`，由正常合成场景生成，无答案标签 |
| `POST /imports` | `{source_name,format?:'jsonl'|'csv',content}`；format默认jsonl；201返回ImportBatch，幂等重试也返回201但 `replayed=true` |
| `GET /imports` | 最近100个ImportBatch，最新在前，不含观察明细 |
| `GET /imports/{batch_id}?limit=100&offset=0` | ImportBatch加 `observations:Observation[]`；limit为1..200、offset>=0；不存在404 |

`source_name`为1..100字符，只允许字母数字/下划线、空格、点、短横及中文；content实际UTF-8最多1MiB，每批最多2000条（JSONL还限制物理行数）。每条遵循SecurityEvent，须显式 `synthetic:true`；CSV中须小写 `true`，regions列为JSON数组，空的object_id/parent_object_id/prompt/task_id转为null。JSON重复键、CSV列不齐/重复表头/格式错误、额外答案字段、重复event_id、同employee+session时间倒序均422。timestamp必须有时区，employee已登记；非空task_id必须属于该员工。

整批完成解析、员工/工单映射后，在一个事务中保存观察记录；出错不保存合法前缀。相同source_name和规范化事件列表得到相同fingerprint并复用批次；原始content摘要保存在source_sha256。相同来源中复用已有event_id但改变内容整批422。每批新建独立检测器，不跨批次累积历史；不执行动作、不扣演练或网关额度、不调用云、不写入演练事件库。

`ImportBatch={id,source_name,status:'completed',mode:'observe',row_count,alert_count,high_risk_count,executed_actions:0,created_at,actor,source_sha256,fingerprint,model_version,replayed,limitations}`。alert_count为风险>=30，高风险为>=60；不是有标签的准确率。

`Observation={event:SecurityEvent,analysis:Analysis,mode:'observe',actions_executed:false,cloud_called:false}`。analysis中的blocked/actions仅是对导入历史记录的判断建议，不能当作已经拦截发生过的操作。

## 独立公开数据资产

`GET /datasets -> DatasetSummary[]` 只读 `data_dir/public-data/catalog.sqlite3` 聚合目录；未导入返回[]，目录损坏/读取失败503；不存在HTTP下载或导入公开源的写接口。当前登记UCI Bank Marketing，摘要含id/name/status/source_url/download_url/license、origin、synthetic、imported_at、sha256、source_integrity、row_count、column_count、quality、business_target、security_labels_available、used_for_detection_training、llm_access、limitations等。每次读取核对本地源压缩包摘要，状态为imported或integrity_failed；摘要不是发行方签名。

当前UCI有效产物为45,211行、17列，`synthetic=false`，`security_labels_available=false`，`used_for_detection_training=false`，`llm_access=false`；未提供个人行接口。它不混入合成customers、业务事件或模型输入，营销y不是攻击标签。CERT研究归档因许可条款待澄清、r1标签不匹配而不登记为已通过的检测基准，详见PUBLIC_DATA.md、CERT_DATA.md。

## 受控合成数据网关：实际交付路径

`GET /access/tasks` 返回 `BusinessTask[]` 每项附加 `quota` 聚合；quota字段为task_id/employee_id/scope/metric/limit/reserved_records/confirmed_records/used_records/remaining_records。**网关副本的quota_scope一律task_lifetime**，不会改写普通演练工单。`GET /access/operations` 返回最近100次持久操作摘要，不含customer_ids、内部events、rows、csv或临时replayed字段。`GET /access/verify` 返回 `{valid,checked_operations}`，只校验网关独立证据链。

`POST /access/execute` 仅admin/analyst可用，请求为：

```json
{"request_id":"bca23fd3-65c2-4c19-871d-b9706442ced1","task_id":"已登记工单ID","operation":"query","record_count":5,"regions":["工单允许的区域"]}
```

request_id为UUID；task_id为1..40字符；operation=query/export（默认query）；record_count为1..5000；regions须1..32项。客户端不能传SQL、目标URL、员工身份、时间、敏感度、设备或模型文本。服务器从工单推导合成员工与目的，使用当前真实时间（业务时段UTC+8）、已登记设备、customers资源、internal通道和敏感度85构造检测事件。

每次query对应一次读取，export对应新的读取和该读取结果的EXPORT；两者都按新申请record_count扣一次生命周期读取额度。工单有效期、允许小时/区域、导出权限、检测阻断、该操作员+工单的持久冻结状态及额度须在返回数据前满足。额度桶按task+employee共享，跨浏览器、操作员和重启累积；额度不是去重客户数，也不是实际返回行数。同一工单不足所申请数量的实际匹配客户时，可能返回较少行，申请额度仍完整计量。

已持久裁定响应为：

```text
{request_id,actor,task_id,operation,allowed,delivered_records,requested_records,
 synthetic:true,created_at,analysis:Analysis,quota:QuotaDecision,
 previous_hash,evidence_hash,cloud_called:false,policy_version:'synthetic-access-gateway-v1',
 replayed,rows:Customer[],csv?:string}
```

Customer字段为 `{id,name,contact,identity_ref,region,employee_id,synthetic:true}`。只有allowed=true的export带csv，CSV列顺序同上述字段并转义公式起始字符。获准HTTP 200；已记录的策略拒绝HTTP 403、allowed=false、delivered_records=0、rows=[]、无csv。角色等更早拒绝为 `{detail}` 403，同样不提供客户行。当前CSV由前端下载到已登录浏览器，不支持服务端任意路径写文件或外网传输；网关从不调用云模型。

幂等按已登录actor身份+request_id限定：同键同请求重放原裁定和记录，不再扣额度；同键改参数409 `idempotency_conflict`。重放获准结果前仍复核当前工单授权、持久冻结及整个网关链；过期/权限变化、冻结、证据损坏会403，不交付旧缓存数据。每actor+task最多500条持久操作，达到上限409 `task_operation_limit`。发现稳定事件ID已有额度记录却缺交付回执时409 `unresolved_reservation`，保守保留额度，不自动退款或再次交付。

新请求和重放都先校验现有网关证据链，损坏时403 `invalid_evidence`，不追加交付记录或新增额度。工单时钟在取得网关及SQLite锁后取值，检测结束及最终交付裁定前还会复核，不能把进入队列时的授权当成有效期租约。

网关额度和交付审计分属两个SQLite库，不是跨库原子事务。正常路径先保留/确认额度，再完成最终会话及工单复核，并成功写交付审计后才向浏览器组装rows/csv。若最终复核拒绝，交付事务回滚，不留下allowed=true或非零delivered_records的记录；已确认额度保守保留，后续按缺回执的未决情况处理，不自动退款。崩溃或审计写失败也可能留下同类状态。持久allowed/delivered_records描述获准交付的合成行，不是客户端接收确认；网络断开不能从审计证明浏览器已收到。重复GET摘要或校验不发起新交付。

## 后端内部边界

模型由 `backend/datafence/models.py` 定义。检测核心只导入这些纯净契约，不导入 evaluation 或读取标签。

- `sandbox.py`: `build_bank(seed=42, customer_count=5000) -> dict`，返回 `employees: list[Employee]`, `tasks: list[BusinessTask]`, `customers`, `accounts`, `transactions`, `loans`（后四项为合成记录列表），`manifest: dict`。至少 100 员工，包含 E0038；客户编号/账号需显著合成，不生成真实可用联系方式。
- `scenarios.py`: `SCENARIOS: list[dict]`，至少含 id/name/description/steps；固定六攻击场景与 normal/approved_batch 两正常对照。`generate_scenario(request: SimulationRequest, employees: list[Employee], tasks: list[BusinessTask]) -> tuple[list[SecurityEvent], list[dict]]`。后者是独立标签，字段 event_id/session_id/ground_truth/attack_type；登录等前缀可根据定义标 NORMAL，标签定义须文档化。不得把标签加入事件。
- `engine.py`: `DetectionEngine(employees, tasks, mode='full', behavior_model=None)`；`analyze(event: SecurityEvent) -> Analysis`，有独立会话状态；`reset()`、`commit_analysis(event, analysis)`、`model_info: dict`。支持mode='rules'/'behavior'/'full'用于消融；可从本地校验后的模型产物加载行为模型，最终以model_info为准。只分析当前已观察前缀，不读取评测标签、不调用云或执行沙盒动作。
- 检测核心只输出动作建议。service.py 编排、执行沙盒动作并持久化。冻结后后续计划步骤不执行，runs记录未执行数。被阻断的导出无法产生后续压缩对象。演练外部上传只写本地模拟接收账本，不发网络请求。
- `evaluation.py`: `run_evaluation(seed: int, sessions: int, output_dir: pathlib.Path) -> dict`，自行独立生成测试事件与标签，调用 detector，用固定训练基线，保存 events.jsonl/labels.jsonl/predictions.jsonl/report.json。返回下面评测对象。应用负责存储返回报告与异步作业状态。

## 演练、评测与展示接口

- 本节同样遵循上方账号及角色约束；`POST /runs` 可带 `Idempotency-Key` 防止重复执行，同键不同参数409，最多同时3个演练；评测最多同时1个。
- `GET /audit/verify`: `{valid,checked_events,broken_event}`，校验事件链与绑定的模拟接收回执摘要。
- `GET /runs/{id}/receipts`: `[{event_id,channel,record_count,received_at,synthetic:true}]`，真实本地模拟接收记录的摘要。
- `GET /health`: `{status:'ok',version,synthetic:true,llm:{...},model:{...},deployment:{network_mode,authentication}}`；llm来自实际配置，不固定为false。synthetic标识业务沙盒，不代表独立公开资产都是合成数据。
- `GET /overview`: `{total_events,abnormal_events,high_risk_events,blocked_events,sensitive_records,active_runs,risk_distribution:{LOW,MEDIUM,HIGH,CRITICAL},recent_events:EventRecord[],top_users:[{employee_id,name,risk_score,event_count}],trend:[{hour,events,risk}],bank:{employees,tasks,customers,accounts,transactions,loans},synthetic:true}`。事件统计按detected_at的UTC+8当日、从最多最新1,000,000条演练持久事件中筛选；不合并导入观察或网关操作。sensitive_records是敏感事件申请记录数之和，不去重或代表实际外泄。bank在服务启动时从持久库COUNT一次后缓存（该实体集合生命周期内不变），不是占位数；trend为空时显示空状态。
- `GET /employees`: `Employee[]`。Employee 字段见 Python 契约。
- `GET /employees/{id}`: `{employee:Employee,tasks:BusinessTask[],events:EventRecord[],baseline:{daily_records,daily_queries},current:{records,queries,regions,exports},latest_intent:IntentResult|null}`。
  `events`仅展示最近500条；`current`独立统计上海时间今日全部处理记录，不受该展示上限影响。records/queries包含被阻断的QUERY/API请求，exports统计EXPORT，不能解释为成功交付量。
- `GET /scenarios`: `[{id,name,description,steps:string[]}]`。
- `POST /runs`（202）: 请求 SimulationRequest，返回 Run；运行在后台执行。`GET /runs`: `Run[]`（最近30次）。`GET /runs/{id}`: `Run`。
- `GET /events?run_id=&limit=100&offset=0`: `EventRecord[]`，最新在前（limit 1..500）。`GET /events/{event_id}`: `EventRecord`。
- `GET /runs/{id}/stream`: SSE，`event: update`，`data: {run:Run,events:EventRecord[]}`；前端也可轮询每秒更新。
- `GET /evaluations`: 评测摘要数组；`GET /evaluations/latest`: `EvaluationReport|null`；`POST /evaluations`（202）请求 `{seed,sessions}` 返回 `{id,status:'running'}`；`GET /evaluations/{id}`: `{id,status:'running'|'completed'|'failed'|'interrupted',report:EvaluationReport|null,error:string|null}`。
- `GET /assets`: `{manifest:dict,assets:[{name,label,count,sensitivity,synthetic:true}]}`。
- `GET /agents`: `[{id,name,status,description,implementation}]`。AI 未配置时必须如实显示；规则能力不能假称 LLM 已调用。
- `GET /policies`: `{version,weights:{D,B,I,P,C},levels:[{name,min,max,actions}],llm_enabled:boolean}`；llm_enabled取实际配置，levels是策略描述，不能替代每事件最终裁定和执行结果。

### Run

`{id,scenario_id,employee_id,status:'running'|'completed'|'failed'|'interrupted',created_at,finished_at:null|string,planned_events,processed_events,blocked_events,skipped_events,sink_records,max_risk,error:null|string}`

### EventRecord

`{event:SecurityEvent,analysis:Analysis,run_id,outcome:'executed'|'blocked',received_at,detected_at,responded_at,executed_records,evidence_hash,previous_hash,receipt_hash}`。

Analysis 使用 Python 契约。chain 节点至少 `{event_id,event_type,timestamp,risk_score,blocked}`；额外字段可有。chain 是当前已处理前缀，不是未来剧本。

### EvaluationReport

`{id,created_at,seed,sessions,event_count,attack_events,normal_events,metrics:{precision,recall,f1,fpr,tp,fp,tn,fn},latency:{processing_ms_p50,processing_ms_p95,detection_delay_seconds_p50,missed_sessions},per_scenario:[{scenario_id,sessions,detected,recall}],ablations:[{mode,precision,recall,f1,fpr}],artifacts:{...},limitations:string[],versions:dict}`。比例均为0..1，零分母用 null。其他指标可追加但不能伪造；latency 必须注明合成事件时间与本地处理耗时之别。

Ground Truth 不通过上述业务接口暴露。API 作业 id 与检测 event/session id 分离，检测不接收 scenario_id 或 run_id。

## 可选模型与执行前语义核验

EventRecord 可含 `ai_analysis:{status,summary,evidence_event_ids,suggested_actions,elapsed_ms,model}`。
status 为 not_configured/skipped/completed/unavailable/invalid_response。Ollama 保留已有风险>=60才附加解释的模式。商汤同样提供只读解释，每次演练最多两次附加分析；另有执行前涉敏 AI 语义核验，不受旧风险阈值限制。旧记录无该字段，不得推断模型调用成功。

`GET /health` 响应的llm字段来自实际服务配置，包含 enabled/status/model；商汤另有 provider、last_call（status/reason_code/elapsed_ms/at）和 budget（date/requests/request_limit/charged_tokens/reserved_tokens/token_limit）。date 为 UTC 日期；已计量和保守预留 token 分开，均不是供应商账户余额。configured 只表示配置存在，事件级 completed 才表示该次分析成功。密钥及密钥路径不通过 API 暴露。

`request_policy` 给出当前服务的 max_output_tokens、temperature、network_deadline_seconds、auto_retries；历史实验必须读取各自报告，不能套用当前参数。last_call 仅表示当前服务进程最近一次调用，独立评测脚本调用不会写入该内存状态；budget 是共享持久账本。budget.status 不可用时停止新云调用。

商汤分析额外包含 provider、reason_code、usage、provider_request_id、response_sha256。只保存校验后的结构化返回，不保存供应商隐藏推理过程或原始错误正文。usage 可为 null，失败调用的未知消耗保守预留，不作零消耗处理。

EventRecord 的 `semantic_analysis` 为 null 或执行前结果。完成时包含 verdict（safe/unsafe/uncertain）、interpretation（execute/negated/quoted/summary/unknown）、evidence_quote 和 reason。策略复验原文引用，unsafe+execute 由本地策略加 BLOCK_AI_PROMPT；safe 仅能解除满足严格独立条件的单关键词误阻断，不能覆盖工单、身份或数据通道约束。不可用/不确定会暂缓该涉敏 AI 请求，但不因此增加恶意风险或冻结会话。模型不直接执行任何动作。

当 `ai_analysis.reused_semantic=true`，附加解释复用同一次语义调用，usage 不重复累加。模型 suggested_actions 不能作为实际响应动作展示。

新记录的 execution_completed_at/responded_at 为本地执行器返回时间，ai_completed_at 为附加解释完成时间，persisted_at 为事件与回执进入写事务时的时间。语义门等待计入 detected_at 之前；事后解释等待不计入执行器完成耗时。旧记录按其历史时间口径读取，不改写已保存的哈希链。

## 持久额度与运行阶段

BusinessTask的quota_scope为session（默认兼容）或task_lifetime。演练计量为成功获准QUERY/API的申请record_count；导出、压缩和上传不重复扣减，也不是去重客户或实际返回行数。演练跨会话范围必须显式选择，不追溯重定义旧工单；网关则按前述独立契约强制生命周期范围，并为每次query/export计入新的读取申请。

QuotaDecision字段为allowed/applicable/status/reservation_id/already_seen/event_id/task_id/employee_id/scope/metric/requested_records/limit/reserved_records/confirmed_records/used_records/remaining_records/reason。status为reserved/confirmed/cancelled/rejected/not_applicable；metric为accepted_request_records。EventRecord可有quota_decision，网关响应使用quota字段。used_records包含reserved+confirmed；not_applicable的限额和计数为null，不能展示为零。超限由确定性策略执行BLOCK_READ。员工详情可含演练账本的lifetime_quotas；会话额度按事件快照查看，网关当前额度从access/tasks读取。

Run 可有 phase、phase_started_at、current_event_type，phase 为 queued/detecting/semantic_review/model_explanation/completed/failed。semantic_review 是操作前等待，model_explanation 是执行器返回后的附加解释等待；阶段本身不是阻断成功证据。

## 已存档云模型诊断

`GET /model-experiments` 只读返回最近十份已保存商汤实验的聚合信息，不发起模型请求。每项包含 id、created_at、protocol、status、model、provider、kind=development_diagnostic、artifact_digests_valid、summary 和 limitations。summary 包含计划/尝试/有效核验数量、状态分布、基线与最终分类指标、请求控制混淆矩阵、已报告/未知 token 用量及实测核验耗时。该接口不返回样例、答案标签、密钥或供应商原始正文。

artifact_digests_valid 只说明四份数据产物与报告保存的 SHA-256 一致，不是数字签名或指标独立复算。前端在摘要不一致时标为不可采信并隐藏指标。评测页面分别解释风险分类与请求暂缓，调用失败的保守暂缓不能计作语义识别正确；当前 AI_PROMPT 沙盒不生成下游模型输出。

## 知识、事件工作台和持久人工闭环

- `GET /knowledge/status`：版本、16条知识数量、SHA-256、检索方法、`network_access:false,scope:project_sandbox_policy,grants_permissions:false`。
- `GET /knowledge/documents`、`GET /knowledge/documents/{id}`：目录与原文。`GET /knowledge/search?q=&limit=5`（q最长300，limit1..8）返回`query,answered,answer,matches,reason,version`，无依据时answer为null。
- `GET /agents/workbench?event_id=`：选定事件所属演练最多500条，未指定时最近100条；返回六模块的实际贡献、事件编号、引用知识和模型状态计数。仅统计当前提供窗口，不能称为全系统累计调用量。
- `GET /events/{id}/review`：`{event_id,revision,current,history}`，空记录revision=0。`POST`同路径接收`request_id:UUID,expected_revision:int>=0,disposition:confirmed_risk|false_positive|needs_investigation,note:1..1000`；冲突409，追加历史不覆盖原判，写入权限为管理员或分析员。
- `GET /reviews/verify`：`valid,checked_reviews`，检查研判链和所绑定原事件摘要。
- `POST /demos`（202）：`request_id:UUID,employee_id`（默认E0038）；同操作者同UUID幂等，内容冲突409。原子创建演示与三个真实运行；已有运行时409。模式local，不调用模型。
- `GET /demos`最近30条，`GET /demos/{id}`单条。Demo含状态`running|awaiting_review|completed|failed|interrupted`、操作者、三个步骤与run_id、实际计数、自动checks、selected_event_id、audit、review_revision、错误。首个失败停止后续，不补造证据；重启不重跑。
- `POST /demos/{id}/confirm`：`review_revision:int>=1`，要求全部自动检查通过、最新人工结论非待调查、事件与研判链复验有效。确认不改变风险和权限。

以上接口均沿用登录、角色、CSRF、JSON与体积限制。知识搜索只读，不调用云；Demo与Review保存在既有datafence.sqlite3并随离线快照备份。

## 双工作空间与统一观察队列（2026-09-28）

账号增加 `business` 角色和公开字段 `employee_id:null|string`。创建业务账号必须绑定现有合成员工。管理员修改绑定撤销该账号会话；从其他角色转为业务角色需先完成绑定。业务会话只可 GET session、access/tasks、access/operations及其单条元数据，并 POST access/execute、auth/logout；其余安全/管理接口返回403。工单范围按绑定员工控制，历史按账号ID与当前绑定工单共同过滤。网关进入事务与交付前复验当前会话和绑定。

- `GET /access/operations/{request_id}`：与列表相同范围的历史元数据，不返回客户行、客户ID或CSV；查无记录404，管理员遇到跨账号同UUID歧义409。
- `GET /observations`：参数 `source=all|gateway|simulation|import`、`status=all|pending|investigating|resolved`、`decision=all|allowed|blocked|observed`、`risk=all|high`、`attention_only:boolean=false`、`q`（最多100字）、`limit=1..100`、`offset>=0`。返回 `items,total,limit,offset,counts`。所有筛选在数据库完整历史上执行；counts也包含status等当前筛选，并非全局指标。需关注条件为阻断或风险分≥30，高风险条件为≥60。
- 观察项有稳定 `key`（simulation:事件ID、gateway:交付序号、import:批次ID:位置）、来源、工单/员工、风险、请求与实际交付数、人工状态和版本。导入 decision 固定 observed、交付为0，`recommended_blocked` 仅为检测建议。列表不包含原始客户行。
- `GET /observations/{key}`：增加 event、analysis、record、events、evidence、review、related_knowledge。导入 evidence 是内容摘要快照，不能称为经过外部认证的执行链；业务与演练保留原链。
- `GET/POST /observations/{key}/review`：请求和返回沿用原事件研判契约；simulation 与旧入口共享同一历史。业务/导入保存独立追加研判链，绑定来源摘要和知识快照。版本冲突、幂等内容冲突、证据/历史失效409。登录和来源在事务入口、最终写入前复验。
- `GET /reviews/verify`：合并检查旧事件研判与新业务/导入研判，仍返回 `valid,checked_reviews`。本地摘要是完整性检查，不是外部签名或不可篡改承诺。
