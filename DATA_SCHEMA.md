# 数据与事件契约

代码中的权威定义为 `backend/datafence/models.py`，HTTP 约定见 `API_CONTRACT.md`。

## 合成实体

默认规模为100员工、50000客户、80000账户、200000交易、6250贷款、200业务工单；实际值取 manifest 和 SQLite 计数，测试采用较小规模。客户、账户、身份与交易标识均带 SYN 前缀；联系地址使用 example.invalid，不生成可用身份证、手机号或银行卡号。所有实体具有 synthetic=true。

账户引用 customer_id，交易引用 account_id，贷款引用 customer_id；每位员工有普通客户服务工单和批量对账工单。工单包括员工、业务目的、有效日期、区域、数量、时间段、允许渠道及导出授权。当前普通工单以区域和数量约束范围，尚无精确客户集合授权。

## 检测事件

event_id/session_id、employee_id、带时区 timestamp、event_type、task_id、purpose、resource、record_count、regions、device_id、sensitivity、channel、object_id、parent_object_id、prompt 和 synthetic。未知字段直接拒绝。

操作种类为 LOGIN/QUERY/EXPORT/COMPRESS/API/UPLOAD/AI_PROMPT。渠道只能为 internal/approved_partner/external/internal_ai；external 是模拟业务属性，不是可访问的 URL。

数据对象表示当前请求关联的合成记录集合，parent_object_id 表示导出/压缩/上传来源；实际防护链只展示已处理前缀。标签、attack_type、scenario_id 和 run_id 不属于检测契约。run_id 仅在控制面与结果存储关联。

## 结果与时间

Analysis 含五维分数、风险等级、IntentResult、命中规则、异常分数、解释、建议动作、blocked 和关联链。事件记录再附执行结果、实际接收/检测/响应时间以及前序哈希、当前哈希。

record_count 表示事件访问记录规模，不等于去重客户数；首页涉及记录量会跨操作累计。模拟接收账本保存实际收到的合成客户 ID 列表，便于证明阻断对结果产生影响。计数与去重人数不可混称。

独立标签文件只供 Evaluation 使用。当前模块边界保障标签不进入检测，但同系统账号仍能访问本地标签文件；强制权限隔离是后续独立验收项。
