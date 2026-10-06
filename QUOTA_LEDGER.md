# DataFence 合成工单额度账本

`backend/datafence/quota.py` 提供持久化、并发安全的额度预留与确认。它补足跨会话工单额度约束，但不替代角色、目的、时间、渠道或敏感数据检测。全部数据和演示工单仍为合成数据。

## 明确的计量口径

字段 `BusinessTask.quota_scope` 默认是 `session`，保持现有工单以会话为范围的口径；只有显式设为 `task_lifetime` 的工单才跨会话、跨重启共享额度。没有把既有的所有审批工单静默改为总生命周期额度。

| 配置 | 额度桶 |
| --- | --- |
| `session` | 工单 ID + 员工 ID + 会话 ID |
| `task_lifetime` | 工单 ID + 员工 ID，覆盖所有会话 |

指标固定为 `accepted_request_records`：成功获准的 `QUERY` / `API` 请求所声明的 `record_count`。即使实际返回的合成客户较少，或不同请求重复访问同一客户，仍按获准请求量计数；它**不是实际返回行数、去重客户数或外泄量**。`EXPORT`、`COMPRESS`、`UPLOAD`、`LOGIN` 与 `AI_PROMPT` 不重复消费读取额度。

`used_records = reserved_records + confirmed_records`，未确认的预留也占用额度，以阻止并发超额。没有可核验工单时返回 `not_applicable`，不补造额度授权；调用方仍需使用确定性检测结果决定是否允许该事件。

## 接入接口

```python
ledger = QuotaLedger(runtime_directory / "quota.sqlite3")
decision = ledger.reserve(event, business_task, blocked=final_analysis.blocked)
```

返回字段：`allowed`、`applicable`、`status`、`reservation_id`（事件 ID）、`already_seen`、`event_id`、`task_id`、`employee_id`、`scope`、`metric`、`requested_records`、`limit`、`reserved_records`、`confirmed_records`、`used_records`、`remaining_records`、`reason`。

- `status=reserved`：已在 SQLite 内原子预留，可以执行一次相应读取。
- `status=confirmed`：该事件已被确认。重试不会重复扣额，调用方也不得据此再次执行业务。
- `status=cancelled`：预留已明确撤回，同一事件 ID 不再重新授予额度。
- `status=rejected`：额度超限，调用方必须阻断本次读取；拒绝本身不占用额度。
- `status=not_applicable`：不是读取、缺少可核验工单，或已被策略阻断。需要同时检查 `allowed` 和 `reason`，不能把“不适用”当作业务授权。

没有可应用额度时，`scope`、额度及用量字段为 `None`，前端应显示“未适用”，而非填入零。

执行成功后调用 `ledger.confirm(event.event_id)`；在确定读取未成功执行时，用 `ledger.cancel(event.event_id, reason="execution_failed")` 撤回预留。`confirm` 和 `cancel` 对各自终态幂等；已确认的用量禁止撤回。如果只是后续审计写入失败，不能把已经成功执行的读取当成失败并退还额度。

`ledger.summary(task, employee_id, session_id="")` 返回当前范围的额度、预留、确认与剩余额度。`session` 范围必须提供会话 ID，`task_lifetime` 不需要。一个工单只能由其绑定员工使用；`event_id` 重试时会核对完整请求及额度政策指纹，改变请求量、会话或策略再复用旧 ID 会被拒绝。

## 事务与故障语义

SQLite `BEGIN IMMEDIATE` 将“读取当前占用、核对上限、写入预留”放在同一事务中，独立连接并发也不能共同占用超出额度的容量。事件 ID 有唯一约束，SQL 值均参数化。`reserved`、`confirmed`、`cancelled`、`rejected` 保留持久记录，便于解释拒绝与撤回。

断电后未确认的 `reserved` **不会自动过期或释放**。如果读取已执行但进程在确认前退出，自动释放可能造成超用，因此重启时保守保留。`already_seen=True` 且 `reserved` 代表未决记录，调用方不能自动假定“上次没有执行”并重复读取。需要人工核查后显式确认或撤回。当前没有自动恢复推断或管理页面。

额度账本与业务事件审计可能位于不同 SQLite 文件，不构成分布式原子事务。建议调用顺序：

1. 完成确定性及语义门的最终裁定。
2. 对未被阻断的读取原子预留额度；拒绝则不执行。
3. 执行业务沙盒读取，成功后确认预留。
4. 将最终决策、实际读取量、额度结果及证据写入事件审计。

失败恢复优先防止额度超用；跨库提交窗口可能产生保守多占，需要留证后处理。更改工单的 scope 会改变额度桶，不能作为重置已消费额度的便捷方式；应用当前没有开放任意工单修改接口。

## 实际验证

已运行：

```powershell
.venv\Scripts\python.exe -m pytest tests/test_quota.py -q
.venv\Scripts\python.exe -m datafence.quota --demo-database runtime/quota-demo.sqlite3
```

额度专项测试 **13 passed in 0.85s**，覆盖跨会话/重启、默认会话范围、策略阻断不消费、导出不重复消费、确认/撤回幂等、事件 ID 冲突、员工与工单隔离、断电预留保留以及真实并发连接。并发测试使用 10 个独立连接，每个请求 3 条、上限 10 条，只有 3 个请求预留成功，最终占用 9 条。

独立演示为每次运行创建 `QUOTA-DEMO-...` 合成工单，不修改应用已有工单：生命周期额度 12 条，第一个会话请求 8 条并确认，第二个会话再请求 8 条被拒绝；最终已确认 8 条、剩余 4 条。演示数据库持久保留在指定本地文件。此结果验证账本，不冒称银行生产限流系统或实际客户级配额。
