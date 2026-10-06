# 本机与内网账号、会话和角色

账号模块为 Windows 本机或受控内网部署提供真实身份认证。业务检测仍使用公开研究数据或合成银行数据，不代表银行生产部署。此模块不创建默认账号、不提供默认密码、不自动登录，也不读取商汤密钥。身份库与业务库分开，默认位置由启动/API 配置选择；CLI 默认为 `runtime/auth.sqlite3`。

## 初始化与本地管理

先停止服务和备份/恢复任务，再在项目根目录的交互终端运行：

```powershell
.venv\Scripts\python.exe scripts\manage_users.py create administrator --role admin
.venv\Scripts\python.exe scripts\manage_users.py create analyst01 --role analyst
.venv\Scripts\python.exe scripts\manage_users.py create observer01 --role viewer
.venv\Scripts\python.exe scripts\manage_users.py create operator01 --role business --employee-id E0038
.venv\Scripts\python.exe scripts\manage_users.py list
.venv\Scripts\python.exe scripts\manage_users.py passwd analyst01
.venv\Scripts\python.exe scripts\manage_users.py disable analyst01
.venv\Scripts\python.exe scripts\manage_users.py enable analyst01
.venv\Scripts\python.exe scripts\manage_users.py role observer01 analyst
.venv\Scripts\python.exe scripts\manage_users.py bind operator01 E0039
```

需要独立部署目录时，在子命令前指定 `--database C:\DataFence\auth.sqlite3`。密码由 `getpass` 隐藏输入两次，不接受命令行参数、环境变量或非交互标准输入，防止密码留在命令历史和进程参数中。CLI 操作者已经具有本机身份库写入权限，属于可信管理员；API 必须另行校验调用者角色。

CLI 所有操作（包括只读列表）持有身份库所在目录的 `RuntimeLock`，与服务及离线快照互斥，避免维护快照期间并发写入。服务运行时的账号管理应使用管理员 API；不要绕过文件锁直接运行 SQLite 写入命令。

CLI 绑定必须在身份库同目录存在有效的合成业务库 `datafence.sqlite3`，并能查到所指定员工；缺库、未知员工或数据损坏会拒绝，不为创建账号生成业务数据。已有 viewer/analyst 转业务角色时，先 `bind 用户 E0038`，再 `role 用户 business`。修改绑定撤销旧会话，需要重新登录。

首个账号必须是 `admin`。用户名为 3–64 位 ASCII 字母、数字、点、下划线或连字符，首字符为字母或数字；首尾空白会去除，大小写归一。密码为 15–128 个字符、UTF-8 最多 512 字节，保留空白和 Unicode，不截断，不要求特定字符组合。请使用独立的长口令；当前没有泄露口令库检查或 MFA。

未登录的首账号初始化接口应调用 `create_user(..., require_uninitialized=True)`，在创建事务内部拒绝已经初始化的数据库；不能只在创建前单独查询 `initialized()`，否则与另一进程初始化之间存在竞争窗口。

## 持久化与会话

- 密码使用 Python `hashlib.scrypt`，`N=32768,r=8,p=3`，每次随机 16 字节 salt、64 字节输出、64 MiB 内存上限。该组合来自 [OWASP Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#scrypt) 的推荐配置；具体计算约占 32 MiB。反序列化只接受固定参数格式，数据库内容不能任意增大工作因子或降级算法。实现使用 [Python 标准库 scrypt](https://docs.python.org/3.12/library/hashlib.html#hashlib.scrypt)，不是通用 SHA256 密码存储。
- 每次登录生成独立的 256 位随机会话 token。SQLite 只保存其 SHA256 摘要，不保存可直接拿去登录的原 token。默认固定 8 小时到期，不随读取延长；重启不延长或重置会话。
- 每个会话的 CSRF token 由原会话 token 通过带固定用途标记的 HMAC-SHA256 派生。读取会话时可以重新计算，因此不需要把原 token 存入数据库；CSRF 值不能用作登录 cookie。校验使用常量时间比较并检查会话仍有效。
- 登出撤销当前会话；改密、禁用和角色变化撤销该账号所有会话。重新启用不会恢复旧会话。登录在密码计算后再次用事务检查账号版本，防止并发禁用/改密后签发旧权限会话。
- 禁用或降级最后一个启用管理员会失败，两个管理员并发互相禁用/降级也不能让启用管理员数量降为零。相关判断与更新在同一个 `BEGIN IMMEDIATE` 事务中。

这些设计对应 [OWASP Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) 的随机会话、到期和撤销原则。模块不依靠浏览器自己删除 cookie 来实现到期。

## 登录限速与并发边界

SQLite 保存登录预留、失败和成功状态，限速跨重启、跨 `AuthStore` 实例生效：同一规范化用户名在滚动 5 分钟窗口内最多 5 个失败/待验证尝试；同一来源 IP 最多 30 次全部登录尝试。成功登录释放用户名失败计数中的本次预留，但仍计入 IP 桶。IPv4 与对应 IPv4-mapped IPv6 使用同一桶。

预留先于耗时密码验证并在事务中完成，避免并发请求都看到空余名额。进程异常留下的待验证项保守占用到窗口结束。限速返回 `rate_limited` 和 `retry_after` 秒，不告诉调用者账号是否存在。未知、错误、禁用账号统一返回 `invalid_credentials`，并执行同工作因子的密码计算以缩小明显的账号存在性时差；不承诺绝对恒定的整请求耗时。每个 Python 进程至多同时执行 4 个 scrypt，多个服务进程仍需部署侧资源限制。

API 必须使用实际连接来源 IP；未经明确代理信任配置，不得直接接受 `X-Forwarded-For` 作为限速键。高并发或公网部署还需要边缘限流及连接限制，当前目标为 Windows 本机/受控内网。[OWASP Authentication](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html) 是限速、通用错误和长口令的参考依据。

## API 接入契约

`AuthStore(path, session_ttl_seconds=28800)` 不依赖 FastAPI，提供：

| 方法 | 返回与作用 |
|---|---|
| `initialized()` | `bool`，只执行 `EXISTS`；不列出账号 |
| `create_user(username,password,role="viewer")` | 新建并返回公开用户字段 |
| `list_users()` | 公开用户字段列表 |
| `login(username,password,client_ip)` | `{token,csrf_token,user,expires_at,expires_unix}` |
| `authenticate(token)` | `{csrf_token,user,expires_at,expires_unix}` 或 `None` |
| `verify_csrf(token,csrf_token)` | 有效会话和 CSRF 是否匹配 |
| `logout(token)` | 幂等撤销；不返回 token |
| `set_enabled(username,enabled)` | 禁用/启用并返回用户 |
| `set_password(username,password)` | 改密并撤销全部会话 |
| `set_role(username,role)` | 改角色并撤销全部会话 |
| `set_employee_id(username,employee_id)` | 更改员工绑定并撤销全部会话 |

公开用户仅包含 `id,username,role,enabled,created_at,updated_at,employee_id`。`create_user` 额外接受关键词参数 `employee_id`，业务角色必须绑定合成员工。`AuthError.code` 为固定错误码；登录错误不得把密码、token、底层异常内容放入日志或响应。数据库操作异常应由 API 映射为通用服务不可用，不能放行访问。

2026-09-28 增加独立业务角色：绑定员工限定可选工单，历史同时限定当前账号与绑定员工，写入网关时复验当前会话及绑定。业务账号不允许读取安全队列、其他员工、云模型配置摘要或管理页面对应接口。admin/analyst 可切换双空间，viewer 只读安全空间。旧身份库在单一事务扩展角色约束，保留用户ID、密码摘要、认证版本和会话外键；迁移失败回滚，不重置用户口令。

API 将登录结果里的 `token` 放入 `df_session` cookie，不得原样序列化整个登录返回值。cookie 应使用 `HttpOnly`、`SameSite=Strict`、`Path=/`；内网访问必须使用 TLS 并设置 `Secure`，仅明确的本机 HTTP 开发模式可以关闭 `Secure`。登录页/初始化状态可公开，业务读取仍须认证。写操作同时要求有效会话、允许的角色、同源校验和对应 CSRF 头。角色字段只表示身份，实际路由的 `admin/analyst/viewer` 权限必须由 API 执行；本模块没有隐式 localhost 豁免。

当前没有 SSO、MFA、密码找回邮件、管理员操作二次认证、跨站账号联合或公网抗机器人能力。Windows 文件 ACL、SQLite/备份访问权限和内网 TLS 由部署层负责；拥有身份库写入权限的本机用户能够改变账户数据，不属于本模块可隔离的攻击者。

## 已完成验证

2026-09-19 运行 `.venv\Scripts\python.exe -m pytest tests/test_auth.py tests/test_auth_api.py -q`：**63 passed**，耗时 39.84 秒，另有 2 条第三方库弃用提示。验证使用独立临时数据库与虚构口令，没有访问当前运行库、真实账号或云服务。

覆盖真实 scrypt 与随机盐、原密码/token 不落库、固定到期、会话与 CSRF 隔离、登出和账号状态撤销、并发管理员保护、并发限速与重启持久性、验证途中改密/禁用/降权、首账号原子创建、CLI 服务目录互斥；HTTP 测试还覆盖匿名拒绝、cookie 属性、管理员/分析员/只读权限、CSRF、LAN HTTPS 与明确 Host/Origin、伪转发头不能绕过、认证数据库故障拒绝访问。这是限定实现的自动化验证，不是完整渗透测试或生产认证。
