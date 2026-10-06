# Windows 本机与内网部署

本版本提供真实账号、私有服务、持久数据、合成资产的受控查询/CSV交付、独立日志观察和可校验恢复。业务数据仍是合成银行；公开 UCI 业务数据单独列示。内网可运行不表示已对接真实银行 IAM、数据库代理或终端防泄漏。

## 安装与首次登录

发布包包含构建后的前端和已经验证的 `iforest-v2`，不包含账号、商汤密钥、运行记录或 CERT 数据。Windows 安装 Python 3.12+ 后，在解压目录执行：

```powershell
.\scripts\setup-private.ps1 -Python 'C:\Python312\python.exe'
.\scripts\start-private.ps1
```

Python 路径按实际安装位置调整。首次安装需要下载锁定的依赖；启动后浏览器访问 `http://127.0.0.1:8765`。首次页面仅在本机允许创建管理员，密码15–128字符。无内置账号、默认密码或匿名业务访问。管理员随后在“系统管理”创建分析员或只读账号。修改密码、角色或禁用账号会撤销其旧会话。

使用 `-DataDirectory` 指定全新数据目录时，启动器会在排他锁内校验并复制发布包携带的已晋升模型，防止新目录悄悄回退到旧模型。已有模型目录保留，不自动覆盖；损坏的发布模型拒绝初始化，源码未携带训练产物时明确提示旧版基线。

`start-private.ps1` 默认要求实际启用且完整验证的 `iforest-v2`：模型、报告、协议、晋升凭据和 active 指针不匹配时启动失败，不会把进程存活当作模型就绪。升级到其他已验证版本时显式传 `-RequiredModel '版本名'`，可再加 `-RequiredModelSha256 '64位摘要'` 锁定产物；部署前在新目录先运行验收。离线研发若直接运行 `python -m datafence.server` 而不指定 `--require-model`，仍可能回退旧版，健康信息会显示降级警告，不能作为部署验收。正在运行的服务持有排他锁，训练 CLI 不得在其运行目录切换 active 模型。

`Required model validated: iforest-v2` 是校验成功提示。启动命令为前台进程，保持 PowerShell 窗口打开，正常停止使用 `Ctrl+C`；如果本机 DataFence 已在所选端口响应，脚本会打印访问地址并退出，不重复启动。脚本依据 Python 进程退出码判断失败，避免 Windows PowerShell 将普通日志误判为启动失败。

本地开发源码需要 Node.js/npm 构建界面，使用 `scripts/setup.ps1`；发布包使用已有 `frontend/dist`，运行时不需要 Node.js。数据库初次生成约50,000条合成客户及相关资产，启动时间受机器性能影响。

## 内网 HTTPS

先完成本机管理员初始化，再准备内网 CA 签发、客户端信任、包含访问主机名 SAN 的 PEM 证书及私钥。服务直接终止 TLS，不信任 `X-Forwarded-*`；不能靠伪造代理头把 HTTP 变成 HTTPS。例：

```powershell
.\scripts\start-private.ps1 -Lan -Port 8765 `
  -AllowedHosts 'datafence.example.internal' `
  -AllowedOrigins 'https://datafence.example.internal:8765' `
  -Certificate 'C:\DataFence\tls\server.crt' `
  -PrivateKey 'C:\DataFence\tls\server.key'
```

域名必须解析到服务器；如使用多个主机名，各参数以逗号分隔并逐个列明，禁用通配。HTTPS origin 包含实际端口且不带结尾斜杠。浏览器登录依赖 Secure/HttpOnly/SameSite=Strict cookie 和会话 CSRF。管理员应只向所需内网开放该端口，避免将服务直接暴露公网。TLS私钥、数据目录及备份只授予服务账号和备份管理员访问，不能放到共享下载目录。

内网启动缺账号、缺证书、缺明确 Host/Origin 或禁用认证时直接失败。本机也默认登录；`DATAFENCE_AUTH_MODE=local_demo` 仅供显式隔离测试，不能启用内网。推荐启动器强制 `required`，不会继承此测试豁免。

## 数据与真实控制的范围

“数据资产”页包含三个独立入口：

- 合成银行资产：由当前数据库生成并持久化，不填充虚构行数。
- 公开 UCI 数据：使用 `.\.venv\Scripts\python.exe scripts\import_public_data.py` 导入；自定义运行目录追加 `--directory 'D:\DataFenceData\public-data'`。记录官方来源、CC BY 4.0、摘要及质量。它的营销标签不是攻击标签，原始行不会发送给商汤。
- 安全日志导入：JSONL/CSV，最多1MiB、2000条，要求显式合成标记、登记员工/工单、时间顺序和无答案字段。整批校验后原子保存，重复相同内容幂等。观察结果只提建议，不声称改变已经发生的操作。

受控访问不依赖攻击剧本：业务账号登录后在独立业务空间选择与其绑定员工对应的工单和区域，管理员/分析员也可切换该空间。服务器使用真实时钟、固定合成数据源、工单范围/导出权限、检测策略及持久额度裁定。获准才返回客户JSON/CSV；拒绝返回403和零客户行。只读账号不能执行。每次“查询”或“导出”都是新的读取请求，按申请行数扣额；网关采用独立、明确的工单生命周期额度桶，跨浏览器、操作员和重启共享。相同请求ID重试不能再扣额，更改参数复用ID会冲突。普通演练的会话额度口径保持不变。安全人员在风险事件队列查看这类操作的调查摘要；历史元数据不重新返回客户行或CSV。

平台操作员在这里获准操作合成工单，不能据此声称已验证真实银行员工身份。CSV只下载到该已登录浏览器，不提供任意目标URL、SQL执行或真实外网传输接口。网关不调用商汤，涉敏 AI 演练的原商汤语义入口仍单独工作。

## 运行和故障恢复

`python -m datafence.server` 固定一个工作进程、64个同时连接的应用并发上限、5秒keep-alive及90秒优雅停机窗口。运行目录持有操作系统文件锁，第二实例不能同时使用同一数据库目录。不要手动追加 `--workers` 或使用开发 `--reload` 运行已部署服务。

`runtime/server-state.json` 记录实际PID与目录；停止前核对进程命令行和目录，不能仅凭可能复用的PID结束其他程序。前台运行时用 Ctrl+C 正常停止。日志位于 `runtime/logs/server.log`，每个5MB，最多5个历史轮转文件。无密码或cookie正文访问日志。启动探针 `/api/health/live` 只报告进程存活，详细健康信息需要登录；存活探针不等同于全功能验收。

重启不会重跑未完成演练，旧 running 作业标 interrupted。额度未决预留保守保留，不自动退款；管理员须结合实际执行和审计记录核查。网关发现旧额度预留但缺交付回执时拒绝重放。CSV/客户行在持久裁定成功后才交付。

## 备份与恢复

先正常停止服务以及正在使用该目录的训练、导入、独立评测等 CLI 写入任务，再执行：

```powershell
.\.venv\Scripts\python.exe -m datafence.maintenance backup runtime backups\snapshot-20260919
.\.venv\Scripts\python.exe -m datafence.maintenance verify backups\snapshot-20260919
.\.venv\Scripts\python.exe -m datafence.maintenance restore backups\snapshot-20260919 restored-runtime
.\scripts\start-private.ps1 -DataDirectory 'E:\gonghang\restored-runtime'
```

备份时持有与服务相同的排他锁，SQLite使用backup API，校验每个文件和数据库；拒绝Windows junction、符号链接及越界路径。跨数据库一致性需要所有写入任务已停止，不能在服务继续写入时只复制主 `.sqlite3` 文件。恢复只能写入不存在的新目录，不覆盖旧数据；旧登录会话全部作废，恢复后的账号密码仍有效。

备份和恢复都先在目标同一文件系统的临时目录中完成复制/校验；恢复先撤销旧会话，再发布完整目录。复制或校验失败不会在指定目标留下半成品；同一路径可在排除故障后重试。若目标被其他任务创建，会拒绝覆盖。异常关机可能留下带 `.datafence-` 前缀的临时目录，它不是已完成快照或恢复结果。

备份包含账号密码哈希及可能的DPAPI密文，按敏感资料保管。DPAPI密文通常只能由原Windows身份解密，迁移到另一台机器或账号时重新运行 `scripts/configure_sensenova.py` 配置商汤。SHA-256是本地一致性检查，不是外部签名；攻击者若可同时改数据和清单仍能重算。

## 验收与更新

先在独立目录或测试服务器解压新发布包，安装依赖并跑 `scripts/check.ps1`（源码检查需Node.js）；保留旧版本与离线快照。新进程加载新版代码和模型，确认登录、合法导出、拒绝无数据、导入质量和审计通过后再切换使用。发布包的 `RELEASE_MANIFEST.json` 可核查文件摘要，包内没有个人配置。

实际本轮测试与剩余缺口见 `PRIVATE_ACCEPTANCE.md` 与 `VALIDATION.md`。尚未验证百万事件性能、高可用、多租户、外部可信审计或真实银行分布检测效果；不要把短时负载测试和模板回归扩写成这些结论。
