# 公开数据导入与适用边界

已实际导入 UCI Bank Marketing 的 `bank-full.csv`。它来自葡萄牙银行历史电话营销业务，属于公开业务数据，**不是本项目合成客户、银行访问日志或攻击检测基准**。UCI 标明许可为 CC BY 4.0；目标字段 `y` 是定期存款订阅结果，不能映射成攻击标签。[UCI 官方来源](https://archive.ics.uci.edu/dataset/222/bank+marketing)

署名：Moro, S., Rita, P., & Cortez, P. (2014). *Bank Marketing*. UCI Machine Learning Repository. [DOI: 10.24432/C5K306](https://doi.org/10.24432/C5K306)。本项目保留原始压缩包，仅生成字段和质量聚合；不修改、拼接、补齐或去重源记录。许可与来源随清单和聚合接口保留；后续共享数据应继续保留署名、许可链接及修改说明。[CC BY 4.0 许可](https://creativecommons.org/licenses/by/4.0/)

## 本次真实导入结果

2026-09-19，官方压缩包 1,023,843 字节；选择 `bank.zip!bank-full.csv`，未将同包10%子集再次累加。

| 检查 | 实际结果 |
| --- | --- |
| 数据记录 / 字段 | 45,211 / 17（16个输入及1个业务结果） |
| 通过结构、类型、取值检查的记录 | 45,211 |
| 无效记录 / 完整重复行 / 空单元格 | 0 / 0 / 0 |
| 显式 `unknown` 类别 | 52,124格，单独计量，不伪装成已知属性 |
| `unknown` 分布 | contact 13,020；poutcome 36,959；education 1,857；job 288 |
| 业务结果 `y` | no 39,922；yes 5,289；均非安全标签 |
| 原CSV体量 | 4,610,348 字节 |

记录数和完整行唯一数不等于去重客户数。该数据包含个人层面金融及人口统计属性，前端只读取来源和质量聚合，不提供个人行，不发给商汤或其他云模型，也不参与检测器训练或安全事件判定。

官方HTTPS下载后固定的压缩包 SHA-256：

```text
e0bf5f5de5b846e2f18e9d90606637267d46dfa260e0f17bb12e605db5efbeb4
```

选定CSV的 SHA-256：

```text
d1513ec63b385506f7cfce9f2c5caa9fe99e7ba4e8c3fa264b3aaf0f849ed32d
```

UCI页面未发布本项目使用的SHA-256；这里是核实来源后固定的版本指纹，不冒称供应商签名。来源内容改变时导入器拒绝，不自动接受新摘要。

## 本地运行和只读接口

```powershell
.\.venv\Scripts\python.exe scripts/import_public_data.py
.\.venv\Scripts\python.exe scripts/import_public_data.py --list
# 无网络环境可使用已核实的同版官方压缩包：
.\.venv\Scripts\python.exe scripts/import_public_data.py --archive D:\datasets\bank-marketing.zip
```

输出固定隔离在 `runtime/public-data/`。`uci-bank-marketing/source.zip` 保存源文件，`manifest.json` 保存许可、来源、摘要及质量；独立 `catalog.sqlite3` 的 `datasets` 表仅保存聚合JSON。没有把个人记录写入应用customers表或events表；原始CSV仅在本地导入过程内存中解析，未解包写到文件系统。

应用可调用 `datafence.public_data.list_datasets(Path('runtime/public-data'))`。目录未导入时返回空列表，不建立目录、不下载；已导入时返回：`id/name/status/source_url/download_url/license/origin/synthetic/row_count/column_count/imported_at/sha256/source_integrity/quality/business_target/security_labels_available/used_for_detection_training/llm_access/limitations`。原始行和密钥不在返回值中。SQLite以只读模式打开，源文件摘要不符时标记 `integrity_failed`，不得将该条显示为有效资产；目录损坏抛出固定 `PublicDataError`，由调用方显示不可用状态。

导入可重入：同版本使用本地缓存、保留首次导入时间、UPSERT同一数据集，不重复累计行数。导入是显式CLI操作；页面读取不会联网。默认路径独立于业务数据与评测标签；这是逻辑隔离，不声明已有操作系统访问控制。

## 下载与解析限制

- 仅允许代码内固定UCI HTTPS地址，无用户自定义URL、无重定向、无环境代理、无自动重试；网络阶段45秒总截止，下载上限100,000,000字节，内容必须匹配固定SHA-256。
- 外层和内层ZIP均先检查全部成员；每层最多32项、单成员16MB、声明总展开24MB、压缩比200倍。仅流式读指定两个成员，不使用 `extract` / `extractall`，不运行内容。
- 拒绝绝对路径、`..`、Windows反斜杠/盘符/备用数据流、重复或大小写冲突名、符号链接、加密项和不支持的压缩算法。
- CSV限制100,000行、单物理行4096字节、单字段128字符，精确检查17列及字段类型/枚举；异常不回显个人行。源数据质量失败时不登记成功资产。

`tests/test_public_data.py` 实际20项通过，其中17项验证UCI固定摘要拒绝、ZIP路径与符号链接防护、资源上限、HTTP重定向/超限/压缩体拒绝、空值/未知/重复/非法目标区分、离线重入、只读目录和源文件篡改检出，另3项检查CERT安全库存。这些验证导入边界，不是DLP效果评测。

## 更适合检测评测的后续公开数据

CMU SEI官方CERT数据包含正常与恶意行为的**合成内部威胁日志**，更接近后续外部检测基准。[CMU官方说明](https://www.sei.cmu.edu/library/insider-threat-test-dataset/)

官方Figshare元数据表明 `r1.tar.bz2` 为87,541,633字节，并标记CC BY 4.0；但下载后发现包内ExactData旧许可另有限制文字，且官方主标签表没有r1条目。本轮已隔离下载并安全检查，详见 `CERT_DATA.md`；未将其登记为许可已澄清的正式资产，也没有映射、训练或评测。公开数据导入完成不代表检测效果通过外部验证。[官方元数据接口](https://api.figshare.com/v2/articles/12841247)
