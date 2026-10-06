# CERT r1 官方数据库存检查

本轮实际下载并校验了CMU CERT r1及独立答案包，**尚未用于训练、阈值调整或检测效果评测**。结论是：r1适合后续日志适配和性能研究，但当前不能作为带攻击标签的外部准确率基准；许可说明也需要先澄清。因此没有把它登记到正式数据资产目录，`list_datasets()` 仍仅展示许可明确的UCI业务数据。

## 来源与实际文件

CMU SEI说明该系列是合成内部威胁数据，包含正常背景与恶意行为场景，答案另外发布；并非真实员工监控日志。[CMU官方说明](https://www.sei.cmu.edu/library/insider-threat-test-dataset/)

文件来自该页面指向的CMU Figshare条目，固定文件ID下载；原始元数据、发布方SHA-256清单和README均保留在 `runtime/public-data/cert-r1/`。[官方条目元数据](https://api.figshare.com/v2/articles/12841247)

| 文件 | 实际字节 | 发布方SHA-256校验 |
| --- | ---: | --- |
| r1.tar.bz2 | 87,541,633 | 通过 |
| answers.tar.bz2 | 1,254,678 | 通过 |
| SEI_Insider_README.txt | 1,446 | 保存本地摘要；清单未给此文件摘要 |
| CHECKSUMS-sha256.txt | 868 | 官方HTTPS下载留档 |

```text
r1.tar.bz2
8a70ad175df477dd5a35e8422ff236bc6a9ca76f48ae7e0d29c471c4efa52fa3

answers.tar.bz2
ed21bf921def01e97326b314f2d1fa77651a945bd31bf513095f8ac7658c9ddd
```

脚本已固定上述发布方摘要；再次下载或离线检查都会拒绝不一致内容。目录库存和摘要不能抵抗能够同时修改程序与所有本地证据的管理员，未声称外部签名认证。

## 日志与标签的检查结果

r1完整检查通过：23个普通文件，总展开372,922,865字节。包含登录、设备、HTTP活动、18个月LDAP、README和许可。未把合成姓名、邮件、用户ID、URL或单行内容输出到页面或聚合接口。

| 日志成员 | 字节 | 物理行数（不是已验证事件数） |
| --- | ---: | ---: |
| r1/logon.csv | 62,397,995 | 849,580 |
| r1/device.csv | 5,018,582 | 65,669 |
| r1/http.csv | 304,248,221 | 3,451,665 |

本轮仅扫描字节、物理行和可核验表头；CSV记录、时间戳、事件ID唯一性和跨文件键还没有完整验证，不能直接用这些行数冒充成功接入的业务事件。尤其HTTP首行未通过表头识别，后续映射必须先核实格式。官方README还说明事件ID未必跨文件唯一；访问日志中的域名仅当数据处理，绝不访问。

答案包库存触发200个tar成员上限，已检查192个普通文件后停止，`inventory.json` 明确 `answers.complete=false`、`reason=tar_resource_limit`；没有静默放宽限制或声称整包检查完毕。主标签 `answers/insiders.csv` 位于这一上限以内，已单独完整读完并仅保存按版本计数：

| dataset | 主标签条目数 |
| --- | ---: |
| 2 | 1 |
| 3.1 / 3.2 | 2 / 2 |
| 4.1 / 4.2 | 3 / 70 |
| 5.1 / 5.2 | 4 / 99 |
| 6.1 / 6.2 | 5 / 5 |
| 1 / 1.0 | 0 |

官方答案README说明这张表列出已知正例及事件观测文件。**没有r1标签条目不代表r1全是正常行为**。不能把r1全部设为NORMAL，也不能把它与较新版本的恶意答案混合，报告看似完整的Precision/Recall/F1。答案包的事件明细本来就有变长行和混合事件类型，不能无条件当普通固定列CSV导入。

后续要做有标签的CERT检测基准，须取得与标签同版本的日志，提前固定映射、员工/时间划分、指标和缺失观测处理，再隔离训练与测试标签。目前官方最早带主标签的r2完整包为8,655,227,129字节，超过本轮100MB下载上限，未下载。可以另选体量与许可都合适的外部基准，不能为凑指标把营销结果当攻击答案。

## 许可说明存在版本差异

Figshare官方元数据标记CC BY 4.0；但实际r1和answers内的 `license.txt` 都保留了2011年ExactData许可，含发布、网络分发和衍生使用的限制文字，同时另有研究报告的有限使用条款。二者的适用关系尚未核实，本项目不作“旧条款已经失效”或“可任意再分发”的断言。[官方r1原包](https://ndownloader.figshare.com/files/24857825)

原版权声明：Copyright © 2011 ExactData, LLC, All Rights Reserved。

检查结果设置 `license_status=repository_and_embedded_terms_need_clarification`，保留档案用于来源核实；未提供原始行下载接口、未向云模型发送、未把数据打包发布。需要进一步澄清后才决定能否作为对外发布的基准资产。UCI正式导入不受这项CERT许可差异影响。

## 复查和资源限制

```powershell
# 已下载文件的离线校验与库存检查，不发网络请求：
.\.venv\Scripts\python.exe scripts/inspect_cert.py
# 首次显式下载；存在且摘要一致时复用缓存：
.\.venv\Scripts\python.exe scripts/inspect_cert.py --download
```

网络仅访问固定Figshare元数据与4个文件ID，允许一次跳转至核实过的CMU S3路径；不接受自定义URL、环境代理或自动重试。单次网络阶段180秒截止，固定下载清单合计低于100,000,000字节。tar只流式读取，不使用文件系统extract，不执行任何内容；每包至多200成员、单文件512MB、总展开1GB，拒绝越界路径、链接和稀疏文件。r1是连接的bzip2流，使用`BZ2File`顺序处理，不需要解包落地约373MB日志。

库存为 `inventory.json`；主标签版本聚合为 `label-index-summary.json`。它们是独立研究产物，不进入业务事件库、检测模型或正式评测指标。`tests/test_public_data.py`包含3项CERT本地检查，验证路径拒绝、预算超限明确报告部分完成、主标签只聚合且不泄漏用户行。
