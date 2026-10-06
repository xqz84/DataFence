# DataFence 本地行为模型训练记录

> 本文是 2026-09-19 的正常行为异常模型历史报告。2026-10-03 另做了带合成攻击标签的离线监督候选，但跨生成器挑战失败且未晋升；现行 `iforest-v2` 未变。当前结论见 `ATTACK_TRAINING_20261003.md`。

2026-09-19：完成真实 Isolation Forest 训练、独立正常校准、冻结后的留出评测和 JSON 推理一致性验证。候选 `iforest-v2` 通过本轮预先设定的部署门槛，当前本地注册表已选择该版本；旧 `iforest-v1` 保留可随时对照。这里训练的是行为异常模型，**不是商汤或其他大语言模型微调**。本轮没有发送云请求，没有读取项目既有 challenge 标签调参。

## 实际数据划分与训练方法

| 划分 | 规模 | 独立种子 | 用途 |
| --- | ---: | ---: | --- |
| 正常训练特征 | 12,000 行 | 712367 | 只用于拟合森林 |
| 正常校准特征 | 4,000 行 | 918273 | 只用于确定异常分映射 |
| 未见正常留出 | 4,000 行 | 102938 | 只用于评估正常误报率 |
| 未见分布偏离探针 | 2,000 行 | 564738 | 只用于评估人工异常组合检出能力 |

这四组是合成行为**特征行**，不能称为真实银行日志。训练流包含日常业务、已批准批量对账、夜间值班、低频设备变更、常规 API 与少量低规模公共数据流转。特征没有员工 ID、事件 ID、会话 ID、场景名、业务标签或攻击答案。

九个输入按固定顺序为：`log_records`、`region_count`、`hour_sin`、`hour_cos`、`new_device`、`external_channel`、`export_action`、`log_session_reads`、`api_calls_60s`。

固定参数：100 棵树、每棵最多 256 行、全部特征、`bootstrap=False`、`contamination="auto"`、单线程、随机种子 712367。正常校准集的第 98 百分位映射到异常分 60，第 99.9 百分位映射到 100，外侧截断至 0—100；不使用留出正例调阈值。`protocol.json` 在训练及留出构造前写入，冻结模型与校准后才构造留出样本。本轮没有超参数搜索、反复挑选留出种子或根据旧 challenge 调整训练分布。

四个划分两两逐行比较，重复行数全部为 0。各组完整数据摘要见 `runtime/models/iforest-v2/report.json` 的 `splits`。训练、校准与留出种子分离只能防止直接重用；正常留出仍来自同一家族生成器，不代表跨银行或现实分布泛化。

## 留出实测结果

下表比较的是 **ML-only 异常分是否 ≥60**。正类是人工构造的分布偏离探针，不是已经证实的真实银行攻击。

| 指标 | 旧版 iforest-v1 | 新版 iforest-v2 |
| --- | ---: | ---: |
| TP / FP / TN / FN | 1349 / 573 / 3427 / 651 | 1659 / 75 / 3925 / 341 |
| Precision | 70.1873% | 95.6747% |
| 探针 Recall | 67.4500% | 82.9500% |
| F1 | 0.687914 | 0.888591 |
| 正常 FPR | 14.3250% | 1.8750% |
| 正常 FPR 的 Wilson 95% 上界 | 15.4449% | 2.3439% |

Precision 会受到此处 1/3 正类占比影响，不能直接用于推断真实业务中罕见攻击的告警精度。旧版对照在同一份留出集运行，没有改写其训练与校准方法。

| 独立偏离探针 | 例数 | 旧版检出率 | 新版检出率 |
| --- | ---: | ---: | ---: |
| 夜间、新设备与大规模读取组合 | 667 | 100% | 100% |
| API 突发调用 | 667 | 2.3988% | **48.8756%** |
| 异常外部数据流转组合 | 666 | 100% | 100% |

**API 突发的行为模型单独检出能力仍不足。** 总体指标不能掩盖该子群缺陷；当前完整检测仍需要已有 API 频率规则、工单约束及事件关联。低量慢速、跨会话累积、业务意图不匹配和 Prompt 同义改写也不能仅由这个模型解决。

本机实际训练与评测耗时 2.097 秒。100 次单行 JSON 模型推理实测 P50 为 0.2232 ms、P95 为 0.3449 ms，仅反映本机此次运行，不是完整请求响应时延。JSON 森林与 sklearn 在全部 6,000 留出行上的最大绝对原始分数误差为 `1.6653345369377348e-16`。

## 冻结的晋升门槛与结果

训练前固定门槛：正常 FPR 的 Wilson 上界 ≤4%；人工偏离探针总体 Recall ≥65%；F1 相对旧版回退不超过 0.01；JSON 分数误差 ≤`1e-12`；训练/校准/正常留出/探针至少分别 5000/2000/2000/1000 行；四划分不重复。

本次六项检查全部通过，执行 `--promote` 后原子写入 `runtime/models/active.json`，选择 `iforest-v2`。这是在当前合成测试协议下的部署准入，不表示模型最优或已达到银行生产标准。模型参数没有依据本次留出结果继续修改。以后若用已见结果设计下一版，必须另设新的冻结留出，不能继续把这里称作未见测试。

## 产物、复现与回退

主要实现：`backend/datafence/training.py`、`model_artifacts.py` 和 `engine.py`。训练命令已实际执行：

```powershell
.venv\Scripts\python.exe -m datafence.training --name iforest-v2 --promote
.venv\Scripts\python.exe -m datafence.training --name iforest-v2-repro
```

第二条命令使用完全相同的冻结协议复跑，数值森林、校准范围、特征和留出指标逐项相同，没有更换 active 版本。两个版本仅名称、记录时间等审计信息不同，因此整个文件摘要可不同。数值内容共同摘要为：

```text
02a26003ef8645f88e76248bd05e0f6723503d28f9bba97b5e57b22d74f0adf1
```

正式模型产物摘要：

```text
3757f64061d270952cf5d3cf19671fc3749543df3117afb838bfb43bf48559ae
```

`runtime/models/iforest-v2/` 包含：

- `model.json`：289,344 字节的数值森林、校准、特征、训练参数与版本摘要。
- `protocol.json`：训练和评测前冻结的协议。
- `report.json`：实际留出指标、混淆矩阵、子群表现、门槛检查与数据摘要。
- `normal_train.npz`、`normal_calibration.npz`、`holdout_features.npz`：各阶段数值特征，可用 `numpy.load(..., allow_pickle=False)` 读取。
- `holdout_labels.json`：独立评估标签，模型加载器和检测输入不读取该文件。
- `promotion.json`：最终晋升凭据。`report.json` 是晋升前冻结的评测快照，其中 `promoted:false` 不代表当前未启用；当前选择以 `active.json` 与 `promotion.json` 为准。

训练目录已经存在时 CLI 拒绝覆盖，复现请指定新的安全名称，例如 `--name iforest-v2-repro2`。保持相同 Python/numpy/sklearn 版本才能比较完全相同的数值结果。本次环境为 Python 3.12.13、numpy 2.5.3、scikit-learn 1.9.1。

默认 `DetectionEngine` 读取 `active.json`；缺少晋升指针时使用旧版。显式旧版对照：

```powershell
$env:DATAFENCE_BEHAVIOR_MODEL = 'legacy'
```

也可在代码中使用 `DetectionEngine(employees, tasks, behavior_model="legacy")`。选择特定候选时只接受注册表内的安全名称，禁止将任意文件路径或 URL 作为模型选择。新模型加载失败会回退旧版并在 `model_info.load_warning` 说明，事件记录的 `model_version` 随实际加载版本变化。

## 加载安全与回归验证

模型使用 JSON 数值数组，不使用 pickle/joblib 或 Python 对象反序列化。加载器验证大小上限、JSON 重复键、有限数值、摘要、特征顺序、树数/节点数、索引范围、无环树结构、深度、节点样本数以及校准范围；active 选择还核验训练报告、门槛状态与晋升摘要。文件摘要只能检测意外修改，不是抵抗本机管理员伪造的外部签名。数值推理与 sklearn 的一致性已实测，不宣称支持任意 sklearn 模型格式。[scikit-learn 持久化文档](https://scikit-learn.org/stable/model_persistence.html)说明了 pickle 类载入的代码执行风险。

`tests/test_training.py` 新增 17 项测试，覆盖数据隔离、JSON 数值一致性、损坏产物拒绝、路径拒绝、晋升失败不启用、旧版回退及最终事件裁定的安全提交。全后端实际命令 `.venv\Scripts\python.exe -m pytest -q` 输出 **145 passed, 2 warnings in 7.38s**；两个 warning 来自测试框架依赖弃用提示。

另提供 `DetectionEngine.commit_analysis(event, final)` 给编排器同步当前事件的最终风险。它只能更新该员工/会话历史最后一条匹配事件的 `risk_score` 与 `blocked`，拒绝旧事件、跨会话、伪造 ID、无效分数；不会把模型文本、动作或外部历史合并进检测状态。检测引擎仍不访问 LLM。

本轮没有重新包装旧场景或 challenge 报告。后续端到端对照应写入新目录并记录新模型版本，保留原先报告作为历史证据。
