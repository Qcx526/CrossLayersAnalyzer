# CrossLayersAnalyzer —— 项目长期备忘

## 项目定位
芯片跨层漏洞攻击链路分析（项目第五部分）。单人 + 一台电脑。
目标：**论文 / 专利**（不是产品）。

## 核心命题（论文卖点，不要改）
> 已有工作问「能否构造一个程序触发该硬件漏洞」（设计验证视角）；
> 本工作问「给定的真实固件是否**已经**构成该漏洞的触发条件」（部署系统威胁评估视角）。

甲方约束「不允许生成新 ELF，必须在原始硬件和固件上分析」
被**改写为问题定义的一部分**，而不是当作限制承受。

## 三个创新点
- **A（主）** 固定程序约束下的可达性求解 → `reachability.py`
- **B（专利）** IR 层语义匹配 → `matcher.py`
- **C** 约束进展度替代代码覆盖率 → `Progress` / `unsatisfied_predicates`

## 判定分层（不可简化，这是审稿人会抓的点）
`controlled` / `constant` / `not_controllable` / `path_dependent` / `unknown`
- `constant`＝「我知道它是 5」
- `not_controllable`＝「我不知道它是几，但攻击者说了不算」
两者结论都是不可利用，但**证据性质不同**，报告里必须分开。

## 本项目已固化的工程约定

1. **UNKNOWN 是一等公民**：信息不足返回 unknown，绝不降级为"未发现"；
   统计时单列，**不得并入负例**。
2. **证据级别纪律**：`edge_nature=inference` ⇒ level ≤ E1；
   `observation` ⇒ level ≥ E2 且必须有仪器来源。由 `test_evidence.py` 机器断言。
3. **过近似方向偏好**：可达性上宁可多连边（假阳性方向），
   绝不漏边（假阴性方向）。安全工具的假阴性＝"我说安全，其实不安全"。
4. **每个过近似逻辑都必须配 `*_resolved` 类指标**并写入报告，
   否则等于把"解析不出来"伪装成"不可达"。
5. **契约的 `trigger` 只放判别性条件**；支撑性条件（写回、传播）放 `pre`。
6. **样本必须带 `binary_label`**，考查其它性质的样本标 `excluded`，
   且报告要打印被排除数 —— 否则会造出不存在的假阴性。
7. **契约真源唯一**在 `contracts/`；`tests/contract_div_zero.py` 只做转发。
8. **报告章节号动态生成**（`sec` 计数器），避免条件章节导致跳号。
9. **报告必须列出分析能力边界**（间接跳转未解析数、无符号表、
   未形式化条件数、未建模项）。

## 目录约定
```
src/crosslayer/   分析引擎（唯一代码真源）
contracts/        硬件触发契约库（与硬件侧工作的交接面）
tests/            测试（run_tests.py 为统一入口）
schemas/          CLEG 节点/边的 JSON Schema
docs/             01 方法调研 / 02 工程框架 / 03 论文策略
                  04 验证方法论 / 05 交接说明（工具·输入输出·样本·用法）
out/              运行产物（报告、证据库、日志）—— 非源码
```

## 对外四问的稳定答案（导师/甲方会反复问）
1. **工具**：纯 Python + z3 / capstone / pyelftools / networkx / jsonschema / PyYAML。
   刻意**不用** WSL、KLEE、Ghidra、商业 EDA —— 为论文复现性做的取舍。
2. **输入**：ELF（自动识别）或裸 `.bin`（**必须显式给 `base_address`**，
   猜错会静默给出错误结论）+ `TriggerContract`（代码，非配置）
   + `AnalysisConfig`（`input_regs` 定义"攻击者从哪进来"，是最关键参数）。
   **输出**：`AnalysisRun` + 7 类逐块判定（含求解出的输入模型值）
   + CLEG 证据库 + 逐样本 Markdown 报告 + summary.json。
3. **样本**：**不来自任何外部来源，全部自研合成**（13 个，`tests/fixtures.py`
   手写编码器）。**不用汇编器**，否则地面真值依赖"编译器按预期编码"这一
   不可验证假设。真值由 capstone 交叉验证（59/59）。
   真实固件**无地面真值**，故只能用合成样本证明引擎逻辑，
   **不能证明真实固件上的有效性** —— 这是 Threats to Validity。
4. **用法**：见 `docs/05-交接说明.md`。结论上限 **E1**，
   只能说"静态分析中存在满足契约的候选"，**不能说"在目标设备上成立"**。
   此边界必须在**第一次**汇报时讲清，否则后患。


## 环境约定（本机特殊，务必遵守）
- **Bash 工具不可用**（`dirname`/`cd`/`head` 全 command not found，exit 127）→ 一律用 PowerShell。
- PowerShell 直读 Python UTF-8 stdout 会 mojibake（甚至读成空）→ 让脚本自己写日志文件，或读 JSON 产物。
- **PowerShell 管道会静默返回空**：`Get-ChildItem | Select-Object`、
  `ForEach-Object { -f }`、`Tee-Object` 在本机 exit 0 但无输出。
  → 列目录/写状态一律用 `[System.IO.Directory]::GetFiles()` +
    `[System.IO.File]::WriteAllLines()` 落盘，再 Read 那个文件。
- 临时取证脚本用完即删（`[System.IO.File]::Delete`，`Remove-Item` 有时报成功但文件仍在）。
- Windows 上不要写 .ps1/.bat 处理含非 ASCII 的路径。
- venv：`C:\Users\Administrator\.workbuddy\binaries\python\envs\default\Scripts\python.exe`
- 不要**嵌套英文双引号**写多行 Python（PowerShell here-string 会破坏它们）→ 写成 .py 文件再跑。
- capstone 必须 `md.detail = True` 才能访问 `insn.operands`。
- z3 不导出 `__version__`（探测会得 n/a，需 `pip show z3-solver`）。


## 不可使用的外部工具
- **WSL 被安全策略拦截**（`PROGRAM BLOCKED BY SECURITY POLICY - wsl.exe`）
- 无 KLEE / Ghidra / 交叉编译器
→ 因此整个引擎是自包含纯 Python。**这对论文是优点**（评审机一键复现），
  不要试图绕回 Linux 工具链。

## 当前状态（2026-09-18）
- 测试 4 套件全通过；端到端 13/13；TP=4 FP=0 TN=7 FN=0
- Precision / Recall = 100%
- 编码器 vs capstone 59/59；证据图不变量 31 项全通过
- 证据图：36 节点 / 30 边（推理 30 / 观测 0）；契约形式化 4/4 (100%)
- 已实现：思路 B（固件自身含触发硬件漏洞的代码段）+ 间接跳转解析
- 未实现：ARM、思路 A、思路 C、Microscope 接入

## 反复出现的正确性陷阱（改代码前先看）
1. `insn.sources` / `insn.operands` 是 **Expr 对象**，不是字符串。
   判寄存器用 `e.kind is ExprKind.REG` 取 `e.name`。
2. LOAD 的地址是**嵌套表达式** `add(base, const(disp))`，
   取基址/偏移必须**递归**（见 `cfg._regs_in` / `_consts_in`）。
3. `jalr` 的操作数个数随助记符而变：`jalr rd,rs1,imm` 是 3 个，
   `jr rs` 只有 1 个。判据：**存在第二个寄存器时第一个才是链接寄存器**。
4. `ret` 不算间接跳转（目标是调用约定固定的），计入会虚高不可解析比例。
5. 常量传播检查只能用 `insn.sources`，**不能用 `operands`** ——
   目标寄存器在指令执行前按定义还不存在。
6. 跨块常量传播要分 must（所有前驱一致）与 per-path（按路径枚举），
   只做 must 会把 path_dependent 误判成 constant。
