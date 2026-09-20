# 契约库

本目录存放**硬件触发契约**的构造代码。

## 为什么契约要写成代码而不是配置文件

触发契约是本工程的输入接口，也是与硬件侧工作的**交接面**。
把它写成 Python 构造代码而不是 YAML，理由：

1. **可类型检查**：谓词种类、操作类别是枚举，写错立刻报错，
   而不是等到运行期才发现"这个字段名拼错了"。
2. **可复用谓词**：常见条件（"操作数可由外部输入控制"、
   "该指令存在"）可以封装成函数，减少重复。
3. **契约本身是被审视的对象**：`formalization_report()` 会算出
   有多少条件**无法被本系统检查**。这个数字是论文中的诚实性指标，
   配置文件做不到这种自省。

## 契约的四段结构

对应硬件漏洞的完整生命周期，缺一段都不完整：

| 段 | 含义 | 对应问题 |
|---|---|---|
| `pre` | **前置状态**：权限、寄存器状态、内存属性、保护状态、微架构状态 | 触发前需要什么条件？ |
| `trigger` | **触发事件**：指令/事务/中断/MMIO/DMA 的语义、参数关系、顺序、时间窗口 | 触发这件事本身长什么样？ |
| `deviation` | **偏差**：硬件相对规范产生的错误行为 | 触发了会怎样错？ |
| `observe` | **观测**：判定偏差发生的可观测信号与所需后端 | 怎么知道它错了？ |

**关键区分：`trigger` 只放判别性条件。**

"这个硬件操作发生了"属于 `trigger`；"结果被写回内存"属于 `pre`
（攻击链的支撑条件，不是触发事件本身）。如果混放，
会把"没有除法但有 store 指令"的固件误判成"触发事件存在"。

## 已有契约

### `div_zero.py` — 除法器除零边界偏差

对应 HardFails 的算术单元边界偏差类别。

- **Pre**：M 特权级；存在除法指令；结果需可写回内存
- **Trigger**：执行无符号除法，除数为 0，被除数可由外部输入控制
- **Deviation**：除零时未按规范返回 `0xFFFFFFFF`
- **Observe**：需 RTL 波形（`div_unit.quotient`）

## 用法

```python
from contracts.div_zero import make_div_zero_contract

contract = make_div_zero_contract()
rep = contract.formalization_report()
print(f"可检查谓词 {rep['checkable_predicates']}/{rep['total_predicates']}")
print(f"未形式化 {rep['unformalized_predicates']} 条")
if rep["unformalized_notes"]:
    for n in rep["unformalized_notes"]:
        print(f"  ! {n}")
```

## 新增契约的检查清单

新写一个契约时，逐条确认：

- [ ] `trigger.predicates` 里**没有**支撑性条件（写回、传播、后续操作）
- [ ] 每条谓词的 `op_class` 填了（否则无法在固件里定位）
- [ ] `deviation.constrained_by_hw=True`（否则这只是"任意注入的偏差"，
      不足以作为真实漏洞证据 —— 这个字段会被证据图记录并告警）
- [ ] `scope.unmodeled_aspects` 非空 —— 诚实声明没建模什么
- [ ] 运行 `formalization_report()`，确认未形式化条件的比例可接受
