# 跨层漏洞分析报告 — 除法器除零边界条件偏差

- **运行 ID**：`run_20260920_104202_S13_pos_indirect_pointer`
- **分析路线**：S13_pos_indirect_pointer / 思路 B
- **耗时**：0.63 s

> 本报告的全部结论均基于**原始固件镜像**的静态与约束分析（证据级别 E1）。
> 未在真实硬件或 RTL 上执行验证，因此**不构成实机可利用性结论**。

## 1. 分析对象身份（镜像未被修改）

| 字段 | 值 |
|---|---|
| path | `F:\qcx\code\CrossLayersAnalyzer\out\samples\S13_pos_indirect_pointer.bin` |
| sha256 | `2c1632d86a615f90818dee94984df96a1ece564529ee20b598e7102677772e2a` |
| size | `20` |
| format | `bin` |
| arch | `riscv32` |
| entry_point | `0x80000000` |
| base_address | `0x80000000` |
| has_symbols | `False` |
| has_debug_info | `False` |
| 可执行段 | 1 个 |

*原始 BIN，装载基址 0x80000000；分析未修改镜像字节*

⚠️ **无符号表**：函数边界为启发式识别，报告中的函数名不可作为定位依据。

⚠️ **无调试信息**：仅提供 PC / 指令 / 硬件模块级定位，**不能声称源码行号**。

## 2. 硬件触发契约

- 契约 ID：`HW-DIV-0001`
- 缺陷类别：`cpu_core`
- 来源：合成契约（用于引擎自检；对应 HardFails 类别的算术单元边界偏差）
- 证据级别：**E0**

**形式化完整性**：4 / 4 个谓词可检查（100%）

## 3. 固件程序摘要

| 指标 | 值 |
|---|---|
| blocks | `3` |
| edges | `2` |
| functions | `1` |
| unreachable_blocks | `0` |
| corrective_blocks | `0` |
| entry_points | `1` |
| lift_total | `5` |
| lift_unknown | `0` |
| lift_unknown_ratio | `0.0` |
| has_symbols | `False` |
| functions_source | `heuristic` |
| indirect_jumps | `1` |
| indirect_resolved | `0` |
| indirect_unresolved | `1` |
| cfg_confidence | `low` |

### 3b. 控制流可信度

- 间接跳转（jalr/jr，无法静态确定目标）：**1** 处
- 其中已解析出目标：0 处
- 未解析（走保守兜底）：1 处
- 控制流可信度评级：**low**

⚠️ **不可达性结论的强度受此限制。** 间接跳转无法静态解析时，本分析器采用**保守过近似**（宁可多连边也不漏边），因此：

  - 报出的「可达 + 可控」候选**不受影响**（过近似只会多报，不会漏报）
  - 报出的「不可达」结论**可能偏保守**——真实可能通过间接跳转到达的地方，会在这里被接上
  - 反过来，若某处**仍然**被判为不可达，说明该地址连兜底策略都没能连上，可信度较高

⚠️ **可信度为 low**：超过一半的间接跳转无法解析。此时建议人工确认这些 `jalr` 的目标范围后再采信可达性结论。

**操作类别分布（前 15）**

| 操作类别 | 数量 |
|---|---|
| return | 2 |
| load | 1 |
| jump | 1 |
| arith_div | 1 |

## 4. 判定结果

- **可行候选**（可达 + 操作数可控）：**0**
- 可达但可控性随路径而变：0
- 片段存在但操作数不可控：0
- 操作数不可控但值静态未知：0
- 片段存在但不可达：0
- 触发片段不存在：0
- 无法判定（UNKNOWN）：1

⚠️ UNKNOWN 表示**信息不足或求解超时**，**不等价于不可利用**，不得并入负例统计。

## 5. 未决事项与证据边界

| 证据层级 | 状态 | 说明 |
|---|---|---|
| E0 语义关联 | ✅ 已完成 | 契约与代码位置的静态关联 |
| E1 静态/约束满足 | ✅ 已完成 | 本报告的主要结论层级 |
| E2 模型可重放 | ❌ 未进行 | 需在模拟器/RTL 上加载同一镜像 |
| E3 有漏洞 RTL 验证 | ❌ 未进行 | 需匹配的目标 RTL |
| E4 板卡验证 | ❌ 未进行 | 需原始目标板卡与固件 |

**因此本报告只能支持「在这份固件的静态分析中，存在满足该触发契约可达性与可控性的候选」这一结论，不能支持「该攻击在目标设备上成立」。**

**具体的分析能力边界**：

- 间接跳转 1 处中 1 处无法静态解析目标；已采用保守过近似（宁可多连边也不漏边），因此「不可达」结论偏保守。
- 无符号表：函数边界为启发式识别，函数名不可作为定位依据。
- 未建模：隐式信息流（控制依赖）、中断与并发、微架构时序。
- 「可控」判定基于污点可达；若外部输入在更早位置已被校验，本分析不会发现 —— 这是「可控」与「可利用」之间的真实差距。

## 6. 复现信息

```json
{
  "run_id": "run_20260920_104202_S13_pos_indirect_pointer",
  "firmware_sha256": "2c1632d86a615f90818dee94984df96a1ece564529ee20b598e7102677772e2a",
  "contract_id": "HW-DIV-0001",
  "elapsed_sec": 0.635,
  "program_stats": {
    "blocks": 3,
    "edges": 2,
    "functions": 1,
    "unreachable_blocks": 0,
    "corrective_blocks": 0,
    "entry_points": 1,
    "lift_total": 5,
    "lift_unknown": 0,
    "lift_unknown_ratio": 0.0,
    "has_symbols": false,
    "functions_source": "heuristic",
    "indirect_jumps": 1,
    "indirect_resolved": 0,
    "indirect_unresolved": 1,
    "cfg_confidence": "low"
  },
  "formalization": {
    "contract_id": "HW-DIV-0001",
    "total_predicates": 4,
    "checkable_predicates": 4,
    "unformalized_predicates": 0,
    "unformalized_notes": [],
    "formalization_ratio": 1.0,
    "is_minimal_poc": false,
    "warning": ""
  }
}
```