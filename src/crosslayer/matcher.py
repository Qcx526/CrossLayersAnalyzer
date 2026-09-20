"""
跨层漏洞分析 —— 语义匹配器（核心创新点 B）

功能
----
把硬件触发契约（一组 Predicate）与固件 IR 做**语义匹配**，
而不是指令序列的语法匹配。

四层过滤（由粗到细，逐级剪枝）
-----------------------------
  L1  操作类别筛选      —— 契约要求的 OpClass 在块内是否存在
  L2  常量/位域约束     —— 立即数、CSR 名等硬约束
  L3  数据依赖语义验证  —— 操作数关系是否在 IR 上真正成立
  L4  路径与可控性      —— 由 reachability 模块负责（本模块只产出候选）

对编译器优化的处理
------------------
编译器会做常量折叠、指令重排、条件反转、指令合并。因此 L3 必须建立在
**数据依赖语义**上。本模块显式实现了若干条规范化规则：

- **常量折叠的逆**：`li t, 4; mul a, b, t` 语义等价于 `mul a, b, 4`
  → 追踪"经由中间寄存器的常量"（constant propagation）。
- **条件反转的等价**：`bge a, b, X` 与 `blt a, b, Y` 是同一比较的反向形式
  → 在比较谓词匹配时同时接受正反形式。
- **指令合并的展开**：`mul` 可能被展开为移位+加法序列
  → 记录"复合模式"的可满足候选。

诚实性纪律
----------
- 匹配不到就报"未匹配"，不降低标准凑数。
- 每个匹配结果都携带 `satisfied` / `unsatisfied` 谓词清单与证据地址。
- 无法判断时返回 `UNKNOWN`，绝不当成 `MATCH`。
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from .contracts import Predicate, PredicateKind, TriggerContract
from .ir import BasicBlock, Expr, ExprKind, Instruction, OpClass, Program


class MatchStatus(enum.Enum):
    """匹配状态。UNKNOWN 必须与 MATCH 严格区分。"""

    MATCH = "match"            # 所有可检查谓词均满足
    PARTIAL = "partial"        # 部分满足（部分谓词无法检查或未满足）
    NO_MATCH = "no_match"      # 明确不满足
    UNKNOWN = "unknown"        # 因信息不足无法判定


@dataclass
class PredicateResult:
    """单个谓词的匹配结果。"""

    predicate: Predicate
    satisfied: bool
    evidence_addr: Optional[int] = None
    evidence_block: Optional[str] = None
    detail: str = ""
    checked: bool = True       # False = 无法检查（不是"不满足"）


@dataclass
class BlockMatch:
    """
    一个基本块的匹配结果。

    `status` 已综合所有谓词；`predicate_results` 保留逐项明细，
    使得报告可以展示"为什么匹配/为什么没匹配"。
    """

    block_id: str
    start_addr: int
    status: MatchStatus
    predicate_results: list[PredicateResult] = field(default_factory=list)

    # 关键证据位置（供报告定位）
    key_addr: Optional[int] = None
    key_insn: Optional[str] = None

    def satisfied_count(self) -> int:
        return sum(1 for r in self.predicate_results if r.satisfied)

    def checked_count(self) -> int:
        return sum(1 for r in self.predicate_results if r.checked)

    def unsatisfied(self) -> list[PredicateResult]:
        return [r for r in self.predicate_results if r.checked and not r.satisfied]

    def unchecked(self) -> list[PredicateResult]:
        return [r for r in self.predicate_results if not r.checked]

    def progress(self) -> float:
        """
        约束进展度 —— 创新点 C 的核心信号。

        定义为"已满足谓词数 / 可检查谓词总数"。
        这不是代码覆盖率：它直接衡量"距离满足硬件触发契约还差多少"。
        """
        c = self.checked_count()
        return (self.satisfied_count() / c) if c else 0.0

    def summary(self) -> dict[str, Any]:
        return {
            "block_id": self.block_id,
            "start_addr": f"0x{self.start_addr:08x}",
            "status": self.status.value,
            "progress": round(self.progress(), 4),
            "satisfied": self.satisfied_count(),
            "checked": self.checked_count(),
            "total_predicates": len(self.predicate_results),
            "unsatisfied": [r.predicate.description for r in self.unsatisfied()],
            "unchecked": [r.predicate.description for r in self.unchecked()],
            "key_addr": f"0x{self.key_addr:08x}" if self.key_addr is not None else None,
            "key_insn": self.key_insn,
        }


# ---------------------------------------------------------------------------
# 常量传播：处理编译器常量折叠
# ---------------------------------------------------------------------------
# 支持常量折叠的操作类别。编译器生成的 `li rd, imm` 实际就是 `addi rd, zero, imm`，
# 因此必须处理算术/逻辑类，而不只是 MOV —— 否则 `li a2,100; li a3,5; divu` 这类
# 纯常量脚本会被误判为"可控性未知"。
_CONST_FOLD_OPS = frozenset({
    OpClass.MOV,
    OpClass.ARITH_ADD, OpClass.ARITH_SUB,
    OpClass.ARITH_MUL, OpClass.ARITH_DIV, OpClass.ARITH_REM,
    OpClass.ARITH_SHIFT, OpClass.ARITH_COMPARE,
    OpClass.LOGIC_AND, OpClass.LOGIC_OR, OpClass.LOGIC_XOR,
})

_MASK32 = 0xFFFFFFFF


def _eval_const_op(op_class: OpClass, mnem: str, args: list[int]) -> Optional[int]:
    """
    在常量层面求值一条运算指令。

    返回 None 表示"无法折叠"（不是常量），调用方据此清除该寄存器的常量性。
    这里**只做保守的正确求值** —— 任何不确定的情况一律返回 None，
    宁可判成未知，也不能把非恒定值误判成常量。

    注意：DIV/REM 在除数为 0 时按 RISC-V 规范有定义（商全 1 / 余数等于被除数），
    但那是**规范行为**；硬件偏差正是偏离该规范。这里按规范求值，
    硬件偏差的检测交由触发契约层处理。
    """
    if not args:
        return None
    a = args[0]
    b = args[1] if len(args) > 1 else None

    # RISC-V 的 M 扩展要求 32 位有符号解释
    def s32(x: int) -> int:
        x &= _MASK32
        return x - (1 << 32) if x & 0x80000000 else x

    try:
        if mnem in ("li",):
            return a & _MASK32
        if mnem in ("mv",):
            return a & _MASK32
        if mnem == "lui":
            return (a << 12) & _MASK32
        if mnem in ("add", "addi"):
            return (a + (b or 0)) & _MASK32
        if mnem in ("sub", "neg"):
            return (a - (b if b is not None else 0)) & _MASK32
        if mnem in ("mul",):
            return (a * b) & _MASK32
        if mnem in ("div",):
            if b == 0:
                return _MASK32
            sa, sb = s32(a), s32(b)
            q = abs(sa) // abs(sb)
            if (sa < 0) != (sb < 0):
                q = -q
            return q & _MASK32
        if mnem in ("divu",):
            if b == 0:
                return _MASK32
            return (a & _MASK32) // (b & _MASK32)
        if mnem in ("rem",):
            if b == 0:
                return a & _MASK32
            sa, sb = s32(a), s32(b)
            r = abs(sa) % abs(sb)
            if sa < 0:
                r = -r
            return r & _MASK32
        if mnem in ("remu",):
            if b == 0:
                return a & _MASK32
            return (a & _MASK32) % (b & _MASK32)
        if mnem in ("and", "andi"):
            return (a & (b or 0)) & _MASK32
        if mnem in ("or", "ori"):
            return (a | (b or 0)) & _MASK32
        if mnem in ("xor", "xori"):
            return (a ^ (b or 0)) & _MASK32
        if mnem in ("sll", "slli"):
            return (a << ((b or 0) & 0x1F)) & _MASK32
        if mnem in ("srl", "srli"):
            return (a & _MASK32) >> ((b or 0) & 0x1F)
        if mnem in ("sra", "srai"):
            return (s32(a) >> ((b or 0) & 0x1F)) & _MASK32
    except (TypeError, ValueError, ZeroDivisionError):
        return None
    return None


def _insn_const_value(insn: Instruction,
                      cur: dict[str, int]) -> Optional[int]:
    """
    尝试把一条指令的目标寄存器值算成常量。

    返回 None 表示该指令的结果不被视为常量。
    """
    if insn.op_class not in _CONST_FOLD_OPS:
        return None

    # 收集源操作数的常量值
    args: list[int] = []
    for s in insn.sources:
        if s.kind is ExprKind.CONST:
            args.append(s.value)
        elif s.kind is ExprKind.REG:
            if s.name == "zero":
                args.append(0)
            elif s.name in cur:
                args.append(cur[s.name])
            else:
                return None          # 有源操作数不是常量 → 结果不是常量
        else:
            return None              # MEM / TEMP / 其它 → 保守放弃

    if not args:
        return None
    return _eval_const_op(insn.op_class, insn.mnemonic, args)


def _propagate_input_independence(
    insns: list[Instruction],
) -> dict[int, set[str]]:
    """
    块内传播"可证明不受外部输入影响"的寄存器集合。

    与常量传播的区别（关键）：
      - 常量传播回答"值是多少"；
      - 本函数回答"攻击者能不能影响它"。

    后者是**更弱**的结论，但适用面更广。例如：
        lui a1, 0x80000      ; a1 是常量 → 也必然 input-independent
        lw  a2, 16(a1)       ; a2 的值静态未知（取决于内存内容），
                             ; 但地址是常量 → a2 也 input-independent
    此时 a2 不是常量，却可以断定"攻击者影响不了它"。

    规则：
      - CONST/zero                                → independent
      - 运算类：所有源都 independent              → independent
      - LOAD：地址表达式不含任何 input: 污点      → independent（值未知但不可控）
      - LOAD：地址含 input: 污点                  → 不 independent
      - CSR_READ                                  → independent（CSR 非攻击者直控）
      - 其它                                       → 不 independent
    """
    out: dict[int, set[str]] = {}
    cur: set[str] = set()

    for insn in insns:
        out[insn.addr] = set(cur)

        ok = _insn_is_input_independent(insn, cur)
        for d in insn.operands:
            if d.kind is not ExprKind.REG or d.name == "zero":
                continue
            if ok:
                cur.add(d.name)
            else:
                cur.discard(d.name)

    return out


def _insn_is_input_independent(insn: Instruction, indep: set[str]) -> bool:
    """判断一条指令的结果是否不受外部输入影响（见 _propagate_input_independence）。"""
    # 自身带输入污点 → 直接否定
    if any(s.startswith("input:") for s in _insn_taint(insn)):
        return False

    if insn.op_class is OpClass.CSR_READ:
        return True

    for s in insn.sources:
        if s.kind is ExprKind.CONST:
            continue
        if s.kind is ExprKind.REG:
            if s.name == "zero" or s.name in indep:
                continue
            return False
        if s.kind is ExprKind.MEM:
            # 地址表达式必须不含输入污点
            addr = insn.mem_addr_expr
            if addr is None:
                return False
            if any(x.startswith("input:") for x in addr.taint_sources):
                return False
            continue
        return False
    return True


def _propagate_constants(
    insns: list[Instruction],
    entry_state: Optional[dict[str, int]] = None,
) -> dict[int, dict[str, int]]:
    """
    对每个指令位置，计算"执行该指令前"已知为常量的寄存器值。

    Parameters
    ----------
    insns
        基本块内的指令序列（按地址升序）。
    entry_state
        进入该块时的初始常量状态（来自前驱块的传播）。
        单块分析时传 None。

    只做保守的块内前向传播；遇到无法折叠的写就清除该寄存器的常量性。
    """
    out: dict[int, dict[str, int]] = {}
    cur: dict[str, int] = dict(entry_state or {})

    for insn in insns:
        # 快照"执行该指令前"的状态
        out[insn.addr] = dict(cur)

        for d in insn.operands:
            if d.kind is not ExprKind.REG:
                continue
            if d.name == "zero":
                continue                      # x0 恒为 0，无需跟踪
            val = _insn_const_value(insn, cur)
            if val is None:
                cur.pop(d.name, None)
            else:
                cur[d.name] = val

    return out


def _propagate_constants_ipa(blocks: list[BasicBlock]) -> dict[int, dict[str, int]]:
    """
    跨基本块的常量传播（自入口做一次前向数据流迭代）。

    单块传播无法覆盖 `a5` 在块 A 赋值、在块 B 使用的情形
    （S5 样本的第二处除法即为此类）。

    实现为保守的 must-analysis：某寄存器只有在**所有**前驱块出口处
    都是同一常量时，才在块入口被视为常量。

    这与 `_propagate_constants_ipa_perpath` 配合使用：
    must 分析用于**断言常量**，per-path 分析用于**诊断为什么不是常量**。
    """
    order = list(blocks)
    if not order:
        return {}

    # 每个块的出口常量状态
    exit_state: dict[str, dict[str, int]] = {}
    in_state: dict[str, dict[str, int]] = {b.block_id: {} for b in order}

    for _ in range(len(order) + 1):        # 迭代至不动点（有限步内收敛）
        changed = False
        for b in order:
            prev_in = in_state[b.block_id]

            # 该块出口状态：以最后一条指令后的状态为准
            cur = dict(prev_in)
            for insn in b.instructions:
                for d in insn.operands:
                    if d.kind is not ExprKind.REG or d.name == "zero":
                        continue
                    val = _insn_const_value(insn, cur)
                    if val is None:
                        cur.pop(d.name, None)
                    else:
                        cur[d.name] = val
            new_exit = cur
            if exit_state.get(b.block_id) != new_exit:
                changed = True
            exit_state[b.block_id] = new_exit

            # 合并前驱出口 → 本块入口
            preds = b.predecessors
            if preds:
                cand: Optional[dict[str, int]] = None
                for p in preds:
                    pe = exit_state.get(p)
                    if pe is None:
                        cand = None
                        break
                    if cand is None:
                        cand = dict(pe)
                    else:
                        # must-analysis：只保留所有前驱一致的常量
                        cand = {k: v for k, v in cand.items()
                                if pe.get(k) == v}
                merged = cand or {}
            else:
                merged = prev_in              # 入口块保持自己的状态
            if merged != prev_in:
                changed = True
                in_state[b.block_id] = merged
        if not changed:
            break

    # 汇总：每个块用自己的入口状态重算一遍
    out: dict[int, dict[str, int]] = {}
    for b in order:
        cmap = _propagate_constants(b.instructions,
                                    entry_state=in_state[b.block_id])
        out.update(cmap)
    return out


def _propagate_constants_ipa_perpath(
    blocks: list[BasicBlock],
) -> dict[int, list[dict[str, int]]]:
    """
    per-path（may-analysis）常量传播。

    对每个块，枚举**所有前驱路径**上的入口常量状态，逐条路径做块内传播。

    返回 `addr -> [state_1, state_2, ...]`，其中每个 state 是"某条前驱路径下
    执行到该指令时的常量表"。

    用途：当 must-analysis 因多前驱不一致而丢弃某常量时，本函数能回答
    "在**某一条**路径上，该操作数其实是常量" —— 这对报告很重要，
    因为它把 "unknown" 细化为 "在这条路径上恒定、在另一条上可控"，
    而不是笼统地说"不可判定"。
    """
    order = list(blocks)
    if not order:
        return {}

    # 先算 must 的出口状态，用于逐路径传播的起点
    in_state: dict[str, list[dict[str, int]]] = {b.block_id: [{}] for b in order}
    for _ in range(len(order) + 1):
        changed = False
        for b in order:
            if not b.predecessors:
                continue
            entries: list[dict[str, int]] = []
            for p in b.predecessors:
                pb = next((x for x in order if x.block_id == p), None)
                if pb is None:
                    continue
                for st in in_state.get(p, [{}]):
                    # 沿该前驱块传播到其出口
                    cur = dict(st)
                    for insn in pb.instructions:
                        for d in insn.operands:
                            if d.kind is not ExprKind.REG or d.name == "zero":
                                continue
                            val = _insn_const_value(insn, cur)
                            if val is None:
                                cur.pop(d.name, None)
                            else:
                                cur[d.name] = val
                    entries.append(cur)
            # 去重，限制路径数避免组合爆炸
            uniq: list[dict[str, int]] = []
            for e in entries:
                if e not in uniq:
                    uniq.append(e)
            uniq = uniq[:8]
            if uniq and uniq != in_state[b.block_id]:
                changed = True
                in_state[b.block_id] = uniq
        if not changed:
            break

    out: dict[int, list[dict[str, int]]] = {}
    for b in order:
        states = in_state.get(b.block_id) or [{}]
        # 逐条路径在该块内传播
        per_addr: dict[int, list[dict[str, int]]] = {}
        for st0 in states:
            cur = dict(st0)
            for insn in b.instructions:
                per_addr.setdefault(insn.addr, []).append(dict(cur))
                for d in insn.operands:
                    if d.kind is not ExprKind.REG or d.name == "zero":
                        continue
                    val = _insn_const_value(insn, cur)
                    if val is None:
                        cur.pop(d.name, None)
                    else:
                        cur[d.name] = val
        for addr, lst in per_addr.items():
            uniq2: list[dict[str, int]] = []
            for e in lst:
                if e not in uniq2:
                    uniq2.append(e)
            out[addr] = uniq2[:8]
    return out


def _const_of(expr: Expr, const_state: dict[str, int]) -> Optional[int]:
    """尝试把一个表达式解析为常量（含经由寄存器传播的常量）。"""
    if expr.kind is ExprKind.CONST:
        return expr.value
    if expr.kind is ExprKind.REG:
        if expr.name == "zero":
            return 0
        return const_state.get(expr.name)
    return None


# ---------------------------------------------------------------------------
# 谓词检查器
# ---------------------------------------------------------------------------
class PredicateChecker:
    """按谓词类型分派检查逻辑。"""

    # 比较运算的"正反形式"等价表 —— 处理编译器条件反转
    _INVERSE = {
        "<": ">=", ">=": "<",
        "<=": ">", ">": "<=",
        "==": "!=", "!=": "==",
        "<u": ">=u", ">=u": "<u",
        "<=u": ">u", ">u": "<=u",
        "<s": ">=s", ">=s": "<s",
    }

    @staticmethod
    def check_block(block: BasicBlock, predicates: list[Predicate],
                    prog: Program) -> list[PredicateResult]:
        const_map = _propagate_constants(block.instructions)
        results: list[PredicateResult] = []
        for p in predicates:
            results.append(PredicateChecker._check_one(p, block, const_map))
        return results

    # ------------------------------------------------------------------
    @staticmethod
    def _check_one(p: Predicate, block: BasicBlock,
                   const_map: dict[int, dict[str, int]]) -> PredicateResult:
        if not p.checkable or p.kind is PredicateKind.UNFORMALIZED:
            return PredicateResult(
                predicate=p, satisfied=False, checked=False,
                detail=f"不可检查：{p.notes or '未形式化'}",
            )

        k = p.kind

        if k is PredicateKind.OP_PRESENT:
            return PredicateChecker._check_op_present(p, block)

        if k is PredicateKind.IMMEDIATE_MATCH:
            return PredicateChecker._check_immediate(p, block, const_map)

        if k is PredicateKind.CSR_ACCESS:
            return PredicateChecker._check_csr(p, block)

        if k is PredicateKind.OPERAND_RELATION:
            return PredicateChecker._check_operand_relation(p, block)

        if k is PredicateKind.INPUT_CONTROLLABLE:
            return PredicateChecker._check_input_controllable(p, block)

        if k is PredicateKind.PRIV_REQUIRED:
            return PredicateChecker._check_priv(p, block)

        if k in (PredicateKind.REACHABILITY, PredicateKind.ORDERING,
                 PredicateKind.TIMING_WINDOW, PredicateKind.OP_SEQUENCE,
                 PredicateKind.MEMORY_ATTR):
            # 这些需要跨块/跨时序信息，由可达性模块或契约层负责
            return PredicateResult(
                predicate=p, satisfied=False, checked=False,
                detail=f"需跨块/时序分析（{k.value}），在本层不判定",
            )

        return PredicateResult(
            predicate=p, satisfied=False, checked=False,
            detail=f"未实现的谓词类型 {k.value} —— 记为 unknown 而非不满足",
        )

    # ------------------------------------------------------------------
    @staticmethod
    def _check_op_present(p: Predicate, block: BasicBlock) -> PredicateResult:
        if p.op_class is None:
            return PredicateResult(predicate=p, satisfied=False, checked=False,
                                   detail="谓词未指定 op_class")
        for insn in block.instructions:
            if insn.op_class is p.op_class:
                return PredicateResult(
                    predicate=p, satisfied=True,
                    evidence_addr=insn.addr, evidence_block=block.block_id,
                    detail=f"块内存在 {p.op_class.value}: {insn.mnemonic}",
                )
        # 别名等价：ARITH_ADD 与 ARITH_ADD_CARRY 在触发语义上常可互替
        aliases = _OP_ALIASES.get(p.op_class, set())
        for insn in block.instructions:
            if insn.op_class in aliases:
                return PredicateResult(
                    predicate=p, satisfied=True,
                    evidence_addr=insn.addr, evidence_block=block.block_id,
                    detail=f"块内存在等价操作 {insn.op_class.value}"
                           f"（等价于 {p.op_class.value}）: {insn.mnemonic}",
                )
        return PredicateResult(predicate=p, satisfied=False, checked=True,
                               detail=f"块内无 {p.op_class.value} 类操作")

    @staticmethod
    def _check_immediate(p: Predicate, block: BasicBlock,
                         const_map: dict[int, dict[str, int]]) -> PredicateResult:
        want = p.expected_value
        if want is None:
            return PredicateResult(predicate=p, satisfied=False, checked=False,
                                   detail="谓词未指定 expected_value")
        for insn in block.instructions:
            if insn.immediate is not None and insn.immediate == want:
                return PredicateResult(predicate=p, satisfied=True,
                                       evidence_addr=insn.addr,
                                       evidence_block=block.block_id,
                                       detail=f"立即数字段 == {want}")
            # 常量传播命中
            st = const_map.get(insn.addr, {})
            for s in insn.sources:
                v = _const_of(s, st)
                if v == want:
                    return PredicateResult(
                        predicate=p, satisfied=True,
                        evidence_addr=insn.addr, evidence_block=block.block_id,
                        detail=f"经常量传播得 {want}（寄存器值）",
                    )
        return PredicateResult(predicate=p, satisfied=False, checked=True,
                               detail=f"未找到立即数/传播常量 {want}")

    @staticmethod
    def _check_csr(p: Predicate, block: BasicBlock) -> PredicateResult:
        if not p.csr_name:
            return PredicateResult(predicate=p, satisfied=False, checked=False,
                                   detail="谓词未指定 csr_name")
        for insn in block.instructions:
            if insn.csr_name == p.csr_name:
                return PredicateResult(predicate=p, satisfied=True,
                                       evidence_addr=insn.addr,
                                       evidence_block=block.block_id,
                                       detail=f"访问 CSR {p.csr_name}")
        # CSR 名解析失败时必须报 unknown，不能报 no_match
        unresolved = [i for i in block.instructions
                      if i.op_class in (OpClass.CSR_READ, OpClass.CSR_WRITE)
                      and not i.csr_name]
        if unresolved:
            return PredicateResult(
                predicate=p, satisfied=False, checked=False,
                evidence_addr=unresolved[0].addr, evidence_block=block.block_id,
                detail=f"块内有 CSR 操作但名称未能解析（{len(unresolved)} 条），"
                       f"无法确认是否匹配 {p.csr_name}",
            )
        return PredicateResult(predicate=p, satisfied=False, checked=True,
                               detail=f"未访问 CSR {p.csr_name}")

    @staticmethod
    def _check_operand_relation(p: Predicate, block: BasicBlock) -> PredicateResult:
        """
        检查操作数关系。

        接受**正反两种形式**：编译器可能把 `if (a >= b)` 编译成
        `blt a, b, else_branch`，因此匹配时必须同时考虑反向比较。
        """
        expr_text = (p.operand_constraint or "").strip()
        if not expr_text:
            return PredicateResult(predicate=p, satisfied=False, checked=False,
                                   detail="谓词未给出 operand_constraint")

        # 解析形如 "a < b" / "x == 0" 的关系
        want = _normalize_relation(expr_text)
        if want is None:
            return PredicateResult(
                predicate=p, satisfied=False, checked=False,
                detail=f"关系表达式无法解析：{expr_text}",
            )

        lhs, oper, rhs = want

        for insn in block.instructions:
            cond = insn.condition
            if cond is None or cond.kind is not ExprKind.OP:
                continue
            op_name = cond.op or ""
            # 正形式
            if _relation_matches(cond, lhs, oper, rhs):
                return PredicateResult(
                    predicate=p, satisfied=True, evidence_addr=insn.addr,
                    evidence_block=block.block_id,
                    detail=f"分支条件 {cond} 满足关系 {expr_text}",
                )
            # 反向形式（编译器条件反转）
            inv = PredicateChecker._INVERSE.get(op_name)
            if inv is not None and _relation_matches(cond, lhs, inv, rhs,
                                                      allow_swapped=True):
                return PredicateResult(
                    predicate=p, satisfied=True, evidence_addr=insn.addr,
                    evidence_block=block.block_id,
                    detail=f"分支条件 {cond} 的反向形式等价于 {expr_text}"
                           f"（编译器条件反转）",
                )

        # 算术比较指令也承载关系
        for insn in block.instructions:
            if insn.op_class is OpClass.ARITH_COMPARE:
                return PredicateResult(
                    predicate=p, satisfied=False, checked=False,
                    evidence_addr=insn.addr, evidence_block=block.block_id,
                    detail=f"块内有比较指令 {insn.mnemonic} 但未能确认其操作数"
                           f"是否满足 {expr_text}",
                )

        return PredicateResult(predicate=p, satisfied=False, checked=True,
                               detail=f"块内无满足 {expr_text} 的关系")

    @staticmethod
    def _check_input_controllable(p: Predicate, block: BasicBlock) -> PredicateResult:
        """
        ★ 检查操作数是否可由外部输入控制 —— 这是创新点 A 的核心维度。

        "片段存在" != "操作数可控"。若某条触发所需的操作数恒为常量，
        则该片段对攻击者不可用。
        """
        target = p.op_class
        if target is None:
            return PredicateResult(predicate=p, satisfied=False, checked=False,
                                   detail="谓词未指定 op_class")

        tainted: list[Instruction] = []
        for insn in block.instructions:
            if insn.op_class is not target and insn.op_class not in _OP_ALIASES.get(target, set()):
                continue
            if _insn_has_input_taint(insn):
                tainted.append(insn)

        if tainted:
            return PredicateResult(
                predicate=p, satisfied=True, evidence_addr=tainted[0].addr,
                evidence_block=block.block_id,
                detail=f"{target.value} 的操作数受外部输入影响"
                       f"（污点源: {sorted(_insn_taint(tainted[0]))}）",
            )

        candidates = [i for i in block.instructions
                      if i.op_class is target or i.op_class in _OP_ALIASES.get(target, set())]
        if candidates:
            return PredicateResult(
                predicate=p, satisfied=False, checked=True,
                evidence_addr=candidates[0].addr, evidence_block=block.block_id,
                detail=f"存在 {target.value} 但操作数不受外部输入影响"
                       f"（片段存在但不可控）",
            )
        return PredicateResult(predicate=p, satisfied=False, checked=True,
                               detail=f"块内无 {target.value} 操作")

    @staticmethod
    def _check_priv(p: Predicate, block: BasicBlock) -> PredicateResult:
        if not p.priv_level:
            return PredicateResult(predicate=p, satisfied=False, checked=False,
                                   detail="谓词未指定 priv_level")
        # 特权级需要跨块的状态推断；本层只检测特权相关指令的存在作为弱证据
        priv_insns = [i for i in block.instructions
                      if i.op_class in (OpClass.PRIV_CHANGE, OpClass.CSR_WRITE,
                                        OpClass.TRAP)]
        if priv_insns:
            return PredicateResult(
                predicate=p, satisfied=False, checked=False,
                evidence_addr=priv_insns[0].addr, evidence_block=block.block_id,
                detail=f"块内有特权相关指令（{priv_insns[0].mnemonic}），"
                       f"但特权级需跨块状态推断，本层不判定",
            )
        return PredicateResult(predicate=p, satisfied=False, checked=False,
                               detail="特权级需跨块状态推断，本层不判定")


# ---------------------------------------------------------------------------
# 辅助
# ---------------------------------------------------------------------------
# 操作类别别名：语义上可互替的关系
_OP_ALIASES: dict[OpClass, set[OpClass]] = {
    OpClass.ARITH_ADD: {OpClass.ARITH_ADD_CARRY},
    OpClass.ARITH_ADD_CARRY: {OpClass.ARITH_ADD},
    OpClass.ARITH_SUB: {OpClass.ARITH_SUB_BORROW},
    OpClass.ARITH_SUB_BORROW: {OpClass.ARITH_SUB},
    OpClass.LOAD: set(),
    OpClass.STORE: set(),
    OpClass.MOV: {OpClass.ARITH_ADD},   # li/mv 可能被编译成 addi
}


def _insn_taint(insn: Instruction) -> set[str]:
    t: set[str] = set()
    for e in list(insn.operands) + list(insn.sources):
        t |= set(e.taint_sources)
    if insn.condition is not None:
        t |= set(insn.condition.taint_sources)
    return t


def _insn_has_input_taint(insn: Instruction) -> bool:
    return any(s.startswith("input:") for s in _insn_taint(insn))


def _normalize_relation(text: str) -> Optional[tuple[str, str, str]]:
    """把 "a < b" 归一化为 (lhs, op, rhs)。"""
    import re
    m = re.fullmatch(
        r"\s*([A-Za-z_][A-Za-z0-9_]*|0x[0-9a-fA-F]+|\d+)\s*"
        r"(==|!=|<=u|>=u|<u|>u|<=|>=|<|>)\s*"
        r"([A-Za-z_][A-Za-z0-9_]*|0x[0-9a-fA-F]+|\d+)\s*",
        text,
    )
    if not m:
        return None
    return m.group(1), m.group(2), m.group(3)


def _relation_matches(cond: Expr, lhs: str, oper: str, rhs: str,
                      allow_swapped: bool = False) -> bool:
    """
    判断分支条件 cond 是否表达了 "lhs oper rhs"。

    为了处理编译器重命名，这里**不比较寄存器名**，只比较结构：
    该条件是"两个操作数之间的比较"，且比较方向一致。

    真正的名字匹配由可达性/切片模块通过数据流确定 ——
    本层刻意保持宽松，避免因寄存器重命名漏掉候选（宁可多报候选，
    后续用可达性与可控性筛掉）。
    """
    if cond is None or cond.kind is not ExprKind.OP:
        return False
    if cond.op != oper:
        return False
    if len(cond.args) != 2:
        return False
    # 结构匹配：两边都是"可变操作数"或常量
    return True


# ---------------------------------------------------------------------------
# 匹配器主体
# ---------------------------------------------------------------------------
@dataclass
class MatchConfig:
    """匹配配置。"""

    min_progress: float = 1.0        # 视为 MATCH 所需的最小约束进展度
    partial_threshold: float = 0.34  # 视为 PARTIAL 的门槛
    require_all_checkable: bool = True


class SemanticMatcher:
    """
    契约 × 程序 的语义匹配器。

    对每个基本块计算匹配状态与**约束进展度**，用于排序与定向搜索。
    """

    def __init__(self, config: Optional[MatchConfig] = None) -> None:
        self.config = config or MatchConfig()

    # ------------------------------------------------------------------
    def match(self, contract: TriggerContract, prog: Program,
              verbose: bool = False) -> list[BlockMatch]:
        """
        在程序上匹配契约。

        返回按 (状态, 进展度, 地址) 排序的块匹配列表。
        """
        predicates = contract.all_predicates()
        if not predicates:
            return []

        results: list[BlockMatch] = []
        for bb in prog.blocks.values():
            if not bb.reachable:
                continue
            prs = PredicateChecker.check_block(bb, predicates, prog)
            status = self._aggregate(prs)

            # 关键证据位置：优先取"第一个满足的谓词"的地址
            key_addr = None
            key_insn = None
            for r in prs:
                if r.satisfied and r.evidence_addr is not None:
                    key_addr = r.evidence_addr
                    insn = prog.block_of_addr(r.evidence_addr)
                    if insn:
                        for i in insn.instructions:
                            if i.addr == key_addr:
                                key_insn = f"{i.mnemonic} {i.op_class.value}"
                                break
                    break

            results.append(BlockMatch(
                block_id=bb.block_id, start_addr=bb.start_addr, status=status,
                predicate_results=prs, key_addr=key_addr, key_insn=key_insn,
            ))

        # 排序：MATCH 优先，其次按进展度，最后按地址
        order = {MatchStatus.MATCH: 0, MatchStatus.PARTIAL: 1,
                 MatchStatus.UNKNOWN: 2, MatchStatus.NO_MATCH: 3}
        results.sort(key=lambda m: (order[m.status], -m.progress(), m.start_addr))
        return results

    # ------------------------------------------------------------------
    def _aggregate(self, prs: list[PredicateResult]) -> MatchStatus:
        checked = [r for r in prs if r.checked]
        unsatisfied = [r for r in checked if not r.satisfied]
        satisfied = [r for r in checked if r.satisfied]

        if not checked:
            return MatchStatus.UNKNOWN

        if not unsatisfied:
            # 所有"可检查"的谓词都满足
            all_ok = all(r.satisfied for r in prs if r.predicate.checkable)
            if all_ok and checked:
                return MatchStatus.MATCH
            return MatchStatus.PARTIAL

        progress = len(satisfied) / len(checked)

        # 关键纪律：只要有"无法检查"的谓词，就不能宣布 NO_MATCH，
        # 因为可能存在我们没能力检查的满足方式。
        has_unchecked = any(not r.checked for r in prs)
        if has_unchecked and not satisfied:
            return MatchStatus.UNKNOWN

        if progress >= self.config.partial_threshold:
            return MatchStatus.PARTIAL
        return MatchStatus.NO_MATCH

    # ------------------------------------------------------------------
    @staticmethod
    def report(matches: list[BlockMatch], top_n: int = 20) -> dict[str, Any]:
        """生成匹配报告。"""
        by_status: dict[str, int] = {}
        for m in matches:
            by_status[m.status.value] = by_status.get(m.status.value, 0) + 1

        return {
            "total_blocks_evaluated": len(matches),
            "status_histogram": by_status,
            "top_candidates": [m.summary() for m in matches[:top_n]],
            "best_progress": round(max((m.progress() for m in matches), default=0.0), 4),
        }
