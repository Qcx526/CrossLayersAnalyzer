"""
跨层漏洞分析 —— 统一中间表示 (Unified IR)

设计目标
--------
把不同 ISA 的指令提升为一个**架构无关的语义表示**，使得：

1. 硬件侧反推出的"触发模式"可以用 IR 表达，与具体 ISA 解耦；
2. 固件侧的指令片段也可以用同一套 IR 表达，从而可以**语义匹配**；
3. 匹配建立在数据依赖语义上，而非指令序列的语法形式 —— 这是应对
   编译器优化（常量折叠、指令重排、条件反转、指令合并）的关键。

设计原则
--------
- **保守优于激进**：无法确定语义的操作标记为 UNKNOWN，绝不猜测。
- **显式记录不确定性**：每个操作携带 `confidence` 与 `notes`，
  拒绝把"看起来像"当成"就是"。
- **可求解**：表达式用 z3 的 AST 构建，直接可用于约束求解。
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Optional, Sequence

import z3


# ---------------------------------------------------------------------------
# 操作类别 —— 硬件触发契约与固件片段匹配时的第一层筛选依据
# ---------------------------------------------------------------------------
class OpClass(enum.Enum):
    """
    架构无关的操作类别。

    这是 HW-SCM 反推出的"触发模式"与固件指令片段之间的**公共词汇表**。
    硬件侧说"需要一次带进位的加法"，固件侧说"有一条 ADDC"，两者在
    OpClass.ARITH_ADD_CARRY 上相遇。

    粒度选择原则：**足够粗以跨 ISA 复用，足够细以表达硬件触发条件**。
    """

    # --- 数据搬运 ---
    LOAD = "load"                    # 内存读
    STORE = "store"                  # 内存写
    MOV = "mov"                      # 寄存器间/立即数搬运

    # --- 算术 ---
    ARITH_ADD = "arith_add"
    ARITH_SUB = "arith_sub"
    ARITH_ADD_CARRY = "arith_add_carry"    # 带进位加（常见于多精度运算，硬件易在此出偏差）
    ARITH_SUB_BORROW = "arith_sub_borrow"
    ARITH_MUL = "arith_mul"
    ARITH_DIV = "arith_div"                # 除零/溢出是硬件偏差高发点
    ARITH_REM = "arith_rem"
    ARITH_SHIFT = "arith_shift"
    ARITH_COMPARE = "arith_compare"        # 产生标志/条件

    # --- 逻辑 ---
    LOGIC_AND = "logic_and"
    LOGIC_OR = "logic_or"
    LOGIC_XOR = "logic_xor"
    LOGIC_NOT = "logic_not"

    # --- 控制流 ---
    BRANCH = "branch"                # 条件跳转
    JUMP = "jump"                    # 无条件跳转
    CALL = "call"                    # 函数调用
    RETURN = "return"
    TRAP = "trap"                    # 异常/陷阱/ecall/ebreak

    # --- 特权与系统 ---
    CSR_READ = "csr_read"
    CSR_WRITE = "csr_write"
    PRIV_CHANGE = "priv_change"      # 特权级切换（mret/sret）
    FENCE = "fence"
    CACHE_OP = "cache_op"            # 缓存维护指令

    # --- 其他 ---
    NOP = "nop"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# 表达式：基于 z3 的符号表达式
# ---------------------------------------------------------------------------
class ExprKind(enum.Enum):
    """表达式节点类型。用显式 AST 而非直接塞 z3 对象，
    是为了便于序列化、切片和人类审阅。"""

    CONST = "const"          # 字面常量
    REG = "reg"              # 寄存器读取（ISA 级）
    MEM = "mem"              # 内存读取
    TEMP = "temp"            # IR 临时值
    INPUT = "input"          # ★ 外部输入（攻击者可控的源）
    OP = "op"                # 运算
    UNKNOWN = "unknown"      # 无法确定


@dataclass
class Expr:
    """
    IR 表达式节点。

    `is_tainted_input` 标记该表达式的值是否可能来源于外部输入 ——
    这是**操作数可控性**分析的基础（创新点 A 的核心维度）。
    """

    kind: ExprKind
    name: str = ""                                   # 寄存器名 / 临时值名 / 输入名
    value: Optional[int] = None                      # 常量值
    width: int = 32
    op: Optional[str] = None                         # 运算名（ExprKind.OP 时）
    args: tuple["Expr", ...] = ()                    # 子表达式
    taint_sources: frozenset[str] = frozenset()      # ★ 污点源集合

    # ------------------------------------------------------------------
    def is_input_tainted(self) -> bool:
        """该表达式是否可达外部输入。"""
        return len(self.taint_sources) > 0

    def is_concrete(self) -> bool:
        """是否是完全确定的常量（可静态求值）。"""
        return self.kind is ExprKind.CONST

    def __str__(self) -> str:
        if self.kind is ExprKind.CONST:
            return f"0x{self.value:x}" if self.value is not None else "const?"
        if self.kind in (ExprKind.REG, ExprKind.TEMP, ExprKind.INPUT):
            return self.name
        if self.kind is ExprKind.MEM:
            base = self.args[0] if self.args else None
            return f"mem[{base}]"
        if self.kind is ExprKind.OP:
            return f"{self.op}({', '.join(str(a) for a in self.args)})"
        return "?"

    def __repr__(self) -> str:
        return f"Expr({self})"


def const(v: int, width: int = 32) -> Expr:
    return Expr(kind=ExprKind.CONST, value=v & ((1 << width) - 1), width=width)


def reg(name: str, width: int = 32) -> Expr:
    return Expr(kind=ExprKind.REG, name=name, width=width)


def temp(name: str, width: int = 32, taint: Iterable[str] = ()) -> Expr:
    return Expr(kind=ExprKind.TEMP, name=name, width=width,
                taint_sources=frozenset(taint))


def input_var(name: str, width: int = 32) -> Expr:
    """外部输入 —— 攻击者可控的符号源。"""
    return Expr(kind=ExprKind.INPUT, name=name, width=width,
                taint_sources=frozenset({name}))


def op(name: str, *args: Expr, width: int = 32) -> Expr:
    """构造运算表达式，自动合并子表达式的污点。"""
    taint: set[str] = set()
    for a in args:
        taint |= set(a.taint_sources)
    return Expr(kind=ExprKind.OP, op=name, args=tuple(args), width=width,
                taint_sources=frozenset(taint))


def mem(base: Expr, width: int = 32) -> Expr:
    return Expr(kind=ExprKind.MEM, args=(base,), width=width,
                taint_sources=base.taint_sources)


# ---------------------------------------------------------------------------
# 指令
# ---------------------------------------------------------------------------
@dataclass
class Instruction:
    """
    一条已提升为 IR 的指令。

    同时保留原始信息（地址、原始字节、助记符）与 IR 语义。
    """

    addr: int                                # 原始地址（必须保留，用于定位）
    size: int                                # 字节长度
    mnemonic: str                            # 原始助记符
    opcode_bytes: bytes                      # 原始字节（用于身份校验）
    op_class: OpClass                        # ★ 架构无关的操作类别
    operands: tuple[Expr, ...] = ()          # 目标（写）
    sources: tuple[Expr, ...] = ()           # 源（读）
    reads_regs: frozenset[str] = frozenset()
    writes_regs: frozenset[str] = frozenset()

    # --- 语义细节（供硬件触发契约匹配）---
    is_conditional: bool = False             # 是否条件执行
    condition: Optional[Expr] = None         # 条件表达式（分支类）
    immediate: Optional[int] = None          # 立即数字段（若有）
    mem_addr_expr: Optional[Expr] = None     # 访存地址表达式
    csr_name: Optional[str] = None           # CSR 名（CSR 类指令）
    priv_level: Optional[str] = None         # 执行所需特权级

    # --- 诚实性字段 ---
    confidence: float = 1.0                  # 语义理解置信度
    notes: str = ""                          # 不确定之处必须写明

    def __str__(self) -> str:
        return f"0x{self.addr:08x}: {self.mnemonic}  [{self.op_class.value}]"


# ---------------------------------------------------------------------------
# 函数与基本块
# ---------------------------------------------------------------------------
@dataclass
class BasicBlock:
    """基本块 —— 单入口单出口的指令序列。"""

    block_id: str
    start_addr: int
    end_addr: int
    instructions: list[Instruction] = field(default_factory=list)

    # 控制流
    successors: list[str] = field(default_factory=list)
    predecessors: list[str] = field(default_factory=list)

    # 数据流摘要（用于快速筛选）
    reads_regs: frozenset[str] = frozenset()
    writes_regs: frozenset[str] = frozenset()
    op_classes: frozenset[OpClass] = frozenset()

    # 标记
    is_entry: bool = False
    reachable: bool = False
    is_corrective: bool = False     # ★ 纠正路径（看门狗/CRC/重试）标记

    def recompute_summary(self) -> None:
        reads: set[str] = set()
        writes: set[str] = set()
        ops: set[OpClass] = set()
        for insn in self.instructions:
            reads |= set(insn.reads_regs)
            writes |= set(insn.writes_regs)
            ops.add(insn.op_class)
        self.reads_regs = frozenset(reads)
        self.writes_regs = frozenset(writes)
        self.op_classes = frozenset(ops)


@dataclass
class Function:
    """函数（可能来自符号表，也可能是启发式识别）。"""

    func_id: str
    name: str
    entry_addr: int
    blocks: list[str] = field(default_factory=list)     # block_id 列表
    is_external_entry: bool = False                     # 是否为外部输入入口
    entry_kind: str = ""                                # uart / usb / isr / main ...
    symbol_source: str = "heuristic"                    # symbol_table / heuristic / manual


# ---------------------------------------------------------------------------
# 程序（CFG 的整体容器）
# ---------------------------------------------------------------------------
@dataclass
class Program:
    """
    一个已提升的固件程序。

    `blocks` 是 CFG 的主索引；`functions` 是按函数组织的视图；
    `inputs` 记录外部输入入口。
    """

    name: str
    arch: str                       # riscv32 / arm / ...
    base_addr: int = 0
    entry_addr: int = 0

    blocks: dict[str, BasicBlock] = field(default_factory=dict)
    functions: dict[str, Function] = field(default_factory=dict)
    addr_to_block: dict[int, str] = field(default_factory=dict)

    # 外部输入入口：名字 → 地址（或符号名）
    inputs: dict[str, int] = field(default_factory=dict)

    # 统计
    stats: dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------
    def block_of_addr(self, addr: int) -> Optional[BasicBlock]:
        bid = self.addr_to_block.get(addr)
        return self.blocks.get(bid) if bid else None

    def all_instructions(self) -> Iterable[Instruction]:
        for b in self.blocks.values():
            yield from b.instructions

    def find_instructions(self, op_classes: Iterable[OpClass]) -> list[Instruction]:
        """按操作类别筛选指令 —— 匹配器的第一层过滤。"""
        want = set(op_classes)
        return [i for i in self.all_instructions() if i.op_class in want]

    def summary(self) -> dict[str, Any]:
        n_insn = sum(len(b.instructions) for b in self.blocks.values())
        op_hist: dict[str, int] = {}
        for i in self.all_instructions():
            op_hist[i.op_class.value] = op_hist.get(i.op_class.value, 0) + 1
        return {
            "name": self.name,
            "arch": self.arch,
            "blocks": len(self.blocks),
            "functions": len(self.functions),
            "instructions": n_insn,
            "inputs": len(self.inputs),
            "op_histogram": dict(sorted(op_hist.items(), key=lambda kv: -kv[1])),
            "stats": self.stats,
        }
