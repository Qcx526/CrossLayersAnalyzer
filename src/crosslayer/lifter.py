"""
跨层漏洞分析 —— RISC-V 指令提升 (ISA → Unified IR)

把 RISC-V 机器码提升为 `ir.Instruction`，并提取：

- 架构无关的操作类别 (OpClass)
- 操作数（目标/源）
- 寄存器读写集合
- ★ 污点传播：哪个寄存器的值来自外部输入

污点模型
--------
外部输入通过约定命名的寄存器/内存位置注入（例如 a0 保存来自 UART 的字节）。
`Lifter.input_regs` 指定哪些寄存器是"输入承载寄存器"。

一个寄存器一旦被标记为 input-tainted，其污点会随 MOV/算术/访存地址传播，
直到被可见常量覆盖为止。这构成**操作数可控性**分析的基础。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional

from capstone import Cs, CS_ARCH_RISCV, CS_MODE_RISCV32, CS_MODE_RISCV64
from capstone import CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_RET, CS_GRP_INT, CS_GRP_IRET

from .ir import (
    Instruction, OpClass, Expr, ExprKind,
    const, reg, temp, input_var, op as mkop, mem as mkmem,
)

# ---------------------------------------------------------------------------
# 操作类别映射
# ---------------------------------------------------------------------------
# 说明：这里用助记符前缀匹配而非完整枚举。RISC-V 的助记符体系规整
# （lw/lb/lh、add/addi/addw、beq/bne/blt...），前缀匹配足够可靠，
# 且能在出现新扩展时优雅退化（落到 UNKNOWN 而不是崩掉）。
_MNEMONIC_TO_OPCLASS: dict[str, OpClass] = {
    # 载入
    "lb": OpClass.LOAD, "lh": OpClass.LOAD, "lw": OpClass.LOAD,
    "lbu": OpClass.LOAD, "lhu": OpClass.LOAD, "ld": OpClass.LOAD, "lwu": OpClass.LOAD,
    "lr": OpClass.LOAD,
    # 存储
    "sb": OpClass.STORE, "sh": OpClass.STORE, "sw": OpClass.STORE,
    "sd": OpClass.STORE, "sc": OpClass.STORE,
    # 搬运
    "mv": OpClass.MOV, "li": OpClass.MOV, "lui": OpClass.MOV, "auipc": OpClass.MOV,
    "la": OpClass.MOV,
    # 算术
    "add": OpClass.ARITH_ADD, "addi": OpClass.ARITH_ADD, "addw": OpClass.ARITH_ADD,
    "addiw": OpClass.ARITH_ADD,
    "sub": OpClass.ARITH_SUB, "subw": OpClass.ARITH_SUB, "neg": OpClass.ARITH_SUB,
    "adc": OpClass.ARITH_ADD_CARRY, "sbc": OpClass.ARITH_SUB_BORROW,
    "mul": OpClass.ARITH_MUL, "mulh": OpClass.ARITH_MUL, "mulhu": OpClass.ARITH_MUL,
    "mulhsu": OpClass.ARITH_MUL, "mulw": OpClass.ARITH_MUL,
    "div": OpClass.ARITH_DIV, "divu": OpClass.ARITH_DIV, "divw": OpClass.ARITH_DIV,
    "divuw": OpClass.ARITH_DIV,
    "rem": OpClass.ARITH_REM, "remu": OpClass.ARITH_REM,
    "remw": OpClass.ARITH_REM, "remuw": OpClass.ARITH_REM,
    "sll": OpClass.ARITH_SHIFT, "slli": OpClass.ARITH_SHIFT,
    "srl": OpClass.ARITH_SHIFT, "srli": OpClass.ARITH_SHIFT,
    "sra": OpClass.ARITH_SHIFT, "srai": OpClass.ARITH_SHIFT,
    "sllw": OpClass.ARITH_SHIFT, "slliw": OpClass.ARITH_SHIFT,
    "srlw": OpClass.ARITH_SHIFT, "srliw": OpClass.ARITH_SHIFT,
    "sraw": OpClass.ARITH_SHIFT, "sraiw": OpClass.ARITH_SHIFT,
    "slt": OpClass.ARITH_COMPARE, "slti": OpClass.ARITH_COMPARE,
    "sltu": OpClass.ARITH_COMPARE, "sltiu": OpClass.ARITH_COMPARE,
    "seqz": OpClass.ARITH_COMPARE, "snez": OpClass.ARITH_COMPARE,
    "sltz": OpClass.ARITH_COMPARE, "sgtz": OpClass.ARITH_COMPARE,
    # 逻辑
    "and": OpClass.LOGIC_AND, "andi": OpClass.LOGIC_AND,
    "or": OpClass.LOGIC_OR, "ori": OpClass.LOGIC_OR,
    "xor": OpClass.LOGIC_XOR, "xori": OpClass.LOGIC_XOR,
    "not": OpClass.LOGIC_NOT,
    # 控制流
    "beq": OpClass.BRANCH, "bne": OpClass.BRANCH, "blt": OpClass.BRANCH,
    "bge": OpClass.BRANCH, "bltu": OpClass.BRANCH, "bgeu": OpClass.BRANCH,
    "beqz": OpClass.BRANCH, "bnez": OpClass.BRANCH,
    "blez": OpClass.BRANCH, "bgez": OpClass.BRANCH,
    "bltz": OpClass.BRANCH, "bgtz": OpClass.BRANCH,
    "j": OpClass.JUMP, "jal": OpClass.JUMP, "jalr": OpClass.JUMP,
    "jr": OpClass.JUMP,
    "call": OpClass.CALL,
    "ret": OpClass.RETURN,
    "ecall": OpClass.TRAP, "ebreak": OpClass.TRAP,
    # 特权
    "csrr": OpClass.CSR_READ, "csrw": OpClass.CSR_WRITE,
    "csrs": OpClass.CSR_WRITE, "csrc": OpClass.CSR_WRITE,
    "csrrw": OpClass.CSR_WRITE, "csrrs": OpClass.CSR_WRITE,
    "csrrc": OpClass.CSR_WRITE, "csrrwi": OpClass.CSR_WRITE,
    "csrrsi": OpClass.CSR_WRITE, "csrrci": OpClass.CSR_WRITE,
    "mret": OpClass.PRIV_CHANGE, "sret": OpClass.PRIV_CHANGE,
    "uret": OpClass.PRIV_CHANGE, "wfi": OpClass.PRIV_CHANGE,
    "fence": OpClass.FENCE, "fence.i": OpClass.FENCE,
    "cbo.clean": OpClass.CACHE_OP, "cbo.flush": OpClass.CACHE_OP,
    "cbo.inval": OpClass.CACHE_OP, "cbo.zero": OpClass.CACHE_OP,
    # 空操作
    "nop": OpClass.NOP,
}

# 前缀表：按长度降序，保证 "addiw" 先于 "add" 匹配
_SORTED_PREFIXES = sorted(_MNEMONIC_TO_OPCLASS.items(), key=lambda kv: -len(kv[0]))


def mnemonic_to_opclass(mnem: str) -> OpClass:
    m = mnem.lower().strip()
    if m in _MNEMONIC_TO_OPCLASS:
        return _MNEMONIC_TO_OPCLASS[m]
    for pfx, oc in _SORTED_PREFIXES:
        if m.startswith(pfx):
            return oc
    return OpClass.UNKNOWN


# ---------------------------------------------------------------------------
# 分支条件构造
# ---------------------------------------------------------------------------
_BRANCH_COND_OPS = {
    "beq": "==", "beqz": "==",
    "bne": "!=", "bnez": "!=",
    "blt": "<s", "bltz": "<s", "bltu": "<u",
    "bge": ">=s", "bgez": ">=s", "bgeu": ">=u",
    "blez": "<=s", "bgtz": ">s",
}


@dataclass
class LiftResult:
    """提升结果。"""

    instructions: list[Instruction]
    unknown_count: int
    total_count: int

    def unknown_ratio(self) -> float:
        return self.unknown_count / self.total_count if self.total_count else 0.0


class RiscvLifter:
    """
    RISC-V 指令提升器。

    Parameters
    ----------
    bits : 32 | 64
    input_regs : 承载外部输入的寄存器名集合。
        例如 UART 接收路径中，a0/a1 可能承载来自线上的数据。
        这些寄存器被标记为污点源。
    input_mem : 承载外部输入的内存地址（若已知），用于识别
        "从固定缓冲区载入"这类模式。
    """

    # RISC-V 寄存器别名（ABI 名 → 语义名）
    _ABI = {
        "zero": "zero", "ra": "ra", "sp": "sp", "gp": "gp", "tp": "tp",
        "t0": "t0", "t1": "t1", "t2": "t2",
        "s0": "s0", "s1": "s1",
        "a0": "a0", "a1": "a1", "a2": "a2", "a3": "a3",
        "a4": "a4", "a5": "a5", "a6": "a6", "a7": "a7",
        "s2": "s2", "s3": "s3", "s4": "s4", "s5": "s5",
        "s6": "s6", "s7": "s7", "s8": "s8", "s9": "s9",
        "s10": "s10", "s11": "s11",
        "t3": "t3", "t4": "t4", "t5": "t5", "t6": "t6",
    }

    def __init__(self, bits: int = 32,
                 input_regs: Iterable[str] = ("a0", "a1"),
                 input_mem: Iterable[int] = ()) -> None:
        mode = CS_MODE_RISCV32 if bits == 32 else CS_MODE_RISCV64
        self.md = Cs(CS_ARCH_RISCV, mode)
        self.md.detail = True
        self.bits = bits
        self.input_regs = set(input_regs)
        self.input_mem = set(input_mem)
        # 污点状态：寄存器 → 污点源集合（模拟执行时维护）
        self._reg_taint: dict[str, frozenset[str]] = {
            r: frozenset({f"input:{r}"}) for r in self.input_regs
        }

    # ------------------------------------------------------------------
    def _reg_expr(self, name: str) -> Expr:
        """构造寄存器表达式，附带当前污点状态。"""
        taint = self._reg_taint.get(name, frozenset())
        e = reg(name, self.bits)
        e.taint_sources = taint
        return e

    def _set_reg_taint(self, name: str, new_taint: frozenset[str]) -> None:
        """
        更新寄存器污点。

        zero 寄存器永远是 0，必须清污点 —— 否则会错误地把
        "与 zero 比较"当成"可控操作数"。
        """
        if name == "zero":
            self._reg_taint[name] = frozenset()
        else:
            self._reg_taint[name] = new_taint

    def reset_taint(self) -> None:
        self._reg_taint = {r: frozenset({f"input:{r}"}) for r in self.input_regs}

    # ------------------------------------------------------------------
    def lift_range(self, data: bytes, base_addr: int) -> LiftResult:
        """提升一段机器码。"""
        out: list[Instruction] = []
        unknown = 0

        for insn in self.md.disasm(data, base_addr):
            mnem = insn.mnemonic
            opc = mnemonic_to_opclass(mnem)

            operands_raw = list(insn.operands)
            reads: set[str] = set()
            writes: set[str] = set()
            srcs: list[Expr] = []
            dsts: list[Expr] = []
            imm: Optional[int] = None
            mem_addr_expr: Optional[Expr] = None
            csr_name: Optional[str] = None
            condition: Optional[Expr] = None
            is_cond = False
            notes = ""
            confidence = 1.0

            # ------ 解析操作数 ------
            # RISC-V 的操作数语义规则（按指令类别）：
            #   R-type  : rd, rs1, rs2          → 第 1 个是目标
            #   I-type  : rd, rs1, imm          → 第 1 个是目标
            #   LOAD    : rd, imm(rs1)          → MEM 操作数是**源**（地址），rd 是目标
            #   STORE   : rs2, imm(rs1)         → 全部是**源**，无目标
            #   BRANCH  : rs1, rs2, target      → 全部是源，最后一个是跳转偏移（**不是比较值**）
            #   JAL     : rd, target            → rd 是目标，target 是偏移
            #   不做"第一条 REG 就是目标"的一刀切，那会在 STORE/BRANCH 上出错。
            try:
                srcs, dsts, reads, writes, mem_addr_expr, imm, cond_info = \
                    self._parse_operands(insn, operands_raw, opc, mnem)
            except Exception as e:  # pragma: no cover
                notes = f"操作数解析异常: {type(e).__name__}"
                confidence = 0.5
                srcs, dsts, reads, writes = [], [], set(), set()
                mem_addr_expr, imm, cond_info = None, None, None

            # ------ 分支条件（用解析阶段返回的 cond_info，避免把跳转偏移当比较值）-----
            is_cond = False
            condition: Optional[Expr] = None
            if opc is OpClass.BRANCH:
                is_cond = True
                cop = _BRANCH_COND_OPS.get(mnem)
                if cop and cond_info is not None:
                    a, b = cond_info
                    condition = Expr(kind=ExprKind.OP, op=cop, args=(a, b),
                                     width=self.bits,
                                     taint_sources=a.taint_sources | b.taint_sources)
                else:
                    notes = (notes + "; " if notes else "") + "分支条件未能解析"

            # ------ CSR 名 ------
            if opc in (OpClass.CSR_READ, OpClass.CSR_WRITE):
                csr_name = self._extract_csr(insn)
                if not csr_name:
                    notes = (notes + "; " if notes else "") + "CSR 名未能解析（影响契约匹配精度）"
                    confidence = min(confidence, 0.7)

            # ------ 无法识别 ------
            if opc is OpClass.UNKNOWN:
                unknown += 1
                notes = (notes + "; " if notes else "") + "未识别指令，语义未知"
                confidence = 0.0            # ------ 更新污点状态（模拟执行）------
            if opc is OpClass.LOAD:
                # 载入：若地址自身受污点影响，则载入值视为可控
                taint = mem_addr_expr.taint_sources if mem_addr_expr else frozenset()
                if taint:
                    taint = frozenset(list(taint) + ["input:mem"])
                for d in dsts:
                    self._set_reg_taint(d.name, taint)
            elif opc in (OpClass.ARITH_ADD, OpClass.ARITH_SUB, OpClass.ARITH_ADD_CARRY,
                         OpClass.ARITH_SUB_BORROW, OpClass.ARITH_MUL, OpClass.ARITH_DIV,
                         OpClass.ARITH_REM, OpClass.ARITH_SHIFT, OpClass.ARITH_COMPARE,
                         OpClass.LOGIC_AND, OpClass.LOGIC_OR, OpClass.LOGIC_XOR,
                         OpClass.LOGIC_NOT, OpClass.MOV):
                taint = self._merge_taint(srcs)
                for d in dsts:
                    self._set_reg_taint(d.name, taint)
            elif opc in (OpClass.CSR_READ,):
                for d in dsts:
                    self._set_reg_taint(d.name, frozenset())  # CSR 值非攻击者可控
            else:
                for d in dsts:
                    self._set_reg_taint(d.name, frozenset())

            # ------ 立即数型算术的污点（寄存器 op 立即数）------
            # 已在上面 ARITH_* 分支统一处理

            out.append(Instruction(
                addr=insn.address,
                size=insn.size,
                mnemonic=mnem,
                opcode_bytes=bytes(insn.bytes),
                op_class=opc,
                operands=tuple(dsts),
                sources=tuple(srcs),
                reads_regs=frozenset(reads - {w for w in writes}),
                writes_regs=frozenset(writes),
                is_conditional=is_cond,
                condition=condition,
                immediate=imm,
                mem_addr_expr=mem_addr_expr,
                csr_name=csr_name,
                confidence=confidence,
                notes=notes,
            ))

        return LiftResult(instructions=out, unknown_count=unknown, total_count=len(out))

    # ------------------------------------------------------------------
    def _parse_operands(self, insn, operands_raw, opc: OpClass, mnem: str):
        """
        按指令类别的语义规则解析操作数。

        返回 (srcs, dsts, reads, writes, mem_addr_expr, imm, cond_info)

        与"第一条寄存器就是目标"的朴素做法相比，这里区分了：
        - STORE: 所有操作数都是源（含地址基址），无目标
        - BRANCH: 所有操作数都是源；**最后一个立即数是跳转偏移，不参与条件比较**
        - LOAD: MEM 操作数是源（地址），rd 是目标
        - JAL/JUMP: rd 是目标，立即数是跳转偏移
        """
        # 常量操作数类型（capstone 5.x 的 RISC-V 常量）
        T_REG = 1   # RISCV_OP_REG
        T_IMM = 2   # RISCV_OP_IMM
        T_MEM = 3   # RISCV_OP_MEM

        srcs: list[Expr] = []
        dsts: list[Expr] = []
        reads: set[str] = set()
        writes: set[str] = set()
        mem_addr_expr: Optional[Expr] = None
        imm: Optional[int] = None
        cond_info = None

        def reg_name(o):
            try:
                if o.type == T_REG and o.reg:
                    return self.md.reg_name(o.reg)
            except Exception:
                pass
            return None

        def base_name(o):
            try:
                if o.type == T_MEM and o.mem.base:
                    return self.md.reg_name(o.mem.base)
            except Exception:
                pass
            return None

        def disp_of(o):
            try:
                if o.type == T_MEM:
                    return int(getattr(o.mem, "disp", 0) or 0)
            except Exception:
                pass
            return 0

        def mem_expr(o) -> Expr:
            bn = base_name(o)
            d = disp_of(o)
            if bn:
                be = self._reg_expr(bn)
                return mkop("add", be, const(d, self.bits), width=self.bits) if d else be
            return const(d, self.bits)

        # ---- 1. 按类别决定操作数角色 ----
        if opc is OpClass.STORE:
            # 所有操作数都是源；MEM 操作数给出目标地址
            for o in operands_raw:
                if o.type == T_REG:
                    rn = reg_name(o)
                    if rn:
                        reads.add(rn)
                        srcs.append(self._reg_expr(rn))
                elif o.type == T_MEM:
                    bn = base_name(o)
                    if bn:
                        reads.add(bn)
                    mem_addr_expr = mem_expr(o)
                    # ★ 内存位移也要记进 immediate。
                    # 跳转表识别（CFG 的间接跳转解析）依赖 `lw t0, off(base)`
                    # 的 off 来算出表项地址；旧实现只对 T_IMM 记 imm，
                    # 于是 `lw t0, 24(a1)` 的 24 丢失，表地址算不出来。
                    d = disp_of(o)
                    if d and imm is None:
                        imm = d
                    srcs.append(mkmem(mem_addr_expr, self.bits))
                elif o.type == T_IMM:
                    imm = int(o.imm)
                    srcs.append(const(imm, self.bits))

        elif opc is OpClass.BRANCH:
            # 所有操作数都是源；最后的 IMM 是跳转偏移 —— 不参与条件
            imm_like: list[int] = []
            regs: list[Expr] = []
            for o in operands_raw:
                if o.type == T_REG:
                    rn = reg_name(o)
                    if rn:
                        reads.add(rn)
                        e = self._reg_expr(rn)
                        regs.append(e)
                        srcs.append(e)
                elif o.type == T_IMM:
                    imm_like.append(int(o.imm))
                    srcs.append(const(int(o.imm), self.bits))
            # 比较双方取自寄存器；不足两个时补 zero
            if len(regs) >= 2:
                cond_info = (regs[0], regs[1])
            elif len(regs) == 1:
                cond_info = (regs[0], const(0, self.bits))
            # 记录分支目标偏移（供 CFG 使用，不是比较值）
            imm = imm_like[-1] if imm_like else None

        elif opc in (OpClass.JUMP, OpClass.CALL, OpClass.RETURN):
            # jal rd, off  /  jalr rd, rs1, off  /  j off  /  jr rs  /  ret
            #
            # ★ 关键陷阱：capstone 会把伪指令折叠，操作数个数随助记符而变：
            #     `jalr rd, rs1, off`  → [rd, rs1, imm]   （3 个）
            #     `jr rs`              → [rs]             （1 个）
            #     `ret`                → []               （0 个）
            # 旧实现用"索引 0 且是 JUMP/CALL 就是链接寄存器"一刀切，
            # 于是 `jr t0` 的 t0 被当成目标吃掉，sources 变空 ——
            # 间接跳转的目标寄存器彻底丢失，CFG 无法解析，触发点被误判为不可达。
            #
            # 正确判据：**只有存在第二个寄存器操作数时，第一个才是链接寄存器**。
            reg_operands = [o for o in operands_raw if o.type == T_REG]
            has_link = len(reg_operands) >= 2
            for i, o in enumerate(operands_raw):
                if o.type == T_REG:
                    rn = reg_name(o)
                    if not rn:
                        continue
                    if i == 0 and has_link and opc in (OpClass.JUMP, OpClass.CALL):
                        # 第一个寄存器是链接寄存器（目标）
                        if rn != "zero":
                            writes.add(rn)
                            e = reg(rn, self.bits)
                            e.taint_sources = frozenset()
                            dsts.append(e)
                    else:
                        # 其余寄存器都是**跳转目标寄存器**（源）
                        reads.add(rn)
                        srcs.append(self._reg_expr(rn))
                elif o.type == T_IMM:
                    imm = int(o.imm)
                    srcs.append(const(imm, self.bits))

        elif opc in (OpClass.CSR_READ, OpClass.CSR_WRITE):
            # csrrw rd, csr, rs1   → rd 是目标；rs1 是源
            for i, o in enumerate(operands_raw):
                if o.type == T_REG:
                    rn = reg_name(o)
                    if rn:
                        if i == 0:
                            if rn != "zero":
                                writes.add(rn)
                                e = reg(rn, self.bits)
                                e.taint_sources = frozenset()
                                dsts.append(e)
                        else:
                            reads.add(rn)
                            srcs.append(self._reg_expr(rn))
                elif o.type == T_IMM:
                    imm = int(o.imm)
                    srcs.append(const(imm, self.bits))

        else:
            # R-type / I-type / LOAD / 算术逻辑：第一个 REG/MEM 是目标
            dst_taken = False
            for o in operands_raw:
                if not dst_taken and o.type in (T_REG, T_MEM):
                    dst_taken = True
                    if o.type == T_REG:
                        rn = reg_name(o)
                        if rn:
                            if rn != "zero":
                                writes.add(rn)
                                e = reg(rn, self.bits)
                                e.taint_sources = self._merge_taint(srcs)
                                dsts.append(e)
                    else:  # 不可能：LOAD 的目标是 REG
                        pass
                elif o.type == T_REG:
                    rn = reg_name(o)
                    if rn:
                        reads.add(rn)
                        srcs.append(self._reg_expr(rn))
                elif o.type == T_IMM:
                    imm = int(o.imm)
                    srcs.append(const(imm, self.bits))
                elif o.type == T_MEM:
                    bn = base_name(o)
                    if bn:
                        reads.add(bn)
                    mem_addr_expr = mem_expr(o)
                    # ★ 内存位移也要记进 immediate。
                    # 跳转表识别（CFG 的间接跳转解析）依赖 `lw t0, off(base)`
                    # 的 off 来算出表项地址；旧实现只对 T_IMM 记 imm，
                    # 于是 `lw t0, 24(a1)` 的 24 丢失，表地址算不出来。
                    d = disp_of(o)
                    if d and imm is None:
                        imm = d
                    srcs.append(mkmem(mem_addr_expr, self.bits))

            # 目标表达式的污点需要包含 MEM 地址的污点（LOAD 的地址可控）
            if dsts and srcs:
                t = self._merge_taint(srcs)
                for d in dsts:
                    d.taint_sources = t

        return srcs, dsts, reads, writes, mem_addr_expr, imm, cond_info

    # ------------------------------------------------------------------
    @staticmethod
    def _merge_taint(srcs: Iterable[Expr]) -> frozenset[str]:
        t: set[str] = set()
        for s in srcs:
            if s.kind is ExprKind.CONST:      # 常量不引入污点
                continue
            t |= set(s.taint_sources)
        return frozenset(t)

    def _reg_name(self, operand) -> Optional[str]:
        """从 capstone operand 取寄存器名。"""
        try:
            if operand.type == 1:  # REG
                rid = operand.reg
                name = self.md.reg_name(rid)
                return name
        except Exception:
            return None
        return None

    def _mem_base_reg(self, operand) -> Optional[str]:
        try:
            if operand.type == 3:  # MEM
                base = operand.mem.base
                if base:
                    return self.md.reg_name(base)
        except Exception:
            return None
        return None

    def _extract_csr(self, insn) -> Optional[str]:
        """
        提取 CSR 名。

        capstone 对 RISC-V CSR 的支持随版本差异较大，
        因此从反汇编文本中做稳健提取，失败则返回 None（不猜）。
        """
        try:
            txt = f"{insn.mnemonic} {insn.op_str}"
            # 形如 "csrrw a0, mstatus, a1"
            parts = [p.strip() for p in insn.op_str.split(",")]
            for p in parts:
                if p.startswith(("m", "s", "u")) and not p.startswith(("mi", "si", "ui")):
                    if p in _KNOWN_CSRS:
                        return p
            for csr in _KNOWN_CSRS:
                if csr in txt:
                    return csr
        except Exception:
            pass
        return None


# 常见 CSR 名（用于契约匹配；不在此表内的 CSR 不猜测）
_KNOWN_CSRS = {
    "mstatus", "misa", "medeleg", "mideleg", "mie", "mtvec", "mscratch",
    "mepc", "mcause", "mtval", "mip", "mtinst", "mtval2",
    "mcycle", "minstret", "mhartid", "mvendorid", "marchid", "mimpid",
    "mcountinhibit", "mhpmevent3",
    "sstatus", "sie", "stvec", "sscratch", "sepc", "scause", "stval", "sip", "satp",
    "pmpcfg0", "pmpcfg1", "pmpcfg2", "pmpcfg3",
    "pmpaddr0", "pmpaddr1", "pmpaddr2", "pmpaddr3",
    "pmpaddr4", "pmpaddr5", "pmpaddr6", "pmpaddr7",
}


def lift_firmware(image, bits: Optional[int] = None,
                  input_regs: Iterable[str] = ("a0", "a1")) -> LiftResult:
    """
    对 FirmwareImage 的所有可执行段做提升。

    注意：段之间的地址连续性不做假设，每段独立提升。
    """
    if bits is None:
        bits = 64 if "64" in (image.arch or "") else 32

    lifter = RiscvLifter(bits=bits, input_regs=input_regs)
    all_insns: list[Instruction] = []
    total_unknown = 0
    total = 0

    for seg in image.executable_segments():
        lifter.reset_taint()
        r = lifter.lift_range(seg.data, seg.vaddr)
        all_insns.extend(r.instructions)
        total_unknown += r.unknown_count
        total += r.total_count

    all_insns.sort(key=lambda i: i.addr)
    return LiftResult(instructions=all_insns, unknown_count=total_unknown, total_count=total)
