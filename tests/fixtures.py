"""
构造可验证的测试固件（含已知 ground truth）

设计思路
--------
本模块用纯 Python 手工编码 RISC-V 机器码，构造若干**已知答案**的固件样本，
用于验证分析引擎的正确性。每个样本都明确：

  - 是否含有触发片段
  - 该片段是否可达
  - 操作数是否可由外部输入控制

这样就能对引擎做 Precision / Recall 的定量评估，而不是"看起来能跑"。

样本清单
--------
  S1  positive_controlled   片段存在 + 可达 + 操作数可控   → 期望 EXPLOITABLE_CANDIDATE
  S2  negative_constant     片段存在 + 可达 + 操作数常量   → 期望 PRESENT_BUT_UNCONTROLLABLE
  S3  negative_unreachable  片段存在 + 不可达              → 期望 PRESENT_BUT_UNREACHABLE
  S4  negative_absent       片段不存在                     → 期望 NOT_PRESENT
  S5  positive_multi        多个片段 + 含纠正路径          → 期望多个候选
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# RISC-V 编码辅助
# ---------------------------------------------------------------------------
OP_R = 0b0110011
OP_IMM = 0b0010011
OP_LOAD = 0b0000011
OP_STORE = 0b0100011
OP_BRANCH = 0b1100011
OP_JAL = 0b1101111
OP_JALR = 0b1100111
OP_LUI = 0b0110111
OP_SYSTEM = 0b1110011

R = {
    "zero": 0, "ra": 1, "sp": 2, "gp": 3, "tp": 4,
    "t0": 5, "t1": 6, "t2": 7, "s0": 8, "s1": 9,
    "a0": 10, "a1": 11, "a2": 12, "a3": 13, "a4": 14, "a5": 15,
    "a6": 16, "a7": 17, "s2": 18, "s3": 19, "s4": 20, "s5": 21,
    "s6": 22, "s7": 23, "s8": 24, "s9": 25, "s10": 26, "s11": 27,
    "t3": 28, "t4": 29, "t5": 30, "t6": 31,
}


def _r(f7, rs2, rs1, f3, rd, op=OP_R):
    return (f7 << 25) | (R[rs2] << 20) | (R[rs1] << 15) | (f3 << 12) | (R[rd] << 7) | op


def _i(imm, rs1, f3, rd, op=OP_IMM):
    return ((imm & 0xFFF) << 20) | (R[rs1] << 15) | (f3 << 12) | (R[rd] << 7) | op


def _s(imm, rs2, rs1, f3, op=OP_STORE):
    m = imm & 0xFFF
    return (((m >> 5) & 0x7F) << 25) | (R[rs2] << 20) | (R[rs1] << 15) | \
           (f3 << 12) | ((m & 0x1F) << 7) | op


def _b(imm, rs2, rs1, f3, op=OP_BRANCH):
    m = imm & 0x1FFF
    return (((m >> 12) & 1) << 31) | (((m >> 5) & 0x3F) << 25) | \
           (R[rs2] << 20) | (R[rs1] << 15) | (f3 << 12) | \
           (((m >> 1) & 0xF) << 8) | (((m >> 11) & 1) << 7) | op


def _j(imm, rd, op=OP_JAL):
    m = imm & 0x1FFFFF
    return (((m >> 20) & 1) << 31) | (((m >> 1) & 0x3FF) << 21) | \
           (((m >> 11) & 1) << 20) | (((m >> 12) & 0xFF) << 12) | \
           (R[rd] << 7) | op


# 指令简写
def LW(rd, rs1, imm):  return _i(imm, rs1, 0b010, rd, OP_LOAD)
def LH(rd, rs1, imm):  return _i(imm, rs1, 0b001, rd, OP_LOAD)
def LB(rd, rs1, imm):  return _i(imm, rs1, 0b000, rd, OP_LOAD)
def SW(rs2, rs1, imm): return _s(imm, rs2, rs1, 0b010)
def SH(rs2, rs1, imm): return _s(imm, rs2, rs1, 0b001)
def SB(rs2, rs1, imm): return _s(imm, rs2, rs1, 0b000)
def ADDI(rd, rs1, imm): return _i(imm, rs1, 0b000, rd)
def ANDI(rd, rs1, imm): return _i(imm, rs1, 0b111, rd)
def ORI(rd, rs1, imm):  return _i(imm, rs1, 0b110, rd)
def XORI(rd, rs1, imm): return _i(imm, rs1, 0b100, rd)
def SLLI(rd, rs1, sh):  return _i(sh, rs1, 0b001, rd)
def SRLI(rd, rs1, sh):  return _i(sh, rs1, 0b101, rd)
def SLTI(rd, rs1, imm): return _i(imm, rs1, 0b010, rd)
def SLTIU(rd, rs1, imm):return _i(imm, rs1, 0b011, rd)
def ADD(rd, rs1, rs2):  return _r(0b0000000, rs2, rs1, 0b000, rd)
def SUB(rd, rs1, rs2):  return _r(0b0100000, rs2, rs1, 0b000, rd)
def SLL(rd, rs1, rs2):  return _r(0b0000000, rs2, rs1, 0b001, rd)
def SLT(rd, rs1, rs2):  return _r(0b0000000, rs2, rs1, 0b010, rd)
def SLTU(rd, rs1, rs2): return _r(0b0000000, rs2, rs1, 0b011, rd)
def XOR(rd, rs1, rs2):  return _r(0b0000000, rs2, rs1, 0b100, rd)
def SRL(rd, rs1, rs2):  return _r(0b0000000, rs2, rs1, 0b101, rd)
def SRA(rd, rs1, rs2):  return _r(0b0100000, rs2, rs1, 0b101, rd)
def OR(rd, rs1, rs2):   return _r(0b0000000, rs2, rs1, 0b110, rd)
def AND(rd, rs1, rs2):  return _r(0b0000000, rs2, rs1, 0b111, rd)
def MUL(rd, rs1, rs2):  return _r(0b0000001, rs2, rs1, 0b000, rd)
def MULH(rd, rs1, rs2): return _r(0b0000001, rs2, rs1, 0b001, rd)
def DIV(rd, rs1, rs2):  return _r(0b0000001, rs2, rs1, 0b100, rd)
def DIVU(rd, rs1, rs2): return _r(0b0000001, rs2, rs1, 0b101, rd)
def REM(rd, rs1, rs2):  return _r(0b0000001, rs2, rs1, 0b110, rd)
def REMU(rd, rs1, rs2): return _r(0b0000001, rs2, rs1, 0b111, rd)
def BEQ(rs1, rs2, off): return _b(off, rs2, rs1, 0b000)
def BNE(rs1, rs2, off): return _b(off, rs2, rs1, 0b001)
def BLT(rs1, rs2, off): return _b(off, rs2, rs1, 0b100)
def BGE(rs1, rs2, off): return _b(off, rs2, rs1, 0b101)
def BLTU(rs1, rs2, off):return _b(off, rs2, rs1, 0b110)
def BGEU(rs1, rs2, off):return _b(off, rs2, rs1, 0b111)
def J(off):             return _j(off, "zero")
def RET():              return _i(0, "ra", 0b000, "zero", OP_JALR)
def JALR(rd, rs1, imm): return _i(imm, rs1, 0b000, rd, OP_JALR)
def LUI(rd, imm):       return ((imm & 0xFFFFF) << 12) | (R[rd] << 7) | OP_LUI
def NOP():              return ADDI("zero", "zero", 0)
def EBREAK():           return 0x00100073
def ECALL():            return 0x00000073
def CSRRW(rd, csr, rs1):return ((csr & 0xFFF) << 20) | (R[rs1] << 15) | (0b001 << 12) | (R[rd] << 7) | OP_SYSTEM
def CSRRS(rd, csr, rs1):return ((csr & 0xFFF) << 20) | (R[rs1] << 15) | (0b010 << 12) | (R[rd] << 7) | OP_SYSTEM


def pack(*insns: int) -> bytes:
    return b"".join(struct.pack("<I", i) for i in insns)


# ---------------------------------------------------------------------------
# 触发契约的目标：我们假设硬件存在一个"除法器边界条件偏差"
# 触发条件（硬件侧反推所得，等价于 Microscope 的输出）：
#   1. 执行一次 DIVU（无符号除法）
#   2. 除数为 0（硬件未按规范返回全 1，而是产生错误结果）
#   3. 被除数可由外部输入控制
#   4. 结果被写回内存（传播到安全资产）
# ---------------------------------------------------------------------------
@dataclass
class Sample:
    name: str
    blob: bytes
    base_addr: int = 0x80000000
    expected_verdicts: list[str] = field(default_factory=list)
    description: str = ""
    notes: list[str] = field(default_factory=list)
    # ★ 该样本在二分类指标（Precision/Recall）里算不算"可利用正样本"。
    #
    # 为什么需要这个字段：有些样本考查的**不是**可利用性，而是
    # 另一条性质（比如"间接跳转目标不得被误判为不可达"）。
    # 这类样本的 expected_verdicts 会列多个可接受判定，
    # 若把它们当成"正样本"，就会在 Precision/Recall 里
    # 制造出根本不存在的假阴性。
    #
    # 取值：
    #   "exploitable"    —— 正样本，计入 TP/FP/FN
    #   "unexploitable"  —— 负样本，计入 TN/FP/FN
    #   "excluded"       —— 只计入逐样本正确性，不计入二分类指标
    binary_label: str = "unexploitable"

    @property
    def is_exploitable_positive(self) -> bool:
        return self.binary_label == "exploitable"

    @property
    def counts_for_binary(self) -> bool:
        return self.binary_label in ("exploitable", "unexploitable")


# ---------------------------------------------------------------------------
def sample_positive_controlled() -> Sample:
    """
    S1：片段存在 + 可达 + 操作数可控。

    脚本：
      entry:
        lw   a1, 0(a0)        ; a1 = 输入缓冲区[0]     ← 外部输入污染
        andi a2, a1, 0xff     ; a2 = 长度字段（可控）
        li   a3, 0            ; a3 = 0                  ← 除数为 0（触发条件）
        divu a4, a2, a3       ; ★ 触发点
        sw   a4, 16(a0)       ; 结果写回（传播到内存）
        ret
    """
    return Sample(
        name="S1_positive_controlled",
        blob=pack(
            LW("a1", "a0", 0),
            ANDI("a2", "a1", 0xFF),
            ADDI("a3", "zero", 0),
            DIVU("a4", "a2", "a3"),
            SW("a4", "a0", 16),
            RET(),
        ),
        expected_verdicts=["exploitable_candidate"],
        description="片段存在、可达、操作数（被除数）由外部输入控制",
        binary_label="exploitable",
    )


def sample_negative_constant() -> Sample:
    """
    S2：片段存在 + 可达，但操作数**恒为常量**。

    脚本：
      entry:
        li   a2, 100          ; a2 = 100 常量
        li   a3, 5            ; a3 = 5   常量
        divu a4, a2, a3       ; ★ 操作存在，但操作数都是常量
        ret

    期望：PRESENT_BUT_UNCONTROLLABLE —— 攻击者无法影响操作数，
    因此该硬件偏差在此固件上不可利用。
    """
    return Sample(
        name="S2_negative_constant",
        blob=pack(
            ADDI("a2", "zero", 100),
            ADDI("a3", "zero", 5),
            DIVU("a4", "a2", "a3"),
            RET(),
        ),
        expected_verdicts=["present_but_uncontrollable"],
        description="片段存在但操作数恒为常量",
    )


def sample_negative_unreachable() -> Sample:
    """
    S3：片段存在但**不可达**（死代码）。

    脚本：
      entry:
        0x00  j    +8              ; 直接跳到 0x08
        0x04  addi a2, zero, 1     ; ← 死代码（被跳过）
        0x08  j    +8              ; 跳过下面的 divu，直达末尾
        0x0c  divu a4, a2, a3      ; ★ 永远执行不到
        0x10  ret

    布局说明（关键）：
      RISC-V 的 J 型偏移是相对**当前指令地址**的字节数。
      0x00 处 `j +8`  → 目标 0x08（跳过 0x04 的 addi）
      0x08 处 `j +8`  → 目标 0x10（跳过 0x0c 的 divu，落到 ret）
    因此 0x0c 的 divu 不可从入口到达。
    """
    return Sample(
        name="S3_negative_unreachable",
        blob=pack(
            J(8),                   # 0x00 → 0x08
            ADDI("a2", "zero", 1),  # 0x04 死代码
            J(8),                   # 0x08 → 0x10
            DIVU("a4", "a2", "a3"), # 0x0c ★ 不可达
            RET(),                  # 0x10
        ),
        expected_verdicts=["present_but_unreachable", "not_present"],
        description="片段存在但无法从入口到达（死代码）",
    )


def sample_negative_absent() -> Sample:
    """
    S4：完全不含触发片段（对照组）。

    脚本：仅做加法和内存写，无除法。
    """
    return Sample(
        name="S4_negative_absent",
        blob=pack(
            LW("a1", "a0", 0),
            ADDI("a2", "a1", 1),
            SW("a2", "a0", 8),
            ADD("a3", "a1", "a2"),
            RET(),
        ),
        expected_verdicts=["not_present"],
        description="不含任何除法操作（阴性对照）",
    )


def sample_positive_multi() -> Sample:
    """
    S5：多个可控触发点 + 一条纠正路径。

    脚本含两次除法：一次操作数可控（真候选），
    一次常量（假候选）；并有一个"检查结果是否异常"的分支（纠正路径雏形）。
    """
    return Sample(
        name="S5_positive_multi",
        blob=pack(
            LW("a1", "a0", 0),          # 0x00  输入
            ANDI("a2", "a1", 0xFF),     # 0x04  可控长度
            ADDI("a3", "zero", 0),      # 0x08  除数 = 0
            DIVU("a4", "a2", "a3"),     # 0x0c  ★ 候选 1（可控）
            BEQ("a4", "zero", 12),      # 0x10  纠正路径：若结果为 0 则跳过写入
            SW("a4", "a0", 16),         # 0x14  写回
            ADDI("a5", "zero", 64),     # 0x18  常量
            ADDI("a6", "zero", 8),      # 0x1c  常量
            DIVU("a7", "a5", "a6"),     # 0x20  ★ 候选 2（常量，不可控）
            RET(),                      # 0x24
        ),
        expected_verdicts=["exploitable_candidate", "present_but_uncontrollable"],
        description="两个除法点：一个可控、一个常量；含纠正路径分支",
        binary_label="exploitable",
    )


# ---------------------------------------------------------------------------
# 以下为**对抗性**样本：专门用于探测假阳性
# 一个安全分析工具最危险的失败模式不是漏报，而是把不可利用的情形
# 报成"可行候选"。这些样本就是针对这一点的。
# ---------------------------------------------------------------------------
def sample_neg_folded_chain() -> Sample:
    """
    S6：常量经过**多级折叠链**后成为操作数 —— 必须仍然判为不可控。

    脚本：
      addi a1, zero, 20       ; a1 = 20
      addi a2, a1, 30         ; a2 = 50     （经 a1 折叠）
      slli a3, a2, 2          ; a3 = 200    （经 a2 折叠）
      andi a4, a3, 0xFF       ; a4 = 200    （经 a3 折叠）
      divu a5, a4, a3         ; ★ 两个操作数都是折叠常量
      ret

    这是对常量传播深度的直接测试。若传播只做一层，a4/a3 会被判为
    "未知"进而可能误报为候选。
    """
    return Sample(
        name="S6_neg_folded_chain",
        blob=pack(
            ADDI("a1", "zero", 20),
            ADDI("a2", "a1", 30),
            SLLI("a3", "a2", 2),
            ANDI("a4", "a3", 0xFF),
            DIVU("a5", "a4", "a3"),
            RET(),
        ),
        expected_verdicts=["present_but_uncontrollable"],
        description="常量经多级折叠链后作为操作数（传播深度测试）",
    )


def sample_pos_partial_control() -> Sample:
    """
    S7：**只有一个**操作数可控 —— 仍应判为可行候选。

    脚本：
      lw   a1, 0(a0)         ; a1 = 输入
      andi a4, a1, 0xFF      ; a4 = 可控被除数
      li   a3, 0             ; a3 = 0 常量除数 → 触发条件恒成立
      divu a5, a4, a3        ; ★ 被除数可控 + 除数恒 0
      ret

    触发条件的关键在于**除数恒为 0**（由常量保证），
    而攻击者只需控制被除数。此时"部分操作数可控"就足以触发，
    不应因为除数不可控而判为不可利用。
    """
    return Sample(
        name="S7_pos_partial_control",
        blob=pack(
            LW("a1", "a0", 0),
            ANDI("a4", "a1", 0xFF),
            ADDI("a3", "zero", 0),
            DIVU("a5", "a4", "a3"),
            RET(),
        ),
        expected_verdicts=["exploitable_candidate"],
        description="仅被除数可控、除数恒为 0（部分可控即可触发）",
        binary_label="exploitable",
    )


def sample_neg_load_derived() -> Sample:
    """
    S8：操作数来自常量地址的 **load** —— 语义上是只读常量表。

    脚本：
      lui  a1, 0x80000       ; a1 = 0x80000000（常量基址）
      lw   a2, 16(a1)        ; a2 = 常量表中的值（非攻击者可控）
      li   a3, 4
      divu a4, a2, a3        ; ★ 被除数来自 const 表，不可控
      ret

    要点：`lw` 的基址是常量 LUI，不是污染输入。
    若污点分析错误地把"任何 load 结果"都视为可控，就会误报。
    """
    return Sample(
        name="S8_neg_load_derived",
        blob=pack(
            LUI("a1", 0x80000),
            LW("a2", "a1", 16),
            ADDI("a3", "zero", 4),
            DIVU("a4", "a2", "a3"),
            RET(),
        ),
        # 两种可接受的答案：
        #   not_controllable     —— 引擎的精确结论（值未知但攻击者影响不了）
        #   present_but_uncontrollable —— 更粗但方向一致的结论
        # 二者都表示"不可利用"；把 not_controllable 单独列出是更优的，
        # 因为它不谎称"这是常量"。
        expected_verdicts=["not_controllable",
                           "present_but_uncontrollable"],
        description="操作数来自常量地址 load（非攻击者可控）",
    )


def sample_pos_two_entries() -> Sample:
    """
    S9：触发点位于**第二个输入入口**的可达路径上。

    脚本：
      entry:
        lw   a1, 0(a0)
        li   a2, 8
        bne  a1, a2, +12       ; a1 != 8 则跳到 去触发
        ret                    ; a1 == 8 直接返回（不触发）
        divu a4, a1, a1        ; ★ 触发点（a1 可控）
        ret
    """
    return Sample(
        name="S9_pos_branch_guarded",
        blob=pack(
            LW("a1", "a0", 0),
            ADDI("a2", "zero", 8),
            BNE("a1", "a2", 8),     # 0x08 -> 跳到 0x10
            RET(),                  # 0x0c
            DIVU("a4", "a1", "a1"), # 0x10 ★
            RET(),                  # 0x14
        ),
        expected_verdicts=["exploitable_candidate"],
        description="触发点受分支条件保护，仍可从输入入口到达",
        binary_label="exploitable",
    )


def sample_neg_dead_after_ret() -> Sample:
    """
    S10：触发点位于 `ret` **之后**（函数外死代码）。

    脚本：
      entry:
        ret                    ; 0x00 直接返回
        divu a4, a1, a2        ; 0x04 ★ 永远不可达
        divu a5, a1, a2        ; 0x08 ★ 永远不可达
    """
    return Sample(
        name="S10_neg_dead_after_ret",
        blob=pack(
            RET(),
            DIVU("a4", "a1", "a2"),
            DIVU("a5", "a1", "a2"),
        ),
        expected_verdicts=["present_but_unreachable"],
        description="ret 之后的死代码，两处触发点均不可达",
    )


def sample_neg_self_zeroed() -> Sample:
    """
    S11：操作数先被输入污染，但随后被**常量覆盖** —— 最终不可控。

    脚本：
      lw   a1, 0(a0)         ; a1 = 输入（污染）
      li   a1, 64            ; a1 被常量覆盖 → 污染失效
      li   a2, 8
      divu a4, a1, a2        ; ★ 两个操作数最终都是常量
      ret

    这是对"污点清除（taint kill）"正确性的测试。
    若污点只累加不清除，a1 会被误判为可控 → 假阳性。
    """
    return Sample(
        name="S11_neg_taint_killed",
        blob=pack(
            LW("a1", "a0", 0),
            ADDI("a1", "zero", 64),   # 覆盖，清除污点
            ADDI("a2", "zero", 8),
            DIVU("a4", "a1", "a2"),
            RET(),
        ),
        expected_verdicts=["present_but_uncontrollable"],
        description="污点被后续常量赋值清除（taint kill 测试）",
    )


def sample_pos_indirect_call_table() -> Sample:
    """
    S12：触发点在**间接跳转目标**上 —— 测间接跳转解析（防假阴性）。

    脚本（地址从 0x80000000 起，每条 4 字节）：
      0x00  lui  a1, 0x80000          ; a1 = 0x80000000（表基址的高 20 位）
      0x04  addi a2, zero, 0          ; a2 = 0
      0x08  lw   t0, 24(a1)           ; t0 = 表项(0x80000018) ← 间接目标
      0x0c  jalr zero, t0, 0          ; ★ 间接跳转 → 应连到 0x80000018
      0x10  ret                       ; 不该走的路径
      0x14  ret
      0x18  divu a4, a2, a2           ; ★ 触发点，仅在间接跳转解析后可达
      0x1c  ret

    为什么要这个样本
    ----------------
    旧实现遇到 `jalr` 只连 fall-through(+4)，于是 0x18 变成"不可达"，
    触发点被漏报 —— 这是**假阴性**。安全工具的假阴性意味着
    "我说安全，其实不安全"，是比假阳性更严重的错误。

    期望：触发点被解析为可达（exploitable_candidate 或
    present_but_uncontrollable 都接受 —— 关键是"可达性没丢"）。
    """
    return Sample(
        name="S12_pos_indirect_jump_table",
        blob=pack(
            LUI("a1", 0x80000),          # 0x00
            ADDI("a2", "zero", 0),       # 0x04
            LW("t0", "a1", 24),          # 0x08  表项 → 0x80000018
            JALR("zero", "t0", 0),       # 0x0c  间接跳转
            RET(),                       # 0x10
            RET(),                       # 0x14
            DIVU("a4", "a2", "a2"),      # 0x18  ★ 触发点
            RET(),                       # 0x1c
        ),
        expected_verdicts=[
            "exploitable_candidate",
            "present_but_uncontrollable",
            "path_dependent",
        ],
        description="触发点位于间接跳转（跳转表）目标上 —— 间接跳转解析测试",
        notes=[
            "本样本考查的是【不可达块不应被误报为不可达】",
            "若解析失败，0x18 会被标成 present_but_unreachable（假阴性）",
        ],
        # 本样本考查的是**可达性保真**，不是可利用性 ——
        # 计入二分类会让"没有误报不可达"被误算成可利用性假阴性。
        binary_label="excluded",
    )


def sample_pos_indirect_pointer() -> Sample:
    """
    S13：间接跳转目标不在跳转表模式内 —— 测兜底策略。

    脚本：
      0x00  lw   t0, 0(a0)        ; t0 = 输入读入的值（真·函数指针）
      0x04  jalr ra, t0, 0        ; ★ 目标完全动态，无法静态解析
      0x08  ret
      0x0c  divu a4, a1, a1       ; ★ 触发点
      0x10  ret

    这种情形静态无法确定目标。若直接丢弃，0x0c 会变"不可达"。
    本工程的兜底策略把"是分支目标但当前不可达的块"也接上，
    以过近似换取不漏报。

    期望：不能判定为 present_but_unreachable（那会是假阴性）。
    接受 present_but_uncontrollable / not_controllable / path_dependent
    / unknown 等一切"未断言不可达"的结论。
    """
    return Sample(
        name="S13_pos_indirect_pointer",
        blob=pack(
            LW("t0", "a0", 0),           # 0x00  从输入取函数指针
            JALR("ra", "t0", 0),         # 0x04  完全动态的间接跳转
            RET(),                       # 0x08
            DIVU("a4", "a1", "a1"),      # 0x0c  ★ 触发点
            RET(),                       # 0x10
        ),
        expected_verdicts=[
            "exploitable_candidate",
            "present_but_uncontrollable",
            "not_controllable",
            "path_dependent",
            "unknown",
        ],
        description="完全动态的函数指针间接跳转 —— 兜底策略测试（不得误报不可达）",
        notes=[
            "本样本断言的是【不得报 present_but_unreachable】，"
            "而不是断言它一定可利用",
        ],
        # 同上：考查可达性保真，不计入可利用性二分类
        binary_label="excluded",
    )


ALL_SAMPLES = [
    sample_positive_controlled,
    sample_negative_constant,
    sample_negative_unreachable,
    sample_negative_absent,
    sample_positive_multi,
    sample_neg_folded_chain,
    sample_pos_partial_control,
    sample_neg_load_derived,
    sample_pos_two_entries,
    sample_neg_dead_after_ret,
    sample_neg_self_zeroed,
    sample_pos_indirect_call_table,
    sample_pos_indirect_pointer,
]


def write_samples(out_dir: str | Path) -> list[tuple[Sample, Path]]:
    """把样本写成 .bin 文件。"""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written: list[tuple[Sample, Path]] = []
    for f in ALL_SAMPLES:
        s = f()
        p = out / f"{s.name}.bin"
        p.write_bytes(s.blob)
        written.append((s, p))
    return written

if __name__ == "__main__":
    import sys
    out = sys.argv[1] if len(sys.argv) > 1 else "samples"
    for s, p in write_samples(out):
        print(f"{p}  ({len(s.blob)} bytes)  {s.description}")
