"""
编码器自校验：用 capstone 反汇编我们自己编码的机器码，确认编码器正确。

这是最关键的元测试 —— 如果编码器错了，所有 ground truth 都不成立，
后续对分析引擎的准确性评估也就失去意义。

比较方式说明
------------
capstone 的 `op_str` 是**给人看的字符串**：它把立即数写成十六进制，
并且会做伪指令别名（`addi x0,x0,0` → `nop`、`jalr x0,0(ra)` → `ret`、
`addi a2,a1,0` → `mv`、`csrrs rd,csr,x0` → `csrr`）。

因此字符串比较会把**格式差异**误判成**编码错误**。
正确做法是比较 **mnemonic 类别 + 数值**：
  - mnemonic 通过别名等价表归一化
  - 立即数一律按十进制数值比较（不比较书写进制）
"""

from __future__ import annotations

import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "src"))

from capstone import CS_ARCH_RISCV, CS_MODE_RISCV32, Cs  # noqa: E402

import fixtures as F  # noqa: E402

# ---------------------------------------------------------------------------
# 伪指令展开
# ---------------------------------------------------------------------------
# capstone 会把一些编码折叠成伪指令显示，操作数也随之省略或改名。
# 校验时必须先把伪指令**展开**回真实编码的语义。
ALIAS = {
    "nop": "addi",
    "ret": "jalr",
    "mv": "addi",
    "j": "jal",
    "csrr": "csrrs",
    "not": "xori",
    "neg": "sub",
    "seqz": "sltiu",
    "snez": "sltu",
}

# CSR 名 → 地址，用于把 capstone 打印的 `mstatus` 还原成数值
CSR_ADDR = {
    "mstatus": 0x300, "misa": 0x301, "medeleg": 0x302, "mideleg": 0x303,
    "mie": 0x304, "mtvec": 0x305, "mscratch": 0x340, "mepc": 0x341,
    "mcause": 0x342, "mtval": 0x343, "mip": 0x344,
    "mcycle": 0xB00, "minstret": 0xB02, "mhartid": 0xF14,
    "sstatus": 0x100, "sie": 0x104, "stvec": 0x105, "sscratch": 0x140,
    "sepc": 0x141, "scause": 0x142, "stval": 0x143, "sip": 0x144,
    "satp": 0x180,
}


def canon_mnem(m: str) -> str:
    return ALIAS.get(m, m)


def expand_pseudo(mnem: str, ops: list[str]) -> list[str]:
    """
    把伪指令的操作数补全为真实指令的操作数。

    nop             -> addi x0, x0, 0
    ret             -> jalr x0, 0(ra)
    mv rd, rs       -> addi rd, rs, 0
    j off           -> jal x0, off
    csrr rd, csr    -> csrrs rd, csr, x0
    """
    if mnem == "nop":
        return ["zero", "zero", "0"]
    if mnem == "ret":
        return ["zero", "0(ra)"]
    if mnem == "mv" and len(ops) == 2:
        return [ops[0], ops[1], "0"]
    if mnem == "j" and len(ops) == 1:
        return ["zero", ops[0]]
    if mnem == "csrr" and len(ops) == 2:
        return [ops[0], ops[1], "zero"]
    if mnem == "not" and len(ops) == 2:
        return [ops[0], ops[1], "-1"]
    # jalr rs  ==  jalr ra, 0(rs)   （rd 省略时默认 ra，offset 默认 0）
    if mnem == "jalr" and len(ops) == 1 and "(" not in ops[0]:
        return ["ra", f"0({ops[0]})"]
    return ops


def parse_int(tok: str) -> int:
    """把 token 解析为有符号十进制整数，支持 CSR 名与寄存器名外的一切形式。"""
    t = tok.strip().rstrip(",")
    if t in CSR_ADDR:
        return CSR_ADDR[t]
    neg = t.startswith("-")
    if neg:
        t = t[1:]
    v = int(t, 16) if t.startswith("0x") else int(t, 10)
    return -v if neg else v


# ---------------------------------------------------------------------------
# 参考解析：把反汇编文本拆成 (mnemonic, [operands])
# ---------------------------------------------------------------------------
def split_ops(s: str) -> list[str]:
    out, depth, cur = [], 0, ""
    for ch in s:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def parse_mem(op: str) -> tuple[int, str]:
    """解析 'imm(reg)' 形式的访存操作数。"""
    m = re.match(r"^(-?0x[0-9a-fA-F]+|-?\d+)\((\w+)\)$", op)
    if not m:
        raise ValueError(f"无法解析访存操作数: {op!r}")
    return parse_int(m.group(1)), m.group(2)


# ---------------------------------------------------------------------------
# 用例： (编码结果, mnemonic, 操作数规格)
#   操作数规格元素：
#     ("reg", "a1")            寄存器
#     ("imm", 16)              立即数（按数值比较）
#     ("mem", 16, "a0")        访存 imm(reg)
# ---------------------------------------------------------------------------
R_ = lambda n: ("reg", n)
I_ = lambda v: ("imm", v)
M_ = lambda imm, r: ("mem", imm, r)

CASES: list[tuple[int, str, list]] = [
    # ---- 访存 ----
    (F.LW("a1", "a0", 0), "lw", [R_("a1"), M_(0, "a0")]),
    (F.LH("a1", "a0", 0), "lh", [R_("a1"), M_(0, "a0")]),
    (F.LB("a1", "a0", 0), "lb", [R_("a1"), M_(0, "a0")]),
    (F.SW("a4", "a0", 16), "sw", [R_("a4"), M_(16, "a0")]),
    (F.SH("a4", "a0", 0), "sh", [R_("a4"), M_(0, "a0")]),
    (F.SB("a4", "a0", 0), "sb", [R_("a4"), M_(0, "a0")]),
    (F.LW("a1", "a0", 2047), "lw", [R_("a1"), M_(2047, "a0")]),
    (F.SW("a4", "a0", 2047), "sw", [R_("a4"), M_(2047, "a0")]),
    (F.LW("a1", "a0", -2048), "lw", [R_("a1"), M_(-2048, "a0")]),
    (F.SW("a4", "a0", -2048), "sw", [R_("a4"), M_(-2048, "a0")]),
    (F.LW("a1", "a0", 100), "lw", [R_("a1"), M_(100, "a0")]),
    # ---- 立即数运算 ----
    (F.ADDI("a2", "a1", 5), "addi", [R_("a2"), R_("a1"), I_(5)]),
    (F.ADDI("a2", "a1", -2048), "addi", [R_("a2"), R_("a1"), I_(-2048)]),
    (F.ADDI("a2", "a1", 2047), "addi", [R_("a2"), R_("a1"), I_(2047)]),
    (F.ANDI("a3", "a2", 255), "andi", [R_("a3"), R_("a2"), I_(255)]),
    (F.ORI("a3", "a2", 15), "ori", [R_("a3"), R_("a2"), I_(15)]),
    (F.XORI("a3", "a2", 15), "xori", [R_("a3"), R_("a2"), I_(15)]),
    (F.SLTI("a3", "a2", 10), "slti", [R_("a3"), R_("a2"), I_(10)]),
    (F.SLTIU("a3", "a2", 10), "sltiu", [R_("a3"), R_("a2"), I_(10)]),
    (F.SLTI("a2", "a1", -100), "slti", [R_("a2"), R_("a1"), I_(-100)]),
    (F.SLLI("a3", "a2", 3), "slli", [R_("a3"), R_("a2"), I_(3)]),
    (F.SRLI("a3", "a2", 3), "srli", [R_("a3"), R_("a2"), I_(3)]),
    # ---- 寄存器运算（含 M 扩展）----
    (F.ADD("a3", "a1", "a2"), "add", [R_("a3"), R_("a1"), R_("a2")]),
    (F.SUB("a3", "a1", "a2"), "sub", [R_("a3"), R_("a1"), R_("a2")]),
    (F.SLT("a3", "a1", "a2"), "slt", [R_("a3"), R_("a1"), R_("a2")]),
    (F.SLTU("a3", "a1", "a2"), "sltu", [R_("a3"), R_("a1"), R_("a2")]),
    (F.XOR("a3", "a1", "a2"), "xor", [R_("a3"), R_("a1"), R_("a2")]),
    (F.OR("a3", "a1", "a2"), "or", [R_("a3"), R_("a1"), R_("a2")]),
    (F.AND("a3", "a1", "a2"), "and", [R_("a3"), R_("a1"), R_("a2")]),
    (F.SLL("a3", "a1", "a2"), "sll", [R_("a3"), R_("a1"), R_("a2")]),
    (F.SRL("a3", "a1", "a2"), "srl", [R_("a3"), R_("a1"), R_("a2")]),
    (F.SRA("a3", "a1", "a2"), "sra", [R_("a3"), R_("a1"), R_("a2")]),
    (F.MUL("a3", "a1", "a2"), "mul", [R_("a3"), R_("a1"), R_("a2")]),
    (F.MULH("a3", "a1", "a2"), "mulh", [R_("a3"), R_("a1"), R_("a2")]),
    (F.DIV("a3", "a1", "a2"), "div", [R_("a3"), R_("a1"), R_("a2")]),
    (F.DIVU("a3", "a1", "a2"), "divu", [R_("a3"), R_("a1"), R_("a2")]),
    (F.REM("a3", "a1", "a2"), "rem", [R_("a3"), R_("a1"), R_("a2")]),
    (F.REMU("a3", "a1", "a2"), "remu", [R_("a3"), R_("a1"), R_("a2")]),
    # ---- 分支 ----
    (F.BEQ("a2", "a3", 8), "beq", [R_("a2"), R_("a3"), I_(8)]),
    (F.BNE("a2", "a3", 8), "bne", [R_("a2"), R_("a3"), I_(8)]),
    (F.BLT("a2", "a3", 8), "blt", [R_("a2"), R_("a3"), I_(8)]),
    (F.BGE("a2", "a3", 8), "bge", [R_("a2"), R_("a3"), I_(8)]),
    (F.BLTU("a2", "a3", 8), "bltu", [R_("a2"), R_("a3"), I_(8)]),
    (F.BGEU("a2", "a3", 8), "bgeu", [R_("a2"), R_("a3"), I_(8)]),
    (F.BEQ("a2", "a3", -16), "beq", [R_("a2"), R_("a3"), I_(-16)]),
    (F.BEQ("a2", "a3", 2046), "beq", [R_("a2"), R_("a3"), I_(2046)]),
    (F.BEQ("a2", "a3", 100), "beq", [R_("a2"), R_("a3"), I_(100)]),
    # ---- 跳转 ----
    (F.J(16), "jal", [R_("zero"), I_(16)]),
    (F.J(-16), "jal", [R_("zero"), I_(-16)]),
    (F.J(100), "jal", [R_("zero"), I_(100)]),
    (F.J(2046), "jal", [R_("zero"), I_(2046)]),
    (F.RET(), "jalr", [R_("zero"), M_(0, "ra")]),
    (F.JALR("ra", "t0", 0), "jalr", [R_("ra"), M_(0, "t0")]),
    # ---- 其他 ----
    (F.NOP(), "addi", [R_("zero"), R_("zero"), I_(0)]),
    (F.EBREAK(), "ebreak", []),
    (F.ECALL(), "ecall", []),
    (F.LUI("a0", 0x80000), "lui", [R_("a0"), I_(0x80000)]),
    (F.CSRRW("a0", 0x300, "a1"), "csrrw", [R_("a0"), I_(0x300), R_("a1")]),
    (F.CSRRS("a0", 0x300, "zero"), "csrrs", [R_("a0"), I_(0x300), R_("zero")]),
]


def disasm(word: int):
    md = Cs(CS_ARCH_RISCV, CS_MODE_RISCV32)
    out = list(md.disasm(struct.pack("<I", word), 0))
    if not out:
        return None
    return out[0].mnemonic, out[0].op_str


def compare(word: int, mnem: str, spec: list) -> str | None:
    """返回 None 表示通过，否则返回差异描述。"""
    got = disasm(word)
    if got is None:
        return "capstone 无法解码"
    g_mnem, g_ops_raw = got
    g_ops = split_ops(g_ops_raw) if g_ops_raw else []
    # 先把伪指令展开
    g_ops = expand_pseudo(g_mnem, g_ops)

    if canon_mnem(g_mnem) != canon_mnem(mnem):
        return f"mnemonic 不符: 期望 {mnem} / 实际 {g_mnem}"

    if len(g_ops) != len(spec):
        return f"操作数个数不符: 期望 {len(spec)} / 实际 {len(g_ops)} ({g_ops_raw})"

    for idx, (kind, gop) in enumerate(zip(spec, g_ops)):
        if kind[0] == "reg":
            if gop != kind[1]:
                return f"操作数{idx}: 期望寄存器 {kind[1]} / 实际 {gop}"
        elif kind[0] == "imm":
            try:
                v = parse_int(gop)
            except ValueError:
                return f"操作数{idx}: 期望立即数 {kind[1]} / 实际 {gop} 无法解析"
            if v != kind[1]:
                return f"操作数{idx}: 期望立即数 {kind[1]} / 实际 {v}"
        elif kind[0] == "mem":
            try:
                imm, reg = parse_mem(gop)
            except ValueError as e:
                return f"操作数{idx}: {e}"
            if imm != kind[1] or reg != kind[2]:
                return (f"操作数{idx}: 期望 {kind[1]}({kind[2]}) "
                        f"/ 实际 {imm}({reg})")
    return None


def main() -> int:
    fail = []
    for word, mnem, spec in CASES:
        err = compare(word, mnem, spec)
        if err:
            fail.append((word, mnem, spec, err, disasm(word)))

    log = ROOT / "out" / "encoder_selfcheck.log"
    log.parent.mkdir(parents=True, exist_ok=True)
    L = []
    L.append("=" * 70)
    L.append("编码器自校验（capstone 交叉验证，按数值比较）")
    L.append("=" * 70)
    L.append(f"用例数: {len(CASES)}")
    L.append(f"通过  : {len(CASES) - len(fail)}")
    L.append(f"失败  : {len(fail)}")
    if fail:
        L.append("")
        L.append("--- 失败明细 ---")
        for word, mnem, spec, err, got in fail:
            L.append(f"  0x{word:08x}  期望 {mnem} {spec}")
            L.append(f"              实际 {got}")
            L.append(f"              >> {err}")
    L.append("")
    L.append("--- 抽样反汇编 ---")
    for word, mnem, spec in CASES[:24]:
        g = disasm(word)
        txt = f"{g[0]} {g[1]}" if g else "<undecoded>"
        L.append(f"  0x{word:08x}  {txt}")
    log.write_text("\n".join(L), encoding="utf-8")
    print("\n".join(L))
    return 1 if fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
