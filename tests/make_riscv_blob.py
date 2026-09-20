"""手工构造 RISC-V 机器码，验证 lifter 的正确性。"""

# 用 riscv 汇编知识手工编码几条指令（RV32）
# 参考: https://riscv.org/wp-content/uploads/2019/12/riscv-spec-20191213.pdf
import struct


def r_type(funct7, rs2, rs1, funct3, rd, opcode):
    return (funct7 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode


def i_type(imm, rs1, funct3, rd, opcode):
    imm12 = imm & 0xFFF
    return (imm12 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode


def s_type(imm, rs2, rs1, funct3, opcode):
    imm12 = imm & 0xFFF
    imm11_5 = (imm12 >> 5) & 0x7F
    imm4_0 = imm12 & 0x1F
    return (imm11_5 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (imm4_0 << 7) | opcode


def b_type(imm, rs2, rs1, funct3, opcode):
    imm13 = imm & 0x1FFF
    imm12 = (imm13 >> 12) & 1
    imm11 = (imm13 >> 11) & 1
    imm10_5 = (imm13 >> 5) & 0x3F
    imm4_1 = (imm13 >> 1) & 0xF
    return ((imm12 << 31) | (imm10_5 << 25) | (rs2 << 20) | (rs1 << 15) |
            (funct3 << 12) | (imm4_1 << 8) | (imm11 << 7) | opcode)


OP = 0b0110011      # R-type
OP_IMM = 0b0010011  # I-type arithmetic
LOAD = 0b0000011
STORE = 0b0100011
BRANCH = 0b1100011
JAL = 0b1101111
SYSTEM = 0b1110011

REG = {"zero": 0, "ra": 1, "sp": 2, "gp": 3, "tp": 4,
       "t0": 5, "t1": 6, "t2": 7, "s0": 8, "s1": 9,
       "a0": 10, "a1": 11, "a2": 12, "a3": 13,
       "a4": 14, "a5": 15, "a6": 16, "a7": 17,
       "s2": 18, "s3": 19, "s4": 20, "s5": 21,
       "s6": 22, "s7": 23, "s8": 24, "s9": 25,
       "s10": 26, "s11": 27, "t3": 28, "t4": 29, "t5": 30, "t6": 31}


def build_test_program():
    """
    构造一个测试程序，模拟"固件中存在硬件触发片段"的场景。

    场景设计（对应对齐硬件触发契约）：
      - a0 承载外部输入（UART 字节）
      - 从 a0 取出长度字段
      - 用该长度做除法（硬件除法器偏差的触发点）
      - 结果用作内存写地址（若除法结果被硬件算错 -> 越界写）
    """
    insns = []

    # 0x00: lw a1, 0(a0)        ; 从输入缓冲区载入一个字
    insns.append(i_type(0, REG["a0"], 0b010, REG["a1"], LOAD))
    # 0x04: andi a2, a1, 0xff   ; 取低 8 位作为长度
    insns.append(i_type(0xFF, REG["a1"], 0b111, REG["a2"], OP_IMM))
    # 0x08: li a3, 0            ; 准备除数
    insns.append(i_type(0, REG["zero"], 0b000, REG["a3"], OP_IMM))
    # 0x0c: divu a4, a2, a3     ; ★ 除法 —— 除数为 0 时的硬件行为是触发点
    insns.append(r_type(0b0000001, REG["a3"], REG["a2"], 0b101, REG["a4"], OP))
    # 0x10: sw a4, 16(a0)       ; ★ 用除法结果作为写值
    insns.append(s_type(16, REG["a4"], REG["a0"], 0b010, STORE))
    # 0x14: addi a0, a0, 4      ; 指针前进
    insns.append(i_type(4, REG["a0"], 0b000, REG["a0"], OP_IMM))
    # 0x18: beq a2, a3, +8    ; ★ 分支：比较 a2/a3（不是立即数）
    insns.append(b_type(8, REG["a3"], REG["a2"], 0b000, BRANCH))
    # 0x1c: csrr a5, mstatus    ; CSR 读（契约匹配用）
    #       csrrs a5, mstatus(0x300), zero -> 0x300027f3
    insns.append(0x300027F3)
    # 0x20: ret
    insns.append(i_type(0, REG["ra"], 0b000, REG["zero"], JAL))

    blob = b"".join(struct.pack("<I", i) for i in insns)
    return blob


if __name__ == "__main__":
    blob = build_test_program()
    print(f"生成 {len(blob)} 字节")
    print(blob.hex())
