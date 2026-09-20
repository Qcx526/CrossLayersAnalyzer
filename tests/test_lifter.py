"""测试 RISC-V lifter 的正确性。"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from make_riscv_blob import build_test_program, REG
from crosslayer.lifter import RiscvLifter


def main():
    blob = build_test_program()
    lifter = RiscvLifter(bits=32, input_regs=("a0",))
    result = lifter.lift_range(blob, 0x80000000)

    print(f"总指令 {result.total_count}, 未识别 {result.unknown_count} "
          f"({result.unknown_ratio():.1%})")
    print("-" * 78)
    for insn in result.instructions:
        dst = ", ".join(str(d) for d in insn.operands)
        src = ", ".join(str(s) for s in insn.sources)
        taint = set()
        for e in list(insn.operands) + list(insn.sources):
            taint |= set(e.taint_sources)
        tmark = f"  TAINT={sorted(taint)}" if taint else ""
        print(f"0x{insn.addr:08x}  {insn.mnemonic:8s} {insn.op_class.value:18s} "
              f"rd=[{dst}] rs=[{src}]{tmark}")
        if insn.condition is not None:
            print(f"          cond: {insn.condition}")
        if insn.csr_name:
            print(f"          csr : {insn.csr_name}")
        if insn.notes:
            print(f"          NOTE: {insn.notes}")


if __name__ == "__main__":
    main()
