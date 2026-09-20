"""
契约库：除法器除零边界条件偏差（硬件触发契约）

这个契约对应一个假设的硬件缺陷：
**除法器在除数为 0 时未按规范返回全 1，而是产生错误结果**。

契约内容（等价于 Microscope HW-SCM 的输出在软件侧的投影）：

  Pre（前置状态）:
    - 需要 M 特权级
    - 需要一条 DIVU 指令存在
    - 除法结果需要能被写回内存（攻击链的支撑条件，不是触发事件本身）

  Trigger（触发事件）:
    - 操作类别：ARITH_DIV
    - 操作数关系：除数为 0（second operand == 0）
    - 操作数可控性：被除数可由外部输入控制
    ★ 这里刻意**不放** store 谓词 —— 判别性条件与支撑条件的区分见
      contracts/README.md

  Deviation（偏差）:
    - wrong_register_result（除法结果错误）
    - constrained_by_hw=True：由硬件契约约束，不是任意注入

  Observe（观测）:
    - 需要 RTL 波形或架构差分才能判定
"""

from __future__ import annotations

from crosslayer.contracts import (
    BugClass,
    Deviation,
    JudgementKind,
    Observe,
    PlatformIdentity,
    Predicate,
    PredicateKind,
    Precondition,
    Scope,
    Trigger,
    TriggerContract,
)
from crosslayer.ir import OpClass


def make_div_zero_contract() -> TriggerContract:
    """构造「除法器除零偏差」的触发契约。"""

    return TriggerContract(
        contract_id="HW-DIV-0001",
        name="除法器除零边界条件偏差",
        bug_class=BugClass.CPU_CORE,
        source_ref=(
            "合成契约（用于引擎自检；对应 HardFails 类别的算术单元边界偏差）"
        ),
        evidence_level="E0",
        is_minimal_poc=False,

        platform=PlatformIdentity(
            soc_model="synthetic-test",
            core_model="rv32-test-core",
            isa="riscv32",
            isa_extensions=["m"],
            chip_revision="r0",
            endianness="little",
        ),

        pre=Precondition(
            privilege="M",
            predicates=[
                Predicate(
                    kind=PredicateKind.OP_PRESENT,
                    description="存在除法操作（DIVU）",
                    op_class=OpClass.ARITH_DIV,
                ),
                Predicate(
                    kind=PredicateKind.OP_PRESENT,
                    description=(
                        "除法结果需要能被写回内存（攻击链的支撑条件，"
                        "不是触发事件本身）"
                    ),
                    op_class=OpClass.STORE,
                ),
            ],
        ),

        trigger=Trigger(
            event_kind="instruction",
            semantic_description=(
                "执行一次无符号除法，除数为 0，且被除数可由外部输入控制"
            ),
            operand_relations=["divisor == 0"],
            # trigger 只放**判别性**条件 —— 即"这个硬件操作发生了"本身。
            # "结果写回内存"属于攻击链的支撑条件，放 preconditions，
            # 否则会把"无除法但有 store"的固件误判为"触发事件存在"。
            predicates=[
                Predicate(
                    kind=PredicateKind.OP_PRESENT,
                    description="触发需要一条除法指令",
                    op_class=OpClass.ARITH_DIV,
                ),
                Predicate(
                    kind=PredicateKind.INPUT_CONTROLLABLE,
                    description=(
                        "被除数必须可由外部输入控制"
                        "（否则攻击者无法影响触发）"
                    ),
                    op_class=OpClass.ARITH_DIV,
                ),
            ],
        ),

        deviation=Deviation(
            deviation_kind="wrong_register_result",
            specification_ref="RISC-V 规范：除零时 DIVU 应返回 2^XLEN - 1",
            expected_value="0xFFFFFFFF",
            actual_value="实现相关（未按规范）",
            first_divergence_point="除法器的 quotient 输出寄存器",
            constrained_by_hw=True,
        ),

        observe=Observe(
            observable_signals=["div_unit.quotient", "core.rd_write_data"],
            required_backend="rtl_waveform",
            judgement_kind=JudgementKind.FUNCTIONAL_ASSERTION,
        ),

        scope=Scope(
            verified_platforms=[],
            unmodeled_aspects=[
                "未建模流水线时序：偏差可能需要特定的指令间隔才出现",
                "未建模异常路径：除零是否触发额外异常取决于实现",
            ],
            observation_blind_spots=[
                "静态分析无法观察微架构状态",
            ],
            assumptions=[
                "假设该核心确实实现了 M 扩展的除法指令",
            ],
        ),

        provenance={"route": "B", "source_kind": "manual_annotation"},
    )


if __name__ == "__main__":
    c = make_div_zero_contract()
    rep = c.formalization_report()
    print(f"契约: {c.name}")
    print(f"可检查谓词: {rep['checkable_predicates']}/{rep['total_predicates']}"
          f" ({rep['formalization_ratio']:.0%})")
    print(f"要求操作类别: {[o.value for o in c.required_op_classes()]}")
    print(f"判别性操作: {[o.value for o in c.trigger_op_classes()]}")
    for p in c.all_predicates():
        ok = p.checkable and p.kind is not PredicateKind.UNFORMALIZED
        flag = "OK " if ok else "---"
        print(f"  [{flag}] {p.kind.value:20s} {p.description}")
