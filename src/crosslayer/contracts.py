"""
跨层漏洞分析 —— 触发契约与能力摘要

本模块定义跨层分析的**靶标**与**素材**：

- `TriggerContract`  : 硬件漏洞的触发契约 H = (Platform, Pre, Trigger, Deviation, Observe, Scope)
- `Capability`       : 固件漏洞的能力摘要 F = (Entry, Condition, Primitive, Constraints, Evidence)
- `FirmwareCapability`: 固件片段实际具备的能力（由固件分析得出）

关键设计
--------
分析的核心问题被表达为**约束可满足性**，而不是"标签相似度"：

    ①  ∃u : Reach(B,u) ∧ Cap(C_fw) ⊨ Pre(H)
    ②  ∃u : Reach(B,u) ∧ Match(Pattern(H), τ_B) ∧ Trigger(H)
    ③  ∀d ∈ Deviation(H) : Propagate(B, d) → Violate(Q)

因此契约中的每个条件都必须能翻译为**可求解的约束**或**可检查的谓词**。
不能翻译成谓词的自然语言描述，一律进 `unformalized` 字段并显式标注，
绝不假装它已被形式化。
"""

from __future__ import annotations

import enum
import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Iterable, Optional

import z3

from .ir import Expr, OpClass


# ---------------------------------------------------------------------------
# 平台身份：同名寄存器必须以平台+版本区分
# ---------------------------------------------------------------------------
@dataclass
class PlatformIdentity:
    soc_model: str = ""
    core_model: str = ""
    isa: str = ""
    isa_extensions: list[str] = field(default_factory=list)
    rtl_commit: str = ""
    chip_revision: str = ""
    config: dict[str, Any] = field(default_factory=dict)
    endianness: str = "little"

    def key(self) -> str:
        """用于在证据图中区分不同平台的同名对象。"""
        return f"{self.core_model}|{self.chip_revision}|{self.rtl_commit}"


# ---------------------------------------------------------------------------
# 触发模式：硬件契约的"软件可见投影"
# ---------------------------------------------------------------------------
class PredicateKind(enum.Enum):
    """
    可检查的谓词类型。

    这是把抽象契约变成可搜索靶标的桥梁。每个谓词都必须能：
    - 在固件 IR 上检查（匹配阶段）
    - 或翻译为 z3 约束（求解阶段）
    """

    OP_PRESENT = "op_present"                # 存在某类操作
    OP_SEQUENCE = "op_sequence"              # 操作序列（含跨基本块）
    OPERAND_RELATION = "operand_relation"    # 操作数关系（如 a == b, a < b）
    IMMEDIATE_MATCH = "immediate_match"      # 立即数等于特定值
    REG_FIELD_MATCH = "reg_field_match"      # 寄存器位域等于特定值
    PRIV_REQUIRED = "priv_required"          # 需要特定特权级
    CSR_ACCESS = "csr_access"                # 访问特定 CSR
    MEMORY_ATTR = "memory_attr"              # 访存属性（可写/缓存性/对齐）
    INPUT_CONTROLLABLE = "input_controllable"  # ★ 操作数可由外部输入控制
    REACHABILITY = "reachability"            # 从外部入口可达
    ORDERING = "ordering"                    # 时序/顺序约束
    TIMING_WINDOW = "timing_window"          # 时间窗口

    # 无法形式化 —— 必须显式标注，不能装作已处理
    UNFORMALIZED = "unformalized"


@dataclass
class Predicate:
    """
    单个可检查谓词。

    `checkable` 为 False 时表示该条件**无法在本系统的建模范围内检查**，
    此时 `kind` 应为 UNFORMALIZED，且 `notes` 必须说明原因。
    """

    kind: PredicateKind
    description: str                       # 人类可读描述（报告用）
    # --- 形式化内容 ---
    op_class: Optional[OpClass] = None
    expected_value: Optional[int] = None
    operand_constraint: Optional[str] = None     # SMT-LIB 片段（针对操作数）
    csr_name: Optional[str] = None
    priv_level: Optional[str] = None
    ordering_hint: Optional[str] = None
    # --- 诚实性 ---
    checkable: bool = True
    notes: str = ""

    def to_smt(self, var_map: dict[str, z3.ExprRef]) -> Optional[z3.BoolRef]:
        """
        尝试翻译为 z3 约束。

        返回 None 表示无法翻译 —— 调用方必须把它当作 unknown，
        **绝不能当作 sat**。这是本系统的一条硬规则。
        """
        if not self.checkable or self.kind is PredicateKind.UNFORMALIZED:
            return None
        if self.kind is PredicateKind.OPERAND_RELATION and self.operand_constraint:
            try:
                # 受限解析：只支持 <lhs> <op> <rhs> 形式的比较，
                # 避免 eval 带来的安全问题。
                return _parse_simple_relation(self.operand_constraint, var_map)
            except Exception:
                return None
        if self.kind is PredicateKind.IMMEDIATE_MATCH and self.expected_value is not None:
            v = var_map.get("__immediate__")
            if v is None:
                return None
            return v == self.expected_value
        return None


def _parse_simple_relation(text: str, var_map: dict[str, z3.ExprRef]) -> Optional[z3.BoolRef]:
    """
    极简的关系表达式解析器。

    仅支持：`<ident|const> <op> <ident|const>`，op ∈ {==,!=,<,<=,>,>=,<u,<=u,>u,>=u}
    故意不支持任意表达式 —— 避免引入代码执行风险，并保证失败时能明确返回 None。
    """
    import re

    m = re.fullmatch(
        r"\s*([A-Za-z_][A-Za-z0-9_]*|0x[0-9a-fA-F]+|\d+)\s*"
        r"(==|!=|<=u|>=u|<u|>u|<=|>=|<|>)\s*"
        r"([A-Za-z_][A-Za-z0-9_]*|0x[0-9a-fA-F]+|\d+)\s*",
        text,
    )
    if not m:
        return None
    lhs_s, oper, rhs_s = m.groups()

    def resolve(tok: str) -> Optional[z3.ExprRef]:
        if re.fullmatch(r"0x[0-9a-fA-F]+|\d+", tok):
            return z3.BitVecVal(int(tok, 0), 32)
        return var_map.get(tok)

    a, b = resolve(lhs_s), resolve(rhs_s)
    if a is None or b is None:
        return None

    unsigned = oper.endswith("u")
    base = oper[:-1] if unsigned else oper
    if base == "==":
        return a == b
    if base == "!=":
        return a != b
    if base == "<":
        return z3.ULT(a, b) if unsigned else a < b
    if base == "<=":
        return z3.ULE(a, b) if unsigned else a <= b
    if base == ">":
        return z3.UGT(a, b) if unsigned else a > b
    if base == ">=":
        return z3.UGE(a, b) if unsigned else a >= b
    return None


# ---------------------------------------------------------------------------
# 触发契约本体
# ---------------------------------------------------------------------------
@dataclass
class Precondition:
    """Pre —— 前置状态：权限、寄存器、内存属性、保护状态、微架构状态。"""

    privilege: str = ""
    required_register_states: list[str] = field(default_factory=list)
    memory_attributes: list[str] = field(default_factory=list)
    protection_state: list[str] = field(default_factory=list)
    microarch_state: list[str] = field(default_factory=list)
    predicates: list[Predicate] = field(default_factory=list)

    def all_predicates(self) -> list[Predicate]:
        return list(self.predicates)


@dataclass
class Trigger:
    """
    Trigger —— 触发条件：事件/指令/事务的语义、参数关系、顺序、时间窗口、并发条件。

    `pattern` 是本系统的核心靶标：一组有序谓词，硬件侧反推的产物。
    """

    event_kind: str = "instruction"     # instruction / transaction / interrupt / mmio / dma / sequence
    semantic_description: str = ""
    operand_relations: list[str] = field(default_factory=list)
    ordering: list[str] = field(default_factory=list)
    timing_window: str = ""
    concurrency: str = ""
    predicates: list[Predicate] = field(default_factory=list)

    def pattern_predicates(self) -> list[Predicate]:
        """返回真正参与匹配的谓词（过滤掉无法检查的）。"""
        return [p for p in self.predicates if p.checkable
                and p.kind is not PredicateKind.UNFORMALIZED]


@dataclass
class Deviation:
    """Deviation —— 硬件相对规范产生的错误行为。思路③的输入。"""

    deviation_kind: str = ""        # wrong_load_value / missing_exception / dma_oob / timing_leak ...
    specification_ref: str = ""
    safety_property_ref: str = ""
    expected_value: str = ""
    actual_value: str = ""
    first_divergence_point: str = ""
    constrained_by_hw: bool = False  # ★ 是否由硬件契约约束。false = 任意注入，不足以证明真实漏洞


class JudgementKind(enum.Enum):
    """判定方式。泄漏类必须用统计/关系判据，不能用 crash 判据替代。"""

    FUNCTIONAL_ASSERTION = "functional_assertion"
    ARCHITECTURAL_DIFFERENTIAL = "architectural_differential"
    PROTOCOL_EXPECTATION = "protocol_expectation"
    ACCESS_CONTROL_CHECK = "access_control_check"
    STATISTICAL_RELATIONAL = "statistical_relational"


@dataclass
class Observe:
    """Observe —— 判定偏差发生的可观测证据及所需后端。"""

    observable_signals: list[str] = field(default_factory=list)
    required_backend: str = ""      # rtl_waveform / board_trace / statistical_measurement ...
    judgement_kind: JudgementKind = JudgementKind.FUNCTIONAL_ASSERTION


@dataclass
class Scope:
    """Scope —— 成立范围、未建模内容、观测盲区、置信依据。"""

    verified_platforms: list[str] = field(default_factory=list)
    unmodeled_aspects: list[str] = field(default_factory=list)
    observation_blind_spots: list[str] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)


class BugClass(enum.Enum):
    """
    硬件缺陷分类。

    CPU 核漏洞、总线/外设缺陷、配置错误、物理扰动、微架构泄漏必须分开标注。
    ProcessorFuzz 主要覆盖处理器验证，不能假定上游已覆盖 DMA、外设或模拟电路漏洞。
    """

    CPU_CORE = "cpu_core"
    BUS_PERIPHERAL = "bus_peripheral"
    MISCONFIGURATION = "misconfiguration"
    PHYSICAL_PERTURBATION = "physical_perturbation"
    MICROARCHITECTURAL_LEAKAGE = "microarchitectural_leakage"
    UNKNOWN = "unknown"


@dataclass
class TriggerContract:
    """
    硬件触发契约 H = (Platform, Pre, Trigger, Deviation, Observe, Scope)。

    这是跨层分析的**靶标**。它的质量直接决定整个分析的上限。
    """

    contract_id: str
    name: str
    bug_class: BugClass = BugClass.UNKNOWN

    platform: PlatformIdentity = field(default_factory=PlatformIdentity)
    pre: Precondition = field(default_factory=Precondition)
    trigger: Trigger = field(default_factory=Trigger)
    deviation: Deviation = field(default_factory=Deviation)
    observe: Observe = field(default_factory=Observe)
    scope: Scope = field(default_factory=Scope)

    # 证据级别（E0-E4）
    evidence_level: str = "E0"

    # 来源溯源：每个字段从哪里来
    provenance: dict[str, Any] = field(default_factory=dict)

    # ★ 最小化 PoC 通常只给出**充分**触发实例，不能自动提升为必要且充分的漏洞定义
    is_minimal_poc: bool = False

    # 无法形式化的条件，必须显式记录
    unformalized: list[str] = field(default_factory=list)

    source_ref: str = ""            # 原始出处（论文/CVE/勘误表/上游报告）

    # ------------------------------------------------------------------
    def all_predicates(self) -> list[Predicate]:
        """契约中所有可检查谓词（匹配器的输入）。"""
        return self.pre.all_predicates() + self.trigger.pattern_predicates()

    def formalization_report(self) -> dict[str, Any]:
        """
        形式化完整性报告。

        报告必须暴露"哪些条件没被形式化"，而不是只展示成功的部分。
        """
        all_p = self.pre.all_predicates() + self.trigger.predicates
        checkable = [p for p in all_p if p.checkable and p.kind is not PredicateKind.UNFORMALIZED]
        return {
            "contract_id": self.contract_id,
            "total_predicates": len(all_p),
            "checkable_predicates": len(checkable),
            "unformalized_predicates": len(all_p) - len(checkable),
            "unformalized_notes": self.unformalized,
            "formalization_ratio": (len(checkable) / len(all_p)) if all_p else 0.0,
            "is_minimal_poc": self.is_minimal_poc,
            "warning": (
                "契约来自最小化 PoC，只给出充分触发实例，不构成必要且充分的漏洞定义"
                if self.is_minimal_poc else ""
            ),
        }

    def required_op_classes(self) -> set[OpClass]:
        """
        契约要求出现的**全部**操作类别 —— 匹配器的第一层过滤输入。

        注意：这包含了支撑性谓词（如"结果需写回内存"对应的 STORE）。
        判断"漏洞是否存在"时应使用 `trigger_op_classes()`。
        """
        out: set[OpClass] = set()
        for p in self.all_predicates():
            if p.op_class is not None:
                out.add(p.op_class)
        return out

    def trigger_op_classes(self) -> set[OpClass]:
        """
        触发事件本身的**判别性**操作类别。

        这是判断"漏洞是否存在"的依据 —— 只有触发事件的硬件操作缺失，
        才说明漏洞在该固件上不存在；支撑性操作（写回、传播）的缺失
        只影响攻击链的完整性，不影响漏洞存在性。

        例：除法器除零契约的 trigger 谓词要求 ARITH_DIV；
        "结果需写回内存"是支撑谓词，对应 STORE。
        若固件有 STORE 但无 ARITH_DIV → 漏洞不存在（NOT_PRESENT）；
        若固件有 ARITH_DIV 但无 STORE → 漏洞存在但链条不完整。
        """
        out: set[OpClass] = set()
        for p in self.trigger.predicates:
            if p.op_class is not None:
                out.add(p.op_class)
        # 若 trigger 未显式给出操作类别，退回全部要求（保守）
        return out or self.required_op_classes()

    # ------------------------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        """序列化（用于证据图持久化）。"""
        return _contract_to_dict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "TriggerContract":
        return _contract_from_dict(d)

    @classmethod
    def from_json_file(cls, path: str | Path) -> "TriggerContract":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


# ---------------------------------------------------------------------------
# 固件能力摘要
# ---------------------------------------------------------------------------
class Primitive(enum.Enum):
    """
    固件漏洞提供的能力原语。

    crash != 任意执行；任意写 != 任意特权写。因此这里必须精确到"能力的种类"，
    而不是简单地说"有漏洞"。
    """

    READ_OOB = "read_oob"
    WRITE_OOB = "write_oob"
    WRITE_BOUNDED = "write_bounded"
    PARTIAL_ADDRESS_CONTROL = "partial_address_control"
    PARTIAL_VALUE_CONTROL = "partial_value_control"
    LENGTH_CONTROL = "length_control"
    INTERFACE_REACHABLE = "interface_reachable"
    CALLBACK_INFLUENCE = "callback_influence"
    DENIAL_OF_SERVICE = "denial_of_service"
    CONTROL_FLOW_HIJACK = "control_flow_hijack"
    UNKNOWN = "unknown"


@dataclass
class Capability:
    """
    固件漏洞的能力摘要 F = (Entry, Condition, Primitive, Constraints, Evidence)。

    思路①的输入：必须能与硬件契约的 Pre 做**约束可满足性**匹配，
    而不是字符串/标签匹配。
    """

    capability_id: str
    source_vulnerability: str = ""     # 上游固件漏洞标识
    entry: str = ""                     # 入口：接口/函数/PC
    condition: str = ""
    primitives: list[Primitive] = field(default_factory=list)

    # 精确的约束描述
    controlled_bytes: Optional[tuple[int, int]] = None   # 可控字节范围
    controlled_value_bits: Optional[int] = None          # 可控位宽
    address_control_ratio: Optional[float] = None        # 地址可控比例 [0,1]
    length_bounds: Optional[tuple[int, int]] = None      # 长度变量的取值范围
    reachable_interfaces: list[str] = field(default_factory=list)

    privilege: str = ""
    evidence_ref: str = ""
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["primitives"] = [p.value for p in self.primitives]
        return d


# ---------------------------------------------------------------------------
# 序列化辅助
# ---------------------------------------------------------------------------
def _predicate_to_dict(p: Predicate) -> dict[str, Any]:
    return {
        "kind": p.kind.value,
        "description": p.description,
        "op_class": p.op_class.value if p.op_class else None,
        "expected_value": p.expected_value,
        "operand_constraint": p.operand_constraint,
        "csr_name": p.csr_name,
        "priv_level": p.priv_level,
        "ordering_hint": p.ordering_hint,
        "checkable": p.checkable,
        "notes": p.notes,
    }


def _predicate_from_dict(d: dict[str, Any]) -> Predicate:
    return Predicate(
        kind=PredicateKind(d["kind"]),
        description=d.get("description", ""),
        op_class=OpClass(d["op_class"]) if d.get("op_class") else None,
        expected_value=d.get("expected_value"),
        operand_constraint=d.get("operand_constraint"),
        csr_name=d.get("csr_name"),
        priv_level=d.get("priv_level"),
        ordering_hint=d.get("ordering_hint"),
        checkable=d.get("checkable", True),
        notes=d.get("notes", ""),
    )


def _contract_to_dict(c: TriggerContract) -> dict[str, Any]:
    return {
        "contract_id": c.contract_id,
        "name": c.name,
        "bug_class": c.bug_class.value,
        "source_ref": c.source_ref,
        "evidence_level": c.evidence_level,
        "is_minimal_poc": c.is_minimal_poc,
        "unformalized": list(c.unformalized),
        "provenance": c.provenance,
        "platform": asdict(c.platform),
        "pre": {
            "privilege": c.pre.privilege,
            "required_register_states": c.pre.required_register_states,
            "memory_attributes": c.pre.memory_attributes,
            "protection_state": c.pre.protection_state,
            "microarch_state": c.pre.microarch_state,
            "predicates": [_predicate_to_dict(p) for p in c.pre.predicates],
        },
        "trigger": {
            "event_kind": c.trigger.event_kind,
            "semantic_description": c.trigger.semantic_description,
            "operand_relations": c.trigger.operand_relations,
            "ordering": c.trigger.ordering,
            "timing_window": c.trigger.timing_window,
            "concurrency": c.trigger.concurrency,
            "predicates": [_predicate_to_dict(p) for p in c.trigger.predicates],
        },
        "deviation": asdict(c.deviation),
        "observe": {
            "observable_signals": c.observe.observable_signals,
            "required_backend": c.observe.required_backend,
            "judgement_kind": c.observe.judgement_kind.value,
        },
        "scope": asdict(c.scope),
    }


def _contract_from_dict(d: dict[str, Any]) -> TriggerContract:
    return TriggerContract(
        contract_id=d["contract_id"],
        name=d.get("name", ""),
        bug_class=BugClass(d.get("bug_class", "unknown")),
        source_ref=d.get("source_ref", ""),
        evidence_level=d.get("evidence_level", "E0"),
        is_minimal_poc=d.get("is_minimal_poc", False),
        unformalized=d.get("unformalized", []),
        provenance=d.get("provenance", {}),
        platform=PlatformIdentity(**d.get("platform", {})),
        pre=Precondition(
            privilege=d.get("pre", {}).get("privilege", ""),
            required_register_states=d.get("pre", {}).get("required_register_states", []),
            memory_attributes=d.get("pre", {}).get("memory_attributes", []),
            protection_state=d.get("pre", {}).get("protection_state", []),
            microarch_state=d.get("pre", {}).get("microarch_state", []),
            predicates=[_predicate_from_dict(x) for x in d.get("pre", {}).get("predicates", [])],
        ),
        trigger=Trigger(
            event_kind=d.get("trigger", {}).get("event_kind", "instruction"),
            semantic_description=d.get("trigger", {}).get("semantic_description", ""),
            operand_relations=d.get("trigger", {}).get("operand_relations", []),
            ordering=d.get("trigger", {}).get("ordering", []),
            timing_window=d.get("trigger", {}).get("timing_window", ""),
            concurrency=d.get("trigger", {}).get("concurrency", ""),
            predicates=[_predicate_from_dict(x) for x in d.get("trigger", {}).get("predicates", [])],
        ),
        deviation=Deviation(**d.get("deviation", {})),
        observe=Observe(
            observable_signals=d.get("observe", {}).get("observable_signals", []),
            required_backend=d.get("observe", {}).get("required_backend", ""),
            judgement_kind=JudgementKind(
                d.get("observe", {}).get("judgement_kind", "functional_assertion")
            ),
        ),
        scope=Scope(**d.get("scope", {})),
    )
