"""
crosslayer — 芯片跨层漏洞攻击链路分析引擎

核心能力
--------
在**不可替换的原始固件**上，判定硬件漏洞触发契约是否可达、
操作数是否可控，输出带证据的候选链。

模块
----
ir          统一中间表示（架构无关）
contracts   触发契约与能力摘要
loader      固件加载与身份固定
lifter      ISA → IR 提升（RISC-V）
cfg         控制流图构建
matcher     语义匹配 + 常量传播 + 输入无关性传播（创新点 B）
reachability 可达性与操作数可控性求解（创新点 A）
evidence    CLEG 证据图存储
pipeline    端到端流水线（含 Markdown 报告生成）

设计纪律
--------
1. 原始镜像不可修改；一切结论引用原始地址。
2. UNKNOWN 是一等公民 —— 信息不足时返回 UNKNOWN，绝不降级为"未发现"。
3. 推理边与观测边严格分离，证据级别 E0-E4 显式标注。
4. 无法形式化的条件必须显式列出，不假装已处理。
"""

__version__ = "0.1.0"

from .ir import (
    OpClass, ExprKind, Expr, Instruction, BasicBlock, Function, Program,
)
from .contracts import (
    PlatformIdentity, Predicate, PredicateKind, Precondition, Trigger,
    Deviation, Observe, Scope, BugClass, TriggerContract,
    Capability, Primitive, JudgementKind,
)
from .loader import FirmwareImage, load_firmware, load_elf, load_raw
from .lifter import RiscvLifter, lift_firmware, LiftResult
from .cfg import build_program
from .matcher import (
    SemanticMatcher, MatchConfig, MatchStatus, BlockMatch, PredicateResult,
)
from .reachability import (
    ReachabilitySolver, ReachabilityResult, Verdict, ControlStatus,
    InputConstraint,
)
from .evidence import EvidenceGraph, Node, Edge, build_graph_from_analysis
from .pipeline import (
    run_analysis, generate_report, AnalysisConfig, AnalysisRun,
)

__all__ = [
    "__version__",
    # ir
    "OpClass", "ExprKind", "Expr", "Instruction", "BasicBlock", "Function", "Program",
    # contracts
    "PlatformIdentity", "Predicate", "PredicateKind", "Precondition", "Trigger",
    "Deviation", "Observe", "Scope", "BugClass", "TriggerContract",
    "Capability", "Primitive", "JudgementKind",
    # loader
    "FirmwareImage", "load_firmware", "load_elf", "load_raw",
    # lifter
    "RiscvLifter", "lift_firmware", "LiftResult",
    # cfg
    "build_program",
    # matcher
    "SemanticMatcher", "MatchConfig", "MatchStatus", "BlockMatch", "PredicateResult",
    # reachability
    "ReachabilitySolver", "ReachabilityResult", "Verdict", "ControlStatus",
    "InputConstraint",
    # evidence
    "EvidenceGraph", "Node", "Edge", "build_graph_from_analysis",
    # pipeline
    "run_analysis", "generate_report", "AnalysisConfig", "AnalysisRun",
]
