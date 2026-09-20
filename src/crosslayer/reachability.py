"""
跨层漏洞分析 —— 可达性与操作数可控性求解（核心创新点 A）

问题定义
--------
给定：
  - 一份**不可替换的原始固件** B
  - 一个硬件触发契约 H（已知其触发所需的操作与操作数关系）
  - 外部输入入口集合 I

求解：
  是否存在输入序列 u，使得
      Reach(B, u)  ∧  Trigger(H) 被满足  ∧  操作数可控于 u

与 Coppelia (MICRO'18) 的区别
-----------------------------
Coppelia 从 **reset 状态**做符号执行，求解"输入 → 违规状态"，
其产物是**一个新的测试程序**。

本模块从**固件实际可达的状态**出发，求解"外部输入 → 固件执行到已有片段
→ 该片段满足触发条件"。搜索空间被固件 CFG 约束，且产物是
**输入序列**而非新程序。

关键分析维度：操作数可控性
--------------------------
"片段存在" != "片段可利用"。三种情形必须区分：

  A. 片段存在，且操作数可由外部输入控制   → 可利用候选
  B. 片段存在，但操作数恒为常量           → 不可利用（常量折叠会杀死可行性）
  C. 片段存在，但所在基本块不可从输入入口到达 → 不可利用

本模块对 A/B/C 给出明确分类，而不是笼统地报"找到片段"。
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

import networkx as nx
import z3

from .contracts import Capability, Primitive, TriggerContract
from .ir import BasicBlock, Expr, ExprKind, Instruction, OpClass, Program
from .matcher import (BlockMatch, MatchStatus, _insn_is_input_independent,
                      _insn_taint, _propagate_constants,
                      _propagate_constants_ipa,
                      _propagate_constants_ipa_perpath,
                      _propagate_input_independence)


# ---------------------------------------------------------------------------
class ControlStatus(enum.Enum):
    """操作数可控性状态。"""

    CONTROLLED = "controlled"          # 可由外部输入控制（可利用）
    CONSTANT = "constant"              # 恒为常量（可静态求值）
    NOT_CONTROLLABLE = "not_controllable"
                                       # 无外部输入可达（不可控），但具体值
                                       # 静态未知（如从常量地址 load 得到）。
                                       # 与 CONSTANT 的区别很重要：
                                       # 不能说"它是常量"，只能说"攻击者影响不了它"。
    PATH_DEPENDENT = "path_dependent"  # 取决于进入本块的路径：某条路径上恒定、
                                       # 另一条路径上可变 —— 比 unknown 精确
    UNKNOWN = "unknown"                # 连"是否受外部输入影响"都无法判定
    NOT_PRESENT = "not_present"        # 操作不存在


class Verdict(enum.Enum):
    """
    最终判定。

    这是给报告用的结论类型。`UNKNOWN` 是一等公民 ——
    在证据不足时必须返回它，绝不能降级成"未发现漏洞"。
    """

    EXPLOITABLE_CANDIDATE = "exploitable_candidate"    # 可达 + 可控，进入求解
    PATH_DEPENDENT = "path_dependent"                  # 可达，但可控性随路径而变
    PRESENT_BUT_UNCONTROLLABLE = "present_but_uncontrollable"
    PRESENT_BUT_UNREACHABLE = "present_but_unreachable"
    NOT_PRESENT = "not_present"
    UNKNOWN = "unknown"
    NOT_CONTROLLABLE = "not_controllable"              # 不可控但值未知


@dataclass
class InputConstraint:
    """求解出的输入约束（供真实接口回放）。"""

    var_name: str
    width: int
    constraint_smtlib: str
    model_value: Optional[int] = None
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "var": self.var_name,
            "width": self.width,
            "constraint": self.constraint_smtlib,
            "model_value": (f"0x{self.model_value:x}"
                            if self.model_value is not None else None),
            "description": self.description,
        }


@dataclass
class ReachabilityResult:
    """
    单个候选的分析结果。

    `counterexample` 是求解出的具体输入值（若 sat）；
    `minimal_conflict` 是 unsat 时的最小冲突集。
    两者都要保留 —— 负例的证据与正例同等重要。
    """

    block_id: str
    block_addr: int
    verdict: Verdict
    control_status: ControlStatus = ControlStatus.UNKNOWN

    # 路径信息
    path_from_entry: list[str] = field(default_factory=list)
    entry_point: Optional[str] = None
    path_length: int = 0

    # 求解信息
    satisfiability: str = "not_checked"        # sat / unsat / unknown / not_checked
    solver: str = ""
    timeout_ms: int = 0
    input_constraints: list[InputConstraint] = field(default_factory=list)
    minimal_conflict: list[str] = field(default_factory=list)

    # 关键指令
    key_addr: Optional[int] = None
    key_insn: Optional[str] = None
    taint_sources: list[str] = field(default_factory=list)

    # 约束进展度（创新点 C）
    progress: float = 0.0

    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "block_id": self.block_id,
            "block_addr": f"0x{self.block_addr:08x}",
            "verdict": self.verdict.value,
            "control_status": self.control_status.value,
            "satisfiability": self.satisfiability,
            "solver": self.solver,
            "timeout_ms": self.timeout_ms,
            "progress": round(self.progress, 4),
            "path_length": self.path_length,
            "entry_point": self.entry_point,
            "path_from_entry": self.path_from_entry,
            "key_addr": (f"0x{self.key_addr:08x}"
                         if self.key_addr is not None else None),
            "key_insn": self.key_insn,
            "taint_sources": self.taint_sources,
            "input_constraints": [c.to_dict() for c in self.input_constraints],
            "minimal_conflict": self.minimal_conflict,
            "notes": self.notes,
        }


# ---------------------------------------------------------------------------
class ReachabilitySolver:
    """
    可达性与可控性求解器。

    Parameters
    ----------
    solver_name : "z3"
    timeout_ms  : 单次求解超时。超时必须返回 unknown，不能当成 unsat。
    """

    SOLVER_TIMEOUT_MS_DEFAULT = 10_000

    def __init__(self, timeout_ms: int = SOLVER_TIMEOUT_MS_DEFAULT) -> None:
        self.timeout_ms = timeout_ms
        self.solver_name = f"z3-{z3.get_version_string()}"
        # 跨块常量表，由 analyze() 填充（addr -> {reg: const}）
        self._const_map: dict[int, dict[str, int]] = {}
        # per-path 常量表，由 analyze() 填充（addr -> [{reg: const}, ...]）
        self._perpath_map: dict[int, list[dict[str, int]]] = {}
        # "不受外部输入影响"的寄存器集合表（addr -> {reg, ...}）
        self._indep_map: dict[int, set[str]] = {}

    # ------------------------------------------------------------------
    def analyze(self, contract: TriggerContract, prog: Program,
                matches: list[BlockMatch],
                max_candidates: int = 50) -> list[ReachabilityResult]:
        """
        对匹配器的候选做可达性与可控性分析。

        只分析 MATCH 与 PARTIAL 状态的候选 —— 这是"由粗到细"的收敛。
        """
        graph = self._build_graph(prog)
        entry_bids = self._entry_blocks(prog)

        # 跨块常量传播：必须在所有块上统一做一次，
        # 否则「上一块赋值常量、本块使用」会被误判为不可控/未知。
        try:
            self._const_map = _propagate_constants_ipa(list(prog.blocks.values()))
        except Exception:
            self._const_map = {}
        try:
            self._perpath_map = _propagate_constants_ipa_perpath(
                list(prog.blocks.values()))
        except Exception:
            self._perpath_map = {}
        try:
            indep: dict[int, set[str]] = {}
            for b in prog.blocks.values():
                # 用块自身的指令做块内传播；跨块入口状态保守取空集，
                # 因此结论只会偏保守（少判 independent），不会误判。
                indep.update(_propagate_input_independence(b.instructions))
            self._indep_map = indep
        except Exception:
            self._indep_map = {}

        out: list[ReachabilityResult] = []
        for m in matches[:max_candidates]:
            if m.status in (MatchStatus.NO_MATCH,):
                continue
            out.append(self._analyze_one(m, contract, prog, graph, entry_bids))

        # ---- 补充"显式阴性判定" ----
        # 匹配器的候选只覆盖"至少含一个相关指令"的块。
        # 对于完全不含契约要求的操作类别的块，必须给出显式的 NOT_PRESENT，
        # 否则"没找到候选"与"确认不存在"会被混为一谈 ——
        # 在安全分析里这是不可接受的：报告必须能说清"检查过了，没有"。
        out.extend(self._absent_findings(contract, prog, graph,
                                         entry_bids, out))

        # 排序：可行候选优先，其次按进展度
        vorder = {
            Verdict.EXPLOITABLE_CANDIDATE: 0,
            Verdict.PATH_DEPENDENT: 1,
            Verdict.UNKNOWN: 2,
            Verdict.NOT_CONTROLLABLE: 3,
            Verdict.PRESENT_BUT_UNCONTROLLABLE: 4,
            Verdict.PRESENT_BUT_UNREACHABLE: 5,
            Verdict.NOT_PRESENT: 6,
        }
        out.sort(key=lambda r: (vorder[r.verdict], -r.progress, r.block_addr))
        return out

    # ------------------------------------------------------------------
    def _absent_findings(
        self, contract: TriggerContract, prog: Program, graph: nx.DiGraph,
        entry_bids: list[str], existing: list[ReachabilityResult],
    ) -> list[ReachabilityResult]:
        """
        为"不含契约要求操作类别"的块生成显式 NOT_PRESENT 判定。

        策略：
        - 只有当**整个程序**都不含契约要求的操作类别时，才在入口块报告一条
          NOT_PRESENT（避免为每个空块都产生噪音）。
        - 若程序含相关指令但都不可达，则对**不可达**的块报告
          PRESENT_BUT_UNREACHABLE —— 这比 NOT_PRESENT 更准确，
          因为它说明"代码里确实有，只是执行不到"。
        """
        required = contract.required_op_classes()
        if not required:
            return []

        # 判别性操作类别：只有触发事件本身的硬件操作缺失，
        # 才说明"漏洞不存在"。支撑性操作（写回等）的缺失不影响存在性判断。
        trigger_ops = contract.trigger_op_classes()

        # 全程序范围内是否存在**触发事件**对应的指令
        trigger_insns = prog.find_instructions(trigger_ops)
        present_anywhere = prog.find_instructions(required)
        covered = {r.block_id for r in existing}

        # 情形 A：整个程序都没有触发事件的操作 → 一条全局 NOT_PRESENT
        if not trigger_insns:
            entry_bid = entry_bids[0] if entry_bids else next(
                iter(prog.blocks), None)
            if entry_bid is None or entry_bid in covered:
                return []
            bb = prog.blocks[entry_bid]
            support_missing = sorted(
                o.value for o in (required - trigger_ops)
                if not prog.find_instructions({o})
            )
            note = (
                f"全程序范围内未出现触发事件要求的操作类别 "
                f"{sorted(o.value for o in trigger_ops)}，触发片段不存在"
            )
            if support_missing:
                note += (f"；另有支撑性操作类别 {support_missing} 未出现，"
                         f"但这不是判定不存在的依据")
            return [ReachabilityResult(
                block_id=entry_bid, block_addr=bb.start_addr,
                verdict=Verdict.NOT_PRESENT,
                control_status=ControlStatus.NOT_PRESENT,
                entry_point=entry_bid,
                notes=[note],
                progress=0.0,
            )]

        # 情形 B：存在相关指令但位于不可达块 → 对每个不可达块报告
        absent: list[ReachabilityResult] = []
        req_addrs = {i.addr for i in present_anywhere}
        for bb in prog.blocks.values():
            if bb.block_id in covered:
                continue
            if bb.reachable:
                continue
            insns = [i for i in bb.instructions if i.addr in req_addrs]
            if not insns:
                continue
            first = insns[0]
            absent.append(ReachabilityResult(
                block_id=bb.block_id, block_addr=bb.start_addr,
                verdict=Verdict.PRESENT_BUT_UNREACHABLE,
                control_status=ControlStatus.NOT_PRESENT,
                key_addr=first.addr,
                key_insn=f"{first.mnemonic} {first.op_class.value}",
                notes=[
                    f"触发片段存在于不可达基本块 {bb.block_id}"
                    f"（地址 0x{bb.start_addr:08x}），"
                    f"无法从任何外部输入入口到达"
                ],
                progress=0.0,
            ))
        return absent

    # ------------------------------------------------------------------
    def _analyze_one(self, m: BlockMatch, contract: TriggerContract,
                     prog: Program, graph: nx.DiGraph,
                     entry_bids: list[str]) -> ReachabilityResult:
        bb = prog.blocks[m.block_id]
        notes: list[str] = []

        # ---- 1. 控制流可达性 ----
        path, entry_bid = self._find_path(graph, entry_bids, m.block_id)
        reachable = path is not None

        # ---- 2. 操作数可控性 ----
        ctrl, key_addr, key_insn, taints = self._check_controllability(
            bb, contract, prog)

        # ---- 3. 综合判定 ----
        if not reachable:
            verdict = Verdict.PRESENT_BUT_UNREACHABLE
            notes.append(
                f"基本块 {m.block_id} 无法从任何外部输入入口到达"
                f"（已检查 {len(entry_bids)} 个入口）"
            )
        elif ctrl is ControlStatus.CONSTANT:
            verdict = Verdict.PRESENT_BUT_UNCONTROLLABLE
            notes.append(
                "操作数恒为常量：常量折叠后触发条件无法由外部输入满足"
            )
        elif ctrl is ControlStatus.NOT_CONTROLLABLE:
            verdict = Verdict.NOT_CONTROLLABLE
            notes.append(
                "操作数不可由外部输入影响（无输入污点可达），"
                "但其具体值静态不可知（如从常量地址 load）。"
                "结论：攻击者无法影响该触发条件；"
                "注意这与「操作数是常量」不同 —— 只是「攻击者控制不了」。"
            )
        elif ctrl is ControlStatus.PATH_DEPENDENT:
            verdict = Verdict.PATH_DEPENDENT
            notes.append(
                "操作数可控性取决于进入本块的路径：在部分路径上为常量、"
                "在另一部分路径上可变。需按具体路径分别评估，"
                "不能笼统判为可控或不可控。"
            )
        elif ctrl is ControlStatus.CONTROLLED:
            verdict = Verdict.EXPLOITABLE_CANDIDATE
        else:
            verdict = Verdict.UNKNOWN
            notes.append("操作数可控性无法判定，需符号执行确认")

        res = ReachabilityResult(
            block_id=m.block_id, block_addr=bb.start_addr, verdict=verdict,
            control_status=ctrl,
            path_from_entry=path or [], entry_point=entry_bid,
            path_length=len(path) if path else 0,
            key_addr=key_addr, key_insn=key_insn,
            taint_sources=sorted(taints),
            progress=m.progress(),
            notes=notes,
        )

        # ---- 4. 对可行候选做约束求解 ----
        if verdict is Verdict.EXPLOITABLE_CANDIDATE:
            self._solve_constraints(res, bb, contract, prog)

        return res

    # ------------------------------------------------------------------
    def _check_controllability(self, bb: BasicBlock, contract: TriggerContract,
                               prog: Program):
        """
        检查触发相关指令的操作数是否受外部输入控制。

        返回 (status, key_addr, key_insn, taint_sources)
        """
        required = contract.required_op_classes()
        if not required:
            # 契约未指定操作类别 —— 检查块内所有指令
            required = {i.op_class for i in bb.instructions}

        candidate_insns = [i for i in bb.instructions if i.op_class in required]
        if not candidate_insns:
            return ControlStatus.NOT_PRESENT, None, None, set()

        # 对每条相关指令，检查是否带输入污点
        for insn in candidate_insns:
            t = _insn_taint(insn)
            input_t = {s for s in t if s.startswith("input:")}
            if input_t:
                return (ControlStatus.CONTROLLED, insn.addr,
                        f"{insn.mnemonic} {insn.op_class.value}", t)

        # 没有输入污点：区分"常量"与"未知"
        # 若相关指令的**全部源操作数**都可由常量传播静态求值 → CONSTANT。
        #
        # 注意：只检查 sources（读取的操作数），不能检查 operands（写目标）。
        # 目标寄存器是在本指令之后才被定义的，必然不在"执行前"的常量表里，
        # 若把它算进来，任何指令都会被误判为"未知"。
        const_map = self._const_map if self._const_map else \
            _propagate_constants(bb.instructions)
        all_const = True
        for insn in candidate_insns:
            st = const_map.get(insn.addr, {})
            for s in insn.sources:
                if s.kind is ExprKind.CONST:
                    continue
                if s.kind is ExprKind.REG:
                    if s.name == "zero":
                        continue
                    if s.name in st:
                        continue
                all_const = False
                break
            if not all_const:
                break

        first = candidate_insns[0]
        label = f"{first.mnemonic} {first.op_class.value}"
        if all_const:
            return ControlStatus.CONSTANT, first.addr, label, set()

        # ---- must 分析失败（多前驱常量不一致）→ 用 per-path 分析细化 ----
        # 若在**某一条**路径上该操作数是常量，说明触发可达性与常量性
        # 取决于进入本块的前驱 —— 这是比 "unknown" 精确得多的结论。
        if self._perpath_map:
            path_states = self._perpath_map.get(first.addr) or []
            if len(path_states) > 1:
                const_on_some = False
                var_on_some = False
                for st in path_states:
                    ok = True
                    for s in first.sources:
                        if s.kind is ExprKind.CONST:
                            continue
                        if s.kind is ExprKind.REG:
                            if s.name == "zero" or s.name in st:
                                continue
                        ok = False
                        break
                    if ok:
                        const_on_some = True
                    else:
                        var_on_some = True
                if const_on_some and var_on_some:
                    return (ControlStatus.PATH_DEPENDENT, first.addr, label,
                            set())

        # ---- 最后一道区分：不可控 vs 未知 ----
        # 走到这里说明"无法把操作数求值为常量"。
        # 但仍要回答一个更有用的问题：**外部输入能不能影响它？**
        #   - 若相关指令及其依赖链上都没有外部输入污点 → 不可控
        #     （例如从常量地址 load 得到的数据、CSR 读出的值）
        #   - 若存在无法判定的来源（如未知来源的内存） → 才是真正的 unknown
        #
        # 注意：`_insn_taint` 为空**不等于**不可控 —— 它只说明"没有识别到的污点"。
        # 因此这里要求：所有源操作数都必须是"确定不受输入影响"的来源：
        # 常量、zero、或由常量地址 load 得到的值。
        if self._is_provably_input_independent(first, const_map):
            return (ControlStatus.NOT_CONTROLLABLE, first.addr, label, set())

        return ControlStatus.UNKNOWN, first.addr, label, set()

    # ------------------------------------------------------------------
    def _is_provably_input_independent(
        self, insn: Instruction, const_map: dict[int, dict[str, int]],
    ) -> bool:
        """
        判断一条指令的操作数是否**可证明**不受外部输入影响。

        直接复用 matcher 的 input-independence 传播 ——
        它给出的正是这个问题的答案（与"值是否为常量"是不同的问题）。
        """
        indep = self._indep_map.get(insn.addr)
        if indep is None:
            return False
        return _insn_is_input_independent(insn, indep)

    # ------------------------------------------------------------------
    def _solve_constraints(self, res: ReachabilityResult, bb: BasicBlock,
                           contract: TriggerContract, prog: Program) -> None:
        """
        对可行候选求解输入约束。

        这里做的是**局部**求解（仅该基本块 + 必要的前置状态），
        而不是对整个固件做符号执行 —— 这是 FuSS (ACM TECS 2025)
        的核心洞察：从已有轨迹出发做局部求解，而非从初始状态重新求解。
        """
        try:
            s = z3.Solver()
            s.set("timeout", self.timeout_ms)

            var_map: dict[str, z3.ExprRef] = {}
            # 为块内出现的输入污点源创建符号变量
            for tsrc in res.taint_sources:
                if tsrc.startswith("input:"):
                    base = tsrc.split(":", 1)[1]
                    if base.startswith("mem"):
                        continue
                    v = z3.BitVec(f"in_{base}", 32)
                    var_map[base] = v

            # 契约的操作数关系谓词作为约束
            constraints_added = 0
            for p in contract.all_predicates():
                if p.operand_constraint:
                    c = p.to_smt(var_map)
                    if c is not None:
                        s.add(c)
                        constraints_added += 1

            if not var_map:
                res.satisfiability = "unknown"
                res.notes.append(
                    "无可符号化的输入变量 —— 无法求解（记为 unknown，"
                    "不视为 unsat）"
                )
                return

            res.solver = self.solver_name
            res.timeout_ms = self.timeout_ms

            r = s.check()
            if r == z3.sat:
                res.satisfiability = "sat"
                model = s.model()
                for name, v in var_map.items():
                    val = model.eval(v, model_completion=True)
                    try:
                        concrete = val.as_long() & 0xFFFFFFFF
                    except Exception:
                        concrete = None
                    res.input_constraints.append(InputConstraint(
                        var_name=f"in_{name}", width=32,
                        constraint_smtlib=str(v),
                        model_value=concrete,
                        description=f"外部输入 {name} 的取值",
                    ))
                if constraints_added == 0:
                    res.notes.append(
                        "契约未提供可求解的操作数约束 —— 模型值仅代表"
                        "符号变量的一个任意解，需人工确认真实触发条件"
                    )
            elif r == z3.unsat:
                res.satisfiability = "unsat"
                res.minimal_conflict = self._minimal_conflict(s, res)
                res.verdict = Verdict.PRESENT_BUT_UNCONTROLLABLE
                res.notes.append(
                    "约束不可满足：固件实际执行路径无法满足该触发条件"
                )
            else:
                res.satisfiability = "unknown"
                res.notes.append(
                    f"求解超时（{self.timeout_ms} ms）—— 记为 unknown，"
                    "不视为 unsat。增大超时或缩小约束范围后重试"
                )

        except Exception as e:  # pragma: no cover
            res.satisfiability = "unknown"
            res.notes.append(f"求解异常 {type(e).__name__}: {e} —— 记为 unknown")

    # ------------------------------------------------------------------
    def _minimal_conflict(self, s: z3.Solver,
                          res: ReachabilityResult) -> list[str]:
        """提取最小冲突集（哪些约束无法同时满足）。"""
        try:
            core = s.unsat_core()
            return [str(c) for c in core]
        except Exception:
            return []

    # ------------------------------------------------------------------
    @staticmethod
    def _build_graph(prog: Program) -> nx.DiGraph:
        g = nx.DiGraph()
        for bid, bb in prog.blocks.items():
            g.add_node(bid)
            for s in bb.successors:
                g.add_edge(bid, s)
        return g

    @staticmethod
    def _entry_blocks(prog: Program) -> list[str]:
        """
        确定外部输入入口对应的基本块。

        优先使用显式声明的 inputs；否则回退到程序入口。
        """
        out: list[str] = []
        for name, addr in prog.inputs.items():
            bb = prog.block_of_addr(addr)
            if bb is not None:
                out.append(bb.block_id)
            else:
                # 入口地址落在某个块内（非块首）—— 找包含它的块
                for candid in prog.blocks.values():
                    if candid.start_addr <= addr < candid.end_addr:
                        out.append(candid.block_id)
                        break
        # 程序入口始终视为可达起点
        entry_bb = prog.block_of_addr(prog.entry_addr)
        if entry_bb is not None and entry_bb.block_id not in out:
            out.append(entry_bb.block_id)
        # 若仍为空（无符号信息），取所有 is_entry 块
        if not out:
            out = [b.block_id for b in prog.blocks.values() if b.is_entry]
        # 最后兜底：第一个可达块
        if not out:
            reach = [b.block_id for b in prog.blocks.values() if b.reachable]
            if reach:
                out = [reach[0]]
        return out

    @staticmethod
    def _find_path(graph: nx.DiGraph, entries: list[str],
                   target: str) -> tuple[Optional[list[str]], Optional[str]]:
        """在 CFG 上找从任一入口到目标的最短路径。"""
        best: Optional[list[str]] = None
        best_entry: Optional[str] = None
        for e in entries:
            if e == target:
                return [e], e
            if e not in graph or target not in graph:
                continue
            try:
                p = nx.shortest_path(graph, source=e, target=target)
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue
            if best is None or len(p) < len(best):
                best, best_entry = p, e
        return best, best_entry

    # ------------------------------------------------------------------
    @staticmethod
    def report(results: list[ReachabilityResult]) -> dict[str, Any]:
        """生成求解报告。"""
        hist: dict[str, int] = {}
        for r in results:
            hist[r.verdict.value] = hist.get(r.verdict.value, 0) + 1

        sat_results = [r for r in results if r.satisfiability == "sat"]
        return {
            "candidates_analyzed": len(results),
            "verdict_histogram": hist,
            "solvable_candidates": len(sat_results),
            "unknown_count": hist.get(Verdict.UNKNOWN.value, 0),
            "note": (
                "UNKNOWN 表示信息不足或求解超时，不等价于『不可利用』。"
                "报告中不可将其归入负例。"
            ),
            "details": [r.to_dict() for r in results],
        }
