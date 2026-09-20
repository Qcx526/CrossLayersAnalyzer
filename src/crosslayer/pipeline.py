"""
跨层漏洞分析 —— 端到端流水线

一条命令完成：固件 → 提升 → CFG → 契约匹配 → 可达性/可控性求解 → 证据图 → 报告

与 Astra 方案骨架的对应关系
--------------------------
  Astra:   上游结果 → 契约/能力 → 固件语义分析 → 候选链 → 定向搜索 → 回放 → 报告
  本实现:  contract  →  loader → lifter → cfg → matcher → reachability → evidence → report

两处内核替换（相对 Astra）：
  1. 候选链生成：知识图谱关联 → HW-SCM 因果反推 + IR 层语义匹配
  2. 搜索反馈  ：覆盖率        → 约束进展度（progress）
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from .cfg import build_program
from .contracts import TriggerContract
from .evidence import EvidenceGraph, build_graph_from_analysis
from .lifter import lift_firmware
from .loader import FirmwareImage, load_firmware
from .matcher import MatchStatus, SemanticMatcher
from .reachability import ReachabilitySolver, Verdict


@dataclass
class AnalysisConfig:
    """一次分析的配置。"""

    target_id: str = "target"
    route: str = "B"                     # A / B / C
    input_regs: tuple[str, ...] = ("a0", "a1")
    input_entries: dict[str, int] = field(default_factory=dict)
    solver_timeout_ms: int = 10_000
    max_candidates: int = 50
    min_progress: float = 1.0
    partial_threshold: float = 0.34


@dataclass
class AnalysisRun:
    """一次分析的完整结果。"""

    run_id: str
    started_at: float
    finished_at: float = 0.0
    image: Optional[FirmwareImage] = None
    program: Any = None
    matches: list[Any] = field(default_factory=list)
    results: list[Any] = field(default_factory=list)
    graph_info: dict[str, Any] = field(default_factory=dict)

    def elapsed(self) -> float:
        return self.finished_at - self.started_at


# ---------------------------------------------------------------------------
def run_analysis(
    firmware_path: str | Path,
    contract: TriggerContract,
    config: Optional[AnalysisConfig] = None,
    db_path: Optional[str | Path] = None,
    base_address: Optional[int] = None,
    arch: str = "riscv32",
    verbose: bool = True,
) -> AnalysisRun:
    """执行端到端分析。"""
    cfg = config or AnalysisConfig()
    t0 = time.time()
    run_id = f"run_{time.strftime('%Y%m%d_%H%M%S')}_{cfg.target_id}"

    def log(msg: str) -> None:
        if verbose:
            print(f"[{time.time()-t0:6.2f}s] {msg}")

    # ---- 1. 加载（身份固定）----
    log(f"加载原始固件: {firmware_path}")
    image = load_firmware(firmware_path, base_address=base_address, arch=arch)
    log(f"  sha256={image.sha256[:16]}…  {image.fmt}/{image.arch}  "
        f"entry=0x{image.entry_point:x}  可执行段={len(image.executable_segments())}")

    # ---- 2. 提升 ----
    log("提升为统一 IR …")
    lifted = lift_firmware(image, input_regs=cfg.input_regs)
    log(f"  指令 {lifted.total_count}，未识别 {lifted.unknown_count} "
        f"({lifted.unknown_ratio():.1%})")
    if lifted.unknown_ratio() > 0.5:
        log("  警告：未识别指令比例过高（>50%），后续分析结论不可靠")

    # ---- 3. CFG ----
    log("构建 CFG …")
    # 外部输入入口：若调用方未显式给出，则把 input_regs 登记为入口。
    # 这一步不能省 —— 否则可达性分析只从程序入口出发，
    # 而"攻击者能从哪些接口进入"正是跨层分析的起点。
    input_entries = dict(cfg.input_entries or {})
    if not input_entries and cfg.input_regs:
        for r in cfg.input_regs:
            input_entries[f"input:{r}"] = image.entry_point

    prog = build_program(
        name=Path(firmware_path).name, lifted=lifted, arch=image.arch,
        base_addr=image.base_address, entry_addr=image.entry_point,
        symbols=image.symbols or None,
        input_entries=input_entries or None,
    )
    log(f"  基本块 {prog.stats['blocks']}，边 {prog.stats['edges']}，"
        f"函数 {prog.stats['functions']}，"
        f"不可达块 {prog.stats['unreachable_blocks']}")

    # ---- 4. 匹配 ----
    log("契约语义匹配 …")
    matcher = SemanticMatcher()
    matches = matcher.match(contract, prog)
    mrep = matcher.report(matches)
    log(f"  状态分布: {mrep['status_histogram']}  最高进展度: {mrep['best_progress']}")
    log(f"  契约形式化率: "
        f"{contract.formalization_report()['formalization_ratio']:.0%}，"
        f"未形式化条件 {contract.formalization_report()['unformalized_predicates']} 条")

    # ---- 5. 可达性与可控性 ----
    log("可达性与操作数可控性求解 …")
    solver = ReachabilitySolver(timeout_ms=cfg.solver_timeout_ms)
    results = solver.analyze(contract, prog, matches,
                             max_candidates=cfg.max_candidates)
    rrep = solver.report(results)
    log(f"  判定分布: {rrep['verdict_histogram']}")

    # ---- 6. 证据图 ----
    graph_info: dict[str, Any] = {}
    if db_path:
        log(f"写入证据图 {db_path} …")
        g = EvidenceGraph(db_path)
        graph_info = build_graph_from_analysis(
            g, contract, image.identity(), prog, results,
            target_id=cfg.target_id, route=cfg.route,
        )
        stats = g.statistics()
        log(f"  节点 {stats['nodes']}，边 {stats['edges']}"
            f"（推理 {stats['inference_edges']} / 观测 {stats['observation_edges']}）")
        g.close()

    return AnalysisRun(
        run_id=run_id, started_at=t0, finished_at=time.time(),
        image=image, program=prog, matches=matches, results=results,
        graph_info=graph_info,
    )


# ---------------------------------------------------------------------------
def generate_report(run: AnalysisRun, contract: TriggerContract,
                    out_path: str | Path) -> Path:
    """
    生成 Markdown 报告。

    报告纪律：
    - 明确列出**未形式化的条件**，不隐藏分析能力的边界
    - 区分"到达/触发/影响"三重证据，不用单一分数掩盖缺项
    - UNKNOWN 单独成节，不并入负例
    """
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    img = run.image
    ident = img.identity() if img else {}
    form = contract.formalization_report()

    feas = [r for r in run.results if r.verdict is Verdict.EXPLOITABLE_CANDIDATE]
    pdep = [r for r in run.results if r.verdict is Verdict.PATH_DEPENDENT]
    unc = [r for r in run.results
           if r.verdict is Verdict.PRESENT_BUT_UNCONTROLLABLE]
    unreach = [r for r in run.results
               if r.verdict is Verdict.PRESENT_BUT_UNREACHABLE]
    absent = [r for r in run.results if r.verdict is Verdict.NOT_PRESENT]
    notctrl = [r for r in run.results if r.verdict is Verdict.NOT_CONTROLLABLE]
    unknown = [r for r in run.results if r.verdict is Verdict.UNKNOWN]

    L: list[str] = []
    w = L.append

    w(f"# 跨层漏洞分析报告 — {contract.name}")
    w("")
    w(f"- **运行 ID**：`{run.run_id}`")
    w(f"- **分析路线**：{run.graph_info.get('values',{}).get('target_id','')} / "
      f"思路 {contract.provenance.get('route','B')}")
    w(f"- **耗时**：{run.elapsed():.2f} s")
    w("")
    w("> 本报告的全部结论均基于**原始固件镜像**的静态与约束分析（证据级别 E1）。")
    w("> 未在真实硬件或 RTL 上执行验证，因此**不构成实机可利用性结论**。")
    w("")

    # ---- 1. 镜像身份 ----
    w("## 1. 分析对象身份（镜像未被修改）")
    w("")
    w("| 字段 | 值 |")
    w("|---|---|")
    for k in ["path", "sha256", "size", "format", "arch", "entry_point",
              "base_address", "has_symbols", "has_debug_info"]:
        w(f"| {k} | `{ident.get(k)}` |")
    w(f"| 可执行段 | {len(ident.get('executable_segments', []))} 个 |")
    w("")
    w(f"*{ident.get('identity_notes','')}*")
    w("")
    if not ident.get("has_symbols"):
        w("⚠️ **无符号表**：函数边界为启发式识别，报告中的函数名不可作为定位依据。")
        w("")
    if not ident.get("has_debug_info"):
        w("⚠️ **无调试信息**：仅提供 PC / 指令 / 硬件模块级定位，"
          "**不能声称源码行号**。")
        w("")

    # ---- 2. 契约与形式化完整性 ----
    w("## 2. 硬件触发契约")
    w("")
    w(f"- 契约 ID：`{contract.contract_id}`")
    w(f"- 缺陷类别：`{contract.bug_class.value}`")
    w(f"- 来源：{contract.source_ref or '未标注'}")
    w(f"- 证据级别：**{contract.evidence_level}**")
    w("")
    w(f"**形式化完整性**：{form['checkable_predicates']} / "
      f"{form['total_predicates']} 个谓词可检查"
      f"（{form['formalization_ratio']:.0%}）")
    w("")
    if form["unformalized_predicates"]:
        w(f"⚠️ 有 **{form['unformalized_predicates']} 条条件无法在本系统中检查**：")
        w("")
        for n in form["unformalized_notes"]:
            w(f"  - {n}")
        w("")
        w("这些条件**未被验证**，不等价于已满足，也不等价于不满足。")
        w("")
    if form["is_minimal_poc"]:
        w(f"⚠️ {form['warning']}")
        w("")

    # ---- 3. 程序摘要 ----
    w("## 3. 固件程序摘要")
    w("")
    st = run.program.stats if run.program else {}
    w("| 指标 | 值 |")
    w("|---|---|")
    for k, v in st.items():
        w(f"| {k} | `{v}` |")
    w("")

    # ---- 3b. 控制流可信度 ----
    #
    # 这一节的存在本身就是一条设计纪律：间接跳转解析不出来的部分，
    # 不能被静默地渲染成"不可达"。必须让读者知道 CFG 有多可信。
    n_ind = st.get("indirect_jumps", 0)
    n_res = st.get("indirect_resolved", 0)
    conf = st.get("cfg_confidence", "unknown")
    if n_ind:
        w("### 3b. 控制流可信度")
        w("")
        w(f"- 间接跳转（jalr/jr，无法静态确定目标）：**{n_ind}** 处")
        w(f"- 其中已解析出目标：{n_res} 处")
        w(f"- 未解析（走保守兜底）：{n_ind - n_res} 处")
        w(f"- 控制流可信度评级：**{conf}**")
        w("")
        if conf != "high":
            w("⚠️ **不可达性结论的强度受此限制。** "
              "间接跳转无法静态解析时，本分析器采用**保守过近似**"
              "（宁可多连边也不漏边），因此：")
            w("")
            w("  - 报出的「可达 + 可控」候选**不受影响**（过近似只会多报，不会漏报）")
            w("  - 报出的「不可达」结论**可能偏保守**——"
              "真实可能通过间接跳转到达的地方，会在这里被接上")
            w("  - 反过来，若某处**仍然**被判为不可达，说明该地址"
              "连兜底策略都没能连上，可信度较高")
            w("")
        if conf == "low":
            w("⚠️ **可信度为 low**：超过一半的间接跳转无法解析。"
              "此时建议人工确认这些 `jalr` 的目标范围后再采信可达性结论。")
            w("")
    if run.program and run.program.summary()["op_histogram"]:
        w("**操作类别分布（前 15）**")
        w("")
        w("| 操作类别 | 数量 |")
        w("|---|---|")
        for k, v in list(run.program.summary()["op_histogram"].items())[:15]:
            w(f"| {k} | {v} |")
        w("")

    # ---- 4. 判定结果 ----
    w("## 4. 判定结果")
    w("")
    w(f"- **可行候选**（可达 + 操作数可控）：**{len(feas)}**")
    w(f"- 可达但可控性随路径而变：{len(pdep)}")
    w(f"- 片段存在但操作数不可控：{len(unc)}")
    w(f"- 操作数不可控但值静态未知：{len(notctrl)}")
    w(f"- 片段存在但不可达：{len(unreach)}")
    w(f"- 触发片段不存在：{len(absent)}")
    w(f"- 无法判定（UNKNOWN）：{len(unknown)}")
    w("")
    if unknown:
        w("⚠️ UNKNOWN 表示**信息不足或求解超时**，"
          "**不等价于不可利用**，不得并入负例统计。")
        w("")
    if pdep:
        w("⚠️ **路径相关（path_dependent）**：该位置的触发条件在**部分路径**上"
          "成立、在另一部分路径上不成立。按路径分别评估，"
          "不应笼统归入可行或不可行。")
        w("")

    # ---- 5. 可行候选详情 ----
    #
    # 章节号是**动态**的：条件章节不出现时不留空号。
    # 固定编号会在"本样本没有可行候选"的报告里出现 4 → 6 的跳号，
    # 让人误以为漏印了一节。
    sec = 5

    if feas:
        w(f"## {sec}. 可行候选详情")
        w("")
        sec += 1
        for i, r in enumerate(feas, 1):
            w(f"### 候选 {i}：`0x{r.block_addr:08x}`")
            w("")
            w(f"- 关键指令：`{r.key_insn}` @ `0x{r.key_addr:08x}`"
              if r.key_addr is not None else f"- 关键指令：`{r.key_insn}`")
            w(f"- 到达路径长度：{r.path_length} 个基本块，"
              f"入口 `{r.entry_point}`")
            w(f"- 污点源：{r.taint_sources}")
            w(f"- 约束进展度：{r.progress:.2%}")
            w(f"- 求解状态：**{r.satisfiability}**"
              + (f"（求解器 {r.solver}，超时 {r.timeout_ms} ms）"
                 if r.solver else ""))
            if r.input_constraints:
                w("")
                w("**求解出的输入约束**：")
                w("")
                w("| 变量 | 位宽 | 模型值 |")
                w("|---|---|---|")
                for c in r.input_constraints:
                    mv = f"0x{c.model_value:x}" if c.model_value is not None else "—"
                    w(f"| `{c.var_name}` | {c.width} | `{mv}` |")
            if r.notes:
                w("")
                for n in r.notes:
                    w(f"- {n}")
            w("")

    # ---- 路径相关候选详情 ----
    if pdep:
        w(f"## {sec}. 路径相关候选详情")
        w("")
        sec += 1
        w("以下位置的触发片段**存在且可达**，但操作数可控性取决于"
          "进入该基本块的路径，因此不能简单归入可行或不可行。")
        w("")
        for i, r in enumerate(pdep, 1):
            w(f"### 路径相关 {i}：`0x{r.block_addr:08x}`")
            w("")
            if r.key_addr is not None:
                w(f"- 关键指令：`{r.key_insn}` @ `0x{r.key_addr:08x}`")
            else:
                w(f"- 关键指令：`{r.key_insn}`")
            w(f"- 到达路径长度：{r.path_length} 个基本块，"
              f"入口 `{r.entry_point}`")
            w(f"- 污点源：{r.taint_sources or '（无外部输入污点）'}")
            w(f"- 约束进展度：{r.progress:.2%}")
            for n in (r.notes or []):
                w(f"- {n}")
            w("")

    # ---- 负例与不可利用分析 ----
    if unreach or unc or pdep or absent or notctrl:
        w(f"## {sec}. 不可利用候选分析（负例）")
        w("")
        sec += 1
        w("负例与正例同等重要：它们说明漏洞在**这份固件**上为何不可利用。")
        w("")
        sub = 1
        if pdep:
            w(f"### {sub}. 可达但可控性随路径而变")
            sub += 1
            w("")
            w("| 地址 | 关键指令 | 说明 |")
            w("|---|---|---|")
            for r in pdep[:20]:
                w(f"| `0x{r.block_addr:08x}` | `{r.key_insn}` | "
                  f"{'; '.join(r.notes) or '部分路径上可控、部分路径上为常量'} |")
            w("")
        if unc:
            w(f"### {sub}. 存在但操作数不可控（恒为常量）")
            sub += 1
            w("")
            w("| 地址 | 关键指令 | 说明 |")
            w("|---|---|---|")
            for r in unc[:20]:
                w(f"| `0x{r.block_addr:08x}` | `{r.key_insn}` | "
                  f"{'; '.join(r.notes) or '操作数恒为常量'} |")
            w("")
        if notctrl:
            w(f"### {sub}. 存在但操作数不受外部输入影响（值静态未知）")
            sub += 1
            w("")
            w("这类情形**不是**「操作数为常量」，而是「攻击者影响不了它」——"
              "例如操作数来自常量地址的内存读取。结论同样是不可利用，"
              "但证据性质不同，不应混为一谈。")
            w("")
            w("| 地址 | 关键指令 | 说明 |")
            w("|---|---|---|")
            for r in notctrl[:20]:
                w(f"| `0x{r.block_addr:08x}` | `{r.key_insn}` | "
                  f"{'; '.join(r.notes) or '无外部输入污点可达'} |")
            w("")
        if unreach:
            w(f"### {sub}. 存在但不可达")
            sub += 1
            w("")
            w("| 地址 | 关键指令 | 说明 |")
            w("|---|---|---|")
            for r in unreach[:20]:
                w(f"| `0x{r.block_addr:08x}` | `{r.key_insn}` | "
                  f"{'; '.join(r.notes) or '无外部输入入口可达'} |")
            w("")
        if absent:
            w(f"### {sub}. 触发片段不存在")
            sub += 1
            w("")
            w("| 地址 | 说明 |")
            w("|---|---|")
            for r in absent[:20]:
                w(f"| `0x{r.block_addr:08x}` | "
                  f"{'; '.join(r.notes) or '全程序未出现该操作类别'} |")
            w("")

    # ---- 未决事项 ----
    w(f"## {sec}. 未决事项与证据边界")
    sec += 1
    w("")
    w("| 证据层级 | 状态 | 说明 |")
    w("|---|---|---|")
    w("| E0 语义关联 | ✅ 已完成 | 契约与代码位置的静态关联 |")
    w("| E1 静态/约束满足 | ✅ 已完成 | 本报告的主要结论层级 |")
    w("| E2 模型可重放 | ❌ 未进行 | 需在模拟器/RTL 上加载同一镜像 |")
    w("| E3 有漏洞 RTL 验证 | ❌ 未进行 | 需匹配的目标 RTL |")
    w("| E4 板卡验证 | ❌ 未进行 | 需原始目标板卡与固件 |")
    w("")
    w("**因此本报告只能支持「在这份固件的静态分析中，"
      "存在满足该触发契约可达性与可控性的候选」这一结论，"
      "不能支持「该攻击在目标设备上成立」。**")
    w("")
    # 把分析能力边界逐条落到纸面
    n_ind = st.get("indirect_jumps", 0)
    n_res = st.get("indirect_resolved", 0)
    lim: list[str] = []
    if n_ind and n_res < n_ind:
        lim.append(
            f"间接跳转 {n_ind} 处中 {n_ind - n_res} 处无法静态解析目标；"
            f"已采用保守过近似（宁可多连边也不漏边），"
            f"因此「不可达」结论偏保守。"
        )
    if not ident.get("has_symbols"):
        lim.append("无符号表：函数边界为启发式识别，函数名不可作为定位依据。")
    if form["unformalized_predicates"]:
        lim.append(
            f"契约有 {form['unformalized_predicates']} 条条件无法检查，"
            f"未验证 ≠ 已满足。"
        )
    lim.append(
        "未建模：隐式信息流（控制依赖）、中断与并发、微架构时序。"
    )
    lim.append(
        "「可控」判定基于污点可达；若外部输入在更早位置已被校验，"
        "本分析不会发现 —— 这是「可控」与「可利用」之间的真实差距。"
    )
    w("**具体的分析能力边界**：")
    w("")
    for s in lim:
        w(f"- {s}")
    w("")

    # ---- 复现信息 ----
    w(f"## {sec}. 复现信息")
    w("")
    w("```json")
    w(json.dumps({
        "run_id": run.run_id,
        "firmware_sha256": ident.get("sha256"),
        "contract_id": contract.contract_id,
        "elapsed_sec": round(run.elapsed(), 3),
        "program_stats": st,
        "formalization": form,
    }, ensure_ascii=False, indent=2))
    w("```")

    out.write_text("\n".join(L), encoding="utf-8")
    return out
