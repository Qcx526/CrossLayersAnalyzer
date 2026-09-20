"""
跨层漏洞分析 —— 控制流图 (CFG) 构建

从提升后的指令序列构建基本块与 CFG，并识别：
- 基本块边界（分支目标、跳转后继、返回）
- 函数边界（优先用符号表，缺失时启发式识别）
- 外部输入入口（通过接口处理函数识别）
- ★ 纠正路径（看门狗喂狗、CRC 校验、重试循环）

关于"纠正路径"
--------------
ARMORY (IEEE TIFS 2021) 证明：针对某类故障的防护可能**大幅增加**
对其他故障模型的脆弱性。因此不能因为"固件有防护"就排除某条路径。
本模块只**标记**纠正路径的存在与位置，判定交给后续的分析层。
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable, Optional

import networkx as nx

from .ir import (
    BasicBlock, ExprKind, Function, Instruction, OpClass, Program,
)
from .lifter import LiftResult


# 常识别的纠正/防护机制关键字（来自符号表或字符串；缺失时不猜）
_CORRECTIVE_KEYWORDS = {
    "watchdog", "wdt", "feed", "kick", "wdi",
    "crc", "checksum", "parity", "ecc",
    "retry", "retries", "resend",
    "verify", "double_check", "redundant",
}


# ---------------------------------------------------------------------------
# 间接跳转解析
# ---------------------------------------------------------------------------
def _regs_in(exprs: Iterable, out: Optional[list[str]] = None) -> list[str]:
    """
    递归收集表达式树里出现的所有寄存器名（按出现顺序）。

    为什么需要递归：LOAD 的地址被提升为 `add(base, const(disp))` 这样的
    **嵌套 OP 表达式**，而不是裸 REG。不递归就会漏掉基址寄存器，
    导致 `lw t0, 24(a1)` 的 a1 找不着，跳转表解析失败。
    """
    if out is None:
        out = []
    for e in exprs:
        k = getattr(e, "kind", None)
        if k is ExprKind.REG:
            out.append(e.name)
        elif k is ExprKind.MEM:
            # 内存表达式的参数里藏着地址计算
            _regs_in(getattr(e, "args", ()), out)
        elif k is ExprKind.OP:
            _regs_in(getattr(e, "args", ()), out)
    return out


def _consts_in(exprs: Iterable, out: Optional[list[int]] = None) -> list[int]:
    """递归收集表达式树里的常量值（用于从 `add(base, 24)` 取出 24）。"""
    if out is None:
        out = []
    for e in exprs:
        k = getattr(e, "kind", None)
        if k is ExprKind.CONST and e.value is not None:
            out.append(e.value)
        elif k in (ExprKind.MEM, ExprKind.OP):
            _consts_in(getattr(e, "args", ()), out)
    return out


def _collect_indirect_targets(
    insns: list[Instruction],
    addr_set: set[int],
    next_addr: dict[int, int],
) -> tuple[dict[int, set[int]], set[int], int]:
    """
    为间接跳转（jalr / jr）猜测可能的目标地址。

    为什么必须做这件事
    ------------------
    间接跳转（函数指针、跳转表、`switch` 编译产物）如果不解析，
    目标块会被标成"不可达"，于是**真正的漏洞触发点被漏报（假阴性）**。
    对安全工具而言假阴性是致命缺陷：它意味着"我说安全，其实不安全"。

    本函数采用**保守过近似**策略，宁可多连边也不漏边：

      策略 1  —— 跳转表识别
        模式：`lw t0, off(base)` 紧邻 `jalr t0`。
        若 `base` 可追溯到一条已解析的 `lui`/`auipc` + 常量偏移，
        则该地址区间内的每个 4 字节对齐位置都可能是目标。
        取该区间的所有对齐地址（上限 `_MAX_TABLE_ENTRIES`，防止爆炸）。

      策略 2  —— 已知函数入口
        间接跳转的常见用途是调用函数指针。把所有已识别的
        "函数入口候选"（call/jump 的静态目标）作为可能目标。

      策略 3  —— 孤岛入口兜底
        若策略 1/2 都没结果，把**所有是分支/跳转目标但当前不可达**的块
        也接上。这是最强的过近似，但能保证不漏报。

    返回 (解析表, 兜底目标集, 间接跳转条数)。
    """
    # addr -> index，用于"取该地址之后的若干条指令"
    idx_of = {i.addr: k for k, i in enumerate(insns)}
    table_targets: dict[int, set[int]] = {}
    fallback: set[int] = set()

    def _const_of(reg_name: str, addr: int) -> Optional[int]:
        """在同一基本块内向前回溯，尝试得到某寄存器的常量值。"""
        k = idx_of.get(addr)
        if k is None:
            return None
        # 只回溯 8 条指令，足够覆盖 lui+addi / lui+lw 模式
        for j in range(k - 1, max(-1, k - 9), -1):
            ins = insns[j]
            writes = any(d.kind is ExprKind.REG and d.name == reg_name
                         for d in ins.operands)
            if not writes:
                continue
            if ins.op_class is OpClass.MOV and ins.immediate is not None:
                return ins.immediate
            # 形如 `addi base, base, imm` 或 `lui base, imm` 的链式构造：
            # 见下面的专用分支
            if ins.op_class is OpClass.ARITH_ADD and ins.immediate is not None:
                # 需要再往前拿 base 的值，递归回溯一次
                return None
            if ins.op_class is OpClass.LOAD:
                return None
        return None

    def _lui_base(reg_name: str, addr: int) -> Optional[int]:
        """
        识别 `lui r, hi` 模式：返回 hi << 12。

        这是跳转表/全局指针最常见的构造方式，单独识别能显著提高
        间接跳转的解析率。只回溯 4 条指令，避免误匹配。
        """
        k = idx_of.get(addr)
        if k is None:
            return None
        for j in range(k - 1, max(-1, k - 5), -1):
            ins = insns[j]
            writes = any(d.kind is ExprKind.REG and d.name == reg_name
                         for d in ins.operands)
            if not writes:
                continue
            if ins.mnemonic == "lui" and ins.immediate is not None:
                return (ins.immediate & 0xFFFFF) << 12
            return None
        return None

    n_indirect = 0
    for i, ins in enumerate(insns):
        # 只关心真正的**间接跳转**：JUMP/CALL 且无立即数。
        # RETURN（ret / jalr x0,ra,0）不算 —— 它的目标是调用约定固定的，
        # 计入会虚高"不可解析控制流"的比例，让报告失真。
        if ins.op_class not in (OpClass.JUMP, OpClass.CALL):
            continue
        if ins.immediate is not None:
            continue
        n_indirect += 1

        targets: set[int] = set()
        # 间接跳转的目标寄存器：`jr t0` / `jalr ra, t0, 0` 里的 t0 在 sources 中。
        # 递归取，防止将来被包进嵌套表达式。
        jmp_regs = _regs_in(ins.sources)
        jmp_reg = jmp_regs[0] if jmp_regs else None

        # ---- 策略 1：跳转表 ----
        # 模式：`lw t0, off(base)` 紧邻 `jalr .., t0, ..`
        #
        # 除了"前一条就是 load"的紧邻情形，还要容忍中间夹着无关指令
        # （真实编译产物里常见）。这里往回看最多 3 条，找**最近一条
        # 写入 jmp_reg 的指令**，若是 LOAD 则尝试解析表基址。
        if jmp_reg is not None:
            k = idx_of[ins.addr]
            load_ins = None
            for j in range(k - 1, max(-1, k - 4), -1):
                cand = insns[j]
                if any(d.kind is ExprKind.REG and d.name == jmp_reg
                       for d in cand.operands):
                    load_ins = cand
                    break
            if load_ins is not None and load_ins.op_class is OpClass.LOAD:
                # ★ 关键：LOAD 的地址是嵌套表达式 `add(a1, const(24))`，
                # 必须递归取寄存器与常量，否则基址和偏移都拿不到。
                base_regs = _regs_in(load_ins.sources)
                base = base_regs[0] if base_regs else None
                off = load_ins.immediate
                if off is None:
                    offs = _consts_in(load_ins.sources)
                    off = offs[-1] if offs else 0
                if base is not None:
                    # 优先按 `lui base, hi` 模式解析（最常见）
                    bval = _lui_base(base, load_ins.addr)
                    if bval is None:
                        bval = _const_of(base, load_ins.addr)
                    if bval is not None:
                        tbl = bval + (off or 0)
                        # 表项为 4 字节，取一块保守区间
                        for e in range(_MAX_TABLE_ENTRIES):
                            a = tbl + e * 4
                            if a in addr_set:
                                targets.add(a)

        # ---- 策略 2：已知函数入口 ----
        if not targets:
            for ins2 in insns:
                if ins2.op_class is OpClass.CALL and ins2.immediate is not None:
                    t = ins2.addr + ins2.immediate
                    if t in addr_set:
                        targets.add(t)

        if targets:
            table_targets[ins.addr] = targets
            fallback |= targets
        else:
            # ---- 策略 3：孤岛入口兜底 ----
            #
            # 目的：保证**不漏报**。把"任何静态跳转/分支的目标地址"
            # 都当作可能的间接目标。这会引入过近似（可能假阳性），
            # 但对安全工具来说，把不可达误判为可达（假阳性）
            # 远好于把可达误判为不可达（假阴性）。
            for ins2 in insns:
                if _is_terminator(ins2):
                    t = _branch_target(ins2, {})
                    if t is not None and t in addr_set:
                        fallback.add(t)
            # 再补一层：镜像里位于任何"终止指令之后"的地址也是
            # 潜在的函数入口（编译器会把函数挨着排）。
            # 这是最粗的兜底，但能覆盖"函数指针完全动态"的情形。
            for ins2 in insns:
                if _is_terminator(ins2):
                    nxt = next_addr.get(ins2.addr)
                    if nxt is not None and nxt in addr_set:
                        fallback.add(nxt)

    return table_targets, fallback, n_indirect


# 跳转表最多枚举多少项。设上限是因为过大的枚举会让 CFG 爆掉，
# 而且真实跳转表极少超过几百项。超出时交由兜底策略处理。
_MAX_TABLE_ENTRIES = 256


# ---------------------------------------------------------------------------
def _is_terminator(insn: Instruction) -> bool:
    """该指令是否结束一个基本块。"""
    return insn.op_class in (
        OpClass.BRANCH, OpClass.JUMP, OpClass.CALL,
        OpClass.RETURN, OpClass.TRAP,
    )


def _branch_target(insn: Instruction, addr_map: dict[int, int]) -> Optional[int]:
    """
    计算分支/跳转的目标地址。

    `addr_map` 是 addr → index 的映射，用于解析相对偏移。
    """
    if insn.op_class not in (OpClass.BRANCH, OpClass.JUMP, OpClass.CALL):
        return None
    # 立即数在提升阶段记录了跳转偏移
    if insn.immediate is None:
        return None
    return insn.addr + insn.immediate


def build_program(name: str, lifted: LiftResult, arch: str,
                  base_addr: int = 0, entry_addr: int = 0,
                  symbols: Optional[dict[str, int]] = None,
                  input_entries: Optional[dict[str, int]] = None) -> Program:
    """
    从提升结果构建 Program（含 CFG）。

    步骤：
    1. 识别基本块边界
    2. 建立块内指令序列
    3. 连接控制流边
    4. 识别函数（符号表优先，启发式兜底）
    5. 计算可达性
    """
    insns = sorted(lifted.instructions, key=lambda i: i.addr)
    if not insns:
        return Program(name=name, arch=arch, base_addr=base_addr, entry_addr=entry_addr)

    addr_set = {i.addr for i in insns}
    next_addr = {}
    for idx, i in enumerate(insns):
        next_addr[i.addr] = insns[idx + 1].addr if idx + 1 < len(insns) else i.addr + i.size

    # ---- 1. 识别基本块起始地址 ----
    leaders: set[int] = {insns[0].addr}
    if entry_addr and entry_addr in addr_set:
        leaders.add(entry_addr)
    for i in insns:
        tgt = _branch_target(i, {})
        if tgt is not None and tgt in addr_set:
            leaders.add(tgt)
        if _is_terminator(i):
            nxt = next_addr.get(i.addr)
            if nxt in addr_set:
                leaders.add(nxt)
    # 符号表的函数入口也是 leader
    if symbols:
        for a in symbols.values():
            if a in addr_set:
                leaders.add(a)

    sorted_leaders = sorted(leaders)

    # ---- 1b. 间接跳转解析（必须在切块前做，因为会影响 leaders）----
    #
    # 为什么放在这里：间接跳转的目标必须先成为 leader，
    # 否则目标地址可能落在某个块的中间，切块时不会被单独识别，
    # 后续连边就会连到"包含它的那个块"而不是精确目标。
    indirect_map, indirect_fallback, n_indirect = _collect_indirect_targets(
        insns, addr_set, next_addr)
    n_indirect_resolved = len(indirect_map)
    for tset in indirect_map.values():
        for t in tset:
            if t in addr_set:
                leaders.add(t)
    # 兜底目标也提升为 leader —— 这是过近似的一部分
    for t in indirect_fallback:
        if t in addr_set:
            leaders.add(t)
    sorted_leaders = sorted(leaders)

    # ---- 2. 切分基本块 ----
    blocks: dict[str, BasicBlock] = {}
    addr_to_block: dict[int, str] = {}
    cur: list[Instruction] = []
    cur_start = insns[0].addr

    def flush(end_addr: int) -> None:
        nonlocal cur, cur_start
        if not cur:
            return
        bid = f"bb_{cur_start:08x}"
        bb = BasicBlock(block_id=bid, start_addr=cur_start, end_addr=end_addr,
                        instructions=list(cur))
        bb.recompute_summary()
        blocks[bid] = bb
        for insn in cur:
            addr_to_block[insn.addr] = bid
        cur = []

    for i in insns:
        if i.addr in leaders and cur:
            flush(i.addr)
            cur_start = i.addr
        elif not cur:
            cur_start = i.addr
        cur.append(i)
        if _is_terminator(i):
            flush(i.addr + i.size)
    flush(insns[-1].addr + insns[-1].size)

        # ---- 3. 连接控制流 ----
    for bb in list(blocks.values()):
        last = bb.instructions[-1]
        succ: list[str] = []
        nxt = next_addr.get(last.addr)
        nxt_bid = addr_to_block.get(nxt) if nxt is not None else None

        if last.op_class is OpClass.BRANCH:
            tgt = _branch_target(last, {})
            tb = addr_to_block.get(tgt) if tgt is not None else None
            if tb:
                succ.append(tb)
            if nxt_bid and nxt_bid != tb:
                succ.append(nxt_bid)
        elif last.op_class in (OpClass.JUMP, OpClass.CALL):
            tgt = _branch_target(last, {})
            tb = addr_to_block.get(tgt) if tgt is not None else None
            if tb:
                succ.append(tb)
                if last.op_class is OpClass.CALL:
                    # 调用：目标入栈，且返回后继续
                    if nxt_bid:
                        succ.append(nxt_bid)
            else:
                # ★ 间接跳转 / 目标在镜像外。
                #
                # 旧行为：只连 fall-through（+4），把间接目标丢掉
                #         → 目标块变成"不可达" → **假阴性**。
                # 新行为：连上所有解析出的可能目标（保守过近似）。
                # 宁可多连边（可能产生假阳性），不可漏边（假阴性更危险）。
                resolved = indirect_map.get(last.addr) or set()
                for t in sorted(resolved):
                    tb2 = addr_to_block.get(t)
                    if tb2 and tb2 != bb.block_id:
                        succ.append(tb2)
                if not resolved:
                    # 策略 3 兜底：连上"孤岛入口"
                    for t in sorted(indirect_fallback):
                        tb2 = addr_to_block.get(t)
                        if tb2 and tb2 != bb.block_id:
                            succ.append(tb2)
                if last.op_class is OpClass.CALL and nxt_bid:
                    succ.append(nxt_bid)
        elif last.op_class in (OpClass.RETURN, OpClass.TRAP):
            pass  # 无后继
        else:
            if nxt_bid:
                succ.append(nxt_bid)

        # 去重保序
        seen = set()
        bb.successors = [s for s in succ if not (s in seen or seen.add(s))]
        for s in bb.successors:
            blocks[s].predecessors.append(bb.block_id)

    # ---- 4. 可达性 ----
    entry_bid = addr_to_block.get(entry_addr) or next(iter(blocks.values())).block_id
    blocks[entry_bid].is_entry = True
    reachable = _reachable_from(blocks, entry_bid)
    for bid, bb in blocks.items():
        bb.reachable = bid in reachable

    # ---- 5. 纠正路径标记（仅基于符号名，缺失时不猜）----
    corrective = 0
    if symbols:
        for sym, a in symbols.items():
            low = sym.lower()
            if any(k in low for k in _CORRECTIVE_KEYWORDS):
                bb = blocks.get(addr_to_block.get(a, ""))
                if bb:
                    bb.is_corrective = True
                    corrective += 1

    # ---- 6. 函数识别 ----
    funcs: dict[str, Function] = {}
    if symbols:
        # 有符号表：按符号划分
        sym_by_addr = sorted(((a, n) for n, a in symbols.items() if a in addr_set))
        for idx, (a, nm) in enumerate(sym_by_addr):
            start_bid = addr_to_block.get(a)
            if not start_bid:
                continue
            fid = f"fn_{a:08x}"
            f = Function(func_id=fid, name=nm, entry_addr=a,
                         symbol_source="symbol_table")
            funcs[fid] = f
        # 用函数入口块的可达块归属函数（简单归属：从入口到下一个入口之前的块）
        entries = sorted(a for a, _ in sym_by_addr)
        for bb in blocks.values():
            if not bb.reachable:
                continue
            owner = None
            for a in entries:
                if a <= bb.start_addr:
                    owner = a
                else:
                    break
            if owner is not None:
                fid = f"fn_{owner:08x}"
                if fid in funcs:
                    funcs[fid].blocks.append(bb.block_id)
    else:
        # 无符号表：用启发式 —— call/jump 目标作为函数入口
        cand: set[int] = set()
        for i in insns:
            if i.op_class in (OpClass.CALL,):
                t = _branch_target(i, {})
                if t in addr_set:
                    cand.add(t)
        if entry_addr in addr_set:
            cand.add(entry_addr)
        for a in sorted(cand):
            fid = f"fn_{a:08x}"
            funcs[fid] = Function(func_id=fid, name=f"sub_{a:08x}",
                                  entry_addr=a, symbol_source="heuristic")

    # ---- 7. 外部输入入口 ----
    inputs: dict[str, int] = dict(input_entries or {})

    prog = Program(
        name=name, arch=arch, base_addr=base_addr, entry_addr=entry_addr,
        blocks=blocks, functions=funcs, addr_to_block=addr_to_block,
        inputs=inputs,
    )

    g = _to_networkx(blocks)
    # 间接跳转里有多少真正解析出了目标（而非走兜底）
    n_indirect_unresolved = max(0, n_indirect - n_indirect_resolved)
    prog.stats = {
        "blocks": len(blocks),
        "edges": g.number_of_edges(),
        "functions": len(funcs),
        "unreachable_blocks": sum(1 for b in blocks.values() if not b.reachable),
        "corrective_blocks": corrective,
        "entry_points": len(inputs),
        "lift_total": lifted.total_count,
        "lift_unknown": lifted.unknown_count,
        "lift_unknown_ratio": round(lifted.unknown_ratio(), 4),
        "has_symbols": bool(symbols),
        "functions_source": "symbol_table" if symbols else "heuristic",
        # ★ 控制流可信度指标：间接跳转越多，可达性结论越弱。
        # 报告必须暴露这个数字，否则会把"解析不出来"伪装成"不可达"。
        "indirect_jumps": n_indirect,
        "indirect_resolved": n_indirect_resolved,
        "indirect_unresolved": n_indirect_unresolved,
        "cfg_confidence": (
            "high" if n_indirect == 0 else
            ("medium" if n_indirect_resolved >= n_indirect * 0.5 else "low")
        ),
    }
    return prog


def _reachable_from(blocks: dict[str, BasicBlock], start: str) -> set[str]:
    seen: set[str] = set()
    stack = [start]
    while stack:
        cur = stack.pop()
        if cur in seen:
            continue
        seen.add(cur)
        for s in blocks[cur].successors:
            if s not in seen:
                stack.append(s)
    return seen


def _to_networkx(blocks: dict[str, BasicBlock]) -> nx.DiGraph:
    g = nx.DiGraph()
    for bid, bb in blocks.items():
        g.add_node(bid, start=bb.start_addr, end=bb.end_addr,
                   n_insn=len(bb.instructions))
        for s in bb.successors:
            g.add_edge(bid, s)
    return g
