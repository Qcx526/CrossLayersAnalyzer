"""
CLEG 证据图 —— 单元测试

为什么这个测试重要
------------------
`evidence.py` 的承诺是"推理边与观测边严格分离、每条边带可求解条件、
边可被反事实反驳"。这些承诺如果不被**机器检验**，就只是文档措辞。
本测试把每条承诺变成一个断言。

不变量清单（与模块 docstring 一一对应）：
  I1  节点类型白名单 —— 不允许出现 schema 未定义的节点类型
  I2  edge_nature 只能是 inference / observation
  I3  推理边的证据级别必须 <= E1
  I4  观测边的证据级别必须 >= E2
  I5  观测边必须携带仪器/来源（禁止凭空断言"我观测到了"）
  I6  triggers 边必须带 condition.satisfiability
  I7  triggers 边必须带 condition.unsatisfied_predicates（约束进展度载体）
  I8  edge_type=equivalent_to 必须带 semantic_equivalence_basis
  I9  counterfactual_tested=true 必须带 counterfactual_result
  I10 统计量自洽：inference + observation == edges
  I11 内容寻址存储：同样内容写入两次得到同一 hash，且只存一份
  I12 边可被反驳：refutation 记录可写可读

用法：
    python tests/test_evidence.py
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from crosslayer.evidence import Edge, EvidenceGraph, Node  # noqa: E402

# ---------------------------------------------------------------------------
# schema 白名单（与 schemas/*.json 保持一致）
# 注意：这里刻意**手工重复**一遍常量而不是 import schema 文件。
# 理由：若 schema 文件被误改，手工副本能让测试失败并暴露改动，
#       而直接读 schema 会让两边一起变，测试就失去了守护作用。
# ---------------------------------------------------------------------------
NODE_TYPES = {
    "FirmwareImage", "CodeLocation", "InstructionFragment", "InputEntry",
    "Capability", "HardwareComponent", "Register", "RegField",
    "AddressSpace", "TriggerContract", "Deviation", "SecurityProperty",
    "Experiment", "Evidence", "CorrectivePath",
}

EDGE_TYPES = {
    "controls", "reaches", "requires", "produces", "triggers",
    "violates", "observed_in", "refuted_by", "equivalent_to",
    "located_in", "accessible_via",
}

EVIDENCE_LEVELS = {"E0", "E1", "E2", "E3", "E4"}
_LEVEL_RANK = {"E0": 0, "E1": 1, "E2": 2, "E3": 3, "E4": 4}


class Checker:
    def __init__(self) -> None:
        self.passed = 0
        self.failed: list[str] = []
        self.checked = 0

    def check(self, cond: bool, label: str) -> None:
        self.checked += 1
        if cond:
            self.passed += 1
        else:
            self.failed.append(label)


def _rows(g: EvidenceGraph, sql: str) -> list[dict]:
    return [dict(r) for r in g.conn.execute(sql).fetchall()]


def _props(e: dict) -> dict:
    return json.loads(e["props"] or "{}")


# ---------------------------------------------------------------------------
def test_invariants(tmp: Path) -> Checker:
    """在一个人工构造的图上检查全部不变量。"""
    c = Checker()
    g = EvidenceGraph(tmp / "inv.db")

    fw = Node(node_id="fw_a", node_type="FirmwareImage",
              label="modem.bin", platform_key="rv32|none|none",
              evidence_level="E4",
              props={"sha256": "ab" * 32, "format": "raw",
                     "arch": "riscv32", "entry_point": "0x80000000"})
    ct = Node(node_id="contract_X", node_type="TriggerContract",
              label="div0", platform_key="rv32|none|none",
              evidence_level="E1", props={"contract_id": "X"})
    loc = Node(node_id="loc_1", node_type="CodeLocation",
               label="0x80000010", platform_key="rv32|none|none",
               evidence_level="E1", props={"address": "0x80000010"})
    ex = Node(node_id="exp_1", node_type="Experiment",
              evidence_level="E2", props={"counterfactual_kind": "cfg_removal"})
    for n in (fw, ct, loc, ex):
        g.add_node(n)

    # 推理边：级联合法
    g.add_edge(Edge(
        edge_id="e_inf_ok", edge_type="triggers", from_node="loc_1",
        to_node="contract_X", edge_nature="inference", evidence_level="E1",
        satisfiability="sat",
        props={"condition": {
            "natural_language": "测试",
            "satisfiability": "sat",
            "unsatisfied_predicates": [],
        }, "provenance": {"source_kind": "smt_solver"}},
    ))

    # 观测边：合法（E2/仪器齐备）
    g.add_edge(Edge(
        edge_id="e_obs_ok", edge_type="observed_in", from_node="loc_1",
        to_node="exp_1", edge_nature="observation", evidence_level="E2",
        satisfiability="sat",
        props={"observed_by": "OpenOCD 0.12 trace",
               "provenance": {"source_kind": "dynamic_observation"},
               "condition": {
                   "natural_language": "观测到除法器除零后 rdata 偏差",
                   "satisfiability": "sat",
                   "unsatisfied_predicates": [],
               }},
    ))

    # ---- I1 节点类型白名单 ----
    for r in _rows(g, "SELECT node_id,node_type FROM nodes"):
        c.check(r["node_type"] in NODE_TYPES,
                f"I1 非法节点类型 {r['node_type']!r} @ {r['node_id']}")

    # ---- I2/I3/I4/I5/I6/I7/I8/I9 逐边 ----
    for e in _rows(g, "SELECT * FROM edges"):
        nat = e["edge_nature"]
        lvl = e["evidence_level"]
        rank = _LEVEL_RANK.get(lvl, -1)

        c.check(nat in ("inference", "observation"),
                f"I2 {e['edge_id']} 非法 edge_nature={nat!r}")
        c.check(lvl in EVIDENCE_LEVELS,
                f"I2b {e['edge_id']} 非法 evidence_level={lvl!r}")
        c.check(e["edge_type"] in EDGE_TYPES,
                f"I2c {e['edge_id']} 非法 edge_type={e['edge_type']!r}")

        if nat == "inference":
            c.check(rank <= 1,
                    f"I3 {e['edge_id']} 推理边级别 {lvl} 超过 E1")
        if nat == "observation":
            c.check(rank >= 2,
                    f"I4 {e['edge_id']} 观测边级别 {lvl} 低于 E2")
            p = _props(e)
            c.check(bool(p.get("observed_by") or p.get("instrument")),
                    f"I5 {e['edge_id']} 观测边缺 observed_by/instrument")

        if e["edge_type"] == "triggers":
            cond = _props(e).get("condition") or {}
            c.check("satisfiability" in cond,
                    f"I6 {e['edge_id']} triggers 边缺 condition.satisfiability")
            c.check("unsatisfied_predicates" in cond,
                    f"I7 {e['edge_id']} triggers 边缺 unsatisfied_predicates")

        if e["edge_type"] == "equivalent_to":
            p = _props(e)
            c.check(bool(p.get("semantic_equivalence_basis")),
                    f"I8 {e['edge_id']} equivalent_to 缺语义等价依据")

        if e["counterfactual_tested"]:
            c.check(e["counterfactual_result"] not in (None, ""),
                    f"I9 {e['edge_id']} 已做反事实但缺 counterfactual_result")

    # ---- I10 统计量自洽 ----
    st = g.statistics()
    c.check(st["inference_edges"] + st["observation_edges"] == st["edges"],
            "I10 推理边 + 观测边 != 总边数")
    c.check(st["nodes"] == 4, f"I10b 节点数应为 4，实为 {st['nodes']}")
    c.check(st["edges"] == 2, f"I10c 边数应为 2，实为 {st['edges']}")

    g.close()
    return c


def test_negative_cases_are_detected(tmp: Path) -> Checker:
    """
    反向测试：把**故意写错**的边塞进图，验证检查逻辑真的能抓到。

    这是测试套件的元测试：如果检查器永远返回"通过"，
    那它守护不了任何东西。
    """
    c = Checker()
    g = EvidenceGraph(tmp / "neg.db")

    # 错误 1：推理边标 E4
    g.add_node(Node(node_id="n1", node_type="CodeLocation"))
    g.add_edge(Edge(edge_id="bad_inf_high", edge_type="located_in",
                    from_node="n1", to_node="n1",
                    edge_nature="inference", evidence_level="E4"))

    # 错误 2：观测边标 E0
    g.add_edge(Edge(edge_id="bad_obs_low", edge_type="observed_in",
                    from_node="n1", to_node="n1",
                    edge_nature="observation", evidence_level="E0"))

    # 错误 3：观测边无来源
    g.add_edge(Edge(edge_id="bad_obs_nosrc", edge_type="observed_in",
                    from_node="n1", to_node="n1",
                    edge_nature="observation", evidence_level="E3"))

    # 错误 4：triggers 边无 condition
    g.add_edge(Edge(edge_id="bad_trig", edge_type="triggers",
                    from_node="n1", to_node="n1",
                    edge_nature="inference", evidence_level="E1"))

    # 错误 5：非法 edge_nature
    g.add_edge(Edge(edge_id="bad_nature", edge_type="reaches",
                    from_node="n1", to_node="n1",
                    edge_nature="guess", evidence_level="E1"))

    problems: list[str] = []
    for e in _rows(g, "SELECT * FROM edges"):
        nat, lvl = e["edge_nature"], e["evidence_level"]
        rank = _LEVEL_RANK.get(lvl, -1)
        if nat not in ("inference", "observation"):
            problems.append(f"{e['edge_id']}:I2")
        if nat == "inference" and rank >= 2:
            problems.append(f"{e['edge_id']}:I3")
        if nat == "observation" and rank < 2:
            problems.append(f"{e['edge_id']}:I4")
        if nat == "observation":
            p = _props(e)
            if not (p.get("observed_by") or p.get("instrument")):
                problems.append(f"{e['edge_id']}:I5")
        if e["edge_type"] == "triggers":
            cond = _props(e).get("condition") or {}
            if "satisfiability" not in cond:
                problems.append(f"{e['edge_id']}:I6")
            if "unsatisfied_predicates" not in cond:
                problems.append(f"{e['edge_id']}:I7")

    for expect in ("bad_inf_high:I3", "bad_obs_low:I4", "bad_obs_nosrc:I5",
                   "bad_trig:I6", "bad_nature:I2"):
        c.check(expect in problems, f"负例未被检出: {expect}")

    g.close()
    return c


def test_content_addressed_store(tmp: Path) -> Checker:
    """I11：内容寻址存储 —— 同内容同 hash，且只落一份文件。"""
    c = Checker()
    store = tmp / "cas"
    g = EvidenceGraph(tmp / "cas.db")

    payload = "触发契约 HW-DIV-0001 的原始报告".encode("utf-8")
    h1 = g.add_artifact(payload, "upstream_report", store)
    h2 = g.add_artifact(payload, "upstream_report", store)
    c.check(h1 == h2, "I11 相同内容两次写入 hash 不一致")

    import hashlib
    c.check(h1 == hashlib.sha256(payload).hexdigest(),
            "I11b hash 与 sha256 不符")

    files = [p for p in store.rglob("*") if p.is_file()]
    c.check(len(files) == 1, f"I11c 内容寻址应只落 1 份文件，实为 {len(files)}")

    diff = g.add_artifact(b"another", "screen_log", store)
    c.check(diff != h1, "I11d 不同内容 hash 相同")
    files2 = [p for p in store.rglob("*") if p.is_file()]
    c.check(len(files2) == 2, f"I11e 应落 2 份文件，实为 {len(files2)}")

    g.close()
    return c


def test_refutation_roundtrip(tmp: Path) -> Checker:
    """I12：反驳记录必须与证实记录同等保留、可读回。"""
    c = Checker()
    g = EvidenceGraph(tmp / "ref.db")
    g.add_node(Node(node_id="a", node_type="CodeLocation"))
    g.add_node(Node(node_id="b", node_type="TriggerContract"))

    g.add_edge(Edge(
        edge_id="e_ref", edge_type="triggers", from_node="a", to_node="b",
        edge_nature="inference", evidence_level="E1",
        satisfiability="sat",
        props={
            "condition": {"natural_language": "原推断：可从入口到达",
                          "satisfiability": "sat",
                          "unsatisfied_predicates": []},
            "refutation": {
                "refuting_experiment": "exp_cfg_surgery",
                "mechanism": "code_unreachable",
                "notes": "删掉该分支后链断裂，说明该边不必要",
            },
        },
    ))

    rows = _rows(g, "SELECT * FROM edges WHERE edge_id='e_ref'")
    c.check(len(rows) == 1, "I12 反驳边未能读回")
    if rows:
        ref = _props(rows[0]).get("refutation") or {}
        c.check(ref.get("mechanism") == "code_unreachable",
                "I12b 反驳机制丢失")
        c.check(bool(ref.get("refuting_experiment")),
                "I12c 反驳实验引用丢失")

    g.close()
    return c


# ---------------------------------------------------------------------------
def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="cleg_test_"))
    print("=" * 78)
    print("CLEG 证据图 —— 不变量测试")
    print("=" * 78)
    print(f"临时目录: {tmp}\n")

    suites = [
        ("不变量守卫", test_invariants),
        ("负例检出（元测试）", test_negative_cases_are_detected),
        ("内容寻址存储", test_content_addressed_store),
        ("反驳记录往返", test_refutation_roundtrip),
    ]

    total_checked = total_failed = 0
    for name, fn in suites:
        c = fn(tmp)
        total_checked += c.checked
        total_failed += len(c.failed)
        flag = "PASS" if not c.failed else "FAIL"
        print(f"[{flag}] {name:<22} 检查 {c.checked} 项，失败 {len(c.failed)}")
        for f in c.failed:
            print(f"        - {f}")

    print()
    print("-" * 78)
    print(f"合计检查 {total_checked} 项，失败 {total_failed} 项")
    print(f"结论：{'全部通过' if total_failed == 0 else '存在失败'}")
    return 0 if total_failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
