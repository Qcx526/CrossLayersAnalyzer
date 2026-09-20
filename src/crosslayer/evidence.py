"""
跨层漏洞分析 —— CLEG 证据图存储

按 `schemas/cleg-node.schema.json` 与 `cleg-edge.schema.json` 实现。

设计要点
--------
1. **推理边与观测边严格分离**：`edge_nature` 是必填字段，
   报告中不允许把推理边渲染成与观测边相同的外观。
2. **每条边带可求解条件**：`condition.smt` + `unsatisfied_predicates`。
   这是"约束进展度"反馈的载体。
3. **反事实验证标记**：`counterfactual_tested` / `counterfactual_result`。
   这是"攻击链"区别于"漏洞关联列表"的判据。
4. **UNKNOWN 一等公民**：`satisfiability` 有 `unknown` 取值，
   且 `Experiment.returned_unknown` 显式记录"无可观测数据"的情形。

存储：SQLite。图数据库解决的是关系遍历，而本项目的难点是
边的条件约束求解与因果性 —— 这两点图数据库都不提供。
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

from .contracts import TriggerContract
from .reachability import ReachabilityResult, Verdict


# ---------------------------------------------------------------------------
SCHEMA_SQL = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS nodes (
    node_id      TEXT PRIMARY KEY,
    node_type    TEXT NOT NULL,
    label        TEXT,
    platform_key TEXT,
    evidence_level TEXT,
    route        TEXT,           -- A / B / C（可逗号分隔多标签）
    props        TEXT NOT NULL,  -- JSON
    created_at   REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS edges (
    edge_id      TEXT PRIMARY KEY,
    edge_type    TEXT NOT NULL,
    from_node    TEXT NOT NULL,
    to_node      TEXT NOT NULL,
    edge_nature  TEXT NOT NULL,  -- inference | observation
    evidence_level TEXT,
    satisfiability TEXT,
    counterfactual_tested INTEGER DEFAULT 0,
    counterfactual_result TEXT,
    props        TEXT NOT NULL,  -- JSON
    created_at   REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS experiments (
    run_id       TEXT PRIMARY KEY,
    firmware_sha256 TEXT,
    target_identity TEXT,
    counterfactual_kind TEXT,
    edge_eliminated TEXT,
    props        TEXT NOT NULL,
    created_at   REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS artifacts (
    content_hash TEXT PRIMARY KEY,
    evidence_kind TEXT,
    rel_path     TEXT,
    size         INTEGER,
    created_at   REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_edges_from ON edges(from_node);
CREATE INDEX IF NOT EXISTS idx_edges_to   ON edges(to_node);
CREATE INDEX IF NOT EXISTS idx_edges_nature ON edges(edge_nature);
CREATE INDEX IF NOT EXISTS idx_nodes_type ON nodes(node_type);
"""


def _hash_obj(obj: Any) -> str:
    blob = json.dumps(obj, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()[:16]


@dataclass
class Node:
    node_id: str
    node_type: str
    label: str = ""
    platform_key: str = ""
    evidence_level: str = "E0"
    route: list[str] = field(default_factory=list)
    props: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id, "node_type": self.node_type,
            "label": self.label, "platform_key": self.platform_key,
            "evidence_level": self.evidence_level, "route": self.route,
            **self.props,
        }


@dataclass
class Edge:
    edge_id: str
    edge_type: str
    from_node: str
    to_node: str
    edge_nature: str = "inference"     # inference | observation
    evidence_level: str = "E1"
    satisfiability: str = "not_checked"
    counterfactual_tested: bool = False
    counterfactual_result: str = "not_tested"
    props: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "edge_id": self.edge_id, "edge_type": self.edge_type,
            "from_node": self.from_node, "to_node": self.to_node,
            "edge_nature": self.edge_nature,
            "evidence_level": self.evidence_level,
            "satisfiability": self.satisfiability,
            "counterfactual_tested": self.counterfactual_tested,
            "counterfactual_result": self.counterfactual_result,
            **self.props,
        }


# ---------------------------------------------------------------------------
class EvidenceGraph:
    """CLEG 证据图的持久化与查询。"""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA_SQL)

    # ------------------------------------------------------------------
    def add_node(self, node: Node) -> str:
        self.conn.execute(
            "INSERT OR REPLACE INTO nodes "
            "(node_id,node_type,label,platform_key,evidence_level,route,props,created_at)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (node.node_id, node.node_type, node.label, node.platform_key,
             node.evidence_level, ",".join(node.route),
             json.dumps(node.props, ensure_ascii=False), time.time()),
        )
        self.conn.commit()
        return node.node_id

    def add_edge(self, edge: Edge) -> str:
        self.conn.execute(
            "INSERT OR REPLACE INTO edges "
            "(edge_id,edge_type,from_node,to_node,edge_nature,evidence_level,"
            " satisfiability,counterfactual_tested,counterfactual_result,props,created_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (edge.edge_id, edge.edge_type, edge.from_node, edge.to_node,
             edge.edge_nature, edge.evidence_level, edge.satisfiability,
             1 if edge.counterfactual_tested else 0,
             edge.counterfactual_result,
             json.dumps(edge.props, ensure_ascii=False), time.time()),
        )
        self.conn.commit()
        return edge.edge_id

    def add_artifact(self, content: bytes, evidence_kind: str,
                     base_dir: str | Path) -> str:
        """
        内容寻址存储：原始材料不丢弃。

        返回 content_hash。
        """
        h = hashlib.sha256(content).hexdigest()
        base = Path(base_dir)
        base.mkdir(parents=True, exist_ok=True)
        rel = h[:2] + "/" + h
        p = base / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if not p.exists():
            p.write_bytes(content)
        self.conn.execute(
            "INSERT OR REPLACE INTO artifacts "
            "(content_hash,evidence_kind,rel_path,size,created_at) VALUES (?,?,?,?,?)",
            (h, evidence_kind, rel, len(content), time.time()),
        )
        self.conn.commit()
        return h

    # ------------------------------------------------------------------
    def nodes_of_type(self, node_type: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM nodes WHERE node_type=?", (node_type,)
        ).fetchall()
        return [self._node_row(r) for r in rows]

    def edges_of_nature(self, nature: str) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT * FROM edges WHERE edge_nature=?", (nature,)
        ).fetchall()
        return [self._edge_row(r) for r in rows]

    def chain_edges(self, node_ids: Iterable[str]) -> list[dict[str, Any]]:
        """取某组节点之间的边（构成一条链）。"""
        ids = list(node_ids)
        if not ids:
            return []
        ph = ",".join("?" * len(ids))
        rows = self.conn.execute(
            f"SELECT * FROM edges WHERE from_node IN ({ph}) AND to_node IN ({ph})",
            ids + ids,
        ).fetchall()
        return [self._edge_row(r) for r in rows]

    # ------------------------------------------------------------------
    @staticmethod
    def _node_row(r: sqlite3.Row) -> dict[str, Any]:
        d = dict(r)
        d["props"] = json.loads(d["props"])
        d["route"] = [x for x in (d.get("route") or "").split(",") if x]
        return d

    @staticmethod
    def _edge_row(r: sqlite3.Row) -> dict[str, Any]:
        d = dict(r)
        d["props"] = json.loads(d["props"])
        d["counterfactual_tested"] = bool(d["counterfactual_tested"])
        return d

    # ------------------------------------------------------------------
    def statistics(self) -> dict[str, Any]:
        n_nodes = self.conn.execute("SELECT COUNT(*) c FROM nodes").fetchone()["c"]
        n_edges = self.conn.execute("SELECT COUNT(*) c FROM edges").fetchone()["c"]
        n_inf = self.conn.execute(
            "SELECT COUNT(*) c FROM edges WHERE edge_nature='inference'"
        ).fetchone()["c"]
        n_obs = self.conn.execute(
            "SELECT COUNT(*) c FROM edges WHERE edge_nature='observation'"
        ).fetchone()["c"]
        n_cf = self.conn.execute(
            "SELECT COUNT(*) c FROM edges WHERE counterfactual_tested=1"
        ).fetchone()["c"]
        n_unknown = self.conn.execute(
            "SELECT COUNT(*) c FROM edges WHERE satisfiability='unknown'"
        ).fetchone()["c"]
        by_type = {
            r["node_type"]: r["c"] for r in self.conn.execute(
                "SELECT node_type, COUNT(*) c FROM nodes GROUP BY node_type")
        }
        return {
            "nodes": n_nodes, "edges": n_edges,
            "inference_edges": n_inf, "observation_edges": n_obs,
            "counterfactual_tested_edges": n_cf,
            "unknown_satisfiability_edges": n_unknown,
            "nodes_by_type": by_type,
        }

    def close(self) -> None:
        self.conn.close()


# ---------------------------------------------------------------------------
def build_graph_from_analysis(
    graph: EvidenceGraph,
    contract: TriggerContract,
    image_identity: dict[str, Any],
    program,                              # ir.Program
    results: list[ReachabilityResult],
    target_id: str,
    route: str = "B",
) -> dict[str, Any]:
    """
    把一次分析的结果写入证据图。

    生成的证据结构（以思路 B 为例）：

        FirmwareImage --located_in--> CodeLocation --triggers--> TriggerContract
              ^                                              |
              |                                              v
              +----------- produces -------------------- SecurityProperty

    所有边默认是 `inference`（来自静态分析 / SMT 求解），证据级别 E1。
    只有在真实硬件/RTL 上观测到的边才标为 `observation` 且 >= E2。
    """
    created_nodes: list[str] = []
    created_edges: list[str] = []

    # --- 固件镜像节点 ---
    fw_id = f"fw_{image_identity.get('sha256','')[:16]}"
    graph.add_node(Node(
        node_id=fw_id, node_type="FirmwareImage",
        label=image_identity.get("path", ""),
        platform_key=contract.platform.key(),
        evidence_level="E4",
        route=[route],
        props={
            "sha256": image_identity.get("sha256"),
            "format": image_identity.get("format"),
            "arch": image_identity.get("arch"),
            "entry_point": image_identity.get("entry_point"),
            "base_address": image_identity.get("base_address"),
            "executable_segments": image_identity.get("executable_segments", []),
            "has_symbols": image_identity.get("has_symbols"),
            "has_debug_info": image_identity.get("has_debug_info"),
            "identity_notes": image_identity.get("identity_notes"),
        },
    ))
    created_nodes.append(fw_id)

    # --- 契约节点 ---
    ct_id = f"contract_{contract.contract_id}"
    graph.add_node(Node(
        node_id=ct_id, node_type="TriggerContract", label=contract.name,
        platform_key=contract.platform.key(),
        evidence_level=contract.evidence_level, route=[route],
        props=contract.to_dict(),
    ))
    created_nodes.append(ct_id)

    # --- 前置条件节点（Capability / Requires）---
    #
    # 为什么把前置条件单独成节点：一条"攻击链"不是
    # 「代码位置 → 契约」的星形放射图，而是有中间环节的路径。
    # 前置条件（权限、寄存器状态、内存属性、保护状态）是链条上的中间环。
    # 把它们显式建模，才谈得上"链"，后续才能对单条边做反事实消除实验。
    pre_specs: list[tuple[str, Any]] = [
        ("privilege", contract.pre.privilege),
        ("required_register_states", contract.pre.required_register_states),
        ("memory_attributes", contract.pre.memory_attributes),
        ("protection_state", contract.pre.protection_state),
        ("microarch_state", contract.pre.microarch_state),
    ]
    for i, (field_name, value) in enumerate(pre_specs):
        if not value:
            continue
        pre_id = f"pre_{contract.contract_id}_{field_name}"
        graph.add_node(Node(
            node_id=pre_id, node_type="Capability",
            label=f"{field_name}: {value}",
            platform_key=contract.platform.key(),
            evidence_level=contract.evidence_level, route=[route],
            props={
                "capability_id": f"{contract.contract_id}.pre.{field_name}",
                "kind": field_name,
                "value": value,
                "source_vulnerability": contract.contract_id,
                "evidence_ref": contract.source_ref or "",
            },
        ))
        created_nodes.append(pre_id)

        e_req = Edge(
            edge_id=f"e_req_{contract.contract_id}_{field_name}",
            edge_type="requires", from_node=ct_id, to_node=pre_id,
            edge_nature="inference", evidence_level="E1",
            satisfiability="not_checked",
            props={
                "condition": {
                    "natural_language": (
                        f"触发该契约需先满足前置条件 [{field_name}]={value}"
                    ),
                    "satisfiability": "not_checked",
                    "unsatisfied_predicates": [
                        f"前置条件 {field_name} 尚未在本固件上验证"
                    ],
                },
                "provenance": {
                    "source_kind": "manual_annotation",
                    "source_ref": contract.source_ref or "",
                    "human_reviewed": False,
                },
                "invalidation_conditions": [
                    "前置条件由人工/上位报告录入，未经本项目因果实验验证"
                ],
            },
        )
        graph.add_edge(e_req)
        created_edges.append(e_req.edge_id)

    # --- 偏差节点（Deviation）---
    #
    # Deviation 是思路③（硬件漏洞影响固件正常执行）的输入。
    # 注意 `constrained_by_hw`：若为 False，说明这只是"任意注入的偏差"，
    # 不足以证明真实漏洞 —— 这个字段必须在图里保留，否则后续统计
    # 会把"注入实验"当成"真实漏洞证据"，这是常见且严重的论证错误。
    dev_id: str | None = None
    d = contract.deviation
    if d is not None and (d.deviation_kind or d.first_divergence_point):
        dev_id = f"dev_{contract.contract_id}"
        graph.add_node(Node(
            node_id=dev_id, node_type="Deviation",
            label=d.deviation_kind or "deviation",
            platform_key=contract.platform.key(),
            evidence_level=contract.evidence_level, route=[route],
            props={
                "deviation_kind": d.deviation_kind,
                "specification_ref": d.specification_ref,
                "safety_property_ref": d.safety_property_ref,
                "expected_value": d.expected_value,
                "actual_value": d.actual_value,
                "first_divergence_point": d.first_divergence_point,
                "constrained_by_hw": d.constrained_by_hw,
                "warning": (
                    None if d.constrained_by_hw else
                    "该偏差未声明由硬件契约约束：可能是任意注入，"
                    "不足以作为真实漏洞证据"
                ),
            },
        ))
        created_nodes.append(dev_id)

        # 契约 --produces--> 偏差（推理边）
        e_pr = Edge(
            edge_id=f"e_prod_{contract.contract_id}",
            edge_type="produces", from_node=ct_id, to_node=dev_id,
            edge_nature="inference", evidence_level="E1",
            satisfiability="not_checked",
            props={
                "condition": {
                    "natural_language": f"满足契约后产生偏差：{d.deviation_kind}",
                    "satisfiability": "not_checked",
                    "unsatisfied_predicates": [
                        "偏差是否真的由该契约产生，尚未做反事实验证"
                    ],
                },
                "provenance": {
                    "source_kind": "upstream_report",
                    "source_ref": contract.source_ref or "",
                },
                "invalidation_conditions": [
                    "发现该偏差由其它机制（如固件纠正路径）产生",
                ],
            },
        )
        graph.add_edge(e_pr)
        created_edges.append(e_pr.edge_id)

    # --- 分析摘要节点 ---
    summ_id = f"analysis_{_hash_obj([r.block_id for r in results])}"
    graph.add_node(Node(
        node_id=summ_id, node_type="Evidence",
        label="static analysis summary", evidence_level="E1", route=[route],
        props={
            "evidence_kind": "cfg",
            "program_stats": program.stats,
            "contract_formalization": contract.formalization_report(),
            "candidates": len(results),
            "verdicts": {
                v.value: sum(1 for r in results if r.verdict is v)
                for v in Verdict
            },
        },
    ))
    created_nodes.append(summ_id)

    # --- 每个候选：CodeLocation + 边 ---
    for r in results:
        loc_id = f"loc_{target_id}_{r.block_addr:08x}"
        graph.add_node(Node(
            node_id=loc_id, node_type="CodeLocation",
            label=f"0x{r.block_addr:08x}",
            platform_key=contract.platform.key(),
            evidence_level="E1", route=[route],
            props={
                "firmware_ref": fw_id,
                "address": f"0x{r.block_addr:08x}",
                "ir_representation": "pcode",
                "key_insn": r.key_insn,
                "verdict": r.verdict.value,
                "control_status": r.control_status.value,
                "progress": r.progress,
            },
        ))
        created_nodes.append(loc_id)

        # 镜像 → 代码位置（located_in，推理边）
        #
        # 证据级别纪律：这是**推理边**，级别必须 <= E1。
        # 容易混淆的点：镜像的 sha256 是 E4 级事实（可直接复算校验），
        # 但"该地址落在该镜像的可执行段内"是分析器算出来的**推理**，
        # 所以边本身记 E1，把 E4 级事实作为事实字段附在旁边。
        # 禁止把推理边标成 E4 —— 那等于把推断伪装成板上观测。
        e1 = Edge(
            edge_id=f"e_loc_{target_id}_{r.block_addr:08x}",
            edge_type="located_in", from_node=loc_id, to_node=fw_id,
            edge_nature="inference", evidence_level="E1",
            satisfiability="sat",
            props={
                "condition": {
                    "natural_language": "该代码位置属于此固件镜像（地址落在可执行段区间内）",
                    "satisfiability": "sat",
                    "solver": "interval_check",
                },
                "provenance": {
                    "source_kind": "static_analysis",
                    "source_ref": "loader.executable_segments",
                    "human_reviewed": False,
                },
                # 复用同一份镜像身份事实：这条事实本身的可信度是 E4
                # （任何人重算 sha256 即可复核），但它是**事实字段**，
                # 不改变本边的推理性质。
                "firmware_identity_evidence_level": "E4",
            },
        )
        graph.add_edge(e1)
        created_edges.append(e1.edge_id)

        # 代码位置 → 契约（triggers，推理边，带条件与进展度）
        unsat_preds = []
        sat_preds = []
        for pr in r.input_constraints:
            sat_preds.append(pr.var_name)
        if r.satisfiability == "unsat":
            unsat_preds = r.minimal_conflict or ["触发条件无法由该路径满足"]

        e2 = Edge(
            edge_id=f"e_trig_{target_id}_{r.block_addr:08x}",
            edge_type="triggers", from_node=loc_id, to_node=ct_id,
            edge_nature="inference", evidence_level="E1",
            satisfiability=r.satisfiability,
            counterfactual_tested=False,
            counterfactual_result="not_tested",
            props={
                "condition": {
                    "natural_language": (
                        f"该代码位置满足契约所需操作；约束进展度 "
                        f"{r.progress:.2f}；求解状态 {r.satisfiability}"
                    ),
                    "satisfiability": r.satisfiability,
                    "solver": r.solver,
                    "timeout_ms": r.timeout_ms,
                    "unsatisfied_predicates": unsat_preds,
                    "satisfied_predicate_names": sat_preds,
                },
                "verdict": r.verdict.value,
                "control_status": r.control_status.value,
                "taint_sources": r.taint_sources,
                "input_constraints": [c.to_dict() for c in r.input_constraints],
                "notes": r.notes,
                "provenance": {
                    "source_kind": "smt_solver" if r.solver else "static_analysis",
                    "source_ref": f"{r.key_insn} @ 0x{r.key_addr:08x}"
                    if r.key_addr is not None else r.key_insn,
                    "confidence": round(r.progress, 4),
                    "human_reviewed": False,
                },
                "counterfactual_tested": False,
                "counterfactual_result": "not_tested",
            },
        )
        graph.add_edge(e2)
        created_edges.append(e2.edge_id)

    return {
        "firmware_node": fw_id,
        "contract_node": ct_id,
        "summary_node": summ_id,
        "nodes_created": len(created_nodes),
        "edges_created": len(created_edges),
        "values": {
            "sha256": image_identity.get("sha256"),
            "target_id": target_id,
        },
    }
