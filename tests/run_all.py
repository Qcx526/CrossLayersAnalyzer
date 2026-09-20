"""
端到端测试：在所有样本上运行分析引擎，评估 Precision / Recall。

这是论文实验的核心脚本 —— 它给出**定量**的准确性评估，而不是"看起来能跑"。

用法：
    python tests/run_all.py

输出：
    out/summary.json          总体指标
    out/reports/<sample>.md   每个样本的分析报告
    out/samples/*.bin         生成的地面真值固件镜像
    out/evidence.db           CLEG 证据图数据库
"""

from __future__ import annotations

import json
import sys
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from crosslayer import (  # noqa: E402
    AnalysisConfig, EvidenceGraph, generate_report, run_analysis,
)
from fixtures import write_samples  # noqa: E402
from contract_div_zero import make_div_zero_contract  # noqa: E402

OUT = ROOT / "out"


# ---------------------------------------------------------------------------
# 判定语义分组
#
# 直接比较字符串会把"更精确但方向相同的判定"误判为失败。
# 例如 not_controllable 比 present_but_uncontrollable 更精确，
# 二者都表示"不可利用"。评分必须按**语义**而不是字面。
# ---------------------------------------------------------------------------
VERDICT_GROUPS: dict[str, str] = {
    "exploitable_candidate": "EXPLOITABLE",
    "path_dependent": "PARTIAL",
    "unknown": "UNKNOWN",
    "not_controllable": "UNEXPLOITABLE",
    "present_but_uncontrollable": "UNEXPLOITABLE",
    "present_but_unreachable": "UNREACHABLE",
    "not_present": "ABSENT",
}


class _Tee:
    """同时写到 stdout 和文件，保证输出可被离线检查。"""

    def __init__(self, *streams):
        self.streams = streams

    def write(self, s):
        for st in self.streams:
            try:
                st.write(s)
            except Exception:
                pass
        return len(s)

    def flush(self):
        for st in self.streams:
            try:
                st.flush()
            except Exception:
                pass


def _check_evidence_graph(db_path: Path) -> dict:
    """
    对证据图做结构与不变量检查。

    检查项（每一条都对应设计纪律里的一条承诺）：
      1. 三类必需节点存在：FirmwareImage / TriggerContract / Evidence
      2. 边的 edge_nature 只能是 inference / observation
      3. **推理边不得带有 >= E2 的证据级别**
         —— 这是"不把推理伪装成观测"的机器可检验形式
      4. 每条 triggers 边都带 condition.satisfiability
      5. 每条 triggers 边都带 unsatisfied_predicates 字段（可为空列表）
      6. 观测边必须携带来源（仪器/日志）—— 防止凭空断言
      7. 统计量自洽（inference + observation == edges）
    """
    lines: list[str] = []
    problems: list[str] = []
    summary: dict = {"ok": False, "db": str(db_path)}

    if not db_path.exists():
        lines.append("  !! 证据图数据库不存在，跳过自检")
        summary["error"] = "db_missing"
        return {"lines": lines, "summary": summary}

    g = EvidenceGraph(db_path)
    try:
        stats = g.statistics()
        all_nodes = [
            dict(r) for r in g.conn.execute(
                "SELECT node_id,node_type,evidence_level FROM nodes").fetchall()
        ]
        all_edges = [
            dict(r) for r in g.conn.execute(
                "SELECT edge_id,edge_type,from_node,to_node,edge_nature,"
                "evidence_level,satisfiability,props FROM edges").fetchall()
        ]

        lines.append(f"  节点 {stats['nodes']}   边 {stats['edges']}"
                     f"（推理 {stats['inference_edges']} / "
                     f"观测 {stats['observation_edges']}）")
        lines.append(f"  节点类型: {stats['nodes_by_type']}")
        lines.append(f"  已做反事实验证的边: "
                     f"{stats['counterfactual_tested_edges']}")
        lines.append(f"  satisfiability=unknown 的边: "
                     f"{stats['unknown_satisfiability_edges']}")

        # --- 检查 1：必需节点类型 ---
        types = {n["node_type"] for n in all_nodes}
        for need in ("FirmwareImage", "TriggerContract", "Evidence"):
            if need not in types:
                problems.append(f"缺少必需节点类型 {need}")

        # --- 检查 2/3：边的性质与证据级别 ---
        _LEVEL = {"E0": 0, "E1": 1, "E2": 2, "E3": 3, "E4": 4}
        for e in all_edges:
            nat = e["edge_nature"]
            if nat not in ("inference", "observation"):
                problems.append(
                    f"{e['edge_id']}: 非法 edge_nature={nat!r}")
                continue
            lvl = _LEVEL.get(e["evidence_level"] or "E0", -1)
            if lvl < 0:
                problems.append(
                    f"{e['edge_id']}: 非法 evidence_level="
                    f"{e['evidence_level']!r}")
            if nat == "inference" and lvl >= 2:
                problems.append(
                    f"{e['edge_id']}: 推理边不得标为 {e['evidence_level']}"
                    f"（>=E2 只能来自真实观测）")

        # --- 检查 4/5：triggers 边的条件字段 ---
        trig = [e for e in all_edges if e["edge_type"] == "triggers"]
        for e in trig:
            try:
                props = json.loads(e["props"])
            except Exception as exc:      # pragma: no cover
                problems.append(f"{e['edge_id']}: props 不是合法 JSON ({exc})")
                continue
            cond = props.get("condition") or {}
            if "satisfiability" not in cond:
                problems.append(
                    f"{e['edge_id']}: condition 缺少 satisfiability")
            if "unsatisfied_predicates" not in cond:
                problems.append(
                    f"{e['edge_id']}: condition 缺少 unsatisfied_predicates")

        # --- 检查 6：观测边必须有来源 ---
        for e in all_edges:
            if e["edge_nature"] != "observation":
                continue
            props = json.loads(e["props"] or "{}")
            if not (props.get("observed_by") or props.get("instrument")):
                problems.append(
                    f"{e['edge_id']}: 观测边缺少 observed_by/instrument")

        # --- 检查 6b：所有边都要有 provenance（来源可追溯） ---
        for e in all_edges:
            props = json.loads(e["props"] or "{}")
            prov = props.get("provenance") or {}
            if not prov.get("source_kind"):
                problems.append(
                    f"{e['edge_id']}: 缺少 provenance.source_kind")

        # --- 检查 8：链结构完整性 ---
        # 一条"攻击链"至少要有 requires / triggers / produces 三类边中的
        # 触发边与条件边；只有 triggers 而无 requires 的图退化成关联列表。
        req_edges = [e for e in all_edges if e["edge_type"] == "requires"]
        lines.append(f"  requires 边: {len(req_edges)}")
        n_fw_nodes = len({n["node_id"] for n in all_nodes
                          if n["node_type"] == "FirmwareImage"})
        if n_fw_nodes and not req_edges:
            problems.append(
                "存在固件与契约节点，但没有任何 requires 边 —— "
                "图退化为关联列表，不构成攻击链")

        # --- 检查 7：统计量自洽 ---
        if stats["inference_edges"] + stats["observation_edges"] != stats["edges"]:
            problems.append("推理边 + 观测边 != 总边数")

        lines.append(f"  triggers 边: {len(trig)}")
        if problems:
            lines.append(f"  !! 发现 {len(problems)} 处问题：")
            for p in problems[:20]:
                lines.append(f"     - {p}")
        else:
            lines.append("  ✅ 全部不变量检查通过")

        summary = {
            "ok": not problems,
            "db": str(db_path),
            "nodes": stats["nodes"],
            "edges": stats["edges"],
            "inference_edges": stats["inference_edges"],
            "observation_edges": stats["observation_edges"],
            "nodes_by_type": stats["nodes_by_type"],
            "triggers_edges": len(trig),
            "problems": problems,
        }
    finally:
        g.close()

    return {"lines": lines, "summary": summary}


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    log_path = OUT / "run_all.log"
    log_f = open(log_path, "w", encoding="utf-8", newline="\n")
    sys.stdout = _Tee(sys.__stdout__, log_f)
    sys.stderr = _Tee(sys.__stderr__, log_f)

    print("=" * 78)
    print("跨层漏洞触发条件判定 —— 端到端验证")
    print("=" * 78)

    samples = write_samples(OUT / "samples")
    contract = make_div_zero_contract()
    print(f"\n触发契约: {contract.contract_id} ({contract.name})")
    print(f"样本数  : {len(samples)}")
    print()

    form = contract.formalization_report()
    print(f"契约形式化程度: {form['checkable_predicates']}/"
          f"{form['total_predicates']} "
          f"({form['formalization_ratio']:.0%})  "
          f"未形式化={form['unformalized_predicates']}")
    if form.get("unformalized_notes"):
        for n in form["unformalized_notes"]:
            print(f"  ! 未形式化: {n}")
    if form.get("warning"):
        print(f"  ! {form['warning']}")
    print()

    rows = []
    for sample, path in samples:
        print("-" * 78)
        print(f"[{sample.name}]  {sample.description}")
        print(f"  期望判定: {sample.expected_verdicts}")
        try:
            cfg = AnalysisConfig(
                target_id=sample.name,
                route="B",
                input_regs=("a0",),
                solver_timeout_ms=8000,
                max_candidates=30,
            )
            run = run_analysis(
                path,
                contract,
                config=cfg,
                db_path=OUT / "evidence.db",
                base_address=sample.base_addr,
                arch="riscv32",
                verbose=False,
            )
        except Exception as e:
            print(f"  !! 分析异常: {type(e).__name__}: {e}")
            traceback.print_exc(file=sys.stdout)
            rows.append({
                "sample": sample.name,
                "ok": False,
                "error": f"{type(e).__name__}: {e}",
            })
            continue

        verdicts = [r.verdict.value for r in run.results]
        got = set(verdicts)
        exp = set(sample.expected_verdicts)
        # 按语义分组比较：更精确的判定不应被算作错误
        got_groups = {VERDICT_GROUPS.get(v, v) for v in got}
        exp_groups = {VERDICT_GROUPS.get(v, v) for v in exp}
        hit = bool(got_groups & exp_groups)

        st = run.program.stats if run.program is not None else {}
        n_cand = sum(
            1 for r in run.results
            if r.verdict.value == "exploitable_candidate"
        )

        print(f"  实际判定: {sorted(got) if got else '(无可达候选)'}")
        print(f"  匹配结果: {'PASS' if hit else 'FAIL'}"
              f"   语义组 实={sorted(got_groups)} 期={sorted(exp_groups)}")
        print(f"  候选数  : {n_cand} / 结果数 {len(run.results)}   "
              f"块={st.get('blocks')}  指令={st.get('lift_total')}  "
              f"函数={st.get('functions')}  耗时={run.elapsed():.3f}s")

        for r in run.results[:8]:
            mark = "  <== CANDIDATE" if (
                r.verdict.value == "exploitable_candidate") else ""
            print(f"    - 0x{r.block_addr:08x} [{r.verdict.value}] "
                  f"可达={'是' if r.path_length else '否'}"
                  f"(len={r.path_length}) "
                  f"可控={r.control_status.value} "
                  f"sat={r.satisfiability} "
                  f"进展={r.progress:.2f}{mark}")
            if r.key_insn:
                print(f"        关键指令: {r.key_insn}")
            for c in r.input_constraints[:3]:
                print(f"        约束: {c}")
            for n in (r.notes or [])[:3]:
                print(f"        · {n}")

        rep = generate_report(
            run, contract, OUT / "reports" / f"{sample.name}.md")
        print(f"  报告    : {rep}")

        rows.append({
            "sample": sample.name,
            "ok": True,
            "binary_label": sample.binary_label,
            "expected": sorted(exp),
            "got": sorted(got),
            "expected_groups": sorted(exp_groups),
            "got_groups": sorted(got_groups),
            "pass": hit,
            "n_candidates": n_cand,
            "n_results": len(run.results),
            "n_blocks": st.get("blocks"),
            "n_instructions": st.get("lift_total"),
            "n_functions": st.get("functions"),
            "n_unreachable": st.get("unreachable_blocks"),
            "n_corrective": st.get("corrective_blocks"),
            "unknown_ratio": st.get("lift_unknown_ratio"),
            "elapsed_sec": round(run.elapsed(), 4),
        })

    # ---- 汇总 ----
    valid = [r for r in rows if r.get("ok")]
    n = len(valid)
    n_hit = sum(1 for r in valid if r["pass"])
    n_err = len(rows) - n

    print()
    print("=" * 78)
    print("汇总结论")
    print("=" * 78)
    print(f"可执行样本 : {n}   异常样本 : {n_err}")
    print(f"判定正确   : {n_hit}/{n}")
    print(f"准确率     : {n_hit / n:.1%}" if n else "准确率     : N/A")
    # ---- 论文级指标：必须分开报告假阳性与假阴性 ----
    #
    # ★ 关键：只用 binary_label 明确标注为 exploitable/unexploitable 的样本
    # 参与二分类统计。S12/S13 考查的是"可达性不得被误报为不可达"，
    # 它们的 expected_verdicts 列了多个可接受判定；若一并计入，
    # 会把"没有误报不可达"错误算成可利用性假阴性。
    scored = [r for r in valid
              if r.get("binary_label") in ("exploitable", "unexploitable")]
    n_excluded = n - len(scored)

    fp = [r for r in scored
          if "EXPLOITABLE" in r["got_groups"]
          and r["binary_label"] == "unexploitable"]
    fn = [r for r in scored
          if "EXPLOITABLE" not in r["got_groups"]
          and r["binary_label"] == "exploitable"]
    tp = [r for r in scored
          if "EXPLOITABLE" in r["got_groups"]
          and r["binary_label"] == "exploitable"]
    tn = [r for r in scored
          if "EXPLOITABLE" not in r["got_groups"]
          and r["binary_label"] == "unexploitable"]

    n_pos = len([r for r in scored if r["binary_label"] == "exploitable"])
    n_neg = len([r for r in scored if r["binary_label"] == "unexploitable"])
    prec = len(tp) / (len(tp) + len(fp)) if (tp or fp) else 1.0
    rec = len(tp) / n_pos if n_pos else 1.0

    print()
    print("二分类视角（可利用 vs 不可利用）")
    print(f"  真阳性 TP={len(tp)}  假阳性 FP={len(fp)}")
    print(f"  真阴性 TN={len(tn)}  假阴性 FN={len(fn)}")
    print(f"  正样本 {n_pos} / 负样本 {n_neg}"
          f"   未计入 {n_excluded}（考查其它性质，见 binary_label）")
    print(f"  精确率 Precision = {prec:.1%}")
    print(f"  召回率 Recall    = {rec:.1%}")
    if fp:
        print(f"  !! 假阳性样本: {[r['sample'] for r in fp]}")
    if fn:
        print(f"  !! 假阴性样本: {[r['sample'] for r in fn]}")

    print()
    print("逐样本")
    for r in valid:
        flag = "OK  " if r["pass"] else "FAIL"
        bl = r.get("binary_label", "?")
        tag = {"exploitable": "POS", "unexploitable": "NEG",
               "excluded": "EXC"}.get(bl, "?")
        print(f"  [{flag}] {r['sample']:<30} [{tag}] "
              f"实={','.join(r['got_groups'])} "
              f"期={','.join(r['expected_groups'])}")

    # ---- 证据图自检 ----
    # evidence.py 若只写不验，等于没写。这里做**结构与不变量**检查。
    print()
    print("=" * 78)
    print("证据图（CLEG）自检")
    print("=" * 78)
    graph_check = _check_evidence_graph(OUT / "evidence.db")
    for line in graph_check["lines"]:
        print(line)

    summary = {
        "n_samples": len(rows),
        "n_ok": n,
        "n_error": n_err,
        "n_pass": n_hit,
        "accuracy": round(n_hit / n, 4) if n else 0.0,
        "binary": {
            "tp": len(tp), "fp": len(fp), "tn": len(tn), "fn": len(fn),
            "n_positive": n_pos, "n_negative": n_neg,
            "n_excluded_from_binary": n_excluded,
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "false_positives": [r["sample"] for r in fp],
            "false_negatives": [r["sample"] for r in fn],
            "note": (
                "仅 binary_label ∈ {exploitable, unexploitable} 的样本参与"
                "二分类统计；excluded 样本考查可达性保真等其它性质"
            ),
        },
        "contract": {
            "id": contract.contract_id,
            "name": contract.name,
            "formalization": form,
        },
        "evidence_graph": graph_check["summary"],
        "rows": rows,
    }
    (OUT / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n写出: {OUT / 'summary.json'}")
    print(f"日志: {log_path}")

    log_f.flush()
    log_f.close()
    ok = (n_err == 0 and n_hit == n and graph_check["summary"].get("ok"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
