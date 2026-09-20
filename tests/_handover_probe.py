"""交接文档取证脚本：把环境版本、契约内容、样本清单写成纯文本。

为什么需要它：本机的 PowerShell 管道会吃掉子进程的 UTF-8 stdout
（读出来是乱码或空），所以凡是需要「读到文字」的场合，
一律让 Python 自己写文件，再由 Read 工具读。
"""

from __future__ import annotations

import platform
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT))


def main() -> int:
    L: list[str] = []
    w = L.append

    w("=" * 70)
    w("A. 运行环境与依赖版本")
    w("=" * 70)
    w(f"python           : {sys.version.split()[0]} ({platform.machine()})")
    w(f"executable       : {sys.executable}")
    for mod, attr in [
        ("z3", "__version__"),
        ("capstone", "__version__"),
        ("elftools", "__version__"),
        ("networkx", "__version__"),
        ("jsonschema", "__version__"),
        ("yaml", "__version__"),
    ]:
        try:
            m = __import__(mod)
            v = getattr(m, attr, None)
            if v is None:
                v = getattr(getattr(m, "version", None), "__version__", "n/a")
            w(f"{mod:<16} : {v}")
        except Exception as e:  # noqa: BLE001
            w(f"{mod:<16} : 缺失 ({type(e).__name__}: {e})")

    import crosslayer
    w(f"{'crosslayer':<16} : {crosslayer.__version__}")
    w(f"引擎包路径       : {Path(crosslayer.__file__).parent}")

    w("")
    w("=" * 70)
    w("B. 硬件触发契约内容（div_zero）")
    w("=" * 70)
    from contracts.div_zero import make_div_zero_contract
    c = make_div_zero_contract()
    rep = c.formalization_report()
    w(f"contract_id      : {c.contract_id}")
    w(f"name             : {c.name}")
    w(f"bug_class        : {c.bug_class.value}")
    w(f"evidence_level   : {c.evidence_level}")
    w(f"platform         : {c.platform.isa} / {c.platform.core_model}")
    w(f"形式化完整性     : {rep['checkable_predicates']}/{rep['total_predicates']} "
      f"({rep['formalization_ratio']:.0%})")
    w(f"required_op_classes (pre+trigger) : "
      f"{[o.value for o in c.required_op_classes()]}")
    w(f"trigger_op_classes  (判别性)      : "
      f"{[o.value for o in c.trigger_op_classes()]}")
    w("")
    w("全部谓词：")
    for p in c.all_predicates():
        ok = p.checkable
        w(f"  [{'OK ' if ok else '---'}] {p.kind.value:<20} {p.description}")

    w("")
    w("=" * 70)
    w("C. 样本清单（地面真值）")
    w("=" * 70)
    sys.path.insert(0, str(ROOT / "tests"))
    from fixtures import ALL_SAMPLES  # type: ignore

    samples = [f() for f in ALL_SAMPLES]

    w(f"样本总数: {len(samples)}")
    w("")
    w(f"{'样本名':<34} {'二分类标签':<14} {'可接受判定'}")
    w("-" * 100)
    for s in samples:
        exp = ", ".join(s.expected_verdicts)
        w(f"{s.name:<34} {s.binary_label:<14} {exp}")

    n_pos = sum(1 for s in samples if s.binary_label == "exploitable")
    n_neg = sum(1 for s in samples if s.binary_label == "unexploitable")
    n_exc = sum(1 for s in samples if s.binary_label == "excluded")
    w("")
    w(f"exploitable={n_pos}  unexploitable={n_neg}  excluded={n_exc}")

    out = ROOT / "out" / "_handover_probe.txt"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(L), encoding="utf-8")
    print(f"written: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
