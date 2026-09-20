"""
统一测试入口 —— 一条命令跑完全部测试。

用法：
    python tests/run_tests.py

退出码 0 表示全部通过；非 0 表示有失败项。
适合作为 CI / 论文复现脚本的第一条命令。
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PY = sys.executable

# (显示名, 脚本相对路径, 用途)
SUITES: list[tuple[str, str, str]] = [
    ("指令编码自检", "tests/test_encoder.py",
     "RISC-V 编码器与 capstone 交叉验证（防止 ground truth 本身写错）"),
    ("IR 提升", "tests/test_lifter.py",
     "反汇编 → 统一 IR 的正确性"),
    ("证据图不变量", "tests/test_evidence.py",
     "CLEG 推理/观测边分离、条件完备性"),
    ("端到端判定", "tests/run_all.py",
     "11 个样本的 Precision / Recall 与证据图自检"),
]


def main() -> int:
    print("=" * 78)
    print("跨层漏洞分析器 —— 全量测试")
    print("=" * 78)
    print(f"Python : {PY}")
    print(f"根目录 : {ROOT}")
    print()

    results = []
    for name, rel, purpose in SUITES:
        script = ROOT / rel
        print("-" * 78)
        print(f"[RUN ] {name}  ({rel})")
        print(f"       {purpose}")
        if not script.exists():
            print("       !! 脚本不存在，跳过")
            results.append((name, "MISSING", 0.0, ""))
            continue

        t0 = time.time()
        p = subprocess.run(
            [PY, str(script)],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        dt = time.time() - t0
        tail = ""
        if p.returncode != 0:
            lines = (p.stdout or "").splitlines()
            # 只保留失败相关的行，避免刷屏
            interesting = [
                ln for ln in lines
                if ("FAIL" in ln or "!!" in ln or "Traceback" in ln
                    or "Error" in ln or "- " in ln)
            ]
            tail = "\n".join((interesting or lines)[-12:])
            print(f"       !! 退出码 {p.returncode}，耗时 {dt:.2f}s")
            if tail:
                for ln in tail.splitlines():
                    print(f"       | {ln}")
        else:
            print(f"       OK  耗时 {dt:.2f}s")

        results.append((name, "PASS" if p.returncode == 0 else "FAIL", dt, tail))

    print()
    print("=" * 78)
    print("测试汇总")
    print("=" * 78)
    n_pass = sum(1 for r in results if r[1] == "PASS")
    for name, status, dt, _ in results:
        mark = {"PASS": "OK  ", "FAIL": "FAIL", "MISSING": "MISS"}[status]
        print(f"  [{mark}] {name:<20} {dt:6.2f}s")
    print()
    print(f"通过 {n_pass}/{len(results)}")

    ok = n_pass == len(results)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
