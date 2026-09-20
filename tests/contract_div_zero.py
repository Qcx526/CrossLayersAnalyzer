"""
测试用契约 —— 转发到 contracts/div_zero.py 的单一真源。

为什么要做这个转发而不是复制一份
--------------------------------
契约在两个地方被定义（测试目录与交付的契约库）会导致**真源分裂**：
改了其中一份，测试还在验证旧契约，于是测试通过但实际交付物是错的。

所以这里只做 re-export，真源唯一在 `contracts/div_zero.py`。
若该文件缺失或接口变更，本模块会立刻 ImportError，
比"测试悄悄验证了一份过时契约"要好得多。
"""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
# 契约包在仓库根目录（与 src/ 平级），需要把根目录加入 sys.path
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from contracts.div_zero import make_div_zero_contract  # noqa: E402,F401

__all__ = ["make_div_zero_contract"]


if __name__ == "__main__":
    c = make_div_zero_contract()
    rep = c.formalization_report()
    print(f"契约: {c.contract_id} — {c.name}")
    print(f"可检查谓词: {rep['checkable_predicates']}/{rep['total_predicates']}"
          f" ({rep['formalization_ratio']:.0%})")
    print(f"要求操作类别: {sorted(o.value for o in c.required_op_classes())}")
    print(f"判别性操作  : {sorted(o.value for o in c.trigger_op_classes())}")
