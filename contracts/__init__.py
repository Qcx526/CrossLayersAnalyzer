"""
契约库 —— 硬件触发契约的构造代码。

每个契约对应一类硬件缺陷，按 Pre / Trigger / Deviation / Observe 四段组织。
详见本目录 README.md。

导入方式：
    from contracts.div_zero import make_div_zero_contract
"""

from .div_zero import make_div_zero_contract

__all__ = ["make_div_zero_contract"]
