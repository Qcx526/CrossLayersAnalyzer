"""
跨层漏洞分析 —— 固件加载与身份固定

**这是"不生成新 ELF"约束的技术落点。**

本模块负责：
1. 加载原始固件（ELF / raw binary），并记录其**身份**（SHA-256、段布局、入口）；
2. 提取可执行段的内容与装载地址；
3. 产出 `FirmwareImage` 对象，供后续分析使用。

关键纪律
--------
- 分析对象**始终是原始镜像**。本模块不做任何代码修改。
- 所有分析产物（反汇编、IR、CFG）都**引用**原始地址，
  使得任何结论都能回溯到原始镜像的具体偏移。
- 记录 `identity` 快照，报告必须携带它，以证明分析的是同一份镜像。
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    HAVE_ELFTOOLS = True
except ImportError:  # pragma: no cover
    HAVE_ELFTOOLS = False


# ---------------------------------------------------------------------------
@dataclass
class Segment:
    """镜像中的一个可装载区域。"""

    name: str
    vaddr: int
    size: int
    data: bytes
    is_executable: bool = False
    is_writable: bool = False
    flags: str = ""


@dataclass
class FirmwareImage:
    """
    原始固件镜像。

    `sha256` 是**不可变身份**：任何实验记录都必须携带它。
    若两次分析的哈希不同，结论不可直接比较。
    """

    path: str
    sha256: str
    size: int
    fmt: str                                    # elf / bin
    arch: str = "unknown"
    entry_point: int = 0
    base_address: int = 0
    endianness: str = "little"

    segments: list[Segment] = field(default_factory=list)

    # 符号与调试信息（可能缺失 —— 缺失必须显式标注，不能用伪造符号替代）
    symbols: dict[str, int] = field(default_factory=dict)
    has_symbols: bool = False
    has_debug_info: bool = False

    # 引导链依赖
    boot_chain_dependency: str = ""

    # 装载一致性说明
    identity_notes: str = ""

    notes: list[str] = field(default_factory=list)

    # ------------------------------------------------------------------
    def executable_segments(self) -> list[Segment]:
        return [s for s in self.segments if s.is_executable]

    def read(self, addr: int, n: int) -> Optional[bytes]:
        """按虚拟地址读取内存内容（跨段查找）。"""
        for s in self.segments:
            if s.vaddr <= addr < s.vaddr + s.size:
                off = addr - s.vaddr
                end = min(off + n, s.size)
                return s.data[off:end]
        return None

    def contains_addr(self, addr: int) -> bool:
        return any(s.vaddr <= addr < s.vaddr + s.size for s in self.segments)

    def identity(self) -> dict[str, Any]:
        """
        身份快照。报告的每个结论都应携带它 —— 
        这是"在原始镜像上分析"这一约束的可验证证据。
        """
        return {
            "path": self.path,
            "sha256": self.sha256,
            "size": self.size,
            "format": self.fmt,
            "arch": self.arch,
            "entry_point": f"0x{self.entry_point:x}",
            "base_address": f"0x{self.base_address:x}",
            "executable_segments": [
                {"name": s.name, "vaddr": f"0x{s.vaddr:x}", "size": s.size}
                for s in self.executable_segments()
            ],
            "has_symbols": self.has_symbols,
            "has_debug_info": self.has_debug_info,
            "identity_notes": self.identity_notes,
        }


# ---------------------------------------------------------------------------
def _detect_arch_from_elf(elf: "ELFFile") -> tuple[str, str, int]:
    """从 ELF header 推断架构、字节序与位宽。"""
    ei = elf.header["e_ident"]
    little = ei["EI_DATA"] == "ELFDATA2LSB"
    endian = "little" if little else "big"
    machine = elf.header["e_machine"]
    is64 = elf.elfclass == 64

    table = {
        "EM_RISCV": "riscv64" if is64 else "riscv32",
        "EM_ARM": "arm",
        "EM_AARCH64": "aarch64",
        "EM_386": "x86",
        "EM_X86_64": "x86_64",
        "EM_PPC": "ppc",
        "EM_PPC64": "ppc64",
        "EM_SPARC": "sparc",
        "EM_SPARCV9": "sparc64",
        "EM_LOONGARCH": "loongarch",
    }
    return table.get(machine, f"unknown({machine})"), endian, (64 if is64 else 32)


def load_elf(path: str | Path) -> FirmwareImage:
    """加载 ELF 格式的原始固件。"""
    if not HAVE_ELFTOOLS:
        raise RuntimeError("pyelftools 未安装，无法解析 ELF")

    path = Path(path)
    raw = path.read_bytes()
    sha = hashlib.sha256(raw).hexdigest()

    with open(path, "rb") as fh:
        elf = ELFFile(fh)
        arch, endian, _bits = _detect_arch_from_elf(elf)

        segments: list[Segment] = []

        # 优先使用 program headers（反映真实装载布局）
        for i, ph in enumerate(elf.iter_segments()):
            if ph["p_type"] != "PT_LOAD":
                continue
            flags = int(ph["p_flags"])
            exec_bit = bool(flags & 0x1)
            write_bit = bool(flags & 0x2)
            segments.append(Segment(
                name=f"LOAD{i}",
                vaddr=int(ph["p_vaddr"]),
                size=int(ph["p_filesz"]),
                data=ph.data(),
                is_executable=exec_bit,
                is_writable=write_bit,
                flags=f"{'R' if flags & 0x4 else '-'}{'W' if write_bit else '-'}{'X' if exec_bit else '-'}",
            ))

        # 没有 PT_LOAD（少见）时退回 section 视图
        if not segments:
            for sec in elf.iter_sections():
                if not (sec["sh_flags"] & 0x4):   # SHF_EXECINSTR
                    continue
                segments.append(Segment(
                    name=sec.name, vaddr=int(sec["sh_addr"]),
                    size=int(sec["sh_size"]), data=sec.data(),
                    is_executable=True, flags="--X",
                ))

        # 符号表（可能不存在）
        symbols: dict[str, int] = {}
        for sec in elf.iter_sections():
            if isinstance(sec, SymbolTableSection):
                for sym in sec.iter_symbols():
                    if sym.name and sym["st_value"]:
                        symbols[sym.name] = int(sym["st_value"])

        has_debug = any(s.name.startswith(".debug") for s in elf.iter_sections())

        entry = int(elf.header["e_entry"])
        base = min((s.vaddr for s in segments), default=0)

    notes: list[str] = []
    if not symbols:
        notes.append("无符号表：函数边界需启发式识别，结论中的函数名不可信")
    if not has_debug:
        notes.append("无调试信息：只能给出 PC/指令/函数级定位，不能声称源码行号")
    if not any(s.is_executable for s in segments):
        notes.append("警告：未发现可执行段，装载布局可能异常")

    return FirmwareImage(
        path=str(path), sha256=sha, size=len(raw), fmt="elf",
        arch=arch, entry_point=entry, base_address=base, endianness=endian,
        segments=segments, symbols=symbols,
        has_symbols=bool(symbols), has_debug_info=has_debug,
        notes=notes,
        identity_notes=(
            f"原始 ELF，{len(segments)} 个 LOAD 段；"
            f"可执行段 {sum(1 for s in segments if s.is_executable)} 个；"
            "分析未修改镜像字节"
        ),
    )


def load_raw(path: str | Path, base_address: int = 0,
             arch: str = "unknown", endianness: str = "little") -> FirmwareImage:
    """
    加载裸二进制（BIN/HEX）。

    裸二进制没有自带布局信息，必须由调用方给出准确的装载地址 —— 
    **地址猜错会导致整个分析失效**，因此这里强制要求显式传入。
    """
    path = Path(path)
    raw = path.read_bytes()
    sha = hashlib.sha256(raw).hexdigest()

    seg = Segment(name="RAW", vaddr=base_address, size=len(raw),
                  data=raw, is_executable=True, is_writable=True, flags="RWX")

    return FirmwareImage(
        path=str(path), sha256=sha, size=len(raw), fmt="bin",
        arch=arch, entry_point=base_address, base_address=base_address,
        endianness=endianness, segments=[seg],
        has_symbols=False, has_debug_info=False,
        notes=[
            "裸二进制：无符号表、无调试信息、无段布局",
            f"装载基址由调用方指定为 0x{base_address:x}（必须与真实硬件一致）",
        ],
        identity_notes=f"原始 BIN，装载基址 0x{base_address:x}；分析未修改镜像字节",
    )


def load_firmware(path: str | Path, base_address: Optional[int] = None,
                  arch: str = "unknown") -> FirmwareImage:
    """按文件头自动选择加载方式。"""
    p = Path(path)
    head = p.read_bytes()[:4]
    if head == b"\x7fELF":
        return load_elf(p)
    if base_address is None:
        raise ValueError(
            "裸二进制必须显式指定装载基址 base_address —— "
            "猜错地址会导致整个分析失效"
        )
    return load_raw(p, base_address=base_address, arch=arch)
