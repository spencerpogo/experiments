from io import BytesIO
from typing import BinaryIO

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import Section, SymbolTableSection
from elftools.elf.enums import ENUM_RELOC_TYPE_x64
from elftools.elf.constants import SHN_INDICES
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86_const import *

from relocation import RelocationHandler


def read_exact(f, n):
    buff = bytearray(n)
    pos = 0
    while pos < n:
        cr = f.readinto(memoryview(buff)[pos:])
        if cr == 0:
            raise EOFError
        pos += cr
    return buff


calling_convention = [
    X86_REG_RDI,
    X86_REG_RSI,
    X86_REG_RDX,
    X86_REG_RCX,
    X86_REG_R8,
    X86_REG_R9,
]


class Section:
    __slots__ = ("elf", "target_sec", "sec")

    def __init__(self, elf, target_sec, sec):
        self.elf = elf
        self.target_sec = target_sec
        self.sec = sec
    
    def relocations_referencing(self, symbol):
        """
        Find all relocations that with a name matching `symbol` in the symbol table
        associated with the relocation section `rela`.
        """
        symtab = self.elf.elf.get_section(self.sec["sh_link"])
        return [
            Relocation(self.elf, self, r)
            for r in self.sec.iter_relocations()
            if symtab.get_symbol(r["r_info_sym"]).name == symbol
        ]

    def relocation_referencing(self, func):
        """
        Find a single relocation with a name matching `symbol` in the symbol table
        associated with the relocation section `rela`. Assert that there is only one
        such matching relocation, and return it.
        """
        rels = self.relocations_referencing(func)
        if len(rels) == 0:
            raise AssertionError(f"no relocations for func {func!r}")
        if len(rels) != 1:
            raise AssertionError(
                f"expected one relocation for func {func!r}, instead got {len(rels)}"
            )
        return rels[0]

    @property
    def sh_offset(self):
        return self.sec["sh_offset"]


def _find_continaing_function(e, rela, section_offset):
    """
    Find the first STT_FUNC symbol in the symbol table associated with `rela` that
    contains the byte that lies `section_offset` bytes from the start of the section
    `rela` is associated with.
    Contains means within the range [st_value, st_value+st_size).
    Return the symbol, and the number of bytes from the start of the function to the offset.
    """
    symtab = e.get_section(rela["sh_link"])
    for sym in symtab.iter_symbols():
        if sym["st_info"]["type"] != "STT_FUNC":
            continue
        if (
            section_offset >= sym["st_value"]
            and section_offset <= sym["st_value"] + sym["st_size"]
        ):
            return sym, section_offset - sym["st_value"]
    raise AssertionError(f"no STT_FUNC contains this offset")


class Relocation:
    __slots__ = ("elf", "section", "reloc")

    def __init__(self, elf, section, reloc):
        self.elf = elf
        self.section = section
        self.reloc = reloc
    
    def find_continaing_function(self):
        """
        Find the first STT_FUNC symbol that contains the location of this relocation. 
        Return the symbol, and the number of bytes from the start of the function to this relocation. 
        """
        if self.section.target_sec is None:
            raise ValueError("Cannot find target section. Relocation section must be created by ELF.relocations_for")
        func, offset = _find_continaing_function(self.elf.elf, self.section.sec, self.reloc["r_offset"])
        return Symbol(self.elf, self.section.target_sec, func), offset


class Symbol:
    __slots__ = ("elf", "section", "sym")

    def __init__(self, elf, section, sym):
        self.elf = elf
        self.section = section
        self.sym = sym
    
    @property
    def name(self):
        return self.sym.name
    
    @property
    def entry(self):
        return self.sym.entry

    @property
    def st_value(self):
        return self.sym["st_value"]

    @property
    def st_size(self):
        return self.sym["st_size"]

    def read_exact(self):
        self.elf.seek(self.section.sh_offset + self.st_value)
        return self.elf.read_exact(self.st_size)



class ELF:
    fh: BinaryIO
    elf: ELFFile
    md: Cs
    __slots__ = ("fh", "elf", "md")

    def __init__(self, fh, elf):
        self.fh = fh
        self.elf = elf
        self.md = None

    @classmethod
    def read_from_path(cls, path):
        with open(path, "rb") as fh:
            fh = BytesIO(fh.read())
        return cls(fh, ELFFile(fh))
    
    def seek(self, i):
        return self.fh.seek(i)

    def read_exact(self, n):
        return read_exact(self.fh, n)
    
    def read_word64(self):
        return self.elf.structs.Elf_word64("").parse_stream(self.fh)

    def section(self, name):
        return Section(self, None, self.elf.get_section_by_name(name))

    def relocations_for(self, sec):
        return Section(self, sec, RelocationHandler(self.elf).find_relocations_for_section(sec.sec))
    
    def setup_disassembler(self):
        if self.md is None:
            self.md = Cs(CS_ARCH_X86, CS_MODE_64)
            self.md.detail = True
    
    def disasm_text(self, text, addr=0x0):
        self.setup_disassembler()
        return self.md.disasm(text, addr)
    
    def disasm(self, n, addr=0x0):
        self.setup_disassembler()
        return self.md.disasm(self.read_exact(n), addr)


class RelocationScheme:
    __slots__ = ("elf", "base", "start_offset", "addresses")

    def __init__(self, elf, base, start_offset, addresses):
        self.elf = elf
        self.base = base
        self.start_offset = start_offset
        self.addresses = addresses

    @classmethod
    def from_ghidra(cls, elf: ELF):
        """A relocation scheme that matches the addresses in Ghidra's disassembly view."""
        base = 0x00100000
        start_offset = next(
            sec for sec in elf.elf.iter_sections() if sec["sh_type"] != "SHT_NULL"
        )["sh_offset"]
        scheme = cls(elf, base, start_offset, {})
        for sec in elf.elf.iter_sections():
            scheme.addresses[sec.name] = scheme.offset_to_addr(sec["sh_offset"])
        if len(scheme.addresses) != elf.elf.num_sections():
            raise AssertionError("duplicate section names")
        return scheme

    def offset_to_addr(self, offset):
        return offset + self.base - self.start_offset

    def addr_to_offset(self, addr):
        return addr - self.base + self.start_offset

    def relocate(self, section):
        reler = RelocationHandler(self.elf.elf)
        relocation_section = reler.find_relocations_for_section(section.sec)
        if not relocation_section.is_RELA():
            raise NotImplementedError(
                "non-RELA relocations support has not been tested."
            )
        reler.apply_section_relocations(self.elf.fh, self.addresses, section.sec, relocation_section)
    
    def seek_addr(self, addr):
        self.elf.fh.seek(self.addr_to_offset(addr))
    
    def disasm_addr(self, addr, n):
        self.seek_addr(addr)
        return self.elf.disasm(n, addr)
