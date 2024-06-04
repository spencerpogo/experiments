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


class ELF:
    fh: BinaryIO
    elf: ELFFile
    md: Cs
    __slots__ = ("fh", "elf", "md")

    def __init__(self, fh):
        self.fh = fh
        self.elf = ELFFile(self.fh)
        self.md = None
    
    @classmethod
    def read_from_path(cls, path):
        with open(path, "rb") as fh:
            fh = BytesIO(fh.read())
        return cls(fh)
    
    def read_exact(self, n):
        return read_exact(self.fh, n)

    def section(self, name):
        return self.elf.get_section_by_name(name)
    
    def relocations_for(self, sec):
        return RelocationHandler(self.elf).find_relocations_for_section(sec)
    
    def relocate(self, section, addresses):
        reler = RelocationHandler(self.elf)
        relocation_section = reler.find_relocations_for_section(section)
        if not relocation_section.is_RELA():
            raise NotImplementedError("non-RELA relocations support has not been tested.")
        reler.apply_section_relocations(self.fh, addresses, section, relocation_section)


    def relocations_referencing(self, rela, symbol):
        """
        Find all relocations that with a name matching `symbol` in the symbol table
        associated with the relocation section `rela`.
        """
        symtab = e.get_section(rela["sh_link"])
        return [
            r
            for r in rela.iter_relocations()
            if symtab.get_symbol(r["r_info_sym"]).name == symbol
        ]


    def relocation_referencing(self, rela, func):
        """
        Find a single relocation with a name matching `symbol` in the symbol table
        associated with the relocation section `rela`. Assert that there is only one
        such matching relocation, and return it.
        """
        rels = relocations_for_symbol(e, rela, func)
        if len(rels) == 0:
            raise AssertionError(f"no relocations for func {func!r}")
        if len(rels) != 1:
            raise AssertionError(
                f"expected one relocation for func {func!r}, instead got {len(rels)}"
            )
        return rels[0]
