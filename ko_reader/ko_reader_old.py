import sys
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.relocation import RelocationHandler
from elftools.elf.enums import ENUM_RELOC_TYPE_x64
from elftools.elf.constants import SHN_INDICES
from binascii import hexlify
from io import BytesIO

# from pwn import disasm
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import *


def symbol_by_name(symbols, sym):
    """Find the first symbol with a name matching `sym`."""
    for i in range(symbols.num_symbols()):
        s = symbols.get_symbol(i)
        if s.name == sym:
            return s
    raise AssertionError(
        f"unable to find symbol {sym!r} in {symbols.num_symbols()} entry symbol table"
    )


def wip_apply_relocations():
    """Messing with applying relocations. not currently used."""
    reler = RelocationHandler(e)
    reler._RELOCATION_RECIPES_X64[ENUM_RELOC_TYPE_x64["R_X86_64_PLT32"]] = (
        RelocationHandler._RELOCATION_RECIPE_TYPE(
            bytesize=4,
            has_addend=True,
            calc_func=RelocationHandler._reloc_calc_sym_plus_addend_pcrel,
        )
    )

    rel = reler.find_relocations_for_section(text)
    # reler.apply_section_relocations(f, rel)


def relocations_for_symbol(e, rela, symbol):
    """
    Find all relocations that with a name matching `symbol` in the symbol table
    associated with `rela`.
    """
    symtab = e.get_section(rela["sh_link"])
    return [
        r
        for r in rela.iter_relocations()
        if symtab.get_symbol(r["r_info_sym"]).name == symbol
    ]


def relocation_for_symbol(e, rela, func):
    """
    Find a single relocation with a name matching `symbol` in the symbol table
    associated with `rela`. Assert that there is only one such matching relocation,
    and return it.
    """
    rels = relocations_for_symbol(e, rela, func)
    if len(rels) == 0:
        raise AssertionError(f"no relocations for func {func!r}")
    if len(rels) != 1:
        raise AssertionError(
            f"expected one relocation for func {func!r}, instead got {len(rels)}"
        )
    return rels[0]


def find_continaing_function(e, rela, section_offset):
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


def read_exact(f, n):
    buff = bytearray(n)
    pos = 0
    while pos < n:
        cr = f.readinto(memoryview(buff)[pos:])
        if cr == 0:
            raise EOFError
        pos += cr
    return buff


def read_symbol(f, section, sym):
    """
    Given a `section` and a symbol `sym` assumed to be in it, return the byte contents
    of that symbol.
    """
    f.seek(section["sh_offset"] + sym["st_value"])
    return read_exact(f, sym["st_size"])


calling_convention = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
calling_convention = [
    X86_REG_RDI,
    X86_REG_RSI,
    X86_REG_RDX,
    X86_REG_RCX,
    X86_REG_R8,
    X86_REG_R9,
]


def relocs_in_range(e, rela, start, sz):
    """
    Generator that will yield all relocations in `rela` within the range of section
    offsets [start, start+sz) given an ELFFile `e`
    """
    for reloc in rela.iter_relocations():
        if reloc["r_offset"] >= start and reloc["r_offset"] <= start + sz:
            yield reloc


def reloc_in_range(e, rela, start, sz):
    relocs = list(relocs_in_range(e, rela, start, sz))
    if not relocs:
        raise AssertionError("no relocations found in range")
    if len(relocs) != 1:
        raise AssertionError(f"found {len(relocs)} relocs in range")
    return relocs[0]


def insn_modifying_reg_before(e, trela, text, reg, func, func_offset):
    """
    Return the last instruction after the start of the function given by the symbol
    `func` but before `func_offset` instruction bytes from that start, that modifies
    `reg`, given an ELFFile `e`, text relocation table `trela`, and text section `text`.
    """
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    found = []
    for i in md.disasm(text, 0x0):
        # stop when we get to the instruction containing the relocation in question
        if i.address + i.size >= func_offset:
            continue
        _, regs_written = i.regs_access()
        if reg in regs_written:
            found.append(i)
    if not found:
        raise AssertionError(f"cannot find an instruction modifying {reg!r}")
    return found[-1]


def read_symbol_relative_reloc(e, rela, reloc, n):
    symtab = e.get_section(rela["sh_link"])
    sym = symtab.get_symbol(reloc["r_info_sym"])
    section = e.get_section(sym["st_shndx"])
    location = section["sh_offset"] + sym["st_value"] + reloc["r_addend"]
    print(f"seek to {hex(location)}={location}")
    e.stream.seek(location)
    return e.stream.read(n)


def main():
    with open(sys.argv[1], "rb") as f_rdonly:
        # if you want to modify the data, such as by applying relocations, read the
        #  entire file into a BytesIO and use it.
        # f = BytesIO(f_rdonly.read())
        # otherwise, use the read-only file handle directly.
        f = f_rdonly
        e = ELFFile(f)
        text = e.get_section_by_name(".text")
        reler = RelocationHandler(e)
        trela = reler.find_relocations_for_section(text)
        if not trela.is_RELA():
            raise AssertionError(
                "text relocations are REL but expected RELA. this will probably work "
                + "just as well, but it hasn't been tested."
            )

        # when compiling a kernel module, the compiler will create an init_module
        #  symbol, and set it to be an alias of the module's init function. It will
        #  then export init_module as a global symbol.
        # source:
        # https://terenceli.github.io/%E6%8A%80%E6%9C%AF/2018/06/02/linux-loadable-module
        symbols = e.get_section_by_name(".symtab")
        if not isinstance(symbols, SymbolTableSection):
            raise AssertionError("unable to load symbol table")
        init = symbol_by_name(symbols, "init_module")
        if init["st_info"]["type"] != "STT_FUNC":
            raise AssertionError("expected init_module to be an STT_FUNC")

        # another way to find the functions we want is to find the call sites of the
        #  kernel APIs they use. In order to be relocated properly, the module will have
        #  to reference the symbol names they want to import. We can trace these
        #  relocations back to the `call`` instruction they are adjusting.
        proc_create_reloc = relocation_for_symbol(e, trela, "proc_create")
        print(proc_create_reloc)
        func, func_offset = find_continaing_function(
            e, trela, proc_create_reloc["r_offset"]
        )
        print(func, func.name, func.entry, func_offset)
        init_text = read_symbol(f, text, func)
        print(init_text)
        print(hex(func_offset))
        # struct proc_dir_entry *proc_create(
        #   const char *name, // arg 0
        #   umode_t mode, // arg 1
        #   struct proc_dir_entry *parent, // arg 2
        #   const struct file_operations *proc_fops // arg 3
        # );
        # ...so proc_fops is calling_convention[3]
        fops_loading_insn = insn_modifying_reg_before(
            e, trela, init_text, calling_convention[3], func, func_offset
        )
        # we assume that fops is located in the .data section, so find the corresponding
        #  relocation.
        fops_reloc = reloc_in_range(
            e,
            trela,
            func["st_value"] + fops_loading_insn.address,
            fops_loading_insn.size,
        )
        print(fops_reloc)
        # for information about relocation types, see page 72 of the System V AMD64 ABI
        #  documentation: https://refspecs.linuxbase.org/elf/x86_64-abi-0.99.pdf
        if fops_reloc["r_info_type"] != ENUM_RELOC_TYPE_x64["R_X86_64_32S"]:
            raise AssertionError("fops reloc type changed. investigate.")

        # you can find these offsets either from subtracting in the ghidra listing, or
        #  by using offsetof(struct file_operations, unlocked_ioctl) in a kernel module
        #  you compile, then disassembling it (or you could load it and then printk).
        # I wanted to make a one-liner you could use to dump an offset, but linux/fs.h
        #  pulls in a ton of other headers files that don't easily work when you try to
        #  sidestep the normal build process.
        unlocked_ioctl_offset = 0x50
        # we assume that the entry in .data will be a function pointer, and therefore
        #  will be written by a relocation.
        container_sym = e.get_section(trela["sh_link"]).get_symbol(
            fops_reloc["r_info_sym"]
        )
        if container_sym["st_info"]["type"] != "STT_SECTION":
            raise AssertionError("fops referenced symbol changed. investigate")
        container_section = e.get_section(container_sym["st_shndx"])
        container_rela = reler.find_relocations_for_section(container_section)
        container_offset = (
            container_sym["st_value"] + fops_reloc["r_addend"] + unlocked_ioctl_offset
        )
        print(hex(container_offset))
        if fops_reloc["r_info_type"] != 11:
            raise AssertionError("fops relocation type changed, check that it is still 8 bytes")
        ioctl_reloc = reloc_in_range(e, container_rela, container_offset, 8)
        print(e.get_section(container_rela["sh_link"]).get_symbol(
            ioctl_reloc["r_info_sym"]
        ).entry)
        print(
            read_symbol_relative_reloc(
                e, trela, fops_reloc, unlocked_ioctl_offset + 0x8
            )
        )


if __name__ == "__main__":
    main()
