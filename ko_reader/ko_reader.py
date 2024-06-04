import sys
from binascii import hexlify
from io import BytesIO
from dataclasses import dataclass
from typing import ClassVar

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.enums import ENUM_RELOC_TYPE_x64
from elftools.elf.constants import SHN_INDICES
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import *

from relocation import RelocationHandler
import simple_emu


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
    location = section["sh_offset"] + sym["st_value"]
    print('seek to', hex(location))
    f.seek(location)
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


def to_signed_32(n):
    sign_bit = 1 << 31
    # extract non-sign bits
    n = n & ((1 << 32) - 1)
    # flip sign bit: move negatives from above positives to below
    n = n ^ sign_bit
    # move negatives below zero
    return n - sign_bit


# represents the address of the current yan85 instruction
@dataclass
class InsAddr(simple_emu.EmuValue):
    pass


@dataclass
class PackedIns(simple_emu.EmuValue):
    pass


def main():
    with open(sys.argv[1], "rb") as f_rdonly:
        # if you want to modify the data, such as by applying relocations, read the
        #  entire file into a BytesIO and use it.
        f = BytesIO(f_rdonly.read())
        # otherwise, use the read-only file handle directly.
        # f = f_rdonly
        e = ELFFile(f)
        text = e.get_section_by_name(".text")
        reler = RelocationHandler(e)
        trela = reler.find_relocations_for_section(text)
        if not trela.is_RELA():
            raise AssertionError(
                "text relocations are REL but expected RELA. this will probably work "
                + "just as well, but it hasn't been tested."
            )

        reler = RelocationHandler(e)

        # kernel modules don't request particular memory offsets. they must be PIE as
        #  they have to be loaded into kernel address space. 
        # This means that when we mimic performing relocations, we can pick whatever
        #  virtual addresses we want. 
        # Let's pick a scheme that will match the ghidra listing view.
        # Make base match the start of the first section.
        base = 0x00100000
        start_offset = next(
            sec for sec in e.iter_sections() if sec["sh_type"] != "SHT_NULL"
        )["sh_offset"]
        offset_to_addr = lambda offset: offset + base - start_offset
        addr_to_offset = lambda addr: addr - base + start_offset
        addresses = {
            sec.name: offset_to_addr(sec["sh_offset"]) for sec in e.iter_sections()
        }
        if len(addresses) != e.num_sections():
            raise AssertionError("duplicate section names")

        module_section = e.get_section_by_name(".gnu.linkonce.this_module")
        rel = reler.find_relocations_for_section(module_section)
        reler.apply_section_relocations(f, addresses, module_section, rel)

        data = e.get_section_by_name(".data")
        rel = reler.find_relocations_for_section(data)
        reler.apply_section_relocations(f, addresses, data, rel)

        rel = reler.find_relocations_for_section(text)
        reler.apply_section_relocations(f, addresses, text, rel)

        textu = e.get_section_by_name(".text.unlikely")
        rel = reler.find_relocations_for_section(textu)
        reler.apply_section_relocations(f, addresses, textu, rel)

        # one way to find the functions we want is to find the call sites of the
        #  kernel APIs they use. In order to be relocated properly, the module will have
        #  to reference the symbol names they want to import. We can trace these
        #  relocations back to the `call`` instruction they are adjusting.
        proc_create_reloc = relocation_for_symbol(e, trela, "proc_create")
        print("proc_create reloc", proc_create_reloc)
        func, func_offset = find_continaing_function(
            e, trela, proc_create_reloc["r_offset"]
        )
        print("func", func.name, func.entry, func_offset)
        init_text = read_symbol(f, text, func)

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
        print(fops_loading_insn)
        if fops_loading_insn.insn_name() != "mov":
            raise AssertionError()
        if len(fops_loading_insn.operands) != 2:
            raise AssertionError()
        _, fops_operand = fops_loading_insn.operands
        if fops_operand.type != CS_OP_IMM:
            raise AssertionError()
        fops_addr = fops_operand.imm
        print("fops addr", hex(fops_addr))

        unlocked_ioctl_offset = 0x50
        f.seek(addr_to_offset(fops_addr) + unlocked_ioctl_offset)
        ioctl_addr = e.structs.Elf_word64("").parse_stream(f)
        print("ioctl addr:", hex(ioctl_addr))

        md = Cs(CS_ARCH_X86, CS_MODE_64)
        # detail needed to populate insn.operands
        md.detail = True
        f.seek(addr_to_offset(ioctl_addr))
        ioctl_code = f.read(256)
        ctx = simple_emu.Context.new()
        insn_gen = md.disasm(ioctl_code, ioctl_addr)
        while True:
            try:
                insn = next(insn_gen)
            except StopIteration as e:
                raise AssertionError("didn't find ioctl opcode cmp instruction") from e
            simple_emu.emulate(ctx, insn)
            if insn.id == X86_INS_CMP and any(
                i.type == X86_OP_IMM and i.imm == 0x539 for i in insn.operands
            ):
                break
        insn = next(insn_gen)
        print(insn)
        simple_emu.emulate(ctx, insn)
        if insn.id != X86_INS_JE:
            raise AssertionError()
        # jmp always has one operand
        ioctl_part2_op, = insn.operands
        if ioctl_part2_op.type != X86_OP_IMM:
            raise AssertionError()
        # as long as we set the disassembly base address correctly, capstone will do
        #  the relative jump calculation for us (ins addr + ins size + rel value)
        ioctl_part2_addr = ioctl_part2_op.imm
        print("ioctl_part2_addr", hex(ioctl_part2_addr))
        
        f.seek(addr_to_offset(ioctl_part2_addr))
        gen = md.disasm(f.read(256), ioctl_part2_addr)
        while True:
            try:
                insn = next(gen)
            except StopIteration as e:
                raise AssertionError("didn't find interpreter loop end comparison") from e
            simple_emu.emulate(ctx, insn)
            # the following block searches for this instruction:
            # cmp byte ptr [rsp + <ip_rsp_off>], 0xff
            if insn.id == X86_INS_CMP:
                # cmp always has two operands
                a, b = insn.operands
                # we are going to make these checks pretty strict, at the risk of
                #  being broken by changes in optimizations from level to level.
                # order of a, b will always be the same due to instruction encoding.
                if (
                    a.type == X86_OP_MEM 
                    and a.size == 1 # operand size 1 byte => byte ptr
                    and a.mem.base == X86_REG_RSP
                    and b.type == X86_OP_IMM
                    and b.imm == 0xff
                ):
                    break
        ip_rsp_off = a.mem.disp
        print("ip rsp off", hex(ip_rsp_off))
        loop_end_addr = insn.address
        jne = next(gen)
        if jne.id != X86_INS_JNE:
            raise AssertionError()
        jne_op = jne.operands[0]
        if jne_op.type != X86_OP_IMM:
            raise AssertionError()
        loop_start_addr = jne_op.value.imm

        print("loop start", hex(loop_start_addr))
        print("loop end", hex(loop_end_addr))
        f.seek(addr_to_offset(ioctl_part2_addr))
        #ctx = simple_emu.Context.new()
        gen = md.disasm(f.read(loop_end_addr - ioctl_part2_addr), ioctl_part2_addr)
        # find the last call instruction within the loop
        call_interp_insn = None
        for insn in gen:
            simple_emu.emulate(ctx, insn)
            if insn.address >= loop_start_addr and insn.id == X86_INS_CALL:
                call_interp_insn = insn
        print(call_interp_insn)
        from pprint import pprint
        for reg, val in ctx.regs.items():
            print(f"{md.reg_name(reg)}:", val)
        return

        op, = call_interp_insn.operands
        if op.type != CS_OP_IMM:
            raise AssertionError()
        interp_insn_addr = op.imm
        print("interpret_instruction@", hex(interp_insn_addr))
        f.seek(addr_to_offset(interp_insn_addr))
        gen = md.disasm(f.read(256), interp_insn_addr)
        ctx = simple_emu.Context.new_branches()
        # void interpret_instruction(vmstate_t *state, instruction_t ins)
        ctx.regs[calling_convention[1]] = PackedIns()
        count = 0
        for insn in gen:
            if insn.op_str == "byte ptr [rdi + 0x10e], r10b":
                print(ctx.stack_locals)
                #break
            simple_emu.emulate(ctx, insn)
            #if insn.op_str == "ecx, ah":
            #    break
            #if insn.id == X86_INS_JS:
            #    break
            if insn.id in {X86_INS_JNE, X86_INS_JE, X86_INS_JS}:
                count += 1
                if count == 9:
                    pass
                    break
            if insn.id == X86_INS_RET:
                break
        
        for reg, val in ctx.regs.items():
            reg == X86_REG_R10 and print(f"{md.reg_name(reg)}:", val)

        from pprint import pprint
        print("SF", ctx.flags["SF"])
        print("ZF", ctx.flags["ZF"])
        pprint(ctx.branches)
        return

        f.seek(addr_to_offset(loop_start_addr))
        gen = md.disasm(f.read(call_interp_insn.address - loop_start_addr), loop_start_addr)
        # now, emulate from the start of the loop until just before the call instruction
        ctx = simple_emu.Context.new()
        mem_rsp_off = None

        def simplification_rule_ipref(val):
            # attempt to match this structure:
            # Add(
            #    left=Scale(val=Local(rsp_off=277), scale=3), # <- ip*3 = ins byte offset
            #    right=Local(rsp_off=264) # <- state.memory
            # )
            if not isinstance(val, simple_emu.Add):
                return val
            if not isinstance(val.left, simple_emu.Scale):
                return val
            if not isinstance(val.right, simple_emu.Local):
                return val
            scale, mem_local = val.left, val.right
            if scale.scale != 3:
                return val    
            if not isinstance(scale.val, simple_emu.Local):
                return val
            ip_local = scale.val
            if ip_local.rsp_off != ip_rsp_off:
                return val
            nonlocal mem_rsp_off
            if mem_rsp_off is None:
                mem_rsp_off = mem_local.rsp_off
            else:
                if mem_local.rsp_off != mem_rsp_off:
                    raise AssertionError()
            return InsAddr()

        ctx.simplification_rules = [simplification_rule_ipref]
        for insn in gen:
            simple_emu.emulate(ctx, insn)
        # void interpret_instruction(vmstate_t *state, instruction_t ins)
        ins_emu_val = ctx.regs[calling_convention[1]]
        print(ctx.stack_locals)
        print(ins_emu_val)
        if not isinstance(ins_emu_val, simple_emu.Or):
            raise AssertionError()
        
        return


if __name__ == "__main__":
    main()
