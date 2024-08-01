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
from simple_emu import InsnFinder, imm_operand
import sixth_gear


def read_symbol(f, section, sym):
    """
    Given a `section` and a symbol `sym` assumed to be in it, return the byte contents
    of that symbol.
    """
    location = section["sh_offset"] + sym["st_value"]
    print("seek to", hex(location))
    f.seek(location)
    return sixth_gear.read_exact(f, sym["st_size"])


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
    elf = sixth_gear.ELF.read_from_path(sys.argv[1])
    f = elf.fh
    e = elf.elf

    # kernel modules don't request particular memory offsets. they must be PIE as
    #  they have to be loaded into kernel address space.
    # This means that when we mimic performing relocations, we can pick whatever
    #  virtual addresses we want.
    # Let's pick a scheme that will match the ghidra listing view.
    # Make base match the start of the first section.
    reloc_scheme = sixth_gear.RelocationScheme.from_ghidra(elf)

    reloc_scheme.relocate(elf.section(".gnu.linkonce.this_module"))
    reloc_scheme.relocate(elf.section(".text"))
    reloc_scheme.relocate(elf.section(".text.unlikely"))
    reloc_scheme.relocate(elf.section(".data"))

    text = elf.section(".text")
    trela = elf.relocations_for(text)

    # one way to find the functions we want is to find the call sites of the
    #  kernel APIs they use. In order to be relocated properly, the module will have
    #  to reference the symbol names they want to import. We can trace these
    #  relocations back to the `call`` instruction they are adjusting.
    proc_create_reloc = trela.relocation_referencing("proc_create")
    print("proc_create reloc", proc_create_reloc)
    func, func_offset = proc_create_reloc.find_continaing_function()
    print("func", func.name, func.entry, func_offset)
    init_text = func.read_exact()

    # struct proc_dir_entry *proc_create(
    #   const char *name, // arg 0
    #   umode_t mode, // arg 1
    #   struct proc_dir_entry *parent, // arg 2
    #   const struct file_operations *proc_fops // arg 3
    # );
    # ...so proc_fops is calling_convention[3]
    *_, fops_loading_insn = (
        insn
        for insn in elf.disasm_text(init_text[:func_offset])
        if simple_emu.modifies_reg(insn, calling_convention[3])
    )
    print(fops_loading_insn)
    fops_addr = InsnFinder(X86_INS_MOV).take_imm(1, fops_loading_insn)
    print("fops addr", hex(fops_addr))

    unlocked_ioctl_offset = 0x50
    reloc_scheme.seek_addr(fops_addr + unlocked_ioctl_offset)
    ioctl_addr = elf.read_word64()
    print("ioctl addr:", hex(ioctl_addr))

    ctx = simple_emu.Context.new()
    insn_gen = reloc_scheme.disasm_addr(ioctl_addr, 256)
    ctx.search_insn(
        "ioctl opcode cmp",
        InsnFinder(X86_INS_CMP).with_any_operand(imm_operand(0x539)),
        insn_gen
    )
    ioctl_part2_addr = InsnFinder(X86_INS_JE).take_imm(0, ctx.emulate_next(insn_gen))
    print("ioctl_part2_addr", hex(ioctl_part2_addr))

    gen = reloc_scheme.disasm_addr(ioctl_part2_addr, 256)
    while True:
        try:
            insn = next(gen)
        except StopIteration as e:
            raise AssertionError("didn't find interpreter loop end comparison") from e
        ctx.emulate(insn)
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
                and a.size == 1  # operand size 1 byte => byte ptr
                and a.mem.base == X86_REG_RSP
                and b.type == X86_OP_IMM
                and b.imm == 0xFF
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
    # ctx = simple_emu.Context.new()
    gen = reloc_scheme.disasm_addr(ioctl_part2_addr, loop_end_addr - ioctl_part2_addr)
    # find the last call instruction within the loop
    call_interp_insn = None
    for insn in gen:
        ctx.emulate(insn)
        if insn.address >= loop_start_addr and insn.id == X86_INS_CALL:
            call_interp_insn = insn
    print("call_interp_insn", call_interp_insn)
    # from pprint import pprint
    # for reg, val in ctx.regs.items():
    #    print(f"{md.reg_name(reg)}:", val)
    return

    (op,) = call_interp_insn.operands
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
            # break
        simple_emu.emulate(ctx, insn)
        # if insn.op_str == "ecx, ah":
        #    break
        # if insn.id == X86_INS_JS:
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
