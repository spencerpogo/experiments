from dataclasses import dataclass
from enum import Enum, auto
from typing import Dict, List, Callable, Optional, Tuple

from capstone import *
from capstone.x86 import *
import capstone.x86 as cs_x86

from registers import Reg, SUBREGS


reg_sizes = {reg: 8 for reg in SUBREGS.keys()}
subreg_to_super = {}
for supreg, subregs in SUBREGS.items():
    subreg_to_super[supreg] = supreg
    for subreg in subregs:
        if subreg.size == 0:
            continue
        subreg_to_super[subreg.id] = supreg
        reg_sizes[subreg.id] = subreg.size


class FlagActionOperation(Enum):
    UNDEFINED = auto()
    SET = auto()
    MODIFY = auto()
    PRIOR = auto()
    TEST = auto()
    RESET = auto()


@dataclass(frozen=True)
class FlagAction:
    op: FlagActionOperation
    flag: str


eflags_values = {}
flags = set()
for attr in dir(cs_x86):
    _, delim, rest = attr.partition("X86_EFLAGS_")
    if not delim:
        continue
    val = getattr(cs_x86, attr)
    action, flag = rest.split("_")
    flags.add(flag)
    eflags_values[val] = FlagAction(op=FlagActionOperation[action], flag=flag)

# this flag can only be reset, wtf...
flags.difference_update({"0F"})


class EmuValue:
    pass


@dataclass(frozen=True)
class RegInitialValue(EmuValue):
    reg: int

    def __repr__(self):
        name = Cs(CS_ARCH_X86, CS_MODE_64).reg_name(self.reg)
        if name is not None:
            return f"{self.__class__.__name__}.{name}"
        return f"{self.__class__.__name__}({self.reg})"


@dataclass(frozen=True)
class Unk:
    pass


@dataclass(frozen=True)
class Const(EmuValue):
    val: int


@dataclass(frozen=True)
class SegmentRef(EmuValue):
    segment: int
    offset: int

    def __repr__(self):
        return f"{self.__class__.__name__}({self.segment}, {hex(self.offset)})"


@dataclass(frozen=True)
class Add(EmuValue):
    left: EmuValue
    right: EmuValue


@dataclass(frozen=True)
class Sub(EmuValue):
    left: EmuValue
    right: EmuValue


@dataclass(frozen=True)
class Scale(EmuValue):
    val: EmuValue
    scale: int


@dataclass(frozen=True)
class Ldm(EmuValue):
    addr: EmuValue
    size: int


@dataclass(frozen=True)
class Shl(EmuValue):
    val: EmuValue
    amt: int


@dataclass(frozen=True)
class Shr(EmuValue):
    val: EmuValue
    amt: int


@dataclass(frozen=True)
class Or(EmuValue):
    lhs: EmuValue
    rhs: EmuValue


@dataclass(frozen=True)
class And(EmuValue):
    lhs: EmuValue
    rhs: EmuValue


def mask_for_size(size_bytes):
    return (1 << (size_bytes * 8)) - 1


@dataclass(frozen=True)
class ConstAnd(EmuValue):
    val: EmuValue
    mask: int

    @classmethod
    def with_size(cls, val, size_bytes):
        return cls(val=val, mask=mask_for_size(size_bytes))
    
    def __repr__(self):
        return f"{self.__class__.__name__}({self.val!r}, {hex(self.mask)})"


@dataclass(frozen=True)
class Local(EmuValue):
    rsp_off: int
    size: int


@dataclass(frozen=True)
class StoredLocal(EmuValue):
    val: EmuValue
    size: int


class FlagValue:
    pass


@dataclass(frozen=True)
class FlagInitial(FlagValue):
    pass


@dataclass(frozen=True)
class FlagUndefined(FlagValue):
    pass


@dataclass(frozen=True)
class FlagSet(FlagValue):
    pass


@dataclass(frozen=True)
class FlagReset(FlagValue):
    pass


@dataclass(frozen=True)
class IsNonZero(FlagValue):
    val: EmuValue

    def __repr__(self):
        return f"{self.__class__.__name__}({self.val!r})"


@dataclass(frozen=True)
class Not(FlagValue):
    val: FlagValue

    def __repr__(self):
        return f"{self.__class__.__name__}({self.val!r})"


@dataclass(frozen=True)
class FlagUnknownModification(FlagValue):
    insn: CsInsn


@dataclass(frozen=True)
class Branch:
    insn: CsInsn
    cond: FlagValue
    location: int

    def __repr__(self):
        return (
            f"{self.__class__.__name__}(" + 
                f"{self.insn!r}, {self.cond!r}, {hex(self.location)}" + 
            ")"
        )


def setup_regs():
    return {reg: RegInitialValue(reg) for reg in SUBREGS.keys()}
    #return {reg: Unk() for reg in SUBREGS.keys()}


def setup_flags():
    return {flag: FlagInitial() for flag in flags}


def simplify(ctx, val):
    if isinstance(val, Add):
        if isinstance(val.left, Scale) and val.left.val == val.right:
            val = Scale(val.left.val, val.left.scale + 1)
        elif isinstance(val.right, Scale) and val.left == val.right.val:
            val = Scale(val.right.val, val.right.scale + 1)
        else:
            val = Add(simplify(ctx, val.left), simplify(ctx, val.right))
    if isinstance(val, Scale):
        val = Scale(val=simplify(ctx, val.val), scale=val.scale)
    if isinstance(val, Ldm) and isinstance(val.addr, Add):
        if (
            val.addr.left == RegInitialValue(X86_REG_RSP)
            and isinstance(val.addr.right, Const)
        ):
            val = Local(val.addr.right.val, size=val.size)
    if isinstance(val, ConstAnd) and isinstance(val.val, ConstAnd):
        outer = val
        inner = val.val
        val = ConstAnd(val=inner.val, mask=outer.mask & inner.mask)
    if (
        isinstance(val, ConstAnd)
        and isinstance(val.val, Shr)
        and isinstance(val.val.val, ConstAnd)
    ):
        outer_and = val
        shr = outer_and.val
        inner_and = shr.val
        val = ConstAnd(inner_and.val, mask=inner_and.mask & (outer_and.mask << shr.amt))
        val = Shr(val, shr.amt)
    if isinstance(val, ConstAnd) and isinstance(val.val, Ldm):
        andop, ldm = val, val.val
        # if we are masking out the exact amount of data we load, the mask is
        #  irrelevant.
        if andop.mask == (1 << (ldm.size * 8)) - 1:
            return val.val
    
    if isinstance(val, IsNonZero):
        val = IsNonZero(simplify(ctx, val.val))
        # shifting has no effect on whether the value is non-zero
        while isinstance(val.val, Shr):
            shr = val.val
            val = IsNonZero(shr.val)
    
    for rule in ctx.simplification_rules:
        val = rule(val)
    return val


def read_reg(ctx, reg):
    phys = subreg_to_super[reg]
    phys_val = ctx.regs[phys]
    if reg in {X86_REG_AH, X86_REG_BH, X86_REG_CH, X86_REG_DH}:
        # need to shift the mask left then shift the value right
        mask = mask_for_size(1) << 8
        val = ConstAnd(val=phys_val, mask=mask)
        val = Shr(val, amt=8)
        return simplify(ctx, val)
    size = reg_sizes[reg]
    if size == 4 or size == 8:
        return phys_val
    if size in {1, 2}:
        return simplify(ctx, ConstAnd.with_size(phys_val, size))
    raise AssertionError(size)


def write_reg(ctx, reg, new_val):
    phys = subreg_to_super[reg]
    stored_val = ctx.regs[phys]
    size = reg_sizes[reg]
    if size == 4 or size == 8:
        ctx.regs[phys] = new_val
        return
    full_mask = (1 << 64) - 1
    if size in set():
        mask = (1 << (size * 8)) - 1
        v = Or(ConstAnd(stored_val, full_mask ^ mask), ConstAnd(new_val, mask))
        ctx.regs[phys] = simplify(ctx, v)
        return
    raise AssertionError(size)


def lea_mem_ref(ctx, op):
    # (scale * index) + base + displacement
    # -- https://en.wikipedia.org/wiki/ModR/M
    #print(f"scale={op.scale} index={op.index} base={op.base} disp={op.disp}")
    v = None
    if op.index != 0:
        v = read_reg(ctx, op.index)
        if op.scale != 1:
            v = Scale(v, op.scale)
    elif op.scale != 1:
        raise NotImplementedError("nonzero scale")

    if op.base != 0:
        r = read_reg(ctx, op.base)
        if v is None:
            v = r
        else:
            v = Add(v, r)
    
    if op.segment != 0:
        if v is not None:
            raise AssertionError("multiple bases")
        if op.scale != 1:
            raise AssertionError()
        v = SegmentRef(op.segment, op.disp)
    elif op.disp != 0:
        v = Add(v, Const(op.disp))

    if v is None:
        raise AssertionError("unknown memory reference format")
    return simplify(ctx, v)


def try_read_local(ctx, offset, size):
    if offset in ctx.stack_locals:
        v = ctx.stack_locals[offset]
        if v.size == size:
            return v.val
        if size <= v.size:
            return ConstAnd.with_size(v, size)
        raise AssertionError("read goes beyond stored local")
    for i in range(8):
        if (offset - i) in ctx.stack_locals:
            v = ctx.stack_locals[offset - i]
            slice_start = i
            slice_len = v.size - i
            if slice_len < size:
                raise AssertionError("read goes beyond stored local")
            mask_segment = (1 << (slice_len * 8)) - 1
            mask = mask_segment << (slice_start * 8)
            v = ConstAnd(v, mask)
            right_shift_amt = slice_start * 8
            if right_shift_amt != 0:
                v = Shr(v, right_shift_amt)
            return simplify(ctx, v)
    return None
    


def emulate_mov(ctx, insn):
    a, b = insn.operands
    if a.type == CS_OP_REG and b.type == CS_OP_REG:
        write_reg(ctx, a.reg, read_reg(ctx, b.reg))
        return
    if a.type in {CS_OP_MEM, CS_OP_FP} and b.type in {CS_OP_REG, CS_OP_IMM}:
        addr = lea_mem_ref(ctx, a.mem)
        if b.type == CS_OP_REG:
            val = read_reg(ctx, b.reg)
        else:
            val = b.imm
        if (
            isinstance(addr, Add)
            and isinstance(addr.left, RegInitialValue)
            and addr.left.reg == X86_REG_RSP
            and isinstance(addr.right, Const)
        ):
            offset = addr.right.val
            ctx.stack_locals[offset] = StoredLocal(
                val=val, size=a.size
            )
        return
    if a.type == CS_OP_REG and b.type in {CS_OP_MEM, CS_OP_FP}:
        addr = lea_mem_ref(ctx, b.mem)
        v = None
        if (
            isinstance(addr, Add)
            and isinstance(addr.left, RegInitialValue)
            and addr.left.reg == X86_REG_RSP
            and isinstance(addr.right, Const)
        ):
            v = try_read_local(ctx, addr.right.val, b.size)
        if v is None:
            v = Ldm(addr, size=b.size)
        write_reg(ctx, a.reg, simplify(ctx, v))
        return
    if a.type == CS_OP_REG and b.type == CS_OP_IMM:
        write_reg(ctx, a.reg, Const(b.imm))
        return
    raise NotImplementedError(f"unimplemented mov variant: {insn}")


def emulate_lea(ctx, insn):
    a, b = insn.operands

    if a.type == CS_OP_REG and b.type in {CS_OP_MEM, CS_OP_FP}:
        write_reg(ctx, a.reg, lea_mem_ref(ctx, b.mem))
        return
    raise AssertionError(f"unimplemented lea variant: {insn}")


def emulate_add(ctx, insn):
    a, b = insn.operands

    if a.type == CS_OP_REG and b.type in {CS_OP_MEM, CS_OP_FP}:
        lhs = read_reg(ctx, a.reg)
        rhs = Ldm(lea_mem_ref(ctx, b.mem), size=b.size)
        write_reg(ctx, a.reg, simplify(ctx, Add(lhs, rhs)))
        return
    raise AssertionError(f"unimplemented add variant: {insn}")


def emulate_sub(ctx, insn):
    a, b = insn.operands

    if a.type == CS_OP_REG and b.type == CS_OP_IMM:
        lhs = read_reg(ctx, a.reg)
        rhs = Const(b.imm)
        write_reg(ctx, a.reg, simplify(ctx, Sub(lhs, rhs)))
        return
    raise AssertionError(str(insn))


def emulate_shl(ctx, insn):
    a, b = insn.operands

    if a.type == CS_OP_REG and b.type == CS_OP_IMM:
        v = read_reg(ctx, a.reg)
        write_reg(ctx, a.reg, simplify(ctx, Shl(v, b.imm)))
        return
    raise AssertionError()


def emulate_shr(ctx, insn):
    a, b = insn.operands

    if a.type == CS_OP_REG and b.type == CS_OP_IMM:
        v = read_reg(ctx, a.reg)
        write_reg(ctx, a.reg, simplify(ctx, Shr(v, b.imm)))
        return
    raise AssertionError(str(insn))


def emulate_xor(ctx, insn):
    a, b = insn.operands

    if a.type == CS_OP_REG and b.type == CS_OP_REG:
        if a.reg == b.reg:
            write_reg(ctx, a.reg, Const(0))
            return
        # *fallthrough*
    raise AssertionError()


def emulate_or(ctx, insn):
    a, b = insn.operands

    if a.type == CS_OP_REG and b.type == CS_OP_REG:
        v = Or(read_reg(ctx, a.reg), read_reg(ctx, b.reg))
        write_reg(ctx, a.reg, v)
        return
    raise AssertionError()


def _emulate(ctx, insn):
    print(insn)
    if insn.id in {X86_INS_MOV, X86_INS_MOVZX}:
        return emulate_mov(ctx, insn)
    if insn.id == X86_INS_LEA:
        return emulate_lea(ctx, insn)
    if insn.id == X86_INS_ADD:
        return emulate_add(ctx, insn)
    if insn.id == X86_INS_SUB:
        return emulate_sub(ctx, insn)
    if insn.id == X86_INS_SHL:
        return emulate_shl(ctx, insn)
    if insn.id == X86_INS_SHR:
        return emulate_shr(ctx, insn)
    if insn.id == X86_INS_OR:
        return emulate_or(ctx, insn)
    if insn.id == X86_INS_XOR:
        return emulate_xor(ctx, insn)
    
    if insn.id in {
        X86_INS_CALL, X86_INS_TEST, X86_INS_JE, X86_INS_JNE, X86_INS_CMP, X86_INS_JMP,
        X86_INS_JS, X86_INS_PUSH, X86_INS_STOSQ
    }:
        # ignore
        return
    raise AssertionError(f"Cannot handle instruction {insn.mnemonic}: {insn}")


def emulate_test(ctx, insn):
    a, b = insn.operands

    if a.type == CS_OP_REG and b.type == CS_OP_IMM:
        val = read_reg(ctx, a.reg)
        ctx.flags["ZF"] = simplify(ctx, IsNonZero(ConstAnd(val=val, mask=b.imm)))
        insn.eflags ^= X86_EFLAGS_MODIFY_ZF
        return
    #if a.type == CS_OP_MEM and b.type == 
    if a.type == CS_OP_REG and b.type == CS_OP_REG and a.reg == b.reg:
        val = read_reg(ctx, a.reg)
        ctx.flags["ZF"] = simplify(ctx, IsNonZero(val))
        ctx.flags["SF"] = simplify(ctx, IsNonZero(
            simplify(ctx, ConstAnd(val=val, mask=1 << (reg_sizes[a.reg] * 8 - 1)))
        ))
        insn.eflags ^= X86_EFLAGS_MODIFY_ZF
        insn.eflags ^= X86_EFLAGS_MODIFY_SF
        return
    if a.type == CS_OP_MEM and b.type == CS_OP_REG:
        addr = lea_mem_ref(ctx, a.mem)
        v = None
        if (
            isinstance(addr, Add)
            and isinstance(addr.left, RegInitialValue)
            and addr.left.reg == X86_REG_RSP
            and isinstance(addr.right, Const)
        ):
            v = try_read_local(ctx, addr.right.val, b.size)
        if v is None:
            v = Ldm(addr, size=b.size)
        v = simplify(ctx, v)
        right = read_reg(ctx, b.reg)
        ctx.flags["ZF"] = simplify(ctx, IsNonZero(
            simplify(ctx, And(v, right))
        ))
        insn.eflags ^= X86_EFLAGS_MODIFY_ZF
        return
    raise AssertionError(f"Cannot handle instruction {insn.mnemonic}: {insn}")


def emulate_conditional_jmp(ctx, insn):
    loc, = insn.operands

    if insn.id == X86_INS_JNE and loc.type == CS_OP_IMM:
        ctx.branches.append(Branch(insn, simplify(ctx, Not(ctx.flags["ZF"])), loc.imm))
        return
    if insn.id == X86_INS_JE and loc.type == CS_OP_IMM:
        ctx.branches.append(Branch(insn, ctx.flags["ZF"], loc.imm))
        return
    if insn.id == X86_INS_JS and loc.type == CS_OP_IMM:
        ctx.branches.append(Branch(insn, ctx.flags["SF"], loc.imm))
        return
    raise AssertionError(f"Cannot handle instruction {insn.mnemonic}: {insn}")


def process_eflags_val(ctx, insn, flag_val):
    act = eflags_values[flag_val]
    if act.op == FlagActionOperation.PRIOR:
        raise AssertionError(
            "we will eventually ignore this, but until then I am curious what makes " + 
            "this occur"
        )
    if act.op == FlagActionOperation.UNDEFINED:
        ctx.flags[act.flag] = FlagUndefined()
        return
    if act.op == FlagActionOperation.SET:
        ctx.flags[act.flag] = FlagSet()
        return
    if act.op == FlagActionOperation.RESET:
        ctx.flags[act.flag] = FlagReset()
        return
    if act.op in {FlagActionOperation.MODIFY, FlagActionOperation.TEST}:
        ctx.flags[act.flag] = FlagUnknownModification(insn=insn)
        return
    raise AssertionError(f"Unsupported flag operation {act.op}")


@dataclass
class Context:
    regs: Dict[int, EmuValue]
    stack_locals: Dict[int, StoredLocal]
    simplification_rules: List[Callable[[EmuValue], EmuValue]]
    branches: Optional[List[Branch]]
    flags: Optional[Dict[str, FlagAction]]

    @classmethod
    def new(cls):
        return cls(
            regs=setup_regs(), stack_locals={}, simplification_rules=[], branches=None,
            flags=None
        )
    
    @classmethod
    def new_branches(cls):
        return cls(
            regs=setup_regs(), stack_locals={}, simplification_rules=[], branches=[],
            flags=setup_flags()
        )

    def emulate(ctx, insn):
        r = _emulate(ctx, insn)
        if ctx.branches is None:
            return r

        _, regs_written = insn.regs_access()
        if insn.id == X86_INS_TEST:
            emulate_test(ctx, insn)
        if insn.id in {X86_INS_JE, X86_INS_JNE, X86_INS_JS}:
            emulate_conditional_jmp(ctx, insn)

        if X86_REG_EFLAGS in regs_written:
            for i in range(64):
                flag_val = 1 << i
                if insn.eflags & flag_val != 0:
                    process_eflags_val(ctx, insn, flag_val)
        return r

    def emulate_next(ctx, gen):
        insn = next(gen)
        ctx.emulate(insn)
        return insn

    def search_insn(ctx, desc, insn_finder, gen):
        while True:
            try:
                insn = next(gen)
            except StopIteration as e:
                raise AssertionError(f"Did not find {desc}") from e
            ctx.emulate(insn)
            if insn_finder.matches(ctx, insn):
                return insn


def modifies_reg(insn, reg):
    _, regs_written = insn.regs_access()
    return reg in regs_written

def imm_operand(imm_value=None):
    if imm_value is None:
        return lambda op: op.type == CS_OP_IMM
    return lambda op: op.type == CS_OP_IMM and op.imm == imm_value


class InsnFinder:
    __slots__ = ("insn_id", "conds")

    def __init__(self, insn_id):
        self.insn_id = insn_id
        self.conds = []
    
    def with_id(self, insn_id):
        self.conds.append(lambda _ctx, insn: insn.id == insn_id)
        return self
    
    def with_any_operand(self, operand_cond):
        self.conds.append(lambda _ctx, insn: any(map(operand_cond, insn.operands)))
        return self
    
    def with_operand(self, i, operand_cond):
        self.conds.append(lambda _ctx, insn: operand_cond(insn.operands[i]))
        return self
    
    def matches(self, ctx, insn):
        if self.insn_id is not None and insn.id != self.insn_id:
            return False
        return all(cond(ctx, insn) for cond in self.conds)
    
    def take_imm(self, i, insn):
        assert self.matches(None, insn)
        assert insn.operands[i].type == CS_OP_IMM
        return insn.operands[i].imm
    
    def take_src_imm(self, insn):
        return self.take_imm(0, insn)
    
    def take_dst_imm(self, insn):
        return self.take_imm(1, insn)
