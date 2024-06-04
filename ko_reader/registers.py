from dataclasses import dataclass


@dataclass
class Reg:
  id: int
  size: int


SUBREGS = {
  35: [ # rax
    Reg(19, 4), # eax
    Reg(3, 2), # ax
    Reg(2, 1), # al
    Reg(1, 1), # ah
    Reg(0, 0), # HAX
  ],
  36: [ # rbp
    Reg(20, 4), # ebp
    Reg(6, 2), # bp
    Reg(7, 1), # bpl
    Reg(0, 0), # BPH
    Reg(0, 0), # HBP
  ],
  37: [ # rbx
    Reg(21, 4), # ebx
    Reg(8, 2), # bx
    Reg(5, 1), # bl
    Reg(4, 1), # bh
    Reg(0, 0), # HBX
  ],
  38: [ # rcx
    Reg(22, 4), # ecx
    Reg(12, 2), # cx
    Reg(10, 1), # cl
    Reg(9, 1), # ch
    Reg(0, 0), # HCX
  ],
  39: [ # rdi
    Reg(23, 4), # edi
    Reg(14, 2), # di
    Reg(15, 1), # dil
    Reg(0, 0), # DIH
    Reg(0, 0), # HDI
  ],
  40: [ # rdx
    Reg(24, 4), # edx
    Reg(18, 2), # dx
    Reg(16, 1), # dl
    Reg(13, 1), # dh
    Reg(0, 0), # HDX
  ],
  41: [ # rip
    Reg(26, 4), # eip
    Reg(34, 2), # ip
    Reg(0, 0), # HIP
  ],
  43: [ # rsi
    Reg(29, 4), # esi
    Reg(45, 2), # si
    Reg(46, 1), # sil
    Reg(0, 0), # SIH
    Reg(0, 0), # HSI
  ],
  44: [ # rsp
    Reg(30, 4), # esp
    Reg(47, 2), # sp
    Reg(48, 1), # spl
    Reg(0, 0), # SPH
    Reg(0, 0), # HSP
  ],
  106: [ # r8
    Reg(226, 4), # r8d
    Reg(234, 2), # r8w
    Reg(218, 1), # r8b
    Reg(0, 0), # R8BH
    Reg(0, 0), # R8WH
  ],
  107: [ # r9
    Reg(227, 4), # r9d
    Reg(235, 2), # r9w
    Reg(219, 1), # r9b
    Reg(0, 0), # R9BH
    Reg(0, 0), # R9WH
  ],
  108: [ # r10
    Reg(228, 4), # r10d
    Reg(236, 2), # r10w
    Reg(220, 1), # r10b
    Reg(0, 0), # R10BH
    Reg(0, 0), # R10WH
  ],
  109: [ # r11
    Reg(229, 4), # r11d
    Reg(237, 2), # r11w
    Reg(221, 1), # r11b
    Reg(0, 0), # R11BH
    Reg(0, 0), # R11WH
  ],
  110: [ # r12
    Reg(230, 4), # r12d
    Reg(238, 2), # r12w
    Reg(222, 1), # r12b
    Reg(0, 0), # R12BH
    Reg(0, 0), # R12WH
  ],
  111: [ # r13
    Reg(231, 4), # r13d
    Reg(239, 2), # r13w
    Reg(223, 1), # r13b
    Reg(0, 0), # R13BH
    Reg(0, 0), # R13WH
  ],
  112: [ # r14
    Reg(232, 4), # r14d
    Reg(240, 2), # r14w
    Reg(224, 1), # r14b
    Reg(0, 0), # R14BH
    Reg(0, 0), # R14WH
  ],
  113: [ # r15
    Reg(233, 4), # r15d
    Reg(241, 2), # r15w
    Reg(225, 1), # r15b
    Reg(0, 0), # R15BH
    Reg(0, 0), # R15WH
  ],
}
