// printf()
#include <stdio.h>
// malloc()
#include <stdlib.h>

//#include "MCRegisterInfo.h"
// actually, the DiffListIterator stuff is private, so include the source.
#include "MCRegisterInfo.c"

// Needed for x86_init
#define GET_REGINFO_ENUM
#include "arch/X86/X86GenRegisterInfo.inc"
#define GET_REGINFO_MC_DESC
#include "arch/X86/X86GenRegisterInfo.inc"

// define intel variation getRegisterName()
#include "arch/X86/X86GenRegisterName1.inc"

// define regsize_map_64
//#include "arch/X86/X86Mapping.h"
/*
<arch/X86/X86Mapping.c awk '
  BEGIN { in_struct=0; }
  /^const uint8_t regsize_map_64 \[\] = {/ { in_struct=1; }
  /^}/ && in_struct { print; in_struct=0; }
  in_struct == 1 { print; }
' > ~/regsize.c
*/
#include "regsize.c"

// map internal register id to public register id
#include "include/capstone/x86.h"
static const struct register_map {
	unsigned short		id;
	unsigned short		pub_id;
} reg_map [] = {
	// first dummy map
	{ 0, 0 },
#include "arch/X86/X86MappingReg.inc"
};

// return 0 on invalid input, or public register ID otherwise
// NOTE: reg_map is sorted in order of internal register
#include "utils.h"
unsigned short X86_register_map(unsigned short id)
{
	if (id < ARR_SIZE(reg_map))
		return reg_map[id].pub_id;

	return 0;
}


// modified from arch/X86/X86Disassembler.c (to avoid linking unnecessary things)
//  to use variable names from X86Mapping.c
void X86_init(MCRegisterInfo *MRI)
{
	// InitMCRegisterInfo(), X86GenRegisterInfo.inc
	// RI->InitMCRegisterInfo(X86RegDesc, 277,
	//                        RA, PC,
	//                        X86MCRegisterClasses, 86,
	//                        X86RegUnitRoots, 162, X86RegDiffLists, X86LaneMaskLists, X86RegStrings,
	//                        X86RegClassStrings,
	//                        X86SubRegIdxLists, 9,
	//                        X86SubRegIdxRanges, X86RegEncodingTable);
	/*
	   InitMCRegisterInfo(X86RegDesc, 234,
	   RA, PC,
	   X86MCRegisterClasses, 79,
	   X86RegUnitRoots, 119, X86RegDiffLists, X86RegStrings,
	   X86SubRegIdxLists, 7,
	   X86SubRegIdxRanges, X86RegEncodingTable);
	*/

	MCRegisterInfo_InitMCRegisterInfo(MRI, X86RegDesc, 277,
			0, 0,
			X86MCRegisterClasses, 86,
			0, 0, X86RegDiffLists, 0,
			X86SubRegIdxLists, 9,
			0);
}

int main(void) {
    MCRegisterInfo *mri;
    mri = malloc(sizeof(*mri));
    X86_init(mri);
    const MCRegisterClass *gr64_cls = MCRegisterInfo_getRegClass(mri, X86_GR64RegClassID);

	puts("from dataclasses import dataclass");
	puts("");
	puts("");
	puts("@dataclass");
	puts("class Reg:");
	puts("  id: int");
	puts("  size: int");
	puts("");
	puts("");

    printf("SUBREGS = {\n");
    DiffListIterator iter;
    const uint16_t *SRI;
    for (int reg = 1; reg < mri->NumRegs; reg++) {
		if ()
        if (!MCRegisterClass_contains(gr64_cls, reg)) continue;
        
		unsigned reg_pub = X86_register_map(reg);
        printf("  %d: [ # %s\n", reg_pub, getRegisterName(reg));
        SRI = mri->SubRegIndices + mri->Desc[reg].SubRegIndices;
        DiffListIterator_init(
			&iter, (MCPhysReg) reg, mri->DiffLists + mri->Desc[reg].SubRegs
		);
        DiffListIterator_next(&iter);

        while(DiffListIterator_isValid(&iter)) {
             unsigned subreg = DiffListIterator_getVal(&iter);
             unsigned subreg_pub = X86_register_map(subreg);
             printf(
				"    Reg(%d, %d), # %s\n", 
				subreg_pub, 
				regsize_map_64[subreg_pub], 
				getRegisterName(subreg)
			);

             ++SRI;
             DiffListIterator_next(&iter);
        }
        printf("  ],\n");
    }

    printf("}\n");
    return 0;
}
