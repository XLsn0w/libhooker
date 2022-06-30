#include "interface/cpu/cpu_intel.h"
#include "interface/if_inject.h"

inline int inj_trap_bytes(){
	return 1;
}

int inj_build_trap(uint8_t *buffer){
	buffer[0] = 0xCC; //int 3
	return LH_SUCCESS;
}

//int inj_relocate_cmp(uint8_t *)

inline int inj_trap(pid_t pid, struct user *iregs) {
	LH_VERBOSE(3, "Copying Null to stack.");
	return inj_pokedata(pid, lh_rget_sp(iregs), (uintptr_t)NULL);
}

/*
 * Relocates code pointed by codePtr from sourcePC to destPC
 */
int inj_relocate_code(uint8_t *codePtr, size_t codeSz, uintptr_t sourcePC, uintptr_t destPC){
	csh handle;
	cs_insn *insns;
	size_t count;
	int result = LH_SUCCESS;

	char pcRegName[4];
	#if __i386__
		strcpy((char *)&pcRegName, "eip");
		if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK)
			goto err_open;
	#elif __x86_64__
		strcpy((char *)&pcRegName, "rip");
		if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
			goto err_open;
	#endif

	//Enable optional details
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

	size_t i, j;

	count = cs_disasm(handle, codePtr, codeSz, sourcePC, 0, &insns);
	if(count < 0)
		goto err_disasm;

	off_t curPos = 0;
	for (i = 0; i < count; i++) {
		cs_insn *insn = &(insns[i]);
		printf("0x"LLX":\t%s\t\t%s\n", insn->address, insn->mnemonic, insn->op_str);
		cs_detail *detail = insn->detail;

		for(j=0; j<detail->x86.op_count; j++){
			cs_x86_op *op = &(detail->x86.operands[j]);
			switch(op->type) {
				case X86_OP_FP:
					printf("\t\toperands["LU"].type: FP = %f\n", j, op->fp);
					break;
				case X86_OP_REG:
					printf("\t\toperands["LU"].type: REG = %s\n", j, cs_reg_name(handle, op->reg));
					break;
				case X86_OP_MEM:
					printf("\t\toperands["LU"].type: MEM\n", j);
					if (op->mem.base != X86_REG_INVALID){
						const char *reg_name = cs_reg_name(handle, op->mem.base);
						printf("\t\t\toperands["LU"].mem.base: REG = %s\n", j, reg_name);
						if(!strcmp(reg_name, (char *)&pcRegName)){
							//apparently works for cmp, lea, anything mem relative hopefully
							//if(!strcmp(insn->mnemonic, "cmp")){
								uint displacement = (sourcePC + insn->size) - destPC;
								if(lh_verbose >= 3){
									LH_VERBOSE(3, ">> New Displacement: "LX"", displacement);
									lh_hexdump("instruction before", insn->bytes, insn->size);
								}
								printf(">> Relocating RELATIVE CMP MEM ACCESS...\n");
								*(uint *)(codePtr + curPos + 3) = displacement & 0xFFFFFFFFFF;
								if(lh_verbose >= 3){
									lh_hexdump("instruction after", codePtr + curPos, insn->size);
								}
							//}
						}
					}
					if (op->mem.index != X86_REG_INVALID){
						printf("\t\t\toperands["LU"].mem.index: REG = %s\n", j, cs_reg_name(handle, op->mem.index));
					}
					if (op->mem.disp != 0){
						printf("\t\t\toperands["LU"].mem.disp: 0x"LLX"\n", j, op->mem.disp);
					}
					break;
				case X86_OP_IMM:
					printf("\t\toperands["LU"].type: IMM = 0x"LLX"\n", j, op->imm);
					break;
				case X86_OP_INVALID:
				default:
					break;
			}
		}

		curPos += insn->size;
	}
	goto ret;
	ret:
		cs_free(insns, count);
		return result;

	err_open:
		LH_ERROR("cs_open failed!");
		return -1;
	err_disasm:
		LH_ERROR("cs_disasm failed!");
		cs_close(&handle);
		return -1;
}
