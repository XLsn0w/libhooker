#include "interface/if_cpu.h"
#include "interface/if_inject.h"

//-------------------------------------------- i386 begin
inline int inj_opcode_bytes(){
	return -1;
}

inline int inj_reljmp_opcode_bytes() {
	return 5;
}

inline int inj_absjmp_opcode_bytes() {
	return 5 + 1;
}

int inj_build_rel_jump(uint8_t *buffer, uintptr_t jump_destination, uintptr_t source) {
	uintptr_t operand = jump_destination - source - 5;

	LH_VERBOSE(4, "REL JUMP (X64) TO " LX " FROM " LX " IS: " LX, jump_destination, source, operand);

	uint32_t lo = (uint32_t) (operand);

	buffer[0] = 0xE9;
	uint32_t *x = (uint32_t *) & (buffer[1]);
	*x = lo;
// 0:   e9 44 33 22 11          jmpq   0x11223349

	return LH_SUCCESS;
}

int inj_build_abs_jump(uint8_t *buffer, uintptr_t jump_destination, uintptr_t source) {
	uint32_t lo = (uint32_t) jump_destination;

	int i = 0;
	buffer[i++] = 0x68;
	uint32_t *x = (uint32_t *) & (buffer[i]);
	*x = lo;
	i += sizeof(uint32_t);
// 0: 68 44 33 22 11    push $11223344

	buffer[i++] = 0xC3;
//5: c3                retq

	return LH_SUCCESS;
}

int inj_pass_args2func(pid_t pid, struct user *iregs, uintptr_t fn, uintptr_t arg1, uintptr_t arg2) {
	int rc;

	LH_VERBOSE(3, "function address is: 0x" LX, fn);
	LH_VERBOSE(3, "Stack Pointer is: 0x" LX "\n", lh_rget_sp(iregs));

	LH_VERBOSE(3, "Copying Arg 1 to stack.");
	if ((rc = inj_pokedata(pid, lh_rget_sp(iregs) + sizeof(uintptr_t), arg1)) != LH_SUCCESS)
		return rc;
	LH_VERBOSE(3, "Copying Arg 2 to stack.");
	if ((rc = inj_pokedata(pid, lh_rget_sp(iregs) + 2 * sizeof(uintptr_t), arg2)) != LH_SUCCESS)
		return rc;

	lh_rset_ip(iregs, fn);
	lh_rset_ax(iregs, 0);

        return LH_SUCCESS;
}

inline void lh_rset_ip(struct user *r, uintptr_t value) {
	r->regs.eip = value;
}

inline uintptr_t lh_rget_ip(struct user *r) {
	return r->regs.eip;
}

inline void lh_rset_sp(struct user *r, uintptr_t value) {
	r->regs.esp = value;
}

inline uintptr_t lh_rget_sp(struct user *r) {
	return r->regs.esp;
}

inline void lh_rset_fp(struct user *r, uintptr_t value) {
	r->regs.ebp = value;
}

inline uintptr_t lh_rget_fp(struct user *r) {
	return r->regs.ebp;
}

inline void lh_rset_ax(struct user *r, uintptr_t value) {
	r->regs.eax = value;
}

inline uintptr_t lh_rget_ax(struct user *r) {
	return r->regs.eax;
}

inline int lh_redzone() {
	return 0;
}

void lh_dump_regs(struct user *r) {
	LH_VERBOSE(3, "--------------------------- i386");
	LH_VERBOSE(3, "%%eip : 0x" LX, r->regs.eip);
	LH_VERBOSE(3, "%%eax : 0x" LX, r->regs.eax);
	LH_VERBOSE(3, "%%ebx : 0x" LX, r->regs.ebx);
	LH_VERBOSE(3, "%%ecx : 0x" LX, r->regs.ecx);
	LH_VERBOSE(3, "%%edx : 0x" LX, r->regs.edx);
	LH_VERBOSE(3, "%%esi : 0x" LX, r->regs.esi);
	LH_VERBOSE(3, "%%edi : 0x" LX, r->regs.edi);
	LH_VERBOSE(3, "%%ebp : 0x" LX, r->regs.ebp);
	LH_VERBOSE(3, "%%oeax: 0x" LX, r->regs.orig_eax);
	LH_VERBOSE(3, "%%esp : 0x" LX, r->regs.esp);
}
//-------------------------------------------- i386 end
