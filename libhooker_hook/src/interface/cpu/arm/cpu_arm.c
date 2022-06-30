#include "interface/if_cpu.h"

//----------------------------------------------------- arm begin
inline int inj_opcode_bytes(){
	return 4;
}

/*
inline int inj_trap_bytes(){
	return 4;
}

int inj_build_trap(uint8_t *buffer){
#ifndef __ARM_EABI__
	memcpy(buffer, 0xef9f0001, inj_trap_bytes());
#else
	memcpy(buffer, 0xe7f001f0, inj_trap_bytes());
#endif
	return LH_SUCCESS;
}
*/


/*
int inj_getinsn_count(uint8_t *buf, size_t sz, int *validbytes){
	return sz / inj_opcode_bytes();
}
*/

inline int inj_absjmp_opcode_bytes() {
	return inj_opcode_bytes() * 2;
}

inline int inj_reljmp_opcode_bytes() {
	return inj_opcode_bytes();
}

int inj_build_rel_jump(uint8_t *buffer, uintptr_t jump_destination, uintptr_t jump_opcode_address) {
	if (jump_destination % 4 != 0) {
		LH_ERROR("Destination address is not multiple of 4");
		return -1;
	}
	if (jump_opcode_address % 4 != 0) {
		LH_ERROR("Opcode address is not multiple of 4");
		return -1;
	}

	uint32_t offset = (uint32_t) jump_destination - jump_opcode_address - 4;
	LH_VERBOSE(4, "Offset is: " LX, offset);
	uint32_t operand = (offset / 4) - 1;
	LH_VERBOSE(4, "Operand is: " LX, operand);

/*
// todo: validate this somehow
  if((operand & 0xFF000000) > 0) {
     LH_ERROR("Jump is too big");
     return -1;
  }
*/
	uint32_t *x = (uint32_t *) buffer;
	*x = operand;
	buffer[3] = 0xEA;

	return LH_SUCCESS;
}

//ldr pc, [pc, #-4] => 04 f0 1f e5
int inj_build_abs_jump(uint8_t *buffer, uintptr_t jump_destination, uintptr_t jump_opcode_address) {
	int i = 0;
	buffer[i++] = 0x04;
	buffer[i++] = 0xf0;
	buffer[i++] = 0x1f;
	buffer[i++] = 0xe5;

	uint32_t dest = (uint32_t) jump_destination;
	uint32_t *x = (uint32_t *) & (buffer[i]);
	*x = dest;

	return LH_SUCCESS;
}

/*
inline int inj_reljmp_opcode_bytes() {
  return inj_absjmp_opcode_bytes();
}
int inj_build_rel_jump(uint8_t* buffer, uintptr_t jump_destination, uintptr_t jump_opcode_address)
{
  return inj_build_abs_jump(buffer, jump_destination, jump_opcode_address);
}
// other useful: http://www.davespace.co.uk/arm/introduction-to-arm/addressing.html
// http://stackoverflow.com/questions/6097958/what-does-the-value-associated-with-the-arm-ldr-instruction-mean
// based on: http://www.codepwn.com/posts/assembling-from-scratch-encoding-blx-instruction-in-arm-thumb/
int inj_build_rel_jump(uint8_t* buffer, uintptr_t jump_destination, uintptr_t jump_opcode_address)
{
  LH_VERBOSE(4, "Calculating relative jump "LX" -> "LX, jump_opcode_address, jump_destination);
  uint32_t aligned = (uint32_t) ((jump_opcode_address + 4) & 0xFFFFFFFC); // +4 => opcode address
  LH_VERBOSE(4,"Aligned: "LX, aligned);
  uint32_t offset = (uint32_t) (jump_destination - aligned);
  LH_VERBOSE(4,"Offset: "LX, offset);

  if( (offset & 0x3) > 0) {
    LH_PRINT("ERROR: offset "LX" is not aligned to 4", offset);
    return -1;
  }

  uint32_t thi = (offset & 0xFE000000) >> 25;
  if((thi  != 0)&&(thi != 0x7F))
  {
    LH_PRINT("ERROR: bits 31-25 in offset "LX" are nonzero "LX," ("LX")", offset, thi);
    return -2;
  }

  uint32_t L = (offset >> 2) & 0x3FF;
  LH_VERBOSE(4,"L: "LX, L);
  uint32_t H = (offset >> 12) & 0x3FF;
  LH_VERBOSE(4,"H: "LX, H);

  uint32_t I2 = (offset >> 22) & 0x1;
  uint32_t I1 = (offset >> 23) & 0x1;
  uint32_t S  = (offset >> 24) & 0x1;

  LH_VERBOSE(4,"S: "LX, S);
  LH_VERBOSE(4,"I1: "LX, I1);
  LH_VERBOSE(4,"I2: "LX, I2);

  uint32_t J1 = (~I1 ^ S) & 0x1;
  LH_VERBOSE(4,"J1: "LX, J1);
  uint32_t J2 = (~I2 ^ S) & 0x1;
  LH_VERBOSE(4,"J2: "LX, J2);

  uint32_t raw_op =
     (L << 1)
     |
     (J2 << 11)
     |
     (J1 << 13)
     |
     (0x3 << 14)
     |
     (H << 16)
     |
     (S << 26)
     |
     (0xF << 28)
  ;
  LH_VERBOSE(4, "Raw op: "LX, raw_op);

  uint32_t shuffled =
    ((raw_op >> 16) & 0xFFFF)
    |
    ((raw_op & 0xFFFF) << 16)
  ;

  uint32_t* x = (uint32_t*) buffer;
  *x = shuffled;

  return LH_SUCCESS;
}
*/

void lh_rset_lr(struct user *r, uintptr_t value) {
	r->regs.uregs[14] = value;
}

uintptr_t lh_rget_lr(struct user *r) {
	return r->regs.uregs[14];
}

inline int inj_trap(pid_t pid, struct user *iregs) {
	LH_VERBOSE(3, "Copying Null to LR");
	lh_rset_lr(iregs, 0x0);
	return LH_SUCCESS;
}

int inj_pass_args2func(pid_t pid, struct user *iregs, uintptr_t fn, uintptr_t arg1, uintptr_t arg2) {
	LH_VERBOSE(3, "function address is: 0x" LX, fn);
	LH_VERBOSE(3, "link register is: 0x" LX, lh_rget_lr(iregs));

	LH_VERBOSE(3, "copying Arg 1 to r0.");
	iregs->regs.uregs[0] = arg1;

	LH_VERBOSE(3, "copying Arg 2 to r1.");
	iregs->regs.uregs[1] = arg2;
	lh_rset_ip(iregs, fn);

	return LH_SUCCESS;

}

inline void lh_rset_ip(struct user *r, uintptr_t value) {
	r->regs.uregs[15] = value;
}

inline uintptr_t lh_rget_ip(struct user *r) {
	return r->regs.uregs[15];
}

inline void lh_rset_sp(struct user *r, uintptr_t value) {
	r->regs.uregs[13] = value;
}

inline uintptr_t lh_rget_sp(struct user *r) {
	return r->regs.uregs[13];
}

inline void lh_rset_fp(struct user *r, uintptr_t value) {
	r->regs.uregs[11] = value;
}

inline uintptr_t lh_rget_fp(struct user *r) {
	return r->regs.uregs[11];
}

inline void lh_rset_ax(struct user *r, uintptr_t value) {
	r->regs.uregs[0] = value;
}

inline uintptr_t lh_rget_ax(struct user *r) {
	return r->regs.uregs[0];
}
inline int lh_redzone() {
	return 0;
}

void lh_dump_regs(struct user *r) {
	LH_VERBOSE(3, "--------------------------- ARM");
	LH_VERBOSE(3, "%%pc : 0x" LX, r->regs.uregs[15]);
	LH_VERBOSE(3, "%%lr : 0x" LX, r->regs.uregs[14]);
	LH_VERBOSE(3, "%%sp : 0x" LX, r->regs.uregs[13]);
	LH_VERBOSE(3, "%%fp : 0x" LX, r->regs.uregs[11]);
	LH_VERBOSE(3, "%%r0 : 0x" LX, r->regs.uregs[0]);
	LH_VERBOSE(3, "%%r1 : 0x" LX, r->regs.uregs[1]);
	LH_VERBOSE(3, "%%r2 : 0x" LX, r->regs.uregs[2]);
	LH_VERBOSE(3, "%%r3 : 0x" LX, r->regs.uregs[3]);
	LH_VERBOSE(3, "%%r4 : 0x" LX, r->regs.uregs[4]);
	LH_VERBOSE(3, "%%r5 : 0x" LX, r->regs.uregs[5]);
	LH_VERBOSE(3, "%%r6 : 0x" LX, r->regs.uregs[6]);
	LH_VERBOSE(3, "%%r7 : 0x" LX, r->regs.uregs[7]);
	LH_VERBOSE(3, "%%r8 : 0x" LX, r->regs.uregs[8]);
	LH_VERBOSE(3, "%%r9 : 0x" LX, r->regs.uregs[9]);
	LH_VERBOSE(3, "%%r10: 0x" LX, r->regs.uregs[10]);
	
}
//----------------------------------------------------- arm end
