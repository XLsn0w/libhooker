#ifndef __INTERFACE_CPU_H
#define __INTERFACE_CPU_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#if defined(__linux__) || defined(__FreeBSD__)
#include <sys/wait.h>
#endif
#include <errno.h>

#if __android__
struct user {
	long uregs[18];
};
#elif defined(__linux__)
#include <sys/user.h>
#endif

#ifdef __FreeBSD__
#include <x86/reg.h>
#define r15 r_r15
#define r14 r_r14
#define r13 r_r13
#define r12 r_r12
#define rbp r_rbp
#define rbx r_rbx
#define r11 r_r11
#define r10 r_r10
#define r9 r_r9
#define r8 r_r8
#define rax r_rax
#define rcx r_rcx
#define rdx r_rdx
#define rsi r_rsi
#define rdi r_rdi
#define rip r_rip
#define cs r_cs
#define eflags r_eflags
#define rsp r_rsp
#define ss r_ss
#define fs_base r_fs_base
#define gs_base r_gs_base
#define ds r_ds
#define es r_es
#define fs r_fs
#define gs r_gs
struct user
{
  struct reg       regs;
  int                           u_fpvalid;
  unsigned long int             u_tsize;
  unsigned long int             u_dsize;
  unsigned long int             u_ssize;
  unsigned long                 start_code;
  unsigned long                 start_stack;
  long int                      signal;
  int                           reserved;
  unsigned long int             magic;
  char                          u_comm [32];
  unsigned long int             u_debugreg [8];
};
#endif

#include "lh_common.h"

#if defined(__i386__) || defined(__x86_64__)
#include <capstone/capstone.h>
#endif

/*
 * Common Functions
 */
size_t inj_getjmp_size(uintptr_t addr);
uint8_t *inj_build_jump(uintptr_t dstAddr, uintptr_t srcAddr, size_t *jumpSz);

int inj_getbackup_size(uint8_t *codePtr, size_t codeSz, size_t payloadSz);
int inj_relocate_code(uint8_t *codePtr, size_t codeSz, uintptr_t sourcePC, uintptr_t destPC);


/*
 * Per-CPU Functions
 */
int inj_trap_bytes();
int inj_opcode_bytes();
int inj_absjmp_opcode_bytes();
int inj_reljmp_opcode_bytes();

#ifndef __arm__
int inj_getinsn_count(uint8_t *buf, size_t sz, int *validbytes);
#endif

int inj_build_trap(uint8_t *buffer);
int inj_build_rel_jump(uint8_t *buffer, uintptr_t jump_destination, uintptr_t jump_opcode_address);
int inj_build_abs_jump(uint8_t *buffer, uintptr_t jump_destination, uintptr_t jump_opcode_address);
int inj_reljmp_opcode_bytes();
int lh_redzone();

int inj_trap(pid_t pid, struct user *iregs);
int inj_pass_args2func(pid_t pid, struct user *iregs, uintptr_t fn, uintptr_t arg1, uintptr_t arg2);

void lh_rset_ip(struct user *r, uintptr_t value);
uintptr_t lh_rget_ip(struct user *r);

void lh_rset_sp(struct user *r, uintptr_t value);
uintptr_t lh_rget_sp(struct user *r);

void lh_rset_fp(struct user *r, uintptr_t value);
uintptr_t lh_rget_fp(struct user *r);

void lh_rset_ax(struct user *r, uintptr_t value);
uintptr_t lh_rget_ax(struct user *r);

void lh_dump_regs(struct user *regs);

#endif
