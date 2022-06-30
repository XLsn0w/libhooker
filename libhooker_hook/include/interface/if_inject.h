#ifndef __INTERFACE_INJECT_H
#define __INTERFACE_INJECT_H
#include <stdint.h>
#include <sys/types.h>
#include "interface/if_cpu.h"
#include "lh_module.h"
#include "interface/inject_types.h"

#define ALIGN(sizeToAlign, alignment) (((sizeToAlign) + (alignment) - 1) & ~((alignment) - 1))

//Temporary interface definition
void *inj_blowdata(pid_t pid, uintptr_t src_in_remote, size_t datasz);
int inj_copydata(pid_t pid, uintptr_t target, const unsigned char *data, size_t datasz);
void inj_find_mmap(lh_session_t * lh, struct user *iregs, struct ld_procmaps *lib_to_hook, uintptr_t lhm_mmap, uintptr_t lhm_munmap);
int inj_peekdata(pid_t pid, uintptr_t src_in_remote, uintptr_t *outpeek);
int inj_pokedata(pid_t pid, uintptr_t destaddr, uintptr_t data);
int inj_ptrcpy(lh_session_t *lh, uintptr_t dstaddr, uintptr_t srcaddr);
int inj_setexecwaitget(lh_session_t * lh, const char *fn, struct user *iregs);
uintptr_t inj_strcpy_alloc(lh_session_t * lh, struct user *iregs, const char *str);
lh_session_t *lh_alloc();
int lh_attach(lh_session_t * session, pid_t pid);
uintptr_t lh_call_func(lh_session_t * lh, struct user *iregs, uintptr_t function, char *funcname, uintptr_t arg0, uintptr_t arg1);
int lh_detach(lh_session_t * session);
void lh_free(lh_session_t ** session);
int lh_inject_library(lh_session_t * lh, const char *dllPath, uintptr_t *out_libaddr);
lh_r_process_t *lh_rproc_gen(lh_session_t *lh);
int inj_build_payload(pid_t r_pid, lh_fn_hook_t *fnh, struct ld_procmaps *lib_to_hook, uintptr_t symboladdr, size_t *saved_bytes);

/* Static functions shouldn't be visible elsewhere. Leaving them here for possible changes
static int inj_exec(pid_t pid);
static int inj_gather_functions(lh_session_t * lh);
static int inj_get_regs(pid_t pid, struct user *regs);
static int inj_process(lh_session_t * lh);
static int inj_set_regs(pid_t pid, const struct user *regs);
static int inj_wait(pid_t pid);
*/

lh_session_t *lh_alloc();
int lh_attach(lh_session_t * session, pid_t pid);
int lh_inject_library(lh_session_t * session, const char *library, uintptr_t * out_libaddr);
int lh_detach(lh_session_t * session);
void lh_free(lh_session_t ** session);
uintptr_t lh_dlsym(lh_session_t * lh, struct user *iregs, char *symbolName);
uintptr_t lh_call_func(lh_session_t * lh, struct user *iregs, uintptr_t function, char *funcname, uintptr_t arg0, uintptr_t arg1);
#endif
