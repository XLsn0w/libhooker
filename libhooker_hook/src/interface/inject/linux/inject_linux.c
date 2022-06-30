#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>
#include <unistd.h>
#include <stdint.h>
#include <dlfcn.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <errno.h>

//debug
#include <time.h>

#ifdef __FreeBSD__
#include <sys/ptrace.h>
#define PTRACE_GETREGS	PT_GETREGS
#define PTRACE_SETREGS	PT_SETREGS
#define PTRACE_PEEKDATA PT_READ_D
#define PTRACE_POKEDATA PT_WRITE_D
#define PTRACE_ATTACH	PT_ATTACH
#define PTRACE_DETACH	PT_DETACH
#define PTRACE_SINGLESTEP PT_STEP
#define PTRACE_CONT	PT_CONTINUE
#define __BSD_VISIBLE 1
#define __WALL WAIT_MYPGRP
#endif

#include "interface/if_inject.h"
#include "lh_module.h"
#include "lh_common.h"

#define MMAP_SIZE 8192

/*
 *
 */
static int inj_gather_functions(lh_session_t * lh) {
	struct ld_procmaps *lib_ld = NULL;
	struct ld_procmaps *lib_dl = NULL;
	struct ld_procmaps *lib_c = NULL;

	bool ld_found = false;
	bool c_found = false;
	bool dl_found = false;
	if (!lh)
		return -1;
	if (lh->ld_maps_num <= 0)
		return -1;

#define LIBNAME_LD "ld"
#define LIBNAME_LIBC "libc"
#define LIBNAME_LIBDL "libdl"
#undef LD_PROCMAPS_FIND_LIB
#define LD_PROCMAPS_FIND_LIB(name,flag,alib,retval) \
do { \
        LH_VERBOSE(2, "Checking if %s exists in procmaps.", name);\
        if (ld_find_library(lh->ld_maps, lh->ld_maps_num, \
                                                name, flag, alib) < 0) { \
                LH_VERBOSE(1, "%s not mapped.", name); \
                retval = false; \
        } else { \
                retval = true; \
                LH_VERBOSE(1,  "Found %s", name); \
        } \
} while (0)
#undef LD_LIB_FIND_FN_ADDR
#define LD_LIB_FIND_FN_ADDR(fn,outfn,alib) \
do { \
        if (outfn) break; \
        outfn = ld_find_address(alib, fn, NULL); \
        if (outfn != 0) { \
                LH_VERBOSE(1,"Found %s at 0x"LX" in %s",  fn, outfn, alib->pathname); \
        } else { \
                LH_VERBOSE(1, "%s not found in %s.", fn, alib->pathname); \
        } \
} while (0)
	if (lh->exe_interp.name) {
		LD_PROCMAPS_FIND_LIB(lh->exe_interp.name, true, &lib_ld, ld_found);
	}
	if (!ld_found) {
		LH_VERBOSE(1, "No interpreter found. Guessing.");
		LD_PROCMAPS_FIND_LIB(LIBNAME_LD, false, &lib_ld, ld_found);
	}
	LD_PROCMAPS_FIND_LIB(LIBNAME_LIBC, false, &lib_c, c_found);
	LD_PROCMAPS_FIND_LIB(LIBNAME_LIBDL, false, &lib_dl, dl_found);

	if (c_found) {
		LD_LIB_FIND_FN_ADDR("malloc", lh->fn_malloc, lib_c);
		LD_LIB_FIND_FN_ADDR("realloc", lh->fn_realloc, lib_c);
		LD_LIB_FIND_FN_ADDR("free", lh->fn_free, lib_c);
	}
	if (ld_found) {
		LD_LIB_FIND_FN_ADDR("malloc", lh->fn_malloc, lib_ld);
		LD_LIB_FIND_FN_ADDR("realloc", lh->fn_realloc, lib_ld);
		LD_LIB_FIND_FN_ADDR("free", lh->fn_free, lib_ld);
	}
	if (!lh->fn_malloc || !lh->fn_realloc || !lh->fn_free) {
		LH_ERROR("Some memory allocation routines are unavailable. Cannot proceed.");
		return -1;
	}
	if (dl_found) {
		LD_LIB_FIND_FN_ADDR("dlopen", lh->fn_dlopen, lib_dl);
		LD_LIB_FIND_FN_ADDR("dlclose", lh->fn_dlclose, lib_dl);
		LD_LIB_FIND_FN_ADDR("dlsym", lh->fn_dlsym, lib_dl);
		LD_LIB_FIND_FN_ADDR("dlerror", lh->fn_dlerror, lib_dl);
	} else if(c_found) {
		LD_LIB_FIND_FN_ADDR(SYM_DLOPEN_MODE, lh->fn_dlopen, lib_c);
		LD_LIB_FIND_FN_ADDR(SYM_DLCLOSE, lh->fn_dlclose, lib_c);
		LD_LIB_FIND_FN_ADDR(SYM_DLSYM, lh->fn_dlsym, lib_c);
	} else {
		LH_ERROR("Couldn't find libc or libdl in memory map");
		char *cmd;
		asprintf(&cmd, "cat /proc/%zu/maps", lh->proc.pid);
		system(cmd);
		free(cmd);
		return -1;
	}
/*
// TODO:
        if (!lh->fn_dlopen || !lh->fn_dlsym) {
                android_way(lh);
                return -1;
        }
*/

	if (!lh->fn_dlopen) {		// || !lh->fn_dlsym)
		LH_ERROR("Dynamic Library loading routines were not found. Cannot proceed.");

		return -1;
	}

#undef LD_PROCMAPS_FIND_LIB
#undef LD_LIB_FIND_FN_ADDR
	return LH_SUCCESS;
}

/*
 * Fetches and returns the registers of the tracked pid
 */
static int inj_get_regs(pid_t pid, struct user *regs) {
	if (!regs){
		return -1;
	}
	memset(regs, 0, sizeof(*regs));
	
	int result = -1;
	#ifdef __FreeBSD__
	result = ptrace(PTRACE_GETREGS, pid, regs, NULL);
	#else
	result = ptrace(PTRACE_GETREGS, pid, NULL, regs);
	#endif

	if (result < 0) {
		LH_ERROR_SE("Ptrace Getregs failed");
		return -1;
	}
	return LH_SUCCESS;
}

/*
 * Sets the registers of the tracked pid from *regs
 */
static int inj_set_regs(pid_t pid, const struct user *regs) {
	if (!regs)
		return -1;

	int result = -1;
	#ifdef __FreeBSD__
	result = ptrace(PTRACE_SETREGS, pid, regs, NULL);
	#else
	result = ptrace(PTRACE_SETREGS, pid, NULL, regs);
	#endif

	if (result < 0) {
		LH_ERROR_SE("Ptrace Setregs failed");
		return -1;
	}
	return LH_SUCCESS;
}

/*
 * Continues execution of a paused process
 */
static int inj_exec(pid_t pid) {
	if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
		LH_ERROR_SE("Ptrace Continue failed");
		return -1;
	}
	return LH_SUCCESS;
}

/*
 * Waits for a trap or termination signal
 */
static int inj_wait(pid_t pid) {
	int status = 0;
	pid_t proc_pid;
	uint signo;
	while(1){
		while ((proc_pid=waitpid(pid, &status, __WALL | WUNTRACED)) != pid && proc_pid >= 0){
			LH_VERBOSE(3, "Skipping process '%d'", proc_pid);
		}
		signo = WSTOPSIG(status);
		LH_VERBOSE(3, "Got Signal: %u (%s)", signo, strsignal(signo));
		
		if(signo == SIGUSR1 || signo == SIGUSR2 || signo >= SIGRTMIN){
			inj_exec(pid); 
		} else {
			break;
		}
	}
	
	if (proc_pid < 0) {
		LH_ERROR("Waitpid failed");
		return -1;
	}
	if (WIFEXITED(status) || WIFSIGNALED(status)) {
		signo = WTERMSIG(status);
		LH_ERROR("Process was terminated by signal %u (%s)", signo, strsignal(signo));
		return -1;
	}
	return LH_SUCCESS;
}

/*
 * Reads memory in the tracked pid at the address specified by "src_in_remote"
 * Stores the data in the address pointed by "outpeek"
 */
int inj_peekdata(pid_t pid, uintptr_t src_in_remote, uintptr_t *outpeek) {
	int err = 0;
	long peekdata = ptrace(PTRACE_PEEKDATA, pid, src_in_remote, NULL);
	err = errno;
	LH_VERBOSE(4, "Peekdata: %p", (void *)peekdata);
	if (peekdata == -1 && err != 0) {
		LH_ERROR_SE("Ptrace PeekText failed with error");
		return -1;
	}
	if (outpeek)
		*outpeek = peekdata;
	else
		LH_ERROR("Invalid arguments.");
	return outpeek ? LH_SUCCESS : -1;
}

/*
 * Reads "datasz" bytes of data from "src_in_remote" addres in the tracked pid
 * Allocates and returns a pointer to memory containing the read data
 */
void *inj_blowdata(pid_t pid, uintptr_t src_in_remote, size_t datasz) {
	datasz = ALIGN(datasz, sizeof(uintptr_t));

	void *re = calloc(1, datasz);
	if (re != NULL) {

		uintptr_t *a = (uintptr_t *) re;
		uintptr_t aaddress = src_in_remote;
		uintptr_t aread;
		size_t read = 0;
		while (read < datasz) {
			if (LH_SUCCESS != inj_peekdata(pid, aaddress, &aread))
				return NULL;

			*a = aread;
			a += 1;
			aaddress += sizeof(uintptr_t);
			read += sizeof(uintptr_t);
		}
	} else {
		LH_ERROR_SE("malloc");
	}
	return re;
}

char *inj_strcpy_tolocal(pid_t pid, uintptr_t r_str){
	if(!r_str)
		return NULL;
	size_t strSz = 1;
	char *l_str = NULL;
	for(; ; strSz++){
		if(!l_str){
			l_str = calloc(strSz, 1);
		} else {
			l_str = realloc(l_str, strSz);
		}
		uintptr_t word;
		if (LH_SUCCESS != inj_peekdata(pid, r_str++, &word)){
			free(l_str);
			return NULL;
		}
		uint8_t ch = (uint8_t)word;
		l_str[strSz-1] = ch;
		if(ch == 0x00){
			break;
		}
	}
	return l_str;
}

#ifndef __arm__
uint8_t *inj_getcodeinj_getcode(pid_t pid, uintptr_t codeAddr, int opcodeNum, int *validBytes){
	int _validBytes;
	int *dst_validBytes = (validBytes == NULL) ? &_validBytes : validBytes;
	size_t codeSz = 1;

	void *codePtr = inj_blowdata(pid, codeAddr, codeSz);
	if(codePtr == NULL){
		goto error_fetch;
	}
	printf("First byte: 0x%x\n", (uint8_t)*((uint8_t *)codePtr));

	while(inj_getinsn_count(codePtr, codeSz, dst_validBytes) < opcodeNum){
		codePtr = realloc(codePtr, ++codeSz);
		if(codePtr == NULL || inj_peekdata(pid, codeAddr, codePtr) != LH_SUCCESS)
			goto error_fetch;
	}
	return codePtr;

	error_fetch:
		if(codePtr)
			free(codePtr);
		LH_ERROR("ERROR: Cannot read at PC 0x%lx", codeAddr);
		return NULL;
}
#endif

static int inj_runto(pid_t pid, uintptr_t addr){
	struct user regs;
	int rc = LH_SUCCESS;

	#if 0
	size_t neededSz = inj_trap_bytes();

	do {
		printf("Dumping at 0x%lx\n", addr);
		// read the code at addr
		int validBytes;
		int opNum = 0;
		uint8_t *code = NULL;
		do {
			if(code != NULL)
				free(code);
			code = inj_getcode(pid, addr, ++opNum, &validBytes);
		} while(validBytes < neededSz);

		printf("We just dumped %d bytes!\n", validBytes);
		int i;
		for(i=0; i<validBytes; i++){
			printf("Code: 0x%x\n", code[i]);
		}
	} while(0);
	#endif

	clock_t begin, end;
	double time_spent;
	begin = clock();

	while(1){
		if((rc=inj_get_regs(pid, &regs)) != LH_SUCCESS){
			return -1;
		}
		uintptr_t cur_pc;
		cur_pc = lh_rget_ip(&regs);
		//printf("PC: 0x%lx\n", cur_pc);
		if(cur_pc == addr){
			break;
		}

		if(ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) < 0){
			LH_ERROR_SE("ptrace");
			return -1;
		}
		inj_wait(pid);
	}

	end = clock();
	time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
	printf("TIME SPENT: %.2f seconds\n", time_spent);


	return LH_SUCCESS;
}

/*
 * Loads and parses informations about the process
 */
static int inj_process(lh_session_t * lh) {
	int rc = LH_SUCCESS;
	do {
		pid_t pid = lh->proc.pid;
		char *filename;
		if (pid <= 0) {
			LH_ERROR("Invalid pid");
			rc = -3;
			break;
		}

		lh->is64 = HOTPATCH_EXE_IS_NEITHER;
		if(!lh->started_by_needle){
#ifdef __FreeBSD__
			asprintf(&filename, "/proc/%d/file", pid);
#else
			asprintf(&filename, "/proc/%d/exe", pid);
#endif
			lh->proc.exename = readlink_safe(filename);
			printf("FILENAME: %s\n", lh->proc.exename);
		} else {
			filename = lh->proc.exename;
		}
		// load symbols from the elf file
		lh->exe_symbols = exe_load_symbols(filename, &lh->exe_symbols_num, &lh->exe_entry_point, &lh->exe_interp, &lh->is64);

		if (!lh->exe_symbols) {
			LH_ERROR("Unable to find any symbols in exe.");
			rc = -2;
			break;
		}
		if (lh->exe_entry_point == 0) {
			LH_ERROR("Entry point is 0. Invalid.");
			rc = -1;
			break;
		}
		LH_VERBOSE(1, "Executable headers are loaded");

		#if 0
		if(lh->started_by_needle){
			/*LH_VERBOSE(3, "Searching for main symbol...");
			uintptr_t proc_main = ld_symbols_get_addr(lh->exe_symbols, lh->exe_entry_point,
														lh->exe_symbols_num, "main", NULL);
			if(proc_main <= 0){
				LH_ERROR("Cannot locate main in the process binary!");
				rc = -3;
				break;
			}
			printf("MAIN: 0x%lx\n", proc_main);
			*/
			printf("ENTRY: 0x%lx\n", lh->exe_entry_point);
			if((rc=inj_runto(lh->proc.pid, lh->exe_entry_point)) != LH_SUCCESS)
				break;
		}
		#endif

		// parse process maps
		lh->ld_maps = ld_load_maps(lh->proc.pid, &lh->ld_maps_num);
		if (!lh->ld_maps) {
			LH_PRINT("ERROR: Unable to load data in /proc/%d/maps.", pid);
			rc = -1;
			break;
		}
		LH_VERBOSE(2, "/proc/%d/maps loaded.", pid);

		if (lh->exe_symbols && lh->exe_symbols_num > 0) {
			qsort(lh->exe_symbols, lh->exe_symbols_num, sizeof(*lh->exe_symbols), elf_symbol_cmpqsort);
		}

		if (LH_SUCCESS != inj_gather_functions(lh)) {
			LH_ERROR("Unable to find all the functions needed. Cannot proceed.");
			rc = -1;
			break;
		}

	} while (0);
	return rc;
}

/*
 * Creates and returns a new empty session (lh_session_t)
 */
lh_session_t *lh_alloc() {
	lh_session_t *re = (lh_session_t *) calloc(1, sizeof(lh_session_t));
	if (!re) {
		LH_ERROR_SE("malloc");
		return NULL;
	}
	return re;
}

/*
 * Attaches ptrace to the running process specified by the pid "pid"
 */
int lh_attach(lh_session_t * session, pid_t pid) {
	int re = LH_SUCCESS;
	do {
		session->proc.pid = pid;

#if 0
		if(session->started_by_needle){
			// wait for wrapped main to raise SIGSTOP
			if(inj_wait(session->proc.pid) != LH_SUCCESS)
				break;
			LH_VERBOSE(3, "Process stopped, attaching...");
		}
#endif

		if(!session->started_by_needle){		
			LH_VERBOSE(1, "Attaching to pid %d", pid);
			if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) {
				LH_ERROR_SE("ptrace attach");
				re = -2;
				break;
			}
			
			LH_VERBOSE(2, "Waiting...");
			if (LH_SUCCESS != inj_wait(session->proc.pid))
				break;
		}

		if (LH_SUCCESS != (re = inj_process(session)))
			break;

		//obtain the current tty name
		//TODO: handle pipes (could use FIFOs)
		char *cur_tty = ttyname(0);
		if(!cur_tty){
			LH_ERROR("Couldn't obtain current tty!");
		} else {
			LH_PRINT("Running on TTY: %s", cur_tty);
			session->proc.ttyName = cur_tty;
		}
		
		// make a copy of the registers at attach time and store them in the session
		if (LH_SUCCESS != (re = inj_get_regs(pid, &(session->original_regs))))
			break;

		lh_dump_regs(&(session->original_regs));
	} while (0);

	if (re != LH_SUCCESS)
		session->proc.pid = 0;

	return re;
}

/*
 * Frees a session object
 */
void lh_free(lh_session_t ** session) {
	if (session == NULL)
		return;

	lh_session_t *s = *session;
	if(!s)
		goto end;

	int i;

	if(s->proc.exename)
		free(s->proc.exename);

	if(s->proc.argv && s->proc.argc){
		for(i=0; i<s->proc.argc; i++)
			free(s->proc.argv[i]);
		free(s->proc.argv);
	}

	if(s->proc.prog_argv && s->proc.prog_argc){
		for(i=0; i<s->proc.prog_argc; i++)
			free(s->proc.prog_argv[i]);
		free(s->proc.prog_argv);
	}

	if(s->exe_symbols){
		for(i=0; i<s->exe_symbols_num; i++){
			if(s->exe_symbols[i].name)
				free(s->exe_symbols[i].name);
		}
		free(s->exe_symbols);
	}

	ld_free_maps(s->ld_maps, s->ld_maps_num);

	if(s->exe_interp.name)
		free(s->exe_interp.name);

	free(s);

	end:
		*session = NULL;
}

/*
 * Detaches ptrace from the tracked pid
 */
int lh_detach(lh_session_t * session) {

	pid_t pid = session->proc.pid;

	if (LH_SUCCESS != inj_set_regs(pid, &(session->original_regs)))
		return 2;

	if (ptrace(PTRACE_DETACH, pid, NULL, NULL)) {
		LH_ERROR_SE("detach");
		return 1;
	}

	return LH_SUCCESS;
}

/*
 * set, exec, wait, get
 * - Sets the tracked pid registers with the values in "iregs"
 * - Steps once in the tracked pid
 * - Waits till the step is complete
 * - Gets the new registers values
 *
 * The "fn" argument is actually unused (only for debug printf)
 */
int inj_setexecwaitget(lh_session_t * lh, const char *fn, struct user *iregs) {
	int rc = LH_SUCCESS;
	uintptr_t prev_sp = lh_rget_sp(iregs);
	uintptr_t prev_fp = lh_rget_fp(iregs);
	do {
		LH_VERBOSE(3, "Setting registers and invoking %s.", fn);
		if ((rc = inj_set_regs(lh->proc.pid, iregs)) != LH_SUCCESS)
			break;
		LH_VERBOSE(3, "Executing..");
		if ((rc = inj_exec(lh->proc.pid)) != LH_SUCCESS)
			break;
		LH_VERBOSE(3, "Waiting...");
		if ((rc = inj_wait(lh->proc.pid)) != LH_SUCCESS)
			break;
		LH_VERBOSE(3, "Getting registers.");
		if ((rc = inj_get_regs(lh->proc.pid, iregs)) != LH_SUCCESS){
			break;
		}
		/*
			We now need to restore the previous stack pointer.
			This is essential if the calling convention used by the target platform assumes caller cleanup (e.g ARM)
			Failing to do so will result in a stack corruption which might go unnoticed until a sudden crash of the target process
		*/
		LH_VERBOSE(3, "Restoring stack pointer...");
		lh_rset_sp(iregs, prev_sp);
		// We also restore FP just to be sure, but it shouldn't be required
		LH_VERBOSE(3, "Restoring stack frame...");
		lh_rset_fp(iregs, prev_fp);
	} while (0);

	return rc;
}

/*
 * Stores "datasz" bytes from "data" into the tracked pid in the address pointed by "target"
 */
int inj_copydata(pid_t pid, uintptr_t target, const unsigned char *data, size_t datasz) {
	size_t pos = 0, idx;
	for(idx=0; pos < datasz; idx += sizeof(uintptr_t)) {
		uintptr_t pokedata = 0;

		// !SAFETY!
		if (pos + sizeof(uintptr_t) > datasz) {
			int err = 0;
			pokedata = ptrace(PTRACE_PEEKDATA, pid, target + idx, NULL);
			err = errno;
			LH_VERBOSE(3, "Peekdata: 0x%x", (void *)pokedata);
			if (pokedata == -1 && err != 0) {
				LH_ERROR_SE("Ptrace PeekText failed with error");
				return -1;
			}

			// LH_VERBOSE(4, "prefetched for pokedata: %p", pokedata);
		}

		size_t jdx;
		for (jdx = 0; jdx < sizeof(uintptr_t) && pos < datasz; jdx++, pos++){
			((uint8_t *)&(pokedata))[jdx] = data[pos];
		}

		LH_VERBOSE(4, "Pokedata: 0x%x", pokedata);
		if (ptrace(PTRACE_POKEDATA, pid, target + idx, pokedata) < 0) {
			LH_ERROR_SE("Ptrace PokeText failed with error");
			return -1;
		}
	}
	return LH_SUCCESS;
}

uintptr_t r_procmem_start = 0;
uintptr_t inj_strcpy_alloc(lh_session_t * lh, struct user *iregs, const char *str){
	if(!str){
		return 0;
	}

	uintptr_t r_target = 0;
	size_t len = strlen(str) + 1;

	if(!lh->started_by_needle){
		r_target = lh_call_func(lh, iregs, lh->fn_malloc, "malloc", len, 0);
		if(r_target <= 0){
			LH_ERROR("malloc failed");
			return 0;
		}
	} else {
		r_procmem_start -= len;
		r_target = r_procmem_start;
	}

	if(inj_copydata(lh->proc.pid, r_target, (uint8_t *)str, len) != LH_SUCCESS)
		return 0;

	return r_target;
}

uintptr_t lh_dlsym(lh_session_t * lh, struct user *iregs, char *symbolName){
	uintptr_t r_str = inj_strcpy_alloc(lh, iregs, symbolName);
	uintptr_t addr = lh_call_func(lh, iregs, lh->fn_dlsym, "dlsym", (uintptr_t)RTLD_DEFAULT, r_str);
	lh_call_func(lh, iregs, lh->fn_free, "free", r_str, 0);
	return addr;
}

uintptr_t lh_call_func(lh_session_t * lh, struct user *iregs, uintptr_t function, char *funcname, uintptr_t arg0, uintptr_t arg1){
	errno = LH_SUCCESS;
	// Pause the process

	if(function == 0 && funcname != NULL){
		function = lh_dlsym(lh, iregs, funcname);
	}

	// Causes a fault after the function call (return to 0) (to return to the debugger)
	if ((errno = inj_trap(lh->proc.pid, iregs)) != LH_SUCCESS){
		return 0;
	}
	// Encode call to function
	if ((errno = inj_pass_args2func(lh->proc.pid, iregs, function, arg0, arg1)) != LH_SUCCESS)
		return 0;
	// Call function and wait for completion
	if ((errno = inj_setexecwaitget(lh, funcname, iregs)) != LH_SUCCESS)
		return 0;
	// Return result
	uintptr_t re = lh_rget_ax(iregs);
	if(funcname && strlen(funcname) > 0)
		LH_VERBOSE(2, "CALL @0x"LX": %s(0x" LX ", 0x" LX ") => "LX"", function, funcname, arg0, arg1, re);
	return re;
}

int inj_ptrcpy(lh_session_t *lh, uintptr_t dstaddr, uintptr_t srcaddr){
	return inj_copydata(lh->proc.pid, dstaddr, (uint8_t *)&(srcaddr), sizeof(uintptr_t));
}

/*
 * Stores data in "data" in the tracked pid at address "target_in_remote"
 * Size of the data is the pointer size on the host machine
 */
int inj_pokedata(pid_t pid, uintptr_t destaddr, uintptr_t data) {
	LH_VERBOSE(3, "Poke Data: 0x%x", (void *)data);
	if (ptrace(PTRACE_POKEDATA, pid, destaddr, (void *)data) < 0) {
		LH_ERROR_SE("Ptrace PokeText failed with error");
		return -1;
	}
	return LH_SUCCESS;
}

/*
 * Calls mmap in the tracked pid
 */
void inj_find_mmap(lh_session_t * lh, struct user *iregs, struct ld_procmaps *lib_to_hook, uintptr_t lhm_mmap, uintptr_t lhm_munmap) {
	int i;
	for (i = 1; i <= 8192; i++)	// 4096*4096 => +-16 MBytes
	{
		// If memory is already mapped, do nothing
		if (lib_to_hook->mmap)
			return;

		int64_t offset = ((i >= 4096 ? i - 4095 : -1 * i) * MMAP_SIZE);
		int64_t address = (int64_t) lib_to_hook->addr_begin;
		address = address + offset;
		if (address < 16384)
			continue;

		uintptr_t wanted_address = (uintptr_t) address;
		LH_VERBOSE(4, "Wanted address for mmap: " LX, wanted_address);

		uintptr_t returned = lh_call_func(lh, iregs, lhm_mmap, NULL, wanted_address, MMAP_SIZE);
		if(errno) break;

		// If the memory has been mapped at the wanted address
		if (returned == wanted_address) {
			lib_to_hook->mmap = returned;
			lib_to_hook->mmap_begin = lib_to_hook->mmap;
			lib_to_hook->mmap_end = lib_to_hook->mmap_begin + MMAP_SIZE;
			LH_VERBOSE(2, "MMAP Address: 0x"LX"", returned);
			return;
		}
		// Free the memory mapped by the OS
		lh_call_func(lh, iregs, lhm_munmap, NULL, returned, MMAP_SIZE);
		if(errno) break;
	}

}

#define R_STRBLKSZ(lh) \
	(sizeof(char *) * lh->proc.argc) + \
	/* r_strBlkSz */ \
	sizeof(uint32_t) + \
	(sizeof(char *) * lh->proc.prog_argc) + \
	/* exename */ \
	sizeof(char *) + \
	/* ttyName */ \
	sizeof(char *)

lh_r_process_t *lh_rproc_gen(lh_session_t *lh){
	lh_r_process_t *rproc = calloc(1, sizeof(lh_r_process_t));
	strncpy(rproc->magic, "LHFO", sizeof(rproc->magic));
	rproc->pid = lh->proc.pid;
	rproc->argc = lh->proc.argc;
	rproc->prog_argc = lh->proc.prog_argc;
	rproc->lh_verbose = lh_verbose;
	return rproc;
}

int n_alloc = 0;
uintptr_t *r_allocs = NULL;

uintptr_t inj_rproc(lh_session_t *lh, struct user *iregs){
	uintptr_t r_procmem = 0;
	r_allocs = calloc(sizeof(uintptr_t), lh->proc.argc + lh->proc.prog_argc + 2);
	uintptr_t r_str;

	size_t r_procSz = 0;
	uint32_t r_strBlkSz = 0;

	// Generate and copy the extra info
	lh_r_process_t *rproc = lh_rproc_gen(lh);

	r_procSz += R_STRBLKSZ(lh);
	r_strBlkSz = r_procSz;

	r_procSz += sizeof(lh_r_process_t);
	r_procSz += r_procSz % sizeof(uintptr_t);


/*
	if(lh->started_by_needle){
		uintptr_t p_main = lh_dlsym(lh, iregs, "main");
		if(p_main <= 0){
			LH_ERROR("FATAL: Cannot find main!");
			return 0;
		}
	}
*/
	if(!lh->started_by_needle){
		LH_VERBOSE(1, "Allocating " LU " bytes in the target.\n", r_procSz);
		r_procmem = lh_call_func(lh, iregs, lh->fn_malloc, "malloc", r_procSz, 0);
		if(r_procmem <= 0){
			LH_ERROR("malloc failed!\n");
			return 0;
		}

	} else {
		struct ld_procmaps *lib_preload;
		if (ld_find_library(lh->ld_maps, lh->ld_maps_num, lh->proc.preload_path, true, &lib_preload) != LH_SUCCESS){
			return 0;
		}
		uintptr_t temp_mem = ld_find_address(lib_preload, "lh_temp_mem", NULL);
		if(temp_mem == 0){
			LH_ERROR("Cannot find lh_temp_mem");
			return 0;
		}
		uintptr_t mem_ptr = inj_blowdata(lh->proc.pid, temp_mem, sizeof(uintptr_t));
		r_procmem = temp_mem;
		r_procmem_start = temp_mem + (1 * 1024 * 1024);
	}
	rproc->argv = (char **)r_procmem;

	size_t strBlkOff = 0;
	int i;

	LH_VERBOSE(2, "Copying module arguments...");
	for(i=0; i<lh->proc.argc; i++, strBlkOff+=sizeof(char *)){
		LH_VERBOSE(2, "Copying module argument '%s'", lh->proc.argv[i]);
		if((r_str = inj_strcpy_alloc(lh, iregs, lh->proc.argv[i])) == 0)
			return 0;

		r_allocs[n_alloc++] = r_str;
		if(inj_ptrcpy(lh, r_procmem + strBlkOff, r_str) != LH_SUCCESS){
			return 0;
		}
	}

	LH_VERBOSE(2, "Copying header size...");
	if (inj_copydata(lh->proc.pid, r_procmem + strBlkOff, (uint8_t *)&(r_strBlkSz), sizeof(r_strBlkSz)) != LH_SUCCESS)
		return 0;
	
	strBlkOff += sizeof(r_strBlkSz);

	rproc->prog_argv = (char **)(r_procmem + strBlkOff);

	LH_VERBOSE(2, "Copying program arguments...");
	for(i=0; i<lh->proc.prog_argc; i++, strBlkOff+=sizeof(char *)){
		LH_VERBOSE(2, "Copying program argument '%s'", lh->proc.prog_argv[i]);
		if((r_str = inj_strcpy_alloc(lh, iregs, lh->proc.prog_argv[i])) == 0)
			return 0;
		r_allocs[n_alloc++] = r_str;
		if(inj_ptrcpy(lh, r_procmem + strBlkOff, r_str) != LH_SUCCESS)
			return 0;
	}

	LH_VERBOSE(2, "Copying exename...");
	if((r_str = inj_strcpy_alloc(lh, iregs, lh->proc.exename)) == 0)
		return 0;
	r_allocs[n_alloc++] = r_str;
	rproc->exename = (char *)(r_str);
	if(inj_ptrcpy(lh, r_procmem + strBlkOff, r_str) != LH_SUCCESS)
		return 0;
	
	strBlkOff += sizeof(char *);
	
	if(lh->proc.ttyName != NULL){
		LH_VERBOSE(2, "Copying ttyName...");
		if((r_str = inj_strcpy_alloc(lh, iregs, lh->proc.ttyName)) == 0)
			return 0;
		r_allocs[n_alloc++] = r_str;
		rproc->ttyName = (char *)(r_str);
		if(inj_ptrcpy(lh, r_procmem + strBlkOff, r_str) != LH_SUCCESS)
			return 0;

	}

	LH_VERBOSE(2, "Copying lh_r_process_t to target...");
	if (inj_copydata(lh->proc.pid, r_procmem + r_strBlkSz, (uint8_t *)rproc, sizeof(lh_r_process_t)) != LH_SUCCESS)
		return 0;

	free(rproc);
	return r_procmem;
}

/*
 * Loads a library shared object (module) in the target (must be built with -fPIC!)
 * lh			=> Session object
 * dllPath			=> Path of the library to load
 * out_libaddr	=> (optional) Where to store the address of the loaded library (relative in the tracked process)
 */
int lh_inject_library(lh_session_t * lh, const char *dllPath, uintptr_t *out_libaddr) {
	LH_PRINT("Loading: %s into %d (%s)", dllPath, lh->proc.pid, lh->proc.exename);

	int rc = LH_SUCCESS;

	uintptr_t dlopen_handle = 0; //handle in target process of the library

	/*
		Flag that indicates if we are hooking functions or just running code
		Gets set to false if the hook settings section is empty.
		In such case, the library will be closed with dlclose after code execution
	*/
	bool oneshot = true;

	/*
		We are now going to copy infos to the hooked process
		We proceed as following:
		-> Create a new structure, lh_r_process_t, to hold any info we want to pass
		-> Create a copy of every char * in module argv on the heap, with inj_strcpy_alloc
		-> Place module argv on top. argv is passed like main, and the hooked program can get the rest of the infos by adding an offset to it
		-> After module argv, place an integer to indicate the total size of the header (till lh_r_process_t)
		-> Place the rest of the char *, still with inj_strcpy_alloc
		-> Place lh_r_process_t after the header
		________________________________________________________
		|                     module_argv (char **)            |
		|------------------------------------------------------|
		|                     header_size                      |
		|------------------------------------------------------|
		|            program_argv (char **), etc...            |
		|------------------------------------------------------|
		|                    lh_r_process_t                    |
		|------------------------------------------------------|
		|______________________________________________________|

	*/
	do {
		uintptr_t result = 0;
		uintptr_t stack[LH_MAX_ARGS] = { 0, 0, 0, 0 };	/* max arguments of the functions we
												   are using */
		int idx = 0;

		struct user oregs;
		struct user iregs;

		uintptr_t r_procmem;
		struct ld_procmaps *lib_to_hook;

		// Get original registers from the tracked process
		LH_VERBOSE(2, "Getting original registers.");
		if ((rc = inj_get_regs(lh->proc.pid, &oregs)) != LH_SUCCESS)
			break;

		// Make a copy of the registers
		memcpy(&iregs, &oregs, sizeof(struct user));

		// Get a copy the stack. Ignore the redzone as it includes local, volatile function data
		lh_rset_sp(&iregs, lh_rget_sp(&iregs) - lh_redzone());
		LH_VERBOSE(2, "Copying stack out.");

		// Save up to LH_MAX_ARGS words (we'll trash them so we need to restore them later)
		for (idx = 0; idx < sizeof(stack) / sizeof(uintptr_t); ++idx) {
			if ((rc = inj_peekdata(lh->proc.pid, lh_rget_sp(&iregs) + (idx * sizeof(uintptr_t)), &stack[idx])) != LH_SUCCESS)
				break;
			if ((rc = inj_pokedata(lh->proc.pid, lh_rget_sp(&iregs) + (idx * sizeof(uintptr_t)), (uintptr_t)0)) != LH_SUCCESS)
				break;
		}
		if (rc < 0){
			LH_ERROR("Cannot copy stack!");
			break; //something went wrong
		}

		r_procmem = inj_rproc(lh, &iregs);
		if(r_procmem == 0){
			LH_ERROR("Couldn't inject remote payload");
			break;
		}

		// Call dlopen and get result
		dlopen_handle = lh_call_func(lh, &iregs, lh->fn_dlopen, "dlopen", r_allocs[0], (RTLD_LAZY | RTLD_GLOBAL));
		LH_VERBOSE(1, "library opened at 0x" LX, dlopen_handle);

		if(lh->fn_dlerror){
			uintptr_t r_str = lh_call_func(lh, &iregs, lh->fn_dlerror, "dlerror", (uintptr_t)NULL, (uintptr_t)NULL);
			char *l_str = inj_strcpy_tolocal(lh->proc.pid, r_str);
			if(l_str == NULL){
				LH_PRINT("dlerror(): no error");
			} else {
				LH_PRINT("dlerror(): %s", l_str);
			}
		}

		if(!dlopen_handle || errno){
			LH_ERROR("dlopen failed!");
			lh_dump_regs(&iregs);
			break;
		}

		if (out_libaddr){
			*out_libaddr = dlopen_handle;
		}


		/*
			Verify that the library has been loaded succesfully by probing /proc/<pid>/maps,
			<pid> is the pid of the process we're tracking
		*/
		do {
			// Get a new copy of the maps after the lib load
			if(lh->ld_maps)
				ld_free_maps(lh->ld_maps, lh->ld_maps_num);
			lh->ld_maps = ld_load_maps(lh->proc.pid, &lh->ld_maps_num);

			struct ld_procmaps *lib_just_loaded;
			// Iterate the maps looking for "dllPath" (the library path)
			if (ld_find_library(lh->ld_maps, lh->ld_maps_num, dllPath, true, &lib_just_loaded) != LH_SUCCESS) {
				LH_ERROR("Couldnt find the loaded library in proc/maps");
				break;
			}

			/*
				We're now going to check the existance of the hook_settings structure by looking for its symbol
			*/
			LH_VERBOSE(2, "We found the library just loaded");
			size_t size;
			uintptr_t outfn = ld_find_address(lib_just_loaded, "hook_settings", &size);
			if (outfn == 0) {
				LH_ERROR("hook_settings symbol not found");
				break;
			}

			LH_VERBOSE(2, "hook_settings found at " LX ", size %d", outfn, size);

			lh_hook_t *hook_settings = (lh_hook_t *) inj_blowdata(lh->proc.pid, outfn, size);
			if (hook_settings == NULL) {
				LH_ERROR("Couldn't retrieve hook_settings symbol");
				break;
			}

			LH_VERBOSE(1, "Hook settings found, v%d", hook_settings->version);

			// For future versions of the structure
			if (hook_settings->version != 1) {
				LH_ERROR("hook_settings version is not supported");
				break;
			}

			// Call autoinit_pre before hook (if specified in the settings)
			if (hook_settings->autoinit_pre != NULL) {
				LH_VERBOSE(2, "Calling autoinit_pre " LX, hook_settings->autoinit_pre);

				result = lh_call_func(lh, &iregs, (uintptr_t) hook_settings->autoinit_pre, "autoinit_pre", lh->proc.argc, r_procmem);
				if(errno) break;

				LH_VERBOSE(2, "Registers after call");
				lh_dump_regs(&iregs);

				LH_VERBOSE(2, "returned: %d", (int)result);

				if (result != LH_SUCCESS) {
					LH_VERBOSE(1, "Not continuing, autoinit_pre is not successful");
					break;
				}
			}

			if(hook_settings->hook_mode == LHM_HOOK_USER){
				uintptr_t lhm_hook = ld_find_address(lib_just_loaded, "lhm_hook", NULL);
				if(lhm_hook == 0){
					LH_ERROR("lhm_hook not found");
					break;
				}
				goto hook_end;
			}

			/*
				Every module is equipped with
					lhm_helper.c
					lh_common.c
				Those files provide wrappers to basic functions

				We do some checks to ensure those functions are present in the loaded library/module
			*/
			uintptr_t lhm_mmap = ld_find_address(lib_just_loaded, "lhm_mmap", NULL);
			if (lhm_mmap == 0) {
				LH_ERROR("lhm_mmap not found");
				break;
			}

			uintptr_t lhm_munmap = ld_find_address(lib_just_loaded, "lhm_munmap", NULL);
			if (lhm_munmap == 0) {
				LH_ERROR("lhm_munmap not found");
				break;
			}

			uintptr_t lhm_memcpy = ld_find_address(lib_just_loaded, "lhm_memcpy", NULL);
			if (lhm_memcpy == 0) {
				LH_ERROR("lhm_memcpy not found");
				break;
			}

			uintptr_t lhm_hexdump = ld_find_address(lib_just_loaded, "lhm_hexdump", NULL);
			if (lhm_hexdump == 0) {
				LH_ERROR("lhm_hexdump not found");
				break;
			}

			int hook_successful = 0;

			uintptr_t hookend = (uintptr_t) hook_settings + size;
			int fni = 0;
			lh_fn_hook_t *fnh = &(hook_settings->fn_hooks[0]);
			LH_VERBOSE(4, "Function hooks: " LX " / " LX " (size " LX ")", (uintptr_t) fnh, hookend, (int)size);
			// For every hook definition
			while ((uintptr_t) fnh < hookend) {
				if (fnh->hook_kind == LHM_FN_HOOK_TRAILING){
					break;
				}

				hook_successful = 0;

				LH_VERBOSE(1, "Function hook libname: '%s', symbol: '%s', offset: " LX, fnh->libname, fnh->symname, fnh->sym_offset);
				LH_VERBOSE(3, "The replacement function: " LX, fnh->hook_fn);

				// Locate the library specified in the hook section (if any)
				if (ld_find_library(lh->ld_maps, lh->ld_maps_num, fnh->libname, false, &lib_to_hook) != LH_SUCCESS) {
					LH_ERROR("Couldn't find the requested library in /proc/<pid>/maps");
					break;
				}

				uintptr_t symboladdr = 0;

				switch(fnh->hook_kind){
					case LHM_FN_HOOK_BY_NAME:
						symboladdr = ld_find_address(lib_to_hook, fnh->symname, NULL);
						if(symboladdr == 0){
							symboladdr = lib_to_hook->addr_begin + lh_dlsym(lh, &iregs, fnh->symname);
						}
						break;
					case LHM_FN_HOOK_BY_OFFSET:
						symboladdr = lib_to_hook->addr_begin + fnh->sym_offset;
						break;
					case LHM_FN_HOOK_BY_AOBSCAN:
						; //empty statement for C89
						long unsigned int idx;
						size_t searchSz = fnh->aob_size;
						uint8_t *pattern = inj_blowdata(lh->proc.pid, (uintptr_t)fnh->aob_pattern, searchSz);
						if(!pattern){
							LH_ERROR("Cannot obtain AOB pattern from module!");
							return -1;
						}

						for(idx = lib_to_hook->addr_begin; idx < lib_to_hook->addr_end; idx++){
							uint8_t *rcode = inj_blowdata(lh->proc.pid, idx, searchSz);
							if(!memcmp(rcode, pattern, searchSz)){
								LH_VERBOSE(2, "AOB SCAN SUCCEDED!");
								free(rcode);
								symboladdr = idx;
								break;
							}
							free(rcode);
						}
						free(pattern);
						break;
					default:
						LH_ERROR("Invalid Hook method Specified!");
						return -1;
				}

				if (symboladdr == 0) {
					LH_PRINT("ERROR: hook_settings->fn_hooks[%d] was not found.", fni);
					break;
				}
				LH_VERBOSE(2, "'%s' resolved to "LX, fnh->symname, symboladdr);


				int do_hook = 1;
				if (!fnh->hook_fn) {
					LH_PRINT("WARNING: hook_settings->fn_hooks[%d], hook_fn is null", fni);
					/*
					 * We accept null replacements, if user just wants to save the function address.
					 * In that case, don't place the hook
					 */
					do_hook = 0;
					goto after_hook;
				}

				if(do_hook){
					//If we haven't allocated a payload buffer yet
					if (lib_to_hook->mmap == 0)
						// Allocate MMAP_SIZE bytes for our payload
						inj_find_mmap(lh, &iregs, lib_to_hook, lhm_mmap, lhm_munmap);

					if (lib_to_hook->mmap == (intptr_t)MAP_FAILED) {
						LH_ERROR("mmap did not work :(");
						break;
					}
				}

				/*
					We now have an empty 4MB (MMAP_SIZE) memory region.
					We proceed as following:
					-> Create a backup of the first 16 bytes (LHM_FN_COPY_BYTES) of the original function, and store it in the map. The map now contains a part of the original function code
					-> Go after opcode_bytes_to_restore in the new map, and place a relative jump to the remaining part of the code (in the original address space)
					-> After this relative jump, place the absolute jump to the replacement code address in the lib/module.
					-> Create a jump trampoline, to make a near jump to the absolute jump, that will in turn jump to the replacement code. Store this trampoline in the original address,
					   Overwriting the original code

					________________________________________________________
					|                     MAPPED MEM                       |
					|------------------------------------------------------|
					|  OCODE:	original code chunk                        |
					|------------------------------------------------------|
					|                      PAYLOAD                         |
					|------------------------------------------------------|
					| RELJMP:	relative jump to remaining code            | //absolute if LH_JUMP_ABS is defined
					| ABSJMP:	absolute jump to replacement code          | //only if LH_JUMP_ABS is not set
					|                                                      |
					| ..........                                           |
					| <in function being replaced>                         |
					| jump ABSJMP (in place of original code)              |
					| REMAINING ORIGINAL CODE                              |
					|                                                      |
					|______________________________________________________|

					To call the original function, one can jump to OCODE.
					The first part of the function is executed, and then RELJMP is taken (and we move to REMAINING ORIGINAL CODE)
				*/

				// Position of payload in target address space
				uintptr_t orig_code_addr = 0;
				size_t saved_bytes = 0;
				if(do_hook){
					orig_code_addr = lib_to_hook->mmap_begin;

					//Build the actual payload
					if(inj_build_payload(
							lh->proc.pid, //pid of the process
							fnh, //infos about the replacement
							lib_to_hook, //infos about the library/exe
							symboladdr, //address of the original function
							&saved_bytes //number of saved opcodes
					) < 0){
						LH_ERROR("Cannot build payload!");
						break;
					}
				}

				after_hook:
					// We store the original function address, if wanted
					if (fnh->orig_function_ptr != 0) {
						uintptr_t func_addr = (do_hook) ? orig_code_addr : symboladdr;
						LH_PRINT("original code ptr: 0x"LX"", func_addr);
						if (LH_SUCCESS != inj_pokedata(lh->proc.pid, fnh->orig_function_ptr, func_addr)) {
							LH_ERROR("Failed to copy original function pointr");
							goto error;
						}
					}
					if (fnh->code_rest_ptr != 0) {
						uintptr_t func_addr = (do_hook) ? symboladdr + saved_bytes: symboladdr;
						LH_PRINT("rest code ptr: 0x"LX"", func_addr);
						if (LH_SUCCESS != inj_pokedata(lh->proc.pid, fnh->code_rest_ptr, func_addr)) {
							LH_ERROR("Failed to copy rest code pointr");
							goto error;
						}
					}

					hook_successful = 1;
					oneshot = false;

					fni++;
					fnh = &(hook_settings->fn_hooks[fni]);

					continue;

				error:
					LH_ERROR("HOOK FAILED!");
					if(lib_to_hook->mmap != 0){
						LH_VERBOSE(3, "Freeing the memory map");
						lh_call_func(lh, &iregs, lhm_munmap, "munmap", lib_to_hook->mmap, MMAP_SIZE);
						if(errno) break;
					}
					break;

			}

			//If the hook succeded and the used defined a post hook function, call it
			if (hook_successful && hook_settings->autoinit_post != 0){
				//int inj_copydata(pid_t pid, uintptr_t target, const unsigned char *data, size_t datasz) {
				inj_copydata(lh->proc.pid, r_procmem + + R_STRBLKSZ(lh) + offsetof(lh_r_process_t, lib), (uint8_t *)lib_to_hook, sizeof(*lib_to_hook));
				LH_VERBOSE(2, "Calling autoinit_post " LX, hook_settings->autoinit_post);
				lh_call_func(lh, &iregs, (uintptr_t) hook_settings->autoinit_post, "autoinit_post", r_procmem + R_STRBLKSZ(lh), 0);
				if(errno) break;
			}

			free(hook_settings);
		} while (0);

		if(oneshot){
			LH_VERBOSE(2, "Freeing args and info...");
			lh_call_func(lh, &iregs, lh->fn_free, "free", r_procmem, 0);

			int i;
			for(i=0; i<n_alloc; i++){
				lh_call_func(lh, &iregs, lh->fn_free, "free", r_allocs[i], 0);
			}

			LH_VERBOSE(1, "Freeing library handle " LX, dlopen_handle);
			result = lh_call_func(lh, &iregs, lh->fn_dlclose, "dlclose", dlopen_handle, 0);
			if(errno) break;
			if(result != 0){
				LH_ERROR("dlclose() failed!\n");
			}
		}

	hook_end:
		free(r_allocs);

		// Cleanup part
		// Restore the original registers
		LH_VERBOSE(2, "Setting original registers.");
		if ((rc = inj_set_regs(lh->proc.pid, &oregs)) != LH_SUCCESS)
			break;

		// Restore the original stack
		LH_VERBOSE(2, "Copying stack back.");
		for (idx = 0; idx < sizeof(stack) / sizeof(uintptr_t); ++idx) {
			if ((rc = inj_pokedata(lh->proc.pid, lh_rget_sp(&oregs) - lh_redzone()
								   + idx * sizeof(size_t), stack[idx])) < 0)
				break;
		}

		if(lh->started_by_needle){
			inj_exec(lh->proc.pid);
		}

		if (rc < 0)
			break;
	} while (0);

	return rc;

}

/*
void lh_hook_init(lh_session_t* session) {
  LH_VERBOSE(1,"Shared object init is running");

  LH_VERBOSE(1,"Autoinit pre: "LX, hook_settings.autoinit_pre);
  if(hook_settings.autoinit_pre != NULL) {
     int a = hook_settings.autoinit_pre(session);
     LH_VERBOSE(1,"Autoinit returned %d", a);
     if(a != LH_SUCCESS) return;
  }

  // TODO?

  LH_VERBOSE(1,"Autoinit post: "LX, hook_settings.autoinit_post);
  if(hook_settings.autoinit_post != NULL) {
     hook_settings.autoinit_post(session);
  }
}
*/
