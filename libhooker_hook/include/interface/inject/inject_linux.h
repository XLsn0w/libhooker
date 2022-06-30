/*
 * Stuff.
 *
 */

#ifndef __INTERFACE_INJECT_LINUX_H
#define __INTERFACE_INJECT_LINUX_H

#include <sys/ptrace.h>
#include <sys/mman.h>
#include "interface/exe/linux_elf.h"
#include "interface/if_cpu.h"

int needle_main(int argc, char *argv[]);

/*
 * Any info you want to pass to the hooked process
 */
PACK(typedef struct {
	char magic[4]; //LHFO

	int argc;
	char **argv;

	int prog_argc;
	char **prog_argv;

	int lh_verbose;
	pid_t pid;

	struct ld_procmaps lib;
	char *exename;
	char *ttyName;
	char *preload_path;
}) lh_r_process_t;

typedef struct {
	lh_r_process_t proc; //lh_common.h
	bool started_by_needle;

	struct user original_regs;
	enum elf_bit is64;
	struct elf_symbol *exe_symbols;
	size_t exe_symbols_num;
	uintptr_t exe_entry_point;
	struct elf_interp exe_interp;	/* dynamic loader from .interp in the exe */
	struct ld_procmaps *ld_maps;
	size_t ld_maps_num;
	/* addresses useful */
	uintptr_t fn_malloc;
	uintptr_t fn_realloc;
	uintptr_t fn_free;
	uintptr_t fn_dlopen;
	uintptr_t fn_dlerror;
	uintptr_t fn_dlclose;
	uintptr_t fn_dlsym;
} lh_session_t;

//#define LH_PRELOAD_SO "lh_preload.so"
#define LH_PRELOAD_SO "liblh_preload.so"

#define LH_LIB_MAX 128
#define LH_MAX_ARGS 4
#endif
