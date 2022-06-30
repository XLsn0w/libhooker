/*
 * Stuff.
 *
 */

#ifndef __LH_MODULE_H
#define __LH_MODULE_H

#include "lh_common.h"
#include "interface/inject_types.h"

#define LHM_MAX_FN_HOOKS 32

#define LHM_STR_LENGTH 64
#define LHM_FN_COPY_BYTES 16

enum {
	LHM_FN_HOOK_TRAILING = 0,
	LHM_FN_HOOK_BY_NAME,
	LHM_FN_HOOK_BY_OFFSET,
	LHM_FN_HOOK_BY_AOBSCAN
};

enum {
	LHM_HOOK_KERNEL = 0,
	LHM_HOOK_USER = 1
};

/*
 * Function hook definition
 */
typedef struct {
	int hook_kind;
	char libname[LHM_STR_LENGTH];
	char symname[LHM_STR_LENGTH];
	// or offset to codesegment
	uintptr_t sym_offset;
	uintptr_t hook_fn;
	uintptr_t orig_function_ptr;
	uintptr_t code_rest_ptr;
	size_t opcode_bytes_to_restore;
	size_t aob_size;
	unsigned char *aob_pattern;
} lh_fn_hook_t;

/*
 * Module definition
 */
typedef struct {
	int version;
	int hook_mode;
	int (*autoinit_pre) (int argc, char **argv);
	void (*autoinit_post) (lh_r_process_t *);
	lh_fn_hook_t fn_hooks[LHM_MAX_FN_HOOKS];
} lh_hook_t;

extern lh_hook_t hook_settings;


#endif
