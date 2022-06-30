#include <dlfcn.h>
#include "lh_module.h"
#include "helpers/lh_inject.h"

int inj_inject_library(const char *dllPath, int argc, char *argv[], void **out_libaddr){
	lh_session_t *lh = lh_alloc();
	if (lh == NULL) {
		return -1;
	}
	lh->proc.pid = getpid();

	int rc = LH_SUCCESS;
	do {
		int result;
		bool oneshot = true;
		struct ld_procmaps *lib_to_hook = NULL;

		LH_PRINT("dlopen '%s'", dllPath);
		void *handle = dlopen(dllPath, RTLD_LAZY | RTLD_GLOBAL);
		if(!handle){
			LH_ERROR_SE("dlopen failed!");
			char *error = dlerror();
			if(!error){
				LH_ERROR_SE("dlerror failed!");
			} else {
				LH_ERROR("dlerror(): %s", error);
			}
			break;
		}
		if(out_libaddr){
			*out_libaddr = handle;
		}

		// Get a new copy of the maps after the lib load
		if(lh->ld_maps)
			ld_free_maps(lh->ld_maps, lh->ld_maps_num);
		lh->ld_maps = ld_load_maps(lh->proc.pid, &lh->ld_maps_num);


		lh_hook_t *hook_settings = dlsym(handle, "hook_settings");
		if (hook_settings == NULL) {
			LH_ERROR("Couldnt retrieve hook_settings symbol");
			break;
		}

		LH_VERBOSE(1, "Hook settings found, v%d", hook_settings->version);

		// For future versions of the structure
		if (hook_settings->version != 1) {
			LH_ERROR("hook_settings version is not supported");
			break;
		}

		if (hook_settings->autoinit_pre != NULL) {
			result = hook_settings->autoinit_pre(argc, argv);
			if (result != LH_SUCCESS) {
				LH_VERBOSE(1, "Not continuing, autoinit_pre is not successful");
				break;
			}
		}

		int hook_successful = 0;

		int fni = 0;
		lh_fn_hook_t *fnh = &(hook_settings->fn_hooks[0]);
		// For every hook definition
		while (1) {
			if (fnh->hook_kind == LHM_FN_HOOK_TRAILING){
				break;
			}

			hook_successful = 0;

			LH_VERBOSE(1, "Function hook libname: '%s', symbol: '%s', offset: " LX, fnh->libname, fnh->symname, fnh->sym_offset);
			LH_VERBOSE(3, "The replacement function: " LX, fnh->hook_fn);

			// Locate the library specified in the hook section (if any)
			if (ld_find_library(lh->ld_maps, lh->ld_maps_num, fnh->libname, false, &lib_to_hook) != LH_SUCCESS) {
				LH_ERROR("Couldn't find the requested library in /proc/<pid>/maps");
				continue; //switch to the next hook
			}

			uintptr_t symboladdr = 0;

			switch(fnh->hook_kind){
				case LHM_FN_HOOK_BY_NAME:
					symboladdr = ld_find_address(lib_to_hook, fnh->symname, NULL);
					if(symboladdr == 0){
						LH_ERROR("Symbol not found, trying dlsym");
						void *lib_handle = dlopen(fnh->libname, RTLD_LAZY | RTLD_GLOBAL);
						if(!lib_handle){
							LH_ERROR_SE("dlopen");
							continue;
						}
						symboladdr = (uintptr_t)dlsym(lib_handle, fnh->symname);
						dlclose(lib_handle);
					}
					break;
				case LHM_FN_HOOK_BY_OFFSET:
					symboladdr = lib_to_hook->addr_begin + fnh->sym_offset;
					break;
				case LHM_FN_HOOK_BY_AOBSCAN:
					; //empty statement for C89
					size_t searchSz = fnh->aob_size;
					uint8_t *pattern = fnh->aob_pattern;
					if(!pattern){
						LH_ERROR("No AOB pattern from module!");
						continue;
					}

					uintptr_t idx;
					for(idx = lib_to_hook->addr_begin; idx < lib_to_hook->addr_end; idx++){
						uint8_t *rcode = (uint8_t *)idx;
						if(!memcmp(rcode, pattern, searchSz)){
							LH_VERBOSE(2, "AOB SCAN SUCCEDED!");
							symboladdr = idx;
							break;
						}
					}
					break;
				default:
					LH_ERROR("Invalid Hook method Specified!");
					continue;
			}

			if (symboladdr == 0) {
				LH_PRINT("ERROR: hook_settings->fn_hooks[%d] was not found.", fni);
				continue;
			}
			//LH_VERBOSE(2, "'%s' resolved to "LX, fnh->symname, symboladdr);
			LH_PRINT("'%s' resolved to "LX, fnh->symname, symboladdr);


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

			uintptr_t orig_code_addr = 0;
			size_t saved_bytes;
			if(do_hook){
				// Alloc memory (mmap) and prepare orig code + jump back
				// This is the new address of the original function
				void *orig_function;
				if((orig_function = inj_build_payload_user(fnh, (uint8_t *)symboladdr, &saved_bytes)) == NULL){
					LH_ERROR("Failed to build payload!");
					continue;
				}
				orig_code_addr = (uintptr_t)orig_function;

				// Enable the hook by copying the replacement jump to our new function
				if(inj_inject_payload(fnh, symboladdr) < 0){
					LH_ERROR("Failed to copy replacement jump!");
					continue;
				}
			}

			after_hook:
				if (fnh->orig_function_ptr != 0) {
					uintptr_t func_addr = (do_hook) ? orig_code_addr : symboladdr;
					*(void **)(fnh->orig_function_ptr) = func_addr;
				}
				if (fnh->code_rest_ptr != 0) {
					uintptr_t func_addr = (do_hook) ? symboladdr + saved_bytes: symboladdr;
					*(void **)(fnh->code_rest_ptr) = func_addr;
				}

				hook_successful = 1;
				oneshot = false;

				fni++;
				fnh++;
		}

		if(hook_successful && hook_settings->autoinit_post != 0){
			hook_settings->autoinit_post(NULL);
		}
	} while(0);

	lh_free(&lh);
	return rc;
}

int unprotect(void *addr) {
	// Move the pointer to the page boundary
	int page_size = getpagesize();
	addr -= (unsigned long)addr % page_size;

	if(mprotect(addr, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
			LH_ERROR_SE("mprotect");
	    return -1;
	}

	return 0;
}

int inj_inject_payload(lh_fn_hook_t *fnh, uintptr_t symboladdr){
	size_t jumpSz;
	// Calculate the JUMP from Original to Replacement, so we can get the minimum size to save
	// We need this to avoid opcode overlapping (especially on Intel, where we can have variable opcode size)
	uint8_t *replacement_jump;	//original -> custom
	if(!(replacement_jump = inj_build_jump(fnh->hook_fn, 0, &jumpSz)))
		return -1;

	if( unprotect((void *)symboladdr) < 0)
			return -1;

	memcpy((void *)symboladdr, replacement_jump, jumpSz);

	return LH_SUCCESS;
}

/*
 * Same as needle variant, but we don't need to copy data back and forth
 */
void *inj_build_payload_user(lh_fn_hook_t *fnh, uint8_t *original_code, size_t *saved_bytes){
	if(original_code == NULL){
		LH_PRINT("ERROR: Code Address not specified");
		return NULL;
	}

	int num_opcode_bytes;
	if(fnh->opcode_bytes_to_restore > 0){
		// User specified bytes to save manually
		num_opcode_bytes = fnh->opcode_bytes_to_restore;
	} else {
		// Calculate amount of bytes to save (important for Intel, variable opcode size)
		// NOTE: original_code being passed is just a random address to calculate a jump size (for now)
		num_opcode_bytes = inj_getbackup_size(original_code, LHM_FN_COPY_BYTES, inj_getjmp_size((uintptr_t)original_code));
	}

	if(num_opcode_bytes < 0){
		LH_ERROR("Cannot determine number of opcode bytes to save");
		LH_PRINT("Code size of %d bytes (LHM_NF_COPY_BYTES) may be too small", LHM_FN_COPY_BYTES);
		num_opcode_bytes = LHM_FN_COPY_BYTES;
	}
	LH_PRINT("Opcode bytes to save: %d", num_opcode_bytes);

	size_t jumpSz;
	uint8_t *jump_back;			//custom -> original
	// JUMP from Replacement back to Original code (skip the original bytes that have been replaced to avoid loop)
	if(!(jump_back = inj_build_jump(original_code + num_opcode_bytes, 0, &jumpSz)))
		return NULL;

	// Allocate space for the payload (code size + jump back)
	// Unlike needle variant, we call mmap here, as we're in the user process
	size_t payloadSz = num_opcode_bytes + jumpSz;

	void *pMem = mmap(0, payloadSz, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if(pMem == MAP_FAILED){
		LH_ERROR_SE("mmap");
		return NULL;
	}
	uint8_t *remote_code = (uint8_t *)pMem;

	memcpy(remote_code, original_code, num_opcode_bytes);
	// Make sure code doesn't contain any PC-relative operation once moved to the new location
	inj_relocate_code(remote_code, num_opcode_bytes, (uintptr_t)original_code, (uintptr_t)pMem);
	memcpy(remote_code + num_opcode_bytes, jump_back, jumpSz);

	if(saved_bytes){
		*saved_bytes = num_opcode_bytes;
	}

	LH_PRINT("Payload Built! 0x"LX" -> 0x"LX" -> 0x"LX" -> 0x"LX"",
		original_code, fnh->hook_fn, pMem, original_code + num_opcode_bytes);

	return pMem;
}
