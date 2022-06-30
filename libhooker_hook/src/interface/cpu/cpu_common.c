#include "interface/if_inject.h"
#include "interface/if_cpu.h"

#ifdef PAYLOAD_SLJIT
#include "sljit/sljitLir.h"
uint8_t *inj_build_jump(uintptr_t dstAddr, uintptr_t srcAddr, size_t *jumpSz){
	void *sljit_code = NULL;
	struct sljit_compiler *compiler = NULL;

	compiler = sljit_create_compiler(NULL);
	if(!compiler){
		LH_ERROR("Unable to create sljit compiler instance");
		return NULL;
	}

	sljit_emit_ijump(compiler, SLJIT_JUMP, SLJIT_IMM, (sljit_sw)dstAddr);


	sljit_code = sljit_generate_code(compiler);
	if(!sljit_code){
		LH_ERROR("Unable to build jump!");
	} else {
		if(jumpSz){
			*jumpSz = compiler->size;
		}
	}

	if(compiler)
		sljit_free_compiler(compiler);

	return (uint8_t *)sljit_code;
}

size_t inj_getjmp_size(uintptr_t addr){
	size_t jumpSz;
	uint8_t *jump;
	if(!(jump = inj_build_jump(addr, 0, &jumpSz)))
		return -1;
	return jumpSz;
}
#else
size_t inj_getjmp_size(uintptr_t addr){
	#ifdef LH_JUMP_ABS
		return inj_absjmp_opcode_bytes();
	#else
		return inj_reljmp_opcode_bytes();
	#endif
}

uint8_t *inj_build_jump(uintptr_t dstAddr, uintptr_t srcAddr, size_t *jumpSzPtr){
	size_t jumpSz = inj_getjmp_size(dstAddr);
	uint8_t *buffer = calloc(jumpSz, 1);
	if(!buffer)
		return NULL;
	#ifdef LH_JUMP_ABS
		if(inj_build_abs_jump(buffer, dstAddr, srcAddr) != LH_SUCCESS)
			goto error;
	#else
		if(inj_build_rel_jump(buffer, dstAddr, srcAddr) != LH_SUCCESS)
			goto error;
	#endif
	if(jumpSzPtr)
		*jumpSzPtr = jumpSz;
	if(lh_verbose > 3)
		lh_hexdump("jump", buffer, jumpSz);
	return buffer;
	error:
		free(buffer);
		return NULL;
}
#endif

#ifndef __arm__
int inj_getinsn_count(uint8_t *buf, size_t sz, int *validbytes){
	csh handle;
	cs_insn *insn;
	#if __i386__
	if (cs_open(CS_ARCH_X86, CS_MODE_32, &handle) != CS_ERR_OK)
	#elif __x86_64__
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
	#elif __arm__
	if (cs_open(CS_ARCH_ARM, CS_MODE_LITTLE_ENDIAN, &handle) != CS_ERR_OK)
	#endif
		goto err_open;

	size_t count, i;
	count = cs_disasm(handle, buf, sz, 0x0, 0, &insn);
	if(count < 0)
		goto err_disasm;

	if(validbytes == NULL)
		goto ret;

	*validbytes = 0;
	for(i=0; i<count; i++){
		*validbytes += insn[i].size;
	}

	ret:
		cs_free(insn, count);
		return count;

	err_open:
		LH_ERROR("cs_open failed!");
		return -1;
	err_disasm:
		LH_ERROR("cs_disasm failed!");
		cs_close(&handle);
		return -1;
}
#endif

int inj_getbackup_size(uint8_t *codePtr, size_t codeSz, size_t payloadSz){
	int i = 0, opSz;
	if((opSz = inj_opcode_bytes()) > 0){ //fixed opcode size
		while(i < payloadSz)
			i += opSz;
		return i;
	} else { //dynamic opcode size
#if defined(__i386__) || defined(__x86_64__)
		int totalBytes = 0;
		int total_insn = inj_getinsn_count(codePtr, payloadSz, &totalBytes);
		if(total_insn <= 0 || totalBytes == 0)
			return -1;
		int _payloadSz = payloadSz;
		while(totalBytes < payloadSz){
			inj_getinsn_count(codePtr, ++_payloadSz, &totalBytes);
			LH_PRINT("VALID: %d  REQUIRED: %d", totalBytes, payloadSz);
		}
		return totalBytes;
#else
		return -1;
#endif
	}
	//return -1;
}

/*
 * Relocates code pointed by codePtr from sourcePC to destPC
 */
#if !defined(__i386__) && !defined(__x86_64__)
int inj_relocate_code(uint8_t *codePtr, size_t codeSz, uintptr_t sourcePC, uintptr_t destPC){
	/* Not yet implemented for other arches */
	return LH_SUCCESS;
}
#endif

/*
 * Builds the jump, relocates original code, and copies it back
 */
int inj_build_payload(
	pid_t r_pid,
	lh_fn_hook_t *fnh,
	struct ld_procmaps *lib_to_hook,
	uintptr_t symboladdr,
	size_t *saved_bytes
)
{
	int result = -1;

	if (lib_to_hook->mmap_begin + LHM_FN_COPY_BYTES > lib_to_hook->mmap_end) {
		LH_PRINT("ERROR: not enough memory to backup code");
		return -1;
	}

	// Read remote code (max LHM_FN_COPY_BYTES bytes)
	uint8_t *remote_code = inj_blowdata(r_pid, symboladdr, LHM_FN_COPY_BYTES);
	if(remote_code == NULL){
		LH_PRINT("ERROR: Can't read code at 0x"LX, symboladdr);
		return -1;
	}

	size_t jumpSz;
	// Calculate the JUMP from Original to Replacement, so we can get the minimum size to save
	// We need this to avoid opcode overlapping (especially on Intel, where we can have variable opcode size)
	uint8_t *replacement_jump;	//original -> custom
	if(!(replacement_jump = inj_build_jump(fnh->hook_fn, 0, &jumpSz)))
		return -1;

	int num_opcode_bytes;
	if(fnh->opcode_bytes_to_restore > 0){
		// User specified bytes to save manually
		num_opcode_bytes = fnh->opcode_bytes_to_restore;
	} else {
		// Calculate amount of bytes to save (important for Intel, variable opcode size)
		num_opcode_bytes = inj_getbackup_size(remote_code, LHM_FN_COPY_BYTES, jumpSz);
	}

	if(num_opcode_bytes < 0){
		LH_ERROR("Cannot determine number of opcode bytes to save");
		LH_PRINT("Code size of %d bytes (LHM_NF_COPY_BYTES) may be too small", LHM_FN_COPY_BYTES);
		num_opcode_bytes = LHM_FN_COPY_BYTES;
	}
	LH_PRINT("Opcode bytes to save: %d", num_opcode_bytes);

	if(saved_bytes)
		*saved_bytes = num_opcode_bytes;

	// Make sure code doesn't contain any PC-relative operation once moved to the new location
	inj_relocate_code(remote_code, num_opcode_bytes, symboladdr, lib_to_hook->mmap_begin);

	//LH_PRINT("Copying %d original bytes to 0x"LX"", num_opcode_bytes, lib_to_hook->mmap);

	uint8_t *jump_back;			//custom -> original
	// JUMP from Replacement back to Original code (skip the original bytes that have been replaced to avoid loop)
	if(!(jump_back = inj_build_jump(symboladdr + num_opcode_bytes, 0, &jumpSz)))
		return -1;

	// Allocate space for the payload (code size + jump back)
	size_t payloadSz = num_opcode_bytes + jumpSz;
	remote_code = realloc(remote_code, payloadSz);
	if (!remote_code) {
		LH_ERROR_SE("realloc");
		if(remote_code)
			free(remote_code);
		return -1;
	}

	memcpy(remote_code + num_opcode_bytes, jump_back, jumpSz);

	//Write the payload to the process
	if (LH_SUCCESS != inj_copydata(r_pid, lib_to_hook->mmap_begin, remote_code, payloadSz)) {
		LH_ERROR("Failed to copy payload bytes");
		goto end;
	}

	//Write the replacement jump to the process
	if (LH_SUCCESS != inj_copydata(r_pid, symboladdr, replacement_jump, jumpSz)) {
		LH_ERROR("Failed to copy replacement bytes");
		goto end;
	}

	/*if (lh_verbose > 3) {
		LH_VERBOSE(4, "Dumping the overwritten original function");
		lh_call_func(lh, &iregs, lhm_hexdump, "lhm_hexdump", symboladdr, 0x10);
		if(errno)
			break;

		LH_VERBOSE(4, "Dumping the corresponding payload area");
		lh_call_func(lh, &iregs, lhm_hexdump, "lhm_hexdump", remote_code, payloadSz);
		if(errno)
			break;
	}*/


	// Check we have enough room
	if (lib_to_hook->mmap_begin + payloadSz > lib_to_hook->mmap_end) {
		LH_ERROR("Not enough memory!");
		result = -1;
		goto end;
	}


	// Copy payload to tracked program
	if (LH_SUCCESS != inj_copydata(r_pid, lib_to_hook->mmap_begin, remote_code, payloadSz)) {
		LH_ERROR("Unable to copy payload");
		goto end;
	}

	LH_PRINT("Payload Built! 0x"LX" -> 0x"LX" -> 0x"LX" -> 0x"LX"",
		symboladdr, fnh->hook_fn, lib_to_hook->mmap_begin, symboladdr + num_opcode_bytes);

	lib_to_hook->mmap_begin += (uintptr_t)payloadSz;

	result = LH_SUCCESS;

	end:
		if(remote_code)
			free(remote_code);
		return result;
}
