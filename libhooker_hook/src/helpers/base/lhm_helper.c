#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/mman.h>

#include "interface/if_os.h"
#include "interface/if_inject.h"

#include "lh_common.h"
#include "lh_module.h"

uintptr_t lhm_mmap(uintptr_t address, size_t size) {
	return (uintptr_t) mmap((void *)address, size, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
}

int lhm_munmap(uintptr_t address, size_t size) {
	return munmap((void *)address, size);
}

uintptr_t lhm_memcpy(uintptr_t dst_address, uintptr_t src_address) {
	return (uintptr_t) memcpy((void *)dst_address, (void *)src_address, LHM_FN_COPY_BYTES);
}

void *lhm_malloc(size_t size){
	return malloc(size);
}

void lhm_hexdump(uintptr_t address, size_t size) {
	lh_hexdump(">> ", (void *)address, (int)size);
}

int lh_stdout = STDOUT_FILENO;

void lh_stdout_set(int fd){
	lh_stdout = fd;
}
void lh_stdout_clear(){
	lh_stdout = -1;
}
int lh_stdout_getcurrent(){
	return lh_stdout;
}

void lh_vaprintf(const char *fmt, va_list ap){
	if(lh_stdout > -1){
		vdprintf(lh_stdout, fmt, ap);
	} else {
		vprintf(fmt, ap);
	}
}

void lh_printf(const char *fmt, ...){
	va_list ap;
	va_start(ap, fmt);
	lh_vaprintf(fmt, ap);
	va_end(ap);
}

int lh_get_stdout(char *tty){
	if(strstr(tty, "pipe:") != NULL){
		uintptr_t start = (uintptr_t)strchr(tty, '[');
		uintptr_t end = (uintptr_t)strchr(tty, ']');
		if(start == 0 || end == 0){
			return -1;
		}
		start += 1; //skip '[' char
		size_t sz = end-start;
		char *pipeno = malloc(sz);
		strncpy(pipeno, (char *)start, sz);
		int fd = atoi(pipeno);
		lh_stdout_set(fd);
		return 0;
	} else {
		int fd = open(tty, O_RDWR);
		if(fd < 0) return -1;
		lh_stdout_set(fd);
		return 0;
	}
	return -1;
}

lh_r_process_t *lh_get_procinfo(int argc, char **argv){
	uintptr_t hdr = (uintptr_t)argv;
	
	uint32_t hdrSz = *(uint32_t *)(hdr + (sizeof(char *) * argc));
	LH_PRINT("hdrSz: %zu", hdrSz);
	if(hdrSz == 0){
		LH_PRINT("No extended header found");
		return NULL;
	}

	lh_r_process_t *proc = (lh_r_process_t *)(hdr + hdrSz);
	if(strncmp(proc->magic, "LHFO", sizeof(proc->magic)) != 0) //check the magic
		return NULL;

	/*proc->argv = argv;
	proc->prog_argv = (char **)(hdr + (sizeof(char *) * argc) + sizeof(hdrSz));*/

	if(proc->lh_verbose > 3){
		LH_PRINT("hdrSz: %d\n", hdrSz);
		lh_hexdump("hdr", proc, sizeof(*proc));
	}
	return proc;
}
