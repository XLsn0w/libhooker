#ifndef __LH_HELPER_BASE_H
#define __LH_HELPER_BASE_H
#include <stdint.h>
#include "interface/inject_types.h"

const char *addr2sym(uintptr_t addr);
lh_r_process_t *lh_get_procinfo(int argc, char **argv);
int lh_get_stdout(char *tty);
void lh_printf(const char *fmt, ...);
void lh_stdout_clear();
int lh_stdout_getcurrent();
void lh_stdout_set(int fd);
void lh_vaprintf(const char *fmt, va_list ap);
void lhm_hexdump(uintptr_t address, size_t size);
void *lhm_malloc(size_t size);
uintptr_t lhm_memcpy(uintptr_t dst_address, uintptr_t src_address);
uintptr_t lhm_mmap(uintptr_t address, size_t size);
int lhm_munmap(uintptr_t address, size_t size);
#endif
