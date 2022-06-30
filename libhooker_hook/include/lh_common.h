/*
 * Stuff.
 *
 */

#ifndef __LH_COMMON_H
#    define __LH_COMMON_H

#    if __x86_64__
#    elif __i386__
#    elif __arm__
#    else
#        error Unsupported architecture!
#    endif

#    include <stdint.h>
#    include <stdbool.h>
#    include <unistd.h>
#    include "interface/if_os.h"
#    include <string.h>
#    include <sys/stat.h>
#ifdef __linux__
#    include <linux/limits.h>
#endif
#    include <errno.h>

#    define LH_SUCCESS 0
#    define LH_FAILURE 1

extern int lh_verbose;
void lh_print(int verbose, int newline, char *fn, int lineno, const char *fmt, ...);
void lh_hexdump(char *desc, void *addr, int len);

char *lh_basename(const char *path);
char *lh_dirname(const char *path);

char *readlink_safe(char *path);

#    define WHEREARG  __FILE__, __LINE__
#    define LH_PRINT(...) lh_print(0,1, WHEREARG, __VA_ARGS__)
#    define LH_VERBOSE(N,...) lh_print(N,1, WHEREARG, __VA_ARGS__)
#    define LH_VERBOSE_NN(N,...) lh_print(N,0, WHEREARG, __VA_ARGS__)
#    define LH_ERROR_SE(fmt, ...) lh_print(0, 1, WHEREARG, "ERROR: "fmt" (%s)", ## __VA_ARGS__, strerror(errno))
#    define LH_ERROR(...) lh_print(0, 1, WHEREARG, "ERROR: " __VA_ARGS__)

#    if __WORDSIZE == 64
#        define LX "%lx"
#        define LLX LX
#        define LU "%lu"
#    else
#        define LX "%x"
#        define LLX "%llx"
#        define LU "%u"
#    endif

#ifdef __FreeBSD__
#define SYM_DLCLOSE	"dlclose"
#define SYM_DLOPEN_MODE	"_rtld_is_dlopened"
#define SYM_DLSYM	"dlsym"
#else
#define SYM_DLCLOSE	"__libc_dlclose"
#define SYM_DLOPEN_MODE	"__libc_dlopen_mode"
#define SYM_DLSYM	"__libc_dlsym"
#endif

#endif
