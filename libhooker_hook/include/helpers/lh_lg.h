#ifndef __LH_HELPER_LG_H
#define __LH_HELPER_LG_H

void *sym2addr(const char *name);
uintptr_t symfile_addr_by_name(const char *name);
int symfile_load(const char *fname);
const char *symfile_name_by_addr(uintptr_t addr);

#endif
