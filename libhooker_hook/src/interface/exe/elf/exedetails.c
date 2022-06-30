/*
 * hotpatch is a dll injection strategy.
 * Copyright (c) 2010-2011, Vikas Naresh Kumar, Selective Intellect LLC
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 *	 notice, this list of conditions and the following disclaimer in the
 *	 documentation and/or other materials provided with the distribution.
 *
 * * Neither the name of Selective Intellect LLC nor the
 *   names of its contributors may be used to endorse or promote products
 *   derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>
#include "interface/exe/linux_elf.h"
#include "elf_types.h"

enum {
	HOTPATCH_SYMBOL_TYPE,
	HOTPATCH_UNKNOWN
};

struct elf_internals {
	int fd;
	enum elf_bit is64;
	off_t proghdr_offset;
	void *proghdrs;				/* program headers */
	size_t proghdr_num;
	size_t proghdr_size;		/* total buffer size */
	off_t sechdr_offset;
	void *sechdrs;				/* section headers */
	size_t sechdr_num;
	size_t sechdr_size;			/* total buffer size */
	size_t secnametbl_idx;
	char *strsectbl;			/* string table for section names */
	size_t strsectbl_size;
	/*
	 * stored here temporarily, should not be freed unless on failure.
	 */
	uintptr_t entry_point;
	struct elf_symbol *symbols;
	size_t symbols_num;
	struct elf_interp interp;
};

/* each of the exe_* functions have to be reentrant and thread-safe */
static int exe_get_hotpatch_type(int info, int group) {
	if (group == HOTPATCH_SYMBOL_TYPE) {
		int value = ELF64_ST_TYPE(info);
		if (value == STT_FUNC)
			return HOTPATCH_SYMBOL_IS_FUNCTION;
		else if (value == STT_FILE)
			return HOTPATCH_SYMBOL_IS_FILENAME;
		else if (value == STT_SECTION)
			return HOTPATCH_SYMBOL_IS_SECTION;
		else if (value == STT_OBJECT)
			return HOTPATCH_SYMBOL_IS_OBJECT;
		else
			return HOTPATCH_SYMBOL_IS_UNKNOWN;
	}
	return -1;
}

static int exe_open_filename(const char *filename) {
	int fd = -1;
	fd = open(filename, O_RDONLY);
	if (fd < 0)
		LH_ERROR("open");

	LH_VERBOSE(3, "Exe file descriptor: %d", fd);

	return fd;
}

static int exe_elf_identify(unsigned char *e_ident, size_t size) {
	if (e_ident && size > 0) {
		if ((e_ident[EI_MAG0] == ELFMAG0) && (e_ident[EI_MAG1] == ELFMAG1) && (e_ident[EI_MAG2] == ELFMAG2) && (e_ident[EI_MAG3] == ELFMAG3)) {
			int is64 = HOTPATCH_EXE_IS_NEITHER;
			/* magic number says this is an ELF file */
			switch (e_ident[EI_CLASS]) {
			case ELFCLASS32:
				is64 = HOTPATCH_EXE_IS_32BIT;
				LH_VERBOSE(3, "File is 32-bit ELF");
				break;
			case ELFCLASS64:
				is64 = HOTPATCH_EXE_IS_64BIT;
				LH_VERBOSE(3, "File is 64-bit ELF");
				break;
			case ELFCLASSNONE:
			default:
				is64 = HOTPATCH_EXE_IS_NEITHER;
				LH_ERROR("File is unsupported ELF");
				break;
			}
			if (is64 != HOTPATCH_EXE_IS_NEITHER) {
				int isbigendian = -1;
				int iscurrent = 0;
				int islinux = 0;
				switch (e_ident[EI_DATA]) {
				case ELFDATA2LSB:
					isbigendian = 0;
					LH_VERBOSE(3, "Little endian format.");
					break;
				case ELFDATA2MSB:
					isbigendian = 1;
					LH_VERBOSE(3, "Big endian format.");
					break;
				case ELFDATANONE:
				default:
					isbigendian = -1;
					LH_ERROR("Unknown endian format.");
					break;
				}
				if (e_ident[EI_VERSION] == EV_CURRENT) {
					iscurrent = 1;
					LH_VERBOSE(3, "Current ELF format.");
				}
				LH_VERBOSE(3, "ELFOSABI: %d", e_ident[EI_OSABI]);
				if (e_ident[EI_OSABI] == ELFOSABI_LINUX || e_ident[EI_OSABI] == ELFOSABI_SYSV) {
					islinux = 1;
					LH_VERBOSE(3, "OS ABI is Linux.");
				}
				if (e_ident[EI_OSABI] == ELFOSABI_FREEBSD) {
					islinux = 1;
					LH_VERBOSE(3, "OS ABI is FreeBSD.");
				}
				if (e_ident[EI_OSABI] == ELFOSABI_OPENBSD) {
					islinux = 1;
					LH_VERBOSE(3, "OS ABI is OpenBSD.");
				}
				if (e_ident[EI_OSABI] == ELFOSABI_NETBSD) {
					islinux = 1;
					LH_VERBOSE(3, "OS ABI is NetBSD.");
				}
				if (e_ident[EI_OSABI] == ELFOSABI_ARM) {
					islinux = 1;
					LH_VERBOSE(3, "OS ABI is ARM.");
				}
				#ifdef __FreeBSD__
				if (e_ident[EI_OSABI] == ELFOSABI_AROS) {
					islinux = 1;
					LH_VERBOSE(3, "OS ABI is Amiga Research OS.");
				}
				#endif
				if (e_ident[EI_OSABI] == ELFOSABI_SOLARIS) {
					islinux = 1;
					LH_VERBOSE(3, "OS ABI is SunOS/Solaris.");
				}
				if (islinux && isbigendian == 0 && iscurrent) {
					return is64;
				}
				LH_ERROR("Not an acceptable header.");
			}
		} else {
			LH_ERROR("This is not an ELF file format.");
		}
	}
	return HOTPATCH_EXE_IS_NEITHER;
}

static int exe_load_symbol_table(struct elf_internals *ei, Elf_Shdr * symh, Elf_Shdr * strh) {
	char *strsymtbl = NULL;
	size_t strsymtbl_size = 0;
	while (ei && symh && strh) {
		LH_VERBOSE(3, "Retrieving symbol table.");
		if (lseek(ei->fd, strh->sh_offset, SEEK_SET) < 0) {
			LH_ERROR_SE("lseek");
			break;
		}
		strsymtbl_size = strh->sh_size + 0;
		if (strsymtbl_size == 0) {
			LH_ERROR("strsymtbl_size == 0");
			break;
		}
		strsymtbl = malloc(strh->sh_size);
		if (!strsymtbl) {
			LH_ERROR_SE("malloc");
			break;
		}
		if (read(ei->fd, strsymtbl, strh->sh_size) < 0) {
			LH_ERROR_SE("read");
			break;
		}
		if (symh->sh_entsize > 0 && symh->sh_size > 0) {
			size_t idx;
			size_t sym_num = symh->sh_size / symh->sh_entsize;
			Elf_Sym *syms = malloc(symh->sh_size);
			if (!syms) {
				LH_ERROR_SE("malloc");
				break;
			}
			if (lseek(ei->fd, symh->sh_offset, SEEK_SET) < 0) {
				LH_ERROR_SE("lseek");
				free(syms);
				break;
			}
			if (read(ei->fd, syms, symh->sh_size) < 0) {
				LH_ERROR_SE("read");
				free(syms);
				break;
			}
			/* there might already exist symbols from another section.
			 * hence using realloc() takes care of that.
			 * */
			ei->symbols = realloc(ei->symbols, (sym_num + ei->symbols_num) * sizeof(*ei->symbols));
			if (!ei->symbols) {
				LH_ERROR_SE("malloc");
				break;
			}
			memset(&ei->symbols[ei->symbols_num], 0, sizeof(*ei->symbols) * sym_num);
			/* index 0 is always NULL */
			for (idx = 1; idx < sym_num; ++idx) {
				const char *name = syms[idx].st_name > 0 ? &strsymtbl[syms[idx].st_name] : "";
				if (name) {
					char *name2;
					int symtype = exe_get_hotpatch_type(syms[idx].st_info,
														HOTPATCH_SYMBOL_TYPE);
					LH_VERBOSE(5, "Symbol " LU " is %s at %p type %d size " LU, idx, name, (void *)syms[idx].st_value, symtype, syms[idx].st_size);
					name2 = strdup(name);
					if (!name2) {
						LH_ERROR_SE("malloc");
						continue;
					}
					ei->symbols[ei->symbols_num].name = name2;
					ei->symbols[ei->symbols_num].address = (uintptr_t) syms[idx].st_value;
					ei->symbols[ei->symbols_num].size = (size_t) syms[idx].st_size;
					ei->symbols[ei->symbols_num].type = symtype;
					ei->symbols_num++;
				}
			}
			free(syms);
			if (strsymtbl)
				free(strsymtbl);
			return 0;
		}
	}
	if (strsymtbl)
		free(strsymtbl);
	return -1;
}

static int exe_load_section_headers(struct elf_internals *ei) {
	Elf_Shdr *strsectblhdr = NULL;
	Elf_Shdr *sechdrs = NULL;
	size_t idx = 0;
	ssize_t symtab = -1;
	ssize_t strtab = -1;

	if (!ei || ei->sechdr_offset == 0 || ei->sechdr_size == 0)
		return -1;
	LH_VERBOSE(2, "Retrieving section headers.");
	ei->sechdrs = malloc(ei->sechdr_size);
	if (!ei->sechdrs) {
		LH_ERROR_SE("malloc");
		return -1;
	}
	memset(ei->sechdrs, 0, ei->sechdr_size);
	LH_VERBOSE(2, "Reading section header offset at " LU, (size_t) ei->sechdr_offset);
	if (lseek(ei->fd, ei->sechdr_offset, SEEK_SET) < 0) {
		LH_ERROR_SE("lseek");
		return -1;
	}
	if (read(ei->fd, ei->sechdrs, ei->sechdr_size) < 0) {
		LH_ERROR_SE("read");
		return -1;
	}
	sechdrs = (Elf_Shdr *) ei->sechdrs;
	strsectblhdr = &sechdrs[ei->secnametbl_idx];
	if (lseek(ei->fd, strsectblhdr->sh_offset, SEEK_SET) < 0) {
		LH_ERROR_SE("lseek");
		return -1;
	}
	ei->strsectbl = malloc(strsectblhdr->sh_size);
	if (!ei->strsectbl) {
		LH_ERROR_SE("malloc");
		return -1;
	}
	ei->strsectbl_size = strsectblhdr->sh_size + 0;
	if (read(ei->fd, ei->strsectbl, strsectblhdr->sh_size) < 0) {
		LH_ERROR_SE("read");
		return -1;
	}
	LH_VERBOSE(2, "Number of sections: " LU, ei->sechdr_num);
	for (idx = 0; idx < ei->sechdr_num; ++idx) {
		const char *name = &ei->strsectbl[sechdrs[idx].sh_name];
		if (name)
			LH_VERBOSE(4, "Section name: %s Addr: %p Len: " LU, name, (void *)sechdrs[idx].sh_offset, sechdrs[idx].sh_size);
		else
			LH_VERBOSE(4, "Section name: %s Addr: %p Len: " LU, "N/A", (void *)sechdrs[idx].sh_offset, sechdrs[idx].sh_size);

		switch (sechdrs[idx].sh_type) {
		case SHT_SYMTAB:
		case SHT_DYNSYM:
			symtab = idx;
			LH_VERBOSE(3, "Symbol table offset: " LU " size: " LU " " "entsize: " LU " entries: " LU, sechdrs[idx].sh_offset, sechdrs[idx].sh_size, sechdrs[idx].sh_entsize, (sechdrs[idx].sh_entsize > 0 ? sechdrs[idx].sh_size / sechdrs[idx].sh_entsize : 0));
			break;
		case SHT_STRTAB:
			if (idx != ei->secnametbl_idx) {
				strtab = idx;
				LH_VERBOSE(3, "Reading symbol table from %s", name);
				if (symtab >= 0 && exe_load_symbol_table(ei, &sechdrs[symtab], &sechdrs[strtab]) < 0) {
					LH_ERROR("Failed to retrieve symbol table.");
				}
				symtab = -1;
			}
			break;
		default:
			break;
		}
	}
	return 0;
}

static int exe_load_program_headers(struct elf_internals *ei) {
	Elf_Phdr *proghdrs = NULL;
	size_t idx = 0;
	int rc = 0;
	if (!ei || ei->proghdr_offset == 0 || ei->proghdr_size == 0)
		return -1;
	ei->proghdrs = malloc(ei->proghdr_size);
	if (!ei->proghdrs) {
		LH_ERROR_SE("malloc");
		return -1;
	}
	memset(ei->proghdrs, 0, ei->proghdr_size);
	if (lseek(ei->fd, ei->proghdr_offset, SEEK_SET) < 0) {
		LH_ERROR_SE("lseek");
		return -1;
	}
	if (read(ei->fd, ei->proghdrs, ei->proghdr_size) < 0) {
		LH_ERROR_SE("read");
		return -1;
	}
	LH_VERBOSE(2, "Number of segments: " LU, ei->proghdr_num);
	proghdrs = (Elf_Phdr *) ei->proghdrs;
	for (idx = 0; idx < ei->proghdr_num; ++idx) {
		rc = 0;
		LH_VERBOSE(4, "Prog-header " LU ": Type: %d " "VAddr: %p PAddr: %p FileSz: " LU " MemSz: " LU, idx, proghdrs[idx].p_type, (void *)proghdrs[idx].p_vaddr, (void *)proghdrs[idx].p_paddr, proghdrs[idx].p_filesz, proghdrs[idx].p_memsz);

		if (proghdrs[idx].p_type == PT_INTERP) {
			LH_VERBOSE(1, "PT_INTERP section found");
			if (proghdrs[idx].p_filesz == 0)
				continue;
			if (lseek(ei->fd, proghdrs[idx].p_offset, SEEK_SET) < 0) {
				LH_ERROR_SE("lseek");
				rc = -1;
				break;
			}
			if (ei->interp.name) {
				free(ei->interp.name);
				memset(&ei->interp, 0, sizeof(ei->interp));
			}
			ei->interp.name = malloc(proghdrs[idx].p_filesz);
			if (!ei->interp.name) {
				LH_ERROR_SE("malloc");
				rc = -1;
				break;
			}
			if (read(ei->fd, ei->interp.name, proghdrs[idx].p_filesz) < 0) {
				LH_ERROR_SE("read");
				rc = -1;
				break;
			}
			ei->interp.length = proghdrs[idx].p_filesz;
			ei->interp.ph_addr = proghdrs[idx].p_vaddr;
			LH_VERBOSE(1, "Found %s at V-Addr 0x" LX, ei->interp.name, ei->interp.ph_addr);
		} else if (proghdrs[idx].p_type == PT_DYNAMIC) {
			LH_VERBOSE(2, "PT_DYNAMIC section found");
		} else if (proghdrs[idx].p_type == PT_LOAD) {
			LH_VERBOSE(2, "PT_LOAD section found");
		}
	}
	return rc;
}

static int exe_load_headers(struct elf_internals *ei) {
	Elf_Ehdr hdr;
	int fd = -1;
	if (!ei) {
		return -1;
	}
	fd = ei->fd;
	memset(&hdr, 0, sizeof(hdr));
	if (lseek(fd, 0, SEEK_SET) < 0) {
		LH_ERROR_SE("lseek");
		return -1;
	}
	if (read(fd, &hdr, sizeof(hdr)) < 0) {
		LH_ERROR_SE("read");
		return -1;
	}
	LH_VERBOSE(2, "Reading Elf header.");
	ei->is64 = exe_elf_identify(hdr.e_ident, EI_NIDENT);
	switch (ei->is64) {
	case HOTPATCH_EXE_IS_64BIT:
		LH_VERBOSE(2, "64-bit valid exe");
		break;
	case HOTPATCH_EXE_IS_32BIT:
		LH_VERBOSE(2, "32-bit valid exe");
		break;
	case HOTPATCH_EXE_IS_NEITHER:
	default:
		return -1;
	}
	LH_VERBOSE(1, "Entry point %p", (void *)hdr.e_entry);
	ei->entry_point = (uintptr_t) hdr.e_entry;
/*
// we do not filter on the architecture anymore
	if (hdr.e_machine != EM_X86_64 && hdr.e_machine != EM_386) {
		LOG_ERROR_UNSUPPORTED_PROCESSOR;
		return -1;
	}
*/
	if (hdr.e_shoff > 0) {
		ei->sechdr_offset = 0 + hdr.e_shoff;
		ei->sechdr_num = 0 + hdr.e_shnum;
		ei->sechdr_size = 0 + hdr.e_shnum * hdr.e_shentsize;
		ei->secnametbl_idx = 0 + hdr.e_shstrndx;
	}
	if (hdr.e_phoff > 0) {
		ei->proghdr_offset = 0 + hdr.e_phoff;
		ei->proghdr_num = 0 + hdr.e_phnum;
		ei->proghdr_size = 0 + hdr.e_phnum * hdr.e_phentsize;
	}
	if (exe_load_section_headers(ei) < 0) {
		LH_ERROR("Error in loading section headers");
		return -1;
	}
	if (exe_load_program_headers(ei) < 0) {
		LH_ERROR("Error in loading section headers");
		return -1;
	}
	return 0;
}

struct elf_symbol *exe_load_symbols(const char *filename, size_t * symbols_num, uintptr_t * entry_point, struct elf_interp *interp, enum elf_bit *is64) {
	int rc = 0;
	struct elf_symbol *symbols = NULL;
	struct elf_internals ei;
	memset(&ei, 0, sizeof(ei));
	if (entry_point)
		*entry_point = 0;
	ei.fd = exe_open_filename(filename);
	if (ei.fd < 0) {
		return NULL;
	}
	if ((rc = exe_load_headers(&ei)) < 0) {
		LH_PRINT("Unable to load Elf details for %s", filename);
	}
	LH_VERBOSE(4, "Freeing internal structure.");
	if (ei.fd >= 0)
		close(ei.fd);
	ei.fd = -1;
	ei.strsectbl_size = 0;
	if (ei.strsectbl) {
		free(ei.strsectbl);
		ei.strsectbl = NULL;
	}
	if (ei.sechdrs) {
		free(ei.sechdrs);
		ei.sechdrs = NULL;
	}
	if (ei.proghdrs) {
		free(ei.proghdrs);
		ei.proghdrs = NULL;
	}
	if (rc < 0) {
		if (ei.interp.name)
			free(ei.interp.name);
		ei.interp.name = NULL;
		if (ei.symbols) {
			size_t idx;
			for (idx = 0; idx < ei.symbols_num; ++idx) {
				free(ei.symbols[idx].name);
				ei.symbols[idx].name = NULL;
			}
			free(ei.symbols);
		}
		ei.symbols = NULL;
		ei.symbols_num = 0;
	} else {
		LH_VERBOSE(2, "Readying return values.");
		symbols = ei.symbols;
		if (symbols_num)
			*symbols_num = ei.symbols_num;
		if (interp) {
			interp->name = ei.interp.name;
			interp->length = ei.interp.length;
			interp->ph_addr = ei.interp.ph_addr;
		} else {
			if (ei.interp.name)
				free(ei.interp.name);
			ei.interp.name = NULL;
		}
		if (is64)
			*is64 = ei.is64;
		if (entry_point)
			*entry_point = ei.entry_point;
	}
	return symbols;
}

int elf_symbol_cmpqsort(const void *p1, const void *p2) {
	return strcmp(((const struct elf_symbol *)p1)->name, ((const struct elf_symbol *)p2)->name);
}
