/*
 * Copyright (c) 2015 Smx
 * Copyright (c) 2011 Roman Tokarev <roman.s.tokarev@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *        notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *        notice, this list of conditions and the following disclaimer in the
 *        documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the author nor the names of any co-contributors
 *        may be used to endorse or promote products derived from this software
 *        without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY CONTRIBUTORS ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <dlfcn.h>
#include "helpers/lh_inject.h"
#include "lh_common.h"

int (*real_main)(int, char **, char **);

int fake_main(int argc, char **argv, char **envp){
	LH_PRINT("Hello there!\n");

	// Make sure we don't propagate LD_PRELOAD
	unsetenv("LD_PRELOAD");

	int orig_argc = argc - 1, i;
	for(i=argc-1; i>=0; i--, orig_argc--){
		if(!strcmp(argv[i], "--"))
			break;
	}

	if(orig_argc <= 1 || orig_argc >= argc){
		LH_ERROR("-- not specified\n");
		return 1;
	}

	char *libraryPath = NULL;
	int libArgvIdx = 0;
	
	for(int i=0; i<argc; i++){
		printf("=> %s\n", argv[i]);
	}

	lh_verbose = strtoul(&argv[1][2], NULL, 10);
	
	libraryPath = argv[2];
	libArgvIdx = 2;
	
	if(libraryPath == NULL){
		LH_ERROR("Invalid library argument!");
		return 1;
	}
	
	int num_args = orig_argc - libArgvIdx;
	
	size_t procmemSz = 0;
	for(i=libArgvIdx; i<libArgvIdx + num_args; i++){
		procmemSz += sizeof(char *);
	}
	procmemSz += sizeof(size_t);

	uintptr_t procmem = (uintptr_t)calloc(1, procmemSz);
	uintptr_t p = procmem;
	for(i=libArgvIdx; i<libArgvIdx + num_args; i++){
		*(uintptr_t *)p = argv[i];
		p += sizeof(char *);
	}
	// no header
	*(size_t *)p = 0;
	
	int ret = inj_inject_library(libraryPath, orig_argc - libArgvIdx, (char **)procmem, NULL);
	LH_PRINT("inj_inject_library() => %d\n", ret);
	
	//free(procmem);
	return real_main(argc - orig_argc, &argv[orig_argc], envp);


	return real_main(argc, argv, envp);
}

int __libc_start_main(int (* main)(int, char **, char **), int argc, char **ubp_av,
				void (* init)(void), void (* fini)(void),
				void (* rtld_fini)(void), void *stack_end)
{
	int (* __real___libc_start_main)(int (* main)(int, char **, char **), int argc, char **ubp_av,
				void (* init)(void), void (* fini)(void),
				void (* rtld_fini)(void), void *stack_end);
	__real___libc_start_main = dlsym(RTLD_NEXT, "__libc_start_main");
	if(__real___libc_start_main <= 0){
		LH_ERROR_SE("dlsym");
		_exit(EXIT_FAILURE);
	}

	real_main = main;
	return __real___libc_start_main(&fake_main, argc, ubp_av, init,
		fini, rtld_fini, stack_end);
}
