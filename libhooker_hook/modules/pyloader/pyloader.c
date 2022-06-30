#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <libgen.h>
#include <fcntl.h>
#include <dlfcn.h>
#include "helpers/lh_base.h"
#include "lh_module.h"

void hook_exit(lh_r_process_t * proc) {
	printf("hook_main finished\n");
}

static char pyProgramName[255];

//#define RESET_STDOUT
//#define REDIRECT_STDOUT

int hook_main(int argc, char **argv) {
	lh_r_process_t *rproc = lh_get_procinfo(argc, argv);
	lh_get_stdout(rproc->ttyName);

	lh_printf("argc: %d\n", argc);

	bool redirectStdOut = false;
	if(argc > 4){
		lh_printf("enableRedirection: %s\n", argv[4]);
		if(*argv[4] == 'y'){
			redirectStdOut = true;
		}
	}

	if(redirectStdOut){
		int ptyFd = open(rproc->ttyName, O_WRONLY);
		if(ptyFd <= 0){
			lh_printf("Failed to open PTY\n");
		} else {
			lh_printf("REDIRECT FILE HANDLES\n");
			//dup2(ptyFd, STDIN_FILENO);
			dup2(ptyFd, STDOUT_FILENO);
			dup2(ptyFd, STDERR_FILENO);
			close(ptyFd);
			printf("HI FROM NEW HANDLES\n");
		}
	}

	char *pyLibrary = argv[1];
	char *pyPrefix = argv[2];
	/*char *pyLibsPath = argv[3];
	char *pyHome = argv[4];*/
	char *pyScript = argv[3];

	lh_printf("HELLO WORLD\n");
	lh_printf("Python Prefix: %s\n", pyPrefix);

	{
		lh_printf("Set PYTHONHOME\n");
		setenv("PYTHONHOME", pyPrefix, 1);

		char *env;
		lh_printf("Set PYTHONPATH\n");
		asprintf(&env, "%s/lib", pyPrefix);
		setenv("PYTHONPATH", env, 1);
		free(env); env = NULL;
	}

	char *ldlib = getenv("LD_LIBRARY_PATH");
	if(ldlib == NULL || strstr(ldlib, pyPrefix) == NULL)
	{
		char *tmp;
		if(ldlib == NULL){
			asprintf(&tmp, "LD_LIBRARY_PATH=%s/lib", pyPrefix);
			lh_printf("Setting %s\n", tmp);
		} else {
			asprintf(&tmp, "LD_LIBRARY_PATH=%s:%s/lib", ldlib, pyPrefix);
			lh_printf("Appending %s -> %s\n", pyPrefix, tmp);
		}
		putenv(tmp);
		free(tmp);
	}


	char *curPath = getenv("PATH");
	lh_printf("PATH is %s\n", curPath);
	if(0){
		lh_printf("Appending to PATH\n");

		char *tPath;
		asprintf(&tPath, "%s:%s/bin", curPath, pyPrefix);
		setenv("PATH", tPath, 1);
		free(tPath);
	}


	int closedPrev = 0;

	do_reload:;
	void *libpython = dlopen(pyLibrary, RTLD_NOW | RTLD_GLOBAL);
	if(libpython == NULL){
		lh_printf("dlopen failed: %s\n", dlerror());
		return LH_SUCCESS;
	} else if(closedPrev == 0) {
		dlclose(libpython);
		closedPrev = 1;
		goto do_reload;
	}

	void (*Py_SetProgramName)(char *) = dlsym(libpython, "Py_SetProgramName");
	void (*Py_SetPythonHome)(char *) = dlsym(libpython, "Py_SetPythonHome");
	void (*Py_Initialize)(void) = dlsym(libpython, "Py_Initialize");
	void (*PyEval_InitThreads)(void) = dlsym(libpython, "PyEval_InitThreads");
	void (*PyRun_SimpleString)(char *) = dlsym(libpython, "PyRun_SimpleString");
	void (*Py_Finalize)(void) = dlsym(libpython, "Py_Finalize");
	void (*Py_InitializeEx)(int) = dlsym(libpython, "Py_InitializeEx");
	int (*Py_IsInitialized)(void) = dlsym(libpython, "Py_IsInitialized");

	if(Py_SetProgramName == NULL || Py_SetPythonHome == NULL || Py_Initialize == NULL || PyEval_InitThreads == NULL || PyRun_SimpleString == NULL || Py_Finalize == NULL){
		lh_printf("Symbols not found\n");
		return LH_SUCCESS;
	}

	char *tmp1 = strdup(pyScript);
	char *tmp2 = strdup(pyScript);

	char *scriptDir = dirname(tmp1);
	char *lastdot = strrchr(tmp2, '.');
	*lastdot = '\0';

	char *scriptName = basename(tmp2);

	lh_printf("Script: %s\n", pyScript);
	lh_printf("ScriptDir: %s, Filename: %s\n", scriptDir, scriptName);

	if(Py_IsInitialized()){
		lh_printf("Python already initialized, destroy it!\n");
		Py_Finalize();
	}
	
	lh_printf("Initialize... (%s)\n", pyScript);

	Py_SetPythonHome(pyPrefix);

	PyEval_InitThreads();

	memset(pyProgramName, 0x00, sizeof(pyProgramName));
	snprintf(pyProgramName, sizeof(pyProgramName), "%s/bin/python", pyPrefix);
	Py_SetProgramName(pyProgramName);

	lh_printf("Calling Py_Initialize...\n");
	Py_Initialize();

	char *pyCode;
	asprintf(&pyCode, "import sys\nsys.path.append(\"%s\")\nimport %s\n", scriptDir, scriptName);
	lh_printf("RUNNING: %s\n", pyCode);
	PyRun_SimpleString(pyCode);
	Py_Finalize();


	free(tmp1);
	free(tmp2);
	free(pyCode);
	lh_printf("DONE!\n");
	return LH_SUCCESS;
}

lh_hook_t hook_settings = {
	.version = 1,
	.autoinit_pre = hook_main,
	.autoinit_post = hook_exit,
	.fn_hooks =
	{
		{
			.hook_kind = LHM_FN_HOOK_TRAILING
		}
	}
};
