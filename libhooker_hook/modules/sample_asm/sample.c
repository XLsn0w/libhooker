#include <stdio.h>
#include "helpers/lh_base.h"
#include "lh_module.h"
#include <sys/mman.h>
#include <dlfcn.h>
#include <signal.h>

#include "sample.h"

void (*original_test_function) (int a, char *b);

void hooked_autoinit_post(lh_r_process_t * proc) {
	LH_PRINT("This function is called after the wanted functions are hooked.");
}

static void onSigSegv(int signum){
	raise(SIGSTOP);
}

void installHandler(){
	struct sigaction sa;
	sa.sa_handler = onSigSegv;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGSEGV, &sa, NULL) == -1){
		LH_PRINT("CANNOT SET SIGSEGV HANDLER!");
	}
}


int hooked_autoinit(int argc, char **argv) {
	lh_r_process_t *proc = lh_get_procinfo(argc, argv);
	original_test_function = NULL;

	installHandler();

	LH_PRINT("");
	LH_PRINT("");
	LH_PRINT("");
	LH_PRINT("This function is intended to autorun at each time being injected to an executable.");
	LH_PRINT("At this time, we were injected into: %u (%s)", proc->pid, proc->prog_argv[0]);
	LH_PRINT("Arguments: %d", argc);
	int i;
	for(i=0; i<argc; i++)
		LH_PRINT("ModArg %d => %s", i, argv[i]);
	for(i=0; i<proc->prog_argc; i++)
		LH_PRINT("ProgArg %d => %s", i, proc->prog_argv[i]);
	LH_PRINT("exe path => %s", proc->exename);
	LH_PRINT("");
	LH_PRINT("");
	LH_PRINT("");
	return LH_SUCCESS;
}

int hooked_otherfunction(int a, char *s) {
	LH_PRINT("Okay, other function is hooked too. %d, %s", a, s);
	// we dont call the original here.

	return 1;
}

lh_hook_t hook_settings = {
	.version = 1,
	.autoinit_pre = hooked_autoinit,
	.autoinit_post = hooked_autoinit_post,
	.fn_hooks =
	{
		{
			.hook_kind = LHM_FN_HOOK_BY_NAME,
			.libname = "",	// hook the main executable
			.symname = "otherfunction",
			.hook_fn = (uintptr_t) hooked_otherfunction,
			.orig_function_ptr = 0,

		},
		{
			.hook_kind = LHM_FN_HOOK_BY_NAME,
			.libname = "",
			.symname = "testfunction",
			.hook_fn = (uintptr_t) hooked_testfunction,
			.orig_function_ptr = (uintptr_t) & original_test_function, //save the original function address to "original_test_function"
		},
		{
			.hook_kind = LHM_FN_HOOK_TRAILING
		}
	}
};
