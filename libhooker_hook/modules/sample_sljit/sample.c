#include <stdio.h>
#include "helpers/lh_base.h"
#include "helpers/lh_inject.h"
#include "helpers/lh_sljit.h"
#include "lh_module.h"

#include <dlfcn.h>
#include <sys/mman.h>
#include <signal.h>

void (*original_test_function) (int a, char *b);

void installHooks(){
	void *sljit_code = NULL;
	struct sljit_compiler *compiler = NULL;

	/* Uncomment to call the original */
	/*
	void (*f)(int, char*) = (void (*)(int a, char *b))original_test_function;
	f(1, "test");
	*/

	void *origCode = inj_build_payload_user(&(hook_settings.fn_hooks[1]), (uintptr_t)original_test_function, NULL);
	if(!origCode){
		LH_ERROR("Cannot build the payload!");
		return;
	}

	compiler = sljit_create_compiler(NULL);
	if(!compiler){
		LH_ERROR("Unable to create sljit compiler instance");
		return;
	}

	/*
		Simple routine that returns 1337
	*/
	#if 0
	sljit_emit_ijump(compiler, SLJIT_JUMP, SLJIT_IMM, (sljit_sw)origCode);
	#else
	sljit_emit_enter(compiler, 0, 0, 0, 0, 0, 0, 0);
	sljit_emit_op1(compiler, SLJIT_MOV, SLJIT_RETURN_REG, 0, SLJIT_IMM, 1337);
	sljit_emit_return(compiler, SLJIT_MOV, SLJIT_RETURN_REG, 1337);
	#endif

	sljit_code = sljit_generate_code(compiler);
	if(!sljit_code){
		LH_ERROR("Unable to build JIT Code");
	}

	if(compiler)
		sljit_free_compiler(compiler);

	lh_hexdump("JIT code", sljit_code, compiler->size);
	/* Set the code we just generated as the replacement */
	hook_settings.fn_hooks[1].hook_fn = (uintptr_t)sljit_code;
	LH_PRINT("Injecting to "LX"", original_test_function);

	inj_inject_payload(&(hook_settings.fn_hooks[1]), (uintptr_t)original_test_function);
}

void hooked_autoinit_post(lh_r_process_t * proc) {
	installHooks();
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
	if(proc){
		LH_PRINT("At this time, we were injected into: %u (%s)", proc->pid, proc->prog_argv[0]);
	}
	LH_PRINT("Arguments: %d", argc);
	int i;
	for(i=0; i<argc; i++)
		LH_PRINT("ModArg %d => %s", i, argv[i]);
	if(proc){
		for(i=0; i<proc->prog_argc; i++){
			LH_PRINT("ProgArg %d => %s", i, proc->prog_argv[i]);
		}
		LH_PRINT("exe path => %s", proc->exename);
	}
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

int hooked_testfunction(int a, char *s) {
	LH_PRINT("We are in the hooked test function! %d %s", a, s);
	LH_PRINT("Lets call the original one with new parameters @0x" LX, original_test_function);
	original_test_function(12345, "_____________________ IS THERE ANYBODY IN THERE?");
	LH_PRINT("Good, hah?\n\n");
	return 0;
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
			.hook_fn = (uintptr_t) 0,
			.orig_function_ptr = (uintptr_t) & original_test_function, //save the original function address to "original_test_function"
		},
		{
			.hook_kind = LHM_FN_HOOK_TRAILING
		}
	}
};

/*
//--------------------------------------------------------------- dont care about these ones, was just testing
  LH_PRINT("Right before calling otherfunction()");
  otherfunction(1, proc->exename);

  void (*of)(int a, char*b);
  of = (void*) 0x00000000004006b1;
  of(1, proc->exename);
  LH_PRINT("Otherfunction() is theoritically called");

  void* addr = (void*)0x00400000;
  if (mprotect(addr, 0x01000, PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
    LH_PRINT("Page successfully modified made writeable");
  } else {
    LH_PRINT("couldnt modify page protection");
  }
*/
