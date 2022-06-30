#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <stdarg.h>
#include <ctype.h>

#if defined(__linux__) || defined(__FreeBSD__)
#include <sched.h>
#include <signal.h>
#include <sys/resource.h>
#include <math.h>
#endif

#include "interface/if_inject.h"

#define APP_NAME "needle"
int g_optind_lib = 0, g_optind_exe = 0;
pid_t g_pid = 0;
int g_uid = -1, g_gid = -1;

uint64_t parse_address(const char *s) {
	if (0 == strncmp(s, "0x", 2))
		return strtoull(s, NULL, 0);
	return strtoull(s, NULL, 16);
}

int print_usage_and_quit(const char *errfmt, ...) {
	if (errfmt != NULL) {
		fprintf(stderr, "ERROR: ");

		va_list arglist;
		va_start(arglist, errfmt);
		vfprintf(stderr, errfmt, arglist);
		va_end(arglist);

		fprintf(stderr, "\n\n");
	}

	fprintf(stderr, "Hooker library, main injection tool\n\n");
	fprintf(stderr, "Usage:\n %s [-v level] pid ./library_to_inject.so [module args]\n", APP_NAME);
	fprintf(stderr, "or\n %s [-v level] [-u uid] [-g gid] './program_to_run args' ./library_to_inject.so [module args]\n", APP_NAME);
	fprintf(stderr, "   -v: verbose\n");
	fprintf(stderr, "   -e hex_memory_address: memory address for the injection\n");
	fprintf(stderr, "                      if not specified, main() will be used (if found)\n");
	fprintf(stderr, "\n");
	fprintf(stderr, " You can specify the pid of an already running process, or a program you want to run.\n");
	fprintf(stderr, " In the latter case, the program will be hooked on startup.\n");
	fprintf(stderr, "  You can specify the uid [-u uid] and gid [-g gid] to use for the newly created process.\n");
	return -3;

}

int parse_opts(int argc, char *argv[]) {
	if (argc == 1)
		return print_usage_and_quit(NULL);

	char c;
	while ((c = getopt(argc, argv, "v:u:g:")) != -1) {
		switch (c) {
		case 'v':
			lh_verbose = atoi(optarg);
			LH_VERBOSE(4, "verbose set to %d", lh_verbose);
			break;
		case 'u':
			g_uid = atoi(optarg);
			break;
		case 'g':
			g_gid = atoi(optarg);
			break;
		case '?':
			if (isprint(optopt))
				return print_usage_and_quit("Unknown option `-%c'.\n", optopt);
			else
				return print_usage_and_quit("Unknown option character `\\x%x'.", optopt);
		default:
			goto sogood;
			// return print_usage_and_quit("Invalid parameter?");
		}
	}

 sogood:
	if (argc == optind)
		return print_usage_and_quit("Missing pid or path to executable to run!");


	pid_t pid_val = atoi(argv[optind]);
	if (pid_val <= 0){
		g_optind_exe = optind;
	} else {
		g_pid = pid_val;
	}
	optind++;

#ifdef LH_PRELOAD
	g_pid = getpid();
	g_optind_exe = 0;
#endif

	if (argc == optind)
		return print_usage_and_quit("no libraries specified");

	g_optind_lib = optind;

	return LH_SUCCESS;
}

char *g_preload_path = NULL;
int runProc(void *arg){
	char **argv = (char **)arg;

	int ret;

	char *env_preload;
	asprintf(&env_preload, "LD_PRELOAD=%s", g_preload_path);

	LH_PRINT("LD_PRELOAD => '%s'", env_preload);

	//constant pointer to char array
	char * const envp[] = {
		env_preload,
		NULL
	};
	
	ptrace(PTRACE_TRACEME, 0, 0, 0);
	
	if((ret = execve(argv[0], argv, envp)) < 0){
		LH_ERROR_SE("execv");
		return ret;
	}

	return ret;
}

int main(int argc, char *argv[]){
	return needle_main(argc, argv);
}

int needle_main(int argc, char *argv[]) {
	int i;
	for(i=0; i<argc; i++){
		printf("NEEDLE[%u] => %s\n", i, argv[i]);
	}
	int re = LH_SUCCESS;

	char **prog_argv = NULL;
	do {
		if (LH_SUCCESS != (re = parse_opts(argc, argv)))
			break;

		//create a new session object
		lh_session_t *session = lh_alloc();
		if (session == NULL) {
			re = -6;
			break;
		}

		if(!g_pid){
			if(!g_optind_exe){
				print_usage_and_quit("Missing pid or path to executable to run!");
				return EXIT_FAILURE;
			} else {
				char *args = strdup(argv[g_optind_exe]);
				char *tok = strtok(args, " ");
				if(!tok || access(tok, F_OK) < 0){
					LH_ERROR("Executable '%s' does not exist!", tok);
					return EXIT_FAILURE;
				}

				
				char *needle_exe  = readlink_safe("/proc/self/exe");
				char *needle_dirn = lh_dirname(needle_exe);
						
				int opt_args = g_optind_exe + 2;
				opt_args += argc - (g_optind_exe + 1);
				
				//freed by lh_free
				prog_argv = calloc(opt_args, sizeof(char *));
				
				int child_arg_index = 0;
				
				prog_argv[child_arg_index++] = strdup(tok);
				for(int i=1; i<g_optind_exe; i++){
					prog_argv[child_arg_index++] = argv[i];
				}
				
				for(int i=g_optind_exe + 1; i<argc; i++){
					prog_argv[child_arg_index++] = argv[i];
				}			
				prog_argv[child_arg_index++] = "--";
				
				while((tok = strtok(NULL, " ")) != NULL){
					prog_argv[child_arg_index++] = strdup(tok);				
					prog_argv = realloc(prog_argv, sizeof(char *) * (child_arg_index + 1));
				}
				prog_argv[child_arg_index++] = NULL;
				
				for(int i=0; i<child_arg_index; i++){
					printf("=> %s\n", prog_argv[i]);
				}
				
				session->proc.prog_argc = child_arg_index;
				session->proc.prog_argv = prog_argv;

				if(!args){
					LH_ERROR_SE("strdup");
					return EXIT_FAILURE;
				}
				free(args);

				struct rlimit rl;
				if(getrlimit(RLIMIT_STACK, &rl) < 0){
					LH_ERROR_SE("getrlimit");
					return EXIT_FAILURE;
				}

				LH_VERBOSE(3, "Stack size: 0x%lx", rl.rlim_cur);

				void *stack_end = calloc(1, rl.rlim_cur);
				if(!stack_end){
					LH_ERROR_SE("malloc");
					return EXIT_FAILURE;
				}

				void *stack_start = (void *)(((uintptr_t)stack_end) + rl.rlim_cur); //stack grows downwards

#if defined(LH_USE_PRELOAD)
				asprintf(&g_preload_path, "%s/"LH_PRELOAD_SO, needle_dirn);
				free(needle_exe); free(needle_dirn);

				if(access(g_preload_path, F_OK) < 0){
					LH_ERROR("ERROR: '%s' missing, cannot continue!", g_preload_path);
					return EXIT_FAILURE;
				}
				
				session->proc.preload_path = g_preload_path;
#endif

				LH_PRINT("Launching executable '%s'", argv[g_optind_exe]);
				#if 0
				if((g_pid = clone(runProc, stack_start, CLONE_VFORK, prog_argv)) < 0){
					LH_ERROR_SE("clone");
					free(stack_end);
					return EXIT_FAILURE;
				}
				#else
				if((g_pid = fork()) < 0){
					LH_ERROR_SE("fork");
					return EXIT_FAILURE;
				} else if(g_pid == 0){ //child
					runProc(prog_argv);
				} else {
					int status = 0;
					int rc;
					if ((rc = ptrace(PTRACE_SETOPTIONS, g_pid, NULL, (void*)PTRACE_O_TRACEEXEC)) < 0 -1){
						LH_ERROR_SE("ptrace");
						break;
					}
					/*
					LH_PRINT("Waiting for SIGTRAP...");
					do {
						if((rc = waitpid(g_pid, &status, 0)) < 0){
							LH_ERROR_SE("waitpid");
							break;
						}
					} while(!(WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP));
					*/
					LH_PRINT("Waiting for SIGSTOP...");
					if((rc = waitpid(g_pid, &status, WSTOPPED)) < 0){
						LH_ERROR_SE("waitpid");
						break;
					}
					
					LH_VERBOSE(2, "Child stopped due to signal: %s", strsignal(WSTOPSIG(status)));
					
					if(rc < 0)
						break;
				}
				#endif

				LH_PRINT("Process launched! PID: %d", g_pid);

				session->proc.exename = strdup(prog_argv[0]);
				session->started_by_needle = true;
			}
		}

		//start tracking the pid specified by the user
		if (LH_SUCCESS != (re = lh_attach(session, g_pid)))
			break;


		char *libpath = realpath(argv[g_optind_lib], NULL);
		if(!libpath){
			LH_ERROR_SE("realpath");
			return EXIT_FAILURE;
		}


		int argp = argc - g_optind_lib;

		//create and prepare module arguments
		char **mod_argv = calloc(1, sizeof(char *) * argp);

		argp = 0;
		mod_argv[argp++] = strdup(libpath);

		int i;
		for (i = g_optind_lib + 1; i < argc; i++) {
			//read any extra argument passed on the command line
			mod_argv[argp++] = strdup(argv[i]);
			//inject the libraries specified by the user
		}

		session->proc.argc = argp;
		session->proc.argv = mod_argv;

		//crate and prepare memory for hooked program arguments
		char *cmdline;

		argp = 0;
		do {
			FILE *pargs;
			asprintf(&cmdline, "/proc/%d/cmdline", g_pid);
			pargs = fopen(cmdline, "r");
			if(!pargs){
				LH_ERROR("Cannot open '%s' for reading, ignoring program args...", cmdline);
				break;
			}
			free(cmdline);

			int ch;
			char *arg;
			while(1){
				if((ch=fgetc(pargs)) == EOF || feof(pargs)){
					break;
				}
				if(ch == 0x00){
					argp++;
				}
			}
			rewind(pargs);
			printf("Allocating %d args\n", argp);
			char **prog_argv = calloc(1, sizeof(char *) * argp);

			int argSz = 0;
			int argc = 0;
			while(1){
				if((ch=fgetc(pargs)) == EOF || feof(pargs)){
					break;
				}
				argSz++;
				if(ch == 0x00){
					if(argc > argp){
						LH_ERROR("ERROR: Unexpected overflow of program arguments!");
						break;
					}
					fseek(pargs, -argSz, SEEK_CUR);
					arg = calloc(1, argSz);
					fread(arg, argSz, 1, pargs);
					argSz = 0;
					prog_argv[argc++] = arg;
				}
			}


			fclose(pargs);
			session->proc.prog_argc = argp;
			session->proc.prog_argv = prog_argv;
		} while(0);

		for(argp=0; argp<session->proc.prog_argc; argp++)
			printf("ProgArg %d => %s\n", argp, session->proc.prog_argv[argp]);
		for(argp=0; argp<session->proc.argc; argp++)
			printf("ModArg %d => %s\n", argp, session->proc.argv[argp]);

		LH_PRINT("Injecting %s", libpath);
		if (LH_SUCCESS != (re = lh_inject_library(session, libpath, NULL))) {
			break;
		}
		free(libpath);

		//detach from the process
		re |= lh_detach(session);

		//free the session object
		lh_free(&session);

	} while (0);

	if (re == LH_SUCCESS)
		LH_PRINT("Successful.");

	return re;
}
