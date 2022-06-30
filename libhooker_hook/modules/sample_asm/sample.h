#ifndef __MOD_SAMPLE_ASM_H
#define __MOD_SAMPLE_ASM_H
extern void hooked_testfunction(int a, char *b);
extern void (*original_test_function) (int a, char *b);
#endif
