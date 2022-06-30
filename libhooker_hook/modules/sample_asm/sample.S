.intel_syntax noprefix

.text
  .globl hooked_testfunction
  .type  hooked_testfunction, @function
  hooked_testfunction:
    mov eax, 1337
    ret //we hooked a function prologue, so stack has ret addr (cdecl)
