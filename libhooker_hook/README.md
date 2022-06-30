# NOTE
## libhooker has been simplified and adapted on top of a newly built injector, with a simplified codebase.
## Follow the new developments here: https://github.com/smx-smx/ezinject



What is libhooker
-----------------
The libhooker project is a multiplatform binary instrumentation framework.
Using it you can inject your own code into a running process, hook its
existing functions, replacing its functionality, etc.

To use it, you need to implement your code as an LHM module.
For a working example, see modules/sample

Usage
-----
Compilation should be as easy as writing make in the root directory of
this package.

After your module is ready, you can load it into a running process using
the needle tool:
``./bin/needle -v 4 `pidof process_to_inject_to` bin/lhm_sample.so``

And thats all.

LHM modules
-----------
Create a dedicated directory in modules for your own module, then you
can build it just typing make in the root directory.

To hook functions, you need to define a hook_settings symbol like this:

```c
lh_hook_t hook_settings = {
  // version of the structure. currently supported: 1
  .version = 1, 

  // function to be run at injection time (and before functions were hooked)
  .autoinit_pre = hooked_autoinit, 

  // function to be run after hooking successfully finished
  .autoinit_post = hooked_autoinit_post,

  // list of functions to be hooked
  .fn_hooks = {

    {
          // supported values:
          //  LHM_FN_HOOK_TRAILING:
          //    last entry in the array should be specified with this constant
          //    processing will stop.
          //  LHM_FN_HOOK_BY_NAME:
          //    the function to be hooked will be specified
          //    based on libname and symname fields
          //  LHM_FN_HOOK_BY_OFFSET: 
          //    when the function to be hooked is not exported,
          //    you can specify its base address (the absolute
          //    address will be calculated based on the base
          //    address of the code section)
          //  LHM_FN_HOOK_BY_AOBSCAN:
          //    the function to be hooked will be specified based on a pattern
          //    the location of the first match is taken as the hook address
          //    required parameters:
          //    .aob_size    -> sizeof(pattern)
          //    .aob_pattern -> { 0xDE, 0xAD, 0xBE, 0xFF } the pattern to look for
          .hook_kind = LHM_FN_HOOK_BY_NAME,

          // name of the library to be hooked, for example libc.so
          // if its an empty string, the current executable will
          // be looked for
          .libname = "",

          // name of the function symbol wanted to be hooked
          .symname = "testfunction",

          // address of the replacement function
          .hook_fn = (uintptr_t) hooked_testfunction,

          // address where you want to store the address of the
          // original symbol (so you can call it any time later)
          .orig_function_ptr = (uintptr_t) &original_test_function,

          // how many opcode bytes you want to restore
          // it can be automatically determined on x86/x64
          //
          // With relative jump we overwrite:
          //   ARM: 4 bytes
          //
          // With absolute jump we overwrite:
          //   ARM: 8 bytes
          .opcode_bytes_to_restore = 8
    },
    {

          .hook_kind = LHM_FN_HOOK_TRAILING
    }
  }
};
```

Credits
-----------------
Big thanks to `foobaro`, an anonymous guy that wrote the preliminar version of libhooker and handed it to me.
