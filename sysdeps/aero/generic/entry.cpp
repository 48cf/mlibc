#include <bits/ensure.h>
#include <mlibc/elf/startup.h>
#include <stdint.h>
#include <stdlib.h>

extern "C" uintptr_t *__dlapi_entrystack();

extern char **environ;

extern "C" void __mlibc_entry(int (*main_fn)(int argc, char *argv[],
                                             char *env[])) {
    // TODO: call __dlapi_enter, otherwise static builds will break (see Linux
    // sysdeps)
    auto result =
        main_fn(mlibc::entry_stack.argc, mlibc::entry_stack.argv, environ);
    exit(result);
}
