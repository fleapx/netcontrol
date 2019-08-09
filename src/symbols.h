#ifndef  TAURUS_SYMBOLS_H
#define  TAURUS_SYMBOLS_H

#include <stdlib.h>

typedef int symbol_bind;
typedef int symbol_type;

enum {
    LOCAL_SYMBOL  = 1,
    GLOBAL_SYMBOL = 2,
    WEAK_SYMBOL   = 3,
};

enum {
    FUNC_SYMBOL   = 4,
    OBJECT_SYMBOL = 5,
    COMMON_SYMBOL = 6,
    THREAD_SYMBOL = 7,
};

int symbols(int (*callback)(const char *libpath, const char *libname, const char *objname,
    const void *addr, const size_t size, const symbol_bind binding, const symbol_type type,
    void *custom), void *custom);

#endif /* TAURUS_SYMBOLS_H */
