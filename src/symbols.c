#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dlfcn.h>
#include <errno.h>
#include <features.h>
#include <fnmatch.h>
#include <limits.h>
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "common_headers.h"
#include "symbols.h"

#define UINTS_PER_WORD (__WORDSIZE / (CHAR_BIT * sizeof (unsigned int)))

static ElfW(Word) gnu_hashtab_symbol_count(const unsigned int *const table)
{
    const unsigned int *const bucket = table + 4 + table[2] * (unsigned int)(UINTS_PER_WORD);
    unsigned int              b = table[0];
    unsigned int              max = 0U;

    while (b-->0U) {
        if (bucket[b] > max)
            max = bucket[b];
    }
    return (ElfW(Word))max;
}

static symbol_bind elf_symbol_binding(const unsigned char st_info)
{
#if __WORDSIZE == 32
    switch (ELF32_ST_BIND(st_info)) {
#elif __WORDSIZE == 64
    switch (ELF64_ST_BIND(st_info)) {
#else
    switch (ELF_ST_BIND(st_info)) {
#endif
    case STB_LOCAL:  return LOCAL_SYMBOL;
    case STB_GLOBAL: return GLOBAL_SYMBOL;
    case STB_WEAK:   return WEAK_SYMBOL;
    default:         return 0;
    }
}

static symbol_type elf_symbol_type(const unsigned char st_info)
{
#if __WORDSIZE == 32
    switch (ELF32_ST_TYPE(st_info)) {
#elif __WORDSIZE == 64
    switch (ELF64_ST_TYPE(st_info)) {
#else
    switch (ELF_ST_TYPE(st_info)) {
#endif
    case STT_OBJECT: return OBJECT_SYMBOL;
    case STT_FUNC:   return FUNC_SYMBOL;
    case STT_COMMON: return COMMON_SYMBOL;
    case STT_TLS:    return THREAD_SYMBOL;
    default:         return 0;
    }
}

static void *dynamic_pointer(const ElfW(Addr) addr,
    const ElfW(Addr) base, const ElfW(Phdr) *const header, const ElfW(Half) headers)
{
    if (addr) {
        ElfW(Half) h;

        for (h = 0; h < headers; h++) {
            if (header[h].p_type == PT_LOAD)
                if (addr >= base + header[h].p_vaddr &&
                    addr <  base + header[h].p_vaddr + header[h].p_memsz)
                    return (void *)addr;
        }
    }

    return NULL;
}

struct phdr_iterator_data {
    int  (*callback)(const char *libpath, const char *libname,
                     const char *objname, const void *addr, const size_t size,
                     const symbol_bind binding, const symbol_type type,
                     void *custom);
    void  *custom;
};

#ifdef BIT64
#define Elf_Sym Elf64_Sym
#else
#define Elf_Sym Elf32_Sym
#endif

static int iterate_phdr(struct dl_phdr_info *info, size_t size, void *dataref)
{
    struct phdr_iterator_data *const data = (struct phdr_iterator_data *)dataref;
    const ElfW(Addr)                 base = info->dlpi_addr;
    const ElfW(Phdr) *const          header = info->dlpi_phdr;
    const ElfW(Half)                 headers = info->dlpi_phnum;
    const char                      *libpath;
    const char                      *libname;
    ElfW(Half)                       h;
    size = size;
    if (!data->callback)
        return 0;

    if (info->dlpi_name && info->dlpi_name[0])
        libpath = info->dlpi_name;
    else
        libpath = "";

    libname = strrchr(libpath, '/');
    if (libname && libname[0] == '/' && libname[1])
        libname++;
    else
        libname = libpath;

    for (h = 0; h < headers; h++) {
        if (header[h].p_type == PT_DYNAMIC) {
            const ElfW(Dyn)  *entry = (const ElfW(Dyn) *)(base + header[h].p_vaddr);
            const ElfW(Word) *hashtab;
            const ElfW(Sym)  *symtab = NULL;
            const char       *strtab = NULL;
            ElfW(Word)        symbol_count = 0;

            for (; entry->d_tag != DT_NULL; entry++) {
                switch (entry->d_tag) {
                case DT_HASH:
                    hashtab = (const ElfW(Word) *)dynamic_pointer((ElfW(Addr))entry->d_un.d_ptr, (ElfW(Addr))base, (const ElfW(Phdr) *)header, (const ElfW(Half))headers);
                    if (hashtab)
                        symbol_count = hashtab[1];
                    break;
                case DT_GNU_HASH:
                    hashtab = (const ElfW(Word) *)dynamic_pointer((ElfW(Addr))entry->d_un.d_ptr, (ElfW(Addr))base, (const ElfW(Phdr) *)header, (const ElfW(Half))headers);
                    if (hashtab) {
                        ElfW(Word) count = gnu_hashtab_symbol_count(hashtab);
                        if (count > symbol_count)
                            symbol_count = count;
                    }
                    break;
                case DT_STRTAB:
                    strtab = (const char *)dynamic_pointer((ElfW(Addr))entry->d_un.d_ptr, (ElfW(Addr))base, (const ElfW(Phdr) *)header, (const ElfW(Half))headers);
                    break;
                case DT_SYMTAB:
                    symtab = (const Elf_Sym*)dynamic_pointer((ElfW(Addr))entry->d_un.d_ptr, (ElfW(Addr))base, (const ElfW(Phdr) *)header, (const ElfW(Half))headers);
                    break;
                }
            }

            if (symtab && strtab && symbol_count > 0) {
                ElfW(Word)  s;

                for (s = 0; s < symbol_count; s++) {
                    const char *name;
                    void *const ptr = dynamic_pointer(base + symtab[s].st_value, base, header, headers);
                    symbol_bind bind = 0;
                    symbol_type type = 0;
                    int result = 0;

                    if (!ptr)
                        continue;

                    type = elf_symbol_type(symtab[s].st_info);
                    bind = elf_symbol_binding(symtab[s].st_info);
                    if (symtab[s].st_name)
                        name = strtab + symtab[s].st_name;
                    else
                        name = "";

                    result = data->callback(libpath, libname, name, ptr, symtab[s].st_size, bind, type, data->custom);
                    if (result)
                        return result;
                }
            }
        }
    }
    return 0;
}

int symbols(int (*callback)(const char *libpath, const char *libname, const char *objname,
    const void *addr, const size_t size, const symbol_bind binding, const symbol_type type,
    void *custom), void *custom)
{
    struct phdr_iterator_data data;

    if (!callback)
        return errno = EINVAL;

    data.callback = callback;
    data.custom = custom;

    return errno = dl_iterate_phdr(iterate_phdr, &data);
}
