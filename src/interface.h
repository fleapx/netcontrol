#ifndef TAURUS_INTERFACE_H
#define TAURUS_INTERFACE_H

#include "common_headers.h"

// 所有调用以下函数的代码都需要使用g_old_函数指针
extern "C" {
#ifdef HOOK_DLOPEN
    extern void* (*g_old_dlopen)(const char*, int);
#endif
#ifdef HOOK_DLSYM
    extern void* (*g_old_dlsym)(void *, const char *);
#endif
#ifdef HOOK_CONNECT
    extern int (*g_old_connect)(int, const struct sockaddr*, socklen_t);
#endif
#ifdef HOOK_ACCEPT
    extern int (*g_old_accept)(int, struct sockaddr *, socklen_t *);
#endif
#ifdef HOOK_ACCEPT4
    extern int (*g_old_accept4)(int, struct sockaddr *, socklen_t *, int);
#endif
#ifdef HOOK_SEND
    extern ssize_t (*g_old_send)(int, const void*, size_t, int);
#endif
#ifdef HOOK_RECV
    extern ssize_t (*g_old_recv)(int, void*, size_t, int);
#endif
#ifdef HOOK_SENDTO
    extern ssize_t (*g_old_sendto)(int, const void *, size_t, int, const struct sockaddr *, 
                    socklen_t);
#endif
#ifdef HOOK_RECVFROM
    extern ssize_t (*g_old_recvfrom)(int, void *buf, size_t, int, struct sockaddr *, socklen_t *);
#endif
#ifdef HOOK_SENDMSG
    extern ssize_t (*g_old_sendmsg)(int, const struct msghdr*, int);
#endif
#ifdef HOOK_RECVMSG
    extern ssize_t (*g_old_recvmsg)(int, struct msghdr*, int);
#endif
#ifdef HOOK_READ
    extern ssize_t (*g_old_read)(int, void*, size_t);
#endif
#ifdef HOOK_WRITE
    extern ssize_t (*g_old_write)(int, const void*, size_t);
#endif
}
#endif // TAURUS_INTERFACE_H
