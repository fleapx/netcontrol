#include "common_headers.h"
#include "info_manager.h"
#include "report.h"
#include "symbols.h"
#include "remote_rule_manager.h"

#ifdef BIT64
static const char* LD_PATH = "/lib64/libdl.so.2";
static const char* LIBC_PATH = "/lib64/libc.so.6";
#else
static const char* LD_PATH = "/lib/libdl.so.2";
static const char* LIBC_PATH = "/lib/libc.so.6";
#endif
static const char* LD_NAME = "libdl.so.2";
static const char* LIBC_NAME = "libc.so.6";
static const char* TAU_NAME = "libtaurus.so";
#ifdef HOOK_DLOPEN
static const char* LIBC_1 = "libc.so.6";
#ifdef BIT64
static const char* LIBC_2 = "/lib64/libc.so.6";
#else
static const char* LIBC_2 = "/lib/libc.so.6";
#endif
static void* s_g_handle = 0;
#endif

static bool s_g_init_hook = false;
static bool s_g_init_taurus = false;
static bool is_in_white(const ControlInfo& ctrlinfo); // 将自身及重要文件排除

class TaurusManager {
public:
    static void init_hook();
    static void init_taurus();
    TaurusManager();
};

TaurusManager gintance;

/**
 * 解析IP通信五元组
 * @param info                     待更新信息
 * @param sockfd
 * @param peerinfo_bak      对等端信息，若显示指定则传入，否则传空
 */
static void get_common_net_info(ControlInfo& info, int sockfd,
        const struct sockaddr* peerinfo_bak) {
    if (!is_sock(sockfd)) { // 排除非socket (send recv 可能用于普通文件)
        return;
    }
    // 获取family
    int family = -1;
    socklen_t len = sizeof (int);
    struct sockaddr_storage tmpaddr;
    socklen_t tmplen = 0;
    if (0 != getsockopt(sockfd, SOL_SOCKET, SO_DOMAIN, (void*) &family, &len)) {
        if (family == -1 && peerinfo_bak != 0) {
            family = peerinfo_bak->sa_family;
        }
        tmplen = sizeof (tmpaddr);
        if (family == -1 && (0 == getsockname(sockfd, (struct sockaddr*) &tmpaddr, &tmplen))) {
            family = tmpaddr.ss_family;
        }
        if (family == -1) {
            return;
        }
    }
    info._mask |= MASK_FAMILY;
    info._family = family;
    // 获取socket type
    int socktype = get_sock_type(sockfd);
    if (socktype != -1) {
        info._mask |= MASK_SOTYPE;
        info._typeset = (1 << socktype); // 采用位运算，支持策略同时指定TCP/UDP
    }
    int sockproto = get_sock_proto(sockfd);
    if (sockproto != -1) {
        info._mask |= MASK_PROTO;
        info._sockproto = sockproto;
    }
    // 获取srcip srcport
    tmplen = sizeof (tmpaddr);
    if (0 == getsockname(sockfd, (struct sockaddr*) &tmpaddr, &tmplen)) {
        if (tmpaddr.ss_family == AF_INET) {
            sockaddr_in* tuple = (sockaddr_in*) & tmpaddr;
            info._mask |= MASK_SRCPORT | MASK_SRCIP;
            info._srcport = ntohs(tuple->sin_port);
            info._srcip = get_ip_from_addr(tuple->sin_addr);
        }
    }
    // 获取dstip dstport
    tmplen = sizeof (tmpaddr);
    if (peerinfo_bak != 0) {
        if (peerinfo_bak->sa_family == AF_INET) {
            sockaddr_in* tuple = (sockaddr_in*) peerinfo_bak;
            info._mask |= MASK_DSTPORT | MASK_DSTIP;
            info._dstport = ntohs(tuple->sin_port);
            info._dstip = get_ip_from_addr(tuple->sin_addr);
        }
    } else if (0 == getpeername(sockfd, (struct sockaddr*) &tmpaddr, &tmplen)) {
        if (tmpaddr.ss_family == AF_INET) {
            sockaddr_in* tuple = (sockaddr_in*) & tmpaddr;
            info._mask |= MASK_DSTPORT | MASK_DSTIP;
            info._dstport = ntohs(tuple->sin_port);
            info._dstip = get_ip_from_addr(tuple->sin_addr);
        }
    }
}


#ifdef __cplusplus
extern "C" {
#endif
#ifdef HOOK_CONNECT
    int (*g_old_connect)(int, const struct sockaddr*, socklen_t) = 0;
    int (*g_tau_connect)(int, const struct sockaddr*, socklen_t) = 0;

    EXPORT int connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen) {
        /**
         * may be 0: addr
         */
        // LOGI("taurus: in %s\n", __FUNCTION__);
        if (!s_g_init_hook) {
            TaurusManager::init_hook();
        }
        if (!s_g_init_hook || !s_g_init_taurus) {
            LOGI("taurus: in %s: init not done\n", __FUNCTION__);
            return g_old_connect(sockfd, addr, addrlen);
        }
        if (sockfd <= 0 || addr == 0) {
            return g_old_connect(sockfd, addr, addrlen);
        }
        if (get_sock_family(sockfd) != AF_INET || get_sock_type(sockfd) != SOCK_STREAM) {
            return g_old_connect(sockfd, addr, addrlen);
        }
        // construct dict
        int result = 0; // 是否放行
        ControlInfo ctrlinfo;
        InfoManager::get_instance().copy_ctrlinfo(ctrlinfo);
        get_common_net_info(ctrlinfo, sockfd, addr);
        if (is_in_white(ctrlinfo)) {
            // LOGI("taurus: in %s: in white list\n", __FUNCTION__);
            return g_old_connect(sockfd, addr, addrlen);
        }
        ctrlinfo._mask |= MASK_API;
        ctrlinfo._api = __FUNCTION__;
        ctrlinfo._uniqid += get_uuid();
        // check rule
        CJsonWrapper::NodeType reportdata = CJsonWrapper::create_object_node();
        if (reportdata != 0) {
            ControlInfo::serial_json(ctrlinfo, reportdata);
#ifdef EMPTYLIB
            result = 1;
#else
            result = RemoteRuleManager::judge_remote(ctrlinfo._uniqid, reportdata);
#endif
        }
        if (reportdata != 0) {
            CJsonWrapper::add_object_int_node(reportdata, "result", result);
#ifndef NDEBUG // report
            Report::get_instance().log(Report::SENDER_LIB, Report::LEVEL_INFO,
                    __LINE__, __FILE__, reportdata);
#endif
            CJsonWrapper::release_root_node(reportdata);
        }
        if (!RemoteRuleManager::ispass(result)) { // 1放过   0拒绝
            LOGI("taurus: %s blocked!\n", __FUNCTION__);
            errno = ETIMEDOUT;
            return -1;
        } else {
            LOGI("taurus: %s passed!\n", __FUNCTION__);
        }
        return g_old_connect(sockfd, addr, addrlen);
    }

#endif
#ifdef HOOK_ACCEPT
    int (*g_old_accept)(int, struct sockaddr *, socklen_t *) = 0;
    int (*g_tau_accept)(int, struct sockaddr *, socklen_t *) = 0;

    EXPORT int accept(int sockfd, struct sockaddr *addr, socklen_t *paddrlen) {
        /**
         * may be 0: addr, paddrlen
         */
        // LOGI("taurus: in %s\n", __FUNCTION__);
        if (!s_g_init_hook) {
            TaurusManager::init_hook();
        }
        if (!s_g_init_hook || !s_g_init_taurus) {
            LOGI("taurus: in %s: init not done\n", __FUNCTION__);
            return g_old_accept(sockfd, addr, paddrlen);
        }
        if (sockfd <= 0) {
            return g_old_accept(sockfd, addr, paddrlen);
        }
        if (get_sock_family(sockfd) != AF_INET || get_sock_type(sockfd) != SOCK_STREAM) {
            return g_old_accept(sockfd, addr, paddrlen);
        }
        sockaddr_storage tmp_addr;
        socklen_t tmp_addrlen = sizeof (tmp_addr);
        int newsock = g_old_accept(sockfd, (struct sockaddr*) &tmp_addr, &tmp_addrlen);
        if (newsock < 0) {
            return newsock;
        }
        if (addr != 0 && paddrlen != 0) { // 合理的向用户buffer赋值
            size_t cplen = tmp_addrlen < *paddrlen ? tmp_addrlen : *paddrlen;
            *paddrlen = cplen;
            memcpy(addr, &tmp_addr, cplen);
        }
        // construct dict
        int result = 0;
        ControlInfo ctrlinfo;
        InfoManager::get_instance().copy_ctrlinfo(ctrlinfo);
        get_common_net_info(ctrlinfo, sockfd, (sockaddr*) & tmp_addr);
        if (is_in_white(ctrlinfo)) {
            LOGI("taurus: in %s: in white list\n", __FUNCTION__);
            return newsock;
        }
        ctrlinfo._mask |= MASK_API;
        ctrlinfo._api = __FUNCTION__;
        ctrlinfo._uniqid += get_uuid();
        // check rule
        CJsonWrapper::NodeType reportdata = CJsonWrapper::create_object_node();
        if (reportdata != 0) {
            ControlInfo::serial_json(ctrlinfo, reportdata);
#ifdef EMPTYLIB
            result = 1;
#else
            result = RemoteRuleManager::judge_remote(ctrlinfo._uniqid, reportdata);
#endif
        }
        if (reportdata != 0) {
            CJsonWrapper::add_object_int_node(reportdata, "result", result);
#ifndef NDEBUG // report
            Report::get_instance().log(Report::SENDER_LIB, Report::LEVEL_INFO,
                    __LINE__, __FILE__, reportdata);
#endif
            CJsonWrapper::release_root_node(reportdata);
        }
        if (!RemoteRuleManager::ispass(result)) { // 1放过   0拒绝
            LOGI("taurus: %s blocked!\n", __FUNCTION__);
            errno = ETIMEDOUT;
            if (newsock != -1) {
                close(newsock);
            }
            return -1;
        } else {
            LOGI("taurus: %s passed!\n", __FUNCTION__);
        }
        return newsock;
    }
#endif
#ifdef HOOK_ACCEPT4
    int (*g_old_accept4)(int, struct sockaddr *, socklen_t *, int) = 0;
    int (*g_tau_accept4)(int, struct sockaddr *, socklen_t *, int) = 0;

    EXPORT int accept4(int sockfd, struct sockaddr *addr, socklen_t *paddrlen, int flags) {
        /**
         * may be 0: addr, paddrlen
         */
        // LOGI("taurus: in %s\n", __FUNCTION__);
        if (!s_g_init_hook) {
            TaurusManager::init_hook();
        }
        if (!s_g_init_hook || !s_g_init_taurus) {
            LOGI("taurus: in %s: init not done\n", __FUNCTION__);
            return g_old_accept4(sockfd, addr, paddrlen, flags);
        }
        if (sockfd <= 0) {
            return g_old_accept4(sockfd, addr, paddrlen, flags);
        }
        if (get_sock_family(sockfd) != AF_INET || get_sock_type(sockfd) != SOCK_STREAM) {
            return g_old_accept4(sockfd, addr, paddrlen, flags);
        }
        sockaddr_storage tmp_addr;
        socklen_t tmp_addrlen = sizeof (tmp_addr);
        int newsock = g_old_accept4(sockfd, (struct sockaddr*) &tmp_addr, &tmp_addrlen, flags);
        if (newsock < 0) {
            return newsock;
        }
        if (addr != 0 && paddrlen != 0) { // 合理的向用户buffer赋值
            size_t cplen = tmp_addrlen < *paddrlen ? tmp_addrlen : *paddrlen;
            *paddrlen = cplen;
            memcpy(addr, &tmp_addr, cplen);
        }
        // construct dict
        int result = 0;
        ControlInfo ctrlinfo;
        InfoManager::get_instance().copy_ctrlinfo(ctrlinfo);
        get_common_net_info(ctrlinfo, sockfd, (sockaddr*) & tmp_addr);
        if (is_in_white(ctrlinfo)) {
            LOGI("taurus: in %s: in white list\n", __FUNCTION__);
            return newsock;
        }
        ctrlinfo._mask |= MASK_API;
        ctrlinfo._api = __FUNCTION__;
        ctrlinfo._uniqid += get_uuid();
        // check rule
        CJsonWrapper::NodeType reportdata = CJsonWrapper::create_object_node();
        if (reportdata != 0) {
            ControlInfo::serial_json(ctrlinfo, reportdata);
#ifdef EMPTYLIB
            result = 1;
#else
            result = RemoteRuleManager::judge_remote(ctrlinfo._uniqid, reportdata);
#endif
        }
        if (reportdata != 0) {
            CJsonWrapper::add_object_int_node(reportdata, "result", result);
#ifndef NDEBUG // report
            Report::get_instance().log(Report::SENDER_LIB, Report::LEVEL_INFO,
                    __LINE__, __FILE__, reportdata);
#endif
            CJsonWrapper::release_root_node(reportdata);
        }
        if (!RemoteRuleManager::ispass(result)) { // 1放过   0拒绝
            LOGI("taurus: %s blocked!\n", __FUNCTION__);
            errno = ETIMEDOUT;
            if (newsock != -1) {
                close(newsock);
            }
            return -1;
        } else {
            LOGI("taurus: %s passed!\n", __FUNCTION__);
        }
        return newsock;
    }
#endif
#ifdef HOOK_SEND
    ssize_t(*g_old_send)(int, const void *, size_t, int) = 0;
    ssize_t(*g_tau_send)(int, const void *, size_t, int) = 0;

    EXPORT ssize_t send(int sockfd, const void *buf, size_t len, int flags) {
        /**
         * May be 0: buf
         */
        // LOGI("taurus: in %s\n", __FUNCTION__);
        if (!s_g_init_hook) {
            TaurusManager::init_hook();
        }
        if (!s_g_init_hook || !s_g_init_taurus) {
            LOGI("taurus: in %s: init not done\n", __FUNCTION__);
            return g_old_send(sockfd, buf, len, flags);
        }
        if (sockfd <= 0 || buf == 0) {
            return g_old_send(sockfd, buf, len, flags);
        }
        if (get_sock_family(sockfd) != AF_INET || get_sock_type(sockfd) != SOCK_DGRAM) {
            // 此函数频繁调用，因此预先筛选
            return g_old_send(sockfd, buf, len, flags);
        }
        // construct dict
        int result = 0;
        ControlInfo ctrlinfo;
        InfoManager::get_instance().copy_ctrlinfo(ctrlinfo);
        get_common_net_info(ctrlinfo, sockfd, 0);
        if (is_in_white(ctrlinfo)) {
            LOGI("taurus: in %s: in white list\n", __FUNCTION__);
            return g_old_send(sockfd, buf, len, flags);
        }
        ctrlinfo._mask |= MASK_API;
        ctrlinfo._api = __FUNCTION__;
        ctrlinfo._uniqid += get_uuid();
        // check rule
        CJsonWrapper::NodeType reportdata = CJsonWrapper::create_object_node();
        if (reportdata != 0) {
            ControlInfo::serial_json(ctrlinfo, reportdata);
#ifdef EMPTYLIB
            result = 1;
#else
            result = RemoteRuleManager::judge_remote(ctrlinfo._uniqid, reportdata);
#endif
        }
        if (reportdata != 0) {
            CJsonWrapper::add_object_int_node(reportdata, "result", result);
#ifndef NDEBUG // report
            Report::get_instance().log(Report::SENDER_LIB, Report::LEVEL_INFO,
                    __LINE__, __FILE__, reportdata);
#endif
            CJsonWrapper::release_root_node(reportdata);
        }
        if (!RemoteRuleManager::ispass(result)) { // 1放过   0拒绝
            LOGI("taurus: %s blocked!\n", __FUNCTION__);
            errno = ETIMEDOUT;
            return -1;
        } else {
            LOGI("taurus: %s passed!\n", __FUNCTION__);
        }
        return g_old_send(sockfd, buf, len, flags);
    }
#endif
#ifdef HOOK_RECV
    ssize_t(*g_old_recv)(int, void *, size_t, int) = 0;
    ssize_t(*g_tau_recv)(int, void *, size_t, int) = 0;

    EXPORT ssize_t recv(int sockfd, void *buf, size_t len, int flags) {
        /**
         * May be 0: buf
         */
        // LOGI("taurus: in %s\n", __FUNCTION__);
        if (!s_g_init_hook) {
            TaurusManager::init_hook();
        }
        if (!s_g_init_hook || !s_g_init_taurus) {
            LOGI("taurus: in %s: init not done\n", __FUNCTION__);
            return g_old_recv(sockfd, buf, len, flags);
        }
        if (sockfd <= 0 || buf == 0) {
            return g_old_recv(sockfd, buf, len, flags);
        }
        if (get_sock_family(sockfd) != AF_INET || get_sock_type(sockfd) != SOCK_DGRAM) {
            // 此函数频繁调用，因此预先筛选
            return g_old_recv(sockfd, buf, len, flags);
        }
        // construct dict
        int result = 0;
        ControlInfo ctrlinfo;
        InfoManager::get_instance().copy_ctrlinfo(ctrlinfo);
        get_common_net_info(ctrlinfo, sockfd, 0);
        if (is_in_white(ctrlinfo)) {
            LOGI("taurus: in %s: in white list\n", __FUNCTION__);
            return g_old_recv(sockfd, buf, len, flags);
        }
        ctrlinfo._mask |= MASK_API;
        ctrlinfo._api = __FUNCTION__;
        ctrlinfo._uniqid += get_uuid();
        // check rule
        CJsonWrapper::NodeType reportdata = CJsonWrapper::create_object_node();
        if (reportdata != 0) {
            ControlInfo::serial_json(ctrlinfo, reportdata);
#ifdef EMPTYLIB
            result = 1;
#else
            result = RemoteRuleManager::judge_remote(ctrlinfo._uniqid, reportdata);
#endif
        }
        if (reportdata != 0) {
            CJsonWrapper::add_object_int_node(reportdata, "result", result);
#ifndef NDEBUG // report
            Report::get_instance().log(Report::SENDER_LIB, Report::LEVEL_INFO,
                    __LINE__, __FILE__, reportdata);
#endif
            CJsonWrapper::release_root_node(reportdata);
        }
        if (!RemoteRuleManager::ispass(result)) { // 1放过   0拒绝
            LOGI("taurus: %s blocked!\n", __FUNCTION__);
            errno = ETIMEDOUT;
            return -1;
        } else {
            LOGI("taurus: %s passed!\n", __FUNCTION__);
        }
        return g_old_recv(sockfd, buf, len, flags);
    }
#endif    
#ifdef HOOK_SENDTO
    ssize_t(*g_old_sendto)(int, const void *, size_t, int, const struct sockaddr *, socklen_t) = 0;
    ssize_t(*g_tau_sendto)(int, const void *, size_t, int, const struct sockaddr *, socklen_t) = 0;

    EXPORT ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
            const struct sockaddr *addr, socklen_t addrlen) {
        /**
         * may be 0: addr       参数addr优先级高于connect的addr
         */
        // LOGI("taurus: in %s\n", __FUNCTION__);
        if (!s_g_init_hook) {
            TaurusManager::init_hook();
        }
        if (!s_g_init_hook || !s_g_init_taurus) {
            LOGI("taurus: in %s: init not done\n", __FUNCTION__);
            return g_old_sendto(sockfd, buf, len, flags, addr, addrlen);
        }
        if (sockfd <= 0 || buf == 0) {
            return g_old_sendto(sockfd, buf, len, flags, addr, addrlen);
        }
        if (get_sock_family(sockfd) != AF_INET || get_sock_type(sockfd) != SOCK_DGRAM) {
            // 此函数频繁调用，因此预先筛选
            return g_old_sendto(sockfd, buf, len, flags, addr, addrlen);
        }
        // construct dict
        int result = 0;
        ControlInfo ctrlinfo;
        InfoManager::get_instance().copy_ctrlinfo(ctrlinfo);
        get_common_net_info(ctrlinfo, sockfd, addr);
        if (is_in_white(ctrlinfo)) {
            LOGI("taurus: in %s: in white list\n", __FUNCTION__);
            return g_old_sendto(sockfd, buf, len, flags, addr, addrlen);
        }
        ctrlinfo._mask |= MASK_API;
        ctrlinfo._api = __FUNCTION__;
        ctrlinfo._uniqid += get_uuid();
        // check rule
        CJsonWrapper::NodeType reportdata = CJsonWrapper::create_object_node();
        if (reportdata != 0) {
            ControlInfo::serial_json(ctrlinfo, reportdata);
#ifdef EMPTYLIB
            result = 1;
#else
            result = RemoteRuleManager::judge_remote(ctrlinfo._uniqid, reportdata);
#endif
        }
        if (reportdata != 0) {
            CJsonWrapper::add_object_int_node(reportdata, "result", result);
#ifndef NDEBUG // report
            Report::get_instance().log(Report::SENDER_LIB, Report::LEVEL_INFO,
                    __LINE__, __FILE__, reportdata);
#endif
            CJsonWrapper::release_root_node(reportdata);
        }
        if (!RemoteRuleManager::ispass(result)) { // 1放过   0拒绝
            LOGI("taurus: %s blocked!\n", __FUNCTION__);
            errno = ETIMEDOUT;
            return -1;
        } else {
            LOGI("taurus: %s passed!\n", __FUNCTION__);
        }
        return g_old_sendto(sockfd, buf, len, flags, addr, addrlen);
    }
#endif
#ifdef HOOK_RECVFROM
    ssize_t(*g_old_recvfrom)(int, void *buf, size_t, int, struct sockaddr *, socklen_t *) = 0;
    ssize_t(*g_tau_recvfrom)(int, void *buf, size_t, int, struct sockaddr *, socklen_t *) = 0;

    EXPORT ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
            struct sockaddr *addr, socklen_t *paddrlen) {
        /**
         * may be 0: addr, paddrlen
         */
        // LOGI("taurus: in %s\n", __FUNCTION__);
        if (!s_g_init_hook) {
            TaurusManager::init_hook();
        }
        if (!s_g_init_hook || !s_g_init_taurus) {
            LOGI("taurus: in %s: init not done\n", __FUNCTION__);
            return g_old_recvfrom(sockfd, buf, len, flags, addr, paddrlen);
        }
        if (sockfd <= 0 || buf == 0) {
            return g_old_recvfrom(sockfd, buf, len, flags, addr, paddrlen);
        }
        if (get_sock_family(sockfd) != AF_INET || get_sock_type(sockfd) != SOCK_DGRAM) {
            // 此函数频繁调用，因此预先筛选
            return g_old_recvfrom(sockfd, buf, len, flags, addr, paddrlen);
        }
        sockaddr_storage tmp_addr;
        socklen_t tmp_addrlen = sizeof (tmp_addr);
        ssize_t recvsize = g_old_recvfrom(sockfd, buf, len, flags, (sockaddr*) & tmp_addr,
                &tmp_addrlen);
        if (recvsize < 0) {
            return recvsize;
        }
        if (addr != 0 && paddrlen != 0) { // 合理的向用户buffer赋值
            size_t cplen = tmp_addrlen < *paddrlen ? tmp_addrlen : *paddrlen;
            *paddrlen = cplen;
            memcpy(addr, &tmp_addr, cplen);
        }
        // construct dict
        int result = 0;
        ControlInfo ctrlinfo;
        InfoManager::get_instance().copy_ctrlinfo(ctrlinfo);
        get_common_net_info(ctrlinfo, sockfd, (sockaddr*) & tmp_addr);
        if (is_in_white(ctrlinfo)) {
            LOGI("taurus: in %s: in white list\n", __FUNCTION__);
            return recvsize;
        }
        ctrlinfo._mask |= MASK_API;
        ctrlinfo._api = __FUNCTION__;
        ctrlinfo._uniqid += get_uuid();
        // check rule
        CJsonWrapper::NodeType reportdata = CJsonWrapper::create_object_node();
        if (reportdata != 0) {
            ControlInfo::serial_json(ctrlinfo, reportdata);
#ifdef EMPTYLIB
            result = 1;
#else
            result = RemoteRuleManager::judge_remote(ctrlinfo._uniqid, reportdata);
#endif
        }
        if (reportdata != 0) {
            CJsonWrapper::add_object_int_node(reportdata, "result", result);
#ifndef NDEBUG // report
            Report::get_instance().log(Report::SENDER_LIB, Report::LEVEL_INFO,
                    __LINE__, __FILE__, reportdata);
#endif
            CJsonWrapper::release_root_node(reportdata);
        }
        if (!RemoteRuleManager::ispass(result)) { // 1放过   0拒绝
            LOGI("taurus: %s blocked!\n", __FUNCTION__);
            errno = ETIMEDOUT;
            if (!buf) { // 清空结果
                memset(buf, 0, len);
            }
            return -1;
        } else {
            LOGI("taurus: %s passed!\n", __FUNCTION__);
        }
        return recvsize;
    }
#endif
#ifdef HOOK_SENDMSG
    ssize_t(*g_old_sendmsg)(int, const msghdr *, int) = 0;
    ssize_t(*g_tau_sendmsg)(int, const msghdr *, int) = 0;

    EXPORT ssize_t sendmsg(int sockfd, const struct msghdr* message, int flags) {
        /**
         * May be 0: message        参数addr优先级高于connect的addr
         */
        // LOGI("taurus: in %s\n", __FUNCTION__);
        if (!s_g_init_hook) {
            TaurusManager::init_hook();
        }
        if (!s_g_init_hook || !s_g_init_taurus) {
            LOGI("taurus: in %s: init not done\n", __FUNCTION__);
            return g_old_sendmsg(sockfd, message, flags);
        }
        if (sockfd <= 0) {
            return g_old_sendmsg(sockfd, message, flags);
        }
        if (get_sock_family(sockfd) != AF_INET || get_sock_type(sockfd) != SOCK_DGRAM) {
            // 此函数频繁调用，因此预先筛选
            return g_old_sendmsg(sockfd, message, flags);
        }
        // construct dict
        int result = 0;
        ControlInfo ctrlinfo;
        InfoManager::get_instance().copy_ctrlinfo(ctrlinfo);
        if (message != 0 && message->msg_name != 0) {
            // 此处避免message缓冲区过小导致get_common_net_info解析失误
            sockaddr_storage tmp_addr;
            socklen_t tmp_addrlen = sizeof (tmp_addr);
            if (tmp_addrlen > message->msg_namelen) {
                tmp_addrlen = message->msg_namelen;
            }
            memset(&tmp_addr, 0, sizeof (tmp_addr));
            memcpy(&tmp_addr, message->msg_name, tmp_addrlen);
            get_common_net_info(ctrlinfo, sockfd, (sockaddr*) & tmp_addr);
        } else {
            get_common_net_info(ctrlinfo, sockfd, 0);
        }
        if (is_in_white(ctrlinfo)) {
            LOGI("taurus: in %s: in white list\n", __FUNCTION__);
            return g_old_sendmsg(sockfd, message, flags);
        }
        // check rule
        CJsonWrapper::NodeType reportdata = CJsonWrapper::create_object_node();
        if (reportdata != 0) {
            ControlInfo::serial_json(ctrlinfo, reportdata);
#ifdef EMPTYLIB
            result = 1;
#else
            result = RemoteRuleManager::judge_remote(ctrlinfo._uniqid, reportdata);
#endif
        }
        if (reportdata != 0) {
            CJsonWrapper::add_object_int_node(reportdata, "result", result);
#ifndef NDEBUG // report
            Report::get_instance().log(Report::SENDER_LIB, Report::LEVEL_INFO,
                    __LINE__, __FILE__, reportdata);
#endif
            CJsonWrapper::release_root_node(reportdata);
        }
        if (!RemoteRuleManager::ispass(result)) { // 1放过   0拒绝
            LOGI("taurus: %s blocked!\n", __FUNCTION__);
            errno = ETIMEDOUT;
            return -1;
        } else {
            LOGI("taurus: %s passed!\n", __FUNCTION__);
        }
        return g_old_sendmsg(sockfd, message, flags);
    }
#endif   
#ifdef HOOK_RECVMSG
    ssize_t(*g_old_recvmsg)(int, struct msghdr *, int) = 0;
    ssize_t(*g_tau_recvmsg)(int, struct msghdr *, int) = 0;

    EXPORT ssize_t recvmsg(int sockfd, struct msghdr* message, int flags) {
        /**
         * May be 0: message
         */
        // LOGI("taurus: in %s\n", __FUNCTION__);
        if (!s_g_init_hook) {
            TaurusManager::init_hook();
        }
        if (!s_g_init_hook || !s_g_init_taurus) {
            LOGI("taurus: in %s: init not done\n", __FUNCTION__);
            return g_old_recvmsg(sockfd, message, flags);
        }
        if (sockfd <= 0) {
            return g_old_recvmsg(sockfd, message, flags);
        }
        if (get_sock_family(sockfd) != AF_INET || get_sock_type(sockfd) != SOCK_DGRAM) {
            // 此函数频繁调用，因此预先筛选
            return g_old_recvmsg(sockfd, message, flags);
        }
        void* old_name = 0; // 备份
        socklen_t old_namelen = 0;
        if (message != 0) {
            old_name = message->msg_name;
            old_namelen = message->msg_namelen;
        }
        sockaddr_storage tmp_addr;
        socklen_t tmp_addrlen = sizeof (tmp_addr);
        message->msg_name = (void*) &tmp_addr; // 缓冲区替换
        message->msg_namelen = tmp_addrlen;
        ssize_t recvd = g_old_recvmsg(sockfd, message, flags);
        if (recvd < 0) {
            return recvd;
        }
        if (message != 0) { // 缓冲区还原
            if (old_name != 0) {
                size_t cplen = message->msg_namelen;
                if (message->msg_namelen > old_namelen) { // 合理的向用户buffer赋值
                    cplen = old_namelen;
                }
                message->msg_namelen = cplen;
                memcpy(old_name, &tmp_addr, cplen);
            } else {
                message->msg_name = old_name;
                message->msg_namelen = old_namelen;
            }
        }
        // construct dict
        int result = 0;
        ControlInfo ctrlinfo;
        InfoManager::get_instance().copy_ctrlinfo(ctrlinfo);
        get_common_net_info(ctrlinfo, sockfd, (sockaddr*) & tmp_addr);
        if (is_in_white(ctrlinfo)) {
            LOGI("taurus: in %s: in white list\n", __FUNCTION__);
            return g_old_recvmsg(sockfd, message, flags);
        }
        ctrlinfo._mask |= MASK_API;
        ctrlinfo._api = __FUNCTION__;
        ctrlinfo._uniqid += get_uuid();
        // check rule
        CJsonWrapper::NodeType reportdata = CJsonWrapper::create_object_node();
        if (reportdata != 0) {
            ControlInfo::serial_json(ctrlinfo, reportdata);
#ifdef EMPTYLIB
            result = 1;
#else
            result = RemoteRuleManager::judge_remote(ctrlinfo._uniqid, reportdata);
#endif
        }
        if (reportdata != 0) {
            CJsonWrapper::add_object_int_node(reportdata, "result", result);
#ifndef NDEBUG // report
            Report::get_instance().log(Report::SENDER_LIB, Report::LEVEL_INFO,
                    __LINE__, __FILE__, reportdata);
#endif
            CJsonWrapper::release_root_node(reportdata);
        }
        if (!RemoteRuleManager::ispass(result)) { // 1放过   0拒绝
            LOGI("taurus: %s blocked!\n", __FUNCTION__);
            errno = ETIMEDOUT;
            return -1;
        } else {
            LOGI("taurus: %s passed!\n", __FUNCTION__);
        }
        return g_old_recvmsg(sockfd, message, flags);
    }
#endif   
#ifdef HOOK_READ
    ssize_t(*g_old_read)(int fd, void* buf, size_t count) = 0;
    ssize_t(*g_tau_read)(int fd, void* buf, size_t count) = 0;

    ssize_t read(int fd, void* buf, size_t count) {
        /**
         * May be 0: buf
         */
        if (!s_g_init_hook) {
            TaurusManager::init_hook();
        }
        if (!s_g_init_hook || !s_g_init_taurus) {
            LOGI("taurus: in %s: init not done\n", __FUNCTION__);
            return g_old_read(fd, buf, count);
        }
        if (fd <= 0 || buf == 0) {
            return g_old_read(fd, buf, count);
        }
        if (!is_sock(fd) || get_sock_family(fd) != AF_INET || get_sock_type(fd) != SOCK_DGRAM) {
            // 此函数频繁调用，因此预先筛选
            return g_old_read(fd, buf, count);
        }
        /*-------------------------------注意在该行代码前不能存在read循环调用------------------------------*/
        // construct dict
        int result = 0;
        ControlInfo ctrlinfo;
        InfoManager::get_instance().copy_ctrlinfo(ctrlinfo);
        get_common_net_info(ctrlinfo, fd, 0);
        if (is_in_white(ctrlinfo)) {
            LOGI("taurus: in %s: in white list\n", __FUNCTION__);
            return g_old_read(fd, buf, count);
        }
        ctrlinfo._mask |= MASK_API;
        ctrlinfo._api = __FUNCTION__;
        ctrlinfo._uniqid += get_uuid();
        // check rule
        CJsonWrapper::NodeType reportdata = CJsonWrapper::create_object_node();
        if (reportdata != 0) {
            ControlInfo::serial_json(ctrlinfo, reportdata);
#ifdef EMPTYLIB
            result = 1;
#else
            result = RemoteRuleManager::judge_remote(ctrlinfo._uniqid, reportdata);
#endif
        }
        if (reportdata != 0) {
            CJsonWrapper::add_object_int_node(reportdata, "result", result);
#ifndef NDEBUG // report
            Report::get_instance().log(Report::SENDER_LIB, Report::LEVEL_INFO,
                    __LINE__, __FILE__, reportdata);
#endif
            CJsonWrapper::release_root_node(reportdata);
        }
        if (!RemoteRuleManager::ispass(result)) { // 1放过   0拒绝
            LOGI("taurus: %s blocked!\n", __FUNCTION__);
            errno = ETIMEDOUT;
            return -1;
        } else {
            LOGI("taurus: %s passed!\n", __FUNCTION__);
        }
        return g_old_read(fd, buf, count);
    }
#endif
#ifdef HOOK_WRITE
    ssize_t(*g_old_write)(int fd, const void* buf, size_t count) = 0;
    ssize_t(*g_tau_write)(int fd, const void* buf, size_t count) = 0;

    ssize_t write(int fd, const void* buf, size_t count) {
        /**
         * May be 0: buf
         */
        // LOGI("taurus: in %s\n", __FUNCTION__); // 避免循环调用
        if (!s_g_init_hook) {
            TaurusManager::init_hook();
        }
        if (!s_g_init_hook || !s_g_init_taurus) {
            LOGI("taurus: in %s: init not done\n", __FUNCTION__);
            return g_old_write(fd, buf, count);
        }
        if (fd <= 0 || buf == 0) {
            return g_old_write(fd, buf, count);
        }
        if (!is_sock(fd) || get_sock_family(fd) != AF_INET || get_sock_type(fd) != SOCK_DGRAM) {
            // 此函数频繁调用，因此预先筛选
            return g_old_write(fd, buf, count);
        }
        /*-------------------------------注意在该行代码前不能存在write循环调用------------------------------*/
        // construct dict
        int result = 0;
        ControlInfo ctrlinfo;
        InfoManager::get_instance().copy_ctrlinfo(ctrlinfo);
        get_common_net_info(ctrlinfo, fd, 0);
        if (is_in_white(ctrlinfo)) {
            LOGI("taurus: in %s: in white list\n", __FUNCTION__);
            return g_old_write(fd, buf, count);
        }
        ctrlinfo._mask |= MASK_API;
        ctrlinfo._api = __FUNCTION__;
        ctrlinfo._uniqid += get_uuid();
        // check rule
        CJsonWrapper::NodeType reportdata = CJsonWrapper::create_object_node();
        if (reportdata != 0) {
            ControlInfo::serial_json(ctrlinfo, reportdata);
#ifdef EMPTYLIB
            result = 1;
#else
            result = RemoteRuleManager::judge_remote(ctrlinfo._uniqid, reportdata);
#endif
        }
        if (reportdata != 0) {
            CJsonWrapper::add_object_int_node(reportdata, "result", result);
#ifndef NDEBUG // report
            Report::get_instance().log(Report::SENDER_LIB, Report::LEVEL_INFO,
                    __LINE__, __FILE__, reportdata);
#endif
            CJsonWrapper::release_root_node(reportdata);
        }
        if (!RemoteRuleManager::ispass(result)) { // 1放过   0拒绝
            LOGI("taurus: %s blocked!\n", __FUNCTION__);
            errno = ETIMEDOUT;
            return -1;
        } else {
            LOGI("taurus: %s passed!\n", __FUNCTION__);
        }
        return g_old_write(fd, buf, count);
    }
#endif
#ifdef HOOK_DLOPEN
    void* (*g_old_dlopen)(const char*, int) = 0;

    EXPORT void* dlopen(const char *filename, int flag) {
        if (!s_g_init_hook) {
            TaurusManager::init_hook();
        }
        if (!s_g_init_hook || !s_g_init_taurus) {
            LOGI("taurus: in %s: init not done\n", __FUNCTION__);
            return g_old_dlopen(filename, flag);
        }
        if (filename == 0) {
            return g_old_dlopen(filename, flag);
        }
        if (!strcmp(filename, LIBC_1) || !strcmp(filename, LIBC_2)) {
            return s_g_handle;
        }
        return g_old_dlopen(filename, flag);
    }
#endif
#ifdef HOOK_DLSYM
    void* (*g_old_dlsym)(void *, const char *) = 0;

    EXPORT void* dlsym(void *handle, const char *symbol) {
        /**
         * may be -1/-2: handle  
         * may be 0: symbol
         */
        if (!s_g_init_hook) {
            TaurusManager::init_hook();
        }
        if (symbol == 0) {
            return g_old_dlsym(handle, symbol);
        }
#ifdef HOOK_DLOPEN
        if (handle == s_g_handle) {
#endif
            // 若被hook则返回本模块同名函数，否则返回系统库函数
            if (0) {
#ifdef HOOK_CONNECT
            } else if (!strcmp(symbol, "connect")) {
                return (void*) g_tau_connect;
                ;
#endif
#ifdef HOOK_ACCEPT
            } else if (!strcmp(symbol, "accept")) {
                return (void*) g_tau_accept;
#endif
#ifdef HOOK_ACCEPT4
            } else if (!strcmp(symbol, "accept4")) {
                return (void*) g_tau_accept4;
#endif
#ifdef HOOK_BIND
            } else if (!strcmp(symbol, "bind")) {
                return (void*) g_tau_bind;
#endif
#ifdef HOOK_SEND
            } else if (!strcmp(symbol, "send")) {
                return (void*) g_tau_send;
#endif
#ifdef HOOK_SENDTO
            } else if (!strcmp(symbol, "sendto")) {
                return (void*) g_tau_sendto;
#endif
#ifdef HOOK_SENDMSG
            } else if (!strcmp(symbol, "sengmsg")) {
                return (void*) g_tau_sendmsg;
#endif
#ifdef HOOK_WRITE
            } else if (!strcmp(symbol, "write")) {
                return (void*) g_tau_write;
#endif
#ifdef HOOK_RECV
            } else if (!strcmp(symbol, "recv")) {
                return (void*) g_tau_recv;
#endif
#ifdef HOOK_RECVFROM
            } else if (!strcmp(symbol, "recvfrom")) {
                return (void*) g_tau_recvfrom;
#endif
#ifdef HOOK_RECVMSG
            } else if (!strcmp(symbol, "recvmsg")) {
                return (void*) g_tau_recvmsg;
#endif
#ifdef HOOK_READ
            } else if (!strcmp(symbol, "read")) {
                return (void*) g_tau_read;
#endif
            }
#ifdef HOOK_DLOPEN
        }
#endif
        return g_old_dlsym(handle, symbol);
    }
#endif
#ifdef __cplusplus
}
#endif

static int get_symbol_cb(const char *libpath, const char *libname,
        const char *objname, const void *addr, const size_t size,
        const int binding, const int type, void *custom __attribute__ ((unused))) {
    UNUSED(libname);
    UNUSED(size);
    UNUSED(binding);
    if (type == FUNC_SYMBOL) {
        if (strstr(libpath, LD_NAME) != 0) {
#ifdef HOOK_DLOPEN
            if (!strcmp(objname, "dlopen")) {
                g_old_dlopen = (typeof (g_old_dlopen))addr;
            }
#endif
#ifdef HOOK_DLSYM
            if (!strcmp(objname, "dlsym")) {
                g_old_dlsym = (typeof (g_old_dlsym))addr;
            }
#endif
            return 0;
        }
        bool islibc = strstr(libpath, LIBC_NAME) != 0; // 有些二进制使用/opt下的libc
        bool istau = strstr(libpath, TAU_NAME) != 0;
        if (!islibc && !istau) {
            return 0;
        }
        if (0) {
#ifdef HOOK_CONNECT
        } else if (!strcmp(objname, "connect")) {
            if (islibc) {
                g_old_connect = (typeof (g_old_connect))addr;
            } else if (istau) {
                g_tau_connect = (typeof (g_old_connect))addr;
            }
            return 0;
#endif
#ifdef HOOK_ACCEPT
        } else if (!strcmp(objname, "accept")) {
            if (islibc) {
                g_old_accept = (typeof (g_old_accept))addr;
            } else if (istau) {
                g_tau_accept = (typeof (g_old_accept))addr;
            }
            return 0;
#endif
#ifdef HOOK_ACCEPT4
        } else if (!strcmp(objname, "accept4")) {
            if (islibc) {
                g_old_accept4 = (typeof (g_old_accept4))addr;
            } else if (istau) {
                g_tau_accept4 = (typeof (g_old_accept4))addr;
            }
            return 0;
#endif
#ifdef HOOK_SEND
        } else if (!strcmp(objname, "send")) {
            if (islibc) {
                g_old_send = (typeof (g_old_send))addr;
            } else if (istau) {
                g_tau_send = (typeof (g_old_send))addr;
            }
            return 0;
#endif
#ifdef HOOK_RECV
        } else if (!strcmp(objname, "recv")) {
            if (islibc) {
                g_old_recv = (typeof (g_old_recv))addr;
            } else if (istau) {
                g_tau_recv = (typeof (g_old_recv))addr;
            }
            return 0;
#endif    
#ifdef HOOK_SENDTO
        } else if (!strcmp(objname, "sendto")) {
            if (islibc) {
                g_old_sendto = (typeof (g_old_sendto))addr;
            } else if (istau) {
                g_tau_sendto = (typeof (g_old_sendto))addr;
            }
            return 0;
#endif
#ifdef HOOK_RECVFROM
        } else if (!strcmp(objname, "recvfrom")) {
            if (islibc) {
                g_old_recvfrom = (typeof (g_old_recvfrom))addr;
            } else if (istau) {
                g_tau_recvfrom = (typeof (g_old_recvfrom))addr;
            }
            return 0;
#endif
#ifdef HOOK_SENDMSG
        } else if (!strcmp(objname, "sendmsg")) {
            if (islibc) {
                g_old_sendmsg = (typeof (g_old_sendmsg))addr;
            } else if (istau) {
                g_tau_sendmsg = (typeof (g_old_sendmsg))addr;
            }
            return 0;
#endif   
#ifdef HOOK_RECVMSG
        } else if (!strcmp(objname, "recvmsg")) {
            if (islibc) {
                g_old_recvmsg = (typeof (g_old_recvmsg))addr;
            } else if (istau) {
                g_tau_recvmsg = (typeof (g_old_recvmsg))addr;
            }
            return 0;
#endif
#ifdef HOOK_READ
        } else if (!strcmp(objname, "read")) {
            if (islibc) {
                g_old_read = (typeof (g_old_read))addr;
            } else if (istau) {
                g_tau_read = (typeof (g_old_read))addr;
            }
            return 0;
#endif
#ifdef HOOK_WRITE
        } else if (!strcmp(objname, "write")) {
            if (islibc) {
                g_old_write = (typeof (g_old_write))addr;
            } else if (istau) {
                g_tau_write = (typeof (g_old_write))addr;
            }
            return 0;
#endif
        }
    }
    return 0;
}

static void check_env() {
    if (!file_exist(LD_PATH) || !file_exist(LIBC_PATH)) {
        LOGI("taurus:system lib not found");
        _Exit(-200);
    }
}

const char* g_ip_in_white[] = {
    "cq02-nsi-soc01.cq02",
    "cq02-nsi-soc02.cq02",
    "cq02-nsi-soc03.cq02",
    "nj02-sys-smart01.nj02",
    "nj02-sys-smart02.nj02",
    "nj02-sys-smart03.nj02",
    0
};
static std::set<std::string> s_white_ip_list;

// 白名单检测

bool is_in_white(const ControlInfo& ctrlinfo) {
    if (ctrlinfo._dstip.find("127") == 0 || ctrlinfo._dstip == ctrlinfo._srcip) { // 忽略环回地址
        return true;
    }
    unsigned int i = 0;
    while (g_white_exe_list[i]) {
        if (!fnmatch(g_white_exe_list[i], ctrlinfo._exe.c_str(), 0)) { // 正则匹配
            return true;
        }
        ++i;
    }

    std::set<std::string>::iterator itor = s_white_ip_list.begin();
    while (itor != s_white_ip_list.end()) {
        if (ctrlinfo._dstip == (*itor)) {
            return true;
        }
        ++itor;
    }
    return false;
}

void TaurusManager::init_hook() {
    check_env();
    symbols(get_symbol_cb, 0);
    if (
#ifdef HOOK_DLOPEN
            g_old_dlopen == 0 ||
#endif
#ifdef HOOK_DLSYM
            g_old_dlsym == 0 ||
#endif
#ifdef HOOK_CONNECT
            g_old_connect == 0 ||
#endif
#ifdef HOOK_ACCEPT
            g_old_accept == 0 ||
#endif
#ifdef HOOK_ACCEPT4
            g_old_accept4 == 0 ||
#endif
#ifdef HOOK_SEND
            g_old_send == 0 ||
#endif    
#ifdef HOOK_RECV
            g_old_recv == 0 ||
#endif
#ifdef HOOK_SENDTO
            g_old_sendto == 0 ||
#endif
#ifdef HOOK_RECVFROM
            g_old_recvfrom == 0 ||
#endif
#ifdef HOOK_SENDMSG
            g_old_sendmsg == 0 ||
#endif
#ifdef HOOK_RECVMSG
            g_old_recvmsg == 0 ||
#endif
#ifdef HOOK_READ
            g_old_read == 0 ||
#endif
#ifdef HOOK_WRITE
            g_old_write == 0 ||
#endif
            false
            ) {
        LOGI("taurus: FATAL ERROR: api ptr not init");
        _Exit(-100);
    }
    s_g_init_hook = true;
}
    
void TaurusManager::init_taurus() {
    if (s_g_init_taurus) {
        return;
    }
    // 避免构造重入
    InfoManager::get_instance();
    Report::get_instance();

    // 初始化白名单
    unsigned int i = 0;
    while (g_ip_in_white[i]) {
        std::vector<std::string> result = get_ipn_by_host(g_ip_in_white[i]);
        s_white_ip_list.insert(result.begin(), result.end());
        ++i;
    }
    s_g_init_taurus = true;
    
    pthread_t subth = -1;
    pthread_create(&subth, 0, (void* (*)(void*))&TaurusManager::init_taurus, 0);
}
    
TaurusManager::TaurusManager() {
    init_hook();
    pthread_t subth = -1;
    pthread_create(&subth, 0, (void* (*)(void*))&TaurusManager::init_taurus, 0);
}

