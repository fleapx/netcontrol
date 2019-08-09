#ifndef TAURUS_COMMON_HEADERS_H
#define TAURUS_COMMON_HEADERS_H

// Linux headers
#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <dlfcn.h>
#include <execinfo.h>
#include <errno.h>
#include <fcntl.h>
#include <fnmatch.h>
#include <libgen.h>
#include <limits.h>
#include <net/if.h>
#include <netdb.h>
#include <pthread.h>
#include <pwd.h>
#include <regex.h>
#include <semaphore.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/epoll.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <tr1/unordered_map>
#include <tr1/memory>
#include <unistd.h>

// C++ headers
#include <algorithm>
#include <fstream>
//#include <thread>
#include <iostream>
#include <sstream>
#include <string>
#include <streambuf>
#include <vector>
#include <map>
#include <set>

#define EXPORT  __attribute__ ((visibility ("default")))
#define INIT    __attribute__((constructor))
#define STR(s)  #s

#if defined(__arm__) || defined(__i386__) || defined(__mips__)
#define BIT32
#elif defined(__x86_64__) || defined(__mips64) || defined(__aarch64__)
#define BIT64
#endif

void logfunci(const char*, ...);
void logfunce(const char*, ...);
void logfuncw(const char*, ...);

#ifdef NDEBUG // release
#define LOGI(...)
#define LOGE(...)
#define LOGW(...)
#else                   // debug
#define LOGI logfunci
#define LOGE logfunce
#define LOGW logfuncw
#endif

class Locker {
public:
    Locker(pthread_mutex_t& lock) : _lock(lock) {
        pthread_mutex_lock(&this->_lock);
    }
    ~Locker() {
        pthread_mutex_unlock(&this->_lock);
    }
private:
    pthread_mutex_t& _lock;
};

class Flocker {
public:
    static bool islock(int pid_file) {
        // 注意，如果文件的所有打开句柄均关闭则文件锁无效
        if (pid_file == -1) {
            return false;
        }
        bool locked = false;
        do {
            if (flock(pid_file, LOCK_EX | LOCK_NB)) {
                if (EWOULDBLOCK == errno) {  // locked
                    locked = true;
                }
                break;
            } else {
                flock(pid_file, LOCK_UN);  // unlocked
                break;
            }
        } while (false);
        return locked;
    }
    
    static int lock_process(int pid_file) {
        // 注意，如果文件的所有打开句柄均关闭则文件锁无效
        if (pid_file == -1) {
            return -1; // priviledge not enough
        }
        int ret = 0;
        do {
            if (flock(pid_file, LOCK_EX | LOCK_NB)) {
                if (EWOULDBLOCK == errno) {
                    ret = 0; // another instance is running
                    break;
                }
            } else {
                ret = 1; // this is the first instance
                break;
            }
            ret = -2; // unknown error
        } while (false);
        return ret;
    }
    
    Flocker(const std::string& lockf) {
        struct stat buffer;
        if (stat(lockf.c_str(), &buffer) == 0) { // file exist
            this->_lockfd = open(lockf.c_str(), O_RDWR);
        } else {
            this->_lockfd = open(lockf.c_str(), O_CREAT | O_RDWR);
        }
        if (this->_lockfd < 0) {
            return;
        }
        flock(this->_lockfd, LOCK_EX);
    }
    ~Flocker() {
        if (this->_lockfd < 0) {
            return;
        }
        flock(this->_lockfd, LOCK_UN);
    }
    
private:
    int _lockfd;
};

class TimeTester {
public:
    TimeTester(const std::string& tag) {
        this->_tag = tag;
        gettimeofday(&this->_start, 0);
    }
    ~TimeTester() {
        gettimeofday(&this->_end, 0);
        unsigned long t = (unsigned long)((this->_end.tv_sec - this->_start.tv_sec) * 1000000);
        t += (unsigned long)(this->_end.tv_usec - this->_start.tv_usec);
        LOGI("%s ElapsedTime:%ld", this->_tag.c_str(), t);
    }
private:
    std::string _tag;
    struct timeval _start;
    struct timeval _end;
};

#define ARRLEN(X) (sizeof(X)/sizeof(X[0]))
#define UNUSED(x) (void)(x)
#define BP kill(getpid(), SIGTRAP); // 临时断点

#if CHAR_BIT != 8
#error "UNSUPPORTED CHAR SIZE"
#endif
#if BYTE_ORDER == BIG_ENDIAN
#error "BIG ENDIAN NOT SUPPORTED"
#endif

/*
    1 == IP地址
    2 == IP+子网 (0.0.0.0/0)
    3 == IP范围 (10.0.0.1-10.0.1.100)
    4 == 机器名     已经经过转换
    5 == 域名       一个域名可对应多个IP
    6 == BNS名      已经经过转换
    255 == 地址集合 
 */
enum MTYPE { // IP地址、端口描述类型
    IP_TYPE_DOTDEC = 1, 
    IP_TYPE_SUBNET = 2, 
    IP_TYPE_RANGE = 3,  
    IP_TYPE_MANAME = 4, 
    IP_TYPE_DONAME = 5, 
    IP_TYPE_BNS = 6,   
    IP_TYPE_SET = 0xff,  
    
    PORT_TYPE_RANGE = 0x103, 
};

enum BASE_INFO {
    MASK_EXE = 1,
    MASK_MD5 = 2,
    MASK_CMD = 4,
    MASK_PEXE = 0x1000000,
    MASK_PMD5 = 0x2000000,
    MASK_PCMD = 0x4000000,
    MASK_SRCIP = 8,
    MASK_DSTIP = 0x10,
    MASK_IP = 0x18,
    MASK_SRCPORT = 0x20,
    MASK_DSTPORT = 0x40,
    MASK_PORT = 0x60,
    MASK_SRC = 0x28,
    MASK_DST = 0x50,
    MASK_SOTYPE = 0x80,
    MASK_PROTO = 0x100,
    MASK_FAMILY = 0x200,
    MASK_BAAS_USRN = 0x400,
    MASK_BAAS_GRPN = 0x800,
    MASK_BAAS_ROLE = 0x1000,
    MASK_API = 0x2000,
};

enum {
    ERR_SUCCESS = 0,
    ERR_SOCKFAIL = -1,
    ERR_CONNFAIL = -2,
    ERR_SENDFAIL = -3,
    ERR_BINDFAIL = -4,
    ERR_LISTFAIL = -5,
    ERR_FIFOFAIL = -10,
    ERR_OPENFAIL = -11,
    ERR_EPCRFAIL = -12,
    ERR_EPCTFAIL = -13,
    ERR_WRITFAIL = -14,
    ERR_READFAIL = -15,
    ERR_FORKFAIL = -20,

    ERR_NOFILE = -100,
    ERR_READFILE = -101,
    ERR_JSONNULL = -110,
    ERR_JSONPARSE = -111,
    ERR_JSONCROBJ = -112,
    ERR_JSONGEOBJ = -113,
};

enum {
    ACTION_OTHACEPT = 200,    // 其他放行条件
    
    ACTION_SUB_MISSOTYPE = 110, // 子规则sotype不匹配
    ACTION_SUB_MISDST = 109, // 子规则dstport不匹配
    ACTION_SUB_MISSRC = 108, // 子规则srcport不匹配
    ACTION_SUB_MISMD5 = 107, // 子规则md5不匹配
    ACTION_SUB_MISEXE = 106, // 子规则exe不匹配
    ACTION_SUB_MISDIREC_1 = 105, // 子规则direction不匹配
    ACTION_SUB_MISDIREC_2 = 104, // 子规则direction不匹配
    ACTION_SUB_MISMASK = 103, // 子规则mask不匹配
    ACTION_SUB_DISABLE = 100, // 子规则未启用
    
    ACTION_ERR_MISID = 13,  // uniqid不匹配
    ACTION_ERR_JSONPARSE = 12, // Json解析失败，放行
    ACTION_ERR_LSOCKCON = 11, // 通信失败，放行
    ACTION_ERR_JSONGEOBJ = 10, // Json操作失败，放行
    ACTION_NOAREA = 8,        // 不在机器表中，放行
    ACTION_IGNORE_NONHOOK = 7, // 不关心的socket api，放行
    ACTION_IGNORE_LOOPBACK = 6, // 环回地址，放行
    ACTION_IGNORE_NONIPV4 = 5, // IPv4以外的协议，放行
    ACTION_WHITE = 4,              // 在白名单中，放行
    ACTION_SWITCHOFF = 3,     // 云控关闭，放行
    ACTION_UNINIT = 2,             // RuleManager未初始化，放行
    ACTION_RULACEPT = 1,       // 规则放行
    ACTION_RULPASS = 0,         // 规则未命中，进行下次判决
    ACTION_RULRJECT = -1,      // 规则拒绝
    ACTION_RULNONE = -2,     // 规则未命中，拒绝
    ACTION_NOSRCIP = -3,        // 无法获取源IP
    ACTION_OTHRJECT = -10,  // 其他拒绝条件
};

enum {
    DIRECT_IN = 1,
    DIRECT_OUT = 2,
    DIRECT_ALL = 3,
};

enum {
    MATCH_COMMON,  // 普通方式匹配
    MATCH_WILDCHAR, // 通配符匹配
    MATCH_REGEX         // 正则匹配
};

namespace std {
template<typename T, size_t N>
T * end(T (&ra)[N]) {
    return ra + N;
}
}

extern const char* g_service_policy_tunnel;
extern const char* g_taurus_lib_lock;
extern const char* g_white_exe_list[];

#include "interface.h"

#endif //TAURUS_COMMON_HEADERS_H
