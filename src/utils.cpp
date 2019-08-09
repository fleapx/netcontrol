#include "utils.h"

const char* g_service_policy_tunnel = "A/tmp/taurus.policy"; // 用于策略判决
const char* g_taurus_lib_lock = "/tmp/taurus.lock"; // 普通进程和server的unix socket通信锁

const char* g_white_exe_list[] = {
    "/usr/bin/taurus*",
    "/noah/modules*",
    "/noah/run/baas/modules*",
    "/sbin/noah",
    "/var/lib/misc/noah",
    "/bin/ping",
    0
};

/* -------------------------------------- 工具函数 -------------------------------------- */

/**
 * 执行命令获取输出
 * @param cmd       命令
 * @param content  缓冲区  
 * @return 
 */
int get_cmd_output(const std::string &cmd, std::string &content) {
    std::string tcmd = cmd + " 2>&1";
    char tcontent[PATH_MAX];
    int status = -1;
    content = "";
    FILE* stream = popen(tcmd.c_str(), "r");
    if (!stream) {
        return -255;
    }
    while (fgets(tcontent, PATH_MAX, stream)) {
        content += tcontent;
        content += "\n";
    }
    status = pclose(stream);
    return status;
}

/**
 * 获取进程资源占用
 * @return 
 */
struct rusage* get_process_info() {
    static struct rusage ru;
    memset(&ru, 0, sizeof (ru));
    getrusage(RUSAGE_SELF, &ru);
    return &ru;
}

/**
 * 获取内核数
 * @return 
 */
int get_processor_num() {
    return get_nprocs_conf();
}

/**
 * 获取系统资源占用：内核数、内存量、启动时间
 * @return 
 */
struct sysinfo* get_sysinfo() {
    static struct sysinfo si;
    memset(&si, 0, sizeof (si));
    sysinfo(&si);
    return &si;
}

/**
 * 获取时间字符串
 * @return 
 */
std::string get_time_tag() {
    time_t t = time(0);
    struct tm* tm_ = localtime(&t);
    char s[64];
    strftime(s, sizeof (s), "%c", tm_);
    return std::string(s);
}

/**
 * 生成唯一标识
 * @return 
 */
std::string get_uuid() {
    const int UUID_LEN = 6; // "pass" "deny" l=4
    const char dict[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    char struuid[UUID_LEN] = {0};
    int i = 0;
    srand(time(NULL));
    for (i = 0; i < UUID_LEN - 1; i++) {
        struuid[i] = dict[rand() % (sizeof (dict) - 1)];
    }
    return std::string(struuid);
}

/**
 * log error
 * @param fmt   格式串
 * @param ...       多个参数
 */
void logfunce(const char* fmt, ...) {
    va_list argptr;
    va_start(argptr, fmt);
    vsyslog(LOG_ERR, fmt, argptr);
    va_end(argptr);
}

/**
 * log info
 * @param fmt   格式串
 * @param ...       多个参数
 */
void logfunci(const char* fmt, ...) {
    va_list argptr;
    va_start(argptr, fmt);
    vsyslog(LOG_INFO, fmt, argptr);
    va_end(argptr);
}

/**
 * log warning
 * @param fmt   格式串
 * @param ...       多个参数
 */
void logfuncw(const char* fmt, ...) {
    va_list argptr;
    va_start(argptr, fmt);
    vsyslog(LOG_WARNING, fmt, argptr);
    va_end(argptr);
}

/**
 * print backtrace
 */
void print_backtrace() {
    syslog(LOG_INFO, "---------------------------BACKTRACE BEGIN---------------------------\n");
    void* buffer[100];
    int i = 0;
    int bt_size = backtrace(buffer, ARRLEN(buffer));
    char** bt_syms = backtrace_symbols(buffer, bt_size);
    if (bt_syms != 0) {
        for (i = 0; i < bt_size; i++) {
            syslog(LOG_INFO, bt_syms[i]);
        }
    }
    syslog(LOG_INFO, "---------------------------BACKTRACE END---------------------------\n");
}

/**
 * 正则匹配
 * @param pattern   模式串
 * @param str           目标串
 * @return 
 */
bool regmatch(const char* pattern, const char* str) {
    regex_t re;
    int err = 0;
    if (0 != regcomp(&re, pattern, REG_EXTENDED)) {
        return false;
    }
    err = regexec(&re, str, 0, 0, 0);
    regfree(&re);
    return err == 0;
}

/**
 * 分割字符串
 * @param s         源串
 * @param token 分割标记
 * @return 
 */
std::vector<std::string> split(const std::string& s, char token) {
    std::vector<std::string> out;
    std::istringstream iss(s);
    std::string l;
    while (std::getline(iss, l, token)) {
        out.push_back(l);
    }
    return out;
}

typedef int (*child_fn) (void*);

int run_in_child_inner(void* args) {
    child_fn fn = (child_fn) ((void**) args)[0];
    void* arg = (void*) ((void**) args)[1];
    int* ret = (int*) ((void**) args)[2];
    *ret = fn(arg);
    return 0;
}

/**
 * 在子进程中执行函数
 * @param mode      fork / clone
 * @param stacksize 子进程函数栈大小(用于clone)
 * @param fn            函数指针
 * @param arg          fn参数
 * @param ret           返回值
 * @param wait        是否等待子进程返回
 * @return                 子进程PID
 */
pid_t run_in_child(int mode, int stacksize, child_fn fn, void* arg, int* ret, unsigned int flags) {
    if (!fn) {
        return -1;
    }
    if (mode == CHILD_MODE_FORK) {
        pid_t pid = fork();
        if (pid == 0) { // pid == 0
            int cret = fn(arg);
            _Exit(cret); //  避免执行到父进程代码空间；此时会执行父进程"进程结束回调"
        }
        if (flags & CHILD_FLAGS_WAIT) {
            if (ret != 0) {
                waitpid(pid, ret, 0);
                *ret = WEXITSTATUS(*ret);
            } else {
                waitpid(pid, 0, 0);
            }
        }
        // 这里取不到子进程返回值，不赋值ret，需要父进程通过waitpid获取返回值
        return pid; // 只返回子进程PID
    } else if (mode == CHILD_MODE_VFORK) {
        pid_t pid = vfork();
        if (pid == 0) { // pid == 0
            int cret = fn(arg);
            _Exit(cret); //  避免执行到父进程代码空间；此时会执行父进程"进程结束回调"
        }
        if (flags & CHILD_FLAGS_WAIT) {
            if (ret != 0) {
                waitpid(pid, ret, 0);
                *ret = WEXITSTATUS(*ret);
            } else {
                waitpid(pid, 0, 0);
            }
        }
        // 这里取不到子进程返回值，不赋值ret，需要父进程通过waitpid获取返回值
        return pid; // 只返回子进程PID
    } else if (mode == CHILD_MODE_CLONE) {
        void* stack_begin = malloc(stacksize);
        void* stack_end = (void*) ((char*) stack_begin + stacksize);
        if (!stack_begin) {
            return -2;
        }
        /* 需要little-endian
         *  CLONE_VM允许内存共享，因此可以直接可以从父进程获取到返回值
         *  CLONE_VFORK为同步机制
         *  CLONE_PARENT设为兄弟节点，防止进程僵死
         */
        void* tmparg[3] = {(void*) fn, (void*) arg, (void*) ret}; // 不可动态分配
        // CLONE_PARENT | CLONE_VM 可以取到返回值
        pid_t pid = clone(run_in_child_inner, stack_end, flags, (void*) &tmparg);
        if (flags & CHILD_FLAGS_WAIT) {
            waitpid(pid, 0, 0);
        }
        return pid;
    }
    return -3;
}

/* -------------------------------------- 文件&进程 -------------------------------------- */

/**
 * 清空启动参数
 * @param argc      main参数
 * @param argv      main参数
 */
void clear_argv(int argc, char** argv) {
    int i = 0;
    for (i = 1; i < argc; i++) { // 只显示进程名
        memset(argv[i], 0, strlen(argv[i]));
    }
}

/**
 * 检测进程是否存在
 * @param pid       进程ID
 * @return 
 */
bool exist_proc(pid_t pid) {
    char path[PATH_MAX];
    snprintf(path, PATH_MAX, "/proc/%d", pid);
    return file_exist(path);
}

/**
 * 检测文件/目录存在
 * @param 路径
 * @return
 */
bool file_exist(const char *path) {
    struct stat buffer;
    return (stat(path, &buffer) == 0);
}

/**
 * 获取命令行
 * @return 
 */
std::string get_cmdline(int pid) {
    std::ifstream file;
    if (pid == -1) {
        file.open("/proc/self/cmdline");
    } else {
        char path[32];
        snprintf(path, sizeof (path), "/proc/%d/cmdline", pid);
        file.open(path);
    }
    std::string line = "$unknown$";
    std::getline(file, line);
    file.close();
    std::replace(line.begin(), line.end(), '\0', ' ');
    line = line.substr(0, 256);
    return line;
}

/**
 * 获取指定环境变量
 * @param name  PATH ...
 * @return 
 */
std::vector<std::string> get_env(const std::string& name) {
    std::vector<std::string> result;
    char* cenv = getenv(name.c_str());
    if (cenv == 0) {
        return result;
    }
    std::string allenv(cenv);
    std::istringstream iss(allenv);
    std::string line;
    while (std::getline(iss, line, ':')) {
        if (line.length()) {
            result.push_back(line);
        }
    }
    return result;
}

/**
 * 获取进程文件路径
 * @param pid   进程ID
 * @return 
 */
std::string get_exe_path(int pid) {
    char link[PATH_MAX];
    memset(link, 0, sizeof (link));
    if (pid == -1) {
        if (readlink("/proc/self/exe", link, sizeof (link)) > 0) {
            return std::string(link);
        } else {
            return std::string("$unknown$");
        }
    } else {
        char path[32];
        snprintf(path, sizeof (path), "/proc/%d/exe", pid);
        if (readlink(path, link, sizeof (link)) > 0) {
            return std::string(link);
        } else {
            return std::string("$unknown$");
        }
    }
}

/**
 * 获取小文本文件内容
 * @param path      路径
 * @param content 缓冲区
 * @return 
 */
bool get_file_content(const std::string& path, std::string& content) {
    std::ifstream t(path.c_str());
    content = "";
    if (!t.is_open()) {
        return false;
    }
    t.seekg(0, std::ios::end);
    content.reserve(t.tellg());
    t.seekg(0, std::ios::beg);
    content.assign((std::istreambuf_iterator<char>(t)), std::istreambuf_iterator<char>());
    t.close();
    return true;
}

/**
 * 获取文本文件最后一行
 * @param fin
 * @param line
 */
std::string& get_last_line(std::ifstream& fin, std::string& line) {
    fin.seekg(-1, std::ios_base::end);
    bool keeplooping = true;
    while (keeplooping) {
        char ch = 0;
        fin.get(ch);
        if ((int) fin.tellg() <= 1) {
            fin.seekg(0);
            keeplooping = false;
        } else if (ch == '\n') {
            keeplooping = false;
        } else {
            fin.seekg(-2, std::ios_base::cur);
        }
    }
    getline(fin, line);
    return line;
}

/**
 * 获取进程父进程PID
 * @param pid   进程ID
 * @return 
 */
pid_t get_ppid(int pid) {
    if (pid == -1) {
        return getppid();
    }

    pid_t fpid = -1;
    char procpath[32];
    char buf[256];
    snprintf(procpath, sizeof (procpath), "/proc/%d/stat", pid);
    if (!file_exist(procpath)) {
        return -1;
    }
    FILE* fp = fopen(procpath, "r");
    if (fp != 0) {
        char* line = 0;
        size_t len = 0;
        ssize_t nread = getline(&line, &len, fp);
        if (nread != -1 && line != 0) {
            if (nread > (int) (sizeof (buf) - 1)) {
                line[sizeof (buf) - 1] = '\0'; // 裁剪字符串，避免溢出
            }
        }
        sscanf(line, "%s %s %s %s %d", buf, buf, buf, buf, &fpid);
        fclose(fp);
    }
    return fpid;
}

/**
 * 获取根目录指定文件名格式的文件
 * @param path        根路径
 * @param filter        文件名正则匹配
 * @return 
 */
std::vector<std::string> get_root_files(const std::string& path, const std::string& filter) {
    std::vector<std::string> filepaths;
    DIR* dir = opendir(path.c_str());
    if (dir != 0) {
        struct dirent* entry = 0;
        while ((entry = readdir(dir)) != 0) {
            if (entry->d_type == DT_REG && !fnmatch(filter.c_str(), entry->d_name, 0)) {
                filepaths.push_back(path + "/" + entry->d_name);
            }
        }
        closedir(dir);
    }
    return filepaths;
}

/**
 * 检测文本包含字符串
 * @param path      文件路径
 * @param str          待查找字符串
 */
bool is_string_in_file(const std::string& path, const std::string& str) {
    std::ifstream t(path.c_str());
    std::string content = "";
    if (!t.is_open()) {
        return false;
    }
    t.seekg(0, std::ios::end);
    content.reserve(t.tellg());
    t.seekg(0, std::ios::beg);
    content.assign((std::istreambuf_iterator<char>(t)), std::istreambuf_iterator<char>());
    t.close();
    return content.find(str) != std::string::npos;
}

/**
 *  杀死进程
 * @param pid       进程ID
 */
void kill_proc(pid_t pid) {
    kill(pid, SIGKILL);
}

/**
 *  获取回溯栈模块   用于检测调用者所在模块
 * @return 
 */
std::vector<std::string> module_in_backtrace() {
    int j = 0;
    int nptrs = 0;
    const int SIZE = 10;
    void *buffer[SIZE];
    char **strings = 0;
    std::vector<std::string> out;

    nptrs = backtrace(buffer, SIZE);
    if (nptrs > 0) {
        strings = backtrace_symbols(buffer, nptrs);
    }
    if (nptrs > 0 && strings != 0) {
        for (j = 0; j < nptrs; j++) {
            out.push_back(strings[j]);
        }
    }
    free(strings);
    return out;
}

/**
 * 重置文件内容
 * @param path
 * @param str
 * @return 
 */
bool set_file_content(const std::string& path, const std::string& str) {
    std::ofstream file(path.c_str());
    if (file.is_open()) {
        file << str;
        file.close();
        return true;
    }
    return false;
}

/**
 * 修改/proc显示的进程路径
 * @param argv0         main函数首参数
 * @param newtitle     新显示名
 * @return 
 */
bool set_proc_title(char* argv0, const char* newtitle) {
    int wn = 0;
    size_t ml = strlen(argv0) + 1;
    memset(argv0, 0, ml);
    wn = snprintf(argv0, ml, "%s", newtitle);
    return wn >= (int) strlen(newtitle); // false: argv[0]不够容纳newtitle
}

/**
 * 向进程发送信号
 * @param pid       进程ID
 * @param sig        信号
 */
void signal_proc(pid_t pid, int sig) {
    kill(pid, sig);
}

/* -------------------------------------- 网络 -------------------------------------- */

/**
 * 获取本机点分十进制IPv4地址
 * @return 
 */
std::string get_current_ip() {
    std::string current_ip;
    int sfd = -1;
    if ((sfd = socket(AF_INET, SOCK_DGRAM, 0)) > 0) {
        int if_count = 0;
        int i = 0;
        struct ifconf ifc;
        struct ifreq ifr[10];
        char ipaddr[INET_ADDRSTRLEN] = {'\0'};
        memset(&ifc, 0, sizeof (struct ifconf));
        ifc.ifc_len = 10 * sizeof (struct ifreq);
        ifc.ifc_buf = (char *) ifr;
        ioctl(sfd, SIOCGIFCONF, (char *) &ifc);
        if_count = ifc.ifc_len / (sizeof (struct ifreq));
        for (i = 0; i < if_count; i++) {
            if (!strcmp(ifr[i].ifr_name, "lo")) { // skip loop back
                continue;
            }
            memset(ipaddr, 0, sizeof (ipaddr));
            struct sockaddr_storage * store = (struct sockaddr_storage *) &(ifr[i].ifr_addr);
            if (store->ss_family == AF_INET) {
                struct sockaddr_in* addr = (struct sockaddr_in*) store;
                inet_ntop(AF_INET, &(addr->sin_addr), ipaddr, INET_ADDRSTRLEN);
            } else if (store->ss_family == AF_INET6) {
                struct sockaddr_in6* addr = (struct sockaddr_in6*) store;
                inet_ntop(AF_INET6, &(addr->sin6_addr), ipaddr, INET_ADDRSTRLEN);
            }
            current_ip = ipaddr;
        }
        close(sfd);
    }
    return current_ip;
}

/**
 * 获取主机名对应点分十进制IPv4地址整数集
 * @param host      主机名
 * @return 
 */
std::vector<unsigned int> get_ipv4_by_host(const std::string& host) {
    std::vector<unsigned int> out;
    struct hostent* host_info = gethostbyname(host.c_str());
    if (host_info != 0) {
        if (host_info->h_addrtype == AF_INET) {
            struct in_addr **address_list = (struct in_addr **) host_info->h_addr_list;
            int i = 0;
            while (address_list[i] != 0) {
                // use *(address_list[i]) as needed...
                out.push_back(address_list[i]->s_addr);
                i++;
            }
        }
    }
    return out;
}

/**
 * 获取IPv4地址整数对应点分十进制IP地址
 * @param host          主机名
 * @return 
 */
std::string get_ip_from_addr(const in_addr& sa) {
    if (sa.s_addr == 0) {
        return get_current_ip();
    } else {
        char ipstr[INET_ADDRSTRLEN] = "0.0.0.0";
        inet_ntop(AF_INET, (const void*) &sa, ipstr, INET_ADDRSTRLEN);
        return std::string(ipstr);
    }
}

/**
 * 获取主机名对应点分十进制IP地址集
 * @param host          主机名
 * @return 
 */
std::vector<std::string> get_ipn_by_host(const std::string& host) {
    std::vector<std::string> out;
    struct hostent* host_info = gethostbyname(host.c_str());
    if (host_info != 0) {
        if (host_info->h_addrtype == AF_INET) {
            struct in_addr **address_list = (struct in_addr **) host_info->h_addr_list;
            int i = 0;
            while (address_list[i] != 0) {
                char* name = inet_ntoa(*address_list[i]);
                if (name != 0) {
                    out.push_back(std::string(name));
                }
                i++;
            }
        }
    }
    return out;
}

/**
 * 获取点分十进制IP地址对应IPv4地址整数
 * @param ip          IP地址字符串
 * @return 
 */
unsigned int get_ipnv4_from_ip(const std::string& ip) {
    in_addr _ip = {0};
    inet_aton(ip.c_str(), &_ip);
    return _ip.s_addr;
}

/**
 * 获取socket family
 * @param sock      socket句柄
 * @return 
 */
int get_sock_family(int sock) {
    sockaddr tmp_addr;
    socklen_t tmp_addrlen = sizeof (tmp_addr);
    if (0 != getsockname(sock, (sockaddr*) & tmp_addr, &tmp_addrlen)) {
        return -1;
    }
    return tmp_addr.sa_family;
}

/**
 * 获取socket protocol(默认IPPROTO_IP/IPPROTO_TCP/IPPROTO_UDP)
 * @param sock      socket句柄
 * @return 
 */
int get_sock_proto(int sock) {
    int type = -1;
    socklen_t length = sizeof (type);
    if (!getsockopt(sock, SOL_SOCKET, SO_PROTOCOL, &type, &length)) {
        return (type & 0xFF);
    }
    return -1;
}

/**
 * 获取socket type(SOCK_STREAM/SOCK_DGRAM/SOCK_RAW)
 * @param sock      socket句柄
 * @return 
 */
int get_sock_type(int sock) {
    int type = -1;
    socklen_t length = sizeof (type);
    if (!getsockopt(sock, SOL_SOCKET, SO_TYPE, &type, &length)) {
        return (type & 0xF);
    }
    return -1;
}

/**
 * 检测文件描述符是否为socket类型
 * @param fd
 * @return 
 */
bool is_sock(int fd) {
    struct stat statbuf;
    if (0 != fstat(fd, &statbuf)) {
        return false;
    }
    return S_ISSOCK(statbuf.st_mode);
}

/* -------------------------------------- 加解密 -------------------------------------- */
const char b64_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        "0123456789+/";
/* 'Private' declarations */
inline void a3_to_a4(unsigned char * a4, unsigned char * a3);
inline void a4_to_a3(unsigned char * a3, unsigned char * a4);
inline unsigned char b64_lookup(char c);

/**
 * BASE64编码
 * @param input         输入缓冲区
 * @param output      输出缓冲区
 * @return 
 */
int base64_encode(const std::string& input, std::string& output) {
    int i = 0;
    int j = 0;
    int enclen = 0;
    unsigned char a3[3];
    unsigned char a4[4];
    int inputlen = input.length();
    char* c_input = (char*) input.c_str();
    char* c_output = (char*) malloc(inputlen * 2);
    if (c_output == 0) {
        return -1;
    }
    while (inputlen--) {
        a3[i++] = *(c_input++);
        if (i == 3) {
            a3_to_a4(a4, a3);
            for (i = 0; i < 4; i++) {
                c_output[enclen++] = b64_alphabet[a4[i]];
            }
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 3; j++) {
            a3[j] = '\0';
        }
        a3_to_a4(a4, a3);
        for (j = 0; j < i + 1; j++) {
            c_output[enclen++] = b64_alphabet[a4[j]];
        }
        while ((i++ < 3)) {
            c_output[enclen++] = '=';
        }
    }
    c_output[enclen] = '\0';
    output = c_output;
    free((void*) c_output);
    return 0;
}

/**
 * BASE64解码
 * @param input         输入缓冲区
 * @param output      输出缓冲区
 * @return 
 */
int base64_decode(const std::string& input, std::string& output) {
    int i = 0;
    int j = 0;
    int declen = 0;
    unsigned char a3[3];
    unsigned char a4[4];
    int inputlen = input.length();
    char* c_input = (char*) input.c_str();
    char* c_output = (char*) malloc(inputlen);
    if (!c_input) {
        return -1;
    }
    while (inputlen--) {
        if (*c_input == '=') {
            break;
        }
        a4[i++] = *(c_input++);
        if (i == 4) {
            for (i = 0; i < 4; i++) {
                a4[i] = b64_lookup(a4[i]);
            }
            a4_to_a3(a3, a4);
            for (i = 0; i < 3; i++) {
                c_output[declen++] = a3[i];
            }
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 4; j++) {
            a4[j] = '\0';
        }
        for (j = 0; j < 4; j++) {
            a4[j] = b64_lookup(a4[j]);
        }
        a4_to_a3(a3, a4);
        for (j = 0; j < i - 1; j++) {
            c_output[declen++] = a3[j];
        }
    }
    c_output[declen] = '\0';
    output = c_output;
    free((void*) c_output);
    return 0;
}

inline void a3_to_a4(unsigned char * a4, unsigned char * a3) {
    a4[0] = (a3[0] & 0xfc) >> 2;
    a4[1] = ((a3[0] & 0x03) << 4) + ((a3[1] & 0xf0) >> 4);
    a4[2] = ((a3[1] & 0x0f) << 2) + ((a3[2] & 0xc0) >> 6);
    a4[3] = (a3[2] & 0x3f);
}

inline void a4_to_a3(unsigned char * a3, unsigned char * a4) {
    a3[0] = (a4[0] << 2) + ((a4[1] & 0x30) >> 4);
    a3[1] = ((a4[1] & 0xf) << 4) + ((a4[2] & 0x3c) >> 2);
    a3[2] = ((a4[2] & 0x3) << 6) + a4[3];
}

inline unsigned char b64_lookup(char c) {
    if (c >= 'A' && c <= 'Z') {
        return c - 'A';
    }
    if (c >= 'a' && c <= 'z') {
        return c - 71;
    }
    if (c >= '0' && c <= '9') {
        return c + 4;
    }
    if (c == '+') {
        return 62;
    }
    if (c == '/') {
        return 63;
    }
    return -1;
}

typedef struct {
    uint32_t lo;
    uint32_t hi;
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    uint8_t buffer[64];
    uint32_t block[16];
} md5_context;

#define MD5_HASH_SIZE           ( 128 / 8 )

typedef struct {
    uint8_t bytes[MD5_HASH_SIZE];
} md5_hash;

#define F( x, y, z )            ( (z) ^ ((x) & ((y) ^ (z))) )
#define G( x, y, z )            ( (y) ^ ((z) & ((x) ^ (y))) )
#define H( x, y, z )            ( (x) ^ (y) ^ (z) )
#define I( x, y, z )            ( (y) ^ ((x) | ~(z)) )
#define STEP( f, a, b, c, d, x, t, s )                          \
    (a) += f((b), (c), (d)) + (x) + (t);                        \
    (a) = (((a) << (s)) | (((a) & 0xffffffff) >> (32 - (s))));  \
    (a) += (b);
#define GET(n) (ctx->block[(n)])
#define SET(n) (ctx->block[(n)] =             \
            ((uint32_t)ptr[(n)*4 + 0] << 0 )      \
        |   ((uint32_t)ptr[(n)*4 + 1] << 8 )      \
        |   ((uint32_t)ptr[(n)*4 + 2] << 16)      \
        |   ((uint32_t)ptr[(n)*4 + 3] << 24) )

static void* transform(md5_context* ctx, void const* data, uintmax_t size) {
    uint8_t* ptr = 0;
    uint32_t a = 0;
    uint32_t b = 0;
    uint32_t c = 0;
    uint32_t d = 0;
    uint32_t saved_a = 0;
    uint32_t saved_b = 0;
    uint32_t saved_c = 0;
    uint32_t saved_d = 0;
    ptr = (uint8_t*) data;
    a = ctx->a;
    b = ctx->b;
    c = ctx->c;
    d = ctx->d;
    do {
        saved_a = a;
        saved_b = b;
        saved_c = c;
        saved_d = d;
        // Round 1
        STEP(F, a, b, c, d, SET(0), 0xd76aa478, 7)
        STEP(F, d, a, b, c, SET(1), 0xe8c7b756, 12)
        STEP(F, c, d, a, b, SET(2), 0x242070db, 17)
        STEP(F, b, c, d, a, SET(3), 0xc1bdceee, 22)
        STEP(F, a, b, c, d, SET(4), 0xf57c0faf, 7)
        STEP(F, d, a, b, c, SET(5), 0x4787c62a, 12)
        STEP(F, c, d, a, b, SET(6), 0xa8304613, 17)
        STEP(F, b, c, d, a, SET(7), 0xfd469501, 22)
        STEP(F, a, b, c, d, SET(8), 0x698098d8, 7)
        STEP(F, d, a, b, c, SET(9), 0x8b44f7af, 12)
        STEP(F, c, d, a, b, SET(10), 0xffff5bb1, 17)
        STEP(F, b, c, d, a, SET(11), 0x895cd7be, 22)
        STEP(F, a, b, c, d, SET(12), 0x6b901122, 7)
        STEP(F, d, a, b, c, SET(13), 0xfd987193, 12)
        STEP(F, c, d, a, b, SET(14), 0xa679438e, 17)
        STEP(F, b, c, d, a, SET(15), 0x49b40821, 22)
        // Round 2
        STEP(G, a, b, c, d, GET(1), 0xf61e2562, 5)
        STEP(G, d, a, b, c, GET(6), 0xc040b340, 9)
        STEP(G, c, d, a, b, GET(11), 0x265e5a51, 14)
        STEP(G, b, c, d, a, GET(0), 0xe9b6c7aa, 20)
        STEP(G, a, b, c, d, GET(5), 0xd62f105d, 5)
        STEP(G, d, a, b, c, GET(10), 0x02441453, 9)
        STEP(G, c, d, a, b, GET(15), 0xd8a1e681, 14)
        STEP(G, b, c, d, a, GET(4), 0xe7d3fbc8, 20)
        STEP(G, a, b, c, d, GET(9), 0x21e1cde6, 5)
        STEP(G, d, a, b, c, GET(14), 0xc33707d6, 9)
        STEP(G, c, d, a, b, GET(3), 0xf4d50d87, 14)
        STEP(G, b, c, d, a, GET(8), 0x455a14ed, 20)
        STEP(G, a, b, c, d, GET(13), 0xa9e3e905, 5)
        STEP(G, d, a, b, c, GET(2), 0xfcefa3f8, 9)
        STEP(G, c, d, a, b, GET(7), 0x676f02d9, 14)
        STEP(G, b, c, d, a, GET(12), 0x8d2a4c8a, 20)
        // Round 3
        STEP(H, a, b, c, d, GET(5), 0xfffa3942, 4)
        STEP(H, d, a, b, c, GET(8), 0x8771f681, 11)
        STEP(H, c, d, a, b, GET(11), 0x6d9d6122, 16)
        STEP(H, b, c, d, a, GET(14), 0xfde5380c, 23)
        STEP(H, a, b, c, d, GET(1), 0xa4beea44, 4)
        STEP(H, d, a, b, c, GET(4), 0x4bdecfa9, 11)
        STEP(H, c, d, a, b, GET(7), 0xf6bb4b60, 16)
        STEP(H, b, c, d, a, GET(10), 0xbebfbc70, 23)
        STEP(H, a, b, c, d, GET(13), 0x289b7ec6, 4)
        STEP(H, d, a, b, c, GET(0), 0xeaa127fa, 11)
        STEP(H, c, d, a, b, GET(3), 0xd4ef3085, 16)
        STEP(H, b, c, d, a, GET(6), 0x04881d05, 23)
        STEP(H, a, b, c, d, GET(9), 0xd9d4d039, 4)
        STEP(H, d, a, b, c, GET(12), 0xe6db99e5, 11)
        STEP(H, c, d, a, b, GET(15), 0x1fa27cf8, 16)
        STEP(H, b, c, d, a, GET(2), 0xc4ac5665, 23)
        // Round 4
        STEP(I, a, b, c, d, GET(0), 0xf4292244, 6)
        STEP(I, d, a, b, c, GET(7), 0x432aff97, 10)
        STEP(I, c, d, a, b, GET(14), 0xab9423a7, 15)
        STEP(I, b, c, d, a, GET(5), 0xfc93a039, 21)
        STEP(I, a, b, c, d, GET(12), 0x655b59c3, 6)
        STEP(I, d, a, b, c, GET(3), 0x8f0ccc92, 10)
        STEP(I, c, d, a, b, GET(10), 0xffeff47d, 15)
        STEP(I, b, c, d, a, GET(1), 0x85845dd1, 21)
        STEP(I, a, b, c, d, GET(8), 0x6fa87e4f, 6)
        STEP(I, d, a, b, c, GET(15), 0xfe2ce6e0, 10)
        STEP(I, c, d, a, b, GET(6), 0xa3014314, 15)
        STEP(I, b, c, d, a, GET(13), 0x4e0811a1, 21)
        STEP(I, a, b, c, d, GET(4), 0xf7537e82, 6)
        STEP(I, d, a, b, c, GET(11), 0xbd3af235, 10)
        STEP(I, c, d, a, b, GET(2), 0x2ad7d2bb, 15)
        STEP(I, b, c, d, a, GET(9), 0xeb86d391, 21)
        a += saved_a;
        b += saved_b;
        c += saved_c;
        d += saved_d;
        ptr += 64;
    } while (size -= 64);
    ctx->a = a;
    ctx->b = b;
    ctx->c = c;
    ctx->d = d;
    return ptr;
}
#undef GET
#undef SET

void md5_init(md5_context* context) {
    context->a = 0x67452301;
    context->b = 0xefcdab89;
    context->c = 0x98badcfe;
    context->d = 0x10325476;
    context->lo = 0;
    context->hi = 0;
}

void md5_update(md5_context* context, void const* buffer, uint32_t buffersize) {
    uint32_t saved_lo;
    uint32_t used;
    uint32_t free;

    saved_lo = context->lo;
    if ((context->lo = (saved_lo + buffersize) & 0x1fffffff) < saved_lo) {
        context->hi++;
    }
    context->hi += (uint32_t) (buffersize >> 29);
    used = saved_lo & 0x3f;
    if (used) {
        free = 64 - used;
        if (buffersize < free) {
            memcpy(&context->buffer[used], buffer, buffersize);
            return;
        }
        memcpy(&context->buffer[used], buffer, free);
        buffer = (uint8_t*) buffer + free;
        buffersize -= free;
        transform(context, context->buffer, 64);
    }
    if (buffersize >= 64) {
        buffer = transform(context, buffer, buffersize & ~(unsigned long) 0x3f);
        buffersize &= 0x3f;
    }
    memcpy(context->buffer, buffer, buffersize);
}

void md5_finit(md5_context* context, md5_hash* digest) {
    uint32_t used;
    uint32_t free;
    used = context->lo & 0x3f;
    context->buffer[used++] = 0x80;
    free = 64 - used;
    if (free < 8) {
        memset(&context->buffer[used], 0, free);
        transform(context, context->buffer, 64);
        used = 0;
        free = 64;
    }
    memset(&context->buffer[used], 0, free - 8);
    context->lo <<= 3;
    context->buffer[56] = (uint8_t) (context->lo);
    context->buffer[57] = (uint8_t) (context->lo >> 8);
    context->buffer[58] = (uint8_t) (context->lo >> 16);
    context->buffer[59] = (uint8_t) (context->lo >> 24);
    context->buffer[60] = (uint8_t) (context->hi);
    context->buffer[61] = (uint8_t) (context->hi >> 8);
    context->buffer[62] = (uint8_t) (context->hi >> 16);
    context->buffer[63] = (uint8_t) (context->hi >> 24);
    transform(context, context->buffer, 64);
    digest->bytes[0] = (uint8_t) (context->a);
    digest->bytes[1] = (uint8_t) (context->a >> 8);
    digest->bytes[2] = (uint8_t) (context->a >> 16);
    digest->bytes[3] = (uint8_t) (context->a >> 24);
    digest->bytes[4] = (uint8_t) (context->b);
    digest->bytes[5] = (uint8_t) (context->b >> 8);
    digest->bytes[6] = (uint8_t) (context->b >> 16);
    digest->bytes[7] = (uint8_t) (context->b >> 24);
    digest->bytes[8] = (uint8_t) (context->c);
    digest->bytes[9] = (uint8_t) (context->c >> 8);
    digest->bytes[10] = (uint8_t) (context->c >> 16);
    digest->bytes[11] = (uint8_t) (context->c >> 24);
    digest->bytes[12] = (uint8_t) (context->d);
    digest->bytes[13] = (uint8_t) (context->d >> 8);
    digest->bytes[14] = (uint8_t) (context->d >> 16);
    digest->bytes[15] = (uint8_t) (context->d >> 24);
}

void md5_calc(void const* buffer, uint32_t buffersize, md5_hash* digest) {
    md5_context context;
    md5_init(&context);
    md5_update(&context, buffer, buffersize);
    md5_finit(&context, digest);
}

std::string get_file_md5(const std::string& filename) {
    md5_context ctx;
    md5_init(&ctx);
    
    char buf[512];
    ssize_t bytes = 0;
    size_t n = 0;
    int m = 0;
    md5_hash hash;
    char dict[] = "0123456789abcdef";
    int fd = open(filename.c_str(), O_RDONLY);
    if (fd != -1) {
#ifdef HOOK_READ
        bytes = g_old_read(fd, buf, sizeof(buf));
#else
        bytes = read(fd, buf, sizeof(buf));
#endif
        while (bytes > 0)
        {
            md5_update(&ctx, buf, bytes);
#ifdef HOOK_READ
            bytes = g_old_read(fd, buf, sizeof(buf));
#else
            bytes = read(fd, buf, sizeof(buf));
#endif
        }
        close(fd);
    }
    md5_finit(&ctx, &hash);
    memset(buf, 0, sizeof(buf));
    for (n = 0; n < sizeof(hash.bytes); n++) {
        buf[m++] = dict[(hash.bytes[n] >> 4) & 0xf];
        buf[m++] = dict[(hash.bytes[n]) & 0xf];
    }
    return std::string(buf);
}

std::string get_string_md5(const std::string& str) {
    md5_context ctx;
    md5_hash hash;
    char buf[512];
    char dict[] = "0123456789abcdef";
    size_t n = 0;
    int m = 0;
    md5_init(&ctx);
    md5_update(&ctx, str.c_str(), str.length());
    md5_finit(&ctx, &hash);
    memset(buf, 0, sizeof(buf));
    for (n = 0; n < sizeof(hash.bytes); n++) {
        buf[m++] = dict[(hash.bytes[n] >> 4) & 0xf];
        buf[m++] = dict[(hash.bytes[n]) & 0xf];
    }
    return std::string(buf);
}