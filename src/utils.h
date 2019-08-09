#ifndef TAURUS_UTILS_H
#define TAURUS_UTILS_H

#include "common_headers.h"
#include "execinfo.h"

/* -------------------------------------- 工具 -------------------------------------- */
int get_cmd_output(const std::string &, std::string &);
/* 获取命令输出 */

struct rusage* get_process_info();
/* 获取进程资源占用 */

int get_processor_num();
/* 获取核心数 */

struct sysinfo* get_sysinfo();
/* 获取系统资源占用 */

std::string get_time_tag();
/* 获取时间字符串 */

std::string get_uuid();
/* 获取进程唯一uuid */

void logfunci(const char* fmt, ...);
// log info

void logfuncw(const char* fmt, ...);
// log warning

void logfunce(const char* fmt, ...);
// log error

void print_backtrace();
/* 打印回溯栈 */

bool regmatch(const char* pattern, const char* str);
/* 正则匹配 */

std::vector<std::string> split(const std::string& s, char token);
/* 字符串拆分 */

enum {
    CHILD_MODE_FORK,        // 子进程继承父进程所有资源，需要通过在父进程中waitpid获取子进程返回值
    CHILD_MODE_VFORK,     // 父进程等待子进程结束
    CHILD_MODE_CLONE,     // 子进程选择性继承父进程资源
    
    CHILD_FLAGS_WAIT = CLONE_VFORK,            // 等待子进程退出(同步)
    CHILD_FLAGS_PARENT = CLONE_PARENT,    // 子进程转兄弟进程(避免进程僵死)
    CHILD_FLAGS_SHARE = CLONE_VM,               // 子进程和父进程共享内存(不使用写拷贝)
    CHILD_FLAGS_FILE = CLONE_FS | CLONE_FILES, // 子进程共享父进程文件系统资源
};

pid_t run_in_child(int mode, int stacksize, int (*fn) (void*), void* arg, int* ret, 
        unsigned int flags);
/* 在子进程中执行函数 */

/* -------------------------------------- 文件&进程 -------------------------------------- */
void clear_argv(int argc, char** argv);
/* 清除参数 */

bool exist_proc(pid_t pid);
/* 检测进程存在 */

bool file_exist(const char *);
/* 检测文件存在 */

std::string get_cmdline(int pid = -1);
/* 获取命令行参数 */

std::vector<std::string> get_env(const std::string&);
/* 获取环境变量 */

std::string get_exe_path(int pid = -1);
/* 获取可执行文件路径 */

bool get_file_content(const std::string& path, std::string& content);
/* 获取小文件内容 */

std::string& get_last_line(std::ifstream& fin, std::string& line);
/* 获取最后一行 */

pid_t get_ppid(int pid = -1);
/* 获取指定进程父进程id*/

std::vector<std::string> get_root_files(const std::string& path, const std::string& filter);
 /* 获取根目录指定文件名格式的文件 */

bool is_string_in_file(const std::string& path, const std::string& str);
/* 检测文本包含字符串 */

void kill_proc(pid_t pid);
/* 杀死进程 */

std::vector<std::string> module_in_backtrace();
/* 获取调用栈中的模块名，避免拦截到特殊函数，例如DNS解析服务 */

bool set_file_content(const std::string& path, const std::string& str);
/* 重置文件内容 */

bool set_proc_title(char* argv0, const char* newtitle);
/* 修改(隐藏)进程名 */

void signal_proc(pid_t pid, int sig);
/* 向进程发送信号 */

/* -------------------------------------- 网络 -------------------------------------- */
std::string get_current_ip();
/* 获取当前IPv4地址 */

std::vector<unsigned int> get_ipv4_by_host(const std::string& host);
/* 获取目标域名所有ipv4地址整数 */

std::string get_ip_from_addr(const in_addr& sa);
/* 根据主机IPv4地址整数获取地址 */

std::vector<std::string> get_ipn_by_host(const std::string& host);
/* 获取目标域名所有ipv4地址*/

unsigned int get_ipnv4_from_ip(const std::string& ip);
/* 根据IPv4地址获取地址整数 */

int get_sock_family(int sock);
/* 从socket句柄获取family */

int get_sock_proto(int sock);
/* 从socket句柄获取连接协议IP/ICMP/UDP */

int get_sock_type(int sock);
/* 从socket句柄获取连接类型TCP/UDP */

bool is_sock(int fd);
/* 检测句柄是否为socket */

/* -------------------------------------- 加解密 -------------------------------------- */
int base64_encode(const std::string& input, std::string& output);
/* base64编码 */

int base64_decode(const std::string& input, std::string& output);
/* base64解码 */

std::string get_file_md5(const std::string& filename);
/* 获取文件MD5 */

std::string get_string_md5(const std::string& str);
/* 获取字符串MD5 */

#endif //TAURUS_UTILS_H
