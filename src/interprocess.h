#ifndef TAURUS_INTERPROCESS_H
#define TAURUS_INTERPROCESS_H

#include "singleton.h"
#include "cjson_glue.h"
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <tr1/unordered_map>
#include <tr1/memory>
#include <unistd.h>
#include <string>
#include <vector>
#include "thpool.h"

enum {
    SERVER_TYPE_NPIPE = 0x0001,                            // Establish named pipe server
    SERVER_TYPE_LSOCK = 0x0002,                           // Establish local socket server
    SERVER_USE_THREAD_POOL = 0x0010,            // Use thread pool to handle incoming connection
    SERVER_HANDLE_MESSAGE = 0x0020,             // Use on_message callback
    SERVER_HANDLE_CONNECT = 0x0040,            // Use on_connect callback
    SERVER_HANDLE_ACCEPT = 0x0080,                 // Handle for read / write after accept
    SERVER_SYNC = 0x0000,
    SERVER_ASYNC = 0x0200,                                  // Establish server asynchronized (default synchronized)
};

struct _start_server_stru { // 用于线程传参
    unsigned int flags;
    void (*on_connect)();
    void (*on_message)(); 
    ThreadPool* threadpool;
    // lsock_server_handler for unix socket && npipe_server_handler for named pipe
    char path[256];
};

struct _accept_stru { // 用于线程传参
    unsigned int flags;
    time_t time;
    int socket_fd;
    int accept_fd;
    void (*on_message)(); 
    struct sockaddr_un address;
};

// 作为server和client，单例避免重复建立服务器
class IPCStub {
    enum {
        LISQUE_MAX = 10000, // listen最大队列长度
        OPEN_MAX = 10, // server支持的同时刻最大连接数
        BUFFER_SIZE = 4096, // recv buffer size
        ACP_TIMER = 1000, // non-block accept interval
        TRY_TIME = 3, // 最大错误次数
        SEND_TIMEOUT = 200000, // 客户端等待超时μs
        NPIPE_INTERVAL = 1000000, // named pipe 事件处理周期μs
        EPOLL_INTERVAL = 100000, // epoll wait周期
    };
    
    typedef int (*lsock_server_handler)(const std::string& input, std::string& output); 
    typedef int (*npipe_server_handler)(const std::string& input, std::string& output);
    typedef void (*server_handler)();
    
public:
    // lsock -> local socket(和所有进程通信、自带同步处理，适合大量高频数据)
    // npip -> named pipe(带权限控制、适合小量数据低频率)
    static int start_lsock_server(
        const std::string& uds_path,            // unix domain socket 路径
        unsigned int flags,                           // 启动参数
        ThreadPool* threadpool,                // 线程池对象用于控制并发量
        server_handler onconnect,              // 成功建立服务器的回调
        lsock_server_handler onmessage   // 接收到消息的回调
    ); 
    static int start_npipe_server(
        const std::string& np_path,             // named pipe 路径
        unsigned int flags,                           // 启动参数
        ThreadPool* threadpool,                 // 线程池对象用于控制并发量
        server_handler onconnect,              // 成功建立服务器的回调
        npipe_server_handler onmessage  // 接收到消息的回调
    ); 
    
    // 用作client
    //// 获取数据
    static int lsock_client_fetch(
        const std::string& uds_path,        // unix domain socket 路径
        const CJsonWrapper::NodeType query, // 发送json数据
        std::string& output                 // 输出json数据
    );
    static int lsock_client_fetch(        
        const std::string& uds_path,        // unix domain socket 路径
        const std::string& query,           // 发送json数据
        std::string& output                 // 输出json数据
    );
    static int npipe_client_fetch(  
        const std::string& np_path,         // named pipe 路径
        const std::string& cmd,               // 发送命令
        std::string& output                      // 输出消息
    );
    //// 发送数据
    static int lsock_client_send(
        const std::string& uds_path,        // unix domain socket 路径
        const CJsonWrapper::NodeType cmd    // 发送json数据
    );
    static int lsock_client_send(
        const std::string& uds_path,        // unix domain socket 路径
        const std::string& cmd              // 发送json数据
    );
    static int npipe_client_send(
        const std::string& np_path,         // named pipe 路径
        const std::string& cmd              // 发送json数据
    );
    
    //// 服务器是否可用
    static bool is_lsock_connect(const std::string& uds_path);
    static bool is_npipe_connect(const std::string& np_path);
    
private:
    static int start_server_thread(struct _start_server_stru* serverdat);
    static int start_lsock_server_thread_inner(
        unsigned int flags,
        char* uds_path, 
        ThreadPool* threadpool,
        server_handler onconnect, 
        lsock_server_handler onmessage
    );
    static int start_npipe_server_thread_inner(
        unsigned int flags,
        char* np_path, 
        server_handler onconnect, 
        npipe_server_handler onmessage
    );
    static void* handle_lsock_client(struct _accept_stru* accept_data);
    static int set_nonblock(int sockfd);
    static int set_block(int sockfd);
    static bool is_lsock_server_start();
    static void handle_accept(
        int sockfd, 
        unsigned int flags,
        ThreadPool* threadpool,
        lsock_server_handler onmessage
    );
};

#endif // TAURUS_INTERPROCESS_H
