#include "interprocess.h"
#include "cjson_glue.h"
#include <sys/types.h>

#include "interface.h"
#include "utils.h"

// 创建基于Unix Socket的Server
int IPCStub::start_lsock_server(const std::string& uds_path, unsigned int flags, 
        ThreadPool* threadpool, server_handler onconnect, lsock_server_handler onmessage) {
    struct _start_server_stru* start_server_data = 
        (struct _start_server_stru*)malloc(sizeof(_start_server_stru));
    memset(start_server_data, 0, sizeof(_start_server_stru));
    start_server_data->on_connect = (server_handler)onconnect;
    start_server_data->on_message = (server_handler)onmessage;
    start_server_data->flags |=  SERVER_TYPE_LSOCK;
    if ((flags & SERVER_USE_THREAD_POOL) && threadpool != 0) {
        start_server_data->flags |= SERVER_USE_THREAD_POOL;
    }
    if ((flags & SERVER_HANDLE_MESSAGE) && onmessage != 0) {
        start_server_data->flags |= SERVER_HANDLE_MESSAGE;
    }
    if ((flags & SERVER_HANDLE_CONNECT) && onconnect != 0) {
        start_server_data->flags |= SERVER_HANDLE_CONNECT;
    }
    if (flags & SERVER_HANDLE_ACCEPT) {
        start_server_data->flags |= SERVER_HANDLE_ACCEPT;
    }
    start_server_data->threadpool = threadpool;
    snprintf(start_server_data->path, sizeof(start_server_data->path), "%s", uds_path.c_str());
    if ((flags & SERVER_ASYNC) == 0) { // 同步
        IPCStub::start_server_thread(start_server_data);
    } else {
        pthread_t subth = (pthread_t)-1;
        pthread_create(&subth, 0, (void* (*)(void*))&IPCStub::start_server_thread, 
                (void*)start_server_data);
        if (subth != (pthread_t)-1) {
            pthread_detach(subth);
        }
    }
    return 0;
}

// 创建基于Named Pipe的server
int IPCStub::start_npipe_server(const std::string& np_path, unsigned int flags, 
        ThreadPool* threadpool, server_handler onconnect, npipe_server_handler onmessage) {
    struct _start_server_stru* start_server_data = 
        (struct _start_server_stru*)malloc(sizeof(_start_server_stru));
    memset(start_server_data, 0, sizeof(_start_server_stru));
    start_server_data->on_connect = (server_handler)onconnect;
    start_server_data->on_message = (server_handler)onmessage;
    start_server_data->flags |=  SERVER_TYPE_NPIPE;
    if ((flags & SERVER_USE_THREAD_POOL) && threadpool != 0) {
        start_server_data->flags |= SERVER_USE_THREAD_POOL;
    }
    if ((flags & SERVER_HANDLE_MESSAGE) && onmessage != 0) {
        start_server_data->flags |= SERVER_HANDLE_MESSAGE;
    }
    if ((flags & SERVER_HANDLE_CONNECT) && onconnect != 0) {
        start_server_data->flags |= SERVER_HANDLE_CONNECT;
    }
    if (flags & SERVER_HANDLE_ACCEPT) {
        start_server_data->flags |= SERVER_HANDLE_ACCEPT;
    }
    start_server_data->threadpool = threadpool;
    snprintf(start_server_data->path, sizeof(start_server_data->path), "%s", np_path.c_str());
    if ((flags & SERVER_ASYNC) == 0) { // 同步
        IPCStub::start_server_thread(start_server_data);
    } else {
        pthread_t subth = -1;
        pthread_create(&subth, 0, (void* (*)(void*))&IPCStub::start_server_thread, 
                (void*)start_server_data);
        if (subth != (pthread_t)-1) {
            pthread_detach(subth);
        }
    }
    return 0;
}

// 检测Unix Socket Server是否存在
bool IPCStub::is_lsock_connect(const std::string& uds_path) {
    int socket_fd = -1;
    int ret = 0;
    int sockerr = ERR_SUCCESS;
    do {
        struct sockaddr_un address;
        socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (socket_fd < 0) {
            sockerr = ERR_SOCKFAIL;
        }
        address.sun_family = AF_UNIX;
        memset(address.sun_path, 0, sizeof(address.sun_path));
        snprintf(address.sun_path, sizeof(address.sun_path), "%s", uds_path.c_str());
        if (address.sun_path[0] == 'A') { // 处理Abstract Unix Domain Socket
            address.sun_path[0] = '\0';
        }
#if (!defined HOOK_CONNECT)
        ret = connect(socket_fd, (struct sockaddr *) &address, sizeof(struct sockaddr_un));
#else
        ret = g_old_connect(socket_fd, (struct sockaddr *) &address, sizeof(struct sockaddr_un));
#endif
        if (ret != 0) {
            sockerr = ERR_CONNFAIL;
            break;
        }
    } while (false);
    if (socket_fd != -1) {
        close(socket_fd);
    }
    if (sockerr != ERR_SUCCESS) {
        LOGI("is_lsock_connect sockerr=%d", sockerr);
    }
    return sockerr == ERR_SUCCESS;
}

// 检测Named Pipe Server是否存在
bool IPCStub::is_npipe_connect(const std::string& np_path) {
    int fifoa = -1;
    bool iscon = true;
    // 由于fifo是单向的，因此需要双fifo实现双向通信
    char np_patha[PATH_MAX]; // 通道A  用于server读，client写
    snprintf(np_patha, sizeof(np_patha), "%sa", np_path.c_str());
    fifoa = open(np_patha, O_WRONLY | O_NONBLOCK);
    if (fifoa != -1) {
        close(fifoa);
    } else {
        iscon = false;
    }
    return iscon;
}

// Local Socket Client上报数据
int IPCStub::lsock_client_send(const std::string& uds_path, const CJsonWrapper::NodeType cmd) {
    if (cmd == 0) {
        return ERR_JSONNULL;
    }
    std::string input;
    if (!CJsonWrapper::get_json_string(cmd, input)) {
        return ERR_JSONPARSE;
    }
    return IPCStub::lsock_client_send(uds_path, cmd);
}

int IPCStub::lsock_client_send(const std::string& uds_path, const std::string& cmd) {
    int socket_fd = -1;
    int ret = 0;
    int sockerr = ERR_SUCCESS;
    do {
        struct sockaddr_un address;
        socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (socket_fd < 0) {
            sockerr = ERR_SOCKFAIL;
        }
        IPCStub::set_block(socket_fd);
        //struct timeval timeout = { 0, SEND_TIMEOUT };
        //setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        //setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        address.sun_family = AF_UNIX;
        memset(address.sun_path, 0, sizeof(address.sun_path));
        snprintf(address.sun_path, sizeof(address.sun_path), "%s", uds_path.c_str());
        if (address.sun_path[0] == 'A') { // 处理Abstract Unix Domain Socket
            address.sun_path[0] = '\0';
        }
#if (!defined HOOK_CONNECT)
        ret = connect(socket_fd, (struct sockaddr *) &address, sizeof(struct sockaddr_un));
#else
        ret = g_old_connect(socket_fd, (struct sockaddr *) &address, 
                        sizeof(struct sockaddr_un));
#endif
        if (ret != 0) {
            sockerr = ERR_CONNFAIL;
            break;
        }
#if (!defined HOOK_SEND)
        if (send(socket_fd, cmd.c_str(), cmd.size() + 1, 0) < 0) {
#else
        if (g_old_send(socket_fd, cmd.c_str(), cmd.size() + 1, 0) < 0) {
#endif
            sockerr = ERR_SENDFAIL;
        }
    } while (false);
    if (socket_fd != -1) {
        close(socket_fd);
    }
    if (sockerr != ERR_SUCCESS) {
        LOGI("lsock_client_send sockerr=%d", sockerr);
    }
    return sockerr;
}

// Local Socket Client请求数据
int IPCStub::lsock_client_fetch(const std::string& uds_path, const CJsonWrapper::NodeType query, 
        std::string& output) {
    if (query == 0) {
        return ERR_JSONNULL;
    }
    std::string input;
    if (!CJsonWrapper::get_json_string(query, input)) {
        return ERR_JSONPARSE;
    }
    return IPCStub::lsock_client_fetch(uds_path, input, output);
}

int IPCStub::lsock_client_fetch(const std::string& uds_path, const std::string& input, 
        std::string& output) {
    int socket_fd = -1;
    int ret = 0;
    int sockerr = ERR_SUCCESS;

    do {
        struct sockaddr_un address;
        socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (socket_fd < 0) {
            sockerr = ERR_SOCKFAIL;
            LOGI("lsock_client_fetch socket=%d", errno);
        }
        IPCStub::set_block(socket_fd);
        // struct timeval timeout = { 0, SEND_TIMEOUT };
        // setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        // setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        address.sun_family = AF_UNIX;
        memset(address.sun_path, 0, sizeof(address.sun_path));
        snprintf(address.sun_path, sizeof(address.sun_path), "%s", uds_path.c_str());
        if (address.sun_path[0] == 'A') { // 处理Abstract Unix Domain Socket
            address.sun_path[0] = '\0';
        }
#if (!defined HOOK_CONNECT)
        ret = connect(socket_fd, (struct sockaddr *) &address, sizeof(struct sockaddr_un));
#else
        ret = g_old_connect(socket_fd, (struct sockaddr *) &address, 
                        sizeof(struct sockaddr_un));
#endif
        if (ret != 0) {
            LOGI("lsock_client_fetch connect=%d", errno);  
            sockerr = ERR_CONNFAIL;
            break;
        }
        ssize_t recv_size = 0;
        ssize_t send_size = 0;
#if (!defined HOOK_SEND)
        send_size = send(socket_fd, input.c_str(), input.size(), 0);
#else
        send_size = g_old_send(socket_fd, input.c_str(), input.size(), 0);
#endif
        if (send_size < 0) {
            LOGI("lsock_client_fetch send=%d", errno);
            sockerr = ERR_SENDFAIL;
            break;
        }
        char buffer[BUFFER_SIZE]; // 接收json数据
#if (!defined HOOK_RECV)
        recv_size = recv(socket_fd, buffer, sizeof(buffer) - 1, 0);
#else
        recv_size = g_old_recv(socket_fd, buffer, sizeof(buffer) - 1, 0);
#endif   
        if (recv_size > 0) {
            buffer[recv_size] = 0;
            output = buffer;
        } else if (recv_size < 0) {
            LOGI("lsock_client_fetch recv=%d", errno);
        }
    } while (false);
    if (sockerr != ERR_SUCCESS) {
        LOGI("lsock_client_fetch sockerr=%d", sockerr);
    }
    if (socket_fd != -1) {
        close(socket_fd);
    }
    return sockerr;
}

int IPCStub::start_npipe_server_thread_inner(unsigned int flags, char* np_path, 
        server_handler onconnect, npipe_server_handler onmessage) {
    int fifoa = -1;
    // 由于fifo是单向的，因此需要双fifo实现双向通信
    char np_patha[PATH_MAX]; // 通道A  用于server读，client写
    char np_pathb[PATH_MAX]; // 通道B  用于server写，client读
    snprintf(np_patha, sizeof(np_patha), "%sa", np_path);
    snprintf(np_pathb, sizeof(np_pathb), "%sb", np_path);
    
    // 目录不存在则创建
    char np_dir [PATH_MAX];
    snprintf(np_dir, PATH_MAX, "%s", np_path);
    dirname(np_dir);
    if (!file_exist(np_dir)) {
        std::string output;
        std::string cmd = "mkdir -p -m 0777 ";
        cmd += np_dir;
        get_cmd_output(cmd , output);
    }
    
    int sockerr = ERR_SUCCESS;
    do {
        sockerr = ERR_SUCCESS;
        unlink(np_patha);
        unlink(np_pathb);
        if (0 != mkfifo(np_patha, 0660)) {
            LOGI("start_npipe_server_thread_inner mkfifoa errno=%d", errno);
            sockerr = ERR_FIFOFAIL; // cannot create pipe
            break;
        }
        if (0 != mkfifo(np_pathb, 0660)) {
            LOGI("start_npipe_server_thread_inner mkfifob errno=%d", errno);
            sockerr = ERR_FIFOFAIL; // cannot create pipe
            break;
        }
        fifoa = open(np_patha, O_RDONLY); // server wait for client, O_NONBLOCK not set
        if (fifoa == -1) {
            LOGI("start_npipe_server_thread_inner opena errno=%d", errno);
            sockerr = ERR_OPENFAIL; // cannot open pipe
            break;
        }
        if (flags & SERVER_HANDLE_CONNECT) {
            onconnect();
        }
        while (true) { // 循环读取
            char cmd[PIPE_BUF];
            ssize_t read_size = 0;
            ssize_t write_size = 0;
            int fifob = open(np_pathb, O_WRONLY);
            if (fifob == -1) {
                LOGI("start_npipe_server_thread_inner openb errno=%d", errno);
                sockerr = ERR_OPENFAIL; // cannot open pipe
                continue;
            }
            memset(cmd, 0, sizeof(cmd));
#ifdef HOOK_READ
            read_size = g_old_read(fifoa, cmd, sizeof(cmd));
#else
            read_size = read(fifoa, cmd, sizeof(cmd));
#endif
            if (read_size <= 0) {
                close(fifob);
                continue;
            }
            std::string input = cmd;
            std::string output;
            if (flags & SERVER_HANDLE_MESSAGE) {
                onmessage(input, output);
            }
            if (output.length() > 0) {
                memset(cmd, 0, sizeof(cmd));
                snprintf(cmd, sizeof(cmd), "%s", output.c_str());
#ifdef HOOK_WRITE
                write_size = g_old_write(fifob, cmd, sizeof(cmd)); 
#else
                write_size = write(fifob, cmd, sizeof(cmd)); 
#endif
                if (write_size < 0) {
                     LOGI("start_npipe_server_thread_inner write=%d", errno);
                 }
            }
            close(fifob);
        }
    } while (false);
    if (fifoa != -1) {
        close(fifoa);
    }
    return 0;
}

int IPCStub::start_server_thread(struct _start_server_stru* serverdata) {
    struct _start_server_stru curdata;
    if (!serverdata) {
        return -1;
    }
    curdata.flags = serverdata->flags;
    curdata.on_connect = serverdata->on_connect;
    curdata.on_message = serverdata->on_message;
    curdata.threadpool = serverdata->threadpool;
    snprintf(curdata.path, sizeof(curdata.path), "%s", serverdata->path);
    free((void*)serverdata); // serverdata通过malloc创建
    if (curdata.flags & SERVER_TYPE_NPIPE) {
        // 管道遇到并发写入，只保证PIPE_BUF大小的数据使用原子操作；适合不频繁、数据量小的数据传输
        IPCStub::start_npipe_server_thread_inner(curdata.flags, curdata.path, curdata.on_connect, 
                (npipe_server_handler)curdata.on_message);
    } else if (curdata.flags & SERVER_TYPE_LSOCK) {
        // 采用epoll模型+threadpool，方便以后扩展
        IPCStub::start_lsock_server_thread_inner(curdata.flags, curdata.path, curdata.threadpool, 
                curdata.on_connect, (lsock_server_handler)curdata.on_message);
    }
    return 0;
}

/*
 *  可选模型：
 *      多线程＋短连接：
 *              此时使用新线程管理新加入的客户端，一次recv+send结束线程
 *              适用于短连接情形，适合当前项目
 *              后续通过线程池控制并发量和资源消耗
 *      多线程＋长连接：
 *              此时使用epoll管理新加入的客户端
 *              适用于客户端较少的情形
 *              客户端较多时，极为耗费资源，引起DDoS攻击
 *      listen socket设置为阻塞模式，有客户端连入才会触发epoll_wait
 *      accept socket设置为非阻塞模式，防止客户端连接后不发送数据直接退出导致阻塞
 */

int IPCStub::start_lsock_server_thread_inner(unsigned int flags, char* uds_path, 
        ThreadPool* threadpool, server_handler onconnect, lsock_server_handler onmessage) { 
    int socket_fd = -1;
    int ret = 0;
    int sockerr = ERR_SUCCESS;
    do {
        struct sockaddr_un address;
        sockerr = ERR_SUCCESS;
        socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (socket_fd < 0) {
            sockerr = ERR_SOCKFAIL; // socket failed
            break;
        }

        IPCStub::set_block(socket_fd);
        address.sun_family = AF_UNIX;
        memset(address.sun_path, 0, sizeof(address.sun_path));
        snprintf(address.sun_path, sizeof(address.sun_path), "%s", uds_path);
        bool abstract = false;
        if (address.sun_path[0] == 'A') { // 处理Abstract Unix Domain Socket
            address.sun_path[0] = '\0';
            abstract = true;
        } else {
            unlink(address.sun_path);
            // 目录不存在则创建
            char uds_dir [PATH_MAX];
            snprintf(uds_dir, PATH_MAX, "%s", uds_path);
            dirname(uds_dir);
            if (!file_exist(uds_dir)) {
                std::string output;
                std::string cmd = "mkdir -p -m 0777 ";
                cmd += uds_dir;
                get_cmd_output(cmd , output);
            }
        }
        ret = bind(socket_fd, (struct sockaddr*)&address, sizeof(struct sockaddr_un));
        if (ret != 0) {
            sockerr = ERR_BINDFAIL; // bind failed
            break;
        }
        ret = listen(socket_fd, LISQUE_MAX);
        if (ret != 0) {
            sockerr = ERR_LISTFAIL; // listen failed
            break;
        }
        if (!abstract) {
            std::string output;
            std::string cmd = "chmod 0777 " ;
            cmd += uds_path;
            get_cmd_output(cmd , output);
        }
        if (flags & SERVER_HANDLE_CONNECT) {
            onconnect();
        }
        IPCStub::set_block(socket_fd);
        while (true) {
            IPCStub::handle_accept(socket_fd, flags, threadpool, onmessage);
            usleep(1000);
        }
    } while (false);
    if (socket_fd != -1) {
        close(socket_fd);
    }
    if (sockerr != ERR_SUCCESS) {
        LOGI("start_lsock_server_thread_inner sockerr=%d", sockerr);
    }
    return sockerr;
}

// 线程池实现，防止阻塞
void IPCStub::handle_accept(int socket_fd, unsigned int flags, ThreadPool* threadpool, 
        lsock_server_handler onmessage) {
    struct sockaddr_un address;
    socklen_t addrsize = (socklen_t)sizeof(struct sockaddr_un);
#if (!defined HOOK_ACCEPT)
    int accept_fd = accept(socket_fd, (struct sockaddr*)&address, &addrsize);
#else
    int accept_fd = g_old_accept(socket_fd, (struct sockaddr*)&address, &addrsize);
#endif
    if ((flags & SERVER_HANDLE_ACCEPT) == 0) {
        if (accept_fd != -1) {
            close(accept_fd);
        }
        return;
    }
    if (accept_fd != -1) { // success
        struct _accept_stru* accept_data = 
            (struct _accept_stru*)malloc(sizeof(struct _accept_stru));
        memset(accept_data, 0, sizeof(struct _accept_stru));
        accept_data->flags = flags;
        accept_data->socket_fd = socket_fd;
        accept_data->accept_fd = accept_fd;
        accept_data->time = time(0);
        accept_data->on_message = (server_handler)onmessage;
        memcpy(&accept_data->address, &address, addrsize);
        if (threadpool != 0) {
            threadpool->add_work((void(*)(void*))&IPCStub::handle_lsock_client,  (void*)accept_data);
        } else {
            pthread_t subth = 0;
            pthread_create(&subth, 0, (void* (*)(void*))&IPCStub::handle_lsock_client,  (void*)accept_data);
            if (subth != 0) {
                pthread_detach(subth);
            }
        }
    }
}

// Unix Socket Server 1对N模式，每次接受数据就返回
void* IPCStub::handle_lsock_client(struct _accept_stru* accept_data) {
    std::string input;
    std::string output;
    struct _accept_stru curdata;
    if (accept_data == 0) {
        return 0;
    }
    memcpy(&curdata, accept_data, sizeof(struct _accept_stru));
    free((void*)accept_data);

    do {
        char buffer[BUFFER_SIZE]; // 接收json数据
        ssize_t recv_size = 0;
        IPCStub::set_block(curdata.accept_fd);    // 使用thpool时开启
#if (!defined HOOK_RECV)
        recv_size = recv(curdata.accept_fd, buffer, sizeof(buffer) - 1, 0);
#else
        recv_size = g_old_recv(curdata.accept_fd, buffer, sizeof(buffer) - 1, 0);
#endif
        if (recv_size > 0) {
            buffer[recv_size] = 0;
            input = buffer;
        }
        if (curdata.flags &  SERVER_HANDLE_MESSAGE) {
            lsock_server_handler handler = (lsock_server_handler)curdata.on_message;
            handler(input, output);
        }
#if (!defined HOOK_SEND)
        send(curdata.accept_fd, output.c_str(), output.length(), 0);
#else
        g_old_send(curdata.accept_fd, output.c_str(), output.length(), 0);
#endif
    } while (false);
    close(curdata.accept_fd);
    return 0;
}

int IPCStub::set_nonblock(int sockfd) {
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) < 0) {
        return -2;
    }
    return 0;
}

int IPCStub::set_block(int sockfd) {
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags < 0) {
        return -1;
    }
    if (fcntl(sockfd, F_SETFL, flags & (~O_NONBLOCK)) < 0) {
        return -2;
    }
    return 0;
}

int IPCStub::npipe_client_send(const std::string& np_path, const std::string& input) {
    int fifoa = -1;
    int fifob = -1;
    // 由于fifo是单向的，因此需要双fifo实现双向通信
    char np_patha[PATH_MAX]; // 通道A  用于server读，client写
    char np_pathb[PATH_MAX]; // 通道B  用于server写，client读
    snprintf(np_patha, sizeof(np_patha), "%sa", np_path.c_str());
    snprintf(np_pathb, sizeof(np_pathb), "%sb", np_path.c_str());
    int sockerr = ERR_SUCCESS;
    do {
        fifoa = open(np_patha, O_WRONLY | O_NONBLOCK);
        if (fifoa == -1) {
            LOGI("npipe_client_send opena errno=%d", errno);
            sockerr = ERR_OPENFAIL; // cannot open named pipe
            break;
        }
        fifob= open(np_pathb, O_RDONLY | O_NONBLOCK);
        if (fifob == -1) {
            LOGI("npipe_client_send openb errno=%d", errno);
            sockerr = ERR_OPENFAIL; // cannot open named pipe
            break;
        }
        char cmd[PIPE_BUF];
        ssize_t write_size = 0;
        memset(cmd, 0, sizeof(cmd));
        snprintf(cmd, sizeof(cmd), "%s", input.c_str());
#ifdef HOOK_WRITE
        write_size = g_old_write(fifoa, cmd, sizeof(cmd));
#else
        write_size = write(fifoa, cmd, sizeof(cmd));
#endif
        if (write_size < 0) {
            sockerr = ERR_WRITFAIL; // write failed
            LOGI("npipe_client_send write errno=%d", errno);
        }
    } while (false);
    if (fifob != -1) {
        close(fifob);
    }
    if (fifoa != -1) {
        close(fifoa);
    }
    return sockerr;
}

int IPCStub::npipe_client_fetch(const std::string& np_path, const std::string& input, 
        std::string& output) {
    int fifoa = -1;
    int fifob = -1;
    // 由于fifo是单向的，因此需要双fifo实现双向通信
    char np_patha[PATH_MAX]; // 通道A  用于server读，client写
    char np_pathb[PATH_MAX]; // 通道B  用于server写，client读
    snprintf(np_patha, sizeof(np_patha), "%sa", np_path.c_str());
    snprintf(np_pathb, sizeof(np_pathb), "%sb", np_path.c_str());
    int sockerr = ERR_SUCCESS;
    Flocker lock(np_path); // 串行化请求避免多写者
    do {
        fifoa = open(np_patha, O_WRONLY);
        if (fifoa == -1) {
            LOGI("npipe_client_send opena errno=%d", errno);
            sockerr = ERR_OPENFAIL; // cannot open named pipe
            break;
        }
        fifob= open(np_pathb, O_RDONLY);
        if (fifob == -1) {
            LOGI("npipe_client_send openb errno=%d", errno);
            sockerr = ERR_OPENFAIL; // cannot open named pipe
            break;
        }
        char cmd[PIPE_BUF];
        ssize_t read_size = 0;
        ssize_t write_size = 0;
        memset(cmd, 0, sizeof(cmd));
        snprintf(cmd, sizeof(cmd), "%s", input.c_str());
#ifdef HOOK_WRITE
        write_size = g_old_write(fifoa, cmd, sizeof(cmd));
#else
        write_size = write(fifoa, cmd, sizeof(cmd));
#endif
        if (write_size < 0) {
            sockerr = ERR_WRITFAIL; // write failed
            LOGI("npipe_client_send write errno=%d", errno);
            break;
        }
        memset(cmd, 0, sizeof(cmd));
#ifdef HOOK_READ
        read_size = g_old_read(fifob, cmd, sizeof(cmd));
#else
        read_size = read(fifob, cmd, sizeof(cmd));
#endif
        if (read_size < 0) {
            sockerr = ERR_READFAIL; // write failed
            LOGI("npipe_client_send read errno=%d", errno);
            break;
        }
        output = cmd;
    } while (false);
    if (fifob != -1) {
        close(fifob);
    }
    if (fifoa != -1) {
        close(fifoa);
    }
    return sockerr;
}
