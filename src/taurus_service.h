#ifndef TAURUS_TAURUS_SERVICE_H
#define TAURUS_TAURUS_SERVICE_H

#include "common_headers.h"
#include "rule_manager.h"

#define t_starter       // 标识属于starter的方法
#define t_daemon    // 标识属于daemon的方法
#define t_service       // 标识属于service的方法 
#define t_health        // 标识用于health check的方法
#define t_public        // 标识公有的方法

// 确保唯一性
class TaurusService : public ISingleton<TaurusService> {
    friend class ISingleton<TaurusService>;
   
public:
    enum {
        SIGCRET = SIGUSR2,
        SERVICE_PULLUP_INTERVAL = 10, // daemon拉起service周期s
        NPIPE_TIMEOUT = 100000, // named pipe建立超时
        CHILD_TIMEOUT = 10, // 子进程启动超时s
        STARTER_TIMEOUT = 100000, // starter启动超时
        STARTER_TRYTIME = 10000, // starter尝试次数
        CHILD_STACK_SIZE = 1024 * 1024,
    };
    
public:
    TaurusService();
    ~TaurusService();
    
    static int t_starter create_taurusd();
    static int t_daemon create_service();
    static bool t_public exist_service();
    static bool t_public exist_taurusd();
    static void t_service sigchild_handler(int /*sig=SIGCHLD*/);
    static void t_starter sigcreate_handler(int /*sig=SIGCRET*/);
    
private:
    int t_service load(const std::string& path, RuleManager* rule);
    int t_health health_check();
    int t_service get_switch();
    void t_service set_switch(int _switch);
    static int t_public lsock_server_handler(const std::string& input, std::string& output);
    static int t_public npipe_server_handler(const std::string& input, std::string& output);;
    
    static void t_service run_loop_service();
    static void t_daemon run_loop_taurusd();
    static void t_service service_handle_newconfig(bool iscmd);
    static void t_service on_service_start();
    static void t_daemon on_taurusd_start();
    
    static bool is_rule_diff();
    
    static int health_check_child(void* args);
    static int create_taurusd_child(void* args);
    static int create_service_child(void*);
    
private:
    bool _init;
    int _cloud_switch;
    RuleManager _rules[2];
    RuleManager* _currule;
    RuleManager* _newrule;
    pthread_mutex_t _mutex;
    static int s_taurusd_lock_fd;
    static int s_service_lock_fd;
};

#endif /* TAURUS_TAURUS_SERVICE_H */

