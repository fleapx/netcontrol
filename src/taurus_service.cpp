#include "common_headers.h"
#include "taurus_service.h"
#include "utils.h"
#include "interprocess.h"
#include "rule_manager.h"
#include "health_check.h"
#include "report.h"
#include "symbols.h"
#include "thpool.h"

static char* s_argv0 = 0;
void handler(int);

static std::string s_service_ctrl_tunnel = "/etc/taurus.ctrl"; // 云控命令通道
static std::string s_daemon_lock = "/etc/taurus.taurusd.pid"; // 进程唯一 NamedPipe
static std::string s_service_lock = "/etc/taurus.service.pid"; // 进程唯一 NamedPipe
static std::string s_policy_lock = "/etc/taurus_conf.lck"; // 策略更新同步 FileLock
static std::string s_service_path = "/usr/bin/taurus_starter"; // 进程路径
static std::string s_health_name = "/health_/taurus"; // 进程名    注意该名称兼容rsyslog进程名
static std::string s_service_name = "/service/taurus"; // 进程名    注意该名称兼容rsyslog进程名
static std::string s_taurusd_name = "/daemon_/taurus"; // 进程名    注意该名称兼容rsyslog进程名
static std::string s_config_backup = "/etc/taurus.config.backup"; // 备份策略目录，由Agent创建
static std::string s_config = "/etc/taurus.config"; // 下发策略目录，由Agent创建
static std::string s_tauruslib_path = "libtaurus.so"; // taurus模块
static std::string s_dst_preload = "/etc/ld.so.preload";
static std::string s_src_preload = "/etc/ld.so.preload.bak";
static std::string s_taurus_log_path = "/var/log";
static std::string s_log_path = "/var/log/taurus.log";
static std::string s_rot_path = "/etc/logrotate.d/taurus";
static std::string s_logconf_path = "/etc/rsyslog.d/taurus.conf";
static std::string s_taurus_status = "/etc/taurus.status"; // 保存上次云控启动/关闭结果

static pid_t s_starter_pid = -1;
static pid_t s_health_pid = -1;
static pid_t s_service_pid = -1;
static pid_t s_daemon_pid = -1;

TaurusService::TaurusService() {
    pthread_mutex_init(&this->_mutex, 0);
    this->_init = true;
    this->_currule = &_rules[0];
    this->_newrule = &_rules[1];
    this->_cloud_switch = 1;
}

TaurusService::~TaurusService() {
    this->_rules[0].clean();
    this->_rules[1].clean();
    pthread_mutex_destroy(&this->_mutex);
}

// 策略加载   0:success  <0:error
int t_service TaurusService::load(const std::string& path, RuleManager* rule) {
    if (rule == 0) {
        Report::get_instance().log(Report::SENDER_SERV, Report::LEVEL_INFO, __LINE__, __FILE__,
                    "TSLO:policy null " + path);
        return -1;
    }
    int ret = -1;
    {
        rule->clean();
        rule->set_g_switch(this->_cloud_switch); // 开启云控
        ret = rule->update(path);
        if (0 == ret) {
            Report::get_instance().log(Report::SENDER_SERV, Report::LEVEL_INFO, __LINE__, __FILE__,
                        "TSLO:load success " + path);
        } else {
            Report::get_instance().log(Report::SENDER_SERV, Report::LEVEL_ERROR, __LINE__, __FILE__,
                        "TSLO:load failed " + path);
        }
    }
    // currule是之前经过验证正确的策略
    return ret;
}

void* self_delay_kill(int sp) {
    sleep(sp);
    _Exit(0);
}

// 建立基于Named Pipe的Server，方便接收Agent云控命令
int t_public TaurusService::npipe_server_handler(const std::string& cmd, std::string& output) {
    if (cmd.length() < 1) {
        return ERR_SUCCESS;
    }
    if (cmd.find("stop") == 0) {
        kill_proc(s_daemon_pid); // 先杀死daemon防止重生
        pthread_t th;
        pthread_create(&th, 0, (void* (*)(void*))self_delay_kill, (void*)1);
        output = "service: stopped";
    } else if (cmd.find("getswitch") == 0) {
        char buf[256];
        snprintf(buf, sizeof(buf), "service: %d, currule: %d", 
                TaurusService::get_instance().get_switch(), 
                TaurusService::get_instance()._currule->get_g_switch());
        output = buf;
    } else if (cmd.find("gethealth") == 0) {
        output = HealthCheck::health_status("", 'r');
    } else if (cmd.find("setswitch") == 0) {
        if (cmd == "setswitchon") {
            TaurusService::get_instance().set_switch(1);
            output = "service: switch set";
        } else if (cmd == "setswitchoff") {
            TaurusService::get_instance().set_switch(0);
            output = "service: switch set";
        }
    } else if (cmd.find("setpolicy") == 0) {
        // 新策略下发
        TaurusService::service_handle_newconfig(true); // 云控初始化配置
        output = "health: " + HealthCheck::health_status("", 'r');
    }
    Report::get_instance().vlog(Report::SENDER_SERV, Report::LEVEL_INFO, __LINE__, __FILE__,
            "TSNS: handle %s-%s", cmd.c_str(), output.c_str());
    return ERR_SUCCESS;
}

int t_service TaurusService::get_switch() {
    Locker lock(this->_mutex);
    return this->_cloud_switch;
}

void t_service TaurusService::set_switch(int _switch) {
    Locker lock(this->_mutex);
    this->_cloud_switch = _switch;
    this->_currule->set_g_switch(_switch);
    this->_newrule->set_g_switch(_switch);
}

// 建立基于Unix Socket的Server
int t_public TaurusService::lsock_server_handler(const std::string& input, std::string& output) {
    TaurusService& self = TaurusService::get_instance();
    CJsonWrapper::NodeType reqroot = CJsonWrapper::parse_text(input);
    if (!reqroot) {
        return ERR_JSONPARSE;
    }
    CJsonWrapper::NodeType resproot = CJsonWrapper::create_object_node();
    if (!resproot) {
        CJsonWrapper::release_root_node(reqroot);
        return ERR_JSONCROBJ;
    }
    std::string cmd;
    std::string uniqid;
    CJsonWrapper::get_object_string_node(reqroot, "cmd", cmd);
    CJsonWrapper::get_object_string_node(reqroot, "uniqid", uniqid);
    
    if (cmd == "judge") { // 请求判决
        std::string exe;
        CJsonWrapper::get_object_string_node(reqroot, "exe", exe);
        int judge_result = ACTION_RULNONE; // true放过   false拒绝
        if (exe == s_service_path) {
            // 若为health_check则使用新策略测试，通过健康检查后将新策略刷入当前策略
            judge_result = self._newrule->judge(reqroot);
        } else {
            // 普通进程使用当前策略
            judge_result = self._currule->judge(reqroot);
        }
        CJsonWrapper::add_object_string_node(resproot, "uniqid", uniqid);		
        CJsonWrapper::add_object_int_node(resproot, "judge", judge_result);
    }
    CJsonWrapper::get_json_string(resproot, output);
    CJsonWrapper::release_root_node(resproot);
    CJsonWrapper::release_root_node(reqroot);
    return ERR_SUCCESS;
}

static sem_t s_service_start_lock;

// taurus wait service create
void t_starter TaurusService::sigcreate_handler(int /*sig=SIGCRET*/) {
    sem_post(&s_service_start_lock);
}

int TaurusService::health_check_child(void*) {
    s_health_pid = getpid();
    // health process
    int healthstate = HealthCheck::health_check(s_config);
    if (0 == healthstate) {
        Report::get_instance().log(Report::SENDER_SERV, Report::LEVEL_INFO, 
                __LINE__, __FILE__, "TSHE:health check success");
        return 0;
    } else {
        Report::get_instance().vlog(Report::SENDER_SERV, Report::LEVEL_ERROR, 
                __LINE__, __FILE__, "TSHE:health check failed:%d", healthstate);
        return -1;
    }
    return -1;
}

int t_health TaurusService::health_check() {
    int ret = -1;
    // 使用clone方式，避免子进程退出时执行父进程"进程结束回调"
    pid_t child_pid = run_in_child(CHILD_MODE_FORK, CHILD_STACK_SIZE, 
            (int(*)(void*))&TaurusService::health_check_child, 0, &ret, 
            CHILD_FLAGS_WAIT | CHILD_FLAGS_PARENT | CHILD_FLAGS_SHARE);
    if (child_pid < 0) {
        Report::get_instance().log(Report::SENDER_SERV, Report::LEVEL_ERROR, 
                    __LINE__, __FILE__, "TSHE:fork health failed");
    } else {
        Report::get_instance().log(Report::SENDER_SERV, Report::LEVEL_INFO, 
                    __LINE__, __FILE__, "TSHE:fork health success");
        s_health_pid = child_pid; // 给父进程空间使用
    }
    return ret;
}

/* 策略文件相同则返回false 不同返回true */
bool TaurusService::is_rule_diff() {
    bool backup_exist = file_exist(s_config_backup.c_str());
    bool config_exist = file_exist(s_config.c_str());
    if (backup_exist != config_exist) { // 策略和备份只存在一份则必定不相同
        return true;
    }
    if (!backup_exist) { // 策略和备份都不存在则认为相同
        return false;
    }
    static const char* s_policy_file[] = { 
        "/machine.json", "/port.json", "/policy.json", "/white.json" 
    };
    unsigned int i = 0;
    std::string backup_json;
    std::string config_json;
    for (i = 0; i < ARRLEN(s_policy_file); i++) {
        backup_json = s_config_backup + s_policy_file[i];
        config_json = s_config + s_policy_file[i];
        backup_exist = file_exist(backup_json.c_str());
        config_exist = file_exist(config_json.c_str());
        if (backup_exist != config_exist) { // 策略和备份只存在一份则必定不相同
            Report::get_instance().log(Report::SENDER_SERV, Report::LEVEL_INFO, 
                            __LINE__, __FILE__, "TSIR:not match 1");
            return true;
        }
        if (!backup_exist) {
            Report::get_instance().log(Report::SENDER_SERV, Report::LEVEL_INFO, 
                            __LINE__, __FILE__, "TSIR:not match 2");
            continue;
        }
        if (get_file_md5(backup_json) != get_file_md5(config_json)) { // 策略和备份文件的md5不同
            Report::get_instance().log(Report::SENDER_SERV, Report::LEVEL_INFO, 
                            __LINE__, __FILE__, "TSIR:not match 3");
            return true;
        }
    }
    Report::get_instance().log(Report::SENDER_SERV, Report::LEVEL_INFO, 
                            __LINE__, __FILE__, "TSIR:same policy, no update");
    return false;
}

void t_service TaurusService::service_handle_newconfig(bool iscmd) {
    TaurusService& serv = TaurusService::get_instance();
    bool backup_exist = file_exist(s_config_backup.c_str());
    bool config_exist = file_exist(s_config.c_str());
    bool loadstate = false ;
    bool healthstate = false;
    bool rulediff = serv.is_rule_diff();
    if (iscmd) { // 云控的初始化
        if (!rulediff) {
            return;
        }
        if (!(loadstate =  serv.load(s_config, serv._newrule) == 0) || 
                !(healthstate = serv.health_check() == 0)) {
            // 策略解释失败，或将康检查失败 覆盖backup到config
            if (!loadstate) {
                Report::get_instance().log(Report::SENDER_SERV, Report::LEVEL_ERROR, 
                        __LINE__, __FILE__, "TSSE:new config load failed");
            }
            if (!healthstate) {
                Report::get_instance().log(Report::SENDER_SERV, Report::LEVEL_ERROR, 
                        __LINE__, __FILE__, "TSSE:new config health check failed");
            }
            Flocker flock(s_policy_lock);
            serv._newrule->clean();
        } else {
            Flocker flock(s_policy_lock);
            std::string output;
            get_cmd_output("/bin/mkdir -p " + s_config_backup, output);
            get_cmd_output("/bin/cp -rfp " + s_config + "/* " + s_config_backup, output);
            RuleManager* tmp = serv._currule;
            serv._currule = serv._newrule;
            serv._newrule = tmp;
            tmp->clean(); // 更新到当前策略
            Report::get_instance().log(Report::SENDER_SERV, Report::LEVEL_INFO, 
                    __LINE__, __FILE__, "TSSE:switch to new rule by cmd");
        }
    }
    else if (config_exist) { // 首次启动初始化
        if (backup_exist) {
            serv.load(s_config_backup, serv._currule);
            if (!rulediff) {
                return;
            }
        }
        if (!(loadstate = serv.load(s_config, serv._newrule) == 0) || 
                !(healthstate = serv.health_check() == 0)) {
            // 策略解释失败，或将康检查失败 覆盖backup到config
            if (!loadstate) {
                Report::get_instance().log(Report::SENDER_SERV, Report::LEVEL_ERROR, 
                        __LINE__, __FILE__, "TSSE:init config load failed");
            }
            if (!healthstate) {
                Report::get_instance().log(Report::SENDER_SERV, Report::LEVEL_ERROR, 
                        __LINE__, __FILE__, "TSSE:init config health check failed");
            }
            Flocker flock(s_policy_lock);
            std::string output;
            get_cmd_output("/bin/mkdir -p " + s_config, output);
            get_cmd_output("/bin/cp -rfp " + s_config_backup + "/* " + s_config, output);
            serv._newrule->clean();
        } else {
            Flocker flock(s_policy_lock);
            std::string output;
            get_cmd_output("/bin/mkdir -p " + s_config_backup, output);
            get_cmd_output("/bin/cp -rfp " + s_config + "/* " + s_config_backup, output);
            RuleManager* tmp = serv._currule;
            serv._currule = serv._newrule;
            serv._newrule = tmp;
            tmp->clean();
            serv.load(s_config, serv._currule); // 将新策略更新到当前策略中
            Report::get_instance().log(Report::SENDER_SERV, Report::LEVEL_INFO, 
                    __LINE__, __FILE__, "TSSE:switch to new rule on init");
        }
    } else if (backup_exist) {
        serv.load(s_config_backup, serv._currule);
    }
}

void t_service TaurusService::on_service_start() {
    // 通知daemon taurus_service初始化完毕
    usleep(NPIPE_TIMEOUT); // 等待s_service_ctrl_tunnel通道建立
    signal_proc(s_daemon_pid, SIGCRET);
}

void t_daemon TaurusService::on_taurusd_start() {
    // 通知Taurus启动器taurus_daemon初始化完毕
}

void t_service TaurusService::run_loop_service() {
    // 开启云控更新、策略判决服务
    s_service_pid = getpid();
    // 初始化线程池
    ThreadPool* pool = &ThreadPool::get_instance();
    pool->set_pid(s_service_pid);
    TaurusService::service_handle_newconfig(false); // 首次启动初始化配置
    IPCStub::start_npipe_server(s_service_ctrl_tunnel, 
            SERVER_ASYNC | SERVER_HANDLE_MESSAGE | SERVER_HANDLE_ACCEPT, 
            0, 0, TaurusService::npipe_server_handler); // 云控更新
    IPCStub::start_lsock_server(g_service_policy_tunnel, 
            SERVER_ASYNC | SERVER_HANDLE_MESSAGE | SERVER_HANDLE_ACCEPT | SERVER_USE_THREAD_POOL, 
            pool, 0, TaurusService::lsock_server_handler); // 策略判决
    // 创建唯一标识，同时常驻
    IPCStub::start_lsock_server(s_service_lock, SERVER_SYNC | SERVER_HANDLE_CONNECT, 0, 
            TaurusService::on_service_start, 0);
}

void t_daemon TaurusService::run_loop_taurusd() {
    // 持续检测和创建service
    while (TaurusService::get_instance()._init) {
        if (!TaurusService::exist_service()) {
            Report::get_instance().log(Report::SENDER_SERV, Report::LEVEL_INFO, 
                        __LINE__, __FILE__, "TSRL: pull up service");
            TaurusService::create_service();
        }
        sleep(SERVICE_PULLUP_INTERVAL); // interval 
    }
}

int TaurusService::create_taurusd_child(void*) {
    // 更新进程名
    set_proc_title(s_argv0, s_taurusd_name.c_str());
    // 创建唯一标识
    IPCStub::start_lsock_server(s_daemon_lock, SERVER_ASYNC | SERVER_HANDLE_CONNECT, 0, 
            TaurusService::on_taurusd_start, 0);
    // 执行事件循环
    TaurusService::run_loop_taurusd();
    return 0;
}

// starter创建常驻TaurusD
int t_starter TaurusService::create_taurusd() {
    int ret = ERR_SUCCESS;
    s_starter_pid = getpid();
    if (!TaurusService::exist_taurusd()) {
        pid_t child_pid = run_in_child(CHILD_MODE_FORK, CHILD_STACK_SIZE, 
                (int(*)(void*))&TaurusService::create_taurusd_child, 0, 0, 0); // CHILD_FLAGS_PARENT
        if (child_pid < 0) {
            Report::get_instance().log(Report::SENDER_SERV, Report::LEVEL_ERROR, 
                        __LINE__, __FILE__, "TSCR:fork daemon failed");
        } else {
            Report::get_instance().log(Report::SENDER_SERV, Report::LEVEL_INFO, 
                        __LINE__, __FILE__, "TSCR:fork daemon success");
            s_daemon_pid = child_pid; // 给父进程空间使用
        }
    }
    return ret;
}

int TaurusService::create_service_child(void*) {
    // 常驻Service进程
    set_proc_title(s_argv0, s_service_name.c_str());
    // 忽略会导致进程退出的信号
    signal(SIGHUP, SIG_IGN);
    signal(SIGINT, SIG_IGN);
    signal(SIGQUIT, SIG_IGN);
    signal(SIGILL, SIG_IGN);
    signal(SIGABRT, SIG_IGN);
    signal(SIGFPE, SIG_IGN);
    signal(SIGSEGV, SIG_IGN);
    signal(SIGPIPE, SIG_IGN); // 防止客户端恶意退出导致管道断裂
    signal(SIGALRM, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
    // 执行事件循环
    TaurusService::run_loop_service();
    return 0;
}

// Taurus Daemon创建常驻Taurus Service
int t_daemon TaurusService::create_service() {
    // child进程中，创建taurus service
    s_daemon_pid = getpid();
    struct sigaction newact;
    struct sigaction oldact;
    memset(&newact, 0, sizeof(newact));
    memset(&oldact, 0, sizeof(oldact));
    newact.sa_handler = (void (*)(int))TaurusService::sigcreate_handler;
    sem_init(&s_service_start_lock, 0, 0);
    sigaction(SIGCRET, &newact, &oldact);
    if (!TaurusService::exist_service()) {
        pid_t child_pid = run_in_child(CHILD_MODE_FORK, CHILD_STACK_SIZE, 
                (int(*)(void*))&TaurusService::create_service_child, 0, 0, CHILD_FLAGS_PARENT);
        if (child_pid < 0) {
            Report::get_instance().log(Report::SENDER_SERV, Report::LEVEL_ERROR, 
                        __LINE__, __FILE__, "TSCR:fork service failed");
        } else {
            Report::get_instance().log(Report::SENDER_SERV, Report::LEVEL_INFO, 
                        __LINE__, __FILE__, "TSCR:fork service success");
            s_service_pid = child_pid; // 给父进程空间使用
        }
        // wait for service create 
        struct timespec _t;
        clock_gettime(CLOCK_REALTIME, &_t);
        _t.tv_sec += CHILD_TIMEOUT;
        sem_timedwait(&s_service_start_lock, &_t); // 等待service进程服务初始化
        sem_close(&s_service_start_lock);
        sigaction(SIGCRET, &oldact, &newact);
    }
    return ERR_SUCCESS;
}

// 检测Taurus Daemon存在
bool t_public TaurusService::exist_taurusd() {
    return IPCStub::is_lsock_connect(s_daemon_lock);
}

// 检测Taurus Service存在
bool t_public TaurusService::exist_service() {
    return IPCStub::is_lsock_connect(s_service_lock);
}

#ifdef HOOK_ACCEPT
int (*g_old_accept)(int, struct sockaddr *, socklen_t *) = 0;
#endif
#ifdef HOOK_CONNECT
int (*g_old_connect)(int, const struct sockaddr*, socklen_t) = 0;
#endif
#ifdef HOOK_SEND
ssize_t (*g_old_send)(int, const void*, size_t, int) = 0;
#endif
#ifdef HOOK_RECV
ssize_t (*g_old_recv)(int, void*, size_t, int) = 0;
#endif
#ifdef HOOK_READ
ssize_t (*g_old_read)(int, void*, size_t) = 0;
#endif
#ifdef HOOK_WRITE
ssize_t (*g_old_write)(int, const void*, size_t) = 0;
#endif

static const char* LIBC_NAME = "libc.so.6";

static int get_symbol_cb(const char *libpath, const char *libname,
        const char *objname, const void *addr, const size_t size,
        const int binding, const int type, void *custom __attribute__ ((unused))) {
    UNUSED(libpath);
    UNUSED(libname);
    UNUSED(size);
    UNUSED(binding);
    if (type == FUNC_SYMBOL && strstr(libpath, LIBC_NAME) != 0) {
        if (false) {
#ifdef HOOK_CONNECT
        } else if (!strcmp(objname, "connect")) {
            g_old_connect = (typeof (g_old_connect))addr;
            return 0;
#endif
#ifdef HOOK_ACCEPT
        } else if (!strcmp(objname, "accept")) {
            g_old_accept = (typeof (g_old_accept))addr;
            return 0;
#endif
#ifdef HOOK_SEND
        } else if (!strcmp(objname, "send")) {
            g_old_send = (typeof (g_old_send))addr;
            return 0;
#endif
#ifdef HOOK_RECV
        } else if (!strcmp(objname, "recv")) {
            g_old_recv = (typeof (g_old_recv))addr;
            return 0;
#endif
#ifdef HOOK_READ
        } else if (!strcmp(objname, "read")) {
            g_old_read = (typeof (g_old_read))addr;
            return 0;
#endif
#ifdef HOOK_WRITE
        } else if (!strcmp(objname, "write")) {
            g_old_write = (typeof (g_old_write))addr;
            return 0;
#endif
        }
    }
    return 0;
}

int start_server(bool wait) {
    int ret = 0;
    if (!TaurusService::exist_service()) { // 首次启动
        if (TaurusService::create_taurusd() < 0) {
            Report::get_instance().log(Report::SENDER_STAR, Report::LEVEL_ERROR, 
                    __LINE__, __FILE__, "MA:taurusd create failed");
            return -3; // 无法连接命令服务
        }
        int waitcount = 10;
        ret = -1; // timeout
        if (wait) {
            while (waitcount-- > 0) {
                sleep(1);
                if (TaurusService::exist_service()) {
                    ret = 0;
                    break;
                }
            }
        }
    }
    return ret;
}

/*  
 * starter作为service，需要在noah之前启动(S50noah)，支持以下命令：
 *      start       读取配置taurus.status，若允许Preload则启动service，执行mount(ld.so.preload)，重启sshd(S13sshd)，打印错误，返回0
 *      stop        执行umount，重启sshd，退出daemon/service进程，记录到配置taurus.status，打印错误，返回0
 *      status      打印daemon状态、service状态、云控状态、上次健康检查状态，返回0
 *      clear       清理配置
 *      restart     忽略
 *      health      打印health健康检查结果，返回0
 *      cctrl       云控(cloud-control)
 *              {"cmd":"switch", "switch":"on"}   打开云控     不打印，返回0
 *              {"cmd":"switch", "switch":"off"}  关闭云控     不打印，返回0
 *              {"cmd":"policy", "folder":"/etc/taurus.config"}   下发策略     打印health健康检查结果，返回0
 *      qlog        查询日志(query log)
 *              {"filter":"accept", "begint":"1536917776", "endt":"1536917776"}
 *              {"filter":"deny", "begint":"1536917776", "endt":"1536917776"}
 *              {"filter":"judge", "begint":"1536917776", "endt":"1536917776"}
 *              accept/deny/judge t1 t2 打印时间区域内所有日志，返回0
 *   注：每次重新部署libtaurus.so需要重启生效
 */
void handle_help(int argc, const std::vector<std::string>& arguments) {
    UNUSED(argc);
    UNUSED(arguments);
    std::cout << "Usage: taurus {start|stop|status|restart|health|cctrl|qlog}" << std::endl;
    std::cout << "    start      start service                  " << std::endl;
    std::cout << "    stop       stop service                   " << std::endl;
    std::cout << "    status     print status                   " << std::endl;
    std::cout << "    clear      clear status                   " << std::endl;
    std::cout << "    restart    start & stop service           " << std::endl;
    std::cout << "    health     print health check result      " << std::endl;
    std::cout << "    cctrl      cloud control                  " << std::endl;
    std::cout << "        setswitch    enable / disable preload hook      " << std::endl;
    std::cout << "        policy       deploy new policy        " << std::endl;
    std::cout << "    qlog       query log                      " << std::endl;
    std::cout << "        accept t1 t2 filter accepted items    " << std::endl;
    std::cout << "        deny t1 t2   filter denied items      " << std::endl;
    std::cout << "        judge t1 t2  accepted and denied items" << std::endl;
}

void handle_clear(int argc, const std::vector<std::string>& arguments) {
    UNUSED(argc);
    UNUSED(arguments);
    int ret = remove(s_taurus_status.c_str());
    std::cout << "clear: remove return " << ret << std::endl;
    _Exit(0);
}

void handle_start(int argc, const std::vector<std::string>& arguments) {
    UNUSED(argc);
    UNUSED(arguments);
    // 环境搭建
    int ret = 0;
    std::string output;
    get_cmd_output("mkdir -p " + s_config + " " + s_config_backup, output);
    if (is_string_in_file("/etc/mtab", s_dst_preload)) {
        ret = get_cmd_output("umount " + s_dst_preload, output);
        std::cout << "start: umount ret=" << ret << " " << output << std::endl;
    } else {
        std::cout << "start: mount already" << std::endl;
    }
    output.clear();
    get_file_content(s_dst_preload, output);
    set_file_content(s_src_preload, output + "\n" + s_tauruslib_path);
    
    {
        Flocker lock(g_taurus_lib_lock);
        std::string content;
        bool needstart = true;
        if (file_exist(s_taurus_status.c_str()) && get_file_content(s_taurus_status, content)) {
            if (content == "stop") {
                std::cout << "start: cloud control stop" << std::endl;
                needstart = false;
            }
        }
        if (needstart) {
            int ret = 0;
            // 启动service，避免service加载libtaurus.so
            if (!TaurusService::exist_service()) {
                ret = start_server(true);
            }
            std::cout << "start: start_server return " << ret << std::endl;
            if (0 == ret) {
                // 执行mount
                if (!is_string_in_file("/etc/mtab", s_dst_preload)) {
                    ret = get_cmd_output("mount --bind " + s_src_preload + " " + s_dst_preload, 
                            output);
                    std::cout << "start: mount return " << ret << " " << output << std::endl; 
                } else {
                    std::cout << "start: mount already" << std::endl;
                }
                if (0 == ret) {
                    // 重启sshd
                    std::string cmdout;
                    ret = get_cmd_output("/sbin/service sshd restart", cmdout);
                    std::cout << "start: runcmd return " << ret << std::endl << cmdout;
                }
            }
        }
    }
    _Exit(0);
}

void handle_stop(int argc, const std::vector<std::string>& arguments) {
    UNUSED(argc);
    UNUSED(arguments);
    int ret = 0;
    // 执行umount
     if (is_string_in_file("/etc/mtab", s_dst_preload)) {
        std::string cmdout;
        ret = get_cmd_output("umount " + s_dst_preload, cmdout);
        std::cout << "stop: umount return " << ret << " " << cmdout << std::endl;
    }
    ret = 0;
    // 重启sshd
    {
        std::string cmdout;
        ret = get_cmd_output("/sbin/service sshd restart", cmdout);
        std::cout << "stop: runcmd return " << ret << std::endl << cmdout;
    }
    {
        Flocker lock(g_taurus_lib_lock);
        if (IPCStub::is_npipe_connect(s_service_ctrl_tunnel)) {
            // 通知server退出
            std::string cmdout;
            ret = IPCStub::npipe_client_fetch(s_service_ctrl_tunnel, "stop", cmdout);
            std::cout << "stop: runcmd return " << ret << " " << cmdout << std::endl;
            sleep(1);
            get_cmd_output("ps aux | grep taurus | awk '{print $2}' | xargs kill -9", cmdout);
        } 
        // 记录到文件
        set_file_content(s_taurus_status, "stop");
    }
    _Exit(0);
}

void handle_status(int argc, const std::vector<std::string>& arguments) {
    UNUSED(argc);
    UNUSED(arguments);
    std::string cmdout;
    int ret = 0;
    if (TaurusService::exist_service()) {
        std::cout << "status: service exist" << std::endl;
    } else {
        std::cout << "status: service nonexist" << std::endl;
    }
    if (TaurusService::exist_taurusd()) {
        std::cout << "status: daemon exist" << std::endl;
    } else {
        std::cout << "status: daemon nonexist" << std::endl;
    }
    if (IPCStub::is_npipe_connect(s_service_ctrl_tunnel))
    {
        cmdout.clear();
        ret = IPCStub::npipe_client_fetch(s_service_ctrl_tunnel, "getswitch", cmdout);
        std::cout << "status: switch " << ret << " " << cmdout << std::endl;
        cmdout.clear();
        ret = IPCStub::npipe_client_fetch(s_service_ctrl_tunnel, "gethealth", cmdout);
        std::cout << "status: health " << ret << " " << cmdout << std::endl;
    } else {
        std::cout << "status: npipe unconnect" << std::endl;
    }
    _Exit(0);
}

void handle_restart(int argc, const std::vector<std::string>& arguments) {
    handle_stop(argc, arguments);
    handle_start(argc, arguments);
    _Exit(0);
}

void handle_health(int argc, const std::vector<std::string>& arguments) {
    UNUSED(argc);
    UNUSED(arguments);
    std::string cmdout;
    int ret = 0;
    if (IPCStub::is_npipe_connect(s_service_ctrl_tunnel)) {
        cmdout.clear();
        ret = IPCStub::npipe_client_fetch(s_service_ctrl_tunnel, "gethealth", cmdout);
        std::cout << "health " << ret << std::endl;
    } else {
        std::cout << "health: npipe unconnect" << std::endl;
    }
    _Exit(0);
}

void handle_cctrl(int argc, const std::vector<std::string>& arguments) {
    if (argc < 3) {
        std::cout << "cctrl: param error" << std::endl;
        _Exit(-1);
    }
    int i = 0;
    std::string json_request;
    for (i = 2; i < argc; i++) {
        json_request += arguments[i]; // 拼接json串
    }
    CJsonWrapper::NodeType root = CJsonWrapper::parse_text(json_request);
    if (root == 0) {
        std::cout << "cctrl: parse error" << std::endl;
        _Exit(-2);
    }
    std::string cmdout;
    std::string k;
    std::string v;
    int ret = 0;
    if (IPCStub::is_npipe_connect(s_service_ctrl_tunnel)) {
        CJsonWrapper::get_object_string_node(root, "cmd", k);
        if (k == "setswitch") {
            CJsonWrapper::get_object_string_node(root, "switch", v);
            cmdout.clear();
            ret = IPCStub::npipe_client_fetch(s_service_ctrl_tunnel, k + v, cmdout);
            std::cout << "cctrl: setswitch " << ret << " " << cmdout << std::endl;
        } else if (k == "setpolicy") {
            CJsonWrapper::get_object_string_node(root, "folder", v);
            get_cmd_output("/bin/cp -rf " + v + "/* " + s_config + "/", cmdout);
            cmdout.clear();
            ret = IPCStub::npipe_client_fetch(s_service_ctrl_tunnel, k, cmdout);
            std::cout << "cctrl: setpolicy " << ret << " " << cmdout << std::endl;
        }
        CJsonWrapper::release_root_node(root);
    } else {
        std::cout << "cctrl: npipe unconnect" << std::endl;
    }
    _Exit(0);
}

void handle_qlog(int argc, const std::vector<std::string>& arguments) {
    if (argc < 3) {
        std::cout << "qlog: param error" << std::endl;
        _Exit(-1);
    }
    int i = 0;
    std::string json_request;
    for (i = 2; i < argc; i++) {
        json_request += arguments[i]; // 拼接json串
    }
    CJsonWrapper::NodeType root = CJsonWrapper::parse_text(json_request);
    if (root == 0) {
        std::cout << "qlog: parse error" << std::endl;
        _Exit(-2);
    }
    std::string filter;
    std::string bt;
    std::string et;
    int ifilter = 0;
    struct tm btm;
    struct tm etm;
    CJsonWrapper::get_object_string_node(root, "filter", filter);
    CJsonWrapper::get_object_string_node(root, "begint", bt);
    CJsonWrapper::get_object_string_node(root, "endt", et);
    if (filter == "accept") {
        ifilter = 1;
    } else if (filter == "deny") {
        ifilter = 2;
    } else if (filter == "judge") {
        ifilter = 3;
    } else {
        std::cout << "qlog: filter error" << std::endl;
        _Exit(-3);
    }
    memset(&btm, 0, sizeof(btm));
    memset(&etm, 0, sizeof(etm));
    if (!strptime(bt.c_str(), "%Y%m%d %H:%M:%S", &btm) || 
            !strptime(et.c_str(), "%Y%m%d %H:%M:%S", &etm)) {
        std::cout << "qlog: time error" << std::endl;
        _Exit(-4);
    }
    time_t btmt = mktime(&btm);
    time_t etmt = mktime(&etm);
    CJsonWrapper::release_root_node(root);
    // 从/var/log/taurus.log*获取信息
    std::vector<std::string> logfiles = get_root_files(s_taurus_log_path, "taurus.log*");
    std::vector<std::string>::iterator itor = logfiles.begin();
    while (itor != logfiles.end()) {
        // 检查时间范围
        const std::string& logpath = (*itor);
        std::string basetime;
        std::string::size_type p = logpath.find('-');
        if (p != std::string::npos) {
            basetime = logpath.substr(p + 1, 6); // format: 201807
        } else { // 没有日期的，则为今天
            char buf[16];
            time_t time_ = time(0);
            struct tm* tmp_tm = gmtime(&time_);
            strftime(buf, sizeof(buf), "%Y%m", tmp_tm); // format: 201807
            basetime = buf;
        }
        std::ifstream logfp(logpath.c_str());
        if (logfp.is_open()) {
            Report::print_filter_netlog(logfp, ifilter, basetime, btmt, etmt);
            logfp.close();
        }
        ++itor;
    }  
    _Exit(0);
}

int main(int argc, char** argv) {
    /* 避免service自身被策略拦截到：
     *  1. 调用connect/accept/...时使用g_old_*函数指针
     *  2. 将自身加入内置白名单和策略白名单
     */
    symbols(get_symbol_cb, 0);
    // 避免构造重入
    Report::get_instance();
    TaurusService::get_instance();
    s_argv0 = argv[0];
    if (0 != getuid()) {
        // 检测越权启动
        char* user = (char*)"unknown";
        struct passwd* pwd = getpwuid(getuid());
        if (pwd != 0) {
            user = pwd->pw_name;
        }
        Report::get_instance().vlog(Report::SENDER_STAR, Report::LEVEL_ERROR, 
                __LINE__, __FILE__, "MA:invalid user-uid=%d name=%s", getuid(), user);
        return -2;
    }
    // 保存参数
    std::vector<std::string> arguments;
    int i = 0;
    for (i = 0; i < argc; i++) {
        arguments.push_back(argv[i]); 
    }
    std::string cmd;
    if (argc > 1) {
        cmd = argv[1];
        clear_argv(argc, argv); // 清除参数
    }
    signal(SIGPIPE, SIG_IGN); // 防止客户端恶意退出导致管道断裂
    
    if (argc < 2) {
        handle_help(argc, arguments);
    } else if (cmd == "start") {
        handle_start(argc, arguments);
    } else if (cmd == "stop") {
        handle_stop(argc, arguments);
    } else if (cmd == "status") {
        handle_status(argc, arguments);
    } else if (cmd == "restart") {
        handle_restart(argc, arguments);
    } else if (cmd == "health") {
        handle_health(argc, arguments);
    } else if (cmd == "cctrl") {
        handle_cctrl(argc, arguments);
    } else if (cmd == "qlog") {
        handle_qlog(argc, arguments);
    } else if (cmd == "clear") {
        handle_clear(argc, arguments);
    } else {
        handle_help(argc, arguments);
    }
    return 0;
}
