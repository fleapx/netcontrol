#ifndef TAURUS_HEALTH_CHECK_H
#define TAURUS_HEALTH_CHECK_H

#include "utils.h"
#include "cjson_glue.h"
#include "singleton.h"
#include "report.h"

class HealthCheck {
public:
    static const std::string health_status(const std::string& str, char op) {
        Locker lock(HealthCheck::_s_mutex);
        static std::string status = "errnum: 0";
        if (op == 'r') {
        } else if (op == 'w') {
            status = str;
        }
        return status;
    }
    
    static int health_check(const std::string& basedir) {
        std::string health_conf_path = basedir + "/health.json";
        if (!file_exist(health_conf_path.c_str())) {
            return ERR_NOFILE; // json文件不存在
        }
        std::string content;
        if (!get_file_content(health_conf_path, content)) {
            return ERR_READFILE; // 文件获取失败
        }
        CJsonWrapper::NodeType root = CJsonWrapper::parse_text(content);
        if (!root) {
            return ERR_JSONPARSE; // json解析失败
        }
        int ret = 0;
        
        std::vector<std::string> cases = CJsonWrapper::get_object_keys(root);
        std::vector<std::string>::iterator caseitor = cases.begin();
        while (caseitor != cases.end()) {
            CJsonWrapper::NodeType casenode = 0;
            const std::string& casename = (*caseitor);
            std::string direction;
            std::string dstip;
            std::string action;
            int family = 0;
            int type = 0;
            int protocol = 0;
            unsigned short dstport = 0;
            
            CJsonWrapper::get_object_object_node(root, casename, casenode);
            if (casenode != 0) {
                bool t_dir = false;
                bool t_act = false;
                bool t_fam = false;
                bool t_typ = false;
                bool t_pro = false;
                t_dir = CJsonWrapper::get_object_string_node(casenode, "direction", direction);
                t_act = CJsonWrapper::get_object_string_node(casenode, "action", action);
                t_fam = CJsonWrapper::get_object_int_node(casenode, "family", family);
                t_typ = CJsonWrapper::get_object_int_node(casenode, "type", type);
                t_pro = CJsonWrapper::get_object_int_node(casenode, "protocol", protocol);
                CJsonWrapper::get_object_string_node(casenode, "dstip", dstip);
                CJsonWrapper::get_object_int_node(casenode, "dstport", dstport);
                if (!t_dir || !t_act || !t_fam || !t_typ || !t_pro) {
                    Report::get_instance().log(Report::SENDER_HEAL, Report::LEVEL_ERROR, 
                            __LINE__, __FILE__, "health_check case invalid:" + casename);
                    ++caseitor;
                    continue;
                }
                // if (api == "INPUT") { } else  // 忽略dstport    // 无法自动测试此种类型
                if (direction == "OUTPUT") { // 忽略srcport
                    struct sockaddr_in ser_addr;
                    memset(&ser_addr, 0, sizeof(ser_addr));
                    ser_addr.sin_family = family;
                    ser_addr.sin_port = htons(dstport);
                    ser_addr.sin_addr.s_addr = inet_addr(dstip.c_str());
                    int ser_sock = socket(family, type, protocol);
                    bool match = false;
                    if (ser_sock != -1) {
                        bool suc = connect(ser_sock, (sockaddr*)&ser_addr, sizeof(ser_addr)) == 0;
                        if ((!suc && action == "REJECT") || (suc && action == "ACCEPT")) {
                            match = true;
                        }
                        close(ser_sock);
                    }
                    if (!match) {
                        ret++;
                    }
                }
            }
            ++caseitor;
        }
        char status[256];
        std::string tag = get_time_tag();
        snprintf(status, sizeof(status), "'%s' errnum: %d", tag.c_str(), ret);
        HealthCheck::health_status(status, 'w');
        CJsonWrapper::release_root_node(root);
        return ret;
    }
    
    static pthread_mutex_t _s_mutex;
};

pthread_mutex_t HealthCheck::_s_mutex = PTHREAD_MUTEX_INITIALIZER;

#endif // TAURUS_HEALTH_CHECK_H