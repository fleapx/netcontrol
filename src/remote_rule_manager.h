#ifndef TAURUS_REMOTE_RULE_MANAGER_H
#define TAURUS_REMOTE_RULE_MANAGER_H

#include "common_headers.h"
#include "cjson_glue.h"
#include "interprocess.h"
#include "utils.h"
#include <string>
#include <set>

// 用于 Agent校验策略的本地校验模式
class RemoteRuleManager {
public:
    static bool ispass(int status) {
        return status > 0;
    }
    
    static int judge_remote(const std::string& uniqid_in, const std::string& input) {
        std::string output;
        int ret = 0;
        ret = IPCStub::lsock_client_fetch(g_service_policy_tunnel, input, output);
        if (ret != 0) {
            return ACTION_ERR_LSOCKCON;
        }
        CJsonWrapper::NodeType resp = CJsonWrapper::parse_text(output);
        if (!resp) {
            return ACTION_ERR_JSONPARSE;
        }
        int result = 0;
        std::string uniqid_out;
        CJsonWrapper::get_object_string_node(resp, "uniqid", uniqid_out);
        CJsonWrapper::get_object_int_node(resp, "judge", result);
        if (uniqid_in != uniqid_out) {
            return ACTION_ERR_MISID;
        }
        CJsonWrapper::release_root_node(resp);
        return result;
    }
    
    static int judge_remote(const std::string& uniqid_in, CJsonWrapper::NodeType& info) {
        std::string output;
        int ret = 0;
        CJsonWrapper::add_object_string_node(info, "cmd", "judge");
        ret = IPCStub::lsock_client_fetch(g_service_policy_tunnel, info, output);
        if (ret != 0) {
            return ACTION_ERR_LSOCKCON;
        }
        CJsonWrapper::NodeType resp = CJsonWrapper::parse_text(output);
        if (!resp) {
            return ACTION_ERR_JSONPARSE;
        }
        int result = 0;
        std::string uniqid_out;
        CJsonWrapper::get_object_string_node(resp, "uniqid", uniqid_out);
        CJsonWrapper::get_object_int_node(resp, "judge", result);
        if (uniqid_in != uniqid_out) {
            LOGI("uniqid mismatch in:%s out:%s", uniqid_in.c_str(), uniqid_out.c_str());
            return ACTION_ERR_MISID;
        }
        CJsonWrapper::release_root_node(resp);
        return result;
    }
};

#endif //TAURUS_REMOTE_RULE_MANAGER_H
