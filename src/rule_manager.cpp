#include <list>

#include "rule_manager.h"
#include "report.h"

RuleItem::RuleItem(const std::string& rulename, CJsonWrapper::NodeType root, RuleManager& ruleman) 
        : _ruleman(ruleman) {
    this->_action = ACTION_RULPASS;
    this->_direction = 0;
    this->_socktype = 0;
    this->_mask = 0;
    this->_enable = false;
    this->_rulename = rulename;
    
    std::vector<std::string> keys = CJsonWrapper::get_object_keys(root);
    std::vector<std::string>::iterator itor = keys.begin();
    while (itor != keys.end()) {
        const std::string& key = (*itor);
        if (key == "describe") {
            std::string c_desc;
            CJsonWrapper::get_object_string_node(root, "describe", c_desc);
            this->_rulename = c_desc;
        }
        if (key == "direction") {
            std::string c_dir;
            if (CJsonWrapper::get_object_string_node(root, "direction", c_dir)) {
                this->_direction = 0;
                if (c_dir.find("IN") != std::string::npos) {
                    this->_direction |= DIRECT_IN;
                } 
                if (c_dir.find("OUT") != std::string::npos) {
                    this->_direction |= DIRECT_OUT;
                }
                if (c_dir.find("ALL") != std::string::npos) {
                    this->_direction |= DIRECT_IN | DIRECT_OUT;
                }
            }
            this->_mask |= MASK_API;
        } else if (key == "protocol") {
            std::string c_pro;
            if (CJsonWrapper::get_object_string_node(root, "protocol", c_pro)) {
                this->_socktype = 0;
                if (c_pro.find("TCP") != std::string::npos) {
                    this->_socktype |= (1 << SOCK_STREAM);
                }
                if (c_pro.find("UDP") != std::string::npos) {
                    this->_socktype |= (1 << SOCK_DGRAM);
                }
                if (c_pro.find("RAW") != std::string::npos) { // exp:ICMP
                    this->_socktype |= (1 << SOCK_RAW);
                }
                this->_mask |= MASK_SOTYPE;
            }
        } else if (key == "action") {
            std::string c_act;
            if (CJsonWrapper::get_object_string_node(root, "action", c_act)) {
                if (c_act == "ACCEPT") {
                    this->_action = ACTION_RULACEPT;
                } else if (c_act == "REJECT") {
                    this->_action = ACTION_RULRJECT;
                }
            }
        } else if (key == "local" || key == "remote") {
            CJsonWrapper::NodeType objnode = 0;
            if (CJsonWrapper::get_object_object_node(root, key, objnode)) {
                this->parse_net_control(key, objnode);
            }
        } else if (key == "process" || key == "md5") {
            CJsonWrapper::NodeType arrnode = 0;
            if (CJsonWrapper::get_object_object_node(root, key, arrnode)) {
                int l = CJsonWrapper::get_array_size(arrnode);
                int i = 0;
                for (; i < l; i++) {
                    std::string item;
                    if (CJsonWrapper::get_array_string_node(arrnode, i, item)) {
                        if (key == "process") {
                            this->_process.push_back(item);
                            this->_mask |= MASK_EXE;
                        } else if (key == "md5") {
                            this->_md5.push_back(item);
                            this->_mask |= MASK_MD5;
                        }
                    }
                }
            }
        }
        ++itor;
    }
    if (this->_direction != 0 && this->_socktype != 0) {
        this->_enable = true;
    }
}

/**
 * 解析policy中对(localport/remoteport/remoteaddr)的组合配置
 * @param key
 * @param node
 * @return 
 */
int RuleItem::parse_net_control(const std::string& key, CJsonWrapper::NodeType node) {
    if (!node) {
        return -1;
    }
    if (key == "local") {
        /*
         *  ① local节点结构为dict
         *  ② local子节点只有array类型的ports，不存在addr / port
         */
        if (!CJsonWrapper::is_object(node)) {
            return -2; // type mismatch
        }
        CJsonWrapper::NodeType ports_node = 0;
        if (CJsonWrapper::get_object_object_node(node, "ports", ports_node)) {
            int l = CJsonWrapper::get_array_size(ports_node);
            int i = 0;
            for (; i < l; i++) {
                std::string port_name;
                if (CJsonWrapper::get_array_string_node(ports_node, i, port_name)) {
                    this->_local_port.push_back(port_name);
                }
            }
        }
        if (this->_local_port.size() > 0) {
            this->_mask |= MASK_SRCPORT;
        }
    } else if (key == "remote") {
        /* 
         *  ① remote节点结构为array(dict)
         *  ② remote每个元素的子节点可能有addr_type / addr_value / port ，且为单元素
         */
        if (!CJsonWrapper::is_array(node)) {
            return -2; // type mismatch
        }
        int l = CJsonWrapper::get_array_size(node);
        int i = 0;
        for (; i < l; i++) {
            CJsonWrapper::NodeType net_rule_node = 0;
            int addrtype = 0;
            bool has_addr = false;
            bool has_port = false;
            bool has_addrtype = false;
            std::string addrvalue;
            std::string port; // 端口集名
            if (!CJsonWrapper::get_array_object_node(node, i, net_rule_node)) {
                continue;
            }
            has_addr = CJsonWrapper::get_object_string_node(net_rule_node, "addr_value", 
                        addrvalue);
            has_addrtype = CJsonWrapper::get_object_int_node(net_rule_node, "addr_type", 
                        addrtype);
            has_port = CJsonWrapper::get_object_string_node(net_rule_node, "port", port);
            if (!has_port && !(has_addr && has_addrtype)) {
                continue; // empty node
            }
            
            NetRuleItem net_rule_item;
            net_rule_item._mask = 0;
            if (has_addr != 0){
                if (addrtype == IP_TYPE_SET) {
                    net_rule_item._addrset_name = addrvalue;
                } else { // we need to alloc a new ip set in _ip
                    std::vector<std::string> input;
                    std::set<unsigned int> output;
                    input.push_back(addrvalue);
                    if (this->_ruleman.parse_ip_for_type(
                            addrtype, input, output) > 0) {
                        std::string t_name = this->_rulename + get_uuid();
                        net_rule_item._addrset_name = t_name;
                        std::set<unsigned int>::iterator itoro = output.begin();
                        while (itoro != output.end()) {
                            this->_ruleman._ip_area_map[(*itoro)].insert(t_name);
                            ++itoro;
                        }
                    }
                }
                net_rule_item._mask |= MASK_DSTIP;
            } 
            if (has_port != 0) {
                net_rule_item._portset_name = port;
                net_rule_item._mask |= MASK_DSTPORT;
            }
            this->_remote_net.push_back(net_rule_item);
        }
        if (this->_remote_net.size() > 0) {
            this->_mask |= MASK_DSTIP | MASK_DSTPORT;
        }
    }
    return 0;
}

/**
 * 判断字符串匹配
 * @param type
 * @param info
 * @param comp
 * @return 
 */
bool RuleItem::handle_str_match(int type, const std::string& info, 
        const std::vector<std::string>& comp) {
    std::vector<std::string>::const_iterator itor = comp.begin();
    if (type == MATCH_REGEX) {
        while (itor != comp.end()) {
            if (regmatch((*itor).c_str(), info.c_str())) {
                return true;
            }
            ++itor;
        }
    } else if (type == MATCH_COMMON) {
        while (itor != comp.end()) {
            if ((*itor) == info) {
                return true;
            }
            ++itor;
        }
    }
    return false;
}

/**
 * 判决(localport/remoteport/remoteaddr)组合匹配
 * @param ip
 * @param port
 * @return 
 */
bool RuleItem::handle_netrule_match(unsigned int ip, unsigned short port) {
    std::tr1::unordered_map<unsigned int, std::set<std::string> >& _ip_area_map = 
        this->_ruleman._ip_area_map;
    std::tr1::unordered_map<unsigned short, std::set<std::string> >& _port_area_map = 
        this->_ruleman._port_area_map;
    std::vector<NetRuleItem>::iterator itor = this->_remote_net.begin();
    while (itor != this->_remote_net.end()) {
        unsigned int mask = (*itor)._mask;
        std::string& addrset_name = (*itor)._addrset_name;
        std::string& portset_name = (*itor)._portset_name;
        bool ipmatch = true; // 无IP情况默认match
        bool portmatch = true; // 无PORT情况默认match
        if ((mask & (MASK_IP | MASK_PORT)) == 0) {
            ++itor;
            continue;
        }
        if (mask & MASK_IP) {
            ipmatch = false;
            if (_ip_area_map.find(ip) != _ip_area_map.end()) {
                std::set<std::string>& belong_areas = _ip_area_map[ip];
                if (std::find(belong_areas.begin(), belong_areas.end(), addrset_name) != 
                        belong_areas.end()) {
                    ipmatch = true;
                }
            }
        } 
        if (mask & MASK_PORT) {
            portmatch = false;
            if (_port_area_map.find(port) != _port_area_map.end()) {
                std::set<std::string>& belong_areas = _port_area_map[port];
                if (std::find(belong_areas.begin(), belong_areas.end(), portset_name) != 
                        belong_areas.end()) {
                    portmatch = true;
                }
            }
        }
        if (ipmatch && portmatch) {
            // 若mask指定项均match则认为match
            return true;
        }
        ++itor;
    }
    return false;
}

/**
 * 单个规则判决，根据返回值 大于0、小于0、等于0 区分判决结果
 * @param ctrlinfo
 * @return 
 */
int RuleItem::judge(const ControlInfo& ctrlinfo, int& subret) {
    if (!this->_enable) {
        subret = ACTION_SUB_DISABLE;
        return ACTION_SUB_DISABLE; // 规则未启用，直接放行
    }
    if ((this->_mask & ctrlinfo._mask) != this->_mask) {
        subret = ACTION_SUB_MISMASK;
        return ACTION_RULPASS; // 信息缺失，进行下次判决
    }
    if (this->_direction == DIRECT_IN) {
        if (ctrlinfo._api != "accept" && ctrlinfo._api != "accept4") {
            subret = ACTION_SUB_MISDIREC_1;
            return ACTION_RULPASS; // 只拦截连入连接
        }
    } else if (this->_direction == DIRECT_OUT) {
        if (ctrlinfo._api != "connect") {
            subret = ACTION_SUB_MISDIREC_2;
            return ACTION_RULPASS; // 只拦截连出连接
        }
    }
    
    std::tr1::unordered_map<unsigned short, std::set<std::string> >& _port_area_map =
        this->_ruleman._port_area_map;
    unsigned int merged_mask = this->_mask & ctrlinfo._mask;
    if (merged_mask & MASK_EXE) {
        if (!this->handle_str_match(MATCH_REGEX, ctrlinfo._exe, this->_process)) {
            subret = ACTION_SUB_MISEXE;
            return ACTION_RULPASS; // 不匹配，尝试匹配下个ruleitem
        }
    }
    if (merged_mask & MASK_MD5) {
        if (!this->handle_str_match(MATCH_COMMON, ctrlinfo._md5, this->_md5)) {
            subret = ACTION_SUB_MISMD5;
            return ACTION_RULPASS; // 不匹配，尝试匹配下个ruleitem
        }
    }
    if (merged_mask & MASK_SRCPORT) {
        if (_port_area_map.find(ctrlinfo._srcport) != _port_area_map.end()) {
            std::set<std::string> portset_names = _port_area_map[ctrlinfo._srcport];
            std::set<std::string>::iterator itorpn = portset_names.begin();
            bool match = false;
            while (itorpn != portset_names.end()) {
                if (std::find(this->_local_port.begin(), this->_local_port.end(), (*itorpn)) != 
                        this->_local_port.end()) {
                    match = true;
                    break;
                }
                ++itorpn;
            }
            if (!match) {
                subret = ACTION_SUB_MISSRC;
                return ACTION_RULPASS; // 不匹配，尝试匹配下个ruleitem
            }
        } else {
            subret = ACTION_SUB_MISSRC;
            return ACTION_RULPASS; // 未找到PORT所属集合
        }
    }
    if (merged_mask & MASK_DST) {
        if (!handle_netrule_match(get_ipnv4_from_ip(ctrlinfo._dstip), ctrlinfo._dstport)) {
            subret = ACTION_SUB_MISDST;
            return ACTION_RULPASS; // 不匹配，尝试匹配下个ruleitem
        }
    }
    if (merged_mask & MASK_SOTYPE) {
        if ((ctrlinfo._typeset & this->_socktype) == 0) { // ctrlinfo的type包含在允许协议集
            subret = ACTION_SUB_MISSOTYPE;
            return ACTION_RULPASS; // 不匹配，尝试匹配下个ruleitem
        }
    }
    return this->_action; // 匹配，返回指定ACTION
}

RuleManager::RuleManager() {
    this->_init = false;
    this->_g_switch = 0;
    pthread_mutex_init(&this->_mutex, 0);
    
    // 白机器写死
    const char* white_machines[] = {
    };
    unsigned int i = 0;
    for (i = 0; i < ARRLEN(white_machines); i++) {
        std::vector<unsigned int> ips = get_ipv4_by_host(white_machines[i]);
        this->_white_ips.insert(ips.begin(), ips.end());
    }
}

RuleManager::~RuleManager() {
    pthread_mutex_destroy(&this->_mutex);
}

/**
 * 更新策略，更新前需要重解析配置文件
 * @param rootdir
 * @return 
 */
int RuleManager::update(const std::string& rootdir) {
    Locker lock(this->_mutex);
    // 初始配置
    this->_ip_area_map.clear();
    this->_port_area_map.clear();
    this->_policy_map.clear();
    this->_base_rule_pool.clear();
    this->_config["policy_json"] = rootdir + "/policy.json";
    this->_config["port_json"] = rootdir + "/port.json";
    this->_config["machine_json"] = rootdir + "/machine.json";
    this->_config["white_json"] = rootdir + "/white.json";
    
    // 策略预处理&&解析
    std::string content;
    int parse_status = ERR_JSONPARSE;
    CJsonWrapper::NodeType root = 0;
    if (get_file_content(this->_config["machine_json"], content)) {
        root = CJsonWrapper::parse_text(content);
        if (root != 0) {
            parse_status = this->parse_machine_json(root);
            CJsonWrapper::release_root_node(root);
        }
    }
    if (parse_status == ERR_SUCCESS) {
        Report::get_instance().log(Report::SENDER_SERV, Report::LEVEL_INFO, __LINE__, __FILE__,
                "RMUP:machine.json parse success");
    } else {
        Report::get_instance().vlog(Report::SENDER_SERV, Report::LEVEL_ERROR, __LINE__, __FILE__,
                "RMUP:machine.json parse failed=%d", parse_status);
        return parse_status;
    }
    parse_status = ERR_JSONPARSE;
    if (get_file_content(this->_config["port_json"], content)) {
        root = CJsonWrapper::parse_text(content);
        if (root != 0) {
            parse_status = this->parse_port_json(root);
            CJsonWrapper::release_root_node(root);
        }
    }
    if (parse_status == ERR_SUCCESS) {
        Report::get_instance().log(Report::SENDER_SERV, Report::LEVEL_INFO, __LINE__, __FILE__,
                "RMUP:port.json parse success");
    } else {
        Report::get_instance().vlog(Report::SENDER_SERV, Report::LEVEL_ERROR, __LINE__, __FILE__,
                "RMUP:port.json parse failed=%d", parse_status);
        return parse_status;
    }
    parse_status = ERR_JSONPARSE;
    if (get_file_content(this->_config["policy_json"], content)) { 
        root = CJsonWrapper::parse_text(content);
        if (root != 0) {
            parse_status = this->parse_policy_json(root);
            CJsonWrapper::release_root_node(root);
        }
    }
    if (parse_status == ERR_SUCCESS) {
        Report::get_instance().log(Report::SENDER_SERV, Report::LEVEL_INFO, __LINE__, __FILE__,
                "RMUP:policy.json parse success");
    } else {
        Report::get_instance().vlog(Report::SENDER_SERV, Report::LEVEL_ERROR, __LINE__, __FILE__,
                "RMUP:policy.json parse failed=%d", parse_status);
        return parse_status;
    }
    this->_init = true; // machine.json policy.json port.json正常解析后策略生效
    parse_status = ERR_JSONPARSE;
    if (get_file_content(this->_config["white_json"], content)) {
        root = CJsonWrapper::parse_text(content);
        if (root != 0) {
            parse_status = this->parse_white_json(root);
            CJsonWrapper::release_root_node(root);
        }
    }
    if (parse_status == ERR_SUCCESS) {
        Report::get_instance().log(Report::SENDER_SERV, Report::LEVEL_INFO, __LINE__, __FILE__,
                "RMUP:white.policy parse success");
    } else {
        Report::get_instance().vlog(Report::SENDER_SERV, Report::LEVEL_ERROR, __LINE__, __FILE__,
                "RMUP:white.policy parse failed=%d", parse_status);
    }
    return 0;
}

/**
 * 清空策略
 */
void RuleManager::clean() {
    _version.clear();
    _config.clear();
    _ip_area_map.clear();
    _port_area_map.clear();
    _policy_map.clear();
    _base_rule_pool.clear();
    _white_map.clear();
}

/**
 * 策略是否为空
 * @return 
 */
bool RuleManager::isempty() {
    return _policy_map.empty();
}

/**
 * 交换策略
 * @param otherman
 */
void RuleManager::swap(RuleManager& otherman) {
    Locker lock1(this->_mutex);
    Locker lock2(otherman._mutex);
    unsigned int _g_switch = otherman._g_switch;
    otherman._g_switch = this->_g_switch;
    this->_g_switch = _g_switch;
    std::tr1::unordered_map<std::string, int> _version = otherman._version;
    otherman._version = this->_version;
    this->_version = _version;
    std::tr1::unordered_map<std::string, std::string> _config = otherman._config;
    otherman._config = this->_config;
    this->_config = _config;
    std::tr1::unordered_map<unsigned int, std::set<std::string> > _ip_area_map = 
                    otherman._ip_area_map;
    otherman._ip_area_map = this->_ip_area_map;
    this->_ip_area_map = _ip_area_map;
    std::tr1::unordered_map<unsigned int, std::string> _ip_match_map = 
                    otherman._ip_match_map;
    otherman._ip_match_map = this->_ip_match_map;
    this->_ip_match_map = _ip_match_map;
    std::tr1::unordered_map<unsigned short, std::set<std::string> > _port_area_map = 
                    otherman._port_area_map;
    otherman._port_area_map = this->_port_area_map;
    this->_port_area_map = _port_area_map;
    std::tr1::unordered_map<std::string, rulevec> _policy_map = otherman._policy_map;
                    otherman._policy_map = this->_policy_map;
    this->_policy_map = _policy_map;
    std::tr1::unordered_map<std::string, std::set<std::string> > _white_map = 
                    otherman._white_map;
    otherman._white_map = this->_white_map;
    this->_white_map = _white_map;
}

/**
 * 判决策略总入口
 * @param root
 * @return 
 */
const char* s_valid_api[] = { 
    "connect", "accept", "accept4", 
    // "send", "recv", "sendto", "recvfrom", "read", "write" 
};

int RuleManager::judge(CJsonWrapper::NodeType root) {
    if (!this->_init) {
        return ACTION_UNINIT; // 未初始化完成，放过
    }
    bool  is_switch_on = this->get_g_switch() != 0;
    Locker lock(this->_mutex);
    ControlInfo ctrlinfo;
    ControlInfo::deserial_json(root, ctrlinfo);
    bool needlog = true;
    int judge = ACTION_RULNONE; // 默认拒绝
    bool issubjudge = false;
    int subjudge = ACTION_RULNONE;
    std::string subjudger;
    do {
        if (!is_switch_on) {
            judge = ACTION_SWITCHOFF; // 云控开关关闭，放过
            break;
        }
        if (this->is_in_white_list(root)) {
            judge = ACTION_WHITE; // 在白名单中，放过
            needlog = false;
            break;
        }
        if (ctrlinfo._family != AF_INET) {
            judge = ACTION_IGNORE_NONIPV4; // 忽略IPv4以外的协议
            break;
        }
        if (ctrlinfo._dstip.find("127")  == 0) {
            judge = ACTION_IGNORE_LOOPBACK; // 忽略环回地址
            needlog = false; // 不打印，避免日志过大
            break;
        }
        if (std::find(s_valid_api, std::end(s_valid_api), ctrlinfo._api) == std::end(s_valid_api)) {
            judge = ACTION_IGNORE_NONHOOK;
            break;
        }
        // 获取当前IP对应的区域
        std::string _srcip;
        if (!CJsonWrapper::get_object_string_node(root, "srcip", _srcip)) {
            judge = ACTION_NOSRCIP; // 上报异常
            break;
        }
        unsigned int srcip = get_ipnv4_from_ip(_srcip);
        if (this->_ip_match_map.find(srcip) == this->_ip_match_map.end()) {
            judge = ACTION_NOAREA; // 该IP未对应任何区域，返回默认策略
            break;
        } 
        std::string curarea = this->_ip_match_map[srcip];
        if (this->_policy_map.find(curarea) == this->_policy_map.end()) {
            judge = ACTION_RULNONE; // 无策略，默认拒绝
            break;
        }
        std::vector<std::tr1::shared_ptr<RuleItem> >::iterator itor = 
                this->_policy_map[curarea].begin();
        while (itor != this->_policy_map[curarea].end()) {
            int subret = 0;
            int ret = (*itor)->judge(ctrlinfo, subret);
            if (ret > 0) {
                judge = ACTION_RULACEPT; // ACCEPT
                issubjudge = true;
                subjudge = ret;
                subjudger = (*itor)->_rulename;
                break;
            } else if (ret < 0) {
                judge = ACTION_RULRJECT; // REJECT
                issubjudge = true;
                subjudge = ret;
                subjudger = (*itor)->_rulename;
                break;
            }
            ++itor;
        }
    } while (false);
    if (needlog) {
        std::string jsonstr;
        CJsonWrapper::add_object_int_node(root, "judge", judge);
        if (issubjudge) {
            CJsonWrapper::add_object_string_node(root, "subjudger", subjudger);
            CJsonWrapper::add_object_int_node(root, "subjudge", subjudge);
        }
        CJsonWrapper::get_json_string(root, jsonstr);
        Report::get_instance().report(Report::SENDER_SERV, Report::LEVEL_INFO, 
                __LINE__, __FILE__, "RMJU:" + jsonstr, false);
    }
    return judge;
}

/**
 * 设置云控开关
 * @param swi
 */
void RuleManager::set_g_switch(unsigned int swi) {
    Locker lock(this->_mutex);
    this->_g_switch = swi;
}

/**
 * 获取云控开关
 * @return 
 */
unsigned int RuleManager::get_g_switch() {
    Locker lock(this->_mutex);
    return this->_g_switch;
}

/**
 * 判断IP是否位于某域内
 * @param ipv4_addr         ipv4地址整数
 * @param type                   IP地址范围类型
 * @param s                         表示IP地址范围的串
 * @return 
 */
bool RuleManager::is_ip_in_range(unsigned int ipv4_addr, int type, const std::string& s) {
    if (type == IP_TYPE_DOTDEC) {
        in_addr ip_begin = { 0 };
        if (0 != inet_aton(s.c_str(), &ip_begin)) {
            if (ip_begin.s_addr == ipv4_addr) {
                return true;
            }
        }
    } else if (type == IP_TYPE_RANGE) {
        size_t m_p = s.find('-');
        in_addr ip_begin = { 0 };
        in_addr ip_end = { 0 };
        if (0 != inet_aton(s.substr(0, m_p).c_str(), &ip_begin) && 
                0 != inet_aton(s.substr(m_p + 1).c_str(), &ip_end)) {
            unsigned long ipbeg = ntohl(ip_begin.s_addr);
            unsigned long ipend = ntohl(ip_end.s_addr);
            unsigned long cur = ntohl(ipv4_addr);
            if (cur >= ipbeg && cur <= ipend) {
                return true;
            }
        }
    } else if (type == IP_TYPE_SUBNET) {
        size_t m_p = s.find('/');
        in_addr ip_begin = { 0 };
        int ip_bit = atoi(s.substr(m_p + 1).c_str());
        if (0 != inet_aton(s.substr(0, m_p).c_str(), &ip_begin) && ip_bit <= 16) {
            unsigned long ipbeg = (ntohl(ip_begin.s_addr) >> ip_bit) << ip_bit;
            unsigned long delta = 1 << ip_bit;
            unsigned long cur = ntohl(ipv4_addr);
            if (cur >= ipbeg && cur <= ipbeg + delta) {
                return true;
            }
        }
    }
    return false;
}

/**
 * 构造机器类型映射
 * @param type
 * @param addrset
 * @param output
 * @return 
 */
int RuleManager::parse_ip_for_type(int type, std::vector<std::string>& addrset, 
        std::set<unsigned int>& output) {
    int succount = 0;
    std::vector<std::string>::iterator itor = addrset.begin();
    while (itor != addrset.end()) {
        std::string& s = (*itor);
        if (type == IP_TYPE_DOTDEC) {
            in_addr ip_begin = { 0 };
            if (0 != inet_aton(s.c_str(), &ip_begin)) {
                output.insert(ip_begin.s_addr);
                ++succount;
            }
        }
        else if (type == IP_TYPE_RANGE) { // 遵循iptables ip合并规则
            size_t m_p = s.find('-');
            in_addr ip_begin = { 0 };
            in_addr ip_end = { 0 };
            if (0 != inet_aton(s.substr(0, m_p).c_str(), &ip_begin) && 
                    0 != inet_aton(s.substr(m_p + 1).c_str(), &ip_end)) {
                unsigned long i = ntohl(ip_begin.s_addr);
                unsigned long ipend = ntohl(ip_end.s_addr);
                if (ipend - i > MAX_IP_POOL_NUM) {
                    LOGI("range too much");
                    break;
                } else {
                    while (i <= ipend) {
                        output.insert(htonl(i));
                        ++i;
                        ++succount;
                    }
                }
            }
        } else if (type == IP_TYPE_SUBNET) {
            size_t m_p = s.find('/');
            in_addr ip_begin = { 0 };
            int ip_bit = atoi(s.substr(m_p + 1).c_str());
            if (0 != inet_aton(s.substr(0, m_p).c_str(), &ip_begin) && ip_bit <= 16) {
                unsigned long ipbeg = (ntohl(ip_begin.s_addr) >> ip_bit) << ip_bit;
                unsigned long i = 1 << ip_bit;
                if (i > MAX_IP_POOL_NUM) {
                    LOGI("range too much");
                    break; 
                } else {
                    while (i-- > 0) {
                        output.insert(htonl(ipbeg + i));
                        ++succount;
                    }
                }
            }
        } else if (type == IP_TYPE_MANAME || type == IP_TYPE_DONAME) {
            std::vector<unsigned int> ipn = get_ipv4_by_host(s);
            std::vector<unsigned int>::iterator ipitor = ipn.begin();
            while (ipitor != ipn.end()) {
                LOGI("reparse %s -> %x", s.c_str(), (*ipitor));
                output.insert(*ipitor);
                ++ipitor;
            }
        }
        ++itor;
    }
    return succount; // 成功解析的IP数
}

/**
 * 递归解析machine.json规则
 * @param area_type_node    父节点，如isolation
 * @param area_name         当前节点名
 * @param ignore_deploy     用于解析type=255情况，将结果解析到cache中
 * @param depth             递归计数
 * @return 
 */
int RuleManager::update_area_map(CJsonWrapper::NodeType area_type_root, std::string& area_name, 
        std::set<unsigned int>& ipset, int depth) {
    bool isdeploy = false;
    if (!area_type_root || depth > 2) { // 最多嵌套3层
        return -1; // invalid param
    }
    CJsonWrapper::NodeType areanode = 0;
    if (!CJsonWrapper::get_object_object_node(area_type_root, area_name, areanode)) {
        return -2; // invalid root
    }
    CJsonWrapper::NodeType addrnode = 0;
    if (!CJsonWrapper::get_object_object_node(areanode, "addr", addrnode)) {
        return -3; // invalid addr
    }
    CJsonWrapper::NodeType deploynode = 0;
    if (CJsonWrapper::get_object_object_node(areanode, "deploy", deploynode)) {
        if (CJsonWrapper::is_true(deploynode)) {
            isdeploy = true;
        }
    }
    int arrsize = CJsonWrapper::get_array_size(addrnode);
    int i = 0;
    std::string item;
    for (; i < arrsize; i++) {
        CJsonWrapper::NodeType curele = 0;
        if (!CJsonWrapper::get_array_object_node(addrnode, i, curele)) {
            continue;
        }
        int addrtype = 0;
        CJsonWrapper::NodeType valuenode = 0;
        if (CJsonWrapper::get_object_int_node(curele, "type", addrtype) &&
                CJsonWrapper::get_object_object_node(curele, "value", valuenode)) {
            std::vector<std::string> addr_values;
            int index = CJsonWrapper::get_array_size(valuenode);
            while (index-- > 0) {
                if (CJsonWrapper::get_array_string_node(valuenode, index, item)) {
                    addr_values.push_back(item);
                }
            }
            if (addrtype == IP_TYPE_SET) { // 递归解析
                std::vector<std::string>::iterator setname_itor = addr_values.begin();
                while (setname_itor != addr_values.end()) { 
                    this->update_area_map(area_type_root, (*setname_itor), ipset, depth + 1);
                    ++setname_itor;
                }
            } else {
                std::set<unsigned int> addr_ints;
                this->parse_ip_for_type(addrtype, addr_values, addr_ints);
                ipset.insert(addr_ints.begin(), addr_ints.end());
            }
        }
    }
    
    if (isdeploy) { // 每个地址都能唯一的映射到区域
        std::set<unsigned int>::iterator itor = ipset.begin();
        while (itor != ipset.end()) {
            this->_ip_match_map[(*itor)] = area_name;
            ++itor;
        }
    }
    return 0;
}

/**
 * 解析机器列表配置
 * @param root
 * @return 
 */
int RuleManager::parse_machine_json(CJsonWrapper::NodeType root) {
    // 解析 IP -- 集群名 的映射
    if (!root) {
        return ERR_JSONPARSE; // parse error
    }
    std::vector<std::string> area_type_names = CJsonWrapper::get_object_keys(root);
    // area type name : isolation / other
    std::vector<std::string>::iterator area_type_name_itor = area_type_names.begin();
    while (area_type_name_itor != area_type_names.end()) {
        std::string& name_layer_1 = (*area_type_name_itor);
        if (name_layer_1 == "other" || name_layer_1 == "isolation") { 
            CJsonWrapper::NodeType area_type_root = 0;
            if (!CJsonWrapper::get_object_object_node(root, name_layer_1, area_type_root)) {
                ++area_type_name_itor;
                continue;
            }
            std::vector<std::string> area_names =
                    CJsonWrapper::get_object_keys(area_type_root);
            std::vector<std::string>::iterator area_name_itor = area_names.begin();
            while (area_name_itor != area_names.end()) {
                std::string& area_name = (*area_name_itor);
                std::set<unsigned int> ipset;
                this->update_area_map(area_type_root, area_name, ipset, 0);
                // 更新结果到_ip_area_map
                std::set<unsigned int>::iterator addr_itor = ipset.begin();
                while (addr_itor != ipset.end()) {
                    this->_ip_area_map[(*addr_itor)].insert(area_name);
                    ++addr_itor;  
                }
                ++area_name_itor;
            }
        } else if (name_layer_1 == "version") {
            int mac_version = 0;
            CJsonWrapper::get_object_int_node(root, "version", mac_version);
            this->_version["machine_json_version"] = mac_version;
        }
        ++area_type_name_itor;
    }
    return ERR_SUCCESS;
}

/**
 * 构造策略对象
 * @param nodetype
 * @param root
 * @param out
 * @return 
 */
int RuleManager::update_policy_map(const std::string& nodetype, CJsonWrapper::NodeType root, 
        strnodemap& out) {
    if (!root || !CJsonWrapper::is_array(root)) {
        return -1; // invalid param
    }
    int len = CJsonWrapper::get_array_size(root);
    int i = 0;
    CJsonWrapper::NodeType subroot = 0;
    std::string c_rule_name;
    if (nodetype == "base_rules") {
        for (; i < len; i++) {
            if (!CJsonWrapper::get_array_object_node(root, i, subroot)) {
                continue;
            }
            CJsonWrapper::NodeType rules = 0;
            if (CJsonWrapper::get_object_string_node(subroot, "rule_name", c_rule_name) &&
                    CJsonWrapper::get_object_object_node(subroot, "rules", rules)) {
                out[c_rule_name] = rules;
            }
        }
    } else if (nodetype == "policys") {
        for (; i < len; i++) {
            if (!CJsonWrapper::get_array_object_node(root, i, subroot)) {
                continue;
            }
            if (CJsonWrapper::get_object_string_node(subroot, "type", c_rule_name)) {
                out[c_rule_name] = subroot;
            }
        }
    }
    return 0;
}

/**
 * 解析策略配置
 * @param nodetype
 * @param root
 * @param out
 * @return 
 */
int RuleManager::parse_policy_json(CJsonWrapper::NodeType root) {
    // 解析 rule / policy           忽略default_policy节点
    if (!root) {
        return ERR_JSONPARSE; // parse error
    }
    CJsonWrapper::NodeType base_rules_root = 0;
    CJsonWrapper::NodeType policys_root = 0;
    int pol_version = 0; // do check on version
    CJsonWrapper::get_object_object_node(root, "policys", policys_root);
    if (!CJsonWrapper::get_object_object_node(root, "base_rules", base_rules_root) || 
            !CJsonWrapper::get_object_int_node(root, "version", pol_version)) {
        return ERR_JSONGEOBJ; // key root not exist
    }
    this->_version["policy_json_version"] = pol_version;
    // 1st step: collect all base rules & policy
    strnodemap baserules;
    strnodemap policys;
    this->update_policy_map("base_rules", base_rules_root, baserules);
    this->update_policy_map("policys", policys_root, policys);
    // 2nd step: update rule pool for basic rules
    strnodemap::iterator base_rules_itor = baserules.begin();
    while (base_rules_itor != baserules.end()) {
        const std::string& base_rules_name = (*base_rules_itor).first;
        CJsonWrapper::NodeType base_root =  (*base_rules_itor).second;
        int lenj = CJsonWrapper::get_array_size(base_root);
        int j = 0;
        for (; j < lenj; j++) { // 解析base_rules包含的每个rules
            CJsonWrapper::NodeType subroot = 0;
            if (!CJsonWrapper::get_array_object_node(base_root, j, subroot)) {
                continue;
            }
            std::string sub_rule_name = base_rules_name + get_uuid();
            this->_base_rule_pool[base_rules_name].push_back(std::tr1::shared_ptr<RuleItem>(
                    new RuleItem(sub_rule_name, subroot, *this)));
        }
        ++base_rules_itor;
    }
    // 3rd step: parse policy for each ip
    strnodemap::iterator itor_pol = policys.begin();
    while (itor_pol != policys.end()) {
        const std::string& area_name = (*itor_pol).first;
        CJsonWrapper::NodeType match_policy_node = (*itor_pol).second;
        CJsonWrapper::NodeType base_rules_root = 0;
        CJsonWrapper::NodeType rules_root = 0;
        if (CJsonWrapper::get_object_object_node(match_policy_node, "base_rules", 
                base_rules_root)) {
            int len = CJsonWrapper::get_array_size(base_rules_root);
            int i = 0;
            std::string c_rule_name;
            for (; i < len; i++) { // 解析当前policys中的每个base_rules
                if (!CJsonWrapper::get_array_string_node(base_rules_root, i, c_rule_name)) {
                    continue;
                }
                if (this->_base_rule_pool.find(c_rule_name) == this->_base_rule_pool.end()) {
                    continue;
                }
                rulevec base_rules = this->_base_rule_pool[c_rule_name];
                rulevec::iterator base_rule_itor = base_rules.begin();
                while (base_rule_itor != base_rules.end()) {
                    this->_policy_map[area_name].push_back((*base_rule_itor));
                    ++base_rule_itor;
                }
            }
        }
        if (CJsonWrapper::get_object_object_node(match_policy_node, "rules", rules_root)) {
            int len = CJsonWrapper::get_array_size(rules_root);
            int i = 0;
            for (; i < len; i++) { // 解析当前policys中的每个rules
                CJsonWrapper::NodeType subroot = 0;
                if (!CJsonWrapper::get_array_object_node(rules_root, i, subroot)) {
                    continue;
                }
                this->_policy_map[area_name].push_back(std::tr1::shared_ptr<RuleItem>(
                        new RuleItem(area_name, subroot, *this)));
            }    
        }  
        ++itor_pol;
    }
    return ERR_SUCCESS;
}

/**
 * 解析端口配置
 * @param root
 * @return 
 */
int RuleManager::parse_port_json(CJsonWrapper::NodeType root) {
    // 解析 port
    if (!root) {
        return ERR_JSONPARSE; // parse error
    }
    std::vector<std::string> item_names = CJsonWrapper::get_object_keys(root);
    std::vector<std::string>::iterator item_name_itor = item_names.begin();
    while (item_name_itor != item_names.end()) {
        std::string& name_layer_1 = (*item_name_itor);
        if (name_layer_1 == "version") {
            int por_version = 0; // do check on version
            CJsonWrapper::get_object_int_node(root, "version", por_version);
            this->_version["port_json_version"] = por_version;
        } else {
            CJsonWrapper::NodeType portarr = 0;
            if (CJsonWrapper::get_object_object_node(root, name_layer_1, portarr)) {
                int arrsize = CJsonWrapper::get_array_size(portarr);
                int i = 0;
                for (; i < arrsize; i++) {
                    int oneport = 0;
                    if (CJsonWrapper::get_array_int_node(portarr, i, oneport)) {
                        this->_port_area_map[oneport].insert(name_layer_1);
                    }
                }
            }
        }
        ++item_name_itor;
    }
    return ERR_SUCCESS;
}

bool RuleManager::is_in_special_white(CJsonWrapper::NodeType root) {
    if (!root) {
        return true; // 放过
    }
    
    // 检测是否为白机器
    std::string _dstip;
    unsigned short _srcport = 0; 
    if (CJsonWrapper::get_object_string_node(root, "dstip", _dstip)) {
        if (CJsonWrapper::get_object_int_node(root, "srcport", _srcport)) {
            unsigned int curipv4 = get_ipnv4_from_ip(_dstip);
            if (this->_white_ips.find(curipv4) != this->_white_ips.end() && _srcport == 22) {
                return true;
            }
        }
    }

    std::string _exe;
    if (CJsonWrapper::get_object_string_node(root, "exe", _exe)) {
        int i = 0;
        while (g_white_exe_list[i]) {
            if (!fnmatch(g_white_exe_list[i], _exe.c_str(), 0)) { // 正则匹配
                return true;
            }
            ++i;
        }
    }
    return false;
}

/**
 * 检测目标是否位于白名单
 * @param root
 * @return 
 */
bool RuleManager::is_in_white_list(CJsonWrapper::NodeType root) {
    if (!root) {
        return true; // 放过
    }
    
    // 如果在特殊白名单中则放行
    if (this->is_in_special_white(root)) {
        return true;
    }
    
    std::tr1::unordered_map<std::string, std::set<std::string> >::iterator white_itor = 
            this->_white_map.begin();
    while (white_itor != this->_white_map.end()) {
        const std::string& k = (*white_itor).first;
        if (k == "exe") {
            std::string curexe;
            std::set<std::string>::iterator itor = (*white_itor).second.begin();
            if (CJsonWrapper::get_object_string_node(root, "exe", curexe)) {
                while (itor != (*white_itor).second.end()) {
                    if (!fnmatch((*itor).c_str(), curexe.c_str(), 0)) {
                        return true; // in white list
                    }
                    ++itor;
                }
            }
        } else if (k == "md5") {
            std::string curmd5;
            std::set<std::string>::iterator itor = (*white_itor).second.begin();
            if (CJsonWrapper::get_object_string_node(root, "md5", curmd5)) {
                while (itor != (*white_itor).second.end()) {
                    if (curmd5 == (*itor)) {
                        return true; // in white list
                    }
                    ++itor;
                }
            }
        } else if (k == "srcip") {
            std::string _ip;
            std::set<std::string>::iterator itor = (*white_itor).second.begin();
            if (CJsonWrapper::get_object_string_node(root, "srcip", _ip)) {
                unsigned int curipv4 = get_ipnv4_from_ip(_ip);
                while (itor != (*white_itor).second.end()) {
                    const std::string& ipv4 = (*itor);
                    int type = IP_TYPE_DOTDEC;
                    if (ipv4.find('-') != std::string::npos) {
                        type = IP_TYPE_RANGE;
                    } else if (ipv4.find('/') != std::string::npos) {
                        type = IP_TYPE_SUBNET;
                    }
                    if (this->is_ip_in_range(curipv4, type, ipv4)) {
                        return true; // in white list
                    }
                    ++itor;
                }
            }
        } else if (k == "dstip") {
            std::string _ip;
            std::set<std::string>::iterator itor = (*white_itor).second.begin();
            if (CJsonWrapper::get_object_string_node(root, "dstip", _ip)) {
                unsigned int curipv4 = get_ipnv4_from_ip(_ip);
                while (itor != (*white_itor).second.end()) {
                    const std::string& ipv4 = (*itor);
                    int type = IP_TYPE_DOTDEC;
                    if (ipv4.find('-') != std::string::npos) {
                        type = IP_TYPE_RANGE;
                    } else if (ipv4.find('/') != std::string::npos) {
                        type = IP_TYPE_SUBNET;
                    }
                    if (this->is_ip_in_range(curipv4, type, ipv4)) {
                        return true; // in white list
                    }
                    ++itor;
                }
            }
        }
        ++white_itor;
    }
    return false; // not in white list
}

/**
 * 解析白名单配置
 * @param root
 * @return 
 */
int RuleManager::parse_white_json(CJsonWrapper::NodeType root) {
    // 解析白名单
    if (!root) {
        return ERR_JSONPARSE; // parse error
    }
    std::vector<std::string> item_names = CJsonWrapper::get_object_keys(root);
    std::vector<std::string>::iterator item_name_itor = item_names.begin();
    while (item_name_itor != item_names.end()) {
        std::string& name_layer_1 = (*item_name_itor);
        if (name_layer_1 == "version") {
            int whi_version = 0; // do check on version
            CJsonWrapper::get_object_int_node(root, "version", whi_version);
            this->_version["white_json_version"] = whi_version;
        } else if (name_layer_1 == "exe") { // 进程路径正则/模块文件MD5/本机IP
            CJsonWrapper::NodeType exenode = 0;
            if (CJsonWrapper::get_object_object_node(root, name_layer_1, exenode)) {
                int arrsize = CJsonWrapper::get_array_size(exenode);
                int i = 0;
                for (; i < arrsize; i++) {
                    std::string exepath;
                    if (CJsonWrapper::get_array_string_node(exenode, i, exepath)) {
                        this->_white_map["exe"].insert(exepath);
                    }
                }
            }
        } else if (name_layer_1 == "md5") {
            CJsonWrapper::NodeType md5node = 0;
            if (CJsonWrapper::get_object_object_node(root, name_layer_1, md5node)) {
                int arrsize = CJsonWrapper::get_array_size(md5node);
                int i = 0;
                for (; i < arrsize; i++) {
                    std::string md5;
                    if (CJsonWrapper::get_array_string_node(md5node, i, md5)) {
                        std::transform(md5.begin(), md5.end(), md5.begin(), ::tolower);
                        this->_white_map["md5"].insert(md5);
                    }
                }
            }
        } else if (name_layer_1 == "srcip") {
            CJsonWrapper::NodeType ipnode = 0;
            if (CJsonWrapper::get_object_object_node(root, name_layer_1, ipnode)) {
                int arrsize = CJsonWrapper::get_array_size(ipnode);
                int i = 0;
                for (; i < arrsize; i++) {
                    std::string ipv4;
                    if (CJsonWrapper::get_array_string_node(ipnode, i, ipv4)) {
                        this->_white_map["srcip"].insert(ipv4);
                    }
                }
            }
        } else if (name_layer_1 == "dstip") {
            CJsonWrapper::NodeType ipnode = 0;
            if (CJsonWrapper::get_object_object_node(root, name_layer_1, ipnode)) {
                int arrsize = CJsonWrapper::get_array_size(ipnode);
                int i = 0;
                for (; i < arrsize; i++) {
                    std::string ipv4;
                    if (CJsonWrapper::get_array_string_node(ipnode, i, ipv4)) {
                        this->_white_map["dstip"].insert(ipv4);
                    }
                }
            }
        }
        ++item_name_itor;
    }
    return ERR_SUCCESS;
}

