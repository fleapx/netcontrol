#ifndef TAURUS_RULE_MANAGER_H
#define TAURUS_RULE_MANAGER_H

#include "common_headers.h"
#include "cjson_glue.h"
#include "utils.h"
#include "interprocess.h"
#include "info_manager.h"

class RuleManager;

class NetRuleItem {
public:
    unsigned int _mask; // MASK_IP:addr MASK_PORT:port
    std::string _addrset_name;
    std::string _portset_name;
};

class RuleItem {
public:
    RuleItem(const std::string& rulename, CJsonWrapper::NodeType root, RuleManager& ruleman);
    int judge(const ControlInfo& ctrlinfo, int& subret);
    
private:
    int parse_net_control(const std::string& key, CJsonWrapper::NodeType node);
    bool handle_netrule_match(unsigned int dstip, unsigned short dstport);
    bool handle_str_match(
        int type,                            // 匹配类型
        const std::string& info,             // 待匹配串
        const std::vector<std::string>& comp // 模式串集合
    );

public:
    std::string _rulename;
    
private:   
    RuleManager& _ruleman; // RuleManager对象必须全局存在
    bool _enable; // 标志该rule合法性
    // 必须因子
    unsigned int _direction; // 1:in 2:out
    unsigned int _socktype; // 1<<1:SOCK_STREAM  1<<2:SOCK_DGRAM   1<<3:SOCK_RAW
    int _action; // -1:REJECT 1:ACCEPT 0:PASSNEXT
    // 可选因子
    unsigned int _mask;
    
    std::vector<NetRuleItem> _remote_net; // 远端 IP / PORT / IP+PORT 规则集合
    std::vector<std::string> _local_port; // 本地 PORT 规则集合
    std::vector<std::string> _process;
    std::vector<std::string> _md5;
    std::vector<std::string> _baas_usrn;
    std::vector<std::string> _baas_grpn;
    std::vector<std::string> _baas_role;
};

// Agent需要事先把policy.json和machine.json中type=4/5/6形式的addr全转换成type=1/2/3形式再存储到本地
class RuleManager {
    typedef std::tr1::unordered_map<std::string, CJsonWrapper::NodeType> strnodemap;
    typedef std::vector<std::tr1::shared_ptr<RuleItem> > rulevec;
    
    enum {
        UPDATE_INTERVAL = 300,
        MAX_IP_POOL_NUM = 65536,
        MAX_POLICY_DEPTH = 10,
    };
    
    friend class RuleItem; // 对RuleItem提供表访问权限
public:
    RuleManager();
    ~RuleManager();
    int update(const std::string& rootdir); // 以根目录为rootdir的策略文件进行升级
    void clean();
    int judge(CJsonWrapper::NodeType root); 
    void swap(RuleManager& otherman);
    bool isempty();
    // bool judge_remote(const std::string& ctrlinfo); // 用于异进程校验
    bool is_in_white_list(CJsonWrapper::NodeType root); // for test
    bool is_in_special_white(CJsonWrapper::NodeType root);
    void set_g_switch(unsigned int swi);
    unsigned int get_g_switch(); // for test
    unsigned int get_current_ip(); // for test
    void trans_json(CJsonWrapper::NodeType root, int layer);
    
private:
    bool is_ip_in_range(
        unsigned int addr,                          // 待测试地址(一般是本机IP)
        int type,                                   // iprange对应的IP类型:IP_TYPE_DOTDEC/IP_TYPE_SUBNET/IP_TYPE_RANGE
        const std::string& iprange);
    int parse_ip_for_type(
            int addrtype,                           // 地址类型
            std::vector<std::string>& addrset,      // 待解析地址字符串
            std::set<unsigned int>& output);        // 输出地址集
    int update_area_map(
            CJsonWrapper::NodeType area_type_root,  // 上级根节点
            std::string& area_name,                 // IP区域名
            std::set<unsigned int>& ipset,          // IP区域地址集
            int depth);                             // 递归深度(IP_TYPE_SET)
    int update_policy_map(                        
            const std::string& nodetype,            // 节点类型(base_rules/policy)
            CJsonWrapper::NodeType root,            // json节点
            strnodemap& out);                       // 输出结果集
    int parse_machine_json(CJsonWrapper::NodeType root);
    int parse_policy_json(CJsonWrapper::NodeType root);
    int parse_port_json(CJsonWrapper::NodeType root);
    int parse_white_json(CJsonWrapper::NodeType root);
    
public:
    bool _init;
    
private:
    unsigned int _g_switch; // 云控开关   false:关  true:开
    pthread_mutex_t _mutex; // 策略锁
    
    std::set<unsigned int> _white_ips;
    
    std::tr1::unordered_map<std::string, int> _version; // 策略文件版本
    std::tr1::unordered_map<std::string, std::string> _config; // 配置
    
    std::tr1::unordered_map<unsigned int, std::set<std::string> > _ip_area_map;
    /*
     *  IP -> [areaname1, areaname2, ...]   通过IP查包含此IP的所有域
     */
    std::tr1::unordered_map<unsigned int, std::string> _ip_match_map;
    /*
     *  IP -> areaname  _ip_match_map   通过IP查所属规则域名
     */
    std::tr1::unordered_map<unsigned short, std::set<std::string> > _port_area_map; 
    /*
     *  PORT -> areaname                         端口表
     */
    std::tr1::unordered_map<std::string, rulevec> _policy_map; // 
    /*
     *  areaname -> rule set                      策略表
     */
    std::tr1::unordered_map<std::string, std::set<std::string> > _white_map; // 
    /*
     *  white_type -> pass pattern set     白名单表
     */
    std::tr1::unordered_map<std::string, rulevec> _base_rule_pool;
    /*
     *  规则池
     */
};

#endif //TAURUS_RULE_MANAGER_H
