#ifndef TAURUS_INFO_MANAGER_H
#define TAURUS_INFO_MANAGER_H

#include "cjson_glue.h"
#include "common_headers.h"
#include "singleton.h"
#include "utils.h"

/**
 *  基础信息收集   fix information
 */
 
class ControlInfo { // 控制信息模板
public:
    ControlInfo();
    std::string _uniqid;
    unsigned int _mask;
    std::string _exe;
    std::string _md5;
    std::string _cmdline;
    std::string _pexe;
    std::string _pmd5;
    std::string _pcmdline;
    std::string _srcip;
    std::string _dstip;
    unsigned short _srcport;
    unsigned short _dstport;
    unsigned int _typeset;
    unsigned int _sockproto;
    unsigned int _family;
    std::string _baas_usrn;
    std::string _baas_grpn;
    std::string _baas_role;
    std::string _api;
    
public:
    static bool deserial_json(const CJsonWrapper::NodeType& input, ControlInfo& output);
    static bool serial_json(const ControlInfo& input, CJsonWrapper::NodeType& output); 
    
    static bool deserial_str(const std::string& input, ControlInfo& output);
    static bool serial_str(const ControlInfo& input, std::string& output);
};

class InfoManager : public ISingleton<InfoManager> {
    friend class ISingleton<InfoManager>;
public:
    InfoManager();
    ~InfoManager();
    bool update();
    
public:
    bool copy_ctrlinfo(ControlInfo& output);
    bool copy_ctrlinfo_str(std::string& output);
    bool copy_ctrlinfo_json(CJsonWrapper::NodeType& output);
    
private:
    int collect_environment();
    int collect_processinfo();
    int collect_networkinfo();
    int collect_gianoinfo();

private:
    pthread_mutex_t _mutex;
    ControlInfo _ctrlinfo;
};

#endif //TAURUS_INFO_MANAGER_H
