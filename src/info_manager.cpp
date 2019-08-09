#include "info_manager.h"

ControlInfo::ControlInfo() : _mask(0) {
    this->_uniqid = get_uuid();
}

// 序列化
bool ControlInfo::serial_str(const ControlInfo& input, std::string& output) {
    CJsonWrapper::NodeType root = CJsonWrapper::create_object_node();
    if (root == 0) {
        return false;
    }
    bool result = false;
    CJsonWrapper::add_object_int_node(root, "mask", input._mask);
    CJsonWrapper::add_object_string_node(root, "exe", input._exe);
    CJsonWrapper::add_object_string_node(root, "md5", input._md5);
    CJsonWrapper::add_object_string_node(root, "cmdline", input._cmdline);
    CJsonWrapper::add_object_string_node(root, "pexe", input._pexe);
    CJsonWrapper::add_object_string_node(root, "pmd5", input._pmd5);
    CJsonWrapper::add_object_string_node(root, "pcmdline", input._pcmdline);
    CJsonWrapper::add_object_string_node(root, "srcip", input._srcip);
    CJsonWrapper::add_object_string_node(root, "dstip", input._dstip);
    CJsonWrapper::add_object_int_node(root, "srcport", input._srcport);
    CJsonWrapper::add_object_int_node(root, "dstport", input._dstport);
    CJsonWrapper::add_object_int_node(root, "socktype", input._typeset);
    CJsonWrapper::add_object_int_node(root, "sockproto", input._sockproto);
    CJsonWrapper::add_object_int_node(root, "family", input._family);
    CJsonWrapper::add_object_string_node(root, "api", input._api);
    CJsonWrapper::add_object_string_node(root, "uniqid", input._uniqid);
    result = CJsonWrapper::get_json_string(root, output);
    CJsonWrapper::release_root_node(root);
    return result;
}

// 反序列化
bool ControlInfo::deserial_str(const std::string& input, ControlInfo& output) {
    CJsonWrapper::NodeType root = CJsonWrapper::parse_text(input);
    if (root == 0) {
        return false;
    }
    CJsonWrapper::get_object_int_node(root, "mask", output._mask);
    CJsonWrapper::get_object_string_node(root, "exe", output._exe);
    CJsonWrapper::get_object_string_node(root, "md5", output._md5);
    CJsonWrapper::get_object_string_node(root, "cmdline", output._cmdline);
    CJsonWrapper::get_object_string_node(root, "pexe", output._pexe);
    CJsonWrapper::get_object_string_node(root, "pmd5", output._pmd5);
    CJsonWrapper::get_object_string_node(root, "pcmdline", output._pcmdline);
    CJsonWrapper::get_object_string_node(root, "srcip", output._srcip);
    CJsonWrapper::get_object_string_node(root, "dstip", output._dstip);
    CJsonWrapper::get_object_int_node(root, "srcport", output._srcport);
    CJsonWrapper::get_object_int_node(root, "dstport", output._dstport);
    CJsonWrapper::get_object_int_node(root, "socktype", output._typeset);
    CJsonWrapper::get_object_int_node(root, "sockproto", output._sockproto);
    CJsonWrapper::get_object_int_node(root, "family", output._family);
    CJsonWrapper::get_object_string_node(root, "api", output._api);
    CJsonWrapper::get_object_string_node(root, "uniqid", output._uniqid);
    CJsonWrapper::release_root_node(root);
    return true;
}

// 序列化
bool ControlInfo::serial_json(const ControlInfo& input, CJsonWrapper::NodeType& output) {
    if (output == 0) {
        return false;
    }
    CJsonWrapper::add_object_int_node(output, "mask", input._mask);
    CJsonWrapper::add_object_string_node(output, "exe", input._exe);
    CJsonWrapper::add_object_string_node(output, "md5", input._md5);
    CJsonWrapper::add_object_string_node(output, "cmdline", input._cmdline);
    CJsonWrapper::add_object_string_node(output, "pexe", input._pexe);
    CJsonWrapper::add_object_string_node(output, "pmd5", input._pmd5);
    CJsonWrapper::add_object_string_node(output, "pcmdline", input._pcmdline);
    CJsonWrapper::add_object_string_node(output, "srcip", input._srcip);
    CJsonWrapper::add_object_string_node(output, "dstip", input._dstip);
    CJsonWrapper::add_object_int_node(output, "srcport", input._srcport);
    CJsonWrapper::add_object_int_node(output, "dstport", input._dstport);
    CJsonWrapper::add_object_int_node(output, "socktype", input._typeset);
    CJsonWrapper::add_object_int_node(output, "sockproto", input._sockproto);
    CJsonWrapper::add_object_int_node(output, "family", input._family);
    CJsonWrapper::add_object_string_node(output, "api", input._api);
    CJsonWrapper::add_object_string_node(output, "uniqid", input._uniqid);
    return true;
}

// 反序列化
bool ControlInfo::deserial_json(const CJsonWrapper::NodeType& input, ControlInfo& output) {
    if (input == 0) {
        return false;
    }
    CJsonWrapper::get_object_int_node(input, "mask", output._mask);
    CJsonWrapper::get_object_string_node(input, "exe", output._exe);
    CJsonWrapper::get_object_string_node(input, "md5", output._md5);
    CJsonWrapper::get_object_string_node(input, "cmdline", output._cmdline);
    CJsonWrapper::get_object_string_node(input, "pexe", output._pexe);
    CJsonWrapper::get_object_string_node(input, "pmd5", output._pmd5);
    CJsonWrapper::get_object_string_node(input, "pcmdline", output._pcmdline);
    CJsonWrapper::get_object_string_node(input, "srcip", output._srcip);
    CJsonWrapper::get_object_string_node(input, "dstip", output._dstip);
    CJsonWrapper::get_object_int_node(input, "srcport", output._srcport);
    CJsonWrapper::get_object_int_node(input, "dstport", output._dstport);
    CJsonWrapper::get_object_int_node(input, "socktype", output._typeset);
    CJsonWrapper::get_object_int_node(input, "sockproto", output._sockproto);
    CJsonWrapper::get_object_int_node(input, "family", output._family);
    CJsonWrapper::get_object_string_node(input, "api", output._api);
    CJsonWrapper::get_object_string_node(input, "uniqid", output._uniqid);
    return true;
}

InfoManager::InfoManager() {
    // Update cache
    this->update();
}

InfoManager::~InfoManager() {
}

bool InfoManager::update() {
    Locker lock(this->_mutex);
    this->_ctrlinfo._mask = 0;
    this->_ctrlinfo._srcport = 0;
    this->_ctrlinfo._dstport = 0;
    this->_ctrlinfo._typeset = 0;
    this->_ctrlinfo._family = 0;
    this->collect_processinfo();
    this->collect_networkinfo();
    // this->collect_gianoinfo();
    return true;
}

bool InfoManager::copy_ctrlinfo(ControlInfo& output) {
    Locker lock(this->_mutex);
    output = this->_ctrlinfo;
    return true;
}

bool InfoManager::copy_ctrlinfo_str(std::string& output) {
    Locker lock(this->_mutex);
    return ControlInfo::serial_str(this->_ctrlinfo, output);
}

bool InfoManager::copy_ctrlinfo_json(CJsonWrapper::NodeType& output) {
    Locker lock(this->_mutex);
    return ControlInfo::serial_json(this->_ctrlinfo, output);
}

int InfoManager::collect_processinfo() {
    this->_ctrlinfo._exe = get_exe_path();
    if (this->_ctrlinfo._exe != "$unknown$") { // linux文件名不能包含特殊字符
        this->_ctrlinfo._mask |= MASK_EXE;
        this->_ctrlinfo._md5 = get_file_md5(this->_ctrlinfo._exe);
        if (this->_ctrlinfo._md5.length() != 0) {
            this->_ctrlinfo._mask |= MASK_MD5;
        }
    }
    this->_ctrlinfo._cmdline = get_cmdline();
    if (this->_ctrlinfo._cmdline != "$unknown$") {
        this->_ctrlinfo._mask |= MASK_CMD;
    }
    this->_ctrlinfo._pexe = get_exe_path(getppid());
    if (this->_ctrlinfo._pexe != "$unknown$") { // linux文件名不能包含特殊字符
        this->_ctrlinfo._mask |= MASK_PEXE;
        this->_ctrlinfo._pmd5 = get_file_md5(this->_ctrlinfo._pexe);
        if (this->_ctrlinfo._pmd5.length() != 0) {
            this->_ctrlinfo._mask |= MASK_PMD5;
        }
    }
    this->_ctrlinfo._pcmdline = get_cmdline(getppid());
    if (this->_ctrlinfo._pcmdline != "$unknown$") {
        this->_ctrlinfo._mask |= MASK_PCMD;
    }
    return 0;  
}

int InfoManager::collect_networkinfo() {
    this->_ctrlinfo._srcip = get_current_ip();
    return 0;       
}

int InfoManager::collect_gianoinfo() {
    /*
    if (file_exist("/noah")) { // 在无noah的机器上，不获取giano信息
        int ret = baas::BAAS_Init();
        if (ret != baas::sdk::BAAS_OK) {
            return -10000000 - ret;
        }
        baas::CredentialGenerator generator = baas::ClientUtility::Login();
        if (!generator.IsOK()) {
            return -20000000 - generator.ErrorCode();
        }
        this->_ctrlinfo._mask |= MASK_BAAS_USRN | MASK_BAAS_GRPN | MASK_BAAS_ROLE;
        this->_ctrlinfo._baas_usrn = generator.my_user();
        this->_ctrlinfo._baas_grpn = generator.my_group();
        this->_ctrlinfo._baas_role = generator.my_roles();
        return 0;
    }
    */
    return -1;
}

