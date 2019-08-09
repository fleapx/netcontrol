#include "report.h"

Report::Report() {
#ifdef LIB
    openlog(0, 0, LOG_USER); // so日志
#else
    openlog("taurus", 0, LOG_USER); // service日志
#endif
    unsigned int i = 0;
    for (i = 0; i < ARRLEN(logf); i++) {
        logf[i] = &logfunci;
    }
    logf[LEVEL_INFO] = &logfunci;
    logf[LEVEL_WARN] = &logfuncw;
    logf[LEVEL_ERROR] = &logfunce;
}

Report::~Report() {
    closelog();
}

// 用于格式化短消息
bool Report::vlog(int sender, int level, int line, const char* file, 
        const char* format, ...) {
    if (level < 0 || level >= Report::LEVEL_MAX) {
        return false;
    }
    char buffer[PATH_MAX];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    logf[level]("sender:%d,level:%d,pid:%d,line:%d,file:%s -> %s", sender, level, getpid(), 
                line, file, buffer);
    return true;
}

// 用于格式化短消息
bool Report::vreport(int sender, int level, int line, const char* file, 
        const char* format, ...) {
    if (level < 0 || level >= Report::LEVEL_MAX) {
        return false;
    }
    char buffer[PATH_MAX];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    logf[level]("sender:%d,level:%d,pid:%d,line:%d,file:%s -> %s", sender, level, getpid(), 
            line, file, buffer);
    return true;
} 

bool Report::log(int sender, int level, int line, const char* file, 
        const std::string& content, bool withtag) {
    if (level < 0 || level >= Report::LEVEL_MAX) {
        return false;
    }
    if (withtag) {
        logf[level]("sender:%d,level:%d,pid:%d,line:%d,file:%s -> %s", sender, level, getpid(), 
                line, file, content.c_str());
    } else {
        logf[level](content.c_str());
    }
    return true;
}

bool Report::report(int sender, int level, int line, const char* file, 
        const std::string& content, bool withtag) {
    if (level < 0 || level >= Report::LEVEL_MAX) {
        return false;
    }
    if (withtag) {
        logf[level]("sender:%d,level:%d,pid:%d,line:%d,file:%s -> %s", sender, level, getpid(), 
                line, file, content.c_str());
    } else {
        logf[level](content.c_str());
    }
    return true;
} 

bool Report::log(int sender, int level, int line, const char* file, 
        const CJsonWrapper::NodeType& root, bool withtag) {
    if (level < 0 || level >= Report::LEVEL_MAX) {
        return false;
    }
    std::string content;
    CJsonWrapper::get_json_string(root, content);
    if (withtag) {
        logf[level]("sender:%d,level:%d,pid:%d,line:%d,file:%s -> %s", sender, level, getpid(), 
                line, file, content.c_str());
    } else {
        logf[level](content.c_str());
    }
    return true;
}

bool Report::report(int sender, int level, int line, const char* file, 
        const CJsonWrapper::NodeType& root, bool withtag) {
    if (level < 0 || level >= Report::LEVEL_MAX) {
        return false;
    }
    std::string content;
    CJsonWrapper::get_json_string(root, content);
    if (withtag) {
        logf[level]("sender:%d,level:%d,pid:%d,line:%d,file:%s -> %s", sender, level, getpid(), 
                line, file, content.c_str());
    } else {
        logf[level](content.c_str());
    }
    return true;
}

// log_base_time format: 201807
bool Report::is_in_logtime(const std::string& log_base_time, const std::string& log_line, 
        time_t& btmt, time_t& etmt) {
    std::istringstream iss(log_line);
    std::string mon;
    std::string day;
    std::string timehms;
    iss >> mon >> day >> timehms;
    if (day.length() == 1) {
        day = "0" + day;
    }
    struct tm linetm;
    memset(&linetm, 0, sizeof(linetm));
    std::string whole_time = log_base_time + day + " " + timehms;
    if (strptime(whole_time.c_str(), "%Y%m%d %H:%M:%S", &linetm)) {
        time_t linetmt = timegm(&linetm);
        if (linetmt >= btmt && linetmt <= etmt) {
            return true;
        }
    }
    return false;
}

const static int s_accept = 1;
const static int s_deny = 2;
const static int s_judge = s_accept | s_deny;

void Report::print_filter_netlog(std::ifstream& logfp, int filter, 
        const std::string& log_base_time, time_t& btmt, time_t& etmt) {
    std::string line;
    while (std::getline(logfp, line)) {
        if (line.find("RMJU") == std::string::npos) {
            continue;
        }
        if (!Report::is_in_logtime(log_base_time, line, btmt, etmt)) {
            continue;
        }
        if (filter == s_judge) {
            std::cout << line << std::endl;
        } else if (filter == s_accept) {
            if (line.find("judge\": -") == std::string::npos) {
                std::cout << line << std::endl;
            }
        } else if (filter == s_deny) {
            if (line.find("judge\": -") != std::string::npos) {
                std::cout << line << std::endl;
            }
        }
    }
}