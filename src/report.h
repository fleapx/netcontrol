#ifndef TAURUS_REPORT_H
#define TAURUS_REPORT_H

#include "singleton.h"
#include "interface.h"
#include "common_headers.h"
#include "cjson_glue.h"
#include "utils.h"

class Report : public ISingleton<Report> {
    friend class ISingleton<Report>;
public:
    enum {
        SENDER_LIB = 0, // libtaurus.so
        SENDER_SERV, // taurus_server
        SENDER_HEAL, // health_check
        SENDER_DAEM,   // taurus_daemon
        SENDER_STAR, // taurus_starter
        
        LEVEL_INFO = 0,
        LEVEL_WARN,
        LEVEL_ERROR,
        LEVEL_MAX
    };
    
public:
    Report();
    ~Report();
    bool log(
            int sender,              // SENDER_*
            int level,                  // LEVEL_*
            int line,                   // line number in source code
            const char* file,     // file name in source code
            const CJsonWrapper::NodeType& content, // data to log
            bool withtag = true
    );
    bool report(                   
            int sender,              // SENDER_*
            int level,                  // LEVEL_*
            int line,                   // line number in source code
            const char* file,     // file name in source code
            const CJsonWrapper::NodeType& content, // data to log
            bool withtag = true
    );
    bool log(
            int sender,              // SENDER_*
            int level,                  // LEVEL_*
            int line,                   // line number in source code
            const char* file,     // file name in source code
            const std::string& content, // data to log
            bool withtag = true
    );
    bool report(
            int sender,              // SENDER_*
            int level,                  // LEVEL_*
            int line,                   // line number in source code
            const char* file,     // file name in source code
            const std::string& content, // data to log
            bool withtag = true
    );
    bool vlog(
            int sender,              // SENDER_*
            int level,                  // LEVEL_*
            int line,                   // line number in source code
            const char* file,     // file name in source code
            const char* format, // data string format
            ...                             // multiple string params
    );
    bool vreport(
            int sender,              // SENDER_*
            int level,                  // LEVEL_*
            int line,                   // line number in source code
            const char* file,     // file name in source code
            const char* format,  // data string format
            ...                             // multiple string params
    );
    
    static void print_filter_netlog(std::ifstream& logfp, int filter, 
        const std::string& log_base_time, time_t& btmt, time_t& etmt);
    
    static bool is_in_logtime(const std::string& log_base_time, const std::string& log_line, 
        time_t& btmt, time_t& etmt);
    
private:
    typeof(logfunci)* logf[LEVEL_MAX];
};

#endif //TAURUS_REPORT_H
