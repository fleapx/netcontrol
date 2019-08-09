#include "remote_rule_manager.h"
#include "thpool.h"
#include <stdio.h>

void lsock_handler(void* buffer) {
    TimeTester tester(__FUNCTION__);
    std::string uniqid = (char*)buffer;
    std::string request = (char*)buffer + 512;
    int result = RemoteRuleManager::judge_remote(uniqid, request);
    printf("%s -> %d\n", request.c_str(), result);
}

void npipe_handler(void* buffer) {
    std::string request = (char*)buffer + 512;
    std::string response;
    IPCStub::npipe_client_fetch("/etc/taurus.ctrl", request, response);
    printf("%s -> %s\n", request.c_str(), response.c_str());
}

int main(int argc, char** argv) {
    int i = 0;
    int type = -1; // 0->lsock   1->npipe
    int testnum = 0;
    char buffer[1024];
    for (i = 1; i < argc; i++) {
        if (!strncmp(argv[i], "-t=", 3)) {
            if (!strcmp(argv[i] + 3, "lsock")) {
                type = 0;
            } else if (!strcmp(argv[i] + 3, "npipe")) {
                type = 1;
            }
        } else if (!strncmp(argv[i], "-n=", 3)) {
            testnum = atoi(argv[i] + 3);
        } else if (!strncmp(argv[i], "-i=", 3)) {
            memcpy((char*)buffer, argv[i] + 3, strlen(argv[i] + 3) + 1);
        } else if (!strncmp(argv[i], "-r=", 3)) {
            memcpy((char*)buffer + 512, argv[i] + 3, strlen(argv[i] + 3) + 1);
        }
    }
    if ((type != 0 && type != 1) || testnum < 1) {
        return -1;
    }
    ThreadPool pool;
    for (i = 0; i < testnum; i++) {
        if (type == 0) {
            pool.add_work((void(*)(void*))lsock_handler, buffer);
        } else if (type == 1) {
            pool.add_work((void(*)(void*))npipe_handler, buffer);
        }
    }
    pool.wait_work();
    return 0;
}
