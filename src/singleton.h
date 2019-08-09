//
// Created by lichao26 on 2018/4/12
//

#ifndef TAURUS_SINGLETON_H
#define TAURUS_SINGLETON_H

#include <stdio.h>
#include <stdlib.h>

template <typename T>
class ISingleton {
public:
    static T& get_instance() {
        static T instance; // 为避免T构造函数产生并发调用，需要在init中单独做顺序初始化
        return instance;
    }
protected:
    ISingleton() {};
    ISingleton(ISingleton const &);
    //ISingleton(ISingleton const &) = delete;
    ISingleton & operator=(ISingleton const &);
    //ISingleton & operator=(ISingleton const &) = delete;
    virtual ~ISingleton() {};
private:
};

#endif //TAURUS_SINGLETON_H
