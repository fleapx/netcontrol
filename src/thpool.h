#ifndef  TAURUS_THPOOL_H
#define TAURUS_THPOOL_H

#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <time.h>
#include <syslog.h>
#if defined(__linux__)
#include <sys/prctl.h>
#endif

#include "singleton.h"
#include "utils.h"

#define err(str) syslog(LOG_INFO, str)
//#define err(str)

static volatile int s_threads_keepalive;
static volatile int s_threads_on_hold;

/* Binary semaphore */
struct bsem {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    int v;
};

/* Job */
struct job {
    job* prev; /* pointer to previous job   */
    void (*function)(void* arg); /* function pointer          */
    void* arg; /* function's argument       */
};

/* Job queue */
struct jobqueue {
    pthread_mutex_t rwmutex; /* used for queue r/w access */
    job *front; /* pointer to front of queue */
    job *rear; /* pointer to rear  of queue */
    bsem *has_jobs; /* flag as binary semaphore  */
    int len; /* number of jobs in queue   */
};

struct thpool_;

/* Thread */
struct thread {
    int id; /* friendly id               */
    pthread_t pthread; /* pointer to actual thread  */
    thpool_* thpool_p; /* access to thpool          */
};

    /* Threadpool */
struct thpool_ {
    thread** threads; /* pointer to threads        */
    volatile int num_threads_alive; /* threads currently alive   */
    volatile int num_threads_working; /* threads currently working */
    pthread_mutex_t thcount_lock; /* used for thread count etc */
    pthread_cond_t threads_all_idle; /* signal to thpool_wait     */
    jobqueue job_queue; /* job queue                 */
};

typedef struct thpool_* threadpool;

threadpool thpool_init(int num_threads);
int thpool_add_work(threadpool thpool_p, void (*function_p)(void*), void* arg_p);
void thpool_wait(threadpool thpool_p);
void thpool_pause(threadpool thpool_p);
void thpool_resume(threadpool thpool_p);
void thpool_destroy(threadpool thpool_p);
int thpool_num_threads_working(threadpool thpool_p);

class ThreadPool : public ISingleton<ThreadPool> {
    friend class ISingleton<ThreadPool>;
private:
    threadpool _pool;
    pid_t _pid;
public:
    ThreadPool() {
        int minker = get_processor_num(); // 最小核心数
        if (minker < 8) {
            minker = 8;
        }
        this->_pool = thpool_init(8);
    }
    
    void add_work(void(*f)(void*), void* d) {
        thpool_add_work(this->_pool, f, d);
    }
    
    void wait_work() {
        thpool_wait(this->_pool);
    }
    
    void set_pid(pid_t pid) { // 设置用于释放的进程pid
        this->_pid = pid;
    }
    
    ~ThreadPool() {
        if (getpid() == this->_pid) { // 防止fork进程释放
            // thpool_destroy(this->_pool);
        }
    }
};

#endif // TAURUS_THPOOL_H
