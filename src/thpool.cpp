#include "thpool.h"

static int thread_init(threadpool thpool_p, struct thread** thread_p, int id);
static void* thread_do(struct thread* thread_p);
static void thread_hold(int sig_id);
static void thread_destroy(struct thread* thread_p);

static int jobqueue_init(jobqueue* jobqueue_p);
static void jobqueue_clear(jobqueue* jobqueue_p);
static void jobqueue_push(jobqueue* jobqueue_p, struct job* newjob_p);
static struct job* jobqueue_pull(jobqueue* jobqueue_p);
static void jobqueue_destroy(jobqueue* jobqueue_p);

static void bsem_init(struct bsem *bsem_p, int value);
static void bsem_reset(struct bsem *bsem_p);
static void bsem_post(struct bsem *bsem_p);
static void bsem_post_all(struct bsem *bsem_p);
static void bsem_wait(struct bsem *bsem_p);

/**
 * @brief  Initialize threadpool
 *
 * Initializes a threadpool. This function will not return untill all
 * threads have initialized successfully.
 *
 * @example
 *
 *    ..
 *    threadpool thpool;                     //First we declare a threadpool
 *    thpool = thpool_init(4);               //then we initialize it to 4 threads
 *    ..
 *
 * @param  num_threads   number of threads to be created in the threadpool
 * @return threadpool    created threadpool on success,
 *                       NULL on error
 */
threadpool thpool_init(int num_threads) {

    s_threads_on_hold = 0;
    s_threads_keepalive = 1;

    if (num_threads < 0) {
        num_threads = 0;
    }

    /* Make new thread pool */
    thpool_* thpool_p = 0;
    thpool_p = (struct thpool_*) malloc(sizeof (struct thpool_));
    if (thpool_p == NULL) {
        err("thpool_init(): Could not allocate memory for thread pool\n");
        return NULL;
    }
    thpool_p->num_threads_alive = 0;
    thpool_p->num_threads_working = 0;

    /* Initialise the job queue */
    if (jobqueue_init(&thpool_p->job_queue) == -1) {
        err("thpool_init(): Could not allocate memory for job queue\n");
        free(thpool_p);
        return NULL;
    }

    /* Make threads in pool */
    thpool_p->threads = (struct thread**) malloc(num_threads * sizeof (struct thread *));
    if (thpool_p->threads == NULL) {
        err("thpool_init(): Could not allocate memory for threads\n");
        jobqueue_destroy(&thpool_p->job_queue);
        free(thpool_p);
        return NULL;
    }

    pthread_mutex_init(&(thpool_p->thcount_lock), NULL);
    pthread_cond_init(&thpool_p->threads_all_idle, NULL);

    /* Thread init */
    int n = 0;
    for (n = 0; n < num_threads; n++) {
        thread_init(thpool_p, &thpool_p->threads[n], n);
#if THPOOL_DEBUG
        printf("THPOOL_DEBUG: Created thread %d in pool \n", n);
#endif
    }

    /* Wait for threads to initialize */
    while (thpool_p->num_threads_alive != num_threads) {
    }

    return thpool_p;
}

/**
 * @brief Add work to the job queue
 *
 * Takes an action and its argument and adds it to the threadpool's job queue.
 * If you want to add to work a function with more than one arguments then
 * a way to implement this is by passing a pointer to a structure.
 *
 * NOTICE: You have to cast both the function and argument to not get warnings.
 *
 * @example
 *
 *    void print_num(int num){
 *       printf("%d\n", num);
 *    }
 *
 *    int main() {
 *       ..
 *       int a = 10;
 *       thpool_add_work(thpool, (void*)print_num, (void*)a);
 *       ..
 *    }
 *
 * @param  threadpool    threadpool to which the work will be added
 * @param  function_p    pointer to function to add as work
 * @param  arg_p         pointer to an argument
 * @return 0 on successs, -1 otherwise.
 */
int thpool_add_work(threadpool thpool_p, void (*function_p)(void*), void* arg_p) {
    job* newjob = 0;

    newjob = (struct job*) malloc(sizeof (struct job));
    if (newjob == NULL) {
        err("thpool_add_work(): Could not allocate memory for new job\n");
        return -1;
    }

    /* add function and argument */
    newjob->function = function_p;
    newjob->arg = arg_p;

    /* add job to queue */
    jobqueue_push(&thpool_p->job_queue, newjob);

    return 0;
}

/**
 * @brief Wait for all queued jobs to finish
 *
 * Will wait for all jobs - both queued and currently running to finish.
 * Once the queue is empty and all work has completed, the calling thread
 * (probably the main program) will continue.
 *
 * Smart polling is used in wait. The polling is initially 0 - meaning that
 * there is virtually no polling at all. If after 1 seconds the threads
 * haven't finished, the polling interval starts growing exponentially
 * untill it reaches max_secs seconds. Then it jumps down to a maximum polling
 * interval assuming that heavy processing is being used in the threadpool.
 *
 * @example
 *
 *    ..
 *    threadpool thpool = thpool_init(4);
 *    ..
 *    // Add a bunch of work
 *    ..
 *    thpool_wait(thpool);
 *    puts("All added work has finished");
 *    ..
 *
 * @param threadpool     the threadpool to wait for
 * @return nothing
 */
void thpool_wait(threadpool thpool_p) {
    pthread_mutex_lock(&thpool_p->thcount_lock);
    while (thpool_p->job_queue.len || thpool_p->num_threads_working) {
        pthread_cond_wait(&thpool_p->threads_all_idle, &thpool_p->thcount_lock);
    }
    pthread_mutex_unlock(&thpool_p->thcount_lock);
}

/**
 * @brief Pauses all threads immediately
 *
 * The threads will be paused no matter if they are idle or working.
 * The threads return to their previous states once thpool_resume
 * is called.
 *
 * While the thread is being paused, new work can be added.
 *
 * @example
 *
 *    threadpool thpool = thpool_init(4);
 *    thpool_pause(thpool);
 *    ..
 *    // Add a bunch of work
 *    ..
 *    thpool_resume(thpool); // Let the threads start their magic
 *
 * @param threadpool    the threadpool where the threads should be paused
 * @return nothing
 */
void thpool_pause(threadpool thpool_p) {
    int n = 0;
    for (n = 0; n < thpool_p->num_threads_alive; n++) {
        pthread_kill(thpool_p->threads[n]->pthread, SIGUSR1);
    }
}

/**
 * @brief Unpauses all threads if they are paused
 *
 * @example
 *    ..
 *    thpool_pause(thpool);
 *    sleep(10);              // Delay execution 10 seconds
 *    thpool_resume(thpool);
 *    ..
 *
 * @param threadpool     the threadpool where the threads should be unpaused
 * @return nothing
 */
void thpool_resume(threadpool thpool_p) {
    // resuming a single threadpool hasn't been
    // implemented yet, meanwhile this supresses
    // the warnings
    (void) thpool_p;

    s_threads_on_hold = 0;
}

/**
 * @brief Destroy the threadpool
 *
 * This will wait for the currently active threads to finish and then 'kill'
 * the whole threadpool to free up memory.
 *
 * @example
 * int main() {
 *    threadpool thpool1 = thpool_init(2);
 *    threadpool thpool2 = thpool_init(2);
 *    ..
 *    thpool_destroy(thpool1);
 *    ..
 *    return 0;
 * }
 *
 * @param threadpool     the threadpool to destroy
 * @return nothing
 */
void thpool_destroy(threadpool thpool_p) {
    /* No need to destory if it's NULL */
    if (thpool_p == NULL) {
        return;
    }
    volatile int threads_total = thpool_p->num_threads_alive;

    /* End each thread 's infinite loop */
    s_threads_keepalive = 0;

    /* Give one second to kill idle threads */
    double timeout = 1.0;
    time_t start = 0;
    time_t end = 0;
    double tpassed = 0.0;
    time(&start);
    while (tpassed < timeout && thpool_p->num_threads_alive) {
        bsem_post_all(thpool_p->job_queue.has_jobs);
        time(&end);
        tpassed = difftime(end, start);
    }

    /* Poll remaining threads */
    while (thpool_p->num_threads_alive) {
        bsem_post_all(thpool_p->job_queue.has_jobs);
        sleep(1);
    }

    /* Job queue cleanup */
    jobqueue_destroy(&thpool_p->job_queue);
    /* Deallocs */
    int n = 0;
    for (n = 0; n < threads_total; n++) {
        thread_destroy(thpool_p->threads[n]);
    }
    free(thpool_p->threads);
    free(thpool_p);
}

/**
 * @brief Show currently working threads
 *
 * Working threads are the threads that are performing work (not idle).
 *
 * @example
 * int main() {
 *    threadpool thpool1 = thpool_init(2);
 *    threadpool thpool2 = thpool_init(2);
 *    ..
 *    printf("Working threads: %d\n", thpool_num_threads_working(thpool1));
 *    ..
 *    return 0;
 * }
 *
 * @param threadpool     the threadpool of interest
 * @return integer       number of threads working
 */
int thpool_num_threads_working(threadpool thpool_p) {
    return thpool_p->num_threads_working;
}

/* Initialize a thread in the thread pool
 *
 * @param thread        address to the pointer of the thread to be created
 * @param id            id to be given to the thread
 * @return 0 on success, -1 otherwise.
 */
int thread_init(thpool_* thpool_p, struct thread** thread_p, int id) {

    *thread_p = (struct thread*) malloc(sizeof (struct thread));
    if (thread_p == NULL) {
        err("thread_init(): Could not allocate memory for thread\n");
        return -1;
    }

    (*thread_p)->thpool_p = thpool_p;
    (*thread_p)->id = id;

    pthread_create(&(*thread_p)->pthread, NULL, (void* (*)(void*))thread_do, (*thread_p));
    pthread_detach((*thread_p)->pthread);
    return 0;
}

/* Sets the calling thread on hold */
void thread_hold(int sig_id) {
    (void) sig_id;
    s_threads_on_hold = 1;
    while (s_threads_on_hold) {
        sleep(1);
    }
}

/* What each thread is doing
 *
 * In principle this is an endless loop. The only time this loop gets interuppted is once
 * thpool_destroy() is invoked or the program exits.
 *
 * @param  thread        thread that will run this function
 * @return nothing
 */
void* thread_do(struct thread* thread_p) {
    /* Set thread name for profiling and debuging */
    char thread_name[128] = {0};
    snprintf(thread_name, sizeof(thread_name), "thread-pool-%d", thread_p->id);

#if defined(__linux__)
    /* Use prctl instead to prevent using _GNU_SOURCE flag and implicit declaration */
    prctl(PR_SET_NAME, thread_name);
#elif defined(__APPLE__) && defined(__MACH__)
    pthread_setname_np(thread_name);
#else
    err("thread_do(): pthread_setname_np is not supported on this system");
#endif

    /* Assure all threads have been created before starting serving */
    thpool_* thpool_p = thread_p->thpool_p;

    /* Register signal handler */
    struct sigaction act;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    act.sa_handler = thread_hold;
    if (sigaction(SIGUSR1, &act, NULL) == -1) {
        err("thread_do(): cannot handle SIGUSR1");
    }

    /* Mark thread as alive (initialized) */
    pthread_mutex_lock(&thpool_p->thcount_lock);
    thpool_p->num_threads_alive += 1;
    pthread_mutex_unlock(&thpool_p->thcount_lock);
    while (s_threads_keepalive) {
        bsem_wait(thpool_p->job_queue.has_jobs);
        if (s_threads_keepalive) {
            pthread_mutex_lock(&thpool_p->thcount_lock);
            thpool_p->num_threads_working++;
            pthread_mutex_unlock(&thpool_p->thcount_lock);
            /* Read job from queue and execute it */
            void (*func_buff)(void*) = 0;
            void* arg_buff = 0;
            job* job_p = jobqueue_pull(&thpool_p->job_queue);
            if (job_p) {
                func_buff = job_p->function;
                arg_buff = job_p->arg;
                func_buff(arg_buff);
                free(job_p);
            }

            pthread_mutex_lock(&thpool_p->thcount_lock);
            thpool_p->num_threads_working--;
            if (!thpool_p->num_threads_working) {
                pthread_cond_signal(&thpool_p->threads_all_idle);
            }
            pthread_mutex_unlock(&thpool_p->thcount_lock);

        }
    }
    pthread_mutex_lock(&thpool_p->thcount_lock);
    thpool_p->num_threads_alive--;
    pthread_mutex_unlock(&thpool_p->thcount_lock);

    return NULL;
}

/* Frees a thread  */
void thread_destroy(thread* thread_p) {
    free(thread_p);
}

/* Initialize queue */
int jobqueue_init(jobqueue* jobqueue_p) {
    jobqueue_p->len = 0;
    jobqueue_p->front = NULL;
    jobqueue_p->rear = NULL;

    jobqueue_p->has_jobs = (struct bsem*) malloc(sizeof (struct bsem));
    if (jobqueue_p->has_jobs == NULL) {
        return -1;
    }

    pthread_mutex_init(&(jobqueue_p->rwmutex), NULL);
    bsem_init(jobqueue_p->has_jobs, 0);

    return 0;
}

/* Clear the queue */
void jobqueue_clear(jobqueue* jobqueue_p) {

    while (jobqueue_p->len) {
        free(jobqueue_pull(jobqueue_p));
    }

    jobqueue_p->front = NULL;
    jobqueue_p->rear = NULL;
    bsem_reset(jobqueue_p->has_jobs);
    jobqueue_p->len = 0;

}

/* Add (allocated) job to queue
 */
void jobqueue_push(jobqueue* jobqueue_p, struct job* newjob) {

    pthread_mutex_lock(&jobqueue_p->rwmutex);
    newjob->prev = NULL;

    switch (jobqueue_p->len) {

        case 0: /* if no jobs in queue */
            jobqueue_p->front = newjob;
            jobqueue_p->rear = newjob;
            break;

        default: /* if jobs in queue */
            jobqueue_p->rear->prev = newjob;
            jobqueue_p->rear = newjob;

    }
    jobqueue_p->len++;

    bsem_post(jobqueue_p->has_jobs);
    pthread_mutex_unlock(&jobqueue_p->rwmutex);
}

/* Get first job from queue(removes it from queue)
<<<<<<< HEAD
 *
 * Notice: Caller MUST hold a mutex
=======
>>>>>>> da2c0fe45e43ce0937f272c8cd2704bdc0afb490
 */
struct job* jobqueue_pull(jobqueue* jobqueue_p) {

    pthread_mutex_lock(&jobqueue_p->rwmutex);
    job* job_p = jobqueue_p->front;

    switch (jobqueue_p->len) {

        case 0: /* if no jobs in queue */
            break;

        case 1: /* if one job in queue */
            jobqueue_p->front = NULL;
            jobqueue_p->rear = NULL;
            jobqueue_p->len = 0;
            break;

        default: /* if >1 jobs in queue */
            jobqueue_p->front = job_p->prev;
            jobqueue_p->len--;
            /* more than one job in queue -> post it */
            bsem_post(jobqueue_p->has_jobs);

    }

    pthread_mutex_unlock(&jobqueue_p->rwmutex);
    return job_p;
}

/* Free all queue resources back to the system */
void jobqueue_destroy(jobqueue* jobqueue_p) {
    jobqueue_clear(jobqueue_p);
    free(jobqueue_p->has_jobs);
}

/* Init semaphore to 1 or 0 */
static void bsem_init(bsem *bsem_p, int value) {
    if (value < 0 || value > 1) {
        err("bsem_init(): Binary semaphore can take only values 1 or 0");
        _Exit(1);
    }
    pthread_mutex_init(&(bsem_p->mutex), NULL);
    pthread_cond_init(&(bsem_p->cond), NULL);
    bsem_p->v = value;
}

/* Reset semaphore to 0 */
static void bsem_reset(bsem *bsem_p) {
    bsem_init(bsem_p, 0);
}

/* Post to at least one thread */
static void bsem_post(bsem *bsem_p) {
    pthread_mutex_lock(&bsem_p->mutex);
    bsem_p->v = 1;
    pthread_cond_signal(&bsem_p->cond);
    pthread_mutex_unlock(&bsem_p->mutex);
}

/* Post to all threads */
static void bsem_post_all(bsem *bsem_p) {
    pthread_mutex_lock(&bsem_p->mutex);
    bsem_p->v = 1;
    pthread_cond_broadcast(&bsem_p->cond);
    pthread_mutex_unlock(&bsem_p->mutex);
}

/* Wait on semaphore until semaphore has value 0 */
static void bsem_wait(bsem* bsem_p) {
    pthread_mutex_lock(&bsem_p->mutex);
    while (bsem_p->v != 1) {
        pthread_cond_wait(&bsem_p->cond, &bsem_p->mutex);
    }
    bsem_p->v = 0;
    pthread_mutex_unlock(&bsem_p->mutex);
}
