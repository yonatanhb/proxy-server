#include <stdio.h>
#include <stdlib.h>
#include "threadpool.h"
#include <unistd.h>

threadpool* create_threadpool(int num_threads_in_pool){
    if(num_threads_in_pool <= 0 || num_threads_in_pool > MAXT_IN_POOL)
        return NULL;

    threadpool* pool = (threadpool*) malloc(sizeof (threadpool));
    if(pool == NULL) {
        perror("error: malloc\n");
        return NULL;
    }

    pool->num_threads = num_threads_in_pool;
    pool->qsize = 0;
    pool->threads = (pthread_t*)malloc(num_threads_in_pool * sizeof(pthread_t));
    if(pool->threads == NULL){
        perror("error: malloc\n");
        free(pool);
        return NULL;
    }
    pool->qhead = pool->qtail = NULL;
    pthread_mutex_init(&(pool->qlock),NULL);
    pthread_cond_init(&(pool->q_not_empty),NULL);
    pthread_cond_init(&(pool->q_empty),NULL);
    pool->shutdown = 0;
    pool->dont_accept = 0;

    for(int i = 0; i < num_threads_in_pool; i++) {
        if(pthread_create(&(pool->threads[i]),NULL, do_work, (void*)pool) != 0) {
            perror("error: pthread_create\n");
            destroy_threadpool(pool);
            return NULL;
        }
    }

    return pool;
}

void dispatch(threadpool* from_me, dispatch_fn dispatch_to_here, void *arg) {

    pthread_mutex_lock(&(from_me->qlock));
    if(from_me->dont_accept) {
        pthread_mutex_unlock(&(from_me->qlock));
        return;
    }
    pthread_mutex_unlock(&(from_me->qlock));

    work_t* work = (work_t*)malloc(sizeof (work_t ));
    if(work == NULL) {
        perror("error: malloc\n");
        pthread_exit(NULL);
    }
    work->routine = dispatch_to_here;
    work->arg = arg;
    work->next = NULL;

    pthread_mutex_lock(&(from_me->qlock));
    if(from_me->qhead == NULL) {
        from_me->qhead = from_me->qtail = work;
    } else {
        from_me->qtail->next = work;
        from_me->qtail = work;
    }
    from_me->qsize++;
    pthread_cond_signal(&(from_me->q_not_empty));

    pthread_mutex_unlock(&(from_me->qlock));
}

void* do_work(void* p) {
    threadpool* pool = (threadpool*)p;

    while(1) {
        pthread_mutex_lock(&(pool->qlock));
        while (pool->qsize == 0 && !pool->shutdown) {
            pthread_cond_wait(&(pool->q_not_empty), &(pool->qlock));
        }

        if (pool->shutdown) {
            pthread_mutex_unlock(&(pool->qlock));
            pthread_exit(NULL);
        }

        work_t* work = pool->qhead;
        pool->qhead = pool->qhead->next;
        if (pool->qhead == NULL) {
            pool->qtail = NULL;
        }
        pool->qsize--;

        if(pool->dont_accept && pool->qsize == 0)
            pthread_cond_signal(&(pool->q_empty));
        pthread_mutex_unlock(&(pool->qlock));

        (*(work->routine))(work->arg);

        free(work);
    }
}

void destroy_threadpool(threadpool* destroyme) {

    pthread_mutex_lock(&(destroyme->qlock));
    destroyme->dont_accept = 1;

    if (destroyme->qsize > 0) {

        pthread_cond_wait(&(destroyme->q_empty), &(destroyme->qlock));
    }
    destroyme->shutdown = 1;

    pthread_cond_broadcast(&(destroyme->q_not_empty));

    pthread_mutex_unlock(&(destroyme->qlock));
    for (int i = 0; i < destroyme->num_threads; i++) {
        pthread_join(destroyme->threads[i], NULL);
    }

    free(destroyme->threads);
    free(destroyme);
}

