#define _GNU_SOURCE
#include <sched.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>


#define handle_error_en(en, msg) \
           do { errno = en; perror(msg); exit(EXIT_FAILURE); } while (0)

#define THREAD_COUNT (3)
typedef struct _THREAD_DATA
{
    int id;
    void* buffer;
} THREAD_DATA;


void *thread_run(void *argp)
{
    static int s = 0;
    int count = 30;
    THREAD_DATA *data = (THREAD_DATA*)argp;
    char *val = data->buffer;

    sleep(1);

    while (count > 0)
    {
        printf("Thread ID: %u, Count: %d, Static: %d, val: %d\n", pthread_self(), data->id, ++s, *val);
        count--;
        sleep(5);
    }
    return NULL;
}

int main()
{
    pthread_t tid;
    int i, s, count;
    cpu_set_t *cpuset = NULL;
    pthread_attr_t attr;
    size_t size;
    THREAD_DATA *data[THREAD_COUNT];
    char *buffer_ptr[THREAD_COUNT];

    printf("starting main\n");
    for (i = 0; i < THREAD_COUNT; i++)
    {
        s = pthread_attr_init(&attr);
        if (s != 0)
            handle_error_en(s, "pthread_attr_init");

        cpuset = CPU_ALLOC(32);
        size = CPU_ALLOC_SIZE(32);
        CPU_ZERO_S(size, cpuset);
        CPU_SET(2 + i, cpuset);
        s = pthread_attr_setaffinity_np(&attr, sizeof(cpuset), cpuset);
        CPU_FREE(cpuset);
        if (s != 0)
            handle_error_en(s, "pthread_attr_setaffinity_np");

        data[i] = malloc(sizeof(THREAD_DATA));
        data[i]->id = i;
        data[i]->buffer = malloc(sizeof(char));
        *(char*)data[i]->buffer = 11;
        pthread_create(&tid, &attr, thread_run, (void *)data[i]);
        printf("Created thread with id %u\n", tid);

        pthread_attr_destroy(&attr);
    }

    count = 30;
    while (count > 0)
    {
        for (i = 0; i < THREAD_COUNT; i++)
        {
            *(char*)data[i]->buffer = count + i;
        }
        count--;
        sleep(5);
    }

    pthread_exit(NULL);
    for (i = 0; i < THREAD_COUNT; i++)
    {
        free(data[i]->buffer);
        free(data[i]);
    }
    printf("closing main\n");
    return 0;
}
