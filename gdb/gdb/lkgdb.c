#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include "lkgdb.h"

int dev_lkgdb_fd = -1;
unsigned int lkgdb_cmd;
static void *lkgdb_kwork (void*);
static pthread_mutex_t lkgdb_lock;
static pthread_cond_t lkgdb_cond;

int lkgdb_init()
{
    pthread_t lkgdb_tid;
    /* Open the lkgdb device */
    dev_lkgdb_fd = open_dev();
    if (dev_lkgdb_fd < 0) {
        return -1;
    }
    /* Create the lkgdb thread */
    if (pthread_create(&lkgdb_tid, NULL, lkgdb_kwork, NULL) < 0)
        return -1;

    return 0;
}

int open_dev()
{
    int fd = 0;
    fd = open("/dev/lkgdb", O_RDWR);
    if (fd < 0) {
        perror ("lkgdb");
        return -1;
    }
    return fd;
}

static void *lkgdb_kwork (void *)
{
start_lkgdb:
    lkgdb_wait ();
    switch (lkgdb_cmd) {
    case SYSCALL_STEPI:
        break;
    default:
        break;
    }

    goto start_lkgdb;
}

void lkgdb_wait ()
{
    /* thread code blocks here until signalled by gdb main thread */
    pthread_mutex_lock(&lkgdb_lock);
    pthread_cond_wait(&lkgdb_cond, &lkgdb_lock);

    pthread_mutex_unlock(&lkgdb_lock);
    /* proceed with thread execution */
}

/* some other thread code that signals a waiting thread that MAX_COUNT has been reached */
void lkgdb_wakeup(unsigned int cmd)
{
    lkgdb_cmd = cmd;
    pthread_cond_signal(&lkgdb_cond);
}
