#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>

#define SHMSZ 4096

typedef struct {
    key_t key;
    unsigned long vma;
    size_t len;
} shm_lock_t;

enum ioctl_cmds {
    IOCTL_REG,
    IOCTL_LOCK,
    IOCTL_UNLOCK
};

int dev_fd;
key_t key;
char *shm;

int open_dev();
int shm_cmd(unsigned long vma, key_t key, int cmd);
void sigint_handler(int signal);

int main(int argc, char **argv)
{
    char c, tmp;
    int shmid;
    char *s;
    pid_t pid = 0;

    pid = getpid();

    printf("own pid is %d", pid);

    signal(SIGINT, sigint_handler);
    open_dev();
    /*
     * Shared memory segment at 1234
     * "1234".
     */
    key = 1234;

    /*
     * Create the segment and set permissions.
     */
    if ((shmid = shmget(key, SHMSZ, IPC_CREAT | 0666)) < 0) {
        perror("shmget");
        return 1;
    }

    /*
     * Now we attach the segment to our data space.
     */
    if ((shm = shmat(shmid, NULL, 0)) == (char *) -1) {
        perror("shmat");
        return 1;
    }

    /*
     * Zero out memory segment
     */
    memset(shm,0,SHMSZ);
    s = shm;

    if (shm_cmd((unsigned long)shm, key, IOCTL_LOCK) < 0) {
        goto errout;
    }

    /* /\* */
    /*  * Read user input from client code and tell */
    /*  * the user what was written. */
    /*  *\/ */
    /* while (*shm != 'q'){ */
    /*     sleep(1); */
    /*     if(tmp == *shm) */
    /*         continue; */

    /*     fprintf(stdout, "You pressed %c\n",*shm); */
    /*     tmp = *shm; */
    /* } */

    /* if(shmdt(shm) != 0) */
    /*     fprintf(stderr, "Could not close memory segment.\n"); */

    /* Busy loop */

    /* Unlock */
    /* if (shm_cmd((unsigned long)shm, key, IOCTL_UNLOCK) < 0) { */
    /*     goto errout; */
    /* } */

    while(1);

 errout:
    close(dev_fd);
    return 0;
}

int open_dev()
{
    shm_lock_t shml;
    int fd = 0;
    char *p = NULL;
    fd = open("/dev/shm_lock", O_RDWR);
    if (fd < 0) {
        perror ("shm_lock");
        return -1;
    }
    dev_fd = fd;
    return 0;
}

int shm_cmd(unsigned long vma, key_t key, int cmd)
{
    shm_lock_t shml;
    shml.vma = vma;
    shml.key = key;
    shml.len = 4096;
    if (ioctl(dev_fd, cmd, &shml) < 0) {
        perror("ioctl lock");
        return -1;
    }

    return 0;
}

void sigint_handler(int signal)
{
    printf("Received signal : %d\n", signal);
    printf("Gona unlock....\n");

    if (shm_cmd((unsigned long)shm, key, IOCTL_UNLOCK) < 0) {
        printf("Error executing unlock ioctl\n");
    }
    exit(signal);
}
