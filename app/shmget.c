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
#include <curses.h>

#define SHMSZ 4096

typedef struct {
    key_t key;
    unsigned long vma;
    size_t len;
} shm_lock_t;

enum ioctl_cmds {
    IOCTL_UNLOCK,
    IOCTL_LOCK,
    IOCTL_MPROTECT_TEST
};

key_t key;
char *shm;

int open_dev();
int shm_cmd(unsigned long vma, key_t key, int cmd);
/* void sigint_handler(int signal); */
int lock(unsigned long addr, key_t key);
int unlock(unsigned long addr, key_t key);
int task_mprotect(unsigned long addr, key_t key);
int write_shmem(unsigned long addr, size_t len);

int main(int argc, char **argv)
{
    char c, tmp;
    int shmid;
    pid_t pid = 0;

    pid = getpid();

    printf("own pid is %d", pid);

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

 get_usr_char:
    printf("Enter 'l' to lock; \n'u' to unlock; \n'w' to write to shmem; \n'm' to test mprotect\n");
    c = getchar();
    printf("entered character is %c\n", c);
    switch (c) {
    case 'l':
        printf("Received character 'l'");
        lock((unsigned long)shm, key);
        goto get_usr_char;
    case 'u':
        printf("Received character 'u'");
        unlock((unsigned long)shm, key);
        goto get_usr_char;
    case 'w':
        printf("Received character 'w'");
        write_shmem((unsigned long)shm, 1);
        goto get_usr_char;
    case 'm':
        printf("Received character 'm'");
        task_mprotect((unsigned long)shm, key);
        goto get_usr_char;
    default:
        printf("Are you sure to quit? Type 'Y'\n");
        c = getchar();
        if (c == 'Y')
            goto errout;
        else
            goto get_usr_char;
    }


 errout:
    printf("Closing the app....\n");
    return 0;
}

int lock(unsigned long addr, key_t key)
{
    int ret = 0;

    if (shm_cmd(addr, key, IOCTL_LOCK) < 0) {
        printf("Error executing lock ioctl\n");
        ret = -1;
        goto errout;
    }

 errout:
    return ret;
}

int unlock(unsigned long addr, key_t key)
{
    int ret = 0;

    printf("Gona unlock....\n");

    if (shm_cmd(addr, key, IOCTL_UNLOCK) < 0) {
        printf("Error executing unlock ioctl\n");
        ret = -1;
    }
 errout:
    return ret;
}

int task_mprotect(unsigned long addr, key_t key)
{
    int ret = 0;

    printf("In task mprotect\n");
    if (shm_cmd(addr, key, IOCTL_MPROTECT_TEST) < 0) {
        printf("Error executing mprotect ioctl\n");
        ret = -1;
        goto errout;
    }

    printf("Executed mprotect ioctl\n");

 errout:
    return ret;
}

int write_shmem(unsigned long addr, size_t len)
{
    int ret = 0;

    printf("In write_shmem\n");
    printf("now would try to write of len %u to 0x%x\n",
           len, (unsigned int)addr);
    memcpy((void *)addr, "A", 1);

 errout:
    return ret;
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
    return fd;
}

int shm_cmd(unsigned long vma, key_t key, int cmd)
{
    shm_lock_t shml;
    int ret = 0, fd = 0;

    printf("Received 'cmd' : %d", cmd);

    printf("Opening device file\n");
    fd = open_dev();

    shml.vma = vma;
    shml.key = key;
    shml.len = 4096;

    printf("Sending ioctl\n");
    if (ioctl(fd, cmd, &shml) < 0) {
        perror("ioctl lock");
        ret = -1;
        goto errout;
    }

 errout:
    printf("Closing the dev_fd file\n");
    close(fd);
    return ret;
}

/* void sigint_handler(int signal) */
/* { */
/*     printf("Received signal : %d\n", signal); */
/*     printf("Gona unlock....\n"); */

/*     if (shm_cmd((unsigned long)shm, key, IOCTL_UNLOCK) < 0) { */
/*         printf("Error executing unlock ioctl\n"); */
/*     } */
/*     exit(signal); */
/* } */
