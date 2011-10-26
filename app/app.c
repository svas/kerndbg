#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>

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

int main() {
    shm_lock_t shml;
    int fd = 0;
    char *p = NULL;
    fd = open("/dev/shm_lock", O_RDWR);
    if (fd < 0) {
        perror ("shm_lock");
        return -1;
    }

    p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (!p)
        perror("cant mmap");
    shml.vma = p;
    shml.len = 4096;
    if (ioctl(fd, IOCTL_LOCK, &shml) < 0) {
        perror("ioctl lock");
        goto errout;
    }

    *p = 'A';
 errout:
    close(fd);
    return 0;
}
