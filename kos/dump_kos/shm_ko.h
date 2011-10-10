#ifndef __SHM_KO_H
#define __SHM_KO_H
typedef struct {
    key_t key;
    unsigned long vma;
} shm_reg_t;

enum shm_lck {
    UNLOCKED,
    LOCKED
};

enum ioctl_cmds {
    IOCTL_REG,
    IOCTL_LOCK,
    IOCTL_UNLOCK
};

typedef struct __tident_t {
    pid_t pid;
    struct timespec time;
    struct list_head list;
} tident_t;

typedef struct {
    key_t key;
    tident_t *tident;
    enum shm_lck lock;
    tident_t *wli; //who locked it
    tident_t tident_list;
    struct list_head list;
} sm_ds;

static sm_ds *get_smds(key_t key);
static int list_add_tident(sm_ds *smds);
static int list_add_smds(key_t key);
static int task_mprotect_pid(pid_t pid, unsigned long start, size_t len,
                             unsigned long prot);
static int task_mprotect(struct task_struct *tsk, unsigned long start,
                         size_t len, unsigned long prot);


#endif
