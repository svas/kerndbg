#ifndef __SHM_KO_H
#define __SHM_KO_H

typedef struct {
    key_t key;
    unsigned long vmaddr;
    size_t len;
} shm_lock_t;

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
} tident_t;

typedef struct {
    key_t key;
    enum shm_lck lock;
    struct semaphore sm_sem;
    tident_t wli; //who locked it
    struct list_head list;
} sm_ds;

static sm_ds *get_smds(key_t key);
static int list_add_smds(key_t key, sm_ds **ret_smds);
/* static int task_mprotect_pid(pid_t pid, unsigned long start, size_t len, */
/*                              unsigned long prot); */
static int task_mprotect(struct task_struct *tsk, unsigned long start,
                         size_t len, unsigned long prot);

static int tasks_act(unsigned long addr, enum shm_lck lck);
static int task_mprotect(struct task_struct *tsk, unsigned long start,
                         size_t len, unsigned long prot);

/* extern struct vm_area_struct *vma_prio_tree_next(struct vm_area_struct *vma, */
/*                                                  struct prio_tree_iter *iter); */

#endif
