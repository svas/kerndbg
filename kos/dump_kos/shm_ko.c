#define EXPORT_SYMTAB
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci_ids.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <linux/wait.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <asm/atomic.h>
#include <linux/kallsyms.h>
#include <linux/spinlock.h>
#include <linux/mount.h>
#include <linux/vfs.h>

#include <asm/uaccess.h>
#include <linux/fs.h>
#include <linux/personality.h>
#include <linux/pagemap.h>
#include <linux/syscalls.h>
#include <linux/rcupdate.h>
#include <linux/device.h>
#include <linux/major.h>
#include <linux/cdev.h>
#include <linux/list.h>
#include <linux/mman.h>

#include "./shm_ko.h"
/* #include <asm/unistd.h> */

MODULE_LICENSE("GPL");

#define DEV_SHM_LOCK_MAJOR 15
#define DEV_SHM_LOCK_MINOR 16

#define DUMP_STACK() { extern void dump_stack(); dump_stack();}

static spinlock_t sm_ds_lock;

static struct class *shm_lock_class;

static LIST_HEAD(sm_ds_list);

static int open_mem(struct inode * inode, struct file * filp)
{
    return capable(CAP_SYS_RAWIO) ? 0 : -EPERM;
}


static int shm_lock_open(struct inode *inode, struct file *filp)
{
    int minor;
    const struct memdev *dev;

    DUMP_STACK();

    return open_mem(inode, filp);
}

static int shm_reg(void *arg)
{
    int ret = 0;
    key_t key;
    sm_ds *smds = NULL;
    shm_reg_t shm_reg;

    copy_from_user(&shm_reg, arg, sizeof(shm_reg_t));

    /* Acquire lock to access sm_ds */
    spin_lock(&sm_ds_lock);

    /* Check if an try with the key is present */
    smds = get_smds(key);

    if (!smds) {
        ret = list_add_smds(shm_reg.key);
        if (ret != 0)
            goto errout;
    }

    /* Entry is present */
    /* check if its already locked */
    if (smds) {
        /* Check if the shared memory is already locked.
         * If yes, then make the whole shared memory RO */
        if (smds -> lock == LOCKED) {
            /* Lock the whole shared memory */
            /* TODO */
        }
        ret = list_add_tident(smds);
    }

errout:
        spin_unlock(&sm_ds_lock);
    return ret;
}

static int shm_lock(void *arg)
{

    return 0;
}

static int shm_unlock(void *arg)
{

    return 0;
}

static long shm_lock_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    DUMP_STACK();
    switch(cmd) {
    case IOCTL_REG:
        return shm_reg(arg);
    case IOCTL_LOCK:
        return shm_lock(arg);
    case IOCTL_UNLOCK:
        return shm_unlock(arg);
    default:
        return -EINVAL;
    }
    return 1;
}

static const struct file_operations shm_lock_fops = {
    .open = shm_lock_open,
    .unlocked_ioctl = shm_lock_ioctl,
    .llseek = noop_llseek,
};

static char *mem_devnode(struct device *dev, mode_t *mode)
{
	if (mode)
		*mode = 0;
	return NULL;
}

static int __init dev_shm_lock_init(void)
{
	int minor;
	int err;


	if (register_chrdev(DEV_SHM_LOCK_MAJOR, "slock", &shm_lock_fops))
		printk("unable to get major %d for memory devs\n", DEV_SHM_LOCK_MAJOR);

	shm_lock_class = class_create(THIS_MODULE, "slock");
	if (IS_ERR(shm_lock_class))
		return PTR_ERR(shm_lock_class);

	shm_lock_class->devnode = mem_devnode;
	if (!device_create(shm_lock_class, NULL, MKDEV(DEV_SHM_LOCK_MAJOR, DEV_SHM_LOCK_MINOR),
                       NULL, "shm_lock")) {
        printk(KERN_INFO "Error in shm_lock class create");
    }

    /* Init sm_ds spink lock */
    spin_lock_init(&sm_ds_lock);
    return 0;
}

static __exit dev_shm_lock_exit (void)
{
    device_destroy(shm_lock_class, MKDEV(DEV_SHM_LOCK_MAJOR, DEV_SHM_LOCK_MINOR));
    return 0;
}

static sm_ds *get_smds(key_t key)
{
    struct list_head *p;
    sm_ds *smds;
    list_for_each(p, &sm_ds_list) {
        smds = list_entry(p, sm_ds, list);
        if (smds -> key == key) {
            return smds;
        }
    }
    return NULL;
}

static int list_add_smds(key_t key)
{
    int ret = 0;
    sm_ds *smds = NULL;
    tident_t *tmp = NULL;
    smds = kmalloc(sizeof(sm_ds), GFP_KERNEL);
    if (!smds) {
        ret = -ENOMEM;
        goto errout;
    }
    smds -> key = key;
    smds -> lock = UNLOCKED;
    smds -> wli = NULL;
    INIT_LIST_HEAD(&(smds -> tident_list.list));
    ret = list_add_tident(smds);
    if (ret != 0)
        goto errout;
    list_add_tail(smds, &sm_ds_list);

 errout:
    return ret;
}

static int list_add_tident(sm_ds *smds)
{
    int ret = 0;
    tident_t *tmp = NULL;
    tmp = kmalloc(sizeof(tident_t), GFP_KERNEL);
    if (!tmp) {
        ret = -ENOMEM;
        goto errout;
    }
    /* Add tident_t entry */
    tmp -> pid = current -> pid;
    tmp -> time.tv_sec = current -> start_time.tv_sec;
    tmp -> time.tv_nsec = current -> start_time.tv_nsec;
    list_add_tail(tmp, &smds -> tident_list);

 errout:
    return ret;
}

static int task_mprotect_pid(pid_t pid, unsigned long start, size_t len,
                             unsigned long prot)
{
    int ret = 0;
    struct task_struct *tsk = NULL;
    struct pid *pid_struct = NULL;

    pid_struct = find_get_pid(pid);
    if (!pid_struct) {
        ret = -ESRCH;
        goto errout;
    }
    /* To map from pid to task_struct */
    tsk = get_pid_task(pid, PIDTYPE_PID);
    if (!tsk) {
        ret = -ESRCH;
        goto errout;
    }

    ret = task_mprotect(tsk, start, len, prot);

 errout:
    return ret;
}

static int task_mprotect(struct task_struct *tsk, unsigned long start,
                         size_t len, unsigned long prot)
{
	unsigned long vm_flags, nstart, end, tmp, reqprot;
	struct vm_area_struct *vma, *prev;
	int error = -EINVAL;
	const int grows = prot & (PROT_GROWSDOWN|PROT_GROWSUP);
	prot &= ~(PROT_GROWSDOWN|PROT_GROWSUP);
	if (grows == (PROT_GROWSDOWN|PROT_GROWSUP)) /* can't be both */
		return -EINVAL;

	if (start & ~PAGE_MASK)
		return -EINVAL;
	if (!len)
		return 0;
	len = PAGE_ALIGN(len);
	end = start + len;
	if (end <= start)
		return -ENOMEM;
	if (!arch_validate_prot(prot))
		return -EINVAL;

	reqprot = prot;
	/*
	 * Does the application expect PROT_READ to imply PROT_EXEC:
	 */
	if ((prot & PROT_READ) && (tsk->personality & READ_IMPLIES_EXEC))
		prot |= PROT_EXEC;

	vm_flags = calc_vm_prot_bits(prot);

	down_write(&tsk->mm->mmap_sem);

	vma = find_vma_prev(tsk->mm, start, &prev);
	error = -ENOMEM;
	if (!vma)
		goto out;
	if (unlikely(grows & PROT_GROWSDOWN)) {
		if (vma->vm_start >= end)
			goto out;
		start = vma->vm_start;
		error = -EINVAL;
		if (!(vma->vm_flags & VM_GROWSDOWN))
			goto out;
	}
	else {
		if (vma->vm_start > start)
			goto out;
		if (unlikely(grows & PROT_GROWSUP)) {
			end = vma->vm_end;
			error = -EINVAL;
			if (!(vma->vm_flags & VM_GROWSUP))
				goto out;
		}
	}
	if (start > vma->vm_start)
		prev = vma;

	for (nstart = start ; ; ) {
		unsigned long newflags;

		/* Here we know that  vma->vm_start <= nstart < vma->vm_end. */

		newflags = vm_flags | (vma->vm_flags & ~(VM_READ | VM_WRITE | VM_EXEC));

		/* newflags >> 4 shift VM_MAY% in place of VM_% */
		if ((newflags & ~(newflags >> 4)) & (VM_READ | VM_WRITE | VM_EXEC)) {
			error = -EACCES;
			goto out;
		}

		error = security_file_mprotect(vma, reqprot, prot);
		if (error)
			goto out;

		tmp = vma->vm_end;
		if (tmp > end)
			tmp = end;
		error = mprotect_fixup(vma, &prev, nstart, tmp, newflags);
		if (error)
			goto out;
		nstart = tmp;

		if (nstart < prev->vm_end)
			nstart = prev->vm_end;
		if (nstart >= end)
			goto out;

		vma = prev->vm_next;
		if (!vma || vma->vm_start != nstart) {
			error = -ENOMEM;
			goto out;
		}
	}
out:
	up_write(&tsk->mm->mmap_sem);
	return error;
}

module_init(dev_shm_lock_init);
module_exit(dev_shm_lock_exit);
