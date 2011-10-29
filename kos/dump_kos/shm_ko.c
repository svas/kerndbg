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
#include <linux/semaphore.h>
#include <asm/page_types.h>

#include "./shm_ko.h"
#include <linux/mm.h>

/* #include <asm/unistd.h> */

MODULE_LICENSE("GPL");

#define DEV_SHM_LOCK_MAJOR 15
#define DEV_SHM_LOCK_MINOR 16

#define DUMP_STACK() ;//{ extern void dump_stack(void); dump_stack();}
#define PRINT_LINE() printk (KERN_INFO "%s:%d", __FUNCTION__, __LINE__)

static spinlock_t sm_ds_lock;

static struct class *shm_lock_class;

static LIST_HEAD(sm_ds_list);

static int open_mem(struct inode * inode, struct file * filp)
{
    return capable(CAP_SYS_RAWIO) ? 0 : -EPERM;
}


static int shm_lock_open(struct inode *inode, struct file *filp)
{
    DUMP_STACK();

    return open_mem(inode, filp);
}

static int shm_lock(sm_ds __user *arg)
{
    int ret = 0;
    shm_lock_t shml;
    sm_ds *smds = NULL;

    printk(KERN_INFO "In lock");

    if(copy_from_user(&shml, arg, sizeof(shm_lock_t)))
        return -EINVAL;

    PRINT_LINE();
    /* Acquire lock to access sm_ds */
    spin_lock(&sm_ds_lock);
    PRINT_LINE();

    /* Check if an array with the key is present */
    smds = get_smds(shml.key);

    if (!smds) {
        printk(KERN_INFO "Inval smds..gona add");
        ret = list_add_smds(shml.key, &smds);
        if (ret != 0 || !smds) {
            PRINT_LINE();
            goto errout;
        }
    }

    /* Next, check if its recursive lock */
    if (smds -> wli.pid  == current->pid &&
        smds->wli.time.tv_sec == current->start_time.tv_sec &&
        smds -> wli.time.tv_nsec == current -> start_time.tv_nsec) {
        printk(KERN_ERR "'Same Task' identity matched.");
        ret = -EINVAL;
        goto errout;
    }

    PRINT_LINE();
    spin_unlock(&sm_ds_lock);

    /* Entry is present.
     * check if its already locked by some other task.
     * Yield and test */
    PRINT_LINE();
    down(&smds->sm_sem);

    spin_lock(&sm_ds_lock);
    /* Update sm_ds struct */
    smds -> lock             = LOCKED;
    smds -> wli.pid          = current->pid;
    smds->wli.time.tv_sec    = current->start_time.tv_sec;
    smds -> wli.time.tv_nsec = current -> start_time.tv_nsec;

    /* Stop all peer tasks AND update PTEs.
     * (Lock the whole shared memory) AND start
     * the tasks. */

    ret = tasks_act(shml.vmaddr, LOCKED);
    if (ret < 0) {
        PRINT_LINE();
        goto errout;
    }

 errout:
    spin_unlock(&sm_ds_lock);
    PRINT_LINE();
   return ret;
}

static int shm_unlock(void *arg)
{

    int ret = 0;
    shm_lock_t shml;
    sm_ds *smds = NULL;

    PRINT_LINE();
    if (copy_from_user(&shml, arg, sizeof(shm_lock_t)))
        return -EINVAL;
    PRINT_LINE();
    /* Acquire lock to access sm_ds */
    spin_lock(&sm_ds_lock);

    PRINT_LINE();
    /* Check if an array with the key is present */
    smds = get_smds(shml.key);

    printk(KERN_INFO "In Unlock");
    if (!smds) {
        printk (KERN_EMERG "Cant find key");
        ret = -EINVAL;
        goto errout;
    }

    /* First, check if its locked */
    if (smds -> lock != LOCKED) {
        printk(KERN_ERR "Not locked.");
        ret = -EINVAL;
        goto errout;
    }

    /* Next, check if its locked by this task.*/
    if (smds -> wli.pid  != current->pid ||
        smds->wli.time.tv_sec != current->start_time.tv_sec ||
        smds -> wli.time.tv_nsec != current -> start_time.tv_nsec) {
        printk(KERN_ERR "Task identity not matched.");
        printk(KERN_INFO "Current- pid : %d tv_sec : %d tv_nsec: %d",
               current->pid, (int) current->start_time.tv_sec,
               (int) current->start_time.tv_nsec);
        printk(KERN_INFO "smds- pid : %d tv_sec : %d tv_nsec: %d",
               (int) smds->wli.pid,
               (int) smds->wli.time.tv_sec,
               (int) smds->wli.time.tv_nsec);
        ret = -EINVAL;
        goto errout;
    }

    /* Stop all peer tasks AND update PTEs.
     * (Unlock the whole shared memory) AND start
     * the tasks. */

    printk(KERN_INFO "Gona update other tasks");
    ret = tasks_act(shml.vmaddr, UNLOCKED);
    if (ret < 0) {
        PRINT_LINE();
        goto errout;
    }

    /* Reset smds */
    smds->lock = UNLOCKED;
    smds->wli.pid = -1;
    smds->wli.time.tv_sec = 0;
    smds->wli.time.tv_nsec = 0;

    spin_unlock(&sm_ds_lock);

    printk(KERN_INFO "Gona update semaphore");

    /* Up the semaphore */
    up(&smds->sm_sem);
    printk(KERN_INFO "Done with unlocking task - pid : %d",
           current->pid);
    return ret;

 errout:
    spin_unlock(&sm_ds_lock);
   return ret;
}

static long shm_lock_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    printk(KERN_INFO "Got ioctl from user");
    switch(cmd) {
    /* case IOCTL_REG: */
    /*     return shm_reg(arg); */
    case IOCTL_LOCK:
        printk(KERN_INFO "Got lock call");
        return shm_lock((void *) arg);
    case IOCTL_UNLOCK:
        printk(KERN_INFO "Got unlock call");
        return shm_unlock((void *) arg);
    default:
        printk(KERN_INFO "undefined lock param");
        return -EINVAL;
    }
    return 0;
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

int __init dev_shm_lock_init(void)
{

	printk(KERN_INFO "**************** In shm_ko init");

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

static __exit void  dev_shm_lock_exit (void)
{
    unregister_chrdev(DEV_SHM_LOCK_MAJOR, "slock");
    device_destroy(shm_lock_class, MKDEV(DEV_SHM_LOCK_MAJOR, DEV_SHM_LOCK_MINOR));
    class_destroy(shm_lock_class);
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

/* Always/Only called from shm_lock context */
static int list_add_smds(key_t key, sm_ds **ret_smds)
{
    int ret = 0;
    sm_ds *smds = NULL;
    smds = kmalloc(sizeof(sm_ds), GFP_KERNEL);
    if (!smds) {
        ret = -ENOMEM;
        goto errout;
    }
    smds -> key              = key;
    sema_init(&smds->sm_sem, 1);
    smds -> lock             = UNLOCKED;
    smds -> wli.pid          = -1;
    smds->wli.time.tv_sec    = 0;
    smds -> wli.time.tv_nsec = 0;

    if (ret_smds)
        *ret_smds = smds;

    list_add_tail(&smds->list, &sm_ds_list);

 errout:
    return ret;
}

/* static int task_mprotect_pid(pid_t pid, unsigned long start, size_t len, */
/*                              unsigned long prot) */
/* { */
/*     int ret = 0; */
/*     struct task_struct *tsk = NULL; */
/*     struct pid *pid_struct = NULL; */

/*     pid_struct = find_get_pid(pid); */
/*     if (!pid_struct) { */
/*         ret = -ESRCH; */
/*         goto errout; */
/*     } */
/*     /\* To map from pid to task_struct *\/ */
/*     tsk = get_pid_task(pid, PIDTYPE_PID); */
/*     if (!tsk) { */
/*         ret = -ESRCH; */
/*         goto errout; */
/*     } */

/*     ret = task_mprotect(tsk, start, len, prot); */

/*  errout: */
/*     return ret; */
/* } */

static int task_mprotect(struct task_struct *tsk, unsigned long start,
                         size_t len, unsigned long prot)
{
	unsigned long vm_flags, nstart, end, tmp;
	struct vm_area_struct *vma, *prev;
	int error = -EINVAL;
	const int grows = prot & (PROT_GROWSDOWN|PROT_GROWSUP);

    DUMP_STACK();

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

        /* Not needed since it a void function */
		/* error = security_file_mprotect(vma, reqprot, prot); */
		/* if (error) */
		/* 	goto out; */

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

static int tasks_act(unsigned long addr, enum shm_lck lck)
{
    int ret = 0;
    struct vm_area_struct *addr_vma = NULL, *other_vma = NULL;
    struct file *addr_file = NULL;
    struct address_space *addr_f_mapping = NULL, *addr_map = NULL;
    struct page *pg = NULL;
    pgoff_t pgoff = 0;
	struct prio_tree_iter iter;
    struct task_struct *other_task = NULL;
    struct pid *other_task_pid = NULL;
    struct mm_struct *other_mm_struct = NULL;

    printk(KERN_INFO "Getting mm read sem");
	down_read(&current->mm->mmap_sem);
    /* Find vma_are_struct object and page struct */
    printk(KERN_INFO "Getting user pages");
    ret = get_user_pages(current, current->mm, addr, 1, 0, 0,
                         &pg, &addr_vma);
    if (ret != 1) {
        PRINT_LINE();
        goto errout2;
    }

    if (!pg || !addr_vma || (addr < addr_vma->vm_start)) {
        PRINT_LINE();
        ret = -EINVAL;
        goto errout2;
    }

    printk(KERN_INFO "Page addr : 0x%x vma addr : 0x%x",
           (unsigned int) pg, (unsigned int) addr_vma);
    pgoff = pg->index << (PAGE_CACHE_SHIFT - PAGE_SHIFT);

    /* Check if its a mapped file */
    addr_file = addr_vma->vm_file;
    if(!addr_file) {
        ret = -EINVAL;
        PRINT_LINE();
        goto errout2;
    }

    printk(KERN_INFO "vm file : 0x%x", (unsigned int) addr_file);

    addr_f_mapping = addr_file->f_mapping;
    if (!addr_f_mapping) {
        ret = -EINVAL;
        PRINT_LINE();
        goto errout2;
    }

    printk(KERN_INFO "addr_map : 0x%x", (unsigned int) addr_map);

    addr_map = pg->mapping;

    if (addr_map != addr_f_mapping) {
        /* Sanity Check */
        ret = -EINVAL;
        PRINT_LINE();
        goto errout2;
    }

    /* Get List of all vma across processes using that has
     * mapped the address */
	spin_lock(&addr_map->i_mmap_lock);
    printk(KERN_INFO "acquired i_mmap_lock. Now iterating list of vmas");
	vma_prio_tree_foreach(other_vma, &iter, &addr_map->i_mmap, pgoff, pgoff)  {
        /* other_vma points to vma_struct obj of one of the processes
         * using the shared address */
        /* owner is rcu..check that */
        printk(KERN_INFO "other vma is 0x%x", (unsigned int)other_vma);
        other_mm_struct = other_vma->vm_mm;
        printk(KERN_INFO "other mm_struct : 0x%x",
               (unsigned int)other_mm_struct);

        other_task = other_mm_struct->owner;

        printk(KERN_INFO "other vma : 0x%x other task : 0x%x "
               "pid : %d", (unsigned int) other_vma,
               (unsigned int) other_task->pid,
               (int) other_task->pid);

        if (other_vma == addr_vma) {
            printk(KERN_INFO "Same task..contn");
            continue;
        }

        /* Stop the task */
        force_sig(SIGSTOP, other_task);
        printk(KERN_INFO "Sent SIGSTOP signal");

        /* /\* Check if the task is stopped *\/ */
        /* if (!task_is_stopped(other_task)) { */
        /*     printk(KERN_ERR "Task (pid %d) could not be stopped", */
        /*            other_task->pid); */
        /* } */

        if (lck == LOCKED) {
            /* mem protect the region for the task */
            /* For now, lets assume that we are mprotecting for one page */
            printk(KERN_INFO "memprotecting the task to RO");
            ret = task_mprotect(other_task, other_vma->vm_start,
                                PAGE_SIZE, PROT_READ);
        } else {
            /* mem protect the region for the task */
            /* For now, lets assume that we are mprotecting for one page */
            printk(KERN_INFO "memprotecting the task to RW");
            ret = task_mprotect(other_task, other_vma->vm_start,
                                PAGE_SIZE, PROT_WRITE);
        }

        if (ret < 0) {
            PRINT_LINE();
            goto errout1;
        }

        /* Start the task */
        force_sig(SIGCONT, other_task);
        printk(KERN_INFO "Sent SIGCONT signal");

        /* /\* Check if the task is started *\/ */
        /* if (other_task->state != 0) { */
        /*     printk(KERN_ERR "Task (pid %d) could not be started", */
        /*            other_task->pid); */
        /* } */

        printk(KERN_INFO "Done with task : 0x%x pid : %d",
               (unsigned int) other_task, (int) other_task->pid);
	}

    printk(KERN_INFO "Done acting on other tasks");

 errout1:
	spin_unlock(&addr_map->i_mmap_lock);
    PRINT_LINE();
 errout2:
	up_read(&current->mm->mmap_sem);
    PRINT_LINE();
    return ret;
}

module_init(dev_shm_lock_init);
module_exit(dev_shm_lock_exit);

