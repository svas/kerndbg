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

int test_kern_func()
{
    DUMP_STACK();
    PRINT_LINE();
    return 0;
}
EXPORT_SYMBOL(test_kern_func);

static long shm_lock_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    DUMP_STACK();
    test_kern_func();
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

module_init(dev_shm_lock_init);
module_exit(dev_shm_lock_exit);

