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

/* #include <asm/unistd.h> */


MODULE_LICENSE("GPL");

#define DEV_MMAP_MINOR 15
#define DEV_MMAP_MAJOR 16

#define DUMP_STACK() { extern void dump_stack(); dump_stack();}

static struct class *mem_class;

char *skbuff_user;

/* This is just a random max size, need to figure out the correct size */
#define MAX_SKU_SIZE (4096)

char *sku_data;

#if 0
void __you_cannot_kmalloc_that_much()
{
}
#endif

static int open_mem(struct inode * inode, struct file * filp)
{
    return capable(CAP_SYS_RAWIO) ? 0 : -EPERM;
}

static int skbuff_user_mmap (struct file * file, struct vm_area_struct * vma);
static const struct file_operations skbuff_user_fops = {
    .mmap       = skbuff_user_mmap,
    .open       = open_mem,
};

static const struct vm_operations_struct mmap_mem_ops = {
#ifdef CONFIG_HAVE_IOREMAP_PROT
    .access = NULL
#endif
};

#ifndef CONFIG_MMU
static unsigned long get_unmapped_area_mem(struct file *file,
                                           unsigned long addr,
                                           unsigned long len,
                                           unsigned long pgoff,
                                           unsigned long flags)
{
    if (!valid_mmap_phys_addr_range(pgoff, len))
        return (unsigned long) -EINVAL;
    return pgoff << PAGE_SHIFT;
}

/* can't do an in-place private mapping if there's no MMU */
static inline int private_mapping_ok(struct vm_area_struct *vma)
{
    return vma->vm_flags & VM_MAYSHARE;
}
#else
#define get_unmapped_area_mem	NULL

static inline int private_mapping_ok(struct vm_area_struct *vma)
{
    return 1;
}
#endif

static int memory_open(struct inode *inode, struct file *filp)
{
    int minor;
    const struct memdev *dev;

    DUMP_STACK();

    filp->f_op = &skbuff_user_fops;
    filp->f_mapping->backing_dev_info = &directly_mappable_cdev_bdi;
    filp->f_mode |= FMODE_UNSIGNED_OFFSET;

    return open_mem(inode, filp);
}

static int skbuff_user_mmap (struct file * file, struct vm_area_struct * vma)
{
	int i, ret = 0;
	struct page *pg;
	size_t size = vma->vm_end - vma->vm_start;
	unsigned long pfn;

    DUMP_STACK();

	if (!skbuff_user)
		skbuff_user = kmalloc (MAX_SKU_SIZE, GFP_KERNEL);
	if (!sku_data)
		sku_data   = kmalloc (MAX_SKU_SIZE, GFP_KERNEL | GFP_ATOMIC);

	if (!skbuff_user || !sku_data) {
		printk (KERN_INFO "mith: vmalloc failure for skbuf_user\n");
		ret = -ENOMEM;
		goto out;
	}

	vma->vm_page_prot = PAGE_SHARED;
	/* Get the physical address from the kernel virtual address and use PAGE_SHIFT to get the PFN */
	pfn = __pa((u32) skbuff_user) >> PAGE_SHIFT;

	vma->vm_flags |= VM_IO | VM_USERMAP | VM_RESERVED | VM_WRITE;

	printk (KERN_INFO "mith: pfn = 0x%lx skbuff_user = 0x%lx phy_addr = 0x%lx\n", pfn, (unsigned long) skbuff_user, __pa((u32) skbuff_user));
    printk (KERN_INFO "mith: VMA size = %d, start = 0x%x\n", size, vma->vm_start);

#if 0
	if (wich_receive_addr != ~0) {
		vma->vm_pgoff = wich_receive_addr >> PAGE_SHIFT;
		printk (KERN_INFO "mith: In skbuff_user_mmap: recv addr = 0x%lx\n", wich_receive_addr);
	}
#endif
	if (!private_mapping_ok (vma)) {
		ret = -ENOSYS;
		goto out;
	}

	vma->vm_ops = &mmap_mem_ops;
	vma->vm_pgoff = pfn;

	/* vma is figured out by the caller of this function which is sys_mmap ().
	   Given the current task`s page table info, a virtually contiguous area is figured out
           by the find_vma () function and is passed onto us. We only need to map these
           virtual addresses to actual physical pages.
	*/
	if (remap_pfn_range (vma, vma->vm_start, pfn, size, vma->vm_page_prot)) {
		//unmap_devmem(pfn, size, vma->vm_page_prot);
		ret = -EAGAIN;
		goto out;
	}
#if 0
	for (i = 0; i < 4096; i += 4) {
		printk (KERN_INFO "%d ", *(unsigned int *) (__va((u32) wich_receive_addr) + i));
	}
#endif
	for (i = 0; i < 4096; i += 4) {
		//printk (KERN_INFO "%d ", *(unsigned int *) (__va((u64) skbuff_user) + i));
		*(unsigned int *) ((u32) skbuff_user + i) = 0xfeedface;
	}
out:
	if (ret < 0) {
		if (skbuff_user)
			kfree (skbuff_user);
		if (sku_data)
			kfree (sku_data);
	}
	return ret;
}

static const struct file_operations memory_fops = {
    .open = memory_open,
    .llseek = noop_llseek,
};

static char *mem_devnode(struct device *dev, mode_t *mode)
{
	if (mode)
		*mode = 0;
	return NULL;
}

static int __init dev_mmap_init(void)
{
	int minor;
	int err;


	if (register_chrdev(DEV_MMAP_MAJOR, "mem2", &memory_fops))
		printk("unable to get major %d for memory devs\n", DEV_MMAP_MAJOR);

	mem_class = class_create(THIS_MODULE, "mem2");
	if (IS_ERR(mem_class))
		return PTR_ERR(mem_class);

	mem_class->devnode = mem_devnode;
	if (!device_create(mem_class, NULL, MKDEV(DEV_MMAP_MAJOR, DEV_MMAP_MINOR),
                       NULL, "skbuff_user1")) {
        printk(KERN_INFO "Error in dev_mmap class create");
    }

    return 0;
}

static __exit dev_mmap_exit (void)
{
    device_destroy(mem_class, MKDEV(DEV_MMAP_MAJOR, DEV_MMAP_MINOR));
    return 0;
}

module_init(dev_mmap_init);
module_exit(dev_mmap_exit);
