/* Enable pr_debug() DYNAMIC_DEBUG is disabled */
#define pr_fmt(fmt) "%s:%s: " fmt, KBUILD_MODNAME, __func__
#define DEBUG 1

#define __E(fmt, args...) ({if(klogger_debug) pr_err("E[%3d:%s()]" fmt, __LINE__, __FUNCTION__, ## args);})
#define __I(fmt, args...) ({if(klogger_debug) pr_info("I[%3d:%s()]" fmt, __LINE__, __FUNCTION__, ## args);})
#define __D(fmt, args...) ({if(klogger_debug) pr_info("D[%3d:%s()]" fmt, __LINE__, __FUNCTION__, ## args);})

#ifdef MODVERSIONS
#include <linux/modversions.h>
#endif

#include <linux/version.h>
#include <generated/autoconf.h>

#include <linux/stddef.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/workqueue.h>
#include <linux/wait.h>
#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/poll.h>
#include <linux/spinlock.h>
#include <linux/sched/signal.h>
#include <linux/uaccess.h>

#define DEVICE_NAME "klogger"
#define MA MAJOR(this->dev_id)
#define EMPTY_OFFSET(knode) ((knode)->offset + QLEN(knode))
#define QLEN(knode) ( (knode)->write_point >= (knode)->read_point ?     \
                      (knode)->write_point - (knode)->read_point :      \
                      (knode)->size - (knode)->read_point + (knode)->write_point)

typedef struct klogger_inode {

    unsigned long     i_ino;  //inode id
    dev_t             i_rdev; //mi
    wait_queue_head_t reader_wq;
    char             *data;
    size_t            size;
    int               refcount;
    size_t            read_point;
    size_t            write_point;
    loff_t            offset;
    rwlock_t          rwlock;

    struct klogger_inode *next;
} knode_t;


typedef struct klogger {
    const char *dev_name;
    dev_t dev_id;
    unsigned baseminor;
    unsigned nr_minor;
    struct cdev *cdev;
    struct class *cls;
    struct device *device;
    knode_t *list;
} klogger_t;
static klogger_t klogger = {
    .dev_name  = DEVICE_NAME,
    .dev_id    = 0,
    .baseminor = 1,
    .cdev      = NULL,
    .cls       = NULL,
    .device    = NULL,
    .list      = NULL,
}, *this = &klogger;


static bool klogger_debug;
static int  klogger_max_size = 10*1024;
module_param(klogger_debug,    bool, 0644);
module_param(klogger_max_size,  int, 0444);


static knode_t *get_knode(const struct inode *inode)
{
    knode_t *knode;

    if(inode == NULL)
        return NULL;

    for(knode = this->list; knode != NULL; knode = knode->next) {
        if(knode->i_ino  == inode->i_ino &&
            knode->i_rdev == inode->i_rdev) {
            return knode;
        }
    }

    return NULL;
}

static knode_t * create_knode(const struct inode *inode, unsigned mi)
{
    knode_t *knode = NULL;

    if(mi < 1 || mi > klogger_max_size) {
        __E("[%u:%u] klogger_max_size:%d", MA, mi, klogger_max_size);
        goto err;
    }

    if((knode = kzalloc(sizeof(knode_t), GFP_KERNEL)) == NULL) {
        goto err;
    }

    knode->i_ino  = inode->i_ino;
    knode->i_rdev = inode->i_rdev;

    init_waitqueue_head(&(knode->reader_wq));
    rwlock_init(&knode->rwlock);

    knode->size = 1024 * mi;
    if((knode->data = vmalloc(sizeof(char) * knode->size)) == NULL) {
        goto data_malloc_failed;
    }

    knode->next = this->list;
    this->list = knode;

    __D("[%u:%u] inode:%ld,\n", MA, mi, knode->i_ino);
    return knode;

    //vfree(knode->data);
  data_malloc_failed:
    kfree(knode);
  err:
    return NULL;
}

static void free_knode(knode_t *knode)
{
    knode_t **ptr;

    if(knode == NULL) {
        return;
    }

    __D("inode %ld\n", knode->i_ino);
    vfree(knode->data);

    ptr = &this->list;
    while(*ptr != knode) {
        if(!*ptr) {
            __E("corrupt knode list.\n");
            break;
        } else {
            ptr = &((**ptr).next);
        }
    }

    *ptr = knode->next;
}

static int klogger_open(struct inode *inode, struct file *file)
{
    unsigned mi = MINOR(inode->i_rdev);
    knode_t *knode = NULL;

    if((knode = get_knode(inode)) == NULL) {
        if((knode = create_knode(inode, mi)) == NULL) {
            __E("[%u:%u] inode %ld\n", MA, mi, inode->i_ino);
            return -ENOMEM; // -EIO;
        }
    }

    knode->refcount++;
    if(!try_module_get(THIS_MODULE)) {
        __E("cannot get module\n");
        knode->refcount--;
        return -ENODEV;
    }
    return 0;
}

static int klogger_release(struct inode *inode, struct file *file)
{
    knode_t *knode;
    int retval = 0;

    if((knode = get_knode(inode)) == NULL) {
        __E("inode %ld\n", inode->i_ino);
        retval = EIO;
        goto out;
    }

    knode->refcount--;

    if(knode->refcount == 0 && QLEN(knode) == 0) {
        free_knode(knode);
    }

  out:
    module_put(THIS_MODULE);
    return retval;
}

static char * read_from_klogger(knode_t *knode, size_t *length, loff_t *ppos)
{
    char *kmem;
    int bytes_copied = 0, n, start_point;
    size_t remaining;

    read_lock(&knode->rwlock);

    __D("\n"
        "Length:                    %zu \n"
        "pos:                      %lld \n"
        "knode->offset:            %lld \n"
        "EMPTY_OFFSET:             %lld \n"
        "knode->read_point:         %zu \n"
        "knode->write_point:        %zu \n",
        *length,
        *ppos,
        knode->offset,
        EMPTY_OFFSET(knode),
        knode->read_point,
        knode->write_point);

    if(*ppos < knode->offset) {
        /* scrolled off */
        *ppos = knode->offset;
    }

    __D("New pos: %lld\n", *ppos);
    if(*ppos >= EMPTY_OFFSET(knode)) {
        /* do nothing if past EOF */
        read_unlock(&knode->rwlock);
        return NULL;
    }

    *length = min_t(size_t,
                    *length,
                    EMPTY_OFFSET(knode) - *ppos);
    remaining = *length;
    __D("Remaining: %zu\n", remaining);

    /* start based on pos */
    start_point = knode->read_point + (*ppos - knode->offset);
    __D("Start point: %d\n", start_point);
    start_point = start_point % knode->size;
    __D("Start point: %d\n", start_point);

    if((kmem = kmalloc(sizeof(char) * remaining, GFP_KERNEL)) == NULL) {
        read_unlock(&knode->rwlock);
        return NULL;
    }

    while(remaining) {
        n = min(remaining, knode->size - start_point);
        memcpy(kmem + bytes_copied, knode->data + start_point, n);
        bytes_copied += n;
        remaining -= n;
        start_point = (start_point + n) % knode->size;
    }
    read_unlock(&knode->rwlock);

    /* update pos */
    *ppos += *length;
    return kmem;
}

static ssize_t klogger_read(struct file *file, char __user *usr_buf,
                          size_t length,
                          loff_t *ppos)
{
    int      ret;
    char    *kmem;
    knode_t *knode;

    __D("\nLength:  %zu \n"
        "pos:      %lld \n",
        length, *ppos);

    if((knode = get_knode(file->f_path.dentry->d_inode)) == NULL) {
        __E("inode %ld.\n", (long)(file->f_path.dentry->d_inode->i_ino));
        return -EIO;
    }

    if(file->f_flags & O_NONBLOCK &&
       *ppos >= EMPTY_OFFSET(knode)) {
        return -EAGAIN;
    }


    wait_event_interruptible(knode->reader_wq,
                             *ppos < knode->offset + QLEN(knode));

    if(signal_pending(current)) {
        //restart read()
        return -ERESTARTSYS;
    }

    if((kmem = read_from_klogger(knode, &length, ppos)) == NULL) {
        return 0;
    }


    ret = copy_to_user(usr_buf, kmem, length) ? -EFAULT : length;

    kfree(kmem);
    return ret;
}

static void write_to_klogger(knode_t *knode, char *kmem, size_t length)
{
    int bytes_copied = 0;
    int overflow = 0;
    int n;

    write_lock(&knode->rwlock);

    __D("\n"
        "Length:             %zu  \n"
        "QLEN:               %zu  \n"
        "knode->size:        %zu  \n"
        "knode->offset:      %lld \n"
        "knode->read_point:  %zu  \n"
        "knode->write_point: %zu  \n",
        length, QLEN(knode), knode->size, knode->offset, knode->read_point, knode->write_point);

    if(QLEN(knode) + length >= (knode->size - 1)) {
        overflow = 1;
        //(knode->offset + (QLEN(knode) + length)) % knode->size + 1;
        knode->offset = knode->offset + QLEN(knode) + length - knode->size + 1;
    }

    while(length) {
        n = min(length, knode->size - knode->write_point);
        memcpy(knode->data + knode->write_point, kmem + bytes_copied, n);
        bytes_copied += n;
        length -= n;
        knode->write_point = (knode->write_point + n) % knode->size;
    }

    if(overflow) {
        knode->read_point = (knode->write_point + 1) % knode->size;
    }

    write_unlock(&knode->rwlock);
}

static ssize_t klogger_write(struct file *file,
                           const char __user *usr_buf,
                           size_t length, loff_t *ppos)
{
    char *kmem = NULL;
    size_t n;
    knode_t *knode;

    __D("\nLength: %zu\npos: %lld\n", length, *ppos);
    if((knode = get_knode(file->f_path.dentry->d_inode)) == NULL) {
        return -EIO;
    }

    n = min(length, knode->size - 1);

    if((kmem = kmalloc(n, GFP_KERNEL)) == NULL) {
        return -ENOMEM;
    }

    if(copy_from_user(kmem, usr_buf, n) > 0) {
        kfree(kmem);
        return -EFAULT;
    }

    write_to_klogger(knode, kmem, n);
    kfree(kmem);

    wake_up_interruptible(&(knode->reader_wq));
    return n;
}

static unsigned int klogger_poll(struct file *file, struct poll_table_struct * wait)
{
    knode_t *knode;

    if((knode = get_knode(file->f_path.dentry->d_inode)) == NULL) {
        return -EIO;
    }

    poll_wait(file, &(knode->reader_wq), wait);

    if(file->f_pos >= EMPTY_OFFSET(knode)) {
        return 0; //is empty
    }

    //file->f_pos < EMPTY_OFFSET(knode)
    return POLLIN | POLLRDNORM;
}

static const struct file_operations klogger_fops = {
    .read    = klogger_read,
    .write   = klogger_write,
    .open    = klogger_open,
    .release = klogger_release,
    .poll    = klogger_poll,
    .llseek  = no_llseek, //default
    .owner   = THIS_MODULE,
};

static int __init klogger_init(void)
{
    int ret = 0;

    this->nr_minor = (typeof(this->nr_minor))klogger_max_size;

    ret = alloc_chrdev_region(&this->dev_id, this->baseminor, this->nr_minor, this->dev_name);
    if(ret < 0) {
        __E("alloc_chrdev_region: %d\n", ret);
        return -1;
    }

    this->cdev = cdev_alloc();
    if(this->cdev == NULL) {
        __E("cdev_alloc\n");
        ret = -2;
        goto klogger_init_error;
    }

    this->cdev->ops   = &klogger_fops;
    this->cdev->owner = THIS_MODULE;

    ret = cdev_add(this->cdev, this->dev_id, this->nr_minor);
    if(ret < 0) {
        __E("cdev_add: %d.\n", ret);
        ret = -3;
        goto klogger_init_error;
    }

    __I("[%u:%u] max size %u K.\n",
        MAJOR(this->dev_id),
        MINOR(this->dev_id),
        this->nr_minor);

    this->cls = class_create(THIS_MODULE, this->dev_name);
    if(this->cls == NULL) {
        __E("class_create\n");
        ret = -4;
        goto klogger_init_error;
    }

    this->device = device_create(this->cls, NULL,
                                    MKDEV(MAJOR(this->dev_id), 256), NULL,
                                    this->dev_name);
    if(this->device == NULL) {
        __E("device_create\n");
        ret = -5;
        goto klogger_init_error;
    }

    __I("okay");
    return 0;

  klogger_init_error:
    if(this->device) {
        device_destroy(this->cls, this->dev_id);
        this->device = NULL;
    }
    if(this->cls) {
        class_destroy(this->cls);
        this->cls = NULL;
    }
    if(this->cdev) {
        cdev_del(this->cdev);
        this->cdev = NULL;
    }
    if(this->dev_id) {
        unregister_chrdev_region(this->dev_id, this->nr_minor);
        this->dev_id = 0;
    }
    return ret;
}

static void __exit klogger_remove(void)
{
    while(this->list != NULL)
        free_knode(this->list);

    device_destroy(this->cls, this->dev_id);
    this->device = NULL;

    class_destroy(this->cls);
    this->cls = NULL;

    cdev_del(this->cdev);
    this->cdev = NULL;

    unregister_chrdev_region(this->dev_id, this->nr_minor);
    this->dev_id = 0;

    __I("done\n");
}

module_init(klogger_init);
module_exit(klogger_remove);

MODULE_AUTHOR       ("liangyuetang@gmail.com");
MODULE_DESCRIPTION  ("Linux Logger KMD");
MODULE_LICENSE("GPL");
