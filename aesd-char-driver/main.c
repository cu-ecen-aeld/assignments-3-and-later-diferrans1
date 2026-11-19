/**
 * @file main.c
 * @brief aesdchar kernel character driver
 *        Supports read, write (newline-delimited), llseek, and
 *        AESDCHAR_IOCSEEKTO ioctl for assignment 9.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include "aesdchar.h"
#include "aesd_ioctl.h"

MODULE_AUTHOR("diferrans1");
MODULE_LICENSE("Dual BSD/GPL");

static int aesdchar_major = 0;
static int aesdchar_minor = 0;
struct aesd_dev aesd_device;

/* Sum of all bytes stored in the circular buffer */
static size_t buffer_total_size(struct aesd_circular_buffer *buf)
{
    uint8_t i;
    size_t total = 0;
    struct aesd_buffer_entry *entry;
    AESD_CIRCULAR_BUFFER_FOREACH(entry, buf, i)
        total += entry->size;
    return total;
}

int aesdchar_open(struct inode *inode, struct file *filp)
{
    filp->private_data = container_of(inode->i_cdev, struct aesd_dev, cdev);
    return 0;
}

int aesdchar_release(struct inode *inode, struct file *filp)
{
    return 0;
}

ssize_t aesdchar_read(struct file *filp, char __user *buf,
                      size_t count, loff_t *f_pos)
{
    struct aesd_dev *dev = filp->private_data;
    size_t entry_offset;
    struct aesd_buffer_entry *entry;
    ssize_t retval = 0;

    if (mutex_lock_interruptible(&dev->lock))
        return -ERESTARTSYS;

    entry = aesd_circular_buffer_find_entry_offset_for_fpos(
                &dev->buffer, *f_pos, &entry_offset);
    if (!entry)
        goto out;

    /* Clamp to end of this entry */
    if (count > entry->size - entry_offset)
        count = entry->size - entry_offset;

    if (copy_to_user(buf, entry->buffptr + entry_offset, count)) {
        retval = -EFAULT;
        goto out;
    }

    *f_pos += count;
    retval  = count;
out:
    mutex_unlock(&dev->lock);
    return retval;
}

ssize_t aesdchar_write(struct file *filp, const char __user *buf,
                       size_t count, loff_t *f_pos)
{
    struct aesd_dev *dev = filp->private_data;
    char *kbuf;
    char *newline;
    ssize_t retval;

    kbuf = kmalloc(count, GFP_KERNEL);
    if (!kbuf)
        return -ENOMEM;

    if (copy_from_user(kbuf, buf, count)) {
        kfree(kbuf);
        return -EFAULT;
    }

    if (mutex_lock_interruptible(&dev->lock)) {
        kfree(kbuf);
        return -ERESTARTSYS;
    }

    /* Append received bytes to the pending accumulator */
    dev->pending = krealloc(dev->pending, dev->pending_len + count, GFP_KERNEL);
    if (!dev->pending) {
        kfree(kbuf);
        mutex_unlock(&dev->lock);
        return -ENOMEM;
    }
    memcpy(dev->pending + dev->pending_len, kbuf, count);
    dev->pending_len += count;
    kfree(kbuf);

    /* Commit every newline-terminated command found in pending */
    while ((newline = memchr(dev->pending, '\n', dev->pending_len)) != NULL) {
        size_t entry_len = (size_t)(newline - dev->pending) + 1;
        char *entry_buf  = kmalloc(entry_len, GFP_KERNEL);
        if (!entry_buf) {
            mutex_unlock(&dev->lock);
            return -ENOMEM;
        }
        memcpy(entry_buf, dev->pending, entry_len);

        struct aesd_buffer_entry new_entry = {
            .buffptr = entry_buf,
            .size    = entry_len
        };

        /* If the buffer is full the oldest slot will be overwritten; free it. */
        if (dev->buffer.full)
            kfree((void *)dev->buffer.entry[dev->buffer.in_offs].buffptr);

        aesd_circular_buffer_add_entry(&dev->buffer, &new_entry);

        /* Shift remaining bytes to the front of pending */
        size_t remaining = dev->pending_len - entry_len;
        if (remaining > 0) {
            memmove(dev->pending, dev->pending + entry_len, remaining);
            dev->pending_len = remaining;
        } else {
            kfree(dev->pending);
            dev->pending     = NULL;
            dev->pending_len = 0;
        }
    }

    retval = count;
    mutex_unlock(&dev->lock);
    return retval;
}

loff_t aesdchar_llseek(struct file *filp, loff_t offset, int whence)
{
    struct aesd_dev *dev = filp->private_data;
    loff_t size;

    mutex_lock(&dev->lock);
    size = (loff_t)buffer_total_size(&dev->buffer);
    mutex_unlock(&dev->lock);

    return fixed_size_llseek(filp, offset, whence, size);
}

long aesdchar_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    struct aesd_dev *dev = filp->private_data;
    struct aesd_seekto seekto;
    loff_t new_pos = 0;
    uint8_t i;
    uint8_t idx;

    if (_IOC_TYPE(cmd) != AESDCHAR_IOC_MAGIC)
        return -ENOTTY;
    if (_IOC_NR(cmd) > AESDCHAR_IOC_MAXNR)
        return -ENOTTY;

    switch (cmd) {
    case AESDCHAR_IOCSEEKTO:
        if (copy_from_user(&seekto, (struct aesd_seekto __user *)arg,
                           sizeof(seekto)))
            return -EFAULT;

        if (mutex_lock_interruptible(&dev->lock))
            return -ERESTARTSYS;

        if (seekto.write_cmd >= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED) {
            mutex_unlock(&dev->lock);
            return -EINVAL;
        }

        /* Walk the in-order entries to compute the absolute byte offset */
        idx = dev->buffer.out_offs;
        for (i = 0; i < seekto.write_cmd; i++) {
            if (!dev->buffer.entry[idx].buffptr) {
                mutex_unlock(&dev->lock);
                return -EINVAL;
            }
            new_pos += (loff_t)dev->buffer.entry[idx].size;
            idx = (idx + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
        }

        if (!dev->buffer.entry[idx].buffptr ||
            seekto.write_cmd_offset >= dev->buffer.entry[idx].size) {
            mutex_unlock(&dev->lock);
            return -EINVAL;
        }

        new_pos     += (loff_t)seekto.write_cmd_offset;
        filp->f_pos  = new_pos;
        mutex_unlock(&dev->lock);
        return 0;

    default:
        return -ENOTTY;
    }
}

static const struct file_operations aesdchar_fops = {
    .owner          = THIS_MODULE,
    .open           = aesdchar_open,
    .release        = aesdchar_release,
    .read           = aesdchar_read,
    .write          = aesdchar_write,
    .llseek         = aesdchar_llseek,
    .unlocked_ioctl = aesdchar_ioctl,
};

static int aesdchar_setup_cdev(struct aesd_dev *dev)
{
    int err;
    dev_t devno = MKDEV(aesdchar_major, aesdchar_minor);
    cdev_init(&dev->cdev, &aesdchar_fops);
    dev->cdev.owner = THIS_MODULE;
    err = cdev_add(&dev->cdev, devno, 1);
    if (err)
        printk(KERN_ERR "aesdchar: cdev_add failed (%d)\n", err);
    return err;
}

static int __init aesdchar_init_module(void)
{
    dev_t dev = 0;
    int result;

    result = alloc_chrdev_region(&dev, aesdchar_minor, 1, "aesdchar");
    if (result < 0) {
        printk(KERN_WARNING "aesdchar: can't get major number\n");
        return result;
    }
    aesdchar_major = MAJOR(dev);

    memset(&aesd_device, 0, sizeof(aesd_device));
    mutex_init(&aesd_device.lock);
    aesd_circular_buffer_init(&aesd_device.buffer);

    result = aesdchar_setup_cdev(&aesd_device);
    if (result)
        unregister_chrdev_region(dev, 1);

    return result;
}

static void __exit aesdchar_cleanup_module(void)
{
    uint8_t i;
    struct aesd_buffer_entry *entry;

    cdev_del(&aesd_device.cdev);
    unregister_chrdev_region(MKDEV(aesdchar_major, aesdchar_minor), 1);

    AESD_CIRCULAR_BUFFER_FOREACH(entry, &aesd_device.buffer, i)
        kfree((void *)entry->buffptr);

    kfree(aesd_device.pending);
}

module_init(aesdchar_init_module);
module_exit(aesdchar_cleanup_module);
