#ifndef AESDCHAR_H
#define AESDCHAR_H

#include <linux/cdev.h>
#include <linux/mutex.h>
#include "aesd-circular-buffer.h"

#ifdef AESD_DEBUG
#  define PDEBUG(fmt, args...) printk(KERN_DEBUG "aesdchar: " fmt, ## args)
#else
#  define PDEBUG(fmt, args...)
#endif

struct aesd_dev {
    struct aesd_circular_buffer buffer;
    char   *pending;        /* partial write accumulator (not yet newline-terminated) */
    size_t  pending_len;
    struct mutex lock;
    struct cdev  cdev;
};

#endif /* AESDCHAR_H */
