#ifndef AESD_IOCTL_H
#define AESD_IOCTL_H

#include <linux/ioctl.h>

struct aesd_seekto {
    uint32_t write_cmd;         /* zero-referenced circular buffer entry to seek into */
    uint32_t write_cmd_offset;  /* byte offset within that entry */
};

#define AESDCHAR_IOC_MAGIC  0x16
#define AESDCHAR_IOCSEEKTO  _IOWR(AESDCHAR_IOC_MAGIC, 1, struct aesd_seekto)
#define AESDCHAR_IOC_MAXNR  1

#endif /* AESD_IOCTL_H */
