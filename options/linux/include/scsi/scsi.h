
#ifndef _LINUX_SCSI_SCSI_H
#define _LINUX_SCSI_SCSI_H

#define RECOVERED_ERROR 0x01
#define ILLEGAL_REQUEST 0x05
#define UNIT_ATTENTION 0x06
#define INQUIRY 0x12
#define START_STOP 0x1b
#define ALLOW_MEDIUM_REMOVAL 0x1e

#define SCSI_IOCTL_GET_IDLUN 0x5382
#define SCSI_IOCTL_TAGGED_ENABLE 0x5383
#define SCSI_IOCTL_TAGGED_DISABLE 0x5384
#define SCSI_IOCTL_PROBE_HOST 0x5385

#endif /* _LINUX_SCSI_SCSI_H */

