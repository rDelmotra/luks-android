#include <stdio.h>
#include <linux/ioctl.h>
#include <linux/usbdevice_fs.h>

/* Uses the kernel's own _IOC encoder and its own struct definitions.
   dir/type/nr are read straight from usbdevice_fs.h:
     USBDEVFS_CONTROL           _IOWR('U', 0, struct usbdevfs_ctrltransfer)
     USBDEVFS_BULK              _IOWR('U', 2, struct usbdevfs_bulktransfer)
     USBDEVFS_CLAIMINTERFACE    _IOR ('U', 15, unsigned int)
     USBDEVFS_RELEASEINTERFACE  _IOR ('U', 16, unsigned int)
     USBDEVFS_CLEAR_HALT        _IOR ('U', 21, unsigned int)  */
int main(void) {
    printf("shifts: NR=%d TYPE=%d SIZE=%d DIR=%d   READ=%u WRITE=%u\n",
           _IOC_NRSHIFT, _IOC_TYPESHIFT, _IOC_SIZESHIFT, _IOC_DIRSHIFT,
           _IOC_READ, _IOC_WRITE);
    printf("sizeof(bulktransfer)      = %zu\n", sizeof(struct usbdevfs_bulktransfer));
    printf("sizeof(ctrltransfer)      = %zu\n", sizeof(struct usbdevfs_ctrltransfer));
    printf("USBDEVFS_BULK             = 0x%08lX\n",
        (unsigned long)_IOC(_IOC_READ|_IOC_WRITE,'U',2,sizeof(struct usbdevfs_bulktransfer)));
    printf("USBDEVFS_CONTROL          = 0x%08lX\n",
        (unsigned long)_IOC(_IOC_READ|_IOC_WRITE,'U',0,sizeof(struct usbdevfs_ctrltransfer)));
    printf("USBDEVFS_CLAIMINTERFACE   = 0x%08lX\n",
        (unsigned long)_IOC(_IOC_READ,'U',15,sizeof(unsigned int)));
    printf("USBDEVFS_RELEASEINTERFACE = 0x%08lX\n",
        (unsigned long)_IOC(_IOC_READ,'U',16,sizeof(unsigned int)));
    printf("USBDEVFS_CLEAR_HALT       = 0x%08lX\n",
        (unsigned long)_IOC(_IOC_READ,'U',21,sizeof(unsigned int)));
    return 0;
}
