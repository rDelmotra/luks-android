#include <linux/usbdevice_fs.h>
#include <stdio.h>

int main() {
    printf("size: %zu\n", sizeof(struct usbdevfs_urb));
    return 0;
}
