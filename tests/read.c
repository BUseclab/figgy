#include <unistd.h>
#include <fcntl.h>

int main(void) {
    char buf[16];

    // using standard wrappers instead of raw syscall(...)
    int fd = openat(AT_FDCWD, "/dev/zero", O_RDONLY);
    if (fd < 0) return 1;

    read(fd, buf, sizeof(buf));
    close(fd);
    
    return 0;
}
