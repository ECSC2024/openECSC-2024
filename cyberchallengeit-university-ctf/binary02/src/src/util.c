#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include "util.h"

void die(const char* msg) {
    puts(msg);
    exit(1);
}

int read_exactly(int fd, void *buf, size_t size) {
    size_t done = 0;
    while (done != size) {
        ssize_t count = read(fd, (char *)buf + done, size - done);
        if (count <= 0)
            return -1;
        done += count;
    }
    return 0;
}

void set_buf() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}