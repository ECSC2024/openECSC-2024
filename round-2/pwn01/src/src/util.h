#pragma once
#include <unistd.h>

void die(const char* msg);
int read_exactly(int fd, void *buf, size_t size);
void set_buf(void);