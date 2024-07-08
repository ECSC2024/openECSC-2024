#include <chall_utils.h>
#include <stdio.h>

void setup_io(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
}

void print_banner(void)
{
    puts("##############################################################");
    puts("#                                                            #");
    puts("# Welcome to AES (Asynchronous Encryption Service) v0.1-beta #");
    puts("#                                                            #");
    puts("##############################################################");
    puts("You have the privilege to access our beta version!");
    puts("Enjoy super fast and secure encryption!");
    puts("For now you can send messages of maximum 8 blocks of 8 bytes.");
    puts("It will encrypt them for you with your secret key.");
    puts("");
}

int menu(void)
{
    int choice;
    puts("\nMenu:");
    puts("1. Encrypt new message");
    puts("2. Get encrypted message");
    puts("3. Exit");
    printf("> ");
    scanf("%d", &choice);
    return choice;
}


ssize_t readn(int fd, char *buf, size_t count)
{
    size_t n = 0;
    while (n < count) {
        ssize_t r = read(fd, buf + n, count - n);
        if (r < 0) {
            return r;
        }
        n += r;
    }
    return n;
}

ssize_t writen(int fd, char *buf, size_t count)
{
    size_t n = 0;
    while (n < count) {
        ssize_t r = write(fd, buf + n, count - n);
        if (r < 0) {
            return r;
        }
        n += r;
    }
    return n;
}
