#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

void die(char *msg) {
    puts(msg);
    exit(1);
}

void game() {
    struct {
        char input[0x28];
        char secret[0x10];
    } data;
    int fd;

    fd = open("/dev/urandom", 0);
    if (fd < 0)
        die("[-] open /dev/urandom");

    if (read(fd, data.secret, 0x10) != 0x10)
        die("[-] read /dev/urandom");

    if (close(fd) != 0)
        die("[-] close /dev/urandom");

    while (1) {
        puts("Guess the secret!");
        read(0, data.input, 0x68);

        if (memcmp(data.input, data.secret, strlen(data.input)) == 0) {
            puts("You win!");
        } else {
            puts("You lose!");
        }

        puts("Wanna play again? (y/n)");
        if (getchar() != 'y')
            break;
    }

    puts("Goodbye!");
    return;
}

int main() {

    char msg[] = "Welcome to the guessing game!\n";
    puts(msg);

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    game();    
    return 0;
}
