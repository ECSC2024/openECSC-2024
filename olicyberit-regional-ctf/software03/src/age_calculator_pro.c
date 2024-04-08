#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

void win() {
    char *args[] = { "/bin/sh", NULL };
    char *env[] = { NULL };
    execve("/bin/sh", args, env);
}

void init() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    puts("    ___                 ______      __           __      __                ____           ");
    puts("   /   | ____ ____     / ____/___ _/ /______  __/ /___ _/ /_____  _____   / __ \\_________ ");
    puts("  / /| |/ __ `/ _ \\   / /   / __ `/ / ___/ / / / / __ `/ __/ __ \\/ ___/  / /_/ / ___/ __ \\");
    puts(" / ___ / /_/ /  __/  / /___/ /_/ / / /__/ /_/ / / /_/ / /_/ /_/ / /     / ____/ /  / /_/ /");
    puts("/_/  |_\\__, /\\___/   \\____/\\__,_/_/\\___/\\__,_/_/\\__,_/\\__/\\____/_/     /_/   /_/   \\____/ ");
    puts("      /____/                                                                              ");
    puts("");
}

int main() {

    char buffer[0x40] = {0};
    int year = 0;

    init();

    puts("What's your name?");
    gets(buffer);
    printf(buffer);

    puts(", what's your birth year?");
    gets(buffer);
    year = atoi(buffer);
    printf("You are %d years old!\n", 2024 - year);  

    return 0;
}
