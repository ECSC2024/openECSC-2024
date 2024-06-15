#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>

void die(const char *msg) {
    puts(msg);
    exit(1);
}

void setupbuf(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void win(void) {
    char flag[0x100];

    int fd = open("flag", 0);
    if (fd < 0)
        die("Error opening flag");

    read(fd, flag, sizeof(flag));
    puts(flag);
    close(fd);
}

#define MAX_DAMAGE

struct dragon {
    char *name;
    unsigned long hp;
};

struct dragon you = {
    .name = "You",
    .hp = 0x1000,
};

struct dragon dragons[10] = {
    {.name = "Fire Dragon", .hp = 0x100},
    {.name = "Ice Dragon", .hp = 0x200},
    {.name = "Earth Dragon", .hp = 0x300},
    {.name = "Wind Dragon", .hp = 0x500},
    {.name = "Water Dragon", .hp = 0x1a00},
    {.name = "Electric Dragon", .hp = 0x3000},
    {.name = "Metal Dragon", .hp = 0x4500},
    {.name = "Dark Dragon", .hp = 0xa000},
    {.name = "Light Dragon", .hp = 0x14000},
    {.name = "Poison Dragon", .hp = 0x7fffffffffffffff},
};

void fight(void) {
    signed char choice;
    struct dragon *dragon;
    short damage;

    puts("Which dragon do you want to fight?");
    for (int i = 0; i < 10; i++) {
        if (dragons[i].name) {
            printf("%d. %s\n", i, dragons[i].name);
        }
    }
    printf("> ");
    if (scanf("%hhd", &choice) != 1)
        die("Invalid choice");
    
    dragon = &dragons[choice];

    if (you.hp <= dragon->hp) {
        puts("Pls! Do you really want to die?");
        return;
    }

    printf("You're fighting %hhd!\n", choice);
    puts("How much damage do you want to deal?");
    if (scanf("%hd", &damage) != 1)
        die("Invalid damage");    
    
    you.hp += dragon->hp;
    dragon->hp -= damage;
    puts("You attacked the dragon!");
}

void check_win(void) {
    for (int i = 0; i < 10; i++) {
        if (dragons[i].hp != 0) {
            puts("Nope :(");
            return;
        }
    }
    win();
}

void banner(void) {
    puts(" (                                                                                                    ");
    puts(" )\\ )                                 (                   )     )                      (           )  ");
    puts("(()/(   (       )  (  (               )\\ )  (   (  (   ( /(  ( /(   (   (              )\\   (   ( /(  ");
    puts(" /(_))  )(   ( /(  )\\))(  (    (     (()/(  )\\  )\\))(  )\\()) )\\()) ))\\  )(   (     (  ((_) ))\\  )\\()) ");
    puts("(_))_  (()\\  )(_))((_))\\  )\\   )\\ )   /(_))((_)((_))\\ ((_)\\ (_))/ /((_)(()\\  )\\    )\\  _  /((_)((_)\\  ");
    puts(" |   \\  ((_)((_)_  (()(_)((_) _(_/(  (_) _| (_) (()(_)| |(_)| |_ (_))   ((_)((_)  ((_)| |(_))( | |(_) ");
    puts(" | |) || '_|/ _` |/ _` |/ _ \\| ' \\))  |  _| | |/ _` | | ' \\ |  _|/ -_) | '_|(_-< / _| | || || || '_ \\ ");
    puts(" |___/ |_|  \\__,_|\\__, |\\___/|_||_|   |_|   |_|\\__, | |_||_| \\__|\\___| |_|  /__/ \\__| |_| \\_,_||_.__/ ");
    puts("                  |___/                        |___/                                                  ");
    puts("");
    puts("Beat all the dragons and join us!");
    puts("");
}

void menu(void) {
    puts("--------------");
    puts("1. You");
    puts("2. Dragons");
    puts("3. Fight");
    puts("4. Check win");
    puts("5. Exit");
    printf("> ");
}

int main() {

    int choice;
    setupbuf();
    banner();
    while (1) {
        menu();
        if (scanf("%d", &choice) != 1)
            die("Invalid choice");

        switch (choice) {
            case 1:
                printf("You: 0x%lx\n", you.hp);
                break;
            case 2:
                for (int i = 0; i < 10; i++) {
                    printf("%d. %s: 0x%lx\n", i, dragons[i].name, dragons[i].hp);
                }
                break;
            case 3:
                fight();
                break;
            case 4:
                check_win();
                break;
            case 5:
                puts("Bye!");
                exit(0);
            default:
                die("Invalid choice");
        }
    }
}