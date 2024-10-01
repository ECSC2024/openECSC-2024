#include <stdio.h>
#include <stdlib.h>

#include <chall.h>

// Global variables
char *categories[] = {
    "Pwn",
    "Rev",
    "Misc",
    "Web",
    "Cry",
};
ctfplayer_t *players    = NULL;
int removed             = 0;
int nplayers            = 0;

int main(void)
{
    init_chall();

    while (1) {
        int choice = main_menu();

        switch (choice) {
        case 1:
            add_player();
            break;
        case 2:
            remove_player();
            break;
        case 3:
            show_player_stats();
            break;
        case 4:
            solve_chall();
            break;
        case 5:
            edit_motto();
            break;
        case 99:
            exit(EXIT_SUCCESS);
        default:
            puts("Invalid choice");
        }
    }

    return 0;
}
