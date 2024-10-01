#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>


#include <chall.h>

void init_chall(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    srand(time(NULL));

    print_banner();
#ifdef DEBUG
    printf("sizeof(ctfplayer_t): %#lx\n", sizeof(ctfplayer_t));
    printf("sizeof(pwner_t): %#lx\n", sizeof(pwner_t));
#endif
}

void print_banner(void)
{
    puts(
        "\n\n"
        " ▄████████     ███        ▄████████     ███        ▄████████    ▄████████   ▄▄▄▄███▄▄▄▄      ▄████████ \n"
        "███    ███ ▀█████████▄   ███    ███ ▀█████████▄   ███    ███   ███    ███ ▄██▀▀▀███▀▀▀██▄   ███    ███ \n"
        " ███    █▀     ▀███▀▀██   ███    █▀     ▀███▀▀██   ███    █▀    ███    ███ ███   ███   ███   ███    █▀ \n"
        " ███            ███   ▀  ▄███▄▄▄         ███   ▀  ▄███▄▄▄       ███    ███ ███   ███   ███   ███       \n"
        " ███            ███     ▀▀███▀▀▀         ███     ▀▀███▀▀▀     ▀███████████ ███   ███   ███ ▀███████████\n"
        " ███    █▄      ███       ███            ███       ███    █▄    ███    ███ ███   ███   ███          ███\n"
        " ███    ███     ███       ███            ███       ███    ███   ███    ███ ███   ███   ███    ▄█    ███\n"
        " ████████▀     ▄████▀     ███           ▄████▀     ██████████   ███    █▀   ▀█   ███   █▀   ▄████████▀ \n\n\n"
    );
    puts(
        "Always dreamt of being a pro CTF player but you have too many skill issues??\n"
        "No worries, we got you covered! Now you can feel the same thrill pro players\n"
        "do, by using our brand new CTF Team Manager Simulator!\n"
        "Create your dream team, and go get those flags!"
    );
}

uint32_t get_choice(void)
{
    char buf[32];
    fgets(buf, sizeof(buf), stdin);
    return strtoul(buf, NULL, 10);
}

char *stripped_fgets(char *str, int size, FILE *stream)
{
    char *ret = fgets(str, size, stream);
    if (ret != NULL) {
        char *nl = strrchr(str, '\n');
        if (nl != NULL) {
            *nl = '\0';
        }
    }
    return ret;
}

uint32_t main_menu(void)
{
    puts(
        "\n\n"
        "1. Add new player\n"
        "2. Remove player\n"
        "3. Show player's stats\n"
        "4. Solve challenge\n"
        "5. Edit motto\n"
        "99. Exit"
    );
    printf("> ");

    return get_choice();
}

void insert_player(ctfplayer_t *player, ctfplayer_t **head)
{
    // Increment the number of players here for simplicity
    nplayers++;

    if (*head == NULL) {
        *head = player;
    } else {
        ctfplayer_t *curr = *head;
        while (curr->next != NULL) {
            curr = curr->next;
        }
        curr->next = player;
    }
}

void delete_player(ctfplayer_t *player, ctfplayer_t **head)
{
    ctfplayer_t *curr = *head;
    ctfplayer_t *prev = NULL;

    while (curr != NULL && curr != player) {
        prev = curr;
        curr = curr->next;
    }
    if (curr == NULL) {
        puts("Player not found");
        return;
    }
    if (prev == NULL) {
        *head = curr->next;
    } else {
        prev->next = curr->next;
    }
    free(curr);
    removed = 1;
    nplayers--;
}

enum category get_category(void)
{
    puts(
        "Choose a category:\n"
        "1. Pwn\n"
        "2. Rev\n"
        "3. Misc\n"
        "4. Web\n"
        "5. Crypto"
    );
    printf("> ");
    uint32_t choice = get_choice() - 1;
    switch (choice) {
    case CAT_PWN:
    case CAT_RE:
    case CAT_MISC:
    case CAT_WEB:
    case CAT_CRY:
        return choice;
    default:
        return -1;
    }
}

ctfplayer_t *select_player(ctfplayer_t **head)
{
    ctfplayer_t *curr = *head;
    if (curr == NULL) {
        puts("No players, add some first\n");
        return NULL;
    }

    puts("Select a player:");
    uint32_t i = 1;
    while (curr != NULL) {
        printf("%d. %s\n", i, curr->nick);
        curr = curr->next;
        i++;
    }
    printf("> ");
    uint32_t choice = get_choice();

    if (choice >= i || choice == 0) {
        puts("Invalid choice");
        return NULL;
    }

    curr = *head;
    for (i = 1; i < choice; i++) {
        curr = curr->next;
    }

    return curr;
}

void init_player(ctfplayer_t *player, enum category cat)
{
    printf("Nickname: ");
    if (stripped_fgets(player->nick, sizeof(player->nick), stdin) == NULL) {
        exit(EXIT_FAILURE);
    }
    printf("Motto: ");
    if (stripped_fgets(player->motto, sizeof(player->motto), stdin) == NULL) {
        exit(EXIT_FAILURE);
    }
    player->cat = cat;
    player->flags = 0;
    player->mental_health = MAX_MENTAL;
    player->skills = (rand() % 100) + 1;
}

void add_player(void)
{
    pwner_t *pwner = NULL;
    ctfplayer_t *player = NULL;

    if (nplayers >= MAX_PLAYERS) {
        puts("Cannot add any more players");
        return;
    }

    enum category choice = get_category();
    switch (choice) {
    case CAT_PWN:
        puts("Adding pwner");
        pwner = malloc(sizeof(pwner_t));
        if (pwner == NULL) {
            puts("Failed to add player");
            exit(EXIT_FAILURE);
        }
        init_player((ctfplayer_t *)pwner, CAT_PWN);
        insert_player((ctfplayer_t *)pwner, &players);

        if (pwner->player.skills == 100) {
            pwner->zero_days = (rand() % 3) + 1;
        }

        pwner->player.try_solve = &pwn_solve;
        break;
    case CAT_RE:
        puts("Adding revver");
        player = malloc(sizeof(ctfplayer_t));
        if (player == NULL) {
            puts("Failed to add player");
            exit(EXIT_FAILURE);
        }
        init_player((ctfplayer_t *)player, CAT_RE);
        insert_player((ctfplayer_t *)player, &players);
        player->try_solve = &re_solve;
        break;
    case CAT_MISC:
        puts("Adding miscer");
        player = malloc(sizeof(ctfplayer_t));
        if (player == NULL) {
            puts("Failed to add player");
            exit(EXIT_FAILURE);
        }
        init_player((ctfplayer_t *)player, CAT_MISC);
        insert_player((ctfplayer_t *)player, &players);
        player->try_solve = &misc_solve;
        break;
    case CAT_WEB:
        puts("Adding webber");
        player = malloc(sizeof(ctfplayer_t));
        if (player == NULL) {
            puts("Failed to add player");
            exit(EXIT_FAILURE);
        }
        init_player((ctfplayer_t *)player, CAT_WEB);
        insert_player((ctfplayer_t *)player, &players);
        player->try_solve = &web_solve;
        break;
    case CAT_CRY:
        puts("Adding cryptoguy");
        player = malloc(sizeof(ctfplayer_t));
        if (player == NULL) {
            puts("Failed to add player");
            exit(EXIT_FAILURE);
        }
        init_player((ctfplayer_t *)player, CAT_CRY);
        insert_player((ctfplayer_t *)player, &players);
        player->try_solve = &cry_solve;
        break;
    default:
        puts("Invalid choice");
        break;
    }
}

void remove_player(void)
{
    ctfplayer_t *player = NULL;

    // treat it as bool
    if (removed) {
        puts("You can only remove one player from the team!");
        return;
    }

    player = select_player(&players);
    if (player == NULL) {
        puts("No player selected");
    } else {
        delete_player(player, &players);
    }
}

void show_player_stats(void)
{
    ctfplayer_t *player = select_player(&players);

    if (player == NULL) {
        return;
    }

    printf("Nickname: %s\n", player->nick);
    printf("Motto: %s\n", player->motto);
    printf("Category: %s\n", categories[player->cat]);
    printf("Flags obtained: %u\n", player->flags);
    printf("Mental health: [%u/100]\n", player->mental_health);
    printf("Skills level: [%u/100]\n", player->skills);
    if (player->cat == CAT_PWN) {
        pwner_t *pwner = (pwner_t *)player;
        printf("0-day exploits: %lu\n", pwner->zero_days);
    }
}

void solve_chall(void)
{
    ctfplayer_t *player = select_player(&players);
    if (player == NULL) {
        return;
    }
    __asm__ volatile("mov $0, %r10");
    player->try_solve(player);
}

void edit_motto(void)
{
    ctfplayer_t *player = select_player(&players);
    if (player == NULL) {
        return;
    }
    printf("New motto: ");
    if (stripped_fgets(player->motto, sizeof(player->motto), stdin) == NULL) {
        exit(EXIT_FAILURE);
    }
}

void pwn_solve(void *self)
{
    pwner_t *pwner = (pwner_t *)self;

    if (pwner->player.mental_health <= 0) {
        puts("Mental gone, cannot solve, go to sleep");
        return;
    }
    pwner->player.mental_health -= 10;

    puts("Sending 'A's...");
    sleep(1);
    puts("Sending 'B's");
    sleep(1);
    puts("Crying in assembly :( ...");
    sleep(1);

    uint32_t chall_diff = (rand() % 100) + 1;
    if (pwner->player.skills >= chall_diff) {
        puts("Challenge pwned");
        puts("You got flag{this_is_not_the_flag_for_this_challenge___Or_is_it?}");
        pwner->player.flags++;
    } else if (pwner->zero_days > 0) {
        puts("Using 0-day exploit to solve the challenge");
        puts("You got flag{this_is_not_the_flag_for_this_challenge___Or_is_it?}");
        pwner->player.flags++;
    } else {
        puts("Skill issues detected, try harder");
    }
}

void re_solve(void *self)
{
    ctfplayer_t *player = (ctfplayer_t *)self;
    if (player->mental_health <= 0) {
        puts("Mental gone, cannot solve, go to sleep");
        return;
    }
    player->mental_health -= 10;
    puts("Disassembling the binary...");
    sleep(1);
    puts("Looking for bugs...");
    sleep(1);
    puts("Crying in java :( ...");
    sleep(1);
    uint32_t chall_diff = (rand() % 100) + 1;
    if (player->skills >= chall_diff) {
        puts("Challenge reversed");
        puts("You got flag{this_is_not_the_flag_for_this_challenge___Or_is_it?}");
        player->flags++;
    } else {
        puts("Skill issues detected, try harder");
    }
}

void misc_solve(void *self)
{
    ctfplayer_t *player = (ctfplayer_t *)self;
    if (player->mental_health <= 0) {
        puts("Mental gone, cannot solve, go to sleep");
        return;
    }
    player->mental_health -= 10;
    puts("Reading the challenge description...");
    sleep(1);
    puts("Googling...");
    sleep(1);
    puts("Crying in python :( ...");
    sleep(1);
    uint32_t chall_diff = (rand() % 100) + 1;
    if (player->skills >= chall_diff) {
        puts("Challenge solved");
        puts("You got flag{this_is_not_the_flag_for_this_challenge___Or_is_it?}");
        player->flags++;
    } else {
        puts("Skill issues detected, try harder");
    }
}

void web_solve(void *self)
{
    ctfplayer_t *player = (ctfplayer_t *)self;
    if (player->mental_health <= 0) {
        puts("Mental gone, cannot solve, go to sleep");
        return;
    }
    player->mental_health -= 10;
    puts("Inspecting the website...");
    sleep(1);
    puts("Sending random XSS payload...");
    sleep(1);
    puts("Crying in javascript :( ...");
    sleep(1);
    uint32_t chall_diff = (rand() % 100) + 1;
    if (player->skills >= chall_diff) {
        puts("Challenge solved");
        puts("You got flag{this_is_not_the_flag_for_this_challenge___Or_is_it?}");
        player->flags++;
    } else {
        puts("Skill issues detected, try harder");
    }
}

void cry_solve(void *self)
{
    ctfplayer_t *player = (ctfplayer_t *)self;
    if (player->mental_health <= 0) {
        puts("Mental gone, cannot solve, go to sleep");
        return;
    }
    player->mental_health -= 10;
    puts("Colliding hashes...");
    sleep(1);
    puts("Reading papers...");
    sleep(1);
    puts("Crying in math :( ...");
    sleep(1);
    uint32_t chall_diff = (rand() % 100) + 1;
    if (player->skills >= chall_diff) {
        puts("Challenge solved");
        puts("You got flag{this_is_not_the_flag_for_this_challenge___Or_is_it?}");
        player->flags++;
    } else {
        puts("Skill issues detected, try harder");
    }
}
