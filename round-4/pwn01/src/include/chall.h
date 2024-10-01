#ifndef CHALL_H
#define CHALL_H

#include <stdint.h>
#include <stdio.h>

// Defines
#define MAX_NICK_LEN    500
#define MAX_MOTTO_LEN   0x200
#define MAX_PLAYERS     5
#define MAX_REMOVED     1
#define MAX_MENTAL      100
#define MAX_SKILLS      100


// Data structures
enum category {
    CAT_PWN,
    CAT_RE,
    CAT_MISC,
    CAT_WEB,
    CAT_CRY,
};

typedef struct __attribute__((__packed__)) ctfplayer {
    struct ctfplayer *next;
    enum category cat;
    char motto[MAX_MOTTO_LEN];
    char nick[MAX_NICK_LEN];
    void (*try_solve)(void *self);
    uint32_t flags;
    short mental_health;
    uint16_t skills;
} ctfplayer_t;

typedef struct pwner {
    ctfplayer_t player;
    uint64_t zero_days;
} pwner_t;


// Global variables
extern char *categories[];
extern ctfplayer_t *players;
extern int removed;
extern int nplayers;


// Prototypes
void init_chall(void);
void print_banner(void);
uint32_t main_menu(void);
uint32_t get_choice(void);
char *stripped_fgets(char *str, int size, FILE *stream);
void insert_player(ctfplayer_t *player, ctfplayer_t **head);
void delete_player(ctfplayer_t *player, ctfplayer_t **head);
ctfplayer_t *select_player(ctfplayer_t **head);
enum category get_category(void);
void add_player(void);
void remove_player(void);
void show_player_stats(void);
void solve_chall(void);
void edit_motto(void);
void init_player(ctfplayer_t *player, enum category cat);
void pwn_solve(void *self);
void re_solve(void *self);
void misc_solve(void *self);
void web_solve(void *self);
void cry_solve(void *self);

#endif // CHALL_H
