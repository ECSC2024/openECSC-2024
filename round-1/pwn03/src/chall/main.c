#include <asm-generic/errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <stddef.h>

unsigned g_cur_rover_idx = 0;

#define ROVER_NAME_LEN 0x100
#define ROVER_PLANET_LEN  0x100
#define JOKE_LEN 0x20

struct __attribute__((packed)) rover {
    uint8_t weight;
    uint8_t x, y, z;
    uint8_t temperature;
    uint8_t battery;
    char planet[ROVER_PLANET_LEN];
    char name[ROVER_NAME_LEN];
    void (*action)(void);
};

struct rover g_rovers[] = {
    {
        .weight = 150,
        .x = 0, .y = 0, .z = 0,
        .temperature = 25,
        .battery = 100,
        .planet = "Mars",
        .name = "Curiosity 2.0",
        .action = NULL
    },
    {
        .weight = 120,
        .x = 10, .y = 15, .z = 1,
        .temperature = 250,
        .battery = 85,
        .planet = "Europa",
        .name = "Ice Explorer",
        .action = NULL
    },
    {
        .weight = 200,
        .x = 20, .y = 5, .z = 0,
        .temperature = 130,
        .battery = 75,
        .planet = "Venus",
        .name = "Sulfur Trekker",
        .action = NULL
    },
    {
        .weight = 140,
        .x = 5, .y = 20, .z = 0,
        .temperature = 12,
        .battery = 90,
        .planet = "Titan",
        .name = "Methane Surfer",
        .action = NULL
    },
    {
        .weight = 165,
        .x = 30, .y = 10, .z = 0,
        .temperature = 6,
        .battery = 95,
        .planet = "Pluto",
        .name = "Ice Miner",
        .action = NULL
    },
    {
        .weight = 130,
        .x = 0, .y = 25, .z = 0,
        .temperature = 46,
        .battery = 70,
        .planet = "Mercury",
        .name = "Solar Glider",
        .action = NULL
    },
    {
        .weight = 180,
        .x = 15, .y = 15, .z = 0,
        .temperature = 120,
        .battery = 80,
        .planet = "Neptune",
        .name = "Storm Navigator",
        .action = NULL
    },
    {
        .weight = 155,
        .x = 25, .y = 0, .z = 0,
        .temperature = 20,
        .battery = 65,
        .planet = "Moon",
        .name = "Lunar Walker",
        .action = NULL
    },
    {
        .weight = 190,
        .x = 35, .y = 20, .z = 0,
        .temperature = 65,
        .battery = 88,
        .planet = "Callisto",
        .name = "Ice Ranger",
        .action = NULL
    },
    {
        .weight = 110,
        .x = 0, .y = 30, .z = 0,
        .temperature = 60,
        .battery = 92,
        .planet = "Venus",
        .name = "Cloud Dancer",
        .action = NULL
    },
    {
        .weight = 175,
        .x = 40, .y = 5, .z = 0,
        .temperature = 1,
        .battery = 77,
        .planet = "Enceladus",
        .name = "Ice Fisher",
        .action = NULL
    },
    {
        .weight = 160,
        .x = 10, .y = 40, .z = 0,
        .temperature = 45,
        .battery = 83,
        .planet = "Mars",
        .name = "Dust Racer",
        .action = NULL
    },
    {
        .weight = 145,
        .x = 20, .y = 25, .z = 0,
        .temperature = 81,
        .battery = 78,
        .planet = "Titan",
        .name = "Hydrocarbon Hunter",
        .action = NULL
    },
    {
        .weight = 130,
        .x = 45, .y = 10, .z = 0,
        .temperature = 244,
        .battery = 60,
        .planet = "Io",
        .name = "Volcano Voyager",
        .action = NULL
    },
    {
        .weight = 170,
        .x = 30, .y = 35, .z = 0,
        .temperature = 90,
        .battery = 85,
        .planet = "Ganymede",
        .name = "Magnetic Mapper",
        .action = NULL
    }

};

void die(char *str) {
    printf("%s\n", str);
    exit(1);
}

int read_exactly(int fd, void *buf, size_t size)
{
    size_t done = 0;        
    while (done <= size) {
        ssize_t count = read(fd, (char *)buf + done, 1);
        if (count <= 0)
            return -1;
        done += count;
    }
    return 0;
}

void cmd_get_planet() { 
    struct rover *r = &g_rovers[g_cur_rover_idx];
    printf("Planet: %s\n", r->planet);
}

void cmd_get_name() { 
    struct rover *r = &g_rovers[g_cur_rover_idx];
    printf("Name: %s\n", r->name);
}

void cmd_set_planet() {
    struct rover *r = &g_rovers[g_cur_rover_idx];
    unsigned inp_size;
    char pad[0x20];

    printf("Send new planet size: ");

    if (scanf("%u", &inp_size) != 1)
        die("err");

    if (inp_size > ROVER_PLANET_LEN)
        die("Invalid planet len");

    printf("New planet: ");
    read_exactly(0, r->planet, inp_size);
}

void cmd_set_name() {
    struct rover *r = &g_rovers[g_cur_rover_idx];
    unsigned inp_size;

    printf("Send new name size: ");

    if (scanf("%u", &inp_size) != 1)
        die("err");

    if (inp_size > ROVER_NAME_LEN)
        die("Invalid name len");

    printf("New name: ");
    read_exactly(0, r->name, inp_size);
}

void cmd_move_rover() {
    struct rover *r = &g_rovers[g_cur_rover_idx];
    printf("Send coordinates (x y z): ");

    if (scanf("%hhu %hhu %hhu", &(r->x), &(r->y), &(r->z)) != 3)
        die("err");

    puts("Coordinates updated!");
}

void cmd_full_info()  { 
    struct rover *r = &g_rovers[g_cur_rover_idx];
    printf("Name: %s\n", r->name);
    printf("Planet: %s\n", r->planet);
    printf("Position (x, y, z): %hhu - %hhu - %hhu\n", r->x, r->y, r->z);
    printf("Battery: %hhu%%\n", r->battery);
    printf("Temperature: %hhu%%\n", r->temperature);
    printf("Weight: %hhu%%\n", r->weight);
}

void (*const g_actions[])(void) = {
    cmd_get_planet, cmd_set_planet,
    cmd_get_name, cmd_set_name,
    cmd_move_rover,
    cmd_full_info
};

const char *g_action_names[] = {
    "Get planet", "Set planet",
    "Get name", "Set name",
    "Move rover",
    "Full info"
};

void opt_choose_rover() {
    unsigned idx;
    unsigned n_max_rovers = sizeof(g_rovers) / sizeof(g_rovers[0]);

    puts("[Rover list]");
    puts("========================");

    for (int i = 0; i < n_max_rovers; i++)
        printf("[%d] %s\n", i, g_rovers[i].name);

    puts("========================");

    printf("Choose the rover: ");
    if (scanf("%u", &idx) != 1)
        die("err");

    if (idx >= n_max_rovers)
        die("Invalid idx");

    g_cur_rover_idx = idx;

    puts("Rover selected!");
}

void opt_send_cmd() {
    unsigned idx;
    unsigned cur_action_idx;
    unsigned n_actions = sizeof(g_actions) / sizeof(g_actions[0]);

    puts("[Action list]");
    puts("========================");

    for (int i = 0; i < n_actions; i++)
        printf("[%d] %s\n", i, g_action_names[i]);

    puts("========================");

    printf("Choose the action: ");
    if (scanf("%u", &idx) != 1)
        die("err");

    if (idx >= n_actions)
        die("Invalid idx");

    cur_action_idx = idx;

    printf("Sending command: %s\n", g_action_names[cur_action_idx]);

    for (int i = 0; i < 10; i++) {
        printf(". ");
        usleep(100000);
    }
    puts("");
    
    g_rovers[g_cur_rover_idx].action = g_actions[cur_action_idx];

    puts("Done!");

}

void opt_execute_cmd() {
    if (g_rovers[g_cur_rover_idx].action == NULL) {
        puts("Command not selected");
        return;
    }

    puts("Executing command on the rover....");
    g_rovers[g_cur_rover_idx].action();
    puts("Done!");
}

unsigned get_option() {
    unsigned option;

    puts("1. Choose rover");
    puts("2. Send cmd to rover");
    puts("3. Execute cmd on rover");

    printf("Option: ");
    if (scanf("%u", &option) != 1)
        die("err");

    return option;
}


void init() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    #define VALIDATE_ARCHITECTURE \
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, (offsetof(struct seccomp_data, arch))), \
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, AUDIT_ARCH_PPC64LE, 1, 0), \
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL)

    #define EXAMINE_SYSCALL \
        BPF_STMT(BPF_LD+BPF_W+BPF_ABS, (offsetof(struct seccomp_data, nr)))

    #define ALLOW_SYSCALL(name) \
        BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_##name, 0, 1), \
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)

    #define KILL_PROCESS \
        BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL)

	struct sock_filter seccomp_filter[] = {
		VALIDATE_ARCHITECTURE,
		EXAMINE_SYSCALL,
		ALLOW_SYSCALL(exit),
		ALLOW_SYSCALL(exit_group),
		ALLOW_SYSCALL(clock_nanosleep),
		ALLOW_SYSCALL(openat),
		ALLOW_SYSCALL(read),
		ALLOW_SYSCALL(write),
		KILL_PROCESS,
	};

    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(seccomp_filter) / sizeof(struct sock_filter)),
        .filter = (struct sock_filter*)&seccomp_filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
        die("prctl(NO_NEW_PRIVS)");

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0, 0))
        die("prctl(PR_SET_SECCOMP)");

    puts("Init done!");
}

int main() {
    unsigned option;
    unsigned inp_size;
    char buf[0x28] = {0};

    init();

    puts("Welcome to the Rover Management System. First of all, I need to verify you're an actual human being. So, please, tell me a funny joke!");
    printf("Joke size: ");

    if (scanf("%u", &inp_size) != 1)
        die("err");

    if (inp_size > JOKE_LEN)
        die("Invalid joke len");

    printf("Joke: ");
    read_exactly(0, buf, inp_size);
    puts("Hahaha! You're fun.");

    while (1) {
        option = get_option();
        switch (option) {
            case 1:
                opt_choose_rover();
                break;
            case 2:
                opt_send_cmd();
                break;
            case 3:
                opt_execute_cmd();
                break;
            default:
                die("Uknown option");
                break;
        }
    }

    return 0;
}
