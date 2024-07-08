#include <unistd.h>

// Defines
#define MAX_N_BLOCKS 8U
#define BLOCK_SIZE 8U
#define KEY_SIZE 8U
#define PIPE_BUF 4096U

// Structs
struct ctx_data {
    unsigned int n_blocks;
    char key[KEY_SIZE];
};

// Prototypes
void setup_io(void);
void print_banner(void);
int menu(void);
ssize_t readn(int fd, char *buf, size_t count);
ssize_t writen(int fd, char *buf, size_t count);
