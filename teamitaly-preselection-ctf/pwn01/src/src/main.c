#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chall_utils.h>

#define MAX_ASYNC_PROCS 0x100

// Global variables
pid_t pids[MAX_ASYNC_PROCS];
int in_pipes[MAX_ASYNC_PROCS][2], out_pipes[MAX_ASYNC_PROCS][2];

void encrypt(struct ctx_data *ctx, char *message, size_t count)
{
    char ciphertext[MAX_N_BLOCKS * BLOCK_SIZE];

    for (size_t i = 0; i < count; i ++) {
        ciphertext[i] = message[i] ^ ctx->key[i % KEY_SIZE];
    }

    write(STDOUT_FILENO, ciphertext, count);
}

void add_message(struct ctx_data *ctx)
{
    int idx = -1;
    ssize_t msg_sz;
    char *message;

    for (int i = 0; i < MAX_ASYNC_PROCS; i++) {
        if (pids[i] == 0) {
            idx = i;
            break;
        }
    }
    if (idx == -1) {
        puts("Cannot process more messages, try collecting some messages first.");
        return;
    }
    printf("Enter message size: ");
    scanf("%ld", &msg_sz);

    if (msg_sz > ctx->n_blocks * BLOCK_SIZE || msg_sz < 0) {
        puts("Invalid message size.");
        return;
    }

    if (pipe(in_pipes[idx])) {
        perror("input pipe");
    }
    if (pipe(out_pipes[idx])) {
        perror("output pipe");
    }
    pids[idx] = fork();

    switch (pids[idx]) {
    case -1:
        perror("fork");
        exit(EXIT_FAILURE);

    case 0:
        close(in_pipes[idx][1]);
        close(out_pipes[idx][0]);
        close(STDERR_FILENO);

        dup2(in_pipes[idx][0], STDIN_FILENO);
        dup2(out_pipes[idx][1], STDOUT_FILENO);

        message = malloc(PIPE_BUF);

        readn(    STDIN_FILENO, message, msg_sz);

        encrypt(ctx, message, msg_sz);

        free(message);

        exit(EXIT_SUCCESS);

    default:
        close(in_pipes[idx][0]);
        close(out_pipes[idx][1]);

        printf("Enter message: ");

        message = malloc(PIPE_BUF);
        msg_sz = readn(STDIN_FILENO, message, msg_sz);
        if (msg_sz == -1) {
            perror("read");
            exit(EXIT_FAILURE);
        }

        writen(in_pipes[idx][1], message, msg_sz);
        free(message);

        printf("PID: %d\n", pids[idx]);

        break;
    }
}

void get_message()
{
    pid_t pid, wpid;
    int idx = -1, status;
    ssize_t count;
    char *ciphertext;

    printf("Enter PID: ");
    scanf("%d", &pid);

    for (int i = 0; i < MAX_ASYNC_PROCS; i++) {
        if (pids[i] == pid) {
            idx = i;
            break;
        }
    }
    if (idx == -1) {
        puts("No such PID found");
        return;
    }

    wpid = waitpid(pid, &status, WNOHANG);
    if (wpid == 0) {
        puts("Process is still running, try again later.");
    } else if (wpid == -1) {
        puts("The encryption process failed, try again.");
        printf("Status: %d\n", status);
    } else {
        printf("Status: %d\n", status);
        ciphertext = malloc(PIPE_BUF);

        count = read(out_pipes[idx][0], ciphertext, PIPE_BUF);
        if (count == -1) {
            perror("read");
            exit(EXIT_FAILURE);
        }
        puts("Ciphertext:");
        writen(STDOUT_FILENO, ciphertext, count);
        puts("");
        free(ciphertext);
    }

    if (wpid != 0) {
        close(in_pipes[idx][1]);
        close(out_pipes[idx][0]);
        pids[idx] = 0;
    }

    return;
}

int main(void)
{
    struct ctx_data *ctx = NULL;

    setup_io();

    print_banner();

    memset(pids, 0, sizeof(pids));
    memset(in_pipes, -1, sizeof(in_pipes));
    memset(out_pipes, -1, sizeof(out_pipes));
    ctx = malloc(sizeof(struct ctx_data));

    printf("Enter key: ");
    readn(STDIN_FILENO, ctx->key, sizeof(ctx->key));
    printf("Enter number of blocks: ");
    scanf("%u", &ctx->n_blocks);

    if (ctx->n_blocks > MAX_N_BLOCKS) {
        puts("Number of blocks unsupported, maybe in next version...");
        exit(EXIT_FAILURE);
    }

    puts("You chose the following key:");
    printf(ctx->key);
    puts("");

    while (1) {
        int choice = menu();
        switch (choice) {
        case 1:
            add_message(ctx);
            break;
        case 2:
            get_message();
            break;
        case 3:
            exit(EXIT_SUCCESS);
        default:
            puts("Invalid choice");
            exit(EXIT_FAILURE);
        }
    }
}
