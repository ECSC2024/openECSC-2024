// SORRY FOR THE INCREDIBLY UGLY CODE.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <unistd.h>
#include <err.h>
#include <sys/types.h>
#include <sys/wait.h>

void setupbuf(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

int read_exactly(int fd, void *buf, size_t size) {
    size_t done = 0;
    while (done != size) {
        ssize_t count = read(fd, (char *)buf + done, size - done);
        if (count <= 0)
            return -1;
        done += count;
    }
    return 0;
}

void *stack_start;
long regs[17];

#define CODE_SIZE 0x200
#define STACK_SIZE 0x100
#define SP 16
#define NUM_REGS (int) (sizeof(regs) / sizeof(long) - 1)

struct __attribute__((packed)) add {
    unsigned char src: 4;
    unsigned char dst: 4;
};

struct __attribute__((packed)) sub {
    unsigned char src: 4;
    unsigned char dst: 4;
};

struct __attribute__((packed)) mul {
    unsigned char src: 4;
    unsigned char dst: 4;
};

struct __attribute__((packed)) div {
    unsigned char src: 4;
    unsigned char dst: 4;
};

struct __attribute__((packed)) and {
    unsigned char src: 4;
    unsigned char dst: 4;
};

struct __attribute__((packed)) or {
    unsigned char src: 4;
    unsigned char dst: 4;
};

struct __attribute__((packed)) xor {
    unsigned char src: 4;
    unsigned char dst: 4;
};

struct __attribute__((packed)) shl {
    unsigned char src: 4;
    unsigned char dst: 4;
};

struct __attribute__((packed)) shr {
    unsigned char src: 4;
    unsigned char dst: 4;
};

struct __attribute__((packed)) push {
    unsigned char size: 2;
    union val {
        unsigned char reg: 4;
        unsigned char imm_8: 8;
        unsigned short imm_16: 16;
    } val;
};

struct __attribute__((packed)) pop {
    unsigned char dst: 4;
};

struct __attribute__((packed)) mov {
    unsigned char src: 4;
    unsigned char dst: 4;
};

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
struct __attribute__((packed)) save {

};

struct __attribute__((packed)) restore {

};
#pragma GCC diagnostic pop

struct __attribute__((packed)) set {
    unsigned short imm_16: 16;
    unsigned char dst: 4;
};

struct __attribute__((packed)) instr {
    unsigned char opcode;
    union op {
        struct add add;
        struct sub sub;
        struct mul mul;
        struct div div;
        struct and and;
        struct or or;
        struct xor xor;
        struct shl shl;
        struct shr shr;
        struct push push;
        struct pop pop;
        struct mov mov;
        struct save save;
        struct restore restore;
        struct set set;
    } op;
};

#define OPCODE_ADD 0x0
#define OPCODE_SUB 0x1
#define OPCODE_MUL 0x2
#define OPCODE_DIV 0x3
#define OPCODE_AND 0x4
#define OPCODE_OR  0x5
#define OPCODE_XOR 0x6
#define OPCODE_SHL 0x7
#define OPCODE_SHR 0x8
#define OPCODE_PUSH 0x9
#define OPCODE_POP 0xa
#define OPCODE_MOV 0xb
#define OPCODE_SAVE 0xc
#define OPCODE_RESTORE 0xd
#define OPCODE_SET 0xe

#define SIZE_IMM_8 0x0
#define SIZE_IMM_16 0x1
#define SIZE_REG 0x2

int parse(struct instr *instr) {
    switch (instr->opcode) {
        case OPCODE_ADD:
            regs[instr->op.add.dst] += regs[instr->op.add.src];
            break;
        case OPCODE_SUB:
            regs[instr->op.sub.dst] -= regs[instr->op.sub.src];
            break;
        case OPCODE_MUL:
            regs[instr->op.mul.dst] *= regs[instr->op.mul.src];
            break;
        case OPCODE_DIV:
            regs[instr->op.div.dst] /= regs[instr->op.div.src];
            break;
        case OPCODE_AND:
            regs[instr->op.and.dst] &= regs[instr->op.and.src];
            break;
        case OPCODE_OR:
            regs[instr->op.or.dst] |= regs[instr->op.or.src];
            break;
        case OPCODE_XOR:
            regs[instr->op.xor.dst] ^= regs[instr->op.xor.src];
            break;
        case OPCODE_SHL:
            regs[instr->op.shl.dst] <<= regs[instr->op.shl.src];
            break;
        case OPCODE_SHR:
            regs[instr->op.shr.dst] >>= regs[instr->op.shr.src];
            break;
        case OPCODE_PUSH:
            switch (instr->op.push.size) {
                case SIZE_IMM_8:
                    if (regs[SP] < (long) stack_start - STACK_SIZE + 1)
                        errx(1, "Segmentation fault");
                    regs[SP] -= 1;
                    *(char *) regs[SP] = instr->op.push.val.imm_8;
                    break;
                case SIZE_IMM_16:
                    if (regs[SP] < (long) stack_start - STACK_SIZE + 2)
                        errx(1, "Segmentation fault");
                    regs[SP] -= 2;
                    *(short *) regs[SP] = instr->op.push.val.imm_16;
                    break;
                case SIZE_REG:
                    if (regs[SP] < (long) stack_start - STACK_SIZE + 8)
                        errx(1, "Segmentation fault");
                    printf("push reg: %d\n", instr->op.push.val.reg);
                    regs[SP] -= 8;
                    *(long *) regs[SP] = regs[instr->op.push.val.reg];
                    break;
                default:
                    return -1;
            }
            break;
        case OPCODE_POP:
            if (regs[SP] > (long) stack_start - 8)
                errx(1, "Segmentation fault");

            regs[instr->op.pop.dst] = *(long *) regs[SP];
            regs[SP] += 8;
            break;
        case OPCODE_MOV:
            regs[instr->op.mov.dst] = regs[instr->op.mov.src];
            break;
        case OPCODE_SAVE:
            if (regs[SP] < (long) ((long) stack_start - STACK_SIZE + (NUM_REGS * 8)))
                errx(1, "Segmentation fault");
            for (int i = 0; i < NUM_REGS; i++) {
                regs[SP] -= 8;
                *(long *) regs[SP] = regs[i];
            }
            break;
        case OPCODE_RESTORE:
            if (regs[SP] > (long) stack_start + (NUM_REGS * 8))
                errx(1, "Segmentation fault");
            for (int i = NUM_REGS - 1; i >= 0; i--) {
                regs[i] = *(long *) regs[SP];
                regs[SP] += 8;
            }
            break;
        case OPCODE_SET:
            regs[instr->op.set.dst] = instr->op.set.imm_16;
            break;
        default:
            return -1;
    }
    return 0;
}

long vm(char *code, unsigned long code_size) {

    char stack[STACK_SIZE];

    stack_start = (void *) ((long) stack + STACK_SIZE);
    regs[SP] = (long) stack_start;

    memset(stack, 0, STACK_SIZE);
    
    for (size_t i = 0; i < code_size; i += sizeof(struct instr))
        if (parse((struct instr *) &code[i]))
            break;

    return regs[0];
}

void child(int *pipefd, char *code, unsigned long code_size) {

    long result;

    if (close(pipefd[0]) == -1)
        errx(1, "Close pipe");
    
    if (close(STDIN_FILENO) == -1)
        errx(1, "Close stdin");
    
    if (close(STDOUT_FILENO) == -1)
        errx(1, "Close stdout");

    result = vm(code, code_size);

    if (write(pipefd[1], &result, sizeof(result)) == -1)
            errx(1, "Write pipe");
    
    if (close(pipefd[1]) == -1)
        errx(1, "Close pipe");

    exit(0);    
}

int main() {

    char banner[] = "\n"
    "   _____ ____             __          __   \n"
    "  |__  // __ \\   ___     / /___  ____/ /__ \n"
    "   /_ </ / / /  / _ \\   / / __ \\/ __  / _ \\\n"
    " ___/ / /_/ /  /  __/  / / /_/ / /_/ /  __/\n"
    "/____/\\____/   \\___/  /_/\\____/\\__,_/\\___/ \n"
    "\n";

    char code[CODE_SIZE];
    unsigned long input_size;
    long result;
    int pipefd[2];
    int pid;

    puts(banner);
    setupbuf();

    memset(code, 0, CODE_SIZE);
    puts("Code size (bytes): ");
    if (scanf("%lu", &input_size) != 1)
        errx(1, "Invalid size");
    
    if (input_size > sizeof(code) || input_size % sizeof(struct instr) != 0)
        errx(1, "Invalid size");

    puts("Code: ");
    if (read_exactly(0, code, input_size) != 0)
        errx(1, "Read error");

    if (pipe(pipefd) == -1)
        errx(1, "Pipe");

    pid = fork();
    if (pid == -1)
        errx(1, "Fork");

    if (!pid)
        child(pipefd, code, input_size);

    if (close(pipefd[1]) == -1)
        errx(1, "Close pipe");

    if (read(pipefd[0], &result, sizeof(result)) == -1)
            errx(1, "Read pipe");
    
    printf("Result: 0x%lx\n", result);

    if (close(pipefd[0]) == -1)
        errx(1, "Close pipe");

    waitpid(pid, NULL, 0);

    exit(0);
}
