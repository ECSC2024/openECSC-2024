// gcc -Wall -o vm vm.c
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MEM_SIZE (1 << 16)
#define ROM_SIZE (1 << 16)
#define NUM_REGS 5

typedef struct Vm {
    uint16_t ram[MEM_SIZE];
    uint8_t rom[ROM_SIZE];
    uint16_t regs[NUM_REGS];
} vm_t;

#define OP_CODE(o) (((o) >> 4) & 0xF)
#define OP_ARG1(o) (((o) >> 2) & 0x3)
#define OP_ARG2(o) ((o) & 0x3)
#define OP_OPT(o) ((o) & 0x3)

typedef uint8_t vm_OP_t;

enum vm_REG {
    A = 0,
    B = 1,
    C = 2,
    SP = 3,
    IP = 4
};

enum vm_OP_CODE {
    HALT = 0,
    LOAD = 1,
    LOAD_PTR = 2,
    STORE = 3,
    CMP_LT = 4,
    ADD = 5,
    SUB = 6,
    CALL = 7,
    RET = 8,
    JMP = 9,
    JZ = 10,
    JNZ = 11,
    PUSH = 12,
    POP = 13,
    AND = 14,
    NOT = 15
};

#ifdef DBG
#define debug(...) fprintf(stderr, __VA_ARGS__)
#else
#define debug(...)
#endif

// void vm_init(vm_t* vm, uint8_t* program, int program_size)
// {
//     for (int i = 0; i < MEM_SIZE; i++) {
//         vm->rom[i] = i < program_size ? program[i] : 0;
//     }

//     for (int i = 0; i < MEM_SIZE; i++) {
//         vm->ram[i] = 0;
//     }

//     for (int i = 0; i < NUM_REGS; i++) {
//         vm->regs[i] = 0;
//     }
// }

void vm_exec(vm_t* vm)
{
    while (1) {
        vm_OP_t op = *(vm_OP_t*)&vm->rom[vm->regs[IP]++];
        uint16_t* regs = vm->regs;
        uint16_t* ram = vm->ram;
        uint16_t maybe_imm = (vm->rom[vm->regs[IP] + 1] & 0xFF) | ((vm->rom[vm->regs[IP]] << 8) & 0xFF00);
        debug("A: %04x, B: %04x, C: %04x, SP: %04x, IP: %04x\n", vm->regs[A], vm->regs[B], vm->regs[C], vm->regs[SP], vm->regs[IP]);
        debug("op: %hhx, opcode: %d, arg1: %d, arg2: %d, options: %d\n", op, OP_CODE(op), OP_ARG1(op), OP_ARG2(op), OP_OPT(op));
        debug("maybe_imm: %d\n", maybe_imm);

        switch (OP_CODE(op)) {
        case HALT:
            debug("HALT\n");
            return;
        case LOAD:
            debug("LOAD\n");
            regs[IP] += 2;
            regs[OP_ARG1(op)] = maybe_imm;
            break;
        case LOAD_PTR:
            debug("LOAD_PTR\n");
            regs[OP_ARG1(op)] = ram[regs[OP_ARG2(op)]];
            break;
        case STORE:
            debug("STORE\n");
            ram[regs[OP_ARG1(op)]] = regs[OP_ARG2(op)];
            break;
        case CMP_LT:
            debug("CMP_LT\n");
            regs[OP_ARG1(op)] = regs[OP_ARG1(op)] < regs[OP_ARG2(op)];
            break;
        case ADD:
            debug("ADD\n");
            regs[OP_ARG1(op)] += regs[OP_ARG2(op)];
            break;
        case SUB:
            debug("SUB\n");
            regs[OP_ARG1(op)] -= regs[OP_ARG2(op)];
            break;
        case CALL:
            debug("CALL\n");
            ram[--regs[SP]] = regs[IP]+2;
            regs[IP] = maybe_imm;
            break;
        case RET:
            debug("RET\n");
            regs[IP] = ram[regs[SP]++];
            break;
        case JMP:
            debug("JMP\n");
            regs[IP] = maybe_imm;
            break;
        case JZ:
            debug("JZ\n");
            if (regs[OP_ARG1(op)] == 0) {
                regs[IP] = maybe_imm;
            } else {
                regs[IP] += 2;
            }
            break;
        case JNZ:
            debug("JNZ\n");
            if (regs[OP_ARG1(op)] != 0) {
                regs[IP] = maybe_imm;
            } else {
                regs[IP] += 2;
            }
            break;
        case PUSH:
            debug("PUSH\n");
            ram[--regs[SP]] = regs[OP_ARG1(op)];
            break;
        case POP:
            debug("POP\n");
            regs[OP_ARG1(op)] = ram[regs[SP]++];
            break;
        case AND:
            debug("AND\n");
            regs[OP_ARG1(op)] &= regs[OP_ARG2(op)];
            break;
        case NOT:
            debug("NOT\n");
            regs[OP_ARG1(op)] = ~regs[OP_ARG2(op)];
            break;
        }

        debug("--------------------\n");
#ifdef DBG
        getchar();
#endif
    }
}

#define FLAG_SIZE 42
#define INNER_SIZE 32

int main(int argc, char** argv)
{
    if (argc < 2) {
        printf("Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    // read program
    FILE* f = fopen(argv[1], "r");
    if (f == NULL) {
        puts("Error opening file");
        return 1;
    }

    uint8_t program[ROM_SIZE];
    size_t program_size = fread(program, 1, ROM_SIZE, f);

    fclose(f);

    // read flag
    char flag[FLAG_SIZE + 1];
    fgets(flag, FLAG_SIZE + 1, stdin);

    if (strncmp(flag, "openECSC{", 9) != 0 || flag[FLAG_SIZE - 1] != '}') {
        puts("Wrong!");
        return 0;
    }

    vm_t vm = { 0 };
    // vm_init(&vm, program, program_size);

    memcpy(vm.rom, program, program_size);
    memcpy(vm.ram, &flag[9], INNER_SIZE);

    vm_exec(&vm);

    int exit_code = vm.regs[A];
    puts(exit_code != 0 ? "Correct!" : "Wrong!");

    debug("A: %d\n", vm.regs[A]);
    debug("B: %d\n", vm.regs[B]);
    debug("C: %d\n", vm.regs[C]);
    debug("SP: %d\n", vm.regs[SP]);
    debug("IP: %d\n", vm.regs[IP]);

    return 0;
}