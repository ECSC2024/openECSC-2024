#define _GNU_SOURCE 1

#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ucontext.h>
#include <stdint.h>


typedef uint8_t u8;
typedef uint16_t u16;
typedef uint64_t u64;

#include "data.c"

// #define DEBUG 1
#define ADD_BYTE_PTR 0x56
#define XOR_BYTE_PTR 0x71
#define SUB_BYTE_PTR 0x90
#define ROL_BYTE_PTR 0x13
#define ROR_BYTE_PTR 0x21
#define ADD_QWORD_PTR 0x34
#define SUB_QWORD_PTR 0x98


#define BITMASK(val, low, hi) (val & (((1ull << hi) - 1) ^ ((1ull << low) - 1)))
#define SBITMASK(val, low, hi) BITMASK(val, low, hi) >> low




#define COP "              ,\n\
     __  _.-\"` `'-.\n\
    /||\\'._ __{}_(\n\
    ||||  |'--.__\\\n\
    |  L.(   ^_\\^\n\
    \\ .-' |   _ |\n\
    | |   )\\___/\n\
    |  \\-'`:._]\n\
jgs \\__/;      '-."


void sigsegv_handler(int sig, siginfo_t* info, void* ucontext) {
  (void) info;
  (void) sig;

  ucontext_t* regs = ucontext;
  u8 opcode = SBITMASK(regs->uc_mcontext.gregs[REG_RAX], 23, 31);
  u16 offset = SBITMASK(regs->uc_mcontext.gregs[REG_CR2], 0, 16);
  u8 operand = SBITMASK(regs->uc_mcontext.gregs[REG_CR2], 16, 24);
  char* addr = (char*) regs->uc_mcontext.gregs[REG_R8] + offset;

#ifdef DEBUG
    printf("SIGSEGV handler\n");
    printf("rip: %llx\n", regs->uc_mcontext.gregs[REG_RIP]);
    printf("rax: %llx\ncr2: %llx\n", regs->uc_mcontext.gregs[REG_RAX], regs->uc_mcontext.gregs[REG_CR2]);
    printf("opcode: %x\toffset: %x\toperand: %x\n", opcode, offset, operand);
    printf("operating on address: %p\n", addr);
#endif

  regs->uc_mcontext.gregs[REG_RIP] += 7;

  switch (opcode) {
  case ADD_BYTE_PTR:
    *addr += operand;
    break;
  case XOR_BYTE_PTR:
    *addr ^= operand;
    break;
  default:
    exit(-SIGSEGV);
  }
}



void sigtrap_handler(int sig, siginfo_t* info, void* ucontext) {
  (void) info;
  (void) sig;
  ucontext_t* regs = ucontext;

  u8 opcode = SBITMASK(regs->uc_mcontext.gregs[REG_RAX], 23, 31);
  u16 offset = SBITMASK(regs->uc_mcontext.gregs[REG_RDI], 0, 16);
  u8 operand = SBITMASK(regs->uc_mcontext.gregs[REG_RDI], 16, 24);
  char* addr = (char*) regs->uc_mcontext.gregs[REG_R8] + offset;

#ifdef DEBUG
    printf("SIGTRAP handler\n");
    printf("rip: %llx\n", regs->uc_mcontext.gregs[REG_RIP]);
    printf("rax: %llx\nrdi: %llx\nr8: %llx\n", regs->uc_mcontext.gregs[REG_RAX], regs->uc_mcontext.gregs[REG_RDI], regs->uc_mcontext.gregs[REG_R8]);
    printf("opcode: %x\toffset: %x\toperand: %x\n", opcode, offset, operand);
    printf("operating on address: %p\n", addr);
#endif

  switch (opcode) {
  case SUB_BYTE_PTR:
    *addr -= operand;
    break;
  case ROL_BYTE_PTR:
    asm(
        ".intel_syntax noprefix\n"
        "mov bl, byte ptr [%0]\n"
        "mov cl, %1\n"
        "rol bl, cl\n"
        "mov byte ptr [%0], bl\n"
        ".att_syntax\n"
        :
        : "r" (addr), "r" (operand)
        : "bl", "cl", "memory"
        );
    break;
  case ROR_BYTE_PTR:
    asm(
        ".intel_syntax noprefix\n"
        "mov bl, byte ptr [%0]\n"
        "mov cl, %1\n"
        "ror bl, cl\n"
        "mov byte ptr [%0], bl\n"
        ".att_syntax\n"
        :
        : "r" (addr), "r" (operand)
        : "bl", "cl", "memory"
        );
    break;

  default:
    exit(-SIGTRAP);
  }
}


void sigill_handler(int sig, siginfo_t* info, void* ucontext) {
  (void) info;
  (void) sig;
  ucontext_t* regs = ucontext;

  u8 opcode = SBITMASK(regs->uc_mcontext.gregs[REG_RAX], 23, 31);
  u16 offset = SBITMASK(regs->uc_mcontext.gregs[REG_RDI], 0, 16);
  u8 operand = SBITMASK(regs->uc_mcontext.gregs[REG_RDI], 16, 24);
  char* addr = (char*) regs->uc_mcontext.gregs[REG_R8] + offset;
  u64 operand2 = regs->uc_mcontext.gregs[REG_RDX];
  u64* val = NULL;


  regs->uc_mcontext.gregs[REG_RIP] += 2;


#ifdef DEBUG
    printf("SIGILL handler\n");
    printf("rip: %llx\n", regs->uc_mcontext.gregs[REG_RIP]);
    printf("rax: %llx\nrdi: %llx\nr8: %llx\n", regs->uc_mcontext.gregs[REG_RAX], regs->uc_mcontext.gregs[REG_RDI], regs->uc_mcontext.gregs[REG_R8]);
    printf("opcode: %x\toffset: %x\toperand: %x\n", opcode, offset, operand);
    printf("operating on address: %p\n", addr);
#endif

    switch (opcode) {
    case SUB_QWORD_PTR:
      val = (u64*) addr;
      *val -= operand2;
      break;
    default:
      exit(-SIGILL);
    }
}


void sigfpe_handler(int sig, siginfo_t* info, void* ucontext) {
  (void) info;
  (void) sig;
  ucontext_t* regs = ucontext;

  u8 opcode = SBITMASK(regs->uc_mcontext.gregs[REG_RAX], 23, 31);
  u16 offset = SBITMASK(regs->uc_mcontext.gregs[REG_RDI], 0, 16);
  u8 operand = SBITMASK(regs->uc_mcontext.gregs[REG_RDI], 16, 24);
  u64 operand2 = regs->uc_mcontext.gregs[REG_RDX];
  char* addr = (char*) regs->uc_mcontext.gregs[REG_R8] + offset;
  u64* val = NULL;

#ifdef DEBUG
    printf("SIGFPE handler\n");
    printf("rip: %llx\n", regs->uc_mcontext.gregs[REG_RIP]);
    printf("rax: %llx\nrdi: %llx\nr8: %llx\n", regs->uc_mcontext.gregs[REG_RAX], regs->uc_mcontext.gregs[REG_RDI], regs->uc_mcontext.gregs[REG_R8]);
    printf("opcode: %x\toffset: %x\toperand: %x\n", opcode, offset, operand);
    printf("operating on address: %p\n", addr);
#endif


    regs->uc_mcontext.gregs[REG_RIP] += 3;

    switch (opcode) {
    case ROR_BYTE_PTR:
      asm(
        ".intel_syntax noprefix\n"
        "mov bl, byte ptr [%0]\n"
        "mov cl, %1\n"
        "ror bl, cl\n"
        "mov byte ptr [%0], bl\n"
        ".att_syntax\n"
        :
        : "r" (addr), "r" (operand)
        : "bl", "cl", "memory"
        );
    break;
    case ADD_QWORD_PTR:
      val = (u64*) addr;
      *val += operand2;
      break;

    default:
      exit(-SIGFPE);
    }
}


void scrambler(u8*);

int main() {
  u8 flag_ro[0x30];
  u8 flag_rw[0x30];

  struct sigaction sigsegv_action = {
    .sa_sigaction = sigsegv_handler,
    .sa_flags = SA_SIGINFO,
    .sa_mask = {0},
  };
  struct sigaction sigtrap_action = {
    .sa_sigaction = sigtrap_handler,
    .sa_flags = SA_SIGINFO,
    .sa_mask = {0},
  };
  struct sigaction sigill_action = {
    .sa_sigaction = sigill_handler,
    .sa_flags = SA_SIGINFO,
    .sa_mask = {0},
  };
  struct sigaction sigfpe_action = {
    .sa_sigaction = sigfpe_handler,
    .sa_flags = SA_SIGINFO,
    .sa_mask = {0},
  };

  sigaction(SIGSEGV, &sigsegv_action, NULL);
  sigaction(SIGTRAP, &sigtrap_action, NULL);
  sigaction(SIGILL, &sigill_action, NULL);
  sigaction(SIGFPE, &sigfpe_action, NULL);


  memset(flag_ro, 0, 0x30);
  read(STDIN_FILENO, flag_ro, 0x30);
  for (int i = 0; i < 0x30; i++) {
    if (flag_ro[i] == '\n') {
      flag_ro[i] = '\0';
    }
  }
  memcpy(flag_rw, flag_ro, 0x30);

  scrambler((u8*) flag_rw);


#ifdef DEBUG
    for (int i = 0; i < 0x30; i++) {
      printf("%02hhx: %02hhx %02hhx", i, flag_rw[i], target[i]);
      if (flag_rw[i] != target[i]) {
        printf(" DIFFERENT");
      }
      puts("");
    }
#endif

  printf("%s\nHold up! Let's check your clown license\n", COP);

  if (!memcmp(flag_rw, target, 0x30)) {
    puts("All clear, m8");
    printf("openECSC{%s}\n", flag_ro);
  } else {
    puts("Nope, you need to go back to clown school.");
  }
  return 0;
}
