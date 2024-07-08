#include <stddef.h>
#define BUF_SIZE 0x80

size_t write(int fd, char* buf, size_t sz);
size_t read(int fd, char *buf, size_t sz);
void exit(int code);

extern char const_flag[];
extern char key[];

#define FUCKUP_DISASM() __asm__ (".byte 0xe8, 0x06, 0x00, 0x00, 0x00, 0x48, 0x83, 0x04, 0x24, 0x08, 0xc3, 0xeb, 0xf8")


size_t strlen(const char* str) {
  char* beg = str;
  while (*str != '\0') {
    str++;
  }
  return str - beg;
}


void vigenere_decrypt(char* ciphertext, char* key) {
  for (int i = 0, j = 0; i < strlen(ciphertext); i++, j++) {
    if (j >= strlen(key)) {
      j = 0;
    }

    if (ciphertext[i] < 'a' || ciphertext[i] > 'z') {
      continue;
    }

    FUCKUP_DISASM();
    int shift = key[j] - 'a';
    ciphertext[i] = ((ciphertext[i] - 'a' - shift + 26) % 26) + 'a';
  }
}


void print_string(char* str) {
  int len = strlen(str);
  write(1, str, len);
  char newline = '\n';
  write(1, &newline, 1);
}



void build_flag(char* flag, char* key) {
  int i;
  for (i = 0; i < BUF_SIZE; i++) {
    *flag++ = '\0';
  }
  FUCKUP_DISASM();

  for (i = 0; i < BUF_SIZE; i++) {
    flag[i] = const_flag[2*i];
  }

  for (i = 0; i < 3; i++) {
    FUCKUP_DISASM();
    vigenere_decrypt(flag, key);
  }
}



int strncmp(const char* s1, const char* s2, size_t sz) {
  for (int i = 0; i < sz; i++) {
    if (*s1++ != *s2++) {
      return 1;
    }
  }
  return 0;
}

static inline void deobfuscate_binary(unsigned char* start) {
  unsigned long long addr = (unsigned long long) start;
  unsigned long long size = ((addr + 0xfff) & ~0xfff) - addr;
  unsigned int j = 0;
  unsigned long long keyi[] = {
    0xdeadbeefdeadd0d0,
  };
  unsigned char* key = keyi;

  for (int i = 0; i < size; i++, j++) {
    if (j >= 8) {
      j = 0;
    }
    start[i] ^= key[j];
  }
}


int main() {

  char real_flag[BUF_SIZE];
  char user_flag[BUF_SIZE];

  deobfuscate_binary(&main + 0x100);

  build_flag(real_flag, key);
  FUCKUP_DISASM();

  read(0, user_flag, BUF_SIZE);

  if (strncmp(real_flag, user_flag, BUF_SIZE) == 0) {
    exit(0);
  } else {
    exit(1);
  }

  return 0;
}
