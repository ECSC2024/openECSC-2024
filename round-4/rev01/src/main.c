// author: Fabio Zoratti @orsobruno96

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>


#define DEBUG



#include "matrices.c"


double work1[4 * 6];
double work2[4 * 6];


inline void matrix_product(double* m1, double* m2, double* dst, size_t row1, size_t col2, size_t col1) {
  for (size_t i = 0; i < row1; i++) {
    for (size_t k = 0; k < col2; k++) {
      dst[i * row1 + k] = 0;
      for (size_t j = 0; j < col1; j++) {
        dst[i * row1 + k] += m1[i * row1 + j] * m2[j * col1 + k];
      }
    }
  }
}


#ifdef DEBUG
void __attribute__ ((noinline)) print_matrix(char* name, double* mat, size_t row, size_t col) {
  printf("Matrix name %s:\n", name);
  for (size_t i = 0; i < row; i++) {
    for (size_t j = 0; j < col; j++) {
      printf("%.16e ", mat[i * row + j]);
    }
    puts("");
  }
  puts("\n");
}
#endif


inline uint64_t bitmask_magic(uint64_t oldval, uint64_t sub, size_t shift) {
  size_t realshift = 64 - shift - 8;
  uint64_t mask = 0xffll << realshift;
  return (oldval & ~mask) | (sub << realshift);
}

inline void map_flag_in_matrix(char* flag) {
  uint64_t* ptr;
  for (int i = 0; i < 16; i++) {
    ptr = (uint64_t*) &F[i];
    *ptr = bitmask_magic(*ptr, (uint64_t) flag[i], shifts[i]);
  }
}

void do_product(void) {
  matrix_product(A, F, work1, 4, 4, 4);
  matrix_product(work1, B, work2, 4, 4, 4);
  matrix_product(work2, C, work1, 4, 4, 4);
  matrix_product(work1, D, work2, 4, 4, 4);
}


double matrix_distance(double* mat1, double* mat2, size_t row, size_t col) {
  double ret = 0;
  double appo = 0;
  for (size_t i = 0; i < row; i++) {
    for (size_t j = 0; j < col; j++) {
      appo = mat1[i * row + j] - mat2[i * row + j];
      ret += appo*appo;
    }
  }
  return ret;
}


int main(int argc, char* argv[]) {
  char content[0x20];
  if (argc != 2) {
    exit(-1);
  }

  if (sscanf(argv[1], "not_the_flag{%17s}", content) != 1) {
    exit(-1);
  }

  char* occ = strstr(content, "}");
  if (occ) *occ = '\0';

  if (strlen(content) != 16) {
    exit(-1);
  }

  map_flag_in_matrix(content);
  do_product();

  double dist = matrix_distance(E, work2, 4, 4);

  if (dist < 1e-32) {
    printf("Now send me your insults via email, please. Here is your flag: %s\n", argv[1]);
  } else {
    puts("Nope");
    exit(-2);
  }

  return 0;
}
