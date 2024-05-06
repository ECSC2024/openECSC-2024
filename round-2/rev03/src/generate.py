import random

# 20x20 matrix with inverse in Zmod256
matrix = [(17, 199, 0, 0, 0, 252, 0, 0, 0, 0, 124, 0, 0, 0, 0, 249, 0, 0, 0, 59),
 (50, 18, 0, 149, 0, 0, 0, 0, 0, 0, 138, 0, 0, 0, 0, 0, 0, 0, 0, 217),
 (0, 0, 0, 175, 0, 0, 0, 0, 0, 128, 0, 0, 0, 103, 0, 31, 0, 0, 36, 0),
 (192, 0, 0, 65, 0, 240, 0, 154, 0, 0, 178, 149, 172, 0, 0, 0, 0, 0, 0, 0),
 (0, 0, 0, 120, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 183, 0),
 (0, 71, 0, 0, 0, 187, 175, 40, 183, 144, 0, 174, 0, 0, 0, 0, 0, 1, 0, 0),
 (206, 0, 0, 241, 0, 0, 0, 0, 233, 0, 0, 231, 0, 0, 0, 192, 188, 0, 0, 140),
 (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 117, 0, 0, 46, 0, 67, 107, 0, 0, 0),
 (0, 0, 0, 0, 0, 0, 0, 252, 0, 0, 0, 113, 0, 0, 0, 0, 138, 0, 0, 0),
 (0, 0, 101, 0, 0, 0, 0, 192, 0, 25, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
 (0, 0, 67, 0, 0, 127, 16, 0, 0, 0, 39, 251, 0, 0, 0, 0, 17, 0, 0, 47),
 (135, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 222, 0, 0, 0, 0, 0, 0),
 (0, 0, 0, 0, 165, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 153, 0, 252),
 (0, 0, 157, 0, 0, 97, 13, 0, 0, 0, 20, 34, 0, 23, 255, 0, 0, 11, 88, 0),
 (0, 0, 0, 166, 0, 0, 0, 0, 10, 0, 0, 0, 139, 0, 0, 0, 56, 0, 221, 0),
 (0, 0, 160, 0, 0, 0, 199, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
 (0, 241, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 83, 0, 186),
 (0, 0, 163, 0, 43, 25, 0, 218, 195, 0, 81, 0, 0, 0, 0, 0, 0, 0, 0, 0),
 (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 98, 0, 0, 113, 88, 0),
 (245, 156, 0, 0, 0, 0, 0, 117, 0, 0, 0, 11, 0, 0, 0, 177, 0, 0, 0, 0)]

c = (131, 106, 208, 182, 233, 37, 146, 61, 5, 241, 45, 37, 135, 39, 5, 194, 223, 244, 55, 64)

N = 20
assert len(matrix) == len(matrix[0]) == len(c) == N

flag_start = b'openECSC{'
flag_end = b'}'
flag_inner = b'ju57_s0m3_fancy_n0p5'
flag = flag_start + flag_inner + flag_end

assert len(flag_inner) == N

res = []
for i in range(N):
	res.append((sum(matrix[i][j] * flag_inner[j] for j in range(N)) + c[i]) % 256)

program = rf'''#include <stdio.h>
#include <string.h>

#define S1(x) #x
#define S2(x) S1(x)

#define OBFUSCATE __asm__ volatile ( \
	"call .LgKmbA"S2(__LINE__)"\n" /* Call next instruction (push rip to stack) */ \
	".LgKmbA"S2(__LINE__)":\n" 	  /* Label to call (__LINE__ trick to get uniq label) */ \
	"addq $6, (%rsp)\n" 	  	  /* Increment rip by 6 (size of addq and retq) */ \
	"ret\n"					  	  /* Pop rip (execute next instr) */ \
);

int main() {{
	char flag[{len(flag)+1}];
	int correct = 0;
	unsigned char x;
	char *input = &flag[{len(flag_start)}];
'''

main = []
main.append(f'fgets(flag, {len(flag)+1}, stdin);\n')
main.append(f'if (strncmp(flag, "{flag_start.decode()}", {len(flag_start)}) != 0) goto end;\n')
main.append(f'if (flag[{len(flag)-1}] != \'{flag_end.decode()}\') goto end;\n')

for i in range(N):
	main.append(f'x = {c[i]};\n')
	main.extend([f'x += input[{j}] * {matrix[i][j]};\n' for j in range(N) if matrix[i][j]])
	main.append(f'if (x != {res[i]}) goto end;\n')

main.append('correct = 1;\n')

# inject obfuscation
rand = random.Random(1337)
insert_at = rand.sample(range(len(main)), len(main)//3)
for ia in sorted(insert_at, reverse=True):
	main.insert(ia, 'OBFUSCATE\n')

program += ''.join(f'\t{m}' for m in main)

program += '\tend:\n'
program += '\tputs(correct ? "Correct!" : "Wrong!");\n'
program += '\treturn 0;\n'
program += '}'

print(program)