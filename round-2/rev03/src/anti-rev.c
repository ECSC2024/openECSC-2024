#include <stdio.h>
#include <string.h>

#define S1(x) #x
#define S2(x) S1(x)

#define OBFUSCATE __asm__ volatile ( \
	"call .LgKmbA"S2(__LINE__)"\n" /* Call next instruction (push rip to stack) */ \
	".LgKmbA"S2(__LINE__)":\n" 	  /* Label to call (__LINE__ trick to get uniq label) */ \
	"addq $6, (%rsp)\n" 	  	  /* Increment rip by 6 (size of addq and retq) */ \
	"ret\n"					  	  /* Pop rip (execute next instr) */ \
);

int main() {
	char flag[31];
	int correct = 0;
	unsigned char x;
	char *input = &flag[9];
	fgets(flag, 31, stdin);
	if (strncmp(flag, "openECSC{", 9) != 0) goto end;
	OBFUSCATE
	if (flag[29] != '}') goto end;
	x = 131;
	x += input[0] * 17;
	x += input[1] * 199;
	x += input[5] * 252;
	x += input[10] * 124;
	OBFUSCATE
	x += input[15] * 249;
	x += input[19] * 59;
	if (x != 186) goto end;
	x = 106;
	x += input[0] * 50;
	x += input[1] * 18;
	x += input[3] * 149;
	OBFUSCATE
	x += input[10] * 138;
	x += input[19] * 217;
	if (x != 68) goto end;
	x = 208;
	x += input[3] * 175;
	x += input[9] * 128;
	OBFUSCATE
	x += input[13] * 103;
	x += input[15] * 31;
	x += input[18] * 36;
	if (x != 255) goto end;
	OBFUSCATE
	x = 182;
	x += input[0] * 192;
	OBFUSCATE
	x += input[3] * 65;
	x += input[5] * 240;
	x += input[7] * 154;
	x += input[10] * 178;
	OBFUSCATE
	x += input[11] * 149;
	x += input[12] * 172;
	OBFUSCATE
	if (x != 216) goto end;
	x = 233;
	x += input[3] * 120;
	x += input[18] * 183;
	if (x != 193) goto end;
	x = 37;
	OBFUSCATE
	x += input[1] * 71;
	OBFUSCATE
	x += input[5] * 187;
	x += input[6] * 175;
	OBFUSCATE
	x += input[7] * 40;
	x += input[8] * 183;
	OBFUSCATE
	x += input[9] * 144;
	OBFUSCATE
	x += input[11] * 174;
	x += input[17] * 1;
	if (x != 116) goto end;
	x = 146;
	x += input[0] * 206;
	x += input[3] * 241;
	OBFUSCATE
	x += input[8] * 233;
	OBFUSCATE
	x += input[11] * 231;
	x += input[15] * 192;
	x += input[16] * 188;
	x += input[19] * 140;
	if (x != 155) goto end;
	x = 61;
	OBFUSCATE
	x += input[10] * 117;
	x += input[13] * 46;
	x += input[15] * 67;
	x += input[16] * 107;
	if (x != 124) goto end;
	x = 5;
	OBFUSCATE
	x += input[7] * 252;
	x += input[11] * 113;
	x += input[16] * 138;
	if (x != 110) goto end;
	x = 241;
	x += input[2] * 101;
	OBFUSCATE
	x += input[7] * 192;
	x += input[9] * 25;
	if (x != 225) goto end;
	x = 45;
	x += input[2] * 67;
	x += input[5] * 127;
	OBFUSCATE
	x += input[6] * 16;
	OBFUSCATE
	x += input[10] * 39;
	OBFUSCATE
	x += input[11] * 251;
	x += input[16] * 17;
	x += input[19] * 47;
	if (x != 199) goto end;
	x = 37;
	x += input[0] * 135;
	OBFUSCATE
	x += input[13] * 222;
	OBFUSCATE
	if (x != 229) goto end;
	OBFUSCATE
	x = 135;
	x += input[4] * 165;
	OBFUSCATE
	x += input[6] * 4;
	OBFUSCATE
	x += input[17] * 153;
	x += input[19] * 252;
	if (x != 94) goto end;
	OBFUSCATE
	x = 39;
	OBFUSCATE
	x += input[2] * 157;
	OBFUSCATE
	x += input[5] * 97;
	x += input[6] * 13;
	x += input[10] * 20;
	x += input[11] * 34;
	OBFUSCATE
	x += input[13] * 23;
	x += input[14] * 255;
	OBFUSCATE
	x += input[17] * 11;
	OBFUSCATE
	x += input[18] * 88;
	OBFUSCATE
	if (x != 129) goto end;
	x = 5;
	x += input[3] * 166;
	x += input[8] * 10;
	OBFUSCATE
	x += input[12] * 139;
	OBFUSCATE
	x += input[16] * 56;
	OBFUSCATE
	x += input[18] * 221;
	if (x != 39) goto end;
	x = 194;
	x += input[2] * 160;
	x += input[6] * 199;
	OBFUSCATE
	if (x != 50) goto end;
	x = 223;
	OBFUSCATE
	x += input[1] * 241;
	x += input[17] * 83;
	OBFUSCATE
	x += input[19] * 186;
	if (x != 22) goto end;
	OBFUSCATE
	x = 244;
	x += input[2] * 163;
	x += input[4] * 43;
	x += input[5] * 25;
	x += input[7] * 218;
	x += input[8] * 195;
	OBFUSCATE
	x += input[10] * 81;
	if (x != 212) goto end;
	OBFUSCATE
	x = 55;
	x += input[14] * 98;
	x += input[17] * 113;
	x += input[18] * 88;
	if (x != 57) goto end;
	OBFUSCATE
	x = 64;
	x += input[0] * 245;
	x += input[1] * 156;
	x += input[7] * 117;
	OBFUSCATE
	x += input[11] * 11;
	x += input[15] * 177;
	OBFUSCATE
	if (x != 169) goto end;
	OBFUSCATE
	correct = 1;
	end:
	puts(correct ? "Correct!" : "Wrong!");
	return 0;
}
