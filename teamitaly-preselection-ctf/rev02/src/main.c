#include "blowfish.h"
#include <stdio.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <elf.h>

#define printf(...) 


// void hex(uint8_t *data, size_t size) {
// 	for (int i = 0; i < size; i++) {
// 		printf("%02x", data[i] & 0xff);
// 	}
// 	puts("");
// }


uint64_t m[] = {0x40020008000,0x4a0000000000,0x100840,0x100000204,0x6000001000,0x200000000000108,0x4100000020000,0x1000000040000010,0x21bdcdbd9c57ea1e,0x42892e109d2816c8,0x69a4b0e183e87d09,0xf3f63785a2fd5a6d,0x895a1dd2d9080fc6,0xf888c564daaa742f,0x5ffd9b9c33e8523d,0x235a3f27383a552d,0xaa04cd6c1162469b,0x592dd30a8fb5c43a,0x5f79983555b8c0bf,0x56f69efa62529d26,0x2cab3685b93761fb,0xd7ef31a570311757,0xfd71db6bb0f8e0e2,0x84deac43d5cc2aee,0x6fe9f5fdc92ae602,0xe8df3cbdb77a6509,0x9eba72f3be536219,0x22ba32b3df1087de,0x547769661351eb97,0x1ef7764438ff2955,0xa7d40e8c68c61111,0x415d05557dea74c5,0x92c9b0a340fc8b69,0x46496d4c7e796f6c,0x31b227a0583027fa,0xf7dbefc7dc42e729,0xe467731cf725120f,0x2579d1e4698e882c,0x40eba97751741d71,0x582d37e7412ad2a1,0xa92f2a89b091ed3e,0xcf7c467ed08e0d6,0x9f759e63beaf1ad4,0xc21b258bfa50cc92,0x33d1b5fc5d6ff8fb,0x432fe9f468c25adb,0x4812fa87904ee2d,0xec8306fdb9f75fb7,0xf6f7e5140661d4ca,0x6427a249bc4ae7da,0xdeaf263a8d59dfd1,0x868468b0657bc766,0xe197a276c4d3c569,0xcad47abcedc1dce5,0xeef8297b02449a77,0x358c55d89c066288,0xf1151232abe32be7,0x1f1127f616b62eda,0xebb07f0234efac04,0xb7940573199b9ff8,0x388614f0f58c54f8,0x818bbe6869125997,0xb42104358f7626f2,0x3e3e6f2dbec31447,0x2396473593d13bb4,0x54417863f9820f4,0xc16453d25592fafc,0x27f8ddbdc2f0b5bb,0x4491b3b7711b007a,0xef749ab07c9cb3a3,0x21e452152184c697,0xd9dd17cd34ea8604};
uint64_t enc_flag[] = {0xa944aec1fa69f65a, 0x00cc92bda750b866, 0xfd78df8d9d56b1d5, 0x734e67ffc25848f4, 0x0d00ee99da8b3af4, 0xf8b8fdb6f32a527a};

int check(uint8_t *flag) {

	uint64_t current_m[8];
	memcpy(current_m, m, 8 * sizeof(uint64_t));
	for (uint64_t j = 0; j < 64; j += 8){

		uint8_t key = 0;
		for (uint64_t i = j; i < j+8; i++) {
			uint64_t bit = 0;
			uint64_t row = current_m[i-j];
			// printf("%016lx\n", row);

			while (row) {
				// printf("%016lx\n", row);
				if (row & 1) {
					// printf("%ld %d %02x\n", bit, i, key);
					key ^= ((flag[bit / 8] >> (bit % 8)) & 1) << (i % 8);
				}
				row >>= 1;
				bit++;

			}
		}
		printf("%02x\n", key);
		// uint64_t out[8] = {0};
		Blowfish_CBC_Decrypt(&key, 1, &m[j+8], current_m, 8);
		// for (int i = 0; i < 8; i++) {
		// 	printf("%016lx ", out[i]);
		// }
		// printf("\n");
		// memcpy(current_m, out, 8 * sizeof(uint64_t));

		// check that is correct sol
		if (j != 56) {
			uint64_t orsum = 0;
			for (int i = 0; i < 8; i++) {
				orsum |= current_m[i];
			}
			uint64_t bitcnt = 0;
			while (orsum) {
				bitcnt += orsum & 1;
				orsum >>= 1;
			}
			printf("bitcnt: %ld\n", bitcnt);
			if (bitcnt > 24) {
				return 1;
			}
		}
	}

	// for (int i = 0; i < 8; i++) {
	// 	printf("%016lx ", current_m[i]);
	// }
	// printf("\n");

	if (current_m[0] == 0xdeadbeef && current_m[1] == 0xc0ffebabe && current_m[2] == 0xbaad1337 && current_m[3] == 0){
		return 0;
	}

	return 1;
}


#define TOKEN_LEN 8

int hex2b(char *hex, char *buf, size_t size) {
	for (int i = 0; i < size; i++) {
		if (sscanf(hex + 2 * i, "%2hhx", buf + i) != 1) {
			return 1;
		}
	}
	return 0;
}


int main(int argc, char **argv) {
	if (argc != 2) {
		return 1;
	}

	char* token = argv[1];

	if (strlen(token) != TOKEN_LEN*2) {
		// puts("Invalid token length");
		return 1;
	}

	char tokenb[TOKEN_LEN];
    if (hex2b(token, tokenb, TOKEN_LEN) != 0) {
		// puts("Invalid hex");
        return 1;
    }

	// puts(tokenb);
	if (check((uint8_t*)tokenb) != 0) {
		// puts("invalid token");
		return 1;
	}

	// printf("%ld\n", sizeof(enc_flag));
	uint64_t dec_flag[sizeof(enc_flag) / sizeof(uint64_t)];

	Blowfish_CBC_Decrypt((uint8_t*)tokenb, TOKEN_LEN, enc_flag, dec_flag, sizeof(enc_flag)/ sizeof(uint64_t));
	puts((void*)dec_flag);

	return 0;
}

