# openECSC 2024 - Round 2

## [rev] arxelerated (21 solves)

oh no, my device starts shredding everything I put in it...
```bash
qemu-system-arm -cpu cortex-m3 -machine lm3s6965evb -kernel arxelerated -semihosting -semihosting-config enable=on,target=native -serial mon:stdio
```

Author: Andrea Raineri <@Rising>

## Overview

The challenge hands out two files:
- `arxelerated`
- `out.enc`

`arxelerated` is a bare metal firmware for an ARM Cortex M3 lm3s6965eb board, which can be emulated with `qemu-system-arm`. As both the display and the serial UART of the board are actively used by the firmware, semihosting needs to be activated when executing the code with qemu.
When the program is launched an image is displayed on the qemu emulated LCD and after a character is sent to the UART via command line the image is progressively encrypted.
At the end of the encryption the final encrypted image is dumped on the command line hex formatted.

`out.enc` is the output in hex of the encryption of the image containing the flag

## Solution

To successfully analyze the program the first element to be noticed is that a lot of undefined instructions of the ARM Thumb2 instruction set are being used (the presence of which gives some decompilation problems to common decompilers like Ghidra).
This type of instructions by default trigger an Hard Fault on the processor, but this behaviour can ultimately be overridden by setting a custom exception handler in the processor vector table. This pattern is very commonly used in ARM processors collaboration with coprocessors dedicated to specific computational duties.
In this case a virtual cryptographic coprocessor is implemented.
The coprocessor is implementing a version of the CRAX ARX block cipher (https://sparkle-lwc.github.io/crax), used in CBC mode.

We can recover the original image of the flag by implementing the decryption of the CRAX cipher (and displaying it with a Python script)

## Exploit

### solution_decrypt.c
```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define NSTEPS 10

#define ROT(x, n) (((x) >> (n)) | ((x) << (32-(n))))

#define ALZETTE_INV_(x, y, c)                \
  (x) ^= (c),                               \
  (y) ^= ROT((x), 16), (x) -= ROT((y), 24), \
  (x) ^= (c),                               \
  (y) ^= ROT((x), 31), (x) -= (y),          \
  (x) ^= (c),                               \
  (y) ^= ROT((x), 17), (x) -= ROT((y), 17), \
  (x) ^= (c),                               \
  (y) ^= ROT((x), 24), (x) -= ROT((y), 31)

const uint32_t RCON[] = {0xB7E15162, 0xBF715880, 0x38B4DA56, 0x324E7738, 0xBB1185EB};

static void ADD_KEY(uint32_t a, uint32_t b, uint32_t c, uint32_t d, uint32_t *x, uint32_t *y, const uint32_t *key) {
    // ADD KEY
    *x ^= c;
    *x ^= key[0 + (a%2)];
    *y ^= key[1 + (a%2)];
    *x ^= d;
}

static void ALZETTE_INV(uint32_t x, uint32_t y, uint32_t c, uint32_t *xout, uint32_t *yout) {
    ALZETTE_INV_(x, y, c);
    *xout = x;
    *yout = y;
}

void craxs10_dec_ref(uint32_t *xword, uint32_t *yword, const uint32_t *key)
{
  ADD_KEY(0, 0, 0, 0, xword, yword, key);
  for (int step = NSTEPS-1; step >= 0; step--) {
    ALZETTE_INV(*xword, *yword, RCON[step%5], xword, yword);
    ADD_KEY(step, 0, 0, step, xword, yword, key);
  }
}

unsigned char enc[] = "d0f5d8cadc1abc0b88ab126119fcc36dc9f1cf384fe2b9bc13c172fb575c3b5ac5092173fcfe1b9ca17b463f240356c65e74a2b183f22d847052357674c4d8457e011cfcd77379ad99a75acb079c3cb0f6b8983e594f7501cb4d4c36d52e1a3c7e95f6a82ea6fa718d4567a22efc516d8d2f4f76d6f8da27b2b933de2fdd1013e5b26223c07000d0a3f8d911a7b8b091ddeb3e2bf5c824f2c0025a825b5286516134abb4f6479bd200cddc26edd1ecd4a90c027bbc06c2a22370f83d64de3d841d7c47089fb612c7a3f61b962a18f287d5bade64ff17d18037db1d127cf47e0db8357c9018958e0da88cd5dc9d27d1160f8a97dd8436961d6b64d35bcb1c7a6e8579accfbab901bd09de1509b814805c0b5a9397e68a5f5e154c5b3450e948774a3ae814ff52bb7fcb294895f1ac9ade96abfba4274e09f707a90a39246f545704baaca80fe476ba672a7a7fce87d61066409cbc188e8964e07cc0ab03f3aa4d6e3dc3613e200d4c1d13a29cca8b3440cae3fab72cf0fa136de0f6e3f74ccd3d1644fc5d5213b6e1ad3472ed27182b7710694c98c1d385456564fb926b34c6f594776fad4b93c18a9e7d993a103c6edb820827e833a3baf9ed74ccaaff172225e92be991a80d28d43899a913d3382d94af02f1937e54fcd8dd8d313b7f70f2cadde1034510bf9f9b6e5e20a9bdfa50209aea9b4b534405e63d855ca53b7f4271e0b22beef4672f6d8acb7a547c8e9390bfa3ca48eea098ad015b364e9c135935a8742c5010ff771c03738bcc93f34c5211efcaea9e8b5fd4a53c564e023400528886d6d0a4ff43018940866f5b541c9d224ff20028c6aa9aa926df02d0196c7a84ab8107da08d51ad43866ff20f853c6cf68fdbcafd61e1c24684d1af92d5f32e2247b2b5ae7785d1754b7b893784a98099da621c92a19b7c351f229fbfb1c8c12ac9e41ea1a9b52f16099a4d351a04632429d12e4f7e483477341daa1e62766fe90d098cfc71e98bd6b43192dc85088431064efb806e4c5bb8f245ef6d59798db2bb122c96b500176c1a6bd7b6d171773ff6f47d81ff63af074c9d25b3ff9d815b12d0e8263f742f00c1b6ba3d196634574d84382c55ad829d4dbfcf061c4d2d088b5ccd343327c3a542a644e8957125b51c6bfc89f302ddc2920f49c17d48403aa85d12c37b3fbce756c6e3aa7b82269eac1030452233a68c961bf657cafe65f78b768dc57d2b25d599dd03d2b79d8996fddd307cfca812bee2850ec6a130f880854f1bb96011b797b890bd848a412904cf5ab9c9007cb588acd0a2f406c75403a80faa7bb6831d2c582fe9fa6538e3869a718b906d8bb75010d060eb1dfb3a4e44c0cb3c0712055211d5080f8bb9e3a639d84bad3c9be819394cc824477847fddb7cb8a0e5920262101dbe5f230b2d4ca721a60e1d617718f7a655862399a83460c8f32591fe128cc5e603ebffca5e4a0bf274de5bf218770fc7b1e8a508460fb29d0759a9cd1f7946ae15761d478a2e71931ed2797a34e10c833f8b52ad8f254323a1b35a1480c0200c3b1356c66fcc1c2bf74b18b92548c26f4189ad3e9e54b2305eae4a71e6b7eda0505126912e2fb195fd5534ef8ebb8959df73a19c942a48b49932cddb9dc2b8dffa1efd1a11a48d1f244f1946bfed63e9ffa133694585e677d15bd5d6e347031bb2021aaf58196b0e9ff358cc1fd7f64f79c098c7dc81c2638796d710070b6af0f9294758cbb5fe21792150305ccd0b21a9e89ee60b87497d95394b851e95f3a1d735330377713fe42eaee778c748a0b2d52bda46097d1c991cc13e1877f5e4bf4c7d6e18628011c400ec34a2d9b458c2e4a1d68e95720e910e9385b1433fe50ee5fa774f35bd11759bdb66558752acc74b5c5da0b2ca0b82147c1cd784622002d4eaff8f7a1f812775957c202d1d9b40ca2029318d17ad9463d4ab454c5f23554accc1a8d6b943eb0ffc1de46cbae9d8a0ef75f71efd02ba6f7188789d17ce51c40511f90242ce4ddf3658d2c1bfb0c3a69a79932eff8e863537f65291ca495e0a311be8a741a6a84861aa494ce3c262d49e5e7f6a42d021fb4d9cea1a0328aa4ad501bb84936fd3e2efb33327444ae6c835bbea6303370489996fe6a79e069261ef4c44fbe16549e0f9b7b4b192ecf835c7f80a294f8867f7eef2f2210080eab898be35481a20f60e98012f5614d964ae45057af0b06639329ed9e2fc793da34d26a7bba5887617ca9dd23a0cadac463604428e277baea0e8e0d2b032cf8c52d7806e9af64b981003eded8a2649d1b6527c5a7f2e12fd95701e223a1af08efa9c57226d728663e3a9ef07aa432cf5819dc0caa5bbd983be44d933c7838e4d9685ac0da4e6e08e50525968f767ff6af59102f649772a9bcca06a5b286b1f263ccfa6020595e8b433508c9f1dfced87a1d12bebf9e1a6af65fd0b5f338736abf2a80f0cb40cad72a178fe898e6796664b25cad03bb4e07de5a9dc06e6c4f90bce16d8757998007c96d541e24137acd2ba943b321eaf7c4eb9c1560326465ca175f91588afb9d959faccb91a90dc5b2df2a60f57c3796dd9f1790449565a29e3cc0fdb548556a30c8d30935cea723c280742133103a0befb454e6968ca7ced009f8888facb8e6c001090588905f7f052867e8ebea078d708ed727460a1cb75c21fe7c30427ccbd6878183706bf133eb2e6b801539750d3831ff531d74a5c6ef8e035b149c9c0b0ed7a6847e08ec8455f21caf5b6c106b0c149592334090a52a12559d9f168faa5aafd421696f9c676c12335589d94f2277f0ad75c4a357fe091234e06e629d17e8f3d9a370da391d734be9d4ab3fe3572e958d654db640efab2bf6785241d0e396550fb79ae6fac2cdccb72ac40624daa08147eb21d763867cc3c22fdc15b85c2aaaf09ae77bb39eda64446215903471d6c22437fdaa5d5d4dfaf75d5c085f498fcab98d93f51b63ebb0aa2951f2b98743130d5fd9412eea3db55013b20a4d7374c33e34a0bc092b0c4567b40795cbad21d42aff5a1a3df19c8c634acffd5003e63c9cfe891d2a861202fa8c354d8e0276f3317c6ae1b21882bbfac85478e709f69bd723138de92df369e66a800cfdce7f8a9d9955231906ea51515588c3f9769cddf9cbb90ec19604cb81bc6cd2bf3aa3368f72205db440405a19e1f0c4c1fe071c8beb09c1e88c930f93f5779ad8b5b94b9c728901aeb01df199e53f3359adbee7570876c257e3f82bed483b22131cb787dd8e8a83543763baeea2a27220a9d70f35a2f52dc32958f1727a75ab6014ea74c2f00da0870febe624dfe27482896035bcb3a2da8032d9d45ad012794fcf4da3cc9da445de840483c36db0b12c0267cbb0ee1cfd8f474754f34ee91337eb3a4c24c16901b27faf12b5625d787875ca5953bcd6450356e06ebc369506356370127f9ed49982e7e08d4c3bac2f9c23f6536c2c5d3ed2813632a7de24fdb420b4168f4c2a10d9a01d6f6cbbffbdadd172f5b153c946ae72fa7e7d7f1fab4bad9506bbde417cf3797358c07e65a385ad2543bad6a43902676f753035a5d593ed602e47a69767100d96a34b3517d618eb7c35085aed6eb2df87425220776dd44f3f5f6b049d432a7ab178f6b829a84b9492fe7e72b05351a929acd1e2039f4487757f8b3892f48d8f4216b8f3eaa86c998f3b49a614141121fdfd6566c691733e1d33d845aecf34dd8f9e5aa042aef90b66408ff38d270b8dc32b412c666d5ba79ca475175908fd316eb2a7d73a95aaef51245f3d5769f257e66bff28d54330ae699fd5877fe22665b2f7ae267e65f77abe62eb1323935d6569001e700ac928b8b9c885659e524a8e9287bc12a99f47418ef958233992dbacfb0e3dd26f5820ad25586a0b49e16d36102bee429efd386b42d10525678b7fbf1f85667e875da44050106daeb45438135472f85b7b7867e153ed0f1c11bc4d24c509e1694384d7527cd13ca5ab2831c53f046728a806f55cf45dd635ae73b1e3b47e114751bfb49d22d5c392b015966aa620fd47bbd01e5e44228ed4bce337bfc71a9d6f2043a5d77be99ad0c36b359962538bad2bb4f83653a2b46a872d45f34f522b075e257512183215c67d8a2e5d7793053069e666e2f42df402cabac692c8e6bb22314c5299512d2b33e63bbd91d2877afded8d3fe9ce96e24a06393a40a6c1989f0f0748a19254a79b4eddaaa1017919514333f6e624020fac9467fec17f357d8cbf7f03d0b7b609caad3a6a1ec9abb3b255a55579cda63575dfa2d896162dd0d60f2563e3608a04341856d4131a2eeefe0eb0ace8a0f92064946a304f7049f16f718fe8a0ec0d358025fe3bb7f2f5d50acb8060aa23648899c9eb61ee78088dba4784390cc2428a062b9d2d9810f5b23a5a56435adbf87ed5b7ac33d4621cc0e6b4664c77014c3ba87b1b26e81b7d826a01d158987d9f82a6851b727b9ec39d229fa772f958a6d337b68a58f622503ac2bb0d15c57e1a6e40df3af3cbea8304912db99b74f0729c492036f857cdd149943b9c46fc797118a5bd4585af68e7bf55e45beae124a9e22b21b103f1b2b211de50c6e237bf9e81145a7f5eddfd24f3f9364597af24368fec0c755d0e43b5c54c8775bc19deaa2c0033c872f065ee035d96cb2e17d3d6c62d885f872463bc9d5d07612bab2db4bb0d1b41e12527dff73ad1aea6c385998fee77f677e1d7e03503c2c96d7c74b5a06762a42e98c2ec05554522a1d0aeb8b4d21914dac40a0919ae2bd1ef1f5be3575e52b0da447219f3c8cc6c2c38133ea9369c3e8428036b731f8162f4707c2d6c514764123c311b71af1425b1be078c0e73a8b00ad4a5d69e94d5ecf16814747656d2e9976352dfb74f099670b34b9b72de82452143bfeb20b3fe52bdc953539db47301ed1ed2a36a44e08aadfcffb4a6f830f74ee3a6e936124d8d8b3416a85cb67dd8185058535d667a80f84ff2bf61fee129651031d9fbc83ffeda9c3140f336cca175fa40a0355bad597729664e9170682418b955b09c16e59070ccf6b9bda3305d82cb8e373b3938672a9d247a4af0e8e3bfa4014311390f2a45785c463f1d268cdc12cf32cf3df3f1aab9493377f4b3a923987176d23edd3ee4cd2711081c65392d912310874a4f500312b6b1e898601780c0f27a67b2835cf7b01fb4d70c565f9925a6e2f525f739af4d3c3214d9f6e66a5678d0ba55ae409fc9e4f7a6a930553cefc2b9b800195647b3abce47a7daa0eb1a04f870711c48d9b32af0ae0ed94882f8cb369404cfe64d7463aa56656be496ad8c43730ff8c2bc103a24216561ddf5ff45a593befee4de9af9c10eb304d4e15e900f4f795ca4c3f4122f94c3a06dbe43b398797df2e7163af7a9d8cd88a4d674e4568cd566c569ba0a358c35b9431e65f28cb0a1d1d109f2c028b1e6f6c3af0df99df73e01279fd3a82c016c51dab484b031ff6c4e11890e2ac3e7c551f905f0e41a99c1ad13e2b7ee5747ca67ab5c898a040eb0d381bff7b78bd50c769ead2f82f1e9cecc527cdde665eca0e3bf8f874fff087d41341afc5a0449a6cbf488d5ae023abbde6c5fcf1b8eeee8a46d70194e349abbd292cb9d698d4c19337abda08b5b2dbaf1603a2650b7960001099f53597d95e0d86fabe65a3fb8e0cc11cb1db49f6d99447d61d605142b8b3d09c51cdae60885e48707b0d8e5e2bf5448c9f4ea65667c4a22851c084c2eb8d6add70d26be7b42f0928f6bb3aae64a24e0b9bdcbf8d53c92fa44caaadaf24cf24889aeacbe02f1abaa7c";
unsigned char fromhex[4096];
const uint32_t key[4] = { 0x22312, 0x5fa32b, 0x5ac810, 0x1337 };

int main() {
    // convert from hex
    for (int i = 0; i < sizeof(enc); i += 2) {
        unsigned char c[3] = {enc[i], enc[i + 1], '\0'};
        fromhex[i / 2] = strtol(c, NULL, 16);
    }

    uint32_t *plaintext = (uint32_t*)fromhex;
    uint32_t iv[2] = {0};
    uint32_t tmp[2] = {0};
    for (int i = 0; i < 1024; i += 2) {
        tmp[0] = *(plaintext);
        tmp[1] = *(plaintext+1);
        craxs10_dec_ref(plaintext, plaintext+1, key);
        *plaintext ^= iv[0];
        *(plaintext+1) ^= iv[1];
        iv[0] = tmp[0];
        iv[1] = tmp[1];
        plaintext++;
        plaintext++;
    }
    // print in hex
    for (int i = 0; i < 4096; i++) {
        printf("%02x", fromhex[i]);
    }
    printf("\n");

    return 0;
}
```

### solution_display.py <decrypted-image-hex>
```python
import numpy as np
import matplotlib.pyplot as plt
import sys

dec = bytes.fromhex(sys.argv[1])

img = np.array([[x >> 4, x & 0xF] for x in dec], dtype=np.uint8).flatten().reshape(64,128)

plt.imshow(img, cmap='gray')
plt.show()
```
