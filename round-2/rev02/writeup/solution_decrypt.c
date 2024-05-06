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

unsigned char enc[] = "d0f5d8cadc1abc0b88ab126119fcc36dc9f1cf384fe2b9bc13c172fb575c3b5ac5092173fcfe1b9ca17b463f240356c65e74a2b183f22d847052357674c4d8457e011cfcd77379ad99a75acb079c3cb0f6b8983e594f7501cb4d4c36d52e1a3c7e95f6a82ea6fa718d4567a22efc516d8d2f4f76d6f8da27b2b933de2fdd1013e5b26223c07000d0a3f8d911a7b8b091ddeb3e2bf5c824f2c0025a825b5286516134abb4f6479bd200cddc26edd1ecd4a90c027bbc06c2a22370f83d64de3d841d7c47089fb612c7a3f61b962a18f287d5bade64ff17d18037db1d127cf47e0db8357c9018958e0da88cd5dc9d27d1160f8a97dd8436961d6b64d35bcb1c7a6e8579accfbab901bd09de1509b814805c0b5a9397e68a5f5e154c5b3450e948774a3ae814ff52bb7fcb294895f1ac9ade96abfba4274e09f707a90a39246f545704baaca80fe476ba672a7a7fce87d61066409cbc188e8964e07cc0ab03f3aa4d6e3dc3613e200d4c1d13a29cca8b3440cae3fab72cf0fa136de0f6e3f74ccd3d1644fc5d5213b6e1ad3472ed27182b7710694c98c1d385456564fb926b34c6f594776fad4b93c18a9e7d993a103c6edb820827e833a3baf9ed74ccaaff172225e92be991a80d28d43899a913d3382d94af02f1937e54fcd8dd8d313b7f70f2cadde1034510bf9f9b6e5e20a9bdfa50209aea9b4b534405e63d855ca53b7f4271e0b22beef4672f6d8acb7a547c8e9390bfa3ca48eea098ad015b364e9c135935a8742c5010ff771c03738bcc93f34c5211efcaea9e8b5fd4a53c564e023400528886d6d0a4ff43018940866f5b541c9d224ff20028c6aa9aa926df02d0196c7a84ab8107da08d51ad43866ff20f853c6cf68fdbcafd61e1c24684d1af92d5f32e2247b2b5ae7785d1754b7b893784a98099da621c92a19b7c351f229fbfb1c8c12ac9e41ea1a9b52f16099a4d351a04632429d12e4f7e483477341daa1e62766fe90d098cfc71e98bd6b43192dc85088431064efb806e4c5bb8f245ef6d59798db2bb122c96b500176c1a6bd7b6d171773ff6f47d81ff63af074c9d25b3ff9d815b12d0e8263f742f00c1b6ba3d196634574d84382c55ad89d12d698ca81f44c07c6a1998f423b7aff5aea7213b04d5437c35dbd4f4ecfed0c009d3d993624432e0e877bb42778e7785519a22a4930e3980fb72ed9214eeab9370687ff3414cb7804ef3de6c07082b4fe7c66f1f44fc429db3376dd423355786a9c3ff7db32f22a3d6adce75a76e306238b00a1ca0230237bf862222546b7510299ad85513b172fb2c0652dc48707d4a569734c9926f677a5dcf3957fba9d0c293e89052d7cf83b73f0c50c91cec5518fe752e4700b693726301152dcd132896424ca6e2aaf8f8e7216cd858a58c887032fdba225ec3e38c78be30441f0b2636306cbf2589ffa9dcf844fa636fcfaf0d44290b0285b26934ed8b2fb015ff95218c085506efefc76035a277cb3a3a26a8afc82d1e47689991fe917cda6ce6cbecc170c4595e1c92f6e4cc1d70b0c361d002eb5b6ae1ecc17fbd0439ca6db1dbb437e4ca22aae6cd903b5dfc4bee841cf8e25bbdc0c443fdaf13e1dd730daa681021ecd517ef1c274a93425bac761ff1801b41a165388e270603c25c35f2de71998388ffeff60f636cc62a75ac70f57c99f9d9d8bcbea7d4b14012ea514a45cb1e89659852afc24fa11f53fd4a7481af39221872fbd78d4eeb213d0ec11c4eb99f724195e94c4dac82e6da3fa914b6df6dfa0aa339152e4006df861280f6235cac0ce3d33899515d741b4aec2bd705c245b762b420e143873f0847c1b58fd4c3f4e35becd88ccb82447d9395f8b7a90ff07ecf05c0961e0ce31ea42b53c248c133258645b132f89b646c9697de726a49868a6aec5c5a13f1ff3fa46eb0441a96e4c3355799b108d63815bdb1d92bfb966b49dcfe824079cd2c916062893bfc0912f99e15a62a257f19d594205183d5b4812b01e6e73da8604ebd986a557d9f238bf94bbd6a98ee8a8dd117b2e2079e5f78cd372f34ef272d6cd996e0c22a0c75bac2bd601cab9653bb758dfea5918bc1114b2f584cb9f16aa58d237f776aa873e8239969bd02f111dffe3fb5fa016f9f5edd997c842cbce39708ff1c2574fdbc78dafd8ffcf6406c3d795a6f7c6d57dff1d4276624eb0b3c122afc0ec98690f67c4a1d46e9cd83960b93a3e6f675ca3bad11b26a33f1d737ea611fecaf9391d067c7e753c2cd9040369c5225236d1d62fac12a22068d1ff329f1bdcd6f54be2dbcd9a07c5792bfadec296ae621e38da7b6e67e44bfc9cd2444e7538314e612a60c9024d63e2db21615b9a78f7fd6087616d3a0bfe03c22b06d692f08fe7fd8375681bc399053afa68e6810337481a37daadb7bccc81781c1e28283d57ad6d23d941004f32d60239ceed9da84fae85abbf65f698565a3e609759e49644deeef89709d50876229ba5c7b6b94601f71e18d79a2c1854cccdf8a57d1db140c3fee5a37876b4df30675db0d7ea851ec78e06f786bc589fff497c9b4d0829d15ac1f26226280b8d1926636d061c48bc6ce07e0a8605e81602cf9105927f00edc79ab96250ecda3949c2d4e98b4d4b92471df4db87e70482caf1c5c110e0230fe84d24b4fee6ebd00ce48809550018e553914b785f3fd72cc3b7090e9137cd886321d96ce5046d5ea6c64c6bdcf5dc22204eac820d086e407554b887337ae1c59117e54d7d8c149822272b7bc56667d199f5471c34554bdf7ec9ee8b5b194f36200fd5bfde7b4ebc0624bdfbd983ced308d4039c702fd2917dbd1340ab314218769a6f80db17c3be7f404ebb7b025181b2d0282df43c559924a972e7ec1be297b04bf765d8aed5315adc77a54f37d240f450fa74e93a4b6b10f29c7af7b52233f62d0f5db0019211842d9e481136a5ffd1b8c84e06b24f6ad9888a6b1916db25148fd2f9e4483df10e66f6bd1c70006821f2d68be62946889b7b634939e17b032047ccda6eefc9a46dd9dd578b0646accaf751405317d700aff470444c1f62922489c6bb032c97cc022e1e0facbc290b789084a97de7e89a36e9156b9021d45a6affe7c9030274b4f950154c3dc87f80d61d3e9b341e9b5a32d29def50a5e18b24e780ff4dc887d7304b4ed3e12c58d64112fc2f9444713e14a1c34d924e87970caead9bf6df82df5e5a33d869388f5934e17e75139c64ebcfce05fcadf4405ccb3a060029777c09406bd841616d875728b5598f3f528ac8f15509848155d69677dcd5b802b0556c68f17909d17943fe614fbe785dd80c6a867409c1cc56f40dfc945b63e697bf06377540074c2657e4362a20c234a51747acc89a47089c6e5c61d7e4f38d9d752d20e55642267bdfcdb60467035648480a1dfd192086e89c0be991431eb40fb6abe71120bc35c39a02b1f56711c48e452d62a488f8c46e2e3ef257f228085f224a328c408c1a4e1168bb8cf6c0b91fddec073508746636b6644af4c0773f095bba54f28f8256784c5f319fb42cba70a106ee4e77e5c6e885de4707f524c1c559a1bebb4d8d160c59c9a2be98de805695468af6b2b27cfcffbe0638966b5a0e6892d9d0e04f7eb0aa5f8471871de189c5b1de900920eb74e904ad9c618171fa7de10955f60353d3a186f0c6e3d56b6dab86cf95a5eb7a3235991292c125c2085c646b70f9bbbb6e0ef29b45f9f30491b4b18f5cb1619765ee6a4c9942667424ec66170e1df2e08c39a147a5fbe306d0ae8c4b0d1fca137471fd55af409577a1c5349786c4f8c598f666df7b47c93bad7d284f262e6e1c122e7a975aa90f36048cf6ad6753bf07d4926445ddb38815142a650b36bb576125c5d8b7d312a9682467fbb136476db01dc2452856e152910552698f24e4cc28c0532ff979bad745622fb85ea2d48d5dffd85c3b11e96fad60fbfa0b6d9a3d75d36c059b736911a860a255b92f8620c7094cc494148e0f21c89e4c80e95f37b94d31b7ad7eb0ea42f56e7c411dddca3eeace8abcaeb7f286b10cb08ba6b357223a90cbee8115ebdd8700f53db31bf5d641d84218be4172aed2ec5f5defd99cf08c58f461eeb7540e7209e3f18d17d1340dbaff031b3082be51d15e45ed1019c0d4d4334783c7cc11f3a1da809d282bab7bfebbae2d52eca9496df84f302cdd9137a108066f292be39b4f2f027610d6d29403130fc0adc890403dc9e72b2301061fc4031c73dc0695f897ed71bc3736c4477d6f948f4b49b8b6cc368acf01353af2ae028cb9d6b429cb3b1c242cccbadb452c3fa3cb57aaf9f7ab392672627c04bbe925e0f7275ac1ad631ba689d3d8423b1814fbc5bc27b5982f62c3d6f5f3ca689070c7f8d942ba6bba53a8340bd9ed9bd56bdbcdedaf6a759deae2530423f640b15460ebe98f45a9a318b30ca8a991afd723c6095dd7508d49c3d5f7230b14a8e8e55343ab1721d7702f0c2c6254b90a4e1c1fab8ecce78389c70d33c978f71f458cd0c4d636179250862bc74bc557df234df521e8650bb01e4e1d326bc6be3db3b8c1b6e9308c63149ad7b46f0068af18d7c17542e1ff4c95cda32b45c37c6ac75a33ce548dc40724f3e95d67b1fbb6158834d9d620960e6d934d3e0b572b6ed49c1b2dfa4be252b552c2f478180e81d7a915d311a4eb55f8b395e07d63ef91328f03e2ebdff69d9e053a62141dee0d89b31fc4b68ad105a4ff63544f7d0e65d10130d86fc993442a1810dcb91023d5c2d6e636d13a459d62332b798d2d98587300cee61aa639c48afcf0730389c1666d88c7ca61c90a2bd53308b44f4a9e6b44f4887d2afa2c0127fe890b4a89a6027bc5946f7cbdaee0252ec14a44d4134091a034f2b0156897df2650da0a53f015981cb8ad7451745091c6fd13142fbb87e3014a531ad6034cd9a232a23feeb032e85133ddce2c2c58b61575549e5fc5d2780dd0dd034ba9e1c4fe400aeee3d5ca2c41d668c65f06841ad1604db22bb25c018c3cc7dc522b054b8d5949c21c3c52cc9beaadd7211535004f805a6f31bce1719a1f7157bb288850926dbc57344ccfaafe364965c5d60128315033f644e26b82da0673aff024b99e3b0a774040f1833adc77c289a7746a62d9d02057405e7e4a36c34c886097b6482c95d5b356b41bd8324d1971cebb972c2e12f045b69d89c3f6dfc9eb83ddd1df66aa7caf7867ddedb412dd421e15ae01ff1b827f26616bd29eba12269b439706a8232dfac61b1fc730829695641c95df516fa73412d1bcbc965386728b9f6db569b760cc8ea00b34f17c804a57fe8bb5028511e085f2df9e7beb96f5df03f443c09a347948c7c1b34b5d7d5b21d05f4d5985c26fddda6f4ba0c28858c343f253a5b4d6a7d4c6aa572ad6a23c5e8eee15dce3b3010a915407568191999fd75daa3938a0a7613d79e745643334cacea70a2e14d2c714bb9f317f39c0662ac326a075c12fb7703d59678cfc82e2c9fa42279be71e3f0da830a969c1368cbeaf8cedd83b52eec522df8a2f2087ce292f127ec3babf6d80368826e05f49cc5a369551b51c339feeece54598549323138a6fa612d7632c8b517e8bebf0ad7c18569296e571fd70ad415499d7e5b562fabd531a14260a9c4394a5f63d8c70803b32af8feedee385d4ee5fa2e46de29304d28f32ab91b01718a5db49415649e7d88167443f0fecd8b05a5efa52e65a26027ecbd827b86b1c3e2c4fef009e57bdb58eeaabd4ba2051d9b0c7d08fdc9872cbd937d6e6633ebd99d0d3502f759eb0d12d7a412e128698";
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