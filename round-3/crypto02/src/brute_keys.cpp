#include <bits/stdc++.h>

#define BITS 32L
#define MASK ((1LL<<BITS)-1L)
#define MUL(x,y) (x*y)
#define ADD(x,y) (x+y)
#define SUB(x,y) (x-y)
#define ROL(x,r) ((x << (r)) | (x >> (BITS - (r))))

#define DEBUG 0

uint RC[] = {2667589438, 3161395992, 3211084506, 3202806575, 827352482, 3632865942, 1447589438, 3161338992};

uint round_f(uint x, uint k, int i){
    return MUL(3, ROL(ADD(k, x), 19)) ^ MUL(5, ROL(SUB(k, x), BITS-29)) ^ ADD(k, MUL((uint)i, 0x13371337LL));
}

std::vector<uint> key_schedule(uint key_l, uint key_r, int n_rounds){
    std::vector<uint> keys;
    keys.push_back(key_l);

    for(int i = 0; i<n_rounds-2; i++){
        uint tmp = key_l;
        key_l = key_r;
        key_r = ADD(tmp, round_f(key_r, RC[i], i+1));
        // std::cout << key_r << " ";
        keys.push_back(key_l);
    }
    // cout << endl;
    keys.push_back(key_r);
    return keys;
}

std::vector<uint> reverse_key_schedule(uint key_l, uint key_r, int n_rounds) {
    std::vector<uint> keys;
    keys.push_back(key_r);
    for (int i = 0; i < n_rounds - 2; i++) {
        uint tmp = key_r;
        key_r = key_l;
        key_l = SUB(tmp, round_f(key_l, RC[n_rounds - 3 - i], n_rounds - 2 - i));
        keys.push_back(key_r);
    }
    keys.push_back(key_l);
    return keys;
}

std::array<uint, 2> encrypt_block(uint l, uint r, std::vector<uint>& round_keys, int n_rounds){
    for(int i = 0; i < n_rounds; i++){
        uint tmp = l;
        l = r;
        r = ADD(tmp, round_f(r, round_keys[i], i+1));
    }

    return {l, r};
}

uint decrypt_block_3_rounds(uint l, uint r, uint k1, uint k2, uint k3, int n_rounds) {
    uint dec1_l = SUB(r, round_f(l, k1, n_rounds));
    uint dec2_l = SUB(l, round_f(dec1_l, k2, n_rounds - 1));
    uint dec3_l = SUB(dec1_l, round_f(dec2_l, k3, n_rounds - 2));

    return dec3_l;
}

void find_first_key(std::vector<std::array<uint, 2>>& pts, std::vector<std::array<uint, 2>>& cts, std::vector<uint>& poss_k1, int n_rounds) {
    int num_pairs;
    std::cin >> num_pairs;
    uint tmp_l, tmp_r;
    for (int i = 0; i < num_pairs; i++) {
        std::cin >> tmp_l;
        std::cin >> tmp_r;
        pts.push_back({tmp_l, tmp_r});
        std::cin >> tmp_l;
        std::cin >> tmp_r;
        cts.push_back({tmp_l, tmp_r});
    }

    if (DEBUG)
        std::cout << "Got input" << std::endl;

    std::vector<uint> new_poss_k1;

    for(uint k1 = 0; k1 < 4294967295; k1++) {
        if (SUB(cts[1][1], round_f(cts[1][0], k1, n_rounds)) == SUB(cts[0][1], round_f(cts[0][0], k1, n_rounds))) {
            poss_k1.push_back(k1);
        }
    }

    if (DEBUG)
        std::cout << "Poss k1: " << poss_k1.size() << std::endl;

    for(int i = 2; i < cts.size(); i+= 2) {
        for(auto k1 : poss_k1) {
            if (SUB(cts[i+1][1], round_f(cts[i+1][0], k1, n_rounds)) == SUB(cts[i][1], round_f(cts[i][0], k1, n_rounds))) {
                new_poss_k1.push_back(k1);
            }
        }

        poss_k1 = new_poss_k1;
        new_poss_k1.clear();
        if (DEBUG)
            std::cout << "Poss k1: " << poss_k1.size() << std::endl;
    }


    std::cout << "Poss k1: " << poss_k1.size() << std::endl;
}

void find_second_key(std::vector<std::array<uint, 2>> pts, std::vector<std::array<uint, 2>> cts, std::vector<uint> poss_k1, int n_rounds) {

    for (auto& key_r : poss_k1) {
        if (DEBUG)
            std::cout << "Testing: " << key_r << std::endl;
        #pragma omp parallel for num_threads(16)
        for (uint key_l = 0; key_l < 4294967295; key_l++) {
            // if (key_l % (1 << 22) == 0) {
            //     std::cout << "count: " << (key_l >> 22) << std::endl;
            // }
            uint k3 = SUB(key_r, round_f(key_l, RC[n_rounds-3], n_rounds-2));
            uint dec1 = decrypt_block_3_rounds(cts[0][0], cts[0][1], key_r, key_l, k3, n_rounds);
            uint dec2 = decrypt_block_3_rounds(cts[1][0], cts[1][1], key_r, key_l, k3, n_rounds);

            if (dec1 != dec2) {
                continue;
            }

            std::vector<uint> round_keys;
            round_keys = reverse_key_schedule(key_l, key_r, n_rounds);
            std::reverse(round_keys.begin(), round_keys.end());
            auto hope = encrypt_block(pts[0][0], pts[0][1], round_keys, n_rounds);
            if (hope[0] == cts[0][0] && hope[1] == cts[0][1]) {
                std::cout << key_r << " " << key_l << std::endl;
            }
        }
    }

    std::cout << -1 << std::endl;

}

int main() {
    int n_rounds = 10;
    std::vector<std::array<uint, 2>> pts, cts;
    std::vector<uint> poss_k1;
    find_first_key(pts, cts, poss_k1, n_rounds);
    find_second_key(pts, cts, poss_k1, n_rounds);

    return 0;
}
