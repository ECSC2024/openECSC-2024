# openECSC 2024 - Round 3

## [crypto] JuniorFeistel (3 solves)

"_need the sequel to babyfeistel pls_"

`nc juniorfeistel.challs.open.ecsc2024.it 38014`

Authors: Matteo Rossi <@mr96>, Lorenzo Demeio <@Devrar>

## Overview

The challenge asks us to perform a key recovery attack on a 10-round custom [Feistel network](https://en.wikipedia.org/wiki/Feistel_cipher), using up to 7000000 chosen plaintexts. We only have one attempt to guess the correct key.

The peculiarity of the cipher is that it uses modular addition insteal of XOR in the Feistel network, that is used in the majority of the real-world ciphers. However, we have a few ARX ciphers in the literature using a similar structure: for example the [TEA](https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm) cipher.

_Note: the intended solution of this challenge does not require any knowledge about the solution of the challenge [BabyFeistel](https://github.com/ECSC2024/openECSC-2024/blob/main/round-2/crypto03/writeup.md) of the previous round._

## Solution

We start with a couple of observations on the cipher:

- plaintexts, ciphertexts and keys are 64-bit long
- round keys are 32-bit long, and are derived using a key schedule algorithm that is a Feistel network too: recovering the last two keys is enough to reconstruct the cipher key (in particular, the round function of the key schedule algorithm is the same as the main cipher, but it is not relevant for the solution).

The proposed solution is based on differential cryptanalysis with the usual path of exploitation:

- we find a differential with high probability
- we query the oracle with pairs of the form $(x, x+D)$, with $D$ being the input difference of our differential
- we find candidates for the last round key, matching them with the desired output difference
- we bruteforce the penultimate round key for the candidates, invert the key schedule and see if the recovered master key is correct by trial encryption

### Finding a differential: basic strategy

Before starting, we need two key observations:

- in the round function, the key is injected via modular addition/subtraction: it is then better to search for differences in terms of modular addition instead of the "usual" XOR ones, as modular addition is not linear with respect to the XOR operation (and viceversa)
- differentials with respect to the modular addition are indepentend from the round key for our cipher (this is not 100% true, but in this case it's a good approximation; intuitively, this is because additions/subtractions between round keys and the plaintext are done as the "first operations" in the round. When this is not the case, usually differentials are key-dependent as, for example, in TEA)

So, to summarize, we look for pairs $(a,b)$ such that $\text{Pr}(f(a+x)-f(x)=b)$ is high, with $f$ being the round function.

Moreover, we want several differences of this type to "glue" together to form a path (differential trail) through the rounds of the cipher, keeping the probability of the full path as high as possible (note: using the Markov property we consider the rounds independent, just multiplying the probabilities of the single transitions to get the probability of the differential trail). On Feistel networks, the best way to go is to look for differences of the form $(a, 0)$ or $(0, a)$ (as inputs of the two branches of the network), to minimize the number of "active" round functions. This means, that our objective is now to maximize $\text{Pr}(f(a+x)-f(x)=0)$.

To reach this objective, we have a lot of different strategies:

- bruteforcing all values of $a$ (remember that we only have $2^{32}$ of them)
- asking a SAT/MILP/CP solver to maximize this probability for us
- going through all the pain of approximating the probability by hand

We, of course, go for the third one :)

_Note: we want to present this approach mostly because it is the most instructive one, but the bruteforce one is of course way less painful to write and debug._

### Finding a differential: exploiting the round function

At this point, we actually need the round function, so let's recall it:

```cpp
uint round_f(uint x, uint k, int i){
    return MUL(3, ROL(ADD(k, x), 19)) ^ MUL(5, ROR(SUB(k, x), 29)) ^ ADD(k, MUL((uint)i, 0x13371337LL));
}
```

Notice that, in this function, the last XOR does not contain our input `x`. Since we are looking for transitions with output `0`, we can ignore that part at the cost of maybe losing a bit of precision. So we actually look for high probability differentials for the round function below:

```cpp
uint round_f(uint x, uint k, int i){
    return MUL(3, ROL(ADD(k, x), 19)) ^ MUL(5, ROR(SUB(k, x), 29));
}
```

Again, we consider everything independent: we calculate probabilities for the XOR and the rotations, then we multiply everything together. Moreover, we list here all the differentials $(a,b)$ through the "new" round function, filtering at the end the ones of the form $(a,0)$.

The additive probability of XOR is well studied in the literature, for example [here](https://www.research.ed.ac.uk/en/publications/the-differential-analysis-of-s-functions). We give here an implementation to calculate it:

```cpp
#define ll __uint128_t
#define mat_type array<array<ll, 8>, 8>

array<mat_type, 8> create_adp_matrices(){
    array<mat_type, 8> res;
    mat_type A0 {{
        {4, 0, 0, 1, 0, 1, 1, 0},
        {0, 0, 0, 1, 0, 1, 0, 0},
        {0, 0, 0, 1, 0, 0, 1, 0},
        {0, 0, 0, 1, 0, 0, 0, 0},
        {0, 0, 0, 0, 0, 1, 1, 0},
        {0, 0, 0, 0, 0, 1, 0, 0},
        {0, 0, 0, 0, 0, 0, 1, 0},
        {0, 0, 0, 0, 0, 0, 0, 0}
    }};

    res[0] = A0;
    for(int k = 0; k < 7; k++){
        mat_type A;

        for(int i = 0; i < 8; i++){
            for(int j = 0; j < 8; j++){
                A[i][j] = A0[i ^ (k+1)][j ^ (k+1)];
            }
        }
        res[k+1] = A;
    }

    return res;
}

double adp_xor(ll a, ll b, ll c, int n, array<mat_type, 8>& adp_matrices){
    array<ll, 8> L {1, 1, 1, 1, 1, 1, 1, 1}, C {1, 0, 0, 0, 0, 0, 0, 0};
    vector<ll> s;

    for(int i = 0; i < n; i++){
        s.push_back(4*((a>>i)&1) + 2*((b>>i)&1) + ((c>>i)&1));
    }

    reverse(s.begin(), s.end());

    for(int i = 0; i < n; i++){
        array<ll, 8> tmp {0, 0, 0, 0, 0, 0, 0, 0};
        for(int j = 0; j < 8; j++){
            for(int k = 0; k < 8; k++){
                tmp[j] += L[k] * adp_matrices[s[i]][k][j];
            }
        }
        L = tmp;
    }

    return double(L[0])/double((__uint128_t)(1) << (2*n));
}
```

The function above calculates the probability $\text{Pr}(((x+a)\oplus (y+b))-(x+y))=c$, over all possible pairs $(x,y)$.

The case of the rotation is easier, as the left shift is linear with respect to modular addition, while the right one can assume only 4 values, that can be calculated by hand. The following code computes the probability.

```cpp
double adp_lrot(ll a, ll b, int r, int n){
    ll res = 0;
    ll ar = a % (1LL << (n-r));
    ll al = a >> (n-r);
    ll dx = ROL(a, r);

    if(b == SUB(ADD(dx, 0), 0))
        res += ((1LL << (n-r)) - ar) * ((1LL << r) - al);
    if(b == SUB(ADD(dx, 0), 1LL << r))
        res += ((1LL << (n-r)) - ar) * al;
    if(b == SUB(ADD(dx, 1), 0))
        res += (ar * ((1LL << r) - al - 1));
    if(b == SUB(ADD(dx, 1), 1LL << r))
        res += (ar * (al+1));
    
    return (double)(res)/(double)(1LL << n);
}
```

Once we know how to calculate these values, we just put everything together, approximating the probability of the full round function:

```cpp
array<ll, 4> enum_lrot_results(ll a, int r, int n){
    ll dx = ROL(a, r);
    return {SUB(ADD(dx, 0), 0), SUB(ADD(dx, 0), 1LL << r), SUB(ADD(dx, 1), 0), SUB(ADD(dx, 1), 1LL << r)};
}

double adp_round_f(ll a, ll b, array<mat_type, 8>& adp_matrices){
    auto tmp_gamma = enum_lrot_results(a, r1, BITS);
    auto tmp_delta = enum_lrot_results(a, BITS-r2, BITS);
    set<ll> gamma(tmp_gamma.begin(), tmp_gamma.end());
    set<ll> delta(tmp_delta.begin(), tmp_delta.end());
    double p = 0.0;

    for(auto g : gamma){
        for(auto d : delta){
            auto p1 = adp_lrot(a, g, r1, BITS);
            auto p2 = adp_lrot(a, d, BITS-r2, BITS);
            auto p3 = adp_xor(MUL(m1, g), MUL(m2, d), b, BITS, adp_matrices);
            p += p1*p2*p3;
        }
    }

    return p;
}
```

Ok, now everything looks good, but we still have one problem to address: bruteforcing everything for the additive probability of xor is not feasible, as it would result in $2^{96}$ tries. To overcome this problem, the strategy is to use a partial difference distribution table (pDDT), trying only the cases with an high probability.

This approach is described in Section 4 of [this article](https://eprint.iacr.org/2013/853), but to summarize: we use the fact that the additive differential probability of XOR is monotonously decreasing with the number of bits of the input words to minimize the tries.

To conclude, our strategy is:

- we create a pDDT for the XOR operation
- we use the `adp_round_f` function to convert it to a pDDT for the round function

The code for the creation of the pDDT of the XOR is given below:

```cpp
void compute_pddt(int n, double p, int k, double pk, ll ak, ll bk, ll ck, set<tuple<ll, ll, ll, double>>& res, array<mat_type, 8>& adp_matrices){
    if(n == k){
        res.insert(make_tuple(ak, bk, ck, pk));
        return;
    }

    for(int x = 0; x < 2; x++){
        for(int y = 0; y < 2; y++){
            for(int z = 0; z < 2; z++){
                ll ak1 = ak + x*(1LL << k);
                ll bk1 = bk + y*(1LL << k);
                ll ck1 = ck + z*(1LL << k);
                double pk = adp_xor(ak1, bk1, ck1, k+1, adp_matrices);
                if(pk >= p)
                    compute_pddt(n, p, k+1, pk, ak1, bk1, ck1, res, adp_matrices);
            }
        }
    }
}
```

The full code for this part is given in the [differential_search.cpp](./src/differential_search.cpp) file.

The final outcome is that the differential `(0x0ffff000, 0)` is a good candidate for our key recovery.

### Key recovery

As we already outlined below, the key recovery step is now quite straightforward:

- we have an iterated differential, that goes from `(0x0ffff000, 0)` to `(0, 0x0ffff000)` over 9 rounds with high probability
- we find all candidates for the last round key based on this differential (code in [key_rec.py](./src/key_rec.py))
- we bruteforce the penultimate round key for each candidate (code in [brute_keys.cpp](./src/brute_keys.cpp))
- we iterate until we find the right candidates to recover the key (usually 3-4 attempts)
