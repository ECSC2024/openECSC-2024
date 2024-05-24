#include <bits/stdc++.h>

using namespace std;

#define BITS 32
#define MASK ((1LL<<BITS)-1)
#define r1 13
#define r2 11
#define m1 3
#define m2 5
#define THRES 0.15
#define THRES_TRAIL 0.00000001

#define MUL(x,y) ((x*y) & MASK)
#define ADD(x,y) ((x+y) & MASK)
#define SUB(x,y) ((x-y+(1LL<<BITS)) & MASK)
#define ROL(x,r) (((x << (r)) | (x >> (BITS - (r)))) & MASK)
#define ROR(x,r) (((x >> (r)) | ((x << (BITS - (r))))) & MASK)
// #define ll long long
// #define ll (unsigned long long)
#define ll __uint128_t

#define mat_type array<array<ll, 8>, 8>

vector<double> bounds;
double big_bound;

std::ostream& operator<<(std::ostream& o, const ll& x) {
    if (x == std::numeric_limits<__int128>::min()) return o << "-170141183460469231731687303715884105728";
    if (x < 0) return o << "-" << -x;
    if (x < 10) return o << (char)(x + '0');
    return o << x / 10 << (char)(x % 10 + '0');
}

ll gcd(ll a, ll b, ll& x, ll& y) {
    if (b == 0) {
        x = 1;
        y = 0;
        return a;
    }
    ll x1, y1;
    ll d = gcd(b, a % b, x1, y1);
    x = y1;
    y = x1 - y1 * (a / b);
    return d;
}

ll modinv(ll a, ll m){
    ll x, y;
    ll g = gcd(a, m, x, y);
    return (x % m + m) % m;
}

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

array<ll, 4> enum_lrot_results(ll a, int r, int n){
    ll dx = ROL(a, r);
    return {SUB(ADD(dx, 0), 0), SUB(ADD(dx, 0), 1LL << r), SUB(ADD(dx, 1), 0), SUB(ADD(dx, 1), 1LL << r)};
}

array<ll, 4> invert_lrot_results(ll b, int r, int n){
    return {ROR(SUB(ADD(b, 0), 0), r), ROR(SUB(ADD(b, 1LL << r), 0), r), ROR(SUB(ADD(b, 0), 1), r), ROR(SUB(ADD(b, 1LL << r), 1), r)};
}

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

int main(){
    set<tuple<ll, ll, ll, double>> pddt;
    map<ll, vector<pair<ll, double>>> round_pddt;
    auto adp_matrices = create_adp_matrices();

    compute_pddt(32, THRES, 0, 0, 0, 0, 0, pddt, adp_matrices);
    cout << pddt.size() << endl;

    ll im1 = modinv(m1, (ll)(1) << BITS);
    ll im2 = modinv(m2, (ll)(1) << BITS);

    for(auto el : pddt){
        auto gamma = (get<0>(el) * im1) & MASK;
        auto delta = (get<1>(el) * im2) & MASK;
        auto l1 = invert_lrot_results(gamma, r1, BITS);
        auto l2 = invert_lrot_results(delta, BITS-r2, BITS);

        set<ll> alpha_cands;

        for(auto x : l1) alpha_cands.insert(x);
        for(auto x : l2) alpha_cands.insert(x);

        for(auto a : alpha_cands){
            auto p = adp_round_f(a, get<2>(el), adp_matrices);
            if(p > 0.001){
                round_pddt[a].push_back(make_pair(get<2>(el), p));
            }
        }
    }

    cout << round_pddt.size() << endl;
    return 0;
}