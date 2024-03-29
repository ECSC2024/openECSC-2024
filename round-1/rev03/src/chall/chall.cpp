// g++ chall.cpp -o chall -std=c++2a

#include <bits/stdc++.h>

#define KEY_LEN 725

using std::string, 
      std::cin, 
      std::cout, 
      std::endl, 
      std::vector, 
      std::flush, 
      std::map, 
      std::pair;

struct node{
    int len;
    int link;
    int fp;
    bool repeated = false;
    bool terminal = false;
    map<char, int> next;
    vector<int> inverse_link;
};

const string alph = "ABCDEFGHIJKLMNOPQRSTUVWXYZ-";
const vector<int> check_array1 = {5, 7, 15, 3, -1, 21, 24, 126, 73, 56, 2, 1, 10, 4, 70, 42, 64, 0, 17, 66, 22, 59, 58, 45, 101, 301};
const vector<vector<int>> check_array2 = {{5, 12, 19, 26, 33, 40, 47, 54, 61, 68, 75, 82, 89, 96, 97, 103, 110, 117, 124, 131, 138, 145, 152, 159, 166, 173, 180, 187, 194, 201, 208, 215, 222, 229, 236, 243, 250, 251, 257, 264, 271, 278, 285, 292, 299, 306, 313, 320, 327, 334, 341, 348, 355, 362, 369, 376, 383, 390, 397, 404, 411, 418, 425, 426, 432, 439, 446, 453, 460, 467, 474, 481, 488, 495, 496, 502, 509, 516, 517, 523, 530, 537, 544, 551, 558, 565, 572, 573, 579, 586, 593, 600, 607, 614, 621, 628, 635, 642, 649, 656, 663, 670, 677, 684, 691, 692, 698, 705, 712, 719, 720, 726, 733, 740, 747, 754, 761, 768, 775, 782, 789, 796, 803, 810, 817, 824, 831, 838, 845}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {28, 77, 210, 336, 735, 805}, {8, 225, 421, 617, 659, 778}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}};
const vector<vector<int>> check_array3 = {{96, 250, 425, 495, 516, 572, 691, 719}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}};

const vector<int> check_array4 = {150522, 156400, 158842, 197423, 212845, 218209, 237975, 241733, 299651, 310452};
const vector<string> check_array5 =
    {
        "HJDQMAALCRSMAAATWYKAAKQUTKAARHROKAAYHWLMAAPCMXMAAGVQPMAARLKDNAAZHXQNAAPZDTMAARLKDNAAGVQPMAAOAMINAAMMCKLAARLKDNAARLKDNAAOAMINAAKQUTKAAGVQPMAAKQUTKAAFUBGNAAPCMXMAAFUBGNAAYHWLMAAGAVRMAABNNMKAAATWYKAARLKDNAALCRSMAAPCMXMAARHROKAAJAWVMAAGAVRMAAOAMINAAPCMXMAARVKXMAAATWYKAARVKXMAAFUBGNAAATWYKAAYHWLMAARLKDNAARHROKAARLKDNAAFUBGNAAPCMXMAARLKDNAAATWYKAALCRSMAAZHXQNAAL",
        "HXQNAALCRSMAARHROKAARLKDNAABNNMKAAJAWVMAAKQUTKAARVKXMAAYHWLMAAPZDTMAABNNMKAAFUBGNAARVKXMAAJAWVMAARVKXMAAATWYKAAGAVRMAARHROKAAPZDTMAAATWYKAAYHWLMAAMMCKLAAGAVRMAARVKXMAARLKDNAARVK",
        "INAAKQUTKAAGVQPMAAKQUTKAAFUBGNAAPCMXMAAFUBGNAAYHWLMAAGAVRMAABNNMKAAATWYKAARLKDNAALCRSMAAPCMXMAARHROKAAJAWVMAAGAVRMAAOAMINAAPCMXMAARVKXMAAATWYKAARVKXMAAFUBGNAAATWYKAAYHWLMAARLKDNAARHROKAARLKDNAAFUBGNAAPCMXMAARLKDNAAATWYKAALCRSMAAZHXQNAALCRSMAARHROKAARLKDNAABNNMKAAJAWVMAAKQUTKAARVKXMAAYHWLMAAPZDTM",
        "LCRSMAAATWYKAAKQUTKAARHROKAAYHWLMAAPCMXMAAGVQPMAARLKDNAAZHXQNAAPZDTMAARLKDNAAGVQPMAAOAMINAAMMCKLAARLKDNAARLKDNAAOAMINAAKQUTKAAGVQPMAAKQUTKAAFUBGNAAPCMXMAAFUBGNAAYHWLMAAGAVRMAABNNMKAAATWYKAARLKDNAALCRSMAAPCMXMAARHROKAAJAWVMAAGAVRMAAOAMINAAPCMXMAARVKXMAAATWYKAARVKXMAAFUBGNAAATWYKAAYHWLMAARLKDNAARHROKAARLKDNAAFUBGNAAPCMXMAARLKDNAAATWYKAALCRSMAAZHXQNAALCRSMAARHROKAARLKDNAABNNMKAAJAWVMAAKQUTKAARVKXMAAYHWLMAAPZDTMAABNNMKAAFUBGNAARVKXMAAJAWVMAARVKXMAAATWYKAAGAVRMAARHROKAAPZDTMAAATWYKAAYHWLMAAMMCKLAAGAVRMAARVKXMAARLKDNAARVKXMAAHJDQMAABNNMKAAZHXQNAAOAMINAARHROKAAMMCKLAAYHWLMAAOAMINAARLKDNAAG",
        "MAABNNMKAAGAVRMAAHJDQMAALCRSMAAATWYKAAKQUTKAARHROKAAYHWLMAAPCMXMAAGVQPMAARLKDNAAZHXQNAAPZDTMAARLKDNAAGVQPMAAOAMINAAMMCKLAARLKDNAARLKDNAAOAMINAAKQUTKAAGVQPMAAKQUTKAAFUBGNAAPCMXMAAFUBGNAAYHWLMAAGAVRMAABNNMKAAATWYKAARLKDNAALCRSMAAPCMXMAARHROKAAJAWVMAAGAVRMAAOAMINAAPCMXMAARVKXMAAATWYKAARVKXMAAFUBGNAAATWYKAAYHWLMAARLKDNAARHROKAARLKDNAAFUBGNAAPCMXMAARLKDNAAATWYKAALCRSMAAZHXQNAALCRSMAARHROKAARLKD",
        "MAAJAWVMAARLKDNAAMMCKLAARVKXMAABNNMK",
        "MINAAPCMXMAARVKXMAAATWYKAARVKXMAAFUBGNAAATWYKAAYHWLMAARLKDNAARHROKAARLKDNAAFUBGNAAPCMXMAARLKDNAAATWYKAALCRSMAAZHXQNAALCRSM",
        "MMCKLAARLKDNAAPCMXMAARLKDNAAJAWVMAAKQUTKAAOAMINAAMMCKLAAOKOANAARVKXMAAATWYKAAOAMINAAKQUTKAAFUBGNAAHJDQMAAOAMINAAJAWVMAAOKOANAALCRSMAAGVQPMAAYHWLMAAHJDQMAARVKXMAALCRSMAAJAWVMAARLKDN",
        "RMAAOAMINAAPCMXMAARVKXMAAATWYKAARVKXMAAFUBGNAAATWYKAAYHWLMAARLKDNAARHROKAARLKDNAAFUBGNAAPCMXMAARLKDNAAATWYKAALCRSMAAZHXQNAALCRSM",
        "SMAAGVQPM"
    };

string hash_string(string s){
    int h = 0;
    int high;
    string ret = "";

    for(int i = 0; i<s.length(); i++){
        h = (h << 4) + s[i];
        if (high = h & 0xF0000000)
            h ^= high >> 24;
        h &= ~high;
    }

    for(int i = 0; i<7; i++){
        ret += alph[h%26];
        h /= 26;
    }

    return ret;
}

// generates the suffix automaton
vector<node> preprocess(string key){
    vector<node> res(2*key.length());
    int size = 0;
    int end = 0;

    res[0].len = 0;
    res[0].link = -1;
    size++;

    for(auto c : key){
        int tmp = end;
        int cur_size = size;
        size++;
        res[cur_size].len = res[tmp].len + 1;
        res[cur_size].fp = res[tmp].len;

        while (tmp != -1 && !res[tmp].next.contains(c)){
            res[tmp].next[c] = cur_size;
            tmp = res[tmp].link;
        }

        if (tmp == -1)
            res[cur_size].link = 0;
        else{
            int tmp2 = res[tmp].next[c];
            if(res[tmp].len == res[tmp2].len - 1)
                res[cur_size].link = tmp2;
            else{
                int idx = size;
                size++;
                res[idx].len = res[tmp].len + 1;
                res[idx].next = res[tmp2].next;
                res[idx].link = res[tmp2].link;
                res[idx].fp = res[tmp2].fp;
                res[idx].repeated = true;

                while (tmp != -1 && res[tmp].next[c] == tmp2){
                    res[tmp].next[c] = idx;
                    tmp = res[tmp].link;
                }

                res[tmp2].link = idx;
                res[cur_size].link = idx;
            }
        }
        
        end = cur_size;
    }

    for (int i = 1; i<size; i++)
        res[res[i].link].inverse_link.push_back(i);

    while (end > 0) {
      res[end].terminal = true;
      end = res[end].link;
    }

    return res;
}

// check the position of the first occurrence of pat as a substring, returns if == to target
bool check1(vector<node> key, string pat, int target){
    auto current = key[0];

    for(int i = 0; i < pat.size(); i++){
        if (!current.next.contains(pat[i]))
            return (target == -1);
        current = key[current.next[pat[i]]];
    }

    return ((current.fp - pat.length() + 1) == target);
}

void check2_recursion(node i, string pat, vector<int>& result, vector<node> key) {
    if (!i.repeated)
        result.push_back(i.fp - pat.length() + 1);
    for (auto x : i.inverse_link)
        check2_recursion(key[x], pat, result, key);
}

// check all the starting positions of pat as a substring, returns if == to target
bool check2(vector<node> key, string pat, vector<int> target){
    auto current = key[0];
    vector<int> result;

    for(int i = 0; i < pat.size(); i++){
        if (!current.next.contains(pat[i]))
            return target.empty();
        current = key[current.next[pat[i]]];
    }

    check2_recursion(current, pat, result, key);
    sort(result.begin(), result.end());
    sort(target.begin(), target.end());

    return (result == target);
}

// check the number of different substrings, returns if == to target
bool check3(vector<node> key, int target){
    int cnt = 0;

    for(auto x : key){
        if (x.len > 0)
            cnt += x.len - key[x.link].len;
    }

    return (cnt == target);
}

void check4_recursion(vector<node> key, vector<int>& occurences, vector<int>& substrings, int i) {
    int tmp_occ = 0;
    int tmp_sub = 0;

    if(!occurences[i]){
        if(key[i].terminal) {
            tmp_occ++;
            tmp_sub++;
        }

        for(auto e : key[i].next) {
            check4_recursion(key, occurences, substrings, e.second);
            tmp_occ += occurences[e.second];
            tmp_sub += substrings[e.second]+occurences[e.second];
        }

        occurences[i] = tmp_occ;
        substrings[i] = tmp_sub;
    }
    else
        return;

}

// check the lexicographically k-th substring, returns if == to target
bool check4(vector<node> key, int k, string target){
    vector<int> count_substrings(key.size());
    vector<int> count_occurrences(key.size());
    int current_node = 0;
    string current_string = "";
    check4_recursion(key, count_occurrences, count_substrings, 0);

    if (k > count_substrings[0])
        return false;
    
    while (k > 0){
        int acc = 0;

        for (auto x : key[current_node].next){
            int tmp = acc;
            acc += count_substrings[x.second];

            if (acc >= k){
                current_node = x.second;
                k -= tmp + count_occurrences[x.second];
                current_string += x.first;
                break;
            }
        }
    }

    return (current_string == target);
}

// check the alphabet
bool check5(string key, string alph){
    for(auto c : key){
        if(alph.find(c) == string::npos)
            return false;
    }
    return true;
}

bool check(string key){

    cout << "Verifying..." << endl;

    if(key.length() != KEY_LEN)
        return false;
    
    if(!check5(key, alph))
        return false;

    string hashed_key = "";

    for (int i = -1; i < KEY_LEN; i+=6){
        if (i >= 0 && key[i] != '-')
            return false;
        hashed_key += hash_string(key.substr(i+1, 5));
    }

    bool res = true;
    auto ds_key = preprocess(hashed_key);

    for (int i = 0; i < check_array1.size(); i++)
        res &= check1(ds_key, string(1, alph[i]), check_array1[i]);
    
    for (int i = 0; i < check_array2.size(); i++)
        res &= check2(ds_key, string(2, alph[i]), check_array2[i]);

    for (int i = 0; i < check_array3.size(); i++)
        res &= check2(ds_key, string(3, alph[i]), check_array3[i]);

        
    res &= check3(ds_key, 353624);

    for (int i = 0; i < check_array4.size(); i++)
        res &= check4(ds_key, check_array4[i], check_array5[i]);

    return res;
}

int main(){
    cin.tie(0)->sync_with_stdio(0);
    string key;

    cout << "Key: " << flush;
    cin >> key;

    if(check(key)){
        string flag;
        std::ifstream flagfile("/home/user/flag");
        cout << "Correct!" << endl;
        if(flagfile.is_open()){
            getline(flagfile, flag);
            cout << flag << endl;
            flagfile.close();
        }
        else cout << "Flag not found on the server, please contact an admin." << endl;
        
    }
    else cout << "Wrong!" << endl;
    return 0;
}