# openECSC 2024 - Round 1

## [rev] back2basics (7 solves)

What's better than a good old crackme to warm you up?

This is a remote challenge, you can connect with:

`nc back2basics.challs.open.ecsc2024.it 38008`

Author: Matteo Rossi <@mr96>

## Overview

The challenge is a C++ binary, with a classic "crackme" fashion. The user is requested a "product key", then some checks are performed and, if the key is valid, the flag is printed.

The binary is stripped and, in the writeup, we will use decompiled code from IDA Freeware 8.3, without any plugin.

## First steps

The main function simply boils down to:
- getting our input
- calling `sub_4B86` with our input string
- if `sub_4B86` returns true, opening a file containing the flag

The first checks in `sub_4B86` are straightforward (only relevant parts of the decompiled code are listed here)
```c
if ( std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::length(a1) == 725 ){
...
    v3 = sub_4ABD(v32, v33) ^ 1;
...
    if ( (_BYTE)v3 )
    {
      return 0;
    }
    else
    {
      sub_7A76(v31, &unk_12078, v30);
      for ( i = -1; i <= 724; i += 6 )
      {
        if ( i >= 0
          && *(_BYTE *)std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator[](a1, i) != 45 )
        {
          v2 = 0;
          return 0;
        }
        std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::substr(v32, a1, i + 1, 5LL);
        sub_3629(v33, v32);
        std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator+=(v31, v33);
        ...
      }
...
}
```

We need to pass the following checks:
- our string must have a length of exactly 725 bytes
- the function check `sub_4ABD` must return true
- our string must contain a dash every 5 characters (so our input format is something like `ABCDE-FGHIJ-...`)

Function `sub_4ABD` is simply checking the alphabet used in our input, that is uppercase letters and dashes.

Then every chunk of 5 uppercase letters (excluding the dashes) is processed, "transformed" in some way and concatenated again.

The function responsible for this transformation is `sub_3629`, that takes 5 uppercase chars in input and given 7 uppercase chars in output. The processing is done via the well known [PJW Hash function](https://en.wikipedia.org/wiki/PJW_hash_function), encoding back its output to a 7-chars long uppercase string with a straightforward base26 encoding.

So, we have a mapping that transforms an input of the form `VTJQO-DLQMW-TFHWC-...` into a processed string of the form `RLKDNAABNNMKAALCRSMAA...`. This resulting string is then passed to the function `sub_37D8`, and here the challenge begins.

## Understanding the data structure
Function `sub_37D8` is (by far) the biggest function in the code. We can infer from `sub_8116` (that turns out being one of the constructors of the `std::vector` class, easily recognizable by the exception string inside) that the return type of this function is an `std::vector` of _something_ (a custom struct type), having length 2 times the size of our input string.

The remaining part of the function iterates over the characters of our input and fills the vector.

We can infer by the sizes that the struct looks something like this (notice that `sub_81DC` is just accessing elements of the struct):
```c
struct something {
  int v1;
  int v2;
  int v3;
  bool v4;
  bool v5;
  std::map<char, int> v6;
  std::vector<int> v7;
};
```

The last part of the struct is a bit less straightforward to reconstruct, but it can be understood by the snippets below. In particular `sub_8608` is recognizible as a vector `.push_back` method, while `sub_82E0` is the `.contains` method of a map, and `sub_8356` is just assigning an element of the map.

```c
while ( v28 != -1 )
{
  v7 = sub_81DC(vector_of_something, v28);
  if ( (unsigned __int8)sub_82E0(v7 + 16, &v25) == 1 )
    break;
  v5 = v29;
  v6 = sub_81DC(vector_of_something, v28);
  *(_DWORD *)sub_8356(v6 + 16, &v25) = v5;
  v28 = *(_DWORD *)(sub_81DC(vector_of_something, v28) + 4);
}
...
while ( v26 > (int)v33 )
{
  v22 = *(int *)(sub_81DC(vector_of_something, (int)v33) + 4);
  v23 = sub_81DC(vector_of_something, v22);
  sub_8608(v23 + 64, &v33);
  LODWORD(v33) = v33 + 1;
}
```

At this point we have two ways, we can:
- continue reversing the function to reconstruct the exact algorithm
- try to guess what kind of data structure we are facing

As a non-rev player, I always try to go for the second one :)

Recap:
- we are dealing with strings
- we are iterating through characters (so probably doing something with substrings)
- our struct is very similar to what we usually find in standard (directed) graph-related data structures

A quick google search leads to the [Suffix Automaton](https://en.wikipedia.org/wiki/Suffix_automaton) data structure, that looks suspiciously similar to what we are facing now. In particular the construction algorithm listed in Wikipedia has exactly the same structure of our main while loop over characters (the implementation is intended to be very textbook, in order to be recognizable without reversing everything, and I'm happy that someone in the Discord in fact managed to do it :)).

_NOTE:_ the implementation is very similar but not the exact same as Wikipedia, so a little bit of work is still needed to fill the gaps. In particular, referring to the struct _something_ that we defined before (now that we have a clearer idea, we'll call it _node_), we can rename the fields as follows.

```c
struct node {
  int len;
  int link;
  int fp;
  bool repeated;
  bool terminal;
  std::map<char, int> next;
  std::vector<int> inverse_link;
};
```

With this new naming:
- `len`, `link` and `next` are defined as in Wikipedia
- `fp` is the first ending position of a string
- `terminal` indicates if a node represents the end of a suffix of the original string
- `repeated` indicates if a node has been obtained by cloning another node (i.e. if we generated the node in the `else` branch in Wikipedia code)
- `inverse_link` is just the inverse mapping of link (i.e. the number `i` is contained in `graph[graph[i].link].inverse_link`).

Ok, now that we know (more or less) what we are facing, we have a series of checks that are performed using this data structure. We have a boolean variable (let's call it `check`), that needs to stay true for the whole process to give us the flag.

The checks can be splitted into:
- three very similar for loops
- function `sub_4422`
- one last slightly different for loop

### The first for loop

```c
for ( j = 0; j < (unsigned __int64)sub_933A(&unk_1B2C0); ++j )
{
  v5 = *(_DWORD *)sub_9362(&unk_1B2C0, j);
  std::allocator<char>::allocator(v29);
  v6 = (char *)std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::operator[](
                  &unk_1B2A0,
                  j);
  sub_78FC(a2, 1LL, (unsigned int)*v6, v29);
  sub_8D66(v30, (__int64)graph);
  check = (check & (unsigned __int8)sub_3D41(v30, a2, v5)) != 0;
  sub_8194(v30);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(a2);
  std::allocator<char>::~allocator(v29);
}
```

The first for loop is quite easy to understand: it access an element of the alphabet of uppercase letters (the same used in `sub_4ABD`, except for the dash) and it passes it to `sub_3D41`. The rest of this for loop is just C++ being C++, but is not relevant for us.

The fuction `sub_3D41` takes our graph, the 1-char long string `a2` and an integer value `v5`. Since the length of `a2` is 1 we don't really need to reverse a lot to understand that:
- the function checks if `graph[0].next` contains (remember that we have already seen this contains method) `a2`, otherwise it returns false
- returns if `graph[0].fp == v5`

So basically we are checking that the first occurrence of every character is in a specific position (hardcoded in the binary)! What is really happening here is that the function is looking for the first occurrrence of a generic substring (not only a single character); this is not relevant here but helps a lot understanding the next two loops.

### The second and third for loops

Second and third loops are exactly the same. As in the first loop we construct strings made up of copies of single uppercase letters. In the second loop, strings have length 2, while in the third one, strings have length 3. What we process is then `AA`, `BB`, `CC`, ... for the second loop, and `AAA`, `BBB`, `CCC`, ... for the third one.

The structure of these loops is very similar to the first one, but we call `sub_4111` instead of `sub_3D41`. These two functions act in a similar way, the only difference is that `sub_4111` acts recursively (with a DFS) to find all occurrences of a substring, instead of stopping at the first one.

In these two loops we are then looking for all the occurrences of length 2 and 3 substrings with all their character being equal!

### The `sub_4422` function

The `sub_4422` function is probably the most straightforward one in terms of code. It takes our `graph` and a constant with value `353624`. It then computes the sum over the nodes of `graph[i].len - graph[graph[i].link].len`.

Easy, right? Turns out it is: by construction of the automaton you can reach a node with paths of length `graph[graph[i].link].len` to `graph[i].len`, and a path in the graph identifies a substring in an unique way. So here we are just counting unique substrings!

This is equivalent (in Python, calling our input `s`) to:
```python
len(set([s[i:j] for i in range(len(s)) for j in range(i+1, len(s)+1)])) == 353624
```

### The last loop

We are finally close to the end. Again we have a check inside a for loop that looks somehow similar to the first 3. The important function is now `sub_4731`.

This function takes our graph, a very long string (hardcoded in the binary) and an integer (hardcoded too, let's call it `k`). Its structure is definitely different from the other ones: this function creates a string during the execution (based on the graph and the integer) and at the end checks if it is equal to the big string it received as input.

Function `sub_453C` is again a DFS: for every node `i` it counts recursively how many paths starting from `i` reach a terminal node _and_ how many different substrings are reachable from node `i`. If we call these values respcetively `occurrences[i]` and `substrings[i]` we have that `substrings[i] = occurrences[i] + sum(substrings[j] where j is a successor of i)`.

The rest of the function `sub_4731` uses these value to perform a lexicographical search to `k`: the aim is to find which is the substring that lives exactly at position k if we order all the substrings in lexicographical order.

_NOTE:_ here substrings are (by construction) counted multiple times, not uniquely as in the previous function.

This can be translated in Python to something like:
```python
def sub_4731(s, target, k):
  return sorted([s[i:j] for i in range(len(s)) for j in range(i+1, len(s)+1)])[k] == target
```

## How to solve?
Now that we have (more or less) understood what we need to do, how can we reconstruct the string? First of all let's extract the data from the binary. The following ones are all the data that we need to reconstruct the string

```python
alph = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# first occurrence of every letter in the alphabet
check_array1 = [5, 7, 15, 3, -1, 21, 24, 126, 73, 56, 2, 1, 10, 4, 70, 42, 64, 0, 17, 66, 22, 59, 58, 45, 101, 301]

# all occurrences of pairs of equal letters (es. "AA" appears in positions 5, 12, 19, ...)
check_array2 = [[5, 12, 19, 26, 33, 40, 47, 54, 61, 68, 75, 82, 89, 96, 97, 103, 110, 117, 124, 131, 138, 145, 152, 159, 166, 173, 180, 187, 194, 201, 208, 215, 222, 229, 236, 243, 250, 251, 257, 264, 271, 278, 285, 292, 299, 306, 313, 320, 327, 334, 341, 348, 355, 362, 369, 376, 383, 390, 397, 404, 411, 418, 425, 426, 432, 439, 446, 453, 460, 467, 474, 481, 488, 495, 496, 502, 509, 516, 517, 523, 530, 537, 544, 551, 558, 565, 572, 573, 579, 586, 593, 600, 607, 614, 621, 628, 635, 642, 649, 656, 663, 670, 677, 684, 691, 692, 698, 705, 712, 719, 720, 726, 733, 740, 747, 754, 761, 768, 775, 782, 789, 796, 803, 810, 817, 824, 831, 838, 845], [], [], [], [], [], [], [], [], [], [], [], [28, 77, 210, 336, 735, 805], [8, 225, 421, 617, 659, 778], [], [], [], [], [], [], [], [], [], [], [], []]

# all occurrences of 3 copies of the same letter
check_array3 = [[96, 250, 425, 495, 516, 572, 691, 719], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], []]

# some substrings that must be in the preprocessed input
check_array5 = [
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
]

# positions of the previous substrings if we order all the substrings of the preprocessed input in lexicographical order
check_array4 = [150522, 156400, 158842, 197423, 212845, 218209, 237975, 241733, 299651, 310452]
n_substrings = 353624

def hash_string(s):
    h = high = 0
    ret = ""

    for i in range(len(s)):
        h = (h << 4) + ord(s[i])
        high = h & 0xF0000000
        h ^= high >> 24
        h &= high ^ 0xFFFFFFFF
    
    for i in range(7):
        ret += alph[h%26]
        h //=26
    
    return ret
```

### Addressing the 3 "easy" loops
The first three loops are decently easy to address: we extract the data from the binary and we carefully place the letters in the corresponding places.

To do it we start with an empty string of length 121*7 (we have (725+1)/6 = 121 chunks of 5 chars that are mapped to 7-char chunks by the initial hashing) and we fill the places in order.

```python
hashed_key = "_"*(121*7)
hashed_key = bytearray(hashed_key.encode())

for i in range(26):
    if check_array1[i] != -1:
        hashed_key[check_array1[i]] = ord(alph[i])
    for el in check_array2[i]:
        for j in range(2):
            hashed_key[el+j] = ord(alph[i])
    for el in check_array3[i]:
        for j in range(3):
            hashed_key[el+j] = ord(alph[i])

hashed_key = bytes(hashed_key).decode()
print(hashed_key)
```

The code prints out something like this:
```
RLKDNAABNNM_AA_C_S_AAFU_G_AAMM___AA_____AAP__X_AA_____AAJ_WV_AA_Q_T_AAO__I_AAMM___AA_____AA_____AAA__Y_AA_____AA_____AA_____AAH____AA_____AA_____AA_____AA_____AA_____AA_____AA_____AA_____AA_____AA_____AA_____AAMM___AA_____AA_NN__AA_____AA_____AA_____AAA____AA_____AA_____AA_____AA_____AA_____AA_____AAZ____AA_____AA_____AA_____AA_____AAMM___AA_____AA_____AA_____AA_____AA_____AA_____AA_____AA_____AA_____AA_____AA_____AA_NN__AAA____AA_____AA_____AA_____AA_____AA_____AA_____AA_____AA_____AA_____AAA____AA_____AA_____AAA____AA_____AA_____AA_____AA_____AA_____AA_____AA_____AAA____AA_____AA_____AA_____AA_____AA_____AA_NN__AA_____AA_____AA_____AA_____AA_____AA_NN__AA_____AA_____AA_____AA_____AAA____AA_____AA_____AA_____AAA____AA_____AAMM___AA_____AA_____AA_____AA_____AA_____AA_NN__AA_____AA_____AA_____AAMM___AA_____AA_____AA_____AA_____AA_____AA
```

### Placing the "big ones"

We ideally want to place the big substrings of the last check, possibly in a unique way, in order to recover as much characters as possible.

Here a good idea is to start placing the longest one, but how can we find its placement? We can for example use the occurrences of `AAA` in that substring.

```python
check_array5_s = sorted(check_array5, key = lambda x: len(x), reverse = True)
tmp = check_array5_s[0]
print([n for n in range(len(tmp)) if tmp.find("AAA", n) == n]) 
```

This code prints `[5, 180, 250, 271, 327, 446, 474]`. Now let's take `check_array3` from the previous section: the difference `271-250` can only be mapped to the difference `516-495` in `check_array3`, so we basically have that the longest substring starts at position `495-250`. We then place greedily all the other substrings.

```python
for j,s in enumerate(check_array5_s[1:]):
    count = 0
    pos = []
    for offset in range(121*7 - len(s)):
        for i in range(len(s)):
            if hashed_key[i+offset] != '_' and hashed_key[i+offset] != s[i]:
                break
        else:
            print(f"{j} can fit at offset {offset}")
            count += 1
            pos.append(offset)
    
    if count == 1:
        hashed_key = bytearray(hashed_key.encode())
        for i in range(len(s)):
            hashed_key[pos[0]+i] = ord(s[i])
        hashed_key = bytes(hashed_key).decode()

print(f"Missing: {hashed_key.count('_')} chars")
missing_chars = [n for n in range(len(hashed_key)) if hashed_key.find("_", n) == n]
print(missing_chars)
print(hashed_key)
```

The code results in the following output, that means we only miss 15 characters (6 at the top and 9 at the bottom).

```
0 can fit at offset 221
1 can fit at offset 238
2 can fit at offset 360
3 can fit at offset 28
4 can fit at offset 589
5 can fit at offset 472
6 can fit at offset 478
7 can fit at offset 193
8 can fit at offset 157
8 can fit at offset 836
Missing: 15 chars
[11, 14, 16, 18, 23, 25, 834, 835, 836, 837, 840, 841, 842, 843, 844]
RLKDNAABNNM_AA_C_S_AAFU_G_AAMMCKLAARLKDNAAPCMXMAARLKDNAAJAWVMAAKQUTKAAOAMINAAMMCKLAAOKOANAARVKXMAAATWYKAAOAMINAAKQUTKAAFUBGNAAHJDQMAAOAMINAAJAWVMAAOKOANAALCRSMAAGVQPMAAYHWLMAAHJDQMAARVKXMAALCRSMAAJAWVMAARLKDNAAMMCKLAARVKXMAABNNMKAAGAVRMAAHJDQMAALCRSMAAATWYKAAKQUTKAARHROKAAYHWLMAAPCMXMAAGVQPMAARLKDNAAZHXQNAAPZDTMAARLKDNAAGVQPMAAOAMINAAMMCKLAARLKDNAARLKDNAAOAMINAAKQUTKAAGVQPMAAKQUTKAAFUBGNAAPCMXMAAFUBGNAAYHWLMAAGAVRMAABNNMKAAATWYKAARLKDNAALCRSMAAPCMXMAARHROKAAJAWVMAAGAVRMAAOAMINAAPCMXMAARVKXMAAATWYKAARVKXMAAFUBGNAAATWYKAAYHWLMAARLKDNAARHROKAARLKDNAAFUBGNAAPCMXMAARLKDNAAATWYKAALCRSMAAZHXQNAALCRSMAARHROKAARLKDNAABNNMKAAJAWVMAAKQUTKAARVKXMAAYHWLMAAPZDTMAABNNMKAAFUBGNAARVKXMAAJAWVMAARVKXMAAATWYKAAGAVRMAARHROKAAPZDTMAAATWYKAAYHWLMAAMMCKLAAGAVRMAARVKXMAARLKDNAARVKXMAAHJDQMAABNNMKAAZHXQNAAOAMINAARHROKAAMMCKLAAYHWLMAAOAMINAARLKDNAAG____AA_____AA
```

### The smart way to conclude

At this point there could be a good idea to conclude: we model the problem of finding the remaining characters as a sort of a subset sum problem. We know that the character `_` is greater than the uppercase letters, so we expect that if we count the current lexicographical position of our substrings in check_array5, we will observe numbers bigger than the ones in check_array4. Adding a letter in one of the missing places decreases this number by a certain amount, and probably this can be modeled with z3 to be solved directly. Unfortunately, I wasn't able to do it :)

### Recovering the upper characters in a less smart way

We use the same idea of listing the "gaps": how many substrings to we miss to get the values in `check_array4`?

```python
subs = sorted(list([hashed_key[i:j] for i in range(len(hashed_key)) for j in range(i+1, len(hashed_key)+1)]))
gaps = []
for i,el in enumerate(check_array5):
    gaps.append(check_array4[i]-subs.index(el)-1)
print(gaps)
```

This code prints `[841, 841, 841, 1690, 2527, 3353, 3360, 4196, 4197, 5863]`, meaning that we need to add, for example, `841` substrings that are lower than `check_array5[0]`. We can retrieve a set of constraints by simply looking at the starting letters of our substrings:
- exactly one of the letters in the upper parts must be `< H` because of substrings 0, 1, 2
- exactly one of the letters must be `= K` because of substring 3 (because the first occurrence of `J` is later)
- the letter at position 18 must be `M` because of conditions 4, 5, 6

The most terrible code I've ever written to bruteforce these constraint is listed below.

```python
possible_hashes_cache = {}
hashed_key = hashed_key[:18] + "M" + hashed_key[19:]
print(hashed_key)
hashed_key_chunks = [hashed_key[i:i+7] for i in range(0, len(hashed_key), 7)]

gaps = []
for i,el in enumerate(check_array5):
    gaps.append(check_array4[i]-subs.index(el)-1)

for a in alph:
    for b in alph:
        for c in alph:
            for d in alph:
                for e in alph:
                    h = hash_string(a+b+c+d+e)
                    possible_hashes_cache[h] = a+b+c+d+e

candidates = [[] for _ in range(3)]

for i, chunk in enumerate(hashed_key_chunks[:4]):
    if '_' not in chunk:
        continue
    print(chunk)
    cnt = 0
    for c in possible_hashes_cache:
        for pos in range(7):
            if chunk[pos] != '_' and chunk[pos] != c[pos]:
                break
        else:
            for j,x in enumerate(alph):
                if (x*2 in c and x*2 not in chunk) or (x*3 in c and x*3 not in chunk):
                    break
                if (x in c and check_array1[j] == -1) or (x in c and check_array1[j] > 7*i+c.index(x)):
                    break
            else:
                cnt += 1
                candidates[i-1].append(c)
    print(f"candidates {cnt}")

candidates_upper = []

for a in candidates[0]:
    for b in tqdm(candidates[1]):
        for c in candidates[2]:
            if 'K' in a+b+c and sum([x < "H" for x in [a[4], b[0], b[2], c[2], c[4]]]) == 1:
                tmp_hashed_key = hashed_key_chunks[0]+a+b+c+''.join(hashed_key_chunks[4:])
                assert len(tmp_hashed_key) == 847
                subs = sorted(list([tmp_hashed_key[i:j] for i in range(len(tmp_hashed_key)) for j in range(i+1, len(tmp_hashed_key)+1)]))

                gaps = []
                for i,el in enumerate(check_array5):
                    gaps.append(check_array4[i]-subs.index(el)-1)

                # print(gaps)
                if all(100>x>0 for x in gaps):
                    print("adding")
                    candidates_upper.append((a,b,c))

print(candidates_upper)
```

This code prints the following list of 11 (triplets of) candidates for the top part of our string:
`[('BNNMKAA', 'ACLSMAA', 'FUSGNAA'), ('BNNMKAA', 'BCLSMAA', 'FUSGNAA'), ('BNNMKAA', 'DCLSMAA', 'FUSGNAA'), ('BNNMKAA', 'ACRSMAA', 'FULGNAA'), ('BNNMKAA', 'BCRSMAA', 'FULGNAA'), ('BNNMKAA', 'DCRSMAA', 'FULGNAA'), ('BNNMKAA', 'LCRSMAA', 'FUAGNAA'), ('BNNMKAA', 'LCRSMAA', 'FUBGNAA'), ('BNNMKAA', 'LCRSMAA', 'FUCGNAA'), ('BNNMKAA', 'LCRSMAA', 'FUDGNAA'), ('BNNMKAA', 'LCRSMAA', 'FUFGNAA')]`

### Recovering the last part

The same technique can be applied for the last characters too (it requires a little bit more of bruteforce, like 30m on my laptop, but still doable). Otherwise, a smarter way is to reason in terms of number of substrings: if we compute the number of substrings of the strings that we have (completing the upper part with all the candidates), we will notice that this number is a lot bigger than `n_substrings`. This hints a lot towards repeated substrings. We can then reuse 7-chars long chunks from our string to fill the gaps and check the number of resulting substrings.

```python
upper_gaps = []
for (a,b,c) in candidates_upper:
    tmp_hashed_key = hashed_key[:7] + a+b+c + hashed_key[28:]
    subs = sorted(list([tmp_hashed_key[i:j] for i in range(len(tmp_hashed_key)) for j in range(i+1, len(tmp_hashed_key)+1)]))
    gaps = []
    for i,el in enumerate(check_array5):
        gaps.append(check_array4[i]-subs.index(el)-1)
    print((a,b,c), gaps)
    upper_gaps.append(tuple(gaps))

candidates = [[] for _ in range(2)]
hashed_key_chunks = [hashed_key[i:i+7] for i in range(0, len(hashed_key), 7)]

for i,chunk in enumerate(hashed_key_chunks[-2:]):
    if '_' not in chunk:
        continue
    print(chunk)
    cnt = 0
    for c in possible_hashes_cache:
        for pos in range(7):
            if chunk[pos] != '_' and chunk[pos] != c[pos]:
                break
            if i == 1 and pos == 0:
                if c[pos] != 'R':
                    break
            if i == 0:
                if sum([x <= 'H' for x in c]) > 4:
                    break
                if sum([x >= 'S' for x in c]) > 1:
                    break
                if pos == 0 and c[pos] >= 'S':
                    break
                if pos == 4 and c[pos] != 'M':
                    break
        else:
            for j,x in enumerate(alph):
                if (x*2 in c and x*2 not in chunk) or (x*3 in c and x*3 not in chunk):
                    break
            else:
                cnt += 1
                candidates[i].append(c)
    print(f"candidates {cnt}")

def last_step(upper_gap):
    ret = []
    for a,b in itertools.product(candidates[0], candidates[1]):
        x = (a+b)[1:]

        v = sorted([x[i:j] for i in range(len(x)) for j in range(i+1, len(x)+1)] + check_array5)

        for i in range(10):
            if v.index(check_array5[i]) != upper_gap[i] + 20 + i:
                break
        else:
            print("adding", x, upper_gap)
            ret.append((x, upper_gap))
    return ret

result = pqdm(list(set(upper_gaps)), last_step, n_jobs=len(set(upper_gaps)))
print(result)
```
