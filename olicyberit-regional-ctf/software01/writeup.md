# OliCyber.IT - Regional CTF

## [binary] Section31 (97 solves)

To solve this challenge you need to watch the entire Star Trek series. GLHF

Author: Fabio Zoratti <@orsobruno96>

## Solution

The file is a small stripped ELF that seems to do nothing other than printing some stuff. The name of the challenge suggests that it is a good idea to look at the sections of the ELF file. Using `readelf -a` we notice that there are several sections in this file with a suspicious name:

```text
  [24] .data             PROGBITS         0000000000404008  00003008
       0000000000000004  0000000000000000  WA       0     0     1
  [25] .bss              NOBITS           000000000040400c  0000300c
       0000000000000004  0000000000000000  WA       0     0     1
  [26] .comment          PROGBITS         0000000000000000  0000300c
       000000000000002e  0000000000000001  MS       0     0     1
  [27] .annobin.notes    STRTAB           0000000000000000  0000303a
       000000000000018c  0000000000000001  MS       0     0     1
  [28] flag_0_f          PROGBITS         0000000000000000  000031c6
       0000000000000001  0000000000000000           0     0     1
  [29] flag_1_l          PROGBITS         0000000000000000  000031c7
       0000000000000001  0000000000000000           0     0     1
  [30] flag_2_a          PROGBITS         0000000000000000  000031c8
       0000000000000001  0000000000000000           0     0     1
  [31] flag_3_g          PROGBITS         0000000000000000  000031c9
       0000000000000001  0000000000000000           0     0     1
  [32] flag_4_{          PROGBITS         0000000000000000  000031ca
       0000000000000001  0000000000000000           0     0     1
  [33] flag_5_f          PROGBITS         0000000000000000  000031cb
       0000000000000001  0000000000000000           0     0     1
```

Taking all the sections with name `flag_[0-9]+_[a-z]` and concatenating the last letter of each section we get the flag. This can be done manually or with a nice oneliner:

```sh
readelf -a $1 | grep flag_ | cut -d '_' -f3 | cut -d ' ' -f1 | awk '{print}' ORS=""
```
