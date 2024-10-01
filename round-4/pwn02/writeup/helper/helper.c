// gcc -o helper helper.c

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

// Proprietary algorithm
#include "hendricks.h"

// Constants for buffer sizes, window size, and match length limits
#define MAX_INPUT_SIZE 4096
#define MAX_BUFFER_SIZE 4096

// Data structure to manage a stream of bits (bit buffer)
typedef struct
{
    int pos;                         // Position in the buffer (in bits)
    int size;                        // Size of the buffer (in bytes)
    uint8_t buffer[MAX_BUFFER_SIZE]; // Actual buffer holding the data
} BitStream;

// Writes 'bit_count' bits from 'value' into the bitstream
void write_bits(BitStream *stream, int value, int bit_count)
{
    for (int i = 0; i < bit_count; i++)
    {
        if (value & (1 << i))
        {
            stream->buffer[stream->pos / 8] |= (1 << (stream->pos % 8));
        }
        else
        {
            stream->buffer[stream->pos / 8] &= ~(1 << (stream->pos % 8));
        }
        stream->pos++;
    }
}

// Encodes a literal using Hendricks codes and writes it to the bitstream
void encode_literal(BitStream *stream, int literal)
{
    Code code = hendricks_ltree[literal];
    write_bits(stream, code.code, code.bit_length);
}

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

// Encodes a distance-length pair using Hendricks codes
int encode_length_distance(BitStream* output, int length, int distance) {
    // Encode the match length using Hendricks codes
    int length_code = 0;
    for (length_code = 0; length_code < D_CODES; length_code++)
    {
        if (base_lengths[length_code] > length)
            break;
    }
    length_code--;

    encode_literal(output, LITERALS + 1 + length_code);

    // Handle extra bits for the match length
    if (extra_length_bits[length_code] > 0)
    {
        int extra_bits = length - base_lengths[length_code];
        write_bits(output, extra_bits, extra_length_bits[length_code]);
    }

    // Encode the match distance
    encode_distance(output, distance);
}

// Hex-encode a byte array
void hex_encode(char* input, int input_size, char* output) {
    static const char hex_chars[] = "0123456789ABCDEF";

    for (int i = 0; i < input_size; ++i) {
        *output++ = hex_chars[input[i] >> 4];
        *output++ = hex_chars[input[i] & 0xF];
    }
    *output = '\0';
}

int main(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <length> <distance>\n", argv[0]);
        return 1;
    }

    int length = atoi(argv[1]);
    int distance = atoi(argv[2]);

    BitStream output_stream;
    output_stream.pos = 0;
    output_stream.size = MAX_INPUT_SIZE;
    memset(output_stream.buffer, '\0', MAX_INPUT_SIZE);

    encode_length_distance(&output_stream, length, distance);

    char output[MAX_INPUT_SIZE] = {0};
    hex_encode(output_stream.buffer, (output_stream.pos + 7) / 8, output);


    puts(output);

}
