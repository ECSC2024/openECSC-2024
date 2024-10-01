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

// ---------------------------------------------------------
// Utility functions (Swap, Hex Conversion, Input Handling)
// ---------------------------------------------------------

// Function to swap two elements of type 'Code'
void swap(Code *a, Code *b)
{
    Code temp = *a;
    *a = *b;
    *b = temp;
}

// Converts a single hexadecimal character to its integer equivalent
int hex_char_to_int(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1; // Invalid hex character
}

// Memory-safe version of hex decoding
// Converts a hex string into a byte array (bit stream)
int hex_decode(const char *input, int input_size, uint8_t *output_stream)
{
    int size = 0;
    for (int i = 0; i < input_size; i += 2)
    {
        int high_nibble = hex_char_to_int(input[i]);
        int low_nibble = hex_char_to_int(input[i + 1]);

        if (high_nibble == -1 || low_nibble == -1)
        {
            fprintf(stderr, "\n[Error] Invalid hex character.\n");
            return -1;
        }

        output_stream[size++] = (high_nibble << 4) | low_nibble;
    }
    return size;
}

// Prompts user for hex input and decodes it into the provided BitStream
int get_hex_input(BitStream *input)
{
    int hex_size = sizeof(input->buffer) * 2 + 1;
    char *tmp_buffer = (char *)alloca(hex_size);

    // Prompt for user input
    printf("\nPlease enter the input string (hex format): ");
    if (fgets(tmp_buffer, hex_size, stdin) == NULL)
    {
        fprintf(stderr, "\n[Error] Failed to read input. Please try again.\n");
        return -1;
    }

    // Strip newline character from input
    tmp_buffer[strcspn(tmp_buffer, "\n")] = 0;
    int input_size = strlen(tmp_buffer);

    // Validate hex input length
    if (input_size % 2 != 0)
    {
        fprintf(stderr, "\n[Error] Invalid hex input.\n");
        return -1;
    }

    // Decode hex input
    int input_buffer_size = hex_decode(tmp_buffer, input_size, input->buffer);
    if (input_buffer_size == -1)
        return -1;

    input->size = input_buffer_size;
    return input_buffer_size;
}

// Function to read an integer from user input
int get_int()
{
    char input[128];
    fgets(input, sizeof(input), stdin);
    return atoi(input);
}

// Function to validate an integer input with a default and max value
int read_and_validate_input(const char *prompt, int default_value, int max_value)
{
    printf("\n%s (default: %d): ", prompt, default_value);
    int val = get_int();
    if (val < 1 || val > max_value)
    {
        fprintf(stderr, "\n[Error] Input out of range.\n");
        return -1;
    }
    return val;
}

// ---------------------------------------------------------
// BitStream operations (Writing and Reading Bits)
// ---------------------------------------------------------

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

// Reads 'bit_count' bits from the bitstream
int read_bits(BitStream *stream, int bit_count)
{
    int value = 0;
    for (int i = 0; i < bit_count; i++)
    {
        if (stream->buffer[stream->pos / 8] & (1 << (stream->pos % 8)))
        {
            value |= (1 << i);
        }
        stream->pos++;
    }
    return value;
}

// ---------------------------------------------------------
// Encoding and Decoding Functions
// ---------------------------------------------------------

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

// ---------------------------------------------------------
// Compression and Decompression Functions
// ---------------------------------------------------------

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

// ---------------------------------------------------------
// Result Printing Functions (Compression and Decompression)
// ---------------------------------------------------------

// Prints the result of the compression
void print_compression_results(BitStream *input, BitStream *output)
{
    int compressed_size = (output->pos + 7) / 8; // Round up bit position to bytes
    int decompressed_size = input->size;
    float weissman_score = (float)decompressed_size / (float)compressed_size;

    printf("\n============= Compression Result =============\n");
    printf("Compressed size         : %d bytes\n", compressed_size);
    printf("Decompressed size       : %d bytes\n", decompressed_size);
    printf("Weissman score          : %.3f\n", weissman_score);
    printf("Output (hex)            : ");
    for (int i = 0; i < (output->pos + 7) / 8; ++i)
    {
        printf("%02X", output->buffer[i]);
    }
    printf("\n==============================================\n");
}

// Prints the result of the decompression
void print_decompression_results(BitStream *input, BitStream *output)
{
    int compressed_size = (input->pos + 7) / 8; // Round up bit position to bytes
    int decompressed_size = output->pos;
    float weissman_score = (float)decompressed_size / (float)compressed_size;

    printf("\n============ Decompression Result ============\n");
    printf("Compressed size         : %d bytes\n", compressed_size);
    printf("Decompressed size       : %d bytes\n", decompressed_size);
    printf("Weissman score          : %.3f\n", weissman_score);
    printf("Output (hex)            : ");
    for (int i = 0; i < output->pos; ++i)
    {
        printf("%02X", output->buffer[i]);
    }
    printf("\n==============================================\n");
}

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

// Handles the decompression operation
void do_decompress()
{
    BitStream input_stream;
    BitStream output_stream;
    output_stream.pos = 0;
    output_stream.size = MAX_INPUT_SIZE;
    memset(output_stream.buffer, '\0', MAX_INPUT_SIZE);

    if (get_hex_input(&input_stream) == -1)
        return;
    if (MO_Decompress(&input_stream, &output_stream) == -1)
        return;

    print_decompression_results(&input_stream, &output_stream);
}

// Handles parameter changes for window size and match length
void do_change_parameters()
{
    int val;

    val = read_and_validate_input("Enter the window size", DEFAULT_WINDOW_SIZE, MAX_WINDOW_SIZE);
    if (val == -1)
        return;
    window_size = val;

    val = read_and_validate_input("Enter the minimum match length", DEFAULT_MIN_MATCH, MAX_LENGTH);
    if (val == -1)
        return;
    min_match = val;

    printf("\n[+] Parameters updated successfully.\n");
}

// Shuffles the Hendricks L-Tree
void do_shuffle()
{
    for (int i = L_CODES - 1; i > 0; i--)
    {
        int j = rand() % (i + 1);
        swap(&hendricks_ltree[i], &hendricks_ltree[j]);
    }
    printf("\n[+] Shuffled L-Tree\n");
}

// Prints the Hendricks L-Tree
void do_print_ltree()
{
    printf("\n[+] L-Tree\n");
    for (int i = 0; i < L_CODES; i++)
    {
        printf("    [%3d] -> %3d", i, hendricks_ltree[i].code);
        if ((i + 1) % 5 == 0 || i == L_CODES - 1)
        {
            printf("\n");
        }
        else
        {
            printf("    ");
        }
    }
}

// ---------------------------------------------------------
// Menu and Initialization Functions
// ---------------------------------------------------------

// Displays the menu
void menu()
{
    printf("\n==============================================\n");
    printf("     Middle-Out + Hendricks Codes Engine\n");
    printf("==============================================\n");
    printf("  1. Compress\n");
    printf("  2. Decompress\n");
    printf("  3. Change Parameters\n");
    printf("  4. Shuffle L-Tree\n");
    printf("  5. Print L-Tree\n");
    printf("  6. Exit\n");
    printf("==============================================\n");
    printf("  Please select an option: ");
}

// Initializes the application (disables buffering, seeds RNG)
void init()
{
    // Disable buffering on stdin, stdout, and stderr
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    // Seed the random number generator
    srand(time(NULL));
}

// ---------------------------------------------------------
// Main Function
// ---------------------------------------------------------

// Main entry point of the application
int main()
{
    init(); // Initialize application

    printf("==============================================\n");
    printf("  Welcome to the alpha version of Middle-Out  \n");
    printf("          + Hendricks Codes engine!           \n");
    printf("==============================================\n");

    int choice;
    do
    {
        menu();
        choice = get_int();

        switch (choice)
        {
        case 1:
            do_compress();
            break;
        case 2:
            do_decompress();
            break;
        case 3:
            do_change_parameters();
            break;
        case 4:
            do_shuffle();
            break;
        case 5:
            do_print_ltree();
            break;
        case 6:
            return 0;
        default:
            fprintf(stderr, "\n[Error] Invalid choice.\n");
            break;
        }
    } while (1);

    return 0;
}
