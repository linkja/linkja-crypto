#ifndef LINKJA_CRYPTO_H
#define LINKJA_CRYPTO_H

#include <stdbool.h>
#include <openssl/sha.h>
#include <jni.h>

// Define the length of the hash byte array used for function output
#define HASH_OUTPUT_BUFFER_LEN SHA512_DIGEST_LENGTH

// Define the length of the hex string character array used for function output
#define HASH_STRING_OUTPUT_BUFFER_LEN ((SHA512_DIGEST_LENGTH * 2) + 1)

// The minimum and maximum lengths allowed for generating random tokens.
// Note that these are the sizes of the byte arry.
#define TOKEN_MIN_LEN 1
#define TOKEN_MAX_LEN 32768


bool bytes_to_hex_string(unsigned char* input, unsigned int input_len, char output[], unsigned int output_len);

bool hex_string_to_bytes(const char input[], unsigned int input_len, unsigned char* output, unsigned int output_len);

bool hash_string(const char *string, unsigned char output[]);

bool hash_data(const unsigned char *data, size_t data_len, unsigned char output[]);

void generate_token(unsigned int length, char output[]);

bool hash_supplemental_data(const char *row_id_str, jsize row_id_len, const char *token_id_str, jsize token_id_len, unsigned char output[]);

#endif
