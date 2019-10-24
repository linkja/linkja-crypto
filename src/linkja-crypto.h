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
// Note that these are the sizes of the byte array.
#define TOKEN_MIN_LEN 1
#define TOKEN_MAX_LEN 32768

// The minimum and maximum lengths allowed for generating random keys.
// Note that these are the sizes of the byte array.  The limits are somewhat
// arbitrary, but are meant to encourage best practice for secure keys.
#define KEY_MIN_LEN 16    // 128-bit key min
#define KEY_MAX_LEN 256   // 2048-bit key max


bool bytes_to_hex_string(unsigned char* input, unsigned int input_len, char output[], unsigned int output_len);

bool hex_string_to_bytes(const char input[], unsigned int input_len, unsigned char* output, unsigned int output_len);

bool hash_string(const char *string, unsigned char output[]);

bool hash_data(const unsigned char *data, size_t data_len, unsigned char output[]);

bool generate_token(unsigned int length, char output[]);

bool generate_key(unsigned int length, unsigned char output[]);

bool hash_supplemental_data(const char *row_id_str, jsize row_id_len, const char *token_id_str, jsize token_id_len, unsigned char output[]);

#endif
