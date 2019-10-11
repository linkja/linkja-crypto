#ifndef LINKJA_CRYPTO_H
#define LINKJA_CRYPTO_H

#include <openssl/sha.h>

#define HASH_OUTPUT_BUFFER_LEN ((SHA512_DIGEST_LENGTH * 2) + 1)

// The minimum and maximum lengths allowed for generating random tokens.
// Note that these are the sizes of the byte arry.
#define TOKEN_MIN_LEN 1
#define TOKEN_MAX_LEN 32768

void hash_string(const char *string, char output[]);

void generate_token(unsigned int length, char output[]);

#endif
