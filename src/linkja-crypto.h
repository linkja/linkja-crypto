#ifndef LINKJA_CRYPTO_H
#define LINKJA_CRYPTO_H

#include <openssl/sha.h>

#define HASH_OUTPUT_BUFFER_LEN ((SHA512_DIGEST_LENGTH * 2) + 1)

void hash_string(const char *string, char output[]);

#endif
