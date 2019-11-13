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
#define KEY_MIN_LEN 16      // 128-bit key min
#define KEY_MAX_LEN 256     // 2048-bit key max

#define AES_KEY_SIZE 32     // Assuming AES-256 implementation
#define AES_BLOCK_SIZE 16
// The calculated tag will always be 16 bytes long - https://crypto.stackexchange.com/a/26787
#define AES_TAG_LEN 16
// For GCM a 12 byte IV is strongly suggested as other IV lengths will require additional calculations
// https://crypto.stackexchange.com/a/26787
#define AES_DEFAULT_IV_LEN 12
#define IV_MIN_LEN AES_DEFAULT_IV_LEN
#define IV_MAX_LEN 256      // Arbitrary max

// Calculate the maximum encrypted array length that we can expect
#define ENCRYPTED_ARRAY_LEN(data_len) (AES_BLOCK_SIZE + data_len)


bool aes_gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                    unsigned char *aad, int aad_len,
                    unsigned char *key, int key_len,
                    unsigned char *iv, int iv_len,
                    unsigned char *ciphertext, int* ciphertext_len,
                    unsigned char *tag);

bool aes_gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                    unsigned char *aad, int aad_len,
                    unsigned char *tag,
                    unsigned char *key, int key_len,
                    unsigned char *iv, int iv_len,
                    unsigned char *plaintext, int *plaintext_len);

bool bytes_to_hex_string(unsigned char* input, unsigned int input_len, char output[], unsigned int output_len);

bool hex_string_to_bytes(const char input[], unsigned int input_len, unsigned char* output, unsigned int output_len);

bool hash_string(const char *string, unsigned char output[]);

bool hash_data(const unsigned char *data, size_t data_len, unsigned char output[]);

bool generate_token(unsigned int length, char output[]);

bool generate_key(unsigned int length, unsigned char output[]);

bool generate_iv(unsigned int length, unsigned char output[]);

bool hash_supplemental_data(const char *row_id_str, jsize row_id_len, const char *token_id_str, jsize token_id_len, unsigned char output[]);

#endif
