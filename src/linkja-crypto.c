#include <jni.h>
#include <stdio.h>
#include <string.h>

#include "linkja-crypto.h"
#include "include/org_linkja_crypto_Library.h"
#include "include/linkja_secret.h"

#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/rand.h>


/*
  bytes_to_hex_string - utility method to take an input byte array (`input`) and create
  a character array representing the hex characters for each byte ('output').
*/
void bytes_to_hex_string(unsigned char* input, unsigned int input_len, char output[], unsigned int output_len)
{
  for (unsigned int i = 0; i < input_len; i++) {
      sprintf(output + (i * 2), "%02x", input[i]);
  }

  // The last character needs to be NULL string terminator
  output[output_len] = 0;
}

/*
  hash_string - given an input character array ('string'), calculate the SHA512
  hash and return a character array ('output') that contains the hexadecimal
  representation of the hash.

  This method assumes that 'output' is HASH_OUTPUT_BUFFER_LEN characters in length

  e.g. string -> "test"
       output -> "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
*/
void hash_string(const char *string, char output[HASH_OUTPUT_BUFFER_LEN])
{
    memset(output, 0, HASH_OUTPUT_BUFFER_LEN);

    if (string == NULL) {
      return;
    }

    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512_CTX sha256;
    SHA512_Init(&sha256);
    SHA512_Update(&sha256, string, strlen(string));
    SHA512_Final(hash, &sha256);
    bytes_to_hex_string(hash, SHA512_DIGEST_LENGTH, output, HASH_OUTPUT_BUFFER_LEN);
}

/*
  generate_token - generate a random array of 'length' bytes, and return a character
  array ('output') that contains the hexadecimal representation of the token.

  The size of 'output' will be (2 * length) + 1 characters.

  e.g. input -> 16
       output -> "d71a16753a7a31d6780ce6318a764524"
*/
void generate_token(unsigned int length, char output[])
{
    unsigned int output_len = ((length * 2) + 1);
    memset(output, 0, output_len);

    unsigned char token[length];
    int result = RAND_priv_bytes(token, length);
    if (result != 1) {
      return;
    }
    
    bytes_to_hex_string(token, length, output, output_len);
}

JNIEXPORT jstring JNICALL Java_org_linkja_crypto_Library_generateToken
  (JNIEnv *env, jclass obj, jint length)
{
    (void)obj;  // Avoid warning about unused parameters.

    if (length < TOKEN_MIN_LEN || length > TOKEN_MAX_LEN) {
        return (*env)->NewStringUTF(env, "");
    }

    char output[(length * 2) + 1];
    generate_token(length, output);
    return (*env)->NewStringUTF(env, output);
}

JNIEXPORT jstring JNICALL Java_org_linkja_crypto_Library_hash
  (JNIEnv *env, jclass obj, jstring input)
{
    (void)obj;  // Avoid warning about unused parameters.

    char output[HASH_OUTPUT_BUFFER_LEN];
    const char *str= (*env)->GetStringUTFChars(env, input, 0);
    hash_string(str, output);
    return (*env)->NewStringUTF(env, output);
}

JNIEXPORT jstring JNICALL Java_org_linkja_crypto_Library_getLibrarySignature
   (JNIEnv *env, jobject obj)
{
    (void)obj;  // Avoid warning about unused parameters.

    return (*env)->NewStringUTF(env, LINKJA_SECRET_HASH);
}
