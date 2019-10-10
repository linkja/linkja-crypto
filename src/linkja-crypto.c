#include <jni.h>
#include <stdio.h>
#include <string.h>

#include "linkja-crypto.h"
#include "include/org_linkja_crypto_Library.h"
#include "include/linkja_secret.h"

#include <openssl/rsa.h>
#include <openssl/sha.h>

JNIEXPORT jstring JNICALL Java_org_linkja_crypto_Library_getLibrarySignature
   (JNIEnv *env, jobject obj)
{
 (void)obj;  // Avoid warning about unused parameters.

 return (*env)->NewStringUTF(env, LINKJA_SECRET_HASH);
}

/*
  hash_string - given an input character array (string), calculate the SHA512
  hash and return a character array (output) that contains the hexadecimal
  representation of the hash.

  This method assumes that output is HASH_OUTPUT_BUFFER_LEN characters in length

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
    int i = 0;
    for(i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }

    // The last character needs to be NULL string terminator
    output[HASH_OUTPUT_BUFFER_LEN] = 0;
}

JNIEXPORT jstring JNICALL Java_org_linkja_crypto_Library_hash
  (JNIEnv *env, jclass obj, jstring input)
{
    (void)env;
    (void)obj;
    (void)input;

    char output[HASH_OUTPUT_BUFFER_LEN];
    const char *str= (*env)->GetStringUTFChars(env, input, 0);
    hash_string(str, output);
    return (*env)->NewStringUTF(env, output);
}
