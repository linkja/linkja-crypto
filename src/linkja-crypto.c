#include <jni.h>
#include <stdio.h>
#include "include/linkja_crypto_Library.h"

#include <openssl/rsa.h>

JNIEXPORT void JNICALL Java_linkja_crypto_Library_test
  (JNIEnv* env, jobject thisObject) {
    printf("linkja-crypto test method\r\n");

    RSA_free(NULL);
    //AES_set_encrypt_key(NULL, NULL, NULL);
}
