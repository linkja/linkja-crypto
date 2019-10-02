#include <jni.h>
#include <stdio.h>
#include "include/linkja_crypto_Library.h"
#include "include/linkja_secret.h"

#include <openssl/rsa.h>

JNIEXPORT void JNICALL Java_linkja_crypto_Library_test
  (JNIEnv* env, jobject thisObject) {
    printf("linkja-crypto test method\r\n");
    printf("%lu\r\n", sizeof(LINKJA_SECRET));

    RSA_free(NULL);
    //AES_set_encrypt_key(NULL, NULL, NULL);
}
