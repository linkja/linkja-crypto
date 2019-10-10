#include <jni.h>
#include <stdio.h>
#include "include/org_linkja_crypto_Library.h"
#include "include/linkja_secret.h"

#include <openssl/rsa.h>

JNIEXPORT jstring JNICALL Java_org_linkja_crypto_Library_getLibrarySignature
   (JNIEnv *env, jobject obj) {
 (void)obj;  // Avoid warning about unused parameters.

 return (*env)->NewStringUTF(env, LINKJA_SECRET_HASH);
}

JNIEXPORT jstring JNICALL Java_org_linkja_crypto_Library_hash
  (JNIEnv *env, jclass obj, jstring input) {
    (void)env;
    (void)obj;
    (void)input;

    return input;

}
