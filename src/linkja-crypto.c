#include <jni.h>
#include <stdio.h>
#include "include/linkja_crypto_Library.h"

JNIEXPORT void JNICALL Java_linkja_crypto_Library_test
  (JNIEnv* env, jobject thisObject) {
    printf("linkja-crypto test method\r\n");
}
