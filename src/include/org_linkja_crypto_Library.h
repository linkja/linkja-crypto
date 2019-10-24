/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class org_linkja_crypto_Library */

#ifndef _Included_org_linkja_crypto_Library
#define _Included_org_linkja_crypto_Library
#ifdef __cplusplus
extern "C" {
#endif
/*
 * Class:     org_linkja_crypto_Library
 * Method:    hash
 * Signature: (Ljava/lang/String;)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_org_linkja_crypto_Library_hash
  (JNIEnv *, jclass, jstring);

/*
 * Class:     org_linkja_crypto_Library
 * Method:    createSecureHash
 * Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_org_linkja_crypto_Library_createSecureHash
  (JNIEnv *, jclass, jstring, jstring, jstring);

/*
 * Class:     org_linkja_crypto_Library
 * Method:    revertSecureHash
 * Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_org_linkja_crypto_Library_revertSecureHash
  (JNIEnv *, jclass, jstring, jstring, jstring);

/*
 * Class:     org_linkja_crypto_Library
 * Method:    generateToken
 * Signature: (I)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_org_linkja_crypto_Library_generateToken
  (JNIEnv *, jclass, jint);

/*
 * Class:     org_linkja_crypto_Library
 * Method:    generateKey
 * Signature: (I)[B
 */
JNIEXPORT jbyteArray JNICALL Java_org_linkja_crypto_Library_generateKey
  (JNIEnv *, jclass, jint);

/*
 * Class:     org_linkja_crypto_Library
 * Method:    getLibrarySignature
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_org_linkja_crypto_Library_getLibrarySignature
  (JNIEnv *, jclass);

#ifdef __cplusplus
}
#endif
#endif
