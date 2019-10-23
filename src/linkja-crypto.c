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
   - utility method to take an input byte array (`input`) and create
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
  Adapted from https://stackoverflow.com/a/31007189
*/
void hex_string_to_bytes(const char input[], unsigned int input_len, unsigned char* output)
{
  unsigned int input_index = 0;
  unsigned int output_index = 0;
  if (input_len % 2 == 1) {
    // input is an odd length, so assume an implicit "0" prefix
    if (sscanf(&(input[0]), "%1hhx", &(output[0])) != 1) {
      return;
    }

    input_index = output_index = 1;
  }

  for (; input_index < input_len; input_index += 2, output_index++) {
    if (sscanf(&(input[input_index]), "%2hhx", &(output[output_index])) != 1) {
      return;
    }
  }
}

/*
  hash_string - given an input character array ('string'), calculate the SHA512
  hash and return a character array ('output') that contains the hexadecimal
  representation of the hash.

  This method assumes that 'output' is HASH_OUTPUT_BUFFER_LEN characters in length

  e.g. string -> "test"
       output -> "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
*/
bool hash_string(const char *string, unsigned char output[HASH_OUTPUT_BUFFER_LEN])
{
  if (string == NULL) {
    memset(output, 0, HASH_OUTPUT_BUFFER_LEN);
    return false;
  }

  return hash_data((unsigned char*)string, strlen(string), output);
}

/*
  hash_data - given an input byte array ('data'), calculate the SHA512
  hash and return a character array ('output') that contains the hexadecimal
  representation of the hash.

  This method assumes that 'output' is HASH_OUTPUT_BUFFER_LEN characters in length

  e.g. data -> 313233346861736831961E45165B002C23DEC32F60828D5AE37C2ADCB11990B69BA847851E71A0A989
       output -> "b5499df2a587a3a91390f6f7c632318fbb8078e0907924d2edbdfc3f408ab2c45f5f84ff4dba3dba775c0a475c8429e743eec3c3a44be8f6690535a5533921a5"
*/
bool hash_data(const unsigned char *data, size_t data_len, unsigned char output[HASH_OUTPUT_BUFFER_LEN])
{
  memset(output, 0, HASH_OUTPUT_BUFFER_LEN);

  // Note that we are allowing data where the length is 0.  Just like with an empty
  // string, we can generate a hash from that, so we need to allow that to be
  // processed.
  if (data == NULL || data_len < 0) {
    return false;
  }

  //unsigned char hash[SHA512_DIGEST_LENGTH];
  SHA512_CTX sha256;
  SHA512_Init(&sha256);
  SHA512_Update(&sha256, data, data_len);
  SHA512_Final(output, &sha256);
  //bytes_to_hex_string(hash, SHA512_DIGEST_LENGTH, output, HASH_OUTPUT_BUFFER_LEN);
  return true;
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

/*

  Returns:
*/
bool hash_supplemental_data(const char *row_id_str, jsize row_id_len, const char *token_id_str, jsize token_id_len, unsigned char output[])
{
  memset(output, 0, HASH_OUTPUT_BUFFER_LEN);

  // If any of the input strings aren't valid (null data or lengths < 0), we are
  // going to abort and return with an empty response;
  if (!row_id_str || row_id_len <= 0) {
    return false;
  } else if (!token_id_str || token_id_len <= 0) {
    return false;
  }

  // Note that this is not a string, it's an array of bytes (because that's how
  // the secret is stored).  Some of the data may be strings, but we ignore
  // their NULL terminators when building our concatenated data array.
  unsigned char *supplemental = NULL;
  size_t supplemental_len = LINKJA_SECRET_LEN + row_id_len + token_id_len;
  if ((supplemental = malloc(supplemental_len)) == NULL) {
    return false;
  }
  memset(supplemental, 0, supplemental_len);

  memcpy(supplemental, row_id_str, row_id_len);
  memcpy(supplemental+row_id_len, token_id_str, token_id_len);
  const unsigned char secret[LINKJA_SECRET_LEN] = LINKJA_SECRET;
  memcpy(supplemental+row_id_len+token_id_len, secret, LINKJA_SECRET_LEN);

  bool result = hash_data(supplemental, supplemental_len, output);
  free(supplemental);  // Be sure we clean up supplemental string
  supplemental = NULL;

  return result;
}

/*
  This is a JNI-specific wrapper around hash_supplemental_data.  It takes as input the
  allowed JNI types.  We created this so that hash_supplemental_data can be easier to
  setup and test for unit testing, without having to construct jstrings.
*/
bool generate_supplemental_hash(JNIEnv *env, jstring rowId, jstring tokenId, unsigned char supplemental_hash[])
{
  jsize row_id_len = (*env)->GetStringUTFLength(env, rowId);
  const char *row_id_str = (*env)->GetStringUTFChars(env, rowId, 0);
  jsize token_id_len = (*env)->GetStringUTFLength(env, tokenId);
  const char *token_id_str = (*env)->GetStringUTFChars(env, tokenId, 0);
  bool supplemental_created = hash_supplemental_data(row_id_str, row_id_len, token_id_str, token_id_len, supplemental_hash);
  (*env)->ReleaseStringUTFChars(env, rowId, row_id_str);
  (*env)->ReleaseStringUTFChars(env, tokenId, token_id_str);

  return supplemental_created;
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

  unsigned char hash[HASH_OUTPUT_BUFFER_LEN];
  const char *str = (*env)->GetStringUTFChars(env, input, 0);
  bool result = hash_string(str, hash);
  (*env)->ReleaseStringUTFChars(env, input, str);

  if (!result) {
    return (*env)->NewStringUTF(env, "");
  }

  char output[HASH_STRING_OUTPUT_BUFFER_LEN];
  bytes_to_hex_string(hash, HASH_OUTPUT_BUFFER_LEN, output, HASH_STRING_OUTPUT_BUFFER_LEN);
  return (*env)->NewStringUTF(env, output);
}

JNIEXPORT jstring JNICALL Java_org_linkja_crypto_Library_createSecureHash
  (JNIEnv *env, jclass obj, jstring input, jstring rowId, jstring tokenId)
{
  (void)obj;  // Avoid warning about unused parameters.

  // Generate the hash token for the real data
  unsigned char hash1[HASH_OUTPUT_BUFFER_LEN];
  const char *input_str = (*env)->GetStringUTFChars(env, input, 0);
  bool hash1_result = hash_string(input_str, hash1);
  (*env)->ReleaseStringUTFChars(env, input, input_str);
  if (!hash1_result) {
    return (*env)->NewStringUTF(env, "");
  }


  // Generate a second hash based off of our internal secret, the row identifier
  // and the token identifier.  If something went wrong we need to stop processing.
  unsigned char supplemental_hash[HASH_OUTPUT_BUFFER_LEN];
  if (!generate_supplemental_hash(env, rowId, tokenId, supplemental_hash)) {
    return (*env)->NewStringUTF(env, "");
  }

  unsigned char final_hash[HASH_OUTPUT_BUFFER_LEN];
  for (int index = 0; index < HASH_OUTPUT_BUFFER_LEN; index++) {
    final_hash[index] = hash1[index] ^ supplemental_hash[index];
  }

  char output[HASH_STRING_OUTPUT_BUFFER_LEN];
  bytes_to_hex_string(final_hash, HASH_OUTPUT_BUFFER_LEN, output, HASH_STRING_OUTPUT_BUFFER_LEN);
  return (*env)->NewStringUTF(env, output);
}

JNIEXPORT jstring JNICALL Java_org_linkja_crypto_Library_revertSecureHash
  (JNIEnv *env, jclass obj, jstring input, jstring rowId, jstring tokenId)
{
  (void)obj;  // Avoid warning about unused parameters.

  // Generate the supplemental hash based off of our internal secret, the row identifier
  // and the token identifier.  If something went wrong we need to stop processing.
  unsigned char supplemental_hash[HASH_OUTPUT_BUFFER_LEN];
  if (!generate_supplemental_hash(env, rowId, tokenId, supplemental_hash)) {
    return (*env)->NewStringUTF(env, "");
  }

  // The contents of input are a STRING - representing the hexadecimal values of each byte in
  // the original byte array.  We need to convert this to a byte array first, before we can
  // run our XOR operation.
  const char *input_str = (*env)->GetStringUTFChars(env, input, 0);
  jsize input_len = (*env)->GetStringUTFLength(env, input);
  // The output array size is half the hex_str length (rounded up)
  int input_hash_len = (input_len+1)/2;
  unsigned char input_hash[input_hash_len];
  hex_string_to_bytes(input_str, (int)input_len, input_hash);
  (*env)->ReleaseStringUTFChars(env, input, input_str);

  unsigned char original_hash[HASH_OUTPUT_BUFFER_LEN];
  for (int index = 0; index < HASH_OUTPUT_BUFFER_LEN; index++) {
    original_hash[index] = input_hash[index] ^ supplemental_hash[index];
  }

  char output[HASH_STRING_OUTPUT_BUFFER_LEN];
  bytes_to_hex_string(original_hash, HASH_OUTPUT_BUFFER_LEN, output, HASH_STRING_OUTPUT_BUFFER_LEN);
  return (*env)->NewStringUTF(env, output);
}

JNIEXPORT jstring JNICALL Java_org_linkja_crypto_Library_getLibrarySignature
   (JNIEnv *env, jobject obj)
{
  (void)obj;  // Avoid warning about unused parameters.

  return (*env)->NewStringUTF(env, LINKJA_SECRET_HASH);
}
