#include <jni.h>
#include <stdio.h>
#include <string.h>

#include "linkja-crypto.h"
#include "include/org_linkja_crypto_Library.h"
#include "include/linkja_secret.h"

#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/pem.h>


/*
    display_openssl_error - utility function to wrap the error handling display when
        encrypt/decrypt fails.  The caller still needs to return the appropriate
        status code.
*/
void display_openssl_error(EVP_CIPHER_CTX *ctx)
{
    ERR_print_errors_fp(stderr);
    EVP_CIPHER_CTX_free(ctx);
}

/*
    aes_gcm_encrypt - performs AES-256-GCM encryption of `plaintext`, using 'aad' as the
    additional authenticated data (to detect tampering).

    Output parameters:
      ciphertext - the encrypted data
      ciphertext_len - the length of the encrypted data array
      tag - used during the decryption operation to ensure that the ciphertext
            and AAD have not been tampered with.

    Returns: true if encryption was successful, false otherwise

    Derived from: https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption
    With input from: https://medium.com/@amit.kulkarni/encrypting-decrypting-a-file-using-openssl-evp-b26e0e4d28d4
*/
bool aes_gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                    unsigned char *aad, int aad_len,
                    unsigned char *key, int key_len,
                    unsigned char *iv, int iv_len,
                    unsigned char *ciphertext, int* ciphertext_len,
                    unsigned char *tag)
{
    *ciphertext_len = 0;

    if (plaintext_len <= 0 || aad_len <= 0 || key_len != AES_KEY_SIZE || iv_len <= 0) {
        return false;
    }

    // Create and initialise the context
    EVP_CIPHER_CTX *ctx = NULL;
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        display_openssl_error(ctx);
        return false;
    }

    // Initialise the encryption operation.
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        display_openssl_error(ctx);
        return false;
    }

    // Set IV length if default 12 bytes (96 bits) is not appropriate
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) {
        display_openssl_error(ctx);
        return false;
    }

    // Initialise key and IV
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
        display_openssl_error(ctx);
        return false;
    }

    int len = 0;
    // Provide any AAD data. This can be called zero or more times as required
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) {
        display_openssl_error(ctx);
        return false;
    }

    // Provide the message to be encrypted, and obtain the encrypted output.
    // EVP_EncryptUpdate can be called multiple times if necessary
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        display_openssl_error(ctx);
        return false;
    }
    *ciphertext_len = len;

    // Finalise the encryption. Normally ciphertext bytes may be written at
    // this stage, but this does not occur in GCM mode
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        display_openssl_error(ctx);
        return false;
    }
    *ciphertext_len += len;

    // Get the tag
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_TAG_LEN, tag)) {
        display_openssl_error(ctx);
        return false;
    }

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return true;
}

bool aes_gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len,
                unsigned char *tag,
                unsigned char *key, int key_len,
                unsigned char *iv, int iv_len,
                unsigned char *plaintext, int *plaintext_len)
{
    *plaintext_len = 0;

    if (ciphertext_len <= 0 || aad_len <= 0 || key_len <= 0 || iv_len <= 0) {
        return false;
    }

    // Create and initialise the context
    EVP_CIPHER_CTX *ctx = NULL;
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        display_openssl_error(ctx);
        return false;
    }

    // Initialise the decryption operation.
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        display_openssl_error(ctx);
        return false;
    }

    // Set IV length. Not necessary if this is 12 bytes (96 bits)
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) {
        display_openssl_error(ctx);
        return false;
    }

    // Initialise key and IV
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
        display_openssl_error(ctx);
        return false;
    }

    // Provide any AAD data. This can be called zero or more times as required
    int len = 0;
    if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)) {
        display_openssl_error(ctx);
        return false;
    }

    // Provide the message to be decrypted, and obtain the plaintext output.
    // EVP_DecryptUpdate can be called multiple times if necessary
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        display_openssl_error(ctx);
        return false;
    }
    *plaintext_len = len;

    // Set expected tag value. Works in OpenSSL 1.0.1d and later
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_TAG_LEN, tag)) {
        display_openssl_error(ctx);
        return false;
    }

    // Finalise the decryption. A positive return value indicates success,
    // anything else is a failure - the plaintext is not trustworthy.
    int ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        *plaintext_len += len;
        return true;
    } else {
        // Verify failed
        return false;
    }
}

bool rsa_encrypt(unsigned char *plaintext, int plaintext_len,
                 unsigned char *key, int key_len,
                 unsigned char *ciphertext, int* ciphertext_len)
{

    if (plaintext_len > MAX_PLAINTEXT_LEN || plaintext_len < MIN_PLAINTEXT_LEN) {
        fprintf(stderr, "Input must be between %d and %d bytes, but was %d\r\n", MIN_PLAINTEXT_LEN, MAX_PLAINTEXT_LEN, plaintext_len);
        return false;
    }

    if (ciphertext == NULL) {
        fprintf(stderr, "The encrypted output array must be allocated before calling rsa_encrypt\r\n");
        return false;
    }
    memset(ciphertext, 0, MAX_PLAINTEXT_LEN);

    // Create and initialise the context
    EVP_CIPHER_CTX *ctx = NULL;
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        display_openssl_error(ctx);
        return false;
    }

    BIO *key_mem = BIO_new_mem_buf(key, key_len);
    if (key_mem == NULL) {
        display_openssl_error(ctx);
        return false;
    }

    EVP_PKEY *public_key = PEM_read_bio_PUBKEY(key_mem, NULL, NULL, NULL);
    BIO_free(key_mem);
    if (public_key == NULL) {
        display_openssl_error(ctx);
        return false;
    }

    RSA *rsa = EVP_PKEY_get1_RSA(public_key);
    EVP_PKEY_free(public_key);
    if (rsa == NULL) {
        display_openssl_error(ctx);
        return false;
    }
    else if (RSA_size(rsa) != RSA_KEY_SIZE) {
        fprintf(stderr, "We are only able to handle a key size of %d, but received %d\r\n", (RSA_KEY_SIZE * 8), (RSA_size(rsa) * 8));
        RSA_free(rsa);
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    *ciphertext_len = RSA_public_encrypt(plaintext_len, plaintext, ciphertext, rsa, RSA_PKCS1_OAEP_PADDING);
    RSA_free(rsa);
    if (*ciphertext_len == -1) {
        memset(ciphertext, 0, MAX_PLAINTEXT_LEN);
        display_openssl_error(ctx);
        return false;
    }

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return true;
}

bool rsa_decrypt(unsigned char *ciphertext, int ciphertext_len,
                 unsigned char *key, int key_len,
                 unsigned char *plaintext, int *plaintext_len)
{
    if (ciphertext_len != RSA_KEY_SIZE) {
        fprintf(stderr, "Input must be exactly %d bytes, but was %d\r\n", RSA_KEY_SIZE, ciphertext_len);
        return false;
    }

    if (plaintext == NULL) {
        fprintf(stderr, "The decrypted output array must be allocated before calling rsa_decrypt\r\n");
        return false;
    }
    memset(plaintext, 0, RSA_KEY_SIZE);

    // Create and initialise the context
    EVP_CIPHER_CTX *ctx = NULL;
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        display_openssl_error(ctx);
        return false;
    }

    BIO *key_mem = BIO_new_mem_buf(key, key_len);
    if (key_mem == NULL) {
        display_openssl_error(ctx);
        return false;
    }

    EVP_PKEY *private_key = PEM_read_bio_PrivateKey(key_mem, NULL, NULL, NULL);
    BIO_free(key_mem);
    if (private_key == NULL) {
        display_openssl_error(ctx);
        return false;
    }

    RSA *rsa = EVP_PKEY_get1_RSA(private_key);
    EVP_PKEY_free(private_key);
    if (rsa == NULL) {
        display_openssl_error(ctx);
        return false;
    }
    else if (RSA_size(rsa) != RSA_KEY_SIZE) {
        fprintf(stderr, "We are only able to handle a key size of %d, but received %d\r\n", (RSA_KEY_SIZE * 8), (RSA_size(rsa) * 8));
        RSA_free(rsa);
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    *plaintext_len = RSA_private_decrypt(ciphertext_len, ciphertext, plaintext, rsa, RSA_PKCS1_OAEP_PADDING);
    RSA_free(rsa);
    if (*plaintext_len == -1) {
        memset(plaintext, 0, MAX_PLAINTEXT_LEN);
        display_openssl_error(ctx);
        return false;
    }

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return true;
}


/*
  bytes_to_hex_string - utility method to take an input byte array (`input`) and create
  a character array representing the hex characters for each byte ('output').

  Returns: true if successful, false otherwise
*/
bool bytes_to_hex_string(unsigned char* input, unsigned int input_len, char output[], unsigned int output_len)
{
  if (input == NULL || input_len == 0 || output == NULL || output_len == 0) {
    return false;
  }

  // The output array size is twice the input string length (1 byte -> 2 characters)
  // plus one more (NULL terminator).  If this doesn't match up exactly, we will exit.
  unsigned int max_output_len = (input_len * 2) + 1;
  if (max_output_len != output_len) {
    return false;
  }

  for (unsigned int i = 0; i < input_len; i++) {
    sprintf(output + (i * 2), "%02x", input[i]);
  }

  // The last character needs to be NULL string terminator
  output[output_len] = 0;
  return true;
}

/*
  hex_string_to_bytes - utility method to take an input character array ('input') that
  represents a hexadecimal string, and convert it to the corresponding byte array
  representation ('output');

  Returns: true if successful, false otherwise

  Adapted from https://stackoverflow.com/a/31007189
*/
bool hex_string_to_bytes(const char input[], unsigned int input_len, unsigned char* output, unsigned int output_len)
{
  if (input == NULL || input_len == 0 || output == NULL || output_len == 0) {
    return false;
  }

  // The output array size is half the input string length (2 characters -> 1 byte)
  // If this doesn't match up exactly, we will exit.
  unsigned int max_output_len = (input_len + 1) / 2;
  if (max_output_len != output_len) {
    return false;
  }

  unsigned int input_index = 0;
  unsigned int output_index = 0;
  if (input_len % 2 == 1) {
    // input is an odd length, so assume an implicit "0" prefix
    if (sscanf(&(input[0]), "%1hhx", &(output[0])) != 1) {
      return false;
    }

    input_index = output_index = 1;
  }

  for (; input_index < input_len; input_index += 2, output_index++) {
    // If at any point we violate our lengths, we need to stop
    if (input_index > input_len || output_index > output_len) {
      return false;
    }

    if (sscanf(&(input[input_index]), "%2hhx", &(output[output_index])) != 1) {
      return false;
    }
  }

  return true;
}

/*
  hash_string - given an input character array ('string'), calculate the SHA512
  hash and return a character array ('output') that contains the hexadecimal
  representation of the hash.

  Returns: true if successful, false otherwise

  This method assumes that 'output' is HASH_OUTPUT_BUFFER_LEN characters in length

  e.g. string -> "test"
       output -> ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff
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
  hash and return a byte array ('output') that contains the hash.

  Returns: true if successful, false otherwise

  This method assumes that 'output' is HASH_OUTPUT_BUFFER_LEN characters in length

  e.g. data -> 313233346861736831961E45165B002C23DEC32F60828D5AE37C2ADCB11990B69BA847851E71A0A989
       output -> b5499df2a587a3a91390f6f7c632318fbb8078e0907924d2edbdfc3f408ab2c45f5f84ff4dba3dba775c0a475c8429e743eec3c3a44be8f6690535a5533921a5
*/
bool hash_data(const unsigned char *data, size_t data_len, unsigned char output[HASH_OUTPUT_BUFFER_LEN])
{
  memset(output, 0, HASH_OUTPUT_BUFFER_LEN);

  // Note that we are allowing data where the length is 0.  Just like with an empty
  // string, we can generate a hash from that, so we need to allow that to be
  // processed.
  if (data == NULL) { // || data_len < 0) {
    return false;
  }

  SHA512_CTX sha256;
  SHA512_Init(&sha256);
  SHA512_Update(&sha256, data, data_len);
  SHA512_Final(output, &sha256);
  return true;
}

/*
  generate_token - generate a random array of 'length' bytes, and return a character
  array ('output') that contains the hexadecimal representation of the token.

  Returns: true if successful, false otherwise

  The size of 'output' will be (2 * length) + 1 characters.

  e.g. input -> 16
       output -> "d71a16753a7a31d6780ce6318a764524"
*/
bool generate_token(unsigned int length, char output[])
{
  if (length < TOKEN_MIN_LEN || length > TOKEN_MAX_LEN) {
    return false;
  }

  unsigned int output_len = ((length * 2) + 1);
  memset(output, 0, output_len);

  unsigned char token[length];
  int result = RAND_priv_bytes(token, length);
  if (result != 1) {
    return false;
  }

  return bytes_to_hex_string(token, length, output, output_len);
}

/*
  generate_bytes - internal function to generate a random array of 'length' bytes,
  and return a byte array ('output') that contains the data.

  NOTE: as an internal function, this assumes all validation checks are done
        on the parameters before it is called.

  Returns: true if successful, false otherwise

  The size of 'output' will match 'length';

  e.g. input -> 16
       output -> d71a16753a7a31d6780ce6318a764524
*/
bool generate_bytes(unsigned int length, unsigned char output[])
{
    memset(output, 0, length);

    int result = RAND_priv_bytes(output, length);
    if (result != 1) {
      return false;
    }

    return true;
}

/*
  generate_key - generate a random array of 'length' bytes, and return a byte
  array ('output') that contains the key data.

  Returns: true if successful, false otherwise

  The size of 'output' will match 'length';

  e.g. input -> 16
       output -> d71a16753a7a31d6780ce6318a764524
*/
bool generate_key(unsigned int length, unsigned char output[])
{
  if (length < KEY_MIN_LEN || length > KEY_MAX_LEN) {
    return false;
  }

  return generate_bytes(length, output);
}

/*
  generate_iv - generate a random array of 'length' bytes, and return a byte
  array ('output') that contains the IV data.

  Returns: true if successful, false otherwise

  The size of 'output' will match 'length';

  e.g. input -> 16
       output -> d71a16753a7a31d6780ce6318a764524
*/
bool generate_iv(unsigned int length, unsigned char output[])
{
  if (length < IV_MIN_LEN || length > IV_MAX_LEN) {
    return false;
  }

  return generate_bytes(length, output);
}

/*
  hash_supplemental_data - given a row identifier ('row_id_str') and token identifier
  ('token_id_str'), create a hash comprised of those values and the project-specific
  secret hash data.  This will return a byte array ('output') that contains the hash.

  Returns: true if successful, false otherwise
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

  Returns: true if successful, false otherwise
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

JNIEXPORT jbyteArray JNICALL Java_org_linkja_crypto_Library_generateKey
  (JNIEnv *env, jclass obj, jint length)
{
  (void)obj;  // Avoid warning about unused parameters.

  if (length < KEY_MIN_LEN || length > KEY_MAX_LEN) {
    return NULL;
  }

  unsigned char output[length];
  generate_key(length, output);
  jbyteArray key = (*env)->NewByteArray(env, length);
  (*env)->SetByteArrayRegion(env, key, 0, length, (jbyte*)output);
  return key;
}

JNIEXPORT jbyteArray JNICALL Java_org_linkja_crypto_Library_generateIV
  (JNIEnv *env, jclass obj, jint length)
{
  (void)obj;  // Avoid warning about unused parameters.

  if (length < IV_MIN_LEN || length > IV_MAX_LEN) {
    return NULL;
  }

  unsigned char output[length];
  generate_iv(length, output);
  jbyteArray key = (*env)->NewByteArray(env, length);
  (*env)->SetByteArrayRegion(env, key, 0, length, (jbyte*)output);
  return key;
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

  char output[HASH_STRING_OUTPUT_BUFFER_LEN + 1];
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

  char output[HASH_STRING_OUTPUT_BUFFER_LEN + 1];
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
  bool result = hex_string_to_bytes(input_str, (int)input_len, input_hash, input_hash_len);
  (*env)->ReleaseStringUTFChars(env, input, input_str);
  if (!result) {
    return (*env)->NewStringUTF(env, "");
  }

  unsigned char original_hash[HASH_OUTPUT_BUFFER_LEN];
  for (int index = 0; index < HASH_OUTPUT_BUFFER_LEN; index++) {
    original_hash[index] = input_hash[index] ^ supplemental_hash[index];
  }

  char output[HASH_STRING_OUTPUT_BUFFER_LEN + 1];
  bytes_to_hex_string(original_hash, HASH_OUTPUT_BUFFER_LEN, output, HASH_STRING_OUTPUT_BUFFER_LEN);
  return (*env)->NewStringUTF(env, output);
}

jobject aesEncryptDecrypt
  (JNIEnv *env, jbyteArray data, jbyteArray aad, jbyteArray key, jbyteArray iv, jbyteArray tag, bool encrypt)
{
    // All byte arrays must be defined.  Note that tag can be empty, but only for
    // the encryption call (because we need to specify it).
    if (data == NULL || aad == NULL || key == NULL || iv == NULL) {
        return NULL;
    }

    // If we're decrypting and there is no tag, then we will have to exit.
    if (!encrypt && tag == NULL) {
        return NULL;
    }

    // Now we can safely get our array lengths
    jsize data_array_len = (*env)->GetArrayLength(env, data);
    jsize aad_array_len = (*env)->GetArrayLength(env, aad);
    jsize key_array_len = (*env)->GetArrayLength(env, key);
    jsize iv_array_len = (*env)->GetArrayLength(env, iv);

    // All of the arrays need to be populated.  If this is not the case, we need
    // to exit now and won't do any other processing.
    if (data_array_len <= 0 || aad_array_len <= 0 || key_array_len != AES_KEY_SIZE || iv_array_len <= 0) {
        return NULL;
    }

    // Manage array lengths for the tag, but only when decrypting.
    if (!encrypt) {
        jsize tag_array_len = (*env)->GetArrayLength(env, tag);
        if (tag_array_len != AES_TAG_LEN) {
            return NULL;
        }
    }

    // Get the data
    jbyte* data_array = (*env)->GetByteArrayElements(env, data, NULL);
    jbyte* aad_array = (*env)->GetByteArrayElements(env, aad, NULL);
    jbyte* key_array = (*env)->GetByteArrayElements(env, key, NULL);
    jbyte* iv_array = (*env)->GetByteArrayElements(env, iv, NULL);
    unsigned char tag_array[AES_TAG_LEN];
    if (!encrypt) {
        (*env)->GetByteArrayRegion(env, tag, 0, AES_TAG_LEN, (jbyte*)tag_array);
    }

    int output_array_max_len = (encrypt ? ENCRYPTED_ARRAY_LEN(data_array_len) : data_array_len);
    unsigned char output_array[output_array_max_len];
    int output_array_len = 0;  // Actual length
    bool result = false;
    if (encrypt) {
        result =  aes_gcm_encrypt((unsigned char *)data_array, data_array_len,
                            (unsigned char *)aad_array, aad_array_len,
                            (unsigned char *)key_array, key_array_len,
                            (unsigned char *)iv_array, iv_array_len,
                            output_array, &output_array_len,
                            tag_array);
    }
    else {
        result =  aes_gcm_decrypt((unsigned char *)data_array, data_array_len,
                            (unsigned char *)aad_array, aad_array_len,
                            tag_array,
                            (unsigned char *)key_array, key_array_len,
                            (unsigned char *)iv_array, iv_array_len,
                            output_array, &output_array_len);
    }

    (*env)->ReleaseByteArrayElements(env, data, data_array, 0);
    (*env)->ReleaseByteArrayElements(env, aad, aad_array, 0);
    (*env)->ReleaseByteArrayElements(env, key, key_array, 0);
    (*env)->ReleaseByteArrayElements(env, iv, iv_array, 0);

    if (!result) {
        return NULL;
    }

    jclass java_class = (*env)->FindClass(env, "org/linkja/crypto/AesResult");
    if (java_class == NULL) {
        return NULL;
    }
    jobject result_obj = (*env)->AllocObject(env, java_class);
    if (result_obj == NULL) {
        return NULL;
    }

    jbyteArray output = (*env)->NewByteArray(env, output_array_len);
    (*env)->SetByteArrayRegion(env, output, 0, output_array_len, (jbyte*)output_array);
    jfieldID enc_data_id = (*env)->GetFieldID(env, java_class, "data", "[B");
    if (enc_data_id == NULL) {
        return NULL;
    }

    (*env)->SetObjectField(env, result_obj, enc_data_id, output);

    jfieldID tag_id = (*env)->GetFieldID(env, java_class, "tag", "[B");
    if (tag_id == NULL) {
        return NULL;
    }

    jbyteArray tag_output = (*env)->NewByteArray(env, AES_TAG_LEN);
    (*env)->SetByteArrayRegion(env, tag_output, 0, AES_TAG_LEN, (jbyte*)tag_array);
    (*env)->SetObjectField(env, result_obj, tag_id, tag_output);

    return result_obj;
}

jobject rsaEncryptDecrypt
  (JNIEnv *env, jbyteArray data, jbyteArray key, bool encrypt)
{
    // All byte arrays must be defined.
    if (data == NULL || key == NULL) {
        printf("1\r\n");
        return NULL;
    }

    // Now we can safely get our array lengths
    jsize data_array_len = (*env)->GetArrayLength(env, data);
    jsize key_array_len = (*env)->GetArrayLength(env, key);

    // All of the arrays need to be populated.  If this is not the case, we need
    // to exit now and won't do any other processing.
    if (data_array_len <= 0 || key_array_len <= 0) {
        printf("2\r\n");
        return NULL;
    }

    // Get the data
    jbyte* data_array = (*env)->GetByteArrayElements(env, data, NULL);
    jbyte* key_array = (*env)->GetByteArrayElements(env, key, NULL);

    unsigned char output_array[RSA_KEY_SIZE];
    int output_array_len = 0;  // Actual length
    bool result = false;
    if (encrypt) {
        result =  rsa_encrypt((unsigned char *)data_array, data_array_len,
                            (unsigned char *)key_array, key_array_len,
                            output_array, &output_array_len);
    }
    else {
        result =  rsa_decrypt((unsigned char *)data_array, data_array_len,
                            (unsigned char *)key_array, key_array_len,
                            output_array, &output_array_len);
    }

    (*env)->ReleaseByteArrayElements(env, data, data_array, 0);
    (*env)->ReleaseByteArrayElements(env, key, key_array, 0);

    if (!result) {
        printf("3\r\n");
        return NULL;
    }

    jclass java_class = (*env)->FindClass(env, "org/linkja/crypto/RsaResult");
    if (java_class == NULL) {
        printf("4\r\n");
        return NULL;
    }
    jobject result_obj = (*env)->AllocObject(env, java_class);
    if (result_obj == NULL) {
        printf("5\r\n");
        return NULL;
    }

    jbyteArray output = (*env)->NewByteArray(env, output_array_len);
    (*env)->SetByteArrayRegion(env, output, 0, output_array_len, (jbyte*)output_array);
    jfieldID enc_data_id = (*env)->GetFieldID(env, java_class, "data", "[B");
    if (enc_data_id == NULL) {
        return NULL;
    }

    (*env)->SetObjectField(env, result_obj, enc_data_id, output);

    jfieldID length_id = (*env)->GetFieldID(env, java_class, "length", "I");
    if (length_id == NULL) {
        return NULL;
    }

    (*env)->SetIntField(env, result_obj, length_id, output_array_len);

    return result_obj;
}

JNIEXPORT jobject JNICALL Java_org_linkja_crypto_Library_aesEncrypt
  (JNIEnv *env, jclass obj, jbyteArray data, jbyteArray aad, jbyteArray key, jbyteArray iv)
{
    (void)obj;  // Avoid warning about unused parameters.

    return aesEncryptDecrypt(env, data, aad, key, iv, NULL, true);
}

JNIEXPORT jobject JNICALL Java_org_linkja_crypto_Library_aesDecrypt
  (JNIEnv *env, jclass obj, jbyteArray data, jbyteArray aad, jbyteArray key, jbyteArray iv, jbyteArray tag)
{
    (void)obj;  // Avoid warning about unused parameters.

    return aesEncryptDecrypt(env, data, aad, key, iv, tag, false);
}

JNIEXPORT jobject JNICALL Java_org_linkja_crypto_Library_rsaEncrypt
  (JNIEnv *env, jclass obj, jbyteArray data, jbyteArray key)
{
    (void)obj;  // Avoid warning about unused parameters.

    return rsaEncryptDecrypt(env, data, key, true);
}

JNIEXPORT jobject JNICALL Java_org_linkja_crypto_Library_rsaDecrypt
  (JNIEnv *env, jclass obj, jbyteArray data, jbyteArray key)
{
    (void)obj;  // Avoid warning about unused parameters.

    return rsaEncryptDecrypt(env, data, key, false);
}

JNIEXPORT jstring JNICALL Java_org_linkja_crypto_Library_getLibrarySignature
   (JNIEnv *env, jobject obj)
{
  (void)obj;  // Avoid warning about unused parameters.

  return (*env)->NewStringUTF(env, LINKJA_SECRET_HASH);
}
