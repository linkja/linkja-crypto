#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <setjmp.h>
#include <string.h>
#include <cmocka.h>

#include "../../linkja-crypto.h"

static void test_aes_encrypt_no_data(void **state) {
    unsigned char key[AES_KEY_SIZE];
    generate_key(AES_KEY_SIZE, key);

    size_t iv_len = AES_DEFAULT_IV_LEN;
    unsigned char iv[iv_len];
    generate_key(iv_len, iv);

    // Message to be encrypted
    unsigned char *plaintext =
        (unsigned char *)"The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog";

    // Additional data
    unsigned char *additional = (unsigned char *)"The five boxing wizards jump quickly.";

    // Buffer for ciphertext. Ensure the buffer is long enough for the
    // ciphertext which may be longer than the plaintext, depending on the
    // algorithm and mode.
    unsigned char ciphertext[ENCRYPTED_ARRAY_LEN(strlen((char *)plaintext))];
    int cipher_len;

    // Buffer for the tag
    unsigned char tag[AES_TAG_LEN];

    // All empty
    assert_false(aes_gcm_encrypt(NULL, 0,
                    NULL, 0,
                    NULL, 0,
                    NULL, 0,
                    ciphertext, &cipher_len, tag));

    // Plaintext only
    assert_false(aes_gcm_encrypt(plaintext, strlen ((char *)plaintext),
                    NULL, 0,
                    NULL, 0,
                    NULL, 0,
                    ciphertext, &cipher_len, tag));

    // Plaintext + AAD
    assert_false(aes_gcm_encrypt(plaintext, strlen ((char *)plaintext),
                    additional, strlen ((char *)additional),
                    NULL, 0,
                    NULL, 0,
                    ciphertext, &cipher_len, tag));

    // Plaintext + AAD + KEY
    assert_false(aes_gcm_encrypt(plaintext, strlen ((char *)plaintext),
                    additional, strlen ((char *)additional),
                    key, AES_KEY_SIZE,
                    NULL, 0,
                    ciphertext, &cipher_len, tag));


    // All set - key wrong size
    assert_false(aes_gcm_encrypt(plaintext, strlen ((char *)plaintext),
                    additional, strlen ((char *)additional),
                    key, AES_KEY_SIZE - 2,
                    iv, iv_len,
                    ciphertext, &cipher_len, tag));


    // All set - IV wrong size
    assert_false(aes_gcm_encrypt(plaintext, strlen ((char *)plaintext),
                    additional, strlen ((char *)additional),
                    key, AES_KEY_SIZE,
                    iv, 0,
                    ciphertext, &cipher_len, tag));
}

static void test_aes_decrypt_no_data(void **state) {
    // We're reusing data from the encrypt test - it's fine that this is never
    // able to actually decrypt, we just need memory locations to be set and filled.
    unsigned char key[AES_KEY_SIZE];
    generate_key(AES_KEY_SIZE, key);

    size_t iv_len = AES_DEFAULT_IV_LEN;
    unsigned char iv[iv_len];
    generate_key(iv_len, iv);

    // Message to be decrypted
    unsigned char *ciphertext =
        (unsigned char *)"The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog";

    // Additional data
    unsigned char *additional = (unsigned char *)"The five boxing wizards jump quickly.";

    // Buffer for plaintext.
    unsigned char plaintext[strlen((char *)ciphertext)];
    int plaintext_len;

    // Buffer for the tag
    unsigned char tag[AES_TAG_LEN];

    // All empty
    assert_false(aes_gcm_decrypt(NULL, 0,
                    NULL, 0,
                    NULL,
                    NULL, 0,
                    NULL, 0,
                    plaintext, &plaintext_len));

    // Plaintext only
    assert_false(aes_gcm_decrypt(ciphertext, strlen ((char *)ciphertext),
                    NULL, 0,
                    NULL,
                    NULL, 0,
                    NULL, 0,
                    plaintext, &plaintext_len));

    // Plaintext + AAD
    assert_false(aes_gcm_decrypt(ciphertext, strlen ((char *)ciphertext),
                    additional, strlen ((char *)additional),
                    NULL,
                    NULL, 0,
                    NULL, 0,
                    plaintext, &plaintext_len));


    // Plaintext + AAD + tag
    assert_false(aes_gcm_decrypt(ciphertext, strlen ((char *)ciphertext),
                    additional, strlen ((char *)additional),
                    tag,
                    NULL, 0,
                    NULL, 0,
                    plaintext, &plaintext_len));

    // Plaintext + AAD + tag + key
    assert_false(aes_gcm_decrypt(ciphertext, strlen ((char *)ciphertext),
                    additional, strlen ((char *)additional),
                    tag,
                    key, AES_KEY_SIZE,
                    NULL, 0,
                    plaintext, &plaintext_len));


    // All set - tag wrong size
    unsigned char invalid_tag[4] = { 0x01, 0x02, 0x03, 0x04 };
    assert_false(aes_gcm_decrypt(ciphertext, strlen ((char *)ciphertext),
                    additional, strlen ((char *)additional),
                    invalid_tag,
                    key, AES_KEY_SIZE,
                    iv, iv_len,
                    plaintext, &plaintext_len));

    // All set - key wrong size
    assert_false(aes_gcm_decrypt(ciphertext, strlen ((char *)ciphertext),
                    additional, strlen ((char *)additional),
                    tag,
                    key, AES_KEY_SIZE - 2,
                    iv, iv_len,
                    plaintext, &plaintext_len));

    // All set - IV wrong size
    assert_false(aes_gcm_decrypt(ciphertext, strlen ((char *)ciphertext),
                    additional, strlen ((char *)additional),
                    tag,
                    key, AES_KEY_SIZE,
                    iv, 0,
                    plaintext, &plaintext_len));
}

// https://wiki.openssl.org/images/0/08/Evp-gcm-encrypt.c
// https://github.com/kulkarniamit/openssl-evp-demo/blob/master/openssl_evp_demo.c
static void test_aes_roundtrip(void **state) {
    unsigned char key[AES_KEY_SIZE];
    generate_key(AES_KEY_SIZE, key);

    size_t iv_len = AES_DEFAULT_IV_LEN;
    unsigned char iv[iv_len];
    generate_key(iv_len, iv);

    // Message to be encrypted
    unsigned char *plaintext =
        (unsigned char *)"The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog The quick brown fox jumps over the lazy dog";
    int plaintext_len = strlen((char *)plaintext);

    // Buffer for ciphertext. Ensure the buffer is long enough for the
    // ciphertext which may be longer than the plaintext, depending on the
    // algorithm and mode.
    unsigned char ciphertext[AES_BLOCK_SIZE + plaintext_len];
    int cipher_len;

    // Buffer for the tag
    unsigned char tag[AES_TAG_LEN];

    // Additional data
    unsigned char *additional = (unsigned char *)"The five boxing wizards jump quickly.";
    int aad_len = strlen((char *)additional);

    assert_true(aes_gcm_encrypt(plaintext, plaintext_len,
                    additional, aad_len,
                    key, AES_KEY_SIZE,
                    iv, iv_len,
                    ciphertext, &cipher_len, tag));

    // Decrypt the ciphertext
    int decrypted_len = 0;
    unsigned char decryptedtext[plaintext_len];
    assert_true(aes_gcm_decrypt(ciphertext, cipher_len,
                           additional, aad_len,
                           tag,
                           key, AES_KEY_SIZE, iv, iv_len,
                           decryptedtext, &decrypted_len));
    assert_true(decrypted_len == plaintext_len);
    assert_true(strncmp((char*)decryptedtext, (char*)plaintext, plaintext_len) == 0);
    assert_true(strlen((char*)plaintext) == decrypted_len);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_aes_encrypt_no_data),
    	cmocka_unit_test(test_aes_decrypt_no_data),
		cmocka_unit_test(test_aes_roundtrip)
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
