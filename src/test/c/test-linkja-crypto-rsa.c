#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <setjmp.h>
#include <string.h>
#include <openssl/rsa.h>
#include <cmocka.h>

#include "../../linkja-crypto.h"

static unsigned char* read_pem_key(char *file_name, size_t *file_len) {
    FILE *fp = fopen(file_name, "rb");
    if (fp == NULL) {
        return NULL;
    }

    fseek(fp, 0, SEEK_END);
    *file_len = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    unsigned char* buffer = malloc(*file_len + 1);
    fread(buffer, *file_len, 1, fp);
    fclose(fp);

    return buffer;
}

static void test_rsa_encrypt_no_data(void **state) {
    // Message to be encrypted
    unsigned char *plaintext =
        (unsigned char *)"The quick brown fox jumps over the lazy dog";

    // Buffer for ciphertext. Ensure the buffer is long enough for the
    // ciphertext which equals the RSA key length we've chosen.
    unsigned char ciphertext[RSA_KEY_SIZE];
    int cipher_len;

    // All empty
    assert_false(rsa_encrypt(NULL, 0,
                    NULL, 0,
                    NULL, &cipher_len));

    // Output array specified
    assert_false(rsa_encrypt(NULL, 0,
                    NULL, 0,
                    ciphertext, &cipher_len));

    // Plaintext only
    assert_false(rsa_encrypt(plaintext, strlen ((char *)plaintext),
                    NULL, 0,
                    ciphertext, &cipher_len));

    // All set - key invalid
    size_t file_len = 0;
    unsigned char *public_key = read_pem_key("invalid-public-test.key", &file_len);
    assert_false(rsa_encrypt(plaintext, strlen ((char *)plaintext),
                    public_key, file_len,
                    ciphertext, &cipher_len));

    // All set - plaintext too short
    file_len = 0;
    public_key = read_pem_key("public-test.key", &file_len);
    assert_false(rsa_encrypt(plaintext, MIN_PLAINTEXT_LEN - 5,
                    public_key, file_len,
                    ciphertext, &cipher_len));

    // All set - plaintext too long
    file_len = 0;
    public_key = read_pem_key("public-test.key", &file_len);
    assert_false(rsa_encrypt(plaintext, MAX_PLAINTEXT_LEN + 1,
                    public_key, file_len,
                    ciphertext, &cipher_len));
}

static void test_rsa_decrypt_no_data(void **state) {
    // Message to be decrypted
    unsigned char *ciphertext =
        (unsigned char *)"The quick brown fox jumps over the lazy dog";

    // Buffer for plaintext. Ensure the buffer is long enough for the
    // plaintext which can't exceed the RSA key length we've chosen.
    unsigned char plaintext[RSA_KEY_SIZE];
    int plain_len;

    // All empty
    assert_false(rsa_decrypt(NULL, 0,
                    NULL, 0,
                    NULL, &plain_len));

    // Output array specified
    assert_false(rsa_decrypt(NULL, 0,
                    NULL, 0,
                    plaintext, &plain_len));

    // Ciphertext only
    assert_false(rsa_decrypt(ciphertext, strlen ((char *)ciphertext),
                    NULL, 0,
                    plaintext, &plain_len));

    // All set - key invalid
    size_t file_len = 0;
    unsigned char *private_key = read_pem_key("invalid-private-test.key", &file_len);
    assert_false(rsa_decrypt(ciphertext, strlen ((char *)ciphertext),
                    private_key, file_len,
                    plaintext, &plain_len));

    // All set - ciphertext too short
    file_len = 0;
    private_key = read_pem_key("private-test.key", &file_len);
    assert_false(rsa_decrypt(ciphertext, MIN_PLAINTEXT_LEN - 5,
                    private_key, file_len,
                    plaintext, &plain_len));

    // All set - ciphertext too long
    file_len = 0;
    private_key = read_pem_key("private-test.key", &file_len);
    assert_false(rsa_decrypt(ciphertext, RSA_KEY_SIZE + 1,
                    private_key, file_len,
                    plaintext, &plain_len));
}

static void test_rsa_roundtrip(void **state) {
    unsigned char *original_data = (unsigned char*)"This is a test string";
    int original_data_len = 21;

    // Encrypt using the public key
    size_t file_len = 0;
    unsigned char *public_key = read_pem_key("public-test.key", &file_len);
    unsigned char encrypted[RSA_KEY_SIZE];
    int encrypted_len = 0;
    bool result = rsa_encrypt(original_data, original_data_len, public_key, file_len, encrypted, &encrypted_len);
    // Confirm encryption works as expected
    assert_true(result);
    assert_true(RSA_KEY_SIZE == encrypted_len);
    free(public_key);
    public_key = NULL;

    // Perform decryption using the private key
    file_len = 0;
    unsigned char *private_key = read_pem_key("private-test.key", &file_len);
    unsigned char decrypted[RSA_KEY_SIZE];
    int decrypted_len = 0;
    result = rsa_decrypt(encrypted, encrypted_len, private_key, file_len, decrypted, &decrypted_len);
    // Confirm decryption works, and returned data matches
    assert_true(result);
    assert_true(original_data_len == decrypted_len);
    assert_memory_equal(decrypted, original_data, original_data_len);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_rsa_encrypt_no_data),
    	cmocka_unit_test(test_rsa_decrypt_no_data),
		cmocka_unit_test(test_rsa_roundtrip)
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
