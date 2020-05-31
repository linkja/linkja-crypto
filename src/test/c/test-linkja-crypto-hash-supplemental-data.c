#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <setjmp.h>
#include <cmocka.h>

#include "../../linkja-crypto.h"

const unsigned char session_key[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
const jsize session_key_len = 32;
const char row_id[] = "1234";
const jsize row_id_len = 4;
const char token_id[] = "hash1";
const jsize token_id_len = 5;

static void test_hash_supplemental_data_session_key_null(void **state) {
	unsigned char output[HASH_OUTPUT_BUFFER_LEN];
	assert_false(hash_supplemental_data(NULL, session_key_len, row_id, row_id_len, token_id, token_id_len, output));
}

static void test_hash_supplemental_data_session_key_invalid_size(void **state) {
	unsigned char output[HASH_OUTPUT_BUFFER_LEN];
	assert_false(hash_supplemental_data(session_key, -1, row_id, row_id_len, token_id, token_id_len, output));
}

static void test_hash_supplemental_data_row_null(void **state) {
	unsigned char output[HASH_OUTPUT_BUFFER_LEN];
	assert_false(hash_supplemental_data(session_key, session_key_len, NULL, row_id_len, token_id, token_id_len, output));
}

static void test_hash_supplemental_data_row_invalid_size(void **state) {
	unsigned char output[HASH_OUTPUT_BUFFER_LEN];
	assert_false(hash_supplemental_data(session_key, session_key_len, row_id, -1, token_id, token_id_len, output));
}

static void test_hash_supplemental_data_token_null(void **state) {
	unsigned char output[HASH_OUTPUT_BUFFER_LEN];
	assert_false(hash_supplemental_data(session_key, session_key_len, row_id, row_id_len, NULL, token_id_len, output));
}

static void test_hash_supplemental_data_token_invalid_size(void **state) {
	unsigned char output[HASH_OUTPUT_BUFFER_LEN];
	assert_false(hash_supplemental_data(session_key, session_key_len, row_id, row_id_len, token_id, -1, output));
}

static void test_hash_supplemental_data_valid(void **state) {
	unsigned char output[HASH_OUTPUT_BUFFER_LEN];
	assert_true(hash_supplemental_data(session_key, session_key_len, row_id, row_id_len, token_id, token_id_len, output));

	// Ideally we'd have a controlled check here, but the secret can change, meaning
	// this test will need to be updated any time the secret is updated.  Instead we
	// are just checking for a non-empty string.
	char result[HASH_STRING_OUTPUT_BUFFER_LEN];
  bytes_to_hex_string(output, HASH_OUTPUT_BUFFER_LEN, result, HASH_STRING_OUTPUT_BUFFER_LEN);
	assert_string_not_equal(result, "");
}

int main(void) {
	const struct CMUnitTest tests[] = {
    cmocka_unit_test(test_hash_supplemental_data_session_key_null),
    cmocka_unit_test(test_hash_supplemental_data_session_key_invalid_size),
		cmocka_unit_test(test_hash_supplemental_data_row_null),
		cmocka_unit_test(test_hash_supplemental_data_row_invalid_size),
		cmocka_unit_test(test_hash_supplemental_data_token_null),
		cmocka_unit_test(test_hash_supplemental_data_token_invalid_size),
		cmocka_unit_test(test_hash_supplemental_data_valid)
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
