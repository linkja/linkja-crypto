#ifdef INCLUDE_SECRETS

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <setjmp.h>
#include <cmocka.h>

#include "../../linkja-crypto.h"

const char row_id[] = "1234";
const jsize row_id_len = 4;
const char token_id[] = "hash1";
const jsize token_id_len = 5;

static void test_hash_supplemental_data_row_null(void **state) {
	unsigned char output[HASH_OUTPUT_BUFFER_LEN];
	assert_false(hash_supplemental_data(NULL, row_id_len, token_id, token_id_len, output));
}

static void test_hash_supplemental_data_row_invalid_size(void **state) {
	unsigned char output[HASH_OUTPUT_BUFFER_LEN];
	assert_false(hash_supplemental_data(row_id, -1, token_id, token_id_len, output));
}

static void test_hash_supplemental_data_token_null(void **state) {
	unsigned char output[HASH_OUTPUT_BUFFER_LEN];
	assert_false(hash_supplemental_data(row_id, row_id_len, NULL, token_id_len, output));
}

static void test_hash_supplemental_data_token_invalid_size(void **state) {
	unsigned char output[HASH_OUTPUT_BUFFER_LEN];
	assert_false(hash_supplemental_data(row_id, row_id_len, token_id, -1, output));
}

static void test_hash_supplemental_data_valid(void **state) {
	unsigned char output[HASH_OUTPUT_BUFFER_LEN];
	assert_true(hash_supplemental_data(row_id, row_id_len, token_id, token_id_len, output));

	// Ideally we'd have a controlled check here, but the secret can change, meaning
	// this test will need to be updated any time the secret is updated.  Instead we
	// are just checking for a non-empty string.
	char result[HASH_STRING_OUTPUT_BUFFER_LEN];
  bytes_to_hex_string(output, HASH_OUTPUT_BUFFER_LEN, result, HASH_STRING_OUTPUT_BUFFER_LEN);
	assert_string_not_equal(result, "");
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_hash_supplemental_data_row_null),
		cmocka_unit_test(test_hash_supplemental_data_row_invalid_size),
		cmocka_unit_test(test_hash_supplemental_data_token_null),
		cmocka_unit_test(test_hash_supplemental_data_token_invalid_size),
		cmocka_unit_test(test_hash_supplemental_data_valid)
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}

#endif
