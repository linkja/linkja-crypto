#ifdef INCLUDE_SECRETS

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <setjmp.h>
#include <cmocka.h>

#include "../../linkja-crypto.h"

const char input[] = "This is a test of data";
const jsize input_len = 22;

static void test_hash_input_data_input_null(void **state) {
	unsigned char output[HASH_OUTPUT_BUFFER_LEN];
	assert_false(hash_input_data(NULL, input_len, output));
}

static void test_hash_input_data_input_invalid_size(void **state) {
	unsigned char output[HASH_OUTPUT_BUFFER_LEN];
	assert_false(hash_input_data(input, -1, output));
}

static void test_hash_input_data_valid(void **state) {
	unsigned char output[HASH_OUTPUT_BUFFER_LEN];
	assert_true(hash_input_data(input, input_len, output));

	// Ideally we'd have a controlled check here, but the secret can change, meaning
	// this test will need to be updated any time the secret is updated.  Instead we
	// are just checking for a non-empty string.
	char result[HASH_STRING_OUTPUT_BUFFER_LEN];
  bytes_to_hex_string(output, HASH_OUTPUT_BUFFER_LEN, result, HASH_STRING_OUTPUT_BUFFER_LEN);
	assert_string_not_equal(result, "");
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_hash_input_data_input_null),
		cmocka_unit_test(test_hash_input_data_input_invalid_size),
		cmocka_unit_test(test_hash_input_data_valid)
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}

#endif
