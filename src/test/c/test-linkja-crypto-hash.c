#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <setjmp.h>
#include <cmocka.h>

#include "../../linkja-crypto.h"

static void test_hash_string_null(void **state) {
	unsigned char output[HASH_OUTPUT_BUFFER_LEN];
	assert_false(hash_string(NULL, output));
}

static void test_hash_string_empty(void **state) {
	unsigned char output[HASH_OUTPUT_BUFFER_LEN];
	assert_true(hash_string("", output));
	char result[HASH_STRING_OUTPUT_BUFFER_LEN];
  bytes_to_hex_string(output, HASH_OUTPUT_BUFFER_LEN, result, HASH_STRING_OUTPUT_BUFFER_LEN);
  assert_string_equal(result, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
	// For SHA-512: assert_string_equal(result, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
}

static void test_hash_string_value(void **state) {
	unsigned char output[HASH_OUTPUT_BUFFER_LEN];
	assert_true(hash_string("test", output));
	char result[HASH_STRING_OUTPUT_BUFFER_LEN];
  bytes_to_hex_string(output, HASH_OUTPUT_BUFFER_LEN, result, HASH_STRING_OUTPUT_BUFFER_LEN);
  assert_string_equal(result, "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08");
	// For SHA-512: assert_string_equal(result, "ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff");
}

static void test_hash_data_null(void **state) {
	unsigned char output[HASH_OUTPUT_BUFFER_LEN];
	assert_false(hash_string(NULL, output));
}

static void test_hash_data_empty(void **state) {
	unsigned char output[HASH_OUTPUT_BUFFER_LEN];
	unsigned char data[] = { 0x0 };
	assert_true(hash_data(data, 0, output));
	char result[HASH_STRING_OUTPUT_BUFFER_LEN];
  bytes_to_hex_string(output, HASH_OUTPUT_BUFFER_LEN, result, HASH_STRING_OUTPUT_BUFFER_LEN);
  assert_string_equal(result, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
	// For SHA-512: assert_string_equal(result, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
}

static void test_hash_data_value(void **state) {
	unsigned char output[HASH_OUTPUT_BUFFER_LEN];
	unsigned char data[] = { 't', 'e', 's', 't' };
	assert_true(hash_data(data, 4, output));
	char result[HASH_STRING_OUTPUT_BUFFER_LEN];
  bytes_to_hex_string(output, HASH_OUTPUT_BUFFER_LEN, result, HASH_STRING_OUTPUT_BUFFER_LEN);
  assert_string_equal(result, "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08");
	// For SHA-512: assert_string_equal(result, "ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff");
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_hash_string_null),
		cmocka_unit_test(test_hash_string_empty),
		cmocka_unit_test(test_hash_string_value),
		cmocka_unit_test(test_hash_data_null),
		cmocka_unit_test(test_hash_data_empty),
		cmocka_unit_test(test_hash_data_value)
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
