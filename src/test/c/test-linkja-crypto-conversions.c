#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <setjmp.h>
#include <cmocka.h>

#include "../../linkja-crypto.h"

static void test_bytes_to_hex_string_input_null(void **state) {
  size_t input_len = 4;
  unsigned char input[] = {0x13, 0x01, 0x59, 0xFA};
  size_t output_len = (input_len * 2) + 1;
  char output[output_len];
  assert_false(bytes_to_hex_string(NULL, input_len, output, output_len));
}

static void test_bytes_to_hex_string_input_too_small(void **state) {
  size_t input_len = 4;
  unsigned char input[] = {0x13, 0x01, 0x59, 0xFA};
  size_t output_len = (input_len * 2) + 1;
  char output[output_len];
  assert_false(bytes_to_hex_string(input, 0, output, output_len));
}

static void test_bytes_to_hex_string_output_null(void **state) {
  size_t input_len = 4;
  unsigned char input[] = {0x13, 0x01, 0x59, 0xFA};
  size_t output_len = (input_len * 2) + 1;
  char output[output_len];
  assert_false(bytes_to_hex_string(input, input_len, NULL, output_len));
}

static void test_bytes_to_hex_string_output_too_small(void **state) {
  size_t input_len = 4;
  unsigned char input[] = {0x13, 0x01, 0x59, 0xFA};
  size_t output_len = (input_len * 2) + 1;
  char output[output_len];
  assert_false(bytes_to_hex_string(input, input_len, output, 0));
}

static void test_bytes_to_hex_string_output_will_not_fit(void **state) {
  size_t input_len = 4;
  unsigned char input[] = {0x13, 0x01, 0x59, 0xFA};
  size_t output_len = input_len;
  char output[output_len];
  assert_false(bytes_to_hex_string(input, input_len, output, output_len));
}

static void test_bytes_to_hex_string_valid(void **state) {
  size_t input_len = 4;
  unsigned char input[] = {0x13, 0x01, 0x59, 0xFA};
  size_t output_len = (input_len * 2) + 1;
  char output[output_len];
  assert_true(bytes_to_hex_string(input, input_len, output, output_len));
  assert_string_equal("130159fa", output);
}

static void test_hex_string_to_bytes_input_null(void **state) {
  size_t input_len = 8;
  size_t output_len = (input_len + 1) / 2;
  unsigned char output[output_len];
  assert_false(hex_string_to_bytes(NULL, input_len, output, output_len));
}

static void test_hex_string_to_bytes_input_too_small(void **state) {
  size_t input_len = 8;
  char input[] = "130159fa";
  size_t output_len = (input_len + 1) / 2;
  unsigned char output[output_len];
  assert_false(hex_string_to_bytes(input, 0, output, output_len));
}

static void test_hex_string_to_bytes_output_null(void **state) {
  size_t input_len = 8;
  char input[] = "130159fa";
  size_t output_len = (input_len + 1) / 2;
  unsigned char output[output_len];
  assert_false(hex_string_to_bytes(input, input_len, NULL, output_len));
}

static void test_hex_string_to_bytes_output_too_small(void **state) {
  size_t input_len = 8;
  char input[] = "130159fa";
  size_t output_len = (input_len + 1) / 2;
  unsigned char output[output_len];
  assert_false(hex_string_to_bytes(input, input_len, output, 0));
}

static void test_hex_string_to_bytes_output_will_not_fit(void **state) {
  size_t input_len = 8;
  char input[] = "130159fa";
  size_t output_len = input_len;
  unsigned char output[output_len];
  assert_false(hex_string_to_bytes(input, input_len, output, output_len));
}

static void test_hex_string_to_bytes_valid(void **state) {
  size_t input_len = 8;
  char input[] = "130159fa";
  size_t output_len = (input_len + 1) / 2;
  unsigned char output[output_len];
  assert_true(hex_string_to_bytes(input, input_len, output, output_len));
  assert_true(0x13 == output[0]);
  assert_true(0x01 == output[1]);
  assert_true(0x59 == output[2]);
  assert_true(0xFA == output[3]);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_bytes_to_hex_string_input_null),
		cmocka_unit_test(test_bytes_to_hex_string_input_too_small),
		cmocka_unit_test(test_bytes_to_hex_string_output_null),
		cmocka_unit_test(test_bytes_to_hex_string_output_too_small),
		cmocka_unit_test(test_bytes_to_hex_string_output_will_not_fit),
		cmocka_unit_test(test_bytes_to_hex_string_valid),
  	cmocka_unit_test(test_hex_string_to_bytes_input_null),
		cmocka_unit_test(test_hex_string_to_bytes_input_too_small),
		cmocka_unit_test(test_hex_string_to_bytes_output_null),
		cmocka_unit_test(test_hex_string_to_bytes_output_too_small),
		cmocka_unit_test(test_hex_string_to_bytes_output_will_not_fit),
		cmocka_unit_test(test_hex_string_to_bytes_valid),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
