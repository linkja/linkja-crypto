#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <setjmp.h>
#include <cmocka.h>

#include "../../linkja-crypto.h"

static void test_generate_token_too_small(void **state) {
	int token_len = (TOKEN_MIN_LEN - 1);
	char output[(token_len * 2) + 1];
	assert_false(generate_token(token_len, output));
}

static void test_generate_token_too_long(void **state) {
	int token_len = (TOKEN_MAX_LEN + 1);
	char output[(token_len * 2) + 1];
	assert_false(generate_token(token_len, output));
}

static void test_generate_token_just_right(void **state) {
	int token_len = 32;
	char output[(token_len * 2) + 1];
	assert_true(generate_token(token_len, output));
	assert_string_not_equal(output, "");  // It'll be random, but not empty
}

static void test_generate_key_too_small(void **state) {
	int key_len = (KEY_MIN_LEN - 1);
	unsigned char output[key_len];
	assert_false(generate_key(key_len, output));
}

static void test_generate_key_too_long(void **state) {
	int key_len = (KEY_MAX_LEN + 1);
	unsigned char output[key_len];
	assert_false(generate_key(key_len, output));
}

static void test_generate_key_just_right(void **state) {
	int key_len = 64;
	unsigned char output[key_len];
	assert_true(generate_key(key_len, output));
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_generate_token_too_small),
		cmocka_unit_test(test_generate_token_too_long),
		cmocka_unit_test(test_generate_token_just_right),
		cmocka_unit_test(test_generate_key_too_small),
		cmocka_unit_test(test_generate_key_too_long),
		cmocka_unit_test(test_generate_key_just_right)
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
