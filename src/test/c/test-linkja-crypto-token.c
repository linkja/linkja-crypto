#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <setjmp.h>
#include <cmocka.h>

#include "../../linkja-crypto.h"

static void test_generate_token_too_small(void **state) {
	int token_len = (TOKEN_MIN_LEN - 1);
	char output[(token_len * 2) + 1];
	generate_token(token_len, output);
	assert_string_equal(output, "");
}

static void test_generate_token_too_long(void **state) {
	int token_len = (TOKEN_MIN_LEN - 1);
	char output[(token_len * 2) + 1];
	generate_token(token_len, output);
	assert_string_equal(output, "");
}

static void test_generate_token_just_right(void **state) {
	int token_len = 32;
	char output[(token_len * 2) + 1];
	generate_token(token_len, output);
	assert_string_not_equal(output, "");  // It'll be random, but not empty
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_generate_token_too_small),
		cmocka_unit_test(test_generate_token_too_long),
		cmocka_unit_test(test_generate_token_just_right)
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
