#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <setjmp.h>
#include <cmocka.h>

#include "../../linkja-crypto.h"

static void test_hash_string_null(void **state) {
	char output[HASH_OUTPUT_BUFFER_LEN];
	hash_string(NULL, output);
	assert_string_equal(output, "");
}

static void test_hash_string_empty(void **state) {
	char output[HASH_OUTPUT_BUFFER_LEN];
	hash_string("", output);
	assert_string_equal(output, "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
}

static void test_hash_string_value(void **state) {
	char output[HASH_OUTPUT_BUFFER_LEN];
	hash_string("test", output);
	assert_string_equal(output, "ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff");
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_hash_string_null),
		cmocka_unit_test(test_hash_string_empty),
		cmocka_unit_test(test_hash_string_value)
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
