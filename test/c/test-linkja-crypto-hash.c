#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "../../src/include/org_linkja_crypto_Library.h"

static void test_hash_stub(void **state) {
	assert_int_equal(1, 1);
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_hash_stub),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
