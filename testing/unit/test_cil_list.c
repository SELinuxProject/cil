#include "CuTest.h"
#include "CilTest.h"

#include "../../src/cil.h"

void test_cil_list_init(CuTest *tc) {
	struct cil_avrule *test_avrule = malloc(sizeof(struct cil_avrule));

	cil_list_init(&test_avrule->perms_str);
	CuAssertPtrNotNull(tc, test_avrule->perms_str);

	free(test_avrule);   
}
