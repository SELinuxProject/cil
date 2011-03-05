#include <sepol/policydb/policydb.h>

#include "CuTest.h"

#include "../../src/cil_symtab.h"
#include "../../src/cil.h"

void test_symtab_init(CuTest *tc) {
	struct cil_db *test_new_db;
	test_new_db = malloc(sizeof(struct cil_db));

	uint32_t rc = 0, i =0;
	
	for (i=0; i<CIL_SYM_NUM; i++) {
	    rc = symtab_init(&test_new_db->symtab[i], CIL_SYM_SIZE);
	    CuAssertIntEquals(tc, 0, rc);
	    // TODO CDS add checks to make sure the symtab looks correct
	}

	free(test_new_db);
}

void test_symtab_init_no_table_neg(CuTest *tc) {
	struct cil_db *test_new_db;
	test_new_db = malloc(sizeof(struct cil_db));

	int rc = symtab_init(&test_new_db->symtab[0], (uint32_t)SIZE_MAX);
	CuAssertIntEquals(tc, -1, rc);

	free(test_new_db);
}

void test_cil_symtab_array_init(CuTest *tc) {
	struct cil_db *test_new_db;
	test_new_db = malloc(sizeof(struct cil_db));

	int rc = cil_symtab_array_init(test_new_db->symtab, CIL_SYM_NUM);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, test_new_db->symtab);

	free(test_new_db);
}

// TODO: Reach SEPOL_ERR return in cil_symtab_array_init ( currently can't produce a method to do so )
void test_cil_symtab_array_init_null_symtab_neg(CuTest *tc) {
	symtab_t *test_symtab = NULL;

	int rc = cil_symtab_array_init(test_symtab, 1);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

