#include <sepol/policydb/policydb.h>

#include "CuTest.h"
#include "CilTest.h"
#include "test_cil_parser.h"

#include "../../src/cil_parser.h"
#include "../../src/cil.h"

// TODO rewrite to use the gen_tree function
void test_cil_parser(CuTest *tc) {
	int rc = 0;
	struct cil_file_data *data;

	struct cil_tree *test_parse_root;
	cil_tree_init(&test_parse_root);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	set_cil_file_data(&data);

	rc = cil_parser(data->buffer, data->file_size + 2, &test_parse_root);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, test_parse_root);
	// TODO add checking of the parse tree that is returned
}

