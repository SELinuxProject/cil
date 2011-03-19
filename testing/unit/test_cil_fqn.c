#include <sepol/policydb/policydb.h>

#include "CuTest.h"
#include "CilTest.h"

#include "../../src/cil_fqn.h"

void test_cil_qualify_name(CuTest *tc) {
	char *line[] = {"(", "role",  "staff_r", ")",
			"(", "user", "staff_u", ")",
			"(", "userrole", "staff_u", "staff_r", ")", NULL};
	/*char *line[] = {"(", "category", "c0", ")",
			"(", "categoryorder", "(", "c0", ")", ")",
			"(", "sensitivity", "s0", ")",
			"(", "sensitivitycategory", "s0", "(", "c0", ")", ")",
			"(", "type", "blah_t", ")",
			"(", "role", "blah_r", ")",
			"(", "user", "blah_u", ")",
			"(", "context", "con", "(", "blah_u", "blah_r", "blah_t", "(", "s0", "(", "c0", ")", ")", "(", "s0", "(", "c0", ")", ")", ")", ")",
			"(", "sid", "test", "con", NULL};*/

	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	cil_build_ast(test_db, tree->root, test_db->ast->root);

	//int rc = cil_qualify_name(test_db->ast->root->cl_head->next->next);
	int rc = cil_qualify_name(test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

//(class file inherits file (open))
void test_cil_qualify_name_cil_flavor(CuTest *tc) {
	char *line[] = {"(", "class",  "file", "inherits", "file",
			"(", "open", ")", ")", NULL};

	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	cil_build_ast(test_db, tree->root, test_db->ast->root);

	//int rc = cil_qualify_name(test_db->ast->root->cl_head->next->next);
	int rc = cil_qualify_name(test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}
