#include <sepol/policydb/policydb.h>

#include "CuTest.h"

#include "../../src/cil.h"
#include "../../src/cil_tree.h"

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

void test_cil_db_init(CuTest *tc) {
	struct cil_db *test_db;

	int rc = cil_db_init(&test_db);

	CuAssertIntEquals(tc, 0, rc);
	CuAssertPtrNotNull(tc, test_db->ast);
	CuAssertPtrNotNull(tc, test_db->symtab);
	CuAssertPtrNotNull(tc, test_db->symtab);
}

// TODO: Reach SEPOL_ERR return in cil_db_init ( currently can't produce a method to do so )

void test_cil_get_parent_symtab_block(CuTest *tc) {
	symtab_t *symtab = NULL;
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->parent->flavor = CIL_BLOCK;
	test_ast_node->line = 1;

	int rc = cil_get_parent_symtab(test_db, test_ast_node, &symtab, CIL_SYM_BLOCKS);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, symtab);
}

void test_cil_get_parent_symtab_class(CuTest *tc) {
	symtab_t *symtab = NULL;
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->parent->flavor = CIL_CLASS;
	test_ast_node->line = 1;

	int rc = cil_get_parent_symtab(test_db, test_ast_node, &symtab, CIL_SYM_BLOCKS);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, symtab);
}

void test_cil_get_parent_symtab_root(CuTest *tc) {
	symtab_t *symtab = NULL;
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->parent->flavor = CIL_ROOT;
	test_ast_node->line = 1;

	int rc = cil_get_parent_symtab(test_db, test_ast_node, &symtab, CIL_SYM_BLOCKS);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, symtab);
}

void test_cil_get_parent_symtab_other_neg(CuTest *tc) {
	symtab_t *symtab = NULL;
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->parent->flavor = 1234567;
	test_ast_node->line = 1;

	int rc = cil_get_parent_symtab(test_db, test_ast_node, &symtab, CIL_SYM_BLOCKS);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
	CuAssertPtrEquals(tc, symtab, NULL);
}

void test_cil_get_parent_symtab_null_neg(CuTest *tc) {
	symtab_t *symtab = NULL;
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = NULL;
	test_ast_node->line = 1;

	int rc = cil_get_parent_symtab(test_db, test_ast_node, &symtab, CIL_SYM_BLOCKS);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
	CuAssertPtrEquals(tc, symtab, NULL);
}

void test_cil_get_parent_symtab_node_null_neg(CuTest *tc) {
	symtab_t *symtab = NULL;
	
	struct cil_tree_node *test_ast_node = NULL;

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_get_parent_symtab(test_db, test_ast_node, &symtab, CIL_SYM_BLOCKS);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
	CuAssertPtrEquals(tc, symtab, NULL);
	CuAssertPtrEquals(tc, test_ast_node, NULL);
}

void test_cil_get_parent_symtab_parent_null_neg(CuTest *tc) {
	symtab_t *symtab = NULL;
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = NULL;
	test_ast_node->line = 1;

	int rc = cil_get_parent_symtab(test_db, test_ast_node, &symtab, CIL_SYM_BLOCKS);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
	CuAssertPtrEquals(tc, symtab, NULL);
}

