#include <sepol/policydb/policydb.h>

#include "CuTest.h"
#include "test_cil_symtab.h"

#include "../../src/cil_tree.h"
#include "../../src/cil_symtab.h"
#include "../../src/cil.h"

void test_cil_symtab_insert(CuTest *tc) {
	symtab_t *test_symtab = NULL;
	char* test_name = "test";
	struct cil_block *test_block = malloc(sizeof(struct cil_block));

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);   

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	cil_symtab_array_init(test_block->symtab, CIL_SYM_NUM);

	test_block->is_abstract = 0;
	test_block->condition = NULL;

	cil_get_parent_symtab(test_db, test_ast_node, &test_symtab, CIL_SYM_BLOCKS);

	int rc = cil_symtab_insert(test_symtab, (hashtab_key_t)test_name, (struct cil_symtab_datum*)test_block, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}
