#include "CuTest.h"
#include "CilTest.h"

#include "../../src/cil.h"
#include "../../src/cil_copy_ast.h"
#include "../../src/cil_build_ast.h"
#include "../../src/cil_resolve_ast.h"

void test_cil_copy_list(CuTest *tc) {
	char *line[] = {"(", "foo1", "foo2", ")", NULL};

	struct cil_tree *test_tree;
	struct cil_list *cil_l;

	gen_test_tree(&test_tree, line);
	cil_list_init(&cil_l);

	cil_set_to_list(test_tree->root->cl_head, cil_l);

	struct cil_list *copy_list;
	cil_list_init(&copy_list);

	cil_copy_list(cil_l, &copy_list);
	CuAssertStrEquals(tc, copy_list->head->data, cil_l->head->data);
	CuAssertStrEquals(tc, copy_list->head->next->data, cil_l->head->next->data);
	CuAssertIntEquals(tc, copy_list->head->flavor, cil_l->head->flavor);
	CuAssertIntEquals(tc, copy_list->head->next->flavor, cil_l->head->next->flavor);
}

void test_cil_copy_list_sublist(CuTest *tc) {
	char *line[] = {"(", "foo1", "foo2", "(", "foo3", ")", ")", NULL};

	struct cil_tree *test_tree;
	struct cil_list *cil_l;
	struct cil_list *sub_list = NULL;

	gen_test_tree(&test_tree, line);
	cil_list_init(&cil_l);

	cil_set_to_list(test_tree->root->cl_head, cil_l);
	sub_list = (struct cil_list *)cil_l->head->next->next->data;

	struct cil_list *copy_list;
	cil_list_init(&copy_list);

	cil_copy_list(cil_l, &copy_list);
	CuAssertStrEquals(tc, copy_list->head->data, cil_l->head->data);
	CuAssertStrEquals(tc, copy_list->head->next->data, cil_l->head->next->data);
	CuAssertStrEquals(tc, ((struct cil_list *)copy_list->head->next->next->data)->head->data, ((struct cil_list *)cil_l->head->next->next->data)->head->data);
	CuAssertIntEquals(tc, copy_list->head->flavor, cil_l->head->flavor);
	CuAssertIntEquals(tc, copy_list->head->next->flavor, cil_l->head->next->flavor);
	CuAssertIntEquals(tc, ((struct cil_list *)copy_list->head->next->next->data)->head->flavor, ((struct cil_list *)cil_l->head->next->next->data)->head->flavor);
}

void test_cil_copy_list_sublist_extra(CuTest *tc) {
	char *line[] = {"(", "foo1", "foo2", "(", "foo3", ")", "foo4", ")", NULL};

	struct cil_tree *test_tree;
	struct cil_list *cil_l;
	struct cil_list *sub_list = NULL;

	gen_test_tree(&test_tree, line);
	cil_list_init(&cil_l);

	cil_set_to_list(test_tree->root->cl_head, cil_l);
	sub_list = (struct cil_list *)cil_l->head->next->next->data;

	struct cil_list *copy_list;
	cil_list_init(&copy_list);

	cil_copy_list(cil_l, &copy_list);
	CuAssertStrEquals(tc, copy_list->head->data, cil_l->head->data);
	CuAssertStrEquals(tc, copy_list->head->next->data, cil_l->head->next->data);
	CuAssertStrEquals(tc, ((struct cil_list *)copy_list->head->next->next->data)->head->data, ((struct cil_list *)cil_l->head->next->next->data)->head->data);
	CuAssertStrEquals(tc, copy_list->head->next->next->next->data, cil_l->head->next->next->next->data);
	CuAssertIntEquals(tc, copy_list->head->flavor, cil_l->head->flavor);
	CuAssertIntEquals(tc, copy_list->head->next->flavor, cil_l->head->next->flavor);
	CuAssertIntEquals(tc, ((struct cil_list *)copy_list->head->next->next->data)->head->flavor, ((struct cil_list *)cil_l->head->next->next->data)->head->flavor);
	CuAssertIntEquals(tc, copy_list->head->next->next->next->flavor, cil_l->head->next->next->next->flavor);
}

void test_cil_copy_list_orignull_neg(CuTest *tc) {
	char *line[] = {"(", "foo1", "foo2", ")", NULL};

	struct cil_tree *test_tree;
	struct cil_list *cil_l = NULL;

	gen_test_tree(&test_tree, line);

	struct cil_list *copy_list;
	cil_list_init(&copy_list);

	cil_copy_list(cil_l, &copy_list);
	CuAssertPtrEquals(tc, copy_list->head, NULL);
}

void test_cil_copy_class(CuTest *tc) {
	char *line[] = {"(", "class", "file", "(", "read", "write", "open", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	cil_gen_class(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	
	struct cil_tree_node *test_copy;
	cil_tree_node_init(&test_copy);

	symtab_t sym;
	symtab_init(&sym, CIL_SYM_SIZE);

	int rc = cil_copy_class(test_ast_node, test_copy, &sym);
	CuAssertIntEquals(tc, rc, SEPOL_OK);
	CuAssertStrEquals(tc, ((struct cil_class *)test_copy->data)->datum.name, 
		((struct cil_class *)test_ast_node->data)->datum.name);
}

void test_cil_copy_type(CuTest *tc) {
	char *line[] = {"(", "type", "test", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	cil_gen_type(test_db, test_tree->root->cl_head->cl_head, test_ast_node, CIL_TYPE);

	struct cil_tree_node *test_copy;
	cil_tree_node_init(&test_copy);

	symtab_t sym;
	symtab_init(&sym, CIL_SYM_SIZE);

	int rc = cil_copy_type(test_ast_node, test_copy, &sym);
	CuAssertIntEquals(tc, rc, SEPOL_OK);
	CuAssertStrEquals(tc, ((struct cil_class *)test_copy->data)->datum.name, 
		((struct cil_class *)test_ast_node->data)->datum.name);
}

