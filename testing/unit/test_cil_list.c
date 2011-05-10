#include "CuTest.h"
#include "CilTest.h"

#include "../../src/cil.h"

void test_cil_list_init(CuTest *tc) {
	struct cil_avrule *test_avrule = malloc(sizeof(struct cil_avrule));

	cil_list_init(&test_avrule->perms_str);
	CuAssertPtrNotNull(tc, test_avrule->perms_str);

	free(test_avrule);   
}

void test_cil_list_item_init(CuTest *tc) {
	struct cil_transform_interface *test_transform_interface;
	cil_transform_interface_init(&test_transform_interface);

	cil_list_item_init(&test_transform_interface->params);
	CuAssertPtrNotNull(tc, test_transform_interface->params);
}

void test_cil_list_append_item(CuTest *tc) {
        char *line[] = {"(", "mlsconstrain", "(", "file", "dir", ")", "(", "create", "relabelto", ")", "(", "eq", "12", "h2", ")", ")", NULL};

	struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	struct cil_list *test_class_list;
	cil_list_init(&test_class_list);

	struct cil_list_item *test_new_item;
	cil_list_item_init(&test_new_item);

	test_new_item->flavor = CIL_CLASS;
	test_new_item->data = test_tree->root->cl_head->cl_head->next->cl_head;

	int rc = cil_list_append_item(test_class_list, test_new_item);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_list_append_item_append(CuTest *tc) {
        char *line[] = {"(", "mlsconstrain", "(", "file", "dir", ")", "(", "create", "relabelto", ")", "(", "eq", "12", "h2", ")", ")", NULL};

	struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	struct cil_list *test_class_list;
	cil_list_init(&test_class_list);

	struct cil_list_item *test_new_item;
	cil_list_item_init(&test_new_item);

	test_new_item->flavor = CIL_CLASS;
	test_new_item->data = test_tree->root->cl_head->cl_head->next->cl_head;

	int rc = cil_list_append_item(test_class_list, test_new_item);
	
	cil_list_item_init(&test_new_item);

	test_new_item->flavor = CIL_CLASS;
	test_new_item->data = test_tree->root->cl_head->cl_head->next->cl_head->next;
	
	int rc2 = cil_list_append_item(test_class_list, test_new_item);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertIntEquals(tc, SEPOL_OK, rc2);
}

void test_cil_list_append_item_append_extra(CuTest *tc) {
        char *line[] = {"(", "mlsconstrain", "(", "file", "dir", "process", ")", "(", "create", "relabelto", ")", "(", "eq", "12", "h2", ")", ")", NULL};

	struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	struct cil_list *test_class_list;
	cil_list_init(&test_class_list);

	struct cil_list_item *test_new_item;
	cil_list_item_init(&test_new_item);

	test_new_item->flavor = CIL_CLASS;
	test_new_item->data = test_tree->root->cl_head->cl_head->next->cl_head;

	int rc = cil_list_append_item(test_class_list, test_new_item);
	
	cil_list_item_init(&test_new_item);
	test_new_item->flavor = CIL_CLASS;
	test_new_item->data = test_tree->root->cl_head->cl_head->next->cl_head->next;
	
	int rc2 = cil_list_append_item(test_class_list, test_new_item);
	
	cil_list_item_init(&test_new_item);
	test_new_item->flavor = CIL_CLASS;
	test_new_item->data = test_tree->root->cl_head->cl_head->next->cl_head->next->next;
	
	int rc3 = cil_list_append_item(test_class_list, test_new_item);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertIntEquals(tc, SEPOL_OK, rc2);
	CuAssertIntEquals(tc, SEPOL_OK, rc3);
}

void test_cil_list_append_item_listnull_neg(CuTest *tc) {
        char *line[] = {"(", "mlsconstrain", "(", "file", "dir", ")", "(", "create", "relabelto", ")", "(", "eq", "12", "h2", ")", ")", NULL};

	struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	struct cil_list *test_class_list = NULL;

	struct cil_list_item *test_new_item;
	cil_list_item_init(&test_new_item);

	test_new_item->flavor = CIL_CLASS;
	test_new_item->data = test_tree->root->cl_head->cl_head->next->cl_head;

	int rc = cil_list_append_item(test_class_list, test_new_item);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_list_append_item_itemnull_neg(CuTest *tc) {
        char *line[] = {"(", "mlsconstrain", "(", "file", "dir", ")", "(", "create", "relabelto", ")", "(", "eq", "12", "h2", ")", ")", NULL};

	struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	struct cil_list *test_class_list;
	cil_list_init(&test_class_list);

	struct cil_list_item *test_new_item = NULL;

	int rc = cil_list_append_item(test_class_list, test_new_item);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_list_prepend_item(CuTest *tc) {
        char *line[] = {"(", "mlsconstrain", "(", "file", "dir", ")", "(", "create", "relabelto", ")", "(", "eq", "12", "h2", ")", ")", NULL};

	struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	struct cil_list *test_class_list;
	cil_list_init(&test_class_list);

	struct cil_list_item *test_new_item;
	cil_list_item_init(&test_new_item);

	test_new_item->flavor = CIL_CLASS;
	test_new_item->data = test_tree->root->cl_head->cl_head->next->cl_head;

	int rc = cil_list_prepend_item(test_class_list, test_new_item);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_list_prepend_item_prepend(CuTest *tc) {
        char *line[] = {"(", "mlsconstrain", "(", "file", "dir", ")", "(", "create", "relabelto", ")", "(", "eq", "12", "h2", ")", ")", NULL};

	struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	struct cil_list *test_class_list;
	cil_list_init(&test_class_list);

	struct cil_list_item *test_new_item;
	cil_list_item_init(&test_new_item);

	test_new_item->flavor = CIL_CLASS;
	test_new_item->data = test_tree->root->cl_head->cl_head->next->cl_head;

	int rc = cil_list_prepend_item(test_class_list, test_new_item);
	
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_list_prepend_item_prepend_neg(CuTest *tc) {
        char *line[] = {"(", "mlsconstrain", "(", "file", "dir", "process", ")", "(", "create", "relabelto", ")", "(", "eq", "12", "h2", ")", ")", NULL};

	struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	struct cil_list *test_class_list;
	cil_list_init(&test_class_list);

	struct cil_list_item *test_new_item;
	cil_list_item_init(&test_new_item);

	test_new_item->flavor = CIL_CLASS;
	test_new_item->data = test_tree->root->cl_head->cl_head->next->cl_head;

	struct cil_list_item *test_new_item_next;
	cil_list_item_init(&test_new_item_next);
	test_new_item->flavor = CIL_CLASS;
	test_new_item->data = test_tree->root->cl_head->cl_head->next->cl_head->next;
	test_new_item->next = test_new_item_next;	
	
	int rc = cil_list_prepend_item(test_class_list, test_new_item);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_list_prepend_item_listnull_neg(CuTest *tc) {
        char *line[] = {"(", "mlsconstrain", "(", "file", "dir", ")", "(", "create", "relabelto", ")", "(", "eq", "12", "h2", ")", ")", NULL};

	struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	struct cil_list *test_class_list = NULL;

	struct cil_list_item *test_new_item;
	cil_list_item_init(&test_new_item);

	test_new_item->flavor = CIL_CLASS;
	test_new_item->data = test_tree->root->cl_head->cl_head->next->cl_head;

	int rc = cil_list_prepend_item(test_class_list, test_new_item);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_list_prepend_item_itemnull_neg(CuTest *tc) {
        char *line[] = {"(", "mlsconstrain", "(", "file", "dir", ")", "(", "create", "relabelto", ")", "(", "eq", "12", "h2", ")", ")", NULL};

	struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	struct cil_list *test_class_list;
	cil_list_init(&test_class_list);

	struct cil_list_item *test_new_item = NULL;

	int rc = cil_list_prepend_item(test_class_list, test_new_item);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}
