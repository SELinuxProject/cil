#include <sepol/policydb/policydb.h>

#include "CuTest.h"
#include "CilTest.h"
#include "test_cil_build_ast.h"

#include "../../src/cil_build_ast.h"

#include "../../src/cil_tree.h"

int __cil_build_ast_node_helper(struct cil_tree_node *, uint32_t *, struct cil_list *);
//int __cil_build_constrain_tree(struct cil_tree_node *parse_current, struct cil_tree_node *expr_root);

// First seen in cil_gen_common
void test_cil_parse_to_list(CuTest *tc) {
	char *line[] = {"(", "allow", "test", "foo", "bar", "(", "read", "write", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_current;
	test_current = test_tree->root->cl_head->cl_head;

	struct cil_avrule *test_avrule = malloc(sizeof(struct cil_avrule));
	test_avrule->rule_kind = CIL_AVRULE_ALLOWED;
	test_avrule->src_str = cil_strdup(test_current->next->data);
	test_avrule->tgt_str = cil_strdup(test_current->next->next->data);
	test_avrule->obj_str = cil_strdup(test_current->next->next->next->data);

	cil_list_init(&test_avrule->perms_str);

	test_current = test_current->next->next->next->next->cl_head;

	int rc = cil_parse_to_list(test_current, test_avrule->perms_str, CIL_AST_STR);
	CuAssertIntEquals(tc, SEPOL_OK, rc);

	free(test_avrule->perms_str);
	test_avrule->perms_str = NULL;
	free(test_avrule);
}

void test_cil_parse_to_list_currnull_neg(CuTest *tc) {
	char *line[] = {"(", "allow", "test", "foo", "bar", "(", "read", "write", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_current;
	test_current = test_tree->root->cl_head->cl_head;

	struct cil_avrule *test_avrule = malloc(sizeof(struct cil_avrule));
	test_avrule->rule_kind = CIL_AVRULE_ALLOWED;
	test_avrule->src_str = cil_strdup(test_current->next->data);
	test_avrule->tgt_str = cil_strdup(test_current->next->next->data);
	test_avrule->obj_str = cil_strdup(test_current->next->next->next->data);

	cil_list_init(&test_avrule->perms_str);

	test_current = NULL;

	int rc = cil_parse_to_list(test_current, test_avrule->perms_str, CIL_AST_STR);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);

	free(test_avrule->perms_str);
	test_avrule->perms_str = NULL;
	free(test_avrule);
}

void test_cil_parse_to_list_listnull_neg(CuTest *tc) {
	char *line[] = {"(", "allow", "test", "foo", "bar", "(", "read", "write", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_current;
	test_current = test_tree->root->cl_head->cl_head;

	struct cil_avrule *test_avrule = malloc(sizeof(struct cil_avrule));
	test_avrule->rule_kind = CIL_AVRULE_ALLOWED;
	test_avrule->src_str = cil_strdup(test_current->next->data);
	test_avrule->tgt_str = cil_strdup(test_current->next->next->data);
	test_avrule->obj_str = cil_strdup(test_current->next->next->next->data);

	test_current = test_current->next->next->next->next->cl_head;

	int rc = cil_parse_to_list(test_current, test_avrule->perms_str, CIL_AST_STR);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);

	free(test_avrule);
}

void test_cil_set_to_list(CuTest *tc) {
	char *line[] = {"(", "foo1", "foo2", "(", "foo3", ")", ")", NULL};

	struct cil_tree *test_tree;
	struct cil_list *cil_l;
	struct cil_list *sub_list = NULL;

	gen_test_tree(&test_tree, line);
	cil_list_init(&cil_l);

	int rc = cil_set_to_list(test_tree->root->cl_head, cil_l, 1);
	sub_list = (struct cil_list *)cil_l->head->next->next->data;

	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertStrEquals(tc, "foo1", (char*)cil_l->head->data);
	CuAssertStrEquals(tc, "foo2", (char*)cil_l->head->next->data);
	CuAssertStrEquals(tc, "foo3", (char*)sub_list->head->data);
}

void test_cil_set_to_list_tree_node_null_neg(CuTest *tc) {
	struct cil_list *cil_l = NULL;
	int rc = cil_set_to_list(NULL, cil_l, 1);

	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_set_to_list_cl_head_null_neg(CuTest *tc) {
	char *line[] = {"(", "foo", "bar", ")", NULL};

	struct cil_list *cil_l;
	struct cil_tree *test_tree = NULL;

	cil_list_init(&cil_l);
	gen_test_tree(&test_tree, line);
	test_tree->root->cl_head = NULL;

	int rc = cil_set_to_list(test_tree->root, cil_l, 1);

	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_set_to_list_listnull_neg(CuTest *tc) {
	char *line[] = {"(", "foo1", "foo2", "foo3", ")", NULL};

	struct cil_tree *test_tree = NULL;
	gen_test_tree(&test_tree, line);

	int rc = cil_set_to_list(test_tree->root, NULL, 1);

	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_block(CuTest *tc) {
	char *line[] = {"(", "block", "a", "(", "type", "log", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_block(test_db, test_tree->root->cl_head->cl_head, test_ast_node, 0, NULL);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, test_ast_node->data);
	CuAssertIntEquals(tc, ((struct cil_block*)test_ast_node->data)->is_abstract, 0);
	CuAssertPtrEquals(tc, ((struct cil_block*)test_ast_node->data)->condition, NULL);
	CuAssertIntEquals(tc, test_ast_node->flavor, CIL_BLOCK);
}

void test_cil_gen_block_justblock_neg(CuTest *tc) {
	char *line[] = {"(", "block", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_block(test_db, test_tree->root->cl_head->cl_head, test_ast_node, 0, NULL);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_block_noname_neg(CuTest *tc) {
	char *line[] = {"(", "block", "(", "type", "log", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_block(test_db, test_tree->root->cl_head->cl_head, test_ast_node, 0, NULL);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_block_dbnull_neg(CuTest *tc) {
	char *line[] = {"(", "block", "foo", "(", "type", "log", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db = NULL;

	int rc = cil_gen_block(test_db, test_tree->root->cl_head->cl_head, test_ast_node, 0, NULL);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_block_treenull_neg(CuTest *tc) {
	char *line[] = {"(", "block", "foo", "(", "type", "log", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	test_tree->root->cl_head->cl_head = NULL;

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_block(test_db, test_tree->root->cl_head->cl_head, test_ast_node, 0, NULL);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_block_nodenull_neg(CuTest *tc) {
	char *line[] = {"(", "block", "foo", "(", "type", "log", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);
	
	struct cil_tree_node *test_ast_node = NULL;

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_gen_block(test_db, test_tree->root->cl_head->cl_head, test_ast_node, 0, NULL);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_block_nodeparentnull_neg(CuTest *tc) {
	char *line[] = {"(", "block", "foo", "(", "type", "log", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = NULL;
	test_ast_node->line = 1;

	int rc = cil_gen_block(test_db, test_tree->root->cl_head->cl_head, test_ast_node, 0, NULL);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_destroy_block(CuTest *tc) {
	char *line[] = {"(", "block", "a", "(", "type", "log", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	cil_gen_block(test_db, test_tree->root->cl_head->cl_head, test_ast_node, 0, NULL);

	cil_destroy_block((struct cil_block*)test_ast_node->data);
	CuAssertPtrEquals(tc, NULL,test_ast_node->data);
}

void test_cil_gen_perm(CuTest *tc) {
	char *line[] = {"(", "class", "foo", "(", "read", "write", "open", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_class *new_node;
	cil_class_init(&new_node);

	struct cil_tree_node *new_tree_node;
	cil_tree_node_init(&new_tree_node);
	new_tree_node->data = new_node;
	new_tree_node->flavor = CIL_CLASS;

	test_ast_node->parent = new_tree_node;
	test_ast_node->line = 1;

	int rc = cil_gen_perm(test_db, test_tree->root->cl_head->cl_head->next->next->cl_head, test_ast_node);
	int rc1 = cil_gen_perm(test_db, test_tree->root->cl_head->cl_head->next->next->cl_head->next, test_ast_node);
	int rc2 = cil_gen_perm(test_db, test_tree->root->cl_head->cl_head->next->next->cl_head->next->next, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertIntEquals(tc, SEPOL_OK, rc1);
	CuAssertIntEquals(tc, SEPOL_OK, rc2);
}

void test_cil_gen_perm_dbnull_neg(CuTest *tc) {
	char *line[] = {"(", "class", "file", "(", "read", "write", "open", ")", ")", NULL};

	int rc = 0;
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_current_perm = NULL;
	struct cil_tree_node *test_new_ast = NULL;
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db = NULL;

	test_current_perm = test_tree->root->cl_head->cl_head->next->next->cl_head;

	cil_tree_node_init(&test_new_ast);
	test_new_ast->parent = test_ast_node;
	test_new_ast->line = test_current_perm->line;

	rc = cil_gen_perm(test_db, test_current_perm, test_new_ast);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_perm_currnull_neg(CuTest *tc) {
	char *line[] = {"(", "class", "file", "(", "read", "write", "open", ")", ")", NULL};

	int rc = 0;
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_current_perm = NULL;
	struct cil_tree_node *test_new_ast = NULL;
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	test_current_perm = NULL; 

	cil_tree_node_init(&test_new_ast);
	test_new_ast->parent = test_ast_node;

	rc = cil_gen_perm(test_db, test_current_perm, test_new_ast);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_perm_astnull_neg(CuTest *tc) {
	char *line[] = {"(", "class", "foo", "(", "read", "write", "open", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node = NULL;

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_class *new_node;
	cil_class_init(&new_node);

	struct cil_tree_node *new_tree_node;
	cil_tree_node_init(&new_tree_node);
	new_tree_node->data = new_node;
	new_tree_node->flavor = CIL_CLASS;

	int rc = cil_gen_perm(test_db, test_tree->root->cl_head->cl_head->next->next->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_perm_nodenull_neg(CuTest *tc) {
	char *line[] = {"(", "class", "file", "(", "read", "write", "open", ")", ")", NULL};

	int rc = 0;
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_current_perm = NULL;
	struct cil_tree_node *test_new_ast = NULL;
	struct cil_tree_node *test_ast_node = NULL;

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_current_perm = test_tree->root->cl_head->cl_head->next->next->cl_head;

	cil_tree_node_init(&test_new_ast);
	test_new_ast->parent = test_ast_node;
	test_new_ast->line = test_current_perm->line;

	rc = cil_gen_perm(test_db, test_current_perm, test_new_ast);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_perm_nodes(CuTest *tc) {
	char *line[] = {"(", "class", "file", "(", "read", "write", "open", ")", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);
	
	struct cil_db *test_db;
	cil_db_init(&test_db);

	char *test_key = test_tree->root->cl_head->cl_head->next->data;
	struct cil_class *test_cls = malloc(sizeof(struct cil_class));
	symtab_init(&test_cls->perms, CIL_SYM_SIZE);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	cil_symtab_insert(&test_db->symtab[CIL_SYM_CLASSES], (hashtab_key_t)test_key, (struct cil_symtab_datum*)test_cls, test_ast_node);

	test_ast_node->data = test_cls;
	test_ast_node->flavor = CIL_CLASS;

	int rc = cil_gen_perm_nodes(test_db, test_tree->root->cl_head->cl_head->next->next->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_perm_nodes_failgen_neg(CuTest *tc) {
	char *line[] = {"(", "class", "file", "(", "read", "write", "open", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	char *test_key = test_tree->root->cl_head->cl_head->next->data;
	struct cil_class *test_cls = malloc(sizeof(struct cil_class));
	//symtab_init(&test_cls->perms, CIL_SYM_SIZE);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	cil_symtab_insert(&test_db->symtab[CIL_SYM_CLASSES], (hashtab_key_t)test_key, (struct cil_symtab_datum*)test_cls, test_ast_node);

	test_ast_node->data = test_cls;
	test_ast_node->flavor = CIL_CLASS;

	int rc = cil_gen_perm_nodes(test_db, test_tree->root->cl_head->cl_head->next->next->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_perm_nodes_inval_perm_neg(CuTest *tc) {
	char *line[] = {"(", "class", "file", "(", "read", "(", "write", "open", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	char *test_key = test_tree->root->cl_head->cl_head->next->data;
	struct cil_class *test_cls = malloc(sizeof(struct cil_class));
	symtab_init(&test_cls->perms, CIL_SYM_SIZE);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	cil_symtab_insert(&test_db->symtab[CIL_SYM_CLASSES], (hashtab_key_t)test_key, (struct cil_symtab_datum*)test_cls, test_ast_node);

	test_ast_node->data = test_cls;
	test_ast_node->flavor = CIL_CLASS;

	int rc = cil_gen_perm_nodes(test_db, test_tree->root->cl_head->cl_head->next->next->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_class(CuTest *tc) { 
	char *line[] = {"(", "class", "file", "(", "read", "write", "open", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_class(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, test_ast_node->cl_tail);
	CuAssertPtrNotNull(tc, test_ast_node->data);
	CuAssertIntEquals(tc, test_ast_node->flavor, CIL_CLASS);
}

void test_cil_gen_class_noname_neg(CuTest *tc) { 
	char *line[] = {"(", "class", "(", "read", "write", "open", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_class(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_class_nodenull_neg(CuTest *tc) {
	char *line[] = {"(", "class", "(", "read", "write", "open", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node = NULL;

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_gen_class(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_class_dbnull_neg(CuTest *tc) {
	char *line[] = {"(", "class", "(", "read", "write", "open", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db = NULL;

	int rc = cil_gen_class(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_class_currnull_neg(CuTest *tc) {
	char *line[] = {"(", "class", "(", "read", "write", "open", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_tree->root->cl_head->cl_head = NULL;

	int rc = cil_gen_class(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_class_noclass_neg(CuTest *tc) { 
	char *line[] = {"(", "test", "read", "write", "open", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_class(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_class_noclassname_neg(CuTest *tc) { 
	char *line[] = {"(", "class", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_class(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_class_namesublist_neg(CuTest *tc) { 
	char *line[] = {"(", "class", "(", "foo", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_class(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_class_noperms_neg(CuTest *tc) { 
	char *line[] = {"(", "class", "foo", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_class(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_class_permsnotinlist_neg(CuTest *tc) { 
	char *line[] = {"(", "class", "foo", "read", "write", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_class(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_class_extrapermlist_neg(CuTest *tc) { 
	char *line[] = {"(", "class", "foo", "(", "read", ")", "(", "write", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_class(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_class_listinlist_neg(CuTest *tc) { 
        char *line[] = {"(", "class", "test", "(", "read", "(", "write", ")", ")", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_class(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_common(CuTest *tc) {
	char *line[] = {"(", "common", "test", "(", "read", "write", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_common(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, test_ast_node->data);
	CuAssertIntEquals(tc, test_ast_node->flavor, CIL_COMMON);
}

void test_cil_gen_common_dbnull_neg(CuTest *tc) {
	char *line[] = {"(", "common", "test", "(", "read", "write", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db = NULL;

	int rc = cil_gen_common(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_common_currnull_neg(CuTest *tc) {
	char *line[] = {"(", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_gen_common(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_common_astnull_neg(CuTest *tc) {
	char *line[] = {"(", "common", "test", "(", "read", "write", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node = NULL;

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_gen_common(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_common_noname_neg(CuTest *tc) {
	char *line[] = {"(", "common", ")", NULL}; 

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_common(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_common_twoperms_neg(CuTest *tc) {
	char *line[] = {"(", "common", "foo", "(", "write", ")", "(", "read", ")", ")", NULL}; 

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_common(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_common_permsublist_neg(CuTest *tc) {
        char *line[] = {"(", "common", "test", "(", "read", "(", "write", ")", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_common(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_common_noperms_neg(CuTest *tc) {
        char *line[] = {"(", "common", "test", "(", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_common(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
       
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_sidcontext(CuTest *tc) {
	char *line[] = {"(", "sidcontext", "test", "(", "blah", "blah", "blah", "(", "s0", "(", "c0", ")", ")", "(", "s0", "(", "c0", ")", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);


	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_sidcontext(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, test_ast_node->data);
	CuAssertIntEquals(tc, test_ast_node->flavor, CIL_SIDCONTEXT);
}

void test_cil_gen_sidcontext_namedcontext(CuTest *tc) {
	char *line[] = {"(", "sidcontext", "test", "something", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_sidcontext(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, test_ast_node->data);
	CuAssertIntEquals(tc, test_ast_node->flavor, CIL_SIDCONTEXT);
}

void test_cil_gen_sidcontext_halfcontext_neg(CuTest *tc) {
	char *line[] = {"(", "sidcontext", "test", "(", "blah", "blah", "blah", "(", "s0", "(", "c0", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_sidcontext(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_sidcontext_noname_neg(CuTest *tc) {
	char *line[] = {"(", "sidcontext", "(", "blah", "blah", "blah", "(", "s0", "(", "c0", ")", ")", "(", "s0", "(", "c0", ")", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_sidcontext(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_sidcontext_empty_neg(CuTest *tc) {
	char *line[] = {"(", "sidcontext", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_sidcontext(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_sidcontext_nocontext_neg(CuTest *tc) {
	char *line[] = {"(", "sidcontext", "test", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_sidcontext(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_sidcontext_dblname_neg(CuTest *tc) {
	char *line[] = {"(", "sidcontext", "test", "test2", "(", "blah", "blah", "blah", "(", "s0", "(", "c0", ")", ")", "(", "s0", "(", "c0", ")", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_sidcontext(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_sidcontext_dbnull_neg(CuTest *tc) {
	char *line[] = {"(", "sidcontext", "test", "(", "blah", "blah", "blah", "(", "s0", "(", "c0", ")", ")", "(", "s0", "(", "c0", ")", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db = NULL;

	int rc = cil_gen_sidcontext(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_sidcontext_pcurrnull_neg(CuTest *tc) {
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_sidcontext(test_db, NULL, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_sidcontext_astnodenull_neg(CuTest *tc) {
	char *line[] = {"(", "sidcontext", "test", "(", "blah", "blah", "blah", "(", "s0", "(", "c0", ")", ")", "(", "s0", "(", "c0", ")", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_sidcontext(test_db, test_tree->root->cl_head->cl_head, NULL);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_type(CuTest *tc) {
	char *line[] = {"(", "type", "test", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_type(test_db, test_tree->root->cl_head->cl_head, test_ast_node, CIL_TYPE);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, test_ast_node->data);
	CuAssertIntEquals(tc, test_ast_node->flavor, CIL_TYPE);
}

void test_cil_gen_type_dbnull_neg(CuTest *tc) {
	char *line[] = {"(", "type", "test", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db = NULL;

	int rc = cil_gen_type(test_db, test_tree->root->cl_head->cl_head, test_ast_node, CIL_TYPE);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_type_currnull_neg(CuTest *tc) {
	char *line[] = {"(", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;
	
	int rc = cil_gen_type(test_db, test_tree->root->cl_head->cl_head, test_ast_node, CIL_TYPE);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_type_astnull_neg(CuTest *tc) {
	char *line[] = {"(", "type", "test", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node = NULL;

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_gen_type(test_db, test_tree->root->cl_head->cl_head, test_ast_node, CIL_TYPE);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_type_extra_neg(CuTest *tc) {
	char *line[] = {"(", "type", "foo", "bar," ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_type(test_db, test_tree->root->cl_head->cl_head, test_ast_node, CIL_TYPE);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_type_invalid_node_neg(CuTest *tc) {
	char *line[] = {"(", "type", "test", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_type(test_db, test_tree->root->cl_head->cl_head, test_ast_node, CIL_BOOL);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_type_extratype_nottypeorattr_neg(CuTest *tc) {
	char *line[] = {"(", "type", "fail", "fail2", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_type(test_db, test_tree->root->cl_head->cl_head, test_ast_node, CIL_BOOL);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_type_attribute(CuTest *tc) {
	char *line[] = {"(", "attribute", "test", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_type(test_db, test_tree->root->cl_head->cl_head, test_ast_node, CIL_ATTR);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, test_ast_node->data);
	CuAssertIntEquals(tc, test_ast_node->flavor, CIL_ATTR);
}

void test_cil_gen_type_attribute_dbnull_neg(CuTest *tc) {
	char *line[] = {"(", "attribute", "test", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db = NULL;

	int rc = cil_gen_type(test_db, test_tree->root->cl_head->cl_head, test_ast_node, CIL_ATTR);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}


void test_cil_gen_type_attribute_currnull_neg(CuTest *tc) {
	char *line[] = {"(", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;
	
	int rc = cil_gen_type(test_db, test_tree->root->cl_head->cl_head, test_ast_node, CIL_ATTR);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}


void test_cil_gen_type_attribute_astnull_neg(CuTest *tc) {
	char *line[] = {"(", "type", "test", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node = NULL;

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_gen_type(test_db, test_tree->root->cl_head->cl_head, test_ast_node, CIL_ATTR);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_type_attribute_extra_neg(CuTest *tc) {
	char *line[] = {"(", "attribute", "foo", "bar," ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_type(test_db, test_tree->root->cl_head->cl_head, test_ast_node, CIL_ATTR);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_typeattr(CuTest *tc) {
	char *line[] = {"(", "typeattribute", "foo", "bar", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_typeattr(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, test_ast_node->data);
	CuAssertStrEquals(tc, ((struct cil_typeattribute*)test_ast_node->data)->type_str, test_tree->root->cl_head->cl_head->next->data);
	CuAssertStrEquals(tc, ((struct cil_typeattribute*)test_ast_node->data)->attr_str, test_tree->root->cl_head->cl_head->next->next->data);
	CuAssertIntEquals(tc, test_ast_node->flavor, CIL_TYPE_ATTR);
}

void test_cil_gen_typeattr_dbnull_neg (CuTest *tc) {
	char *line[] = {"(", "typeattribute", "foo", "bar", ")", NULL};

	struct  cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db = NULL;

	int rc = cil_gen_typeattr(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_typeattr_currnull_neg (CuTest *tc) {
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_gen_typeattr(test_db, NULL, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc); 	
}

void test_cil_gen_typeattr_astnull_neg (CuTest *tc) {
	char *line[] = {"(", "typeattribute", "foo", "bar", ")", NULL};

	struct  cil_tree *test_tree;
	gen_test_tree(&test_tree, line);
	
	struct cil_tree_node *test_ast_node = NULL;

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_gen_typeattr(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_typeattr_typenull_neg (CuTest *tc) {
	char *line[] = {"(", "typeattribute", "foo", "bar" ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	test_tree->root->cl_head->cl_head->next = NULL;

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_gen_typeattr(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);	
}

void test_cil_gen_typeattr_attrnull_neg (CuTest *tc) {
	char *line[] = {"(", "typeattribute", "foo", "bar" ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	test_tree->root->cl_head->cl_head->next->next = NULL;

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_gen_typeattr(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);	
}

void test_cil_gen_typeattr_attrlist_neg (CuTest *tc) {
	char *line[] = {"(", "typeattribute", "foo", "(", "bar", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_gen_typeattr(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_typeattr_extra_neg (CuTest *tc) {
	char *line[] = {"(", "typeattribute", "foo", "bar", "extra", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_gen_typeattr(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_expr_stack_and(CuTest *tc) {
	char *line[] = {"(", "booleanif", "(", "&&", "foo", "bar", ")",
			"(", "allow", "foo", "bar", "baz", "(", "read", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	struct cil_booleanif *bif;
	cil_boolif_init(&bif);

	int rc = cil_gen_expr_stack(test_tree->root->cl_head->cl_head->next->cl_head, CIL_BOOL, &bif->expr_stack);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_expr_stack_or(CuTest *tc) {
	char *line[] = {"(", "booleanif", "(", "||", "foo", "bar", ")",
			"(", "allow", "foo", "bar", "baz", "(", "read", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	struct cil_booleanif *bif;
	cil_boolif_init(&bif);

	int rc = cil_gen_expr_stack(test_tree->root->cl_head->cl_head->next->cl_head, CIL_BOOL, &bif->expr_stack);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_expr_stack_xor(CuTest *tc) {
	char *line[] = {"(", "booleanif", "(", "^", "foo", "bar", ")",
			"(", "allow", "foo", "bar", "baz", "(", "read", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	struct cil_booleanif *bif;
	cil_boolif_init(&bif);

	int rc = cil_gen_expr_stack(test_tree->root->cl_head->cl_head->next->cl_head, CIL_BOOL, &bif->expr_stack);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_expr_stack_not(CuTest *tc) {
	char *line[] = {"(", "booleanif", "(", "!", "foo", ")",
			"(", "allow", "foo", "bar", "baz", "(", "read", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	struct cil_booleanif *bif;
	cil_boolif_init(&bif);

	int rc = cil_gen_expr_stack(test_tree->root->cl_head->cl_head->next->cl_head, CIL_BOOL, &bif->expr_stack);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_expr_stack_not_neg(CuTest *tc) {
	char *line[] = {"(", "booleanif", "(", "!", "foo", "bar", ")",
			"(", "allow", "foo", "bar", "baz", "(", "read", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	struct cil_booleanif *bif;
	cil_boolif_init(&bif);

	int rc = cil_gen_expr_stack(test_tree->root->cl_head->cl_head->next->cl_head, CIL_BOOL, &bif->expr_stack);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_expr_stack_eq(CuTest *tc) {
	char *line[] = {"(", "booleanif", "(", "==", "foo", "bar", ")",
			"(", "allow", "foo", "bar", "baz", "(", "read", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	struct cil_booleanif *bif;
	cil_boolif_init(&bif);

	int rc = cil_gen_expr_stack(test_tree->root->cl_head->cl_head->next->cl_head, CIL_BOOL, &bif->expr_stack);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_expr_stack_neq(CuTest *tc) {
	char *line[] = {"(", "booleanif", "(", "!=", "foo", "bar", ")",
			"(", "allow", "foo", "bar", "baz", "(", "read", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	struct cil_booleanif *bif;
	cil_boolif_init(&bif);

	int rc = cil_gen_expr_stack(test_tree->root->cl_head->cl_head->next->cl_head, CIL_BOOL, &bif->expr_stack);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_expr_stack_nested(CuTest *tc) {
	char *line[] = {"(", "booleanif", "(", "||", "(","!=", "foo", "bar", ")", "(", "==", "baz", "boo", ")", ")",
			"(", "allow", "foo", "bar", "baz", "(", "read", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	struct cil_booleanif *bif;
	cil_boolif_init(&bif);

	int rc = cil_gen_expr_stack(test_tree->root->cl_head->cl_head->next->cl_head, CIL_BOOL, &bif->expr_stack);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_expr_stack_nested_neg(CuTest *tc) {
	char *line[] = {"(", "booleanif", "(", "(","!=", "foo", "bar", ")",
			"(", "allow", "foo", "bar", "baz", "(", "read", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	struct cil_booleanif *bif;
	cil_boolif_init(&bif);

	int rc = cil_gen_expr_stack(test_tree->root->cl_head->cl_head->next->cl_head, CIL_BOOL, &bif->expr_stack);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_expr_stack_arg1null_neg(CuTest *tc) {
	char *line[] = {"(", "booleanif", "(", "==", ")",
			"(", "allow", "foo", "bar", "baz", "(", "read", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	struct cil_booleanif *bif;
	cil_boolif_init(&bif);

	int rc = cil_gen_expr_stack(test_tree->root->cl_head->cl_head->next->cl_head, CIL_BOOL, &bif->expr_stack);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_expr_stack_arg2null_neg(CuTest *tc) {
	char *line[] = {"(", "booleanif", "(", "==", "foo", ")",
			"(", "allow", "foo", "bar", "baz", "(", "read", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	struct cil_booleanif *bif;
	cil_boolif_init(&bif);

	int rc = cil_gen_expr_stack(test_tree->root->cl_head->cl_head->next->cl_head, CIL_BOOL, &bif->expr_stack);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_expr_stack_extraarg_neg(CuTest *tc) {
	char *line[] = {"(", "booleanif", "(", "==", "foo", "bar", "extra", ")",
			"(", "allow", "foo", "bar", "baz", "(", "read", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	struct cil_booleanif *bif;
	cil_boolif_init(&bif);

	int rc = cil_gen_expr_stack(test_tree->root->cl_head->cl_head->next->cl_head, CIL_BOOL, &bif->expr_stack);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_expr_stack_currnull_neg(CuTest *tc) {
	char *line[] = {"(", "booleanif", "(", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	struct cil_booleanif *bif;
	cil_boolif_init(&bif);

	int rc = cil_gen_expr_stack(test_tree->root->cl_head->cl_head->next->cl_head, CIL_BOOL, &bif->expr_stack);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_expr_stack_stacknull_neg(CuTest *tc) {
	char *line[] = {"(", "booleanif", "(", "^", "foo", "bar", ")",
			"(", "allow", "foo", "bar", "(", "read", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_expr_stack(test_tree->root->cl_head->cl_head->next->cl_head, CIL_BOOL, NULL);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_boolif(CuTest *tc) {
	char *line[] = {"(", "booleanif", "(", "&&", "foo", "bar", ")",
			"(", "allow", "foo", "bar", "(", "read", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_boolif(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_boolif_nested(CuTest *tc) {
	char *line[] = {"(", "booleanif", "(", "&&", "(", "||", "foo", "bar", ")", "baz", ")",
			"(", "allow", "foo", "baz", "(", "read", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_boolif(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_boolif_nested_neg(CuTest *tc) {
	char *line[] = {"(", "booleanif", "(", "(", "||", "foo", "bar", ")", "baz", ")",
			"(", "allow", "foo", "baz", "(", "read", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_boolif(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_boolif_extra_neg(CuTest *tc) {
	char *line[] = {"(", "booleanif", "(", "&&", "(", "||", "foo", "bar", ")", "baz", "beef", ")",
			"(", "allow", "foo", "baz", "(", "read", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_boolif(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_boolif_extra_parens_neg(CuTest *tc) {
	char *line[] = {"(", "booleanif", "(", "(", "||", "foo", "bar", ")", ")",
			"(", "allow", "foo", "baz", "(", "read", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_boolif(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_boolif_nocond(CuTest *tc) {
	char *line[] = {"(", "booleanif", "baz",
			"(", "allow", "foo", "bar", "(", "read", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_boolif(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_boolif_neg(CuTest *tc) {
	char *line[] = {"(", "booleanif", "(", "**", "foo", "bar", ")",
			"(", "allow", "foo", "bar", "(", "read", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_boolif(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_boolif_dbnull_neg(CuTest *tc) {
	char *line[] = {"(", "booleanif", "(", "&&", "foo", "bar", ")",
			"(", "allow", "foo", "bar", "(", "read", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db = NULL;

	int rc = cil_gen_boolif(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_boolif_currnull_neg(CuTest *tc) {
	char *line[] = {"(", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_boolif(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_boolif_astnull_neg(CuTest *tc) {
	char *line[] = {"(", "booleanif", "(", "&&", "foo", "bar", ")",
			"(", "allow", "foo", "bar", "(", "read", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node = NULL;

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_gen_boolif(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_boolif_nocond_neg(CuTest *tc) {
	char *line[] = {"(", "booleanif", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_boolif(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_boolif_notruelist_neg(CuTest *tc) {
	char *line[] = {"(", "booleanif", "(", "&&", "foo", "bar", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_boolif(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_boolif_empty_cond_neg(CuTest *tc) {
	char *line[] = {"(", "booleanif", "(", ")",
			"(", "allow", "foo", "bar", "(", "read", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_boolif(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_else(CuTest *tc) {
	char *line[] = {"(", "booleanif", "(", "&&", "foo", "bar", ")",
			"(", "allow", "foo", "bar", "(", "read", ")", ")",
			"(", "else",
				"(", "allow", "foo", "bar", "(", "write", ")", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_tree_node *else_node;
	cil_tree_node_init(&else_node);
	else_node->parent = test_ast_node;

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	cil_gen_boolif(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	int rc = cil_gen_else(test_db, test_tree->root->cl_head->cl_head, else_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_else_neg(CuTest *tc) {
	char *line[] = {"(", "booleanif", "(", "&&", "foo", "bar", ")",
			"(", "allow", "foo", "bar", "(", "read", ")", ")",
			"(", "else",
				"(", "allow", "foo", "bar", "(", "write", ")", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	cil_gen_boolif(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	int rc = cil_gen_else(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_else_dbnull_neg(CuTest *tc) {
	char *line[] = {"(", "booleanif", "(", "&&", "foo", "bar", ")",
			"(", "allow", "foo", "bar", "(", "read", ")", ")",
			"(", "else",
				"(", "allow", "foo", "bar", "(", "write", ")", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_tree_node *else_node;
	cil_tree_node_init(&else_node);
	else_node->parent = test_ast_node;

	struct cil_db *test_db = NULL;

	cil_gen_boolif(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	int rc = cil_gen_else(test_db, test_tree->root->cl_head->cl_head, else_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_else_currnull_neg(CuTest *tc) {
	char *line[] = {"(", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_tree_node *else_node;
	cil_tree_node_init(&else_node);
	else_node->parent = test_ast_node;

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	cil_gen_boolif(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	int rc = cil_gen_else(test_db, test_tree->root->cl_head->cl_head, else_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_else_astnull_neg(CuTest *tc) {
	char *line[] = {"(", "booleanif", "(", "&&", "foo", "bar", ")",
			"(", "allow", "foo", "bar", "(", "read", ")", ")",
			"(", "else",
				"(", "allow", "foo", "bar", "(", "write", ")", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_tree_node *else_node = NULL;

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	cil_gen_boolif(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	int rc = cil_gen_else(test_db, test_tree->root->cl_head->cl_head, else_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_tunif(CuTest *tc) {
	char *line[] = {"(", "tunableif", "(", "&&", "foo", "bar", ")",
			"(", "allow", "foo", "bar", "(", "read", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_tunif(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_tunif_nocond(CuTest *tc) {
	char *line[] = {"(", "tunableif", "baz",
			"(", "allow", "foo", "bar", "(", "read", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_tunif(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_tunif_nested(CuTest *tc) {
	char *line[] = {"(", "tunableif", "(", "&&", "(", "||", "foo", "bar", ")", "baz", ")",
			"(", "allow", "foo", "baz", "(", "read", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_tunif(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_tunif_nested_neg(CuTest *tc) {
	char *line[] = {"(", "tunableif", "(", "(", "||", "foo", "bar", ")", "baz", ")",
			"(", "allow", "foo", "baz", "(", "read", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_tunif(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_tunif_extra_neg(CuTest *tc) {
	char *line[] = {"(", "tunableif", "(", "&&", "(", "||", "foo", "bar", ")", "baz", "beef", ")",
			"(", "allow", "foo", "baz", "(", "read", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_tunif(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_tunif_extra_parens_neg(CuTest *tc) {
	char *line[] = {"(", "tunableif", "(", "(", "||", "foo", "bar", ")", ")",
			"(", "allow", "foo", "baz", "(", "read", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_tunif(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_tunif_neg(CuTest *tc) {
	char *line[] = {"(", "tunableif", "(", "**", "foo", "bar", ")",
			"(", "allow", "foo", "bar", "(", "read", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_tunif(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_tunif_dbnull_neg(CuTest *tc) {
	char *line[] = {"(", "tunableif", "(", "&&", "foo", "bar", ")",
			"(", "allow", "foo", "bar", "(", "read", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db = NULL;

	int rc = cil_gen_tunif(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_tunif_currnull_neg(CuTest *tc) {
	char *line[] = {"(", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_tunif(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_tunif_astnull_neg(CuTest *tc) {
	char *line[] = {"(", "tunableif", "(", "&&", "foo", "bar", ")",
			"(", "allow", "foo", "bar", "(", "read", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node = NULL;

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_gen_tunif(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_tunif_nocond_neg(CuTest *tc) {
	char *line[] = {"(", "tunableif", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_tunif(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_tunif_notruelist_neg(CuTest *tc) {
	char *line[] = {"(", "tunableif", "(", "&&", "foo", "bar", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_tunif(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_typealias(CuTest *tc) {
	char *line[] = {"(", "typealias", ".test.type", "type_t", ")", "(", "type", "test", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_typealias(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, test_ast_node->data);
	CuAssertStrEquals(tc, ((struct cil_typealias*)test_ast_node->data)->type_str, test_tree->root->cl_head->cl_head->next->data);
	CuAssertIntEquals(tc, test_ast_node->flavor, CIL_TYPEALIAS);
}

void test_cil_gen_typealias_incomplete_neg(CuTest *tc) {
	char *line[] = {"(", "typealias", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_typealias(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_typealias_incomplete_neg2(CuTest *tc) {
	char *line[] = {"(", "typealias", ".test.type", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_typealias(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_typealias_extratype_neg(CuTest *tc) {
	char *line[] = {"(", "typealias", ".test.type", "foo", "extra_t", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_typealias(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_typealias_dbnull_neg(CuTest *tc) {
	char *line[] = {"(", "typealias", ".test.type", "type_t", ")", "(", "type", "test", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db = NULL;

	int rc = cil_gen_typealias(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_typealias_currnull_neg(CuTest *tc) {
	char *line[] = {"(", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_typealias(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_typealias_astnull_neg(CuTest *tc) {
	char *line[] = {"(", "typealias", ".test.type", "type_t", ")", "(", "type", "test", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node = NULL;

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_gen_typealias(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_role(CuTest *tc) {
	char *line[] = {"(", "role", "test_r", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_role(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, test_ast_node->data);
	CuAssertIntEquals(tc, test_ast_node->flavor, CIL_ROLE);
}

void test_cil_gen_role_dbnull_neg(CuTest *tc) {
	char *line[] = {"(", "role", "test_r", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db = NULL;

	int rc = cil_gen_role(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_role_currnull_neg(CuTest *tc) {
	char *line[] = {"(", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_gen_role(test_db, test_tree->root->cl_head->cl_head, test_ast_node);

	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_role_astnull_neg(CuTest *tc) {
	char *line[] = {"(", "role", "test_r", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node = NULL;

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_gen_role(test_db, test_tree->root->cl_head->cl_head, test_ast_node);

	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_role_extrarole_neg(CuTest *tc) {
	char *line[] = {"(", "role", "test_r", "extra_r", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_role(test_db, test_tree->root->cl_head->cl_head, test_ast_node);

	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_role_noname_neg(CuTest *tc) {
	char *line[] = {"(", "role", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_role(test_db, test_tree->root->cl_head->cl_head, test_ast_node);

	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_roletrans(CuTest *tc) {
	char *line[] = {"(", "roletransition", "foo_r",  "bar_t",  "foobar_r", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_roletrans(test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, test_ast_node->data);
	CuAssertIntEquals(tc, test_ast_node->flavor, CIL_ROLETRANS);
}

void test_cil_gen_roletrans_currnull_neg(CuTest *tc) {
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_roletrans(NULL, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc); 	
}

void test_cil_gen_roletrans_astnull_neg (CuTest *tc) {
	char *line[] = {"(", "roletransition" "foo_r", "bar_t", "foobar_r", ")", NULL};

	struct  cil_tree *test_tree;
	gen_test_tree(&test_tree, line);
	
	struct cil_tree_node *test_ast_node = NULL;

	int rc = cil_gen_roletrans(test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_roletrans_srcnull_neg(CuTest *tc) {
	char *line[] = {"(", "roletransition", "foo_r", "bar_t", "foobar_r", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	test_tree->root->cl_head->cl_head->next = NULL;

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_roletrans(test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_roletrans_tgtnull_neg(CuTest *tc) {
	char *line[] = {"(", "roletransition", "foo_r", "bar_t", "foobar_r", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	test_tree->root->cl_head->cl_head->next->next = NULL;

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_roletrans(test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_roletrans_resultnull_neg(CuTest *tc) {
	char *line[] = {"(", "roletransition", "foo_r", "bar_t", "foobar_r", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	test_tree->root->cl_head->cl_head->next->next->next = NULL;

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_roletrans(test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_roletrans_extra_neg(CuTest *tc) {
	char *line[] = {"(", "roletransition", "foo_r", "bar_t", "foobar_r", "extra", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_roletrans(test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_bool_true(CuTest *tc) {
	char *line[] = {"(", "bool", "foo", "true", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_bool(test_db, test_tree->root->cl_head->cl_head, test_ast_node, CIL_BOOL);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, test_ast_node->data);
	CuAssertIntEquals(tc, ((struct cil_bool*)test_ast_node->data)->value, 1);
	CuAssertIntEquals(tc, test_ast_node->flavor, CIL_BOOL);
}

void test_cil_gen_bool_tunable_true(CuTest *tc) {
	char *line[] = {"(", "tunable", "foo", "true", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_bool(test_db, test_tree->root->cl_head->cl_head, test_ast_node, CIL_TUNABLE);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, test_ast_node->data);
	CuAssertIntEquals(tc, ((struct cil_bool*)test_ast_node->data)->value, 1);
	CuAssertIntEquals(tc, test_ast_node->flavor, CIL_TUNABLE);
}

void test_cil_gen_bool_false(CuTest *tc) {
	char *line[] = {"(", "bool", "bar", "false", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_bool(test_db, test_tree->root->cl_head->cl_head, test_ast_node, CIL_BOOL);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, test_ast_node->data);
	CuAssertIntEquals(tc, ((struct cil_bool*)test_ast_node->data)->value, 0);
	CuAssertIntEquals(tc, test_ast_node->flavor, CIL_BOOL);
}

void test_cil_gen_bool_tunable_false(CuTest *tc) {
	char *line[] = {"(", "tunable", "bar", "false", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_bool(test_db, test_tree->root->cl_head->cl_head, test_ast_node, CIL_TUNABLE);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, test_ast_node->data);
	CuAssertIntEquals(tc, ((struct cil_bool*)test_ast_node->data)->value, 0);
	CuAssertIntEquals(tc, test_ast_node->flavor, CIL_TUNABLE);
}

void test_cil_gen_bool_none_neg(CuTest *tc) {
	char *line[] = {"(", "bool", "foo", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_bool(test_db, test_tree->root->cl_head->cl_head, test_ast_node, CIL_BOOL);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_bool_dbnull_neg(CuTest *tc) {
	char *line[] = {"(", "bool", "foo", "bar", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db = NULL;

	int rc = cil_gen_bool(test_db, test_tree->root->cl_head->cl_head, test_ast_node, CIL_BOOL);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_bool_currnull_neg(CuTest *tc) {
	char *line[] = {"(", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_bool(test_db, test_tree->root->cl_head->cl_head, test_ast_node, CIL_BOOL);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_bool_astnull_neg(CuTest *tc) {
	char *line[] = {"(", "bool", "foo", "bar", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node = NULL;

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_gen_bool(test_db, test_tree->root->cl_head->cl_head, test_ast_node, CIL_BOOL);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_bool_notbool_neg(CuTest *tc) {
	char *line[] = {"(", "bool", "foo", "bar", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_bool(test_db, test_tree->root->cl_head->cl_head, test_ast_node, CIL_BOOL);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_bool_boolname_neg(CuTest *tc) {
	char *line[] = {"(", "bool", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_bool(test_db, test_tree->root->cl_head->cl_head, test_ast_node, CIL_BOOL);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_bool_extraname_false_neg(CuTest *tc) {
	char *line[] = {"(", "bool", "foo", "false", "bar", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_bool(test_db, test_tree->root->cl_head->cl_head, test_ast_node, CIL_BOOL);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_bool_extraname_true_neg(CuTest *tc) {
	char *line[] = {"(", "bool", "foo", "true", "bar", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_bool(test_db, test_tree->root->cl_head->cl_head, test_ast_node, CIL_BOOL);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_roleallow(CuTest *tc) {
	char *line[] = {"(", "roleallow", "staff_r", "sysadm_r", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);
	
	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_current;
	test_current = test_tree->root->cl_head->cl_head;

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;
	
	int rc = cil_gen_roleallow(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertPtrNotNull(tc, test_ast_node->data);
	CuAssertStrEquals(tc, ((struct cil_role_allow*)test_ast_node->data)->src_str, test_current->next->data);
	CuAssertStrEquals(tc, ((struct cil_role_allow*)test_ast_node->data)->tgt_str, test_current->next->next->data);
	CuAssertIntEquals(tc, test_ast_node->flavor, CIL_ROLEALLOW);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_roleallow_dbnull_neg(CuTest *tc) {
	char *line[] = {"(", "roleallow", "foo", "bar", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db = NULL;

	int rc = cil_gen_roleallow(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_roleallow_currnull_neg(CuTest *tc) {
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_gen_roleallow(test_db, NULL, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc); 
}

void test_cil_gen_roleallow_astnull_neg(CuTest *tc) {
	char *line[] = {"(", "roleallow", "foo", "bar", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node = NULL;

	int rc = cil_gen_roleallow(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_roleallow_srcnull_neg(CuTest *tc) {
	char *line[] = {"(", "roleallow", "foo", "bar", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	test_tree->root->cl_head->cl_head->next = NULL;

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_roleallow(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_roleallow_tgtnull_neg(CuTest *tc) {
	char *line[] = {"(", "roleallow", "foo", "bar", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	test_tree->root->cl_head->cl_head->next->next = NULL;

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_roleallow(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_roleallow_extra_neg(CuTest *tc) {
	char *line[] = {"(", "roleallow", "foo", "bar", "extra", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_roleallow(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_avrule(CuTest *tc) {
	char *line[] = {"(", "allow", "test", "foo", "bar", "(", "read", "write", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	struct cil_tree_node *test_current;
	test_current = test_tree->root->cl_head->cl_head;

	int rc = cil_gen_avrule(test_current, test_ast_node, CIL_AVRULE_ALLOWED);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, test_ast_node->data);
	CuAssertStrEquals(tc, ((struct cil_avrule*)test_ast_node->data)->src_str, test_current->next->data);
	CuAssertStrEquals(tc, ((struct cil_avrule*)test_ast_node->data)->tgt_str, test_current->next->next->data);
	CuAssertStrEquals(tc, ((struct cil_avrule*)test_ast_node->data)->obj_str, test_current->next->next->next->data);
	CuAssertIntEquals(tc, test_ast_node->flavor, CIL_AVRULE);
	CuAssertPtrNotNull(tc, ((struct cil_avrule*)test_ast_node->data)->perms_str);

	struct cil_list_item *test_list = ((struct cil_avrule*)test_ast_node->data)->perms_str->head;
	test_current = test_current->next->next->next->next->cl_head;

	while(test_list != NULL) {
	    CuAssertIntEquals(tc, test_list->flavor, CIL_AST_STR);
	    CuAssertStrEquals(tc, test_list->data, test_current->data );
	    test_list = test_list->next;
	    test_current = test_current->next;
	}
}

void test_cil_gen_avrule_sourceparens_neg(CuTest *tc) {
	char *line[] = {"(", "allow", "(", "test", ")", "foo", "bar", "(", "read", "write", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	struct cil_tree_node *test_current;
	test_current = test_tree->root->cl_head->cl_head;

	int rc = cil_gen_avrule(test_current, test_ast_node, CIL_AVRULE_ALLOWED);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_avrule_targetparens_neg(CuTest *tc) {
	char *line[] = {"(", "allow", "test", "(", "foo", ")", "bar", "(", "read", "write", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	struct cil_tree_node *test_current;
	test_current = test_tree->root->cl_head->cl_head;

	int rc = cil_gen_avrule(test_current, test_ast_node, CIL_AVRULE_ALLOWED);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_avrule_currnull_neg(CuTest *tc) {
	char *line[] = {"(", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	struct cil_tree_node *test_current;
	test_current = test_tree->root->cl_head->cl_head;

	int rc = cil_gen_avrule(test_current, test_ast_node, CIL_AVRULE_ALLOWED);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_avrule_astnull_neg(CuTest *tc) {
	char *line[] = {"(", "allow", "test", "foo", "bar", "(", "read", "write", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node = NULL;

	struct cil_tree_node *test_current;
	test_current = test_tree->root->cl_head->cl_head;

	int rc = cil_gen_avrule(test_current, test_ast_node, CIL_AVRULE_ALLOWED);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_avrule_sourcedomainnull_neg(CuTest *tc) {
	char *line[] = {"(", "allow", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	struct cil_tree_node *test_current;
	test_current = test_tree->root->cl_head->cl_head;

	int rc = cil_gen_avrule(test_current, test_ast_node, CIL_AVRULE_ALLOWED);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_avrule_targetdomainnull_neg(CuTest *tc) {
	char *line[] = {"(", "allow", "foo", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	struct cil_tree_node *test_current;
	test_current = test_tree->root->cl_head->cl_head;

	int rc = cil_gen_avrule(test_current, test_ast_node, CIL_AVRULE_ALLOWED);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_avrule_objectclassnull_neg(CuTest *tc) {
	char *line[] = {"(", "allow", "foo", "bar", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	struct cil_tree_node *test_current;
	test_current = test_tree->root->cl_head->cl_head;

	int rc = cil_gen_avrule(test_current, test_ast_node, CIL_AVRULE_ALLOWED);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_avrule_permsnull_neg(CuTest *tc) {
	char *line[] = {"(", "allow", "foo", "bar", "baz", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	struct cil_tree_node *test_current;
	test_current = test_tree->root->cl_head->cl_head;

	int rc = cil_gen_avrule(test_current, test_ast_node, CIL_AVRULE_ALLOWED);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_avrule_notlist_neg(CuTest *tc) {
	char *line[] = {"(", "allow", "test", "foo", "bar", "write", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	struct cil_tree_node *test_current;
	test_current = test_tree->root->cl_head->cl_head;

	int rc = cil_gen_avrule(test_current, test_ast_node, CIL_AVRULE_ALLOWED);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_avrule_twolists_neg(CuTest *tc) {
	char *line[] = {"(", "allow", "test", "foo", "bar", "(", "write", ")", "(", "read", ")",  NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	struct cil_tree_node *test_current;
	test_current = test_tree->root->cl_head->cl_head;

	int rc = cil_gen_avrule(test_current, test_ast_node, CIL_AVRULE_ALLOWED);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_type_rule_transition(CuTest *tc) {
	char *line[] = {"(", "typetransition", "foo", "bar", "file", "foobar", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_type_rule(test_tree->root->cl_head->cl_head, test_ast_node, CIL_TYPE_TRANSITION);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertStrEquals(tc, ((struct cil_type_rule*)test_ast_node->data)->src_str, test_tree->root->cl_head->cl_head->next->data);
	CuAssertStrEquals(tc, ((struct cil_type_rule*)test_ast_node->data)->tgt_str, test_tree->root->cl_head->cl_head->next->next->data);
	CuAssertStrEquals(tc, ((struct cil_type_rule*)test_ast_node->data)->obj_str, test_tree->root->cl_head->cl_head->next->next->next->data);
	CuAssertStrEquals(tc, ((struct cil_type_rule*)test_ast_node->data)->result_str, test_tree->root->cl_head->cl_head->next->next->next->next->data);
	CuAssertIntEquals(tc, ((struct cil_type_rule*)test_ast_node->data)->rule_kind, CIL_TYPE_TRANSITION);
	CuAssertIntEquals(tc, test_ast_node->flavor, CIL_TYPE_RULE);
}

void test_cil_gen_type_rule_transition_currnull_neg(CuTest *tc) {
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_type_rule(NULL, test_ast_node, CIL_TYPE_TRANSITION);
	CuAssertIntEquals(tc, SEPOL_ERR, rc); 
}

void test_cil_gen_type_rule_transition_astnull_neg(CuTest *tc) {
	char *line[] = {"(", "typetransition", "foo", "bar", "file", "foobar", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node = NULL;

	int rc = cil_gen_type_rule(test_tree->root->cl_head->cl_head, test_ast_node, CIL_TYPE_TRANSITION);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}	

void test_cil_gen_type_rule_transition_srcnull_neg(CuTest *tc) {
	char *line[] = {"(", "typetransition", "foo", "bar", "file", "foobar", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	test_tree->root->cl_head->cl_head->next = NULL;
	
	int rc = cil_gen_type_rule(test_tree->root->cl_head->cl_head, test_ast_node, CIL_TYPE_TRANSITION);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_type_rule_transition_tgtnull_neg(CuTest *tc) {
	char *line[] = {"(", "typetransition", "foo", "bar", "file", "foobar", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	test_tree->root->cl_head->cl_head->next->next = NULL;

	int rc = cil_gen_type_rule(test_tree->root->cl_head->cl_head, test_ast_node, CIL_TYPE_TRANSITION);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_type_rule_transition_objnull_neg(CuTest *tc) {
	char *line[] = {"(", "typetransition", "foo", "bar", "file", "foobar", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	test_tree->root->cl_head->cl_head->next->next->next = NULL;

	int rc = cil_gen_type_rule(test_tree->root->cl_head->cl_head, test_ast_node, CIL_TYPE_TRANSITION);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_type_rule_transition_resultnull_neg(CuTest *tc) {
	char *line[] = {"(", "typetransition", "foo", "bar", "file", "foobar", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	test_tree->root->cl_head->cl_head->next->next->next->next = NULL;

	int rc = cil_gen_type_rule(test_tree->root->cl_head->cl_head, test_ast_node, CIL_TYPE_TRANSITION);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_type_rule_transition_extra_neg(CuTest *tc) {
	char *line[] = {"(", "typetransition", "foo", "bar", "file", "foobar", "extra", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_type_rule(test_tree->root->cl_head->cl_head, test_ast_node, CIL_TYPE_TRANSITION);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_type_rule_change(CuTest *tc) {
	char *line[] = {"(", "typechange", "foo", "bar", "file", "foobar", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_type_rule(test_tree->root->cl_head->cl_head, test_ast_node, CIL_TYPE_CHANGE);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertStrEquals(tc, ((struct cil_type_rule*)test_ast_node->data)->src_str, test_tree->root->cl_head->cl_head->next->data);
	CuAssertStrEquals(tc, ((struct cil_type_rule*)test_ast_node->data)->tgt_str, test_tree->root->cl_head->cl_head->next->next->data);
	CuAssertStrEquals(tc, ((struct cil_type_rule*)test_ast_node->data)->obj_str, test_tree->root->cl_head->cl_head->next->next->next->data);
	CuAssertStrEquals(tc, ((struct cil_type_rule*)test_ast_node->data)->result_str, test_tree->root->cl_head->cl_head->next->next->next->next->data);
	CuAssertIntEquals(tc, ((struct cil_type_rule*)test_ast_node->data)->rule_kind, CIL_TYPE_CHANGE);
	CuAssertIntEquals(tc, test_ast_node->flavor, CIL_TYPE_RULE);
}

void test_cil_gen_type_rule_change_currnull_neg(CuTest *tc) {
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_type_rule(NULL, test_ast_node, CIL_TYPE_CHANGE);
	CuAssertIntEquals(tc, SEPOL_ERR, rc); 
}

void test_cil_gen_type_rule_change_astnull_neg(CuTest *tc) {
	char *line[] = {"(", "typechange", "foo", "bar", "file", "foobar", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node = NULL;

	int rc = cil_gen_type_rule(test_tree->root->cl_head->cl_head, test_ast_node, CIL_TYPE_CHANGE);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}	

void test_cil_gen_type_rule_change_srcnull_neg(CuTest *tc) {
	char *line[] = {"(", "typechange", "foo", "bar", "file", "foobar", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	test_tree->root->cl_head->cl_head->next = NULL;
	
	int rc = cil_gen_type_rule(test_tree->root->cl_head->cl_head, test_ast_node, CIL_TYPE_CHANGE);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_type_rule_change_tgtnull_neg(CuTest *tc) {
	char *line[] = {"(", "typechange", "foo", "bar", "file", "foobar", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	test_tree->root->cl_head->cl_head->next->next = NULL;

	int rc = cil_gen_type_rule(test_tree->root->cl_head->cl_head, test_ast_node, CIL_TYPE_CHANGE);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_type_rule_change_objnull_neg(CuTest *tc) {
	char *line[] = {"(", "typechange", "foo", "bar", "file", "foobar", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	test_tree->root->cl_head->cl_head->next->next->next = NULL;

	int rc = cil_gen_type_rule(test_tree->root->cl_head->cl_head, test_ast_node, CIL_TYPE_CHANGE);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_type_rule_change_resultnull_neg(CuTest *tc) {
	char *line[] = {"(", "typechange", "foo", "bar", "file", "foobar", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	test_tree->root->cl_head->cl_head->next->next->next->next = NULL;

	int rc = cil_gen_type_rule(test_tree->root->cl_head->cl_head, test_ast_node, CIL_TYPE_CHANGE);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_type_rule_change_extra_neg(CuTest *tc) {
	char *line[] = {"(", "typechange", "foo", "bar", "file", "foobar", "extra", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_type_rule(test_tree->root->cl_head->cl_head, test_ast_node, CIL_TYPE_CHANGE);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_type_rule_member(CuTest *tc) {
	char *line[] = {"(", "typemember", "foo", "bar", "file", "foobar", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_type_rule(test_tree->root->cl_head->cl_head, test_ast_node, CIL_TYPE_MEMBER);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertStrEquals(tc, ((struct cil_type_rule*)test_ast_node->data)->src_str, test_tree->root->cl_head->cl_head->next->data);
	CuAssertStrEquals(tc, ((struct cil_type_rule*)test_ast_node->data)->tgt_str, test_tree->root->cl_head->cl_head->next->next->data);
	CuAssertStrEquals(tc, ((struct cil_type_rule*)test_ast_node->data)->obj_str, test_tree->root->cl_head->cl_head->next->next->next->data);
	CuAssertStrEquals(tc, ((struct cil_type_rule*)test_ast_node->data)->result_str, test_tree->root->cl_head->cl_head->next->next->next->next->data);
	CuAssertIntEquals(tc, ((struct cil_type_rule*)test_ast_node->data)->rule_kind, CIL_TYPE_MEMBER);
	CuAssertIntEquals(tc, test_ast_node->flavor, CIL_TYPE_RULE);
}

void test_cil_gen_type_rule_member_currnull_neg(CuTest *tc) {
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_type_rule(NULL, test_ast_node, CIL_TYPE_MEMBER);
	CuAssertIntEquals(tc, SEPOL_ERR, rc); 
}

void test_cil_gen_type_rule_member_astnull_neg(CuTest *tc) {
	char *line[] = {"(", "typemember", "foo", "bar", "file", "foobar", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node = NULL;

	int rc = cil_gen_type_rule(test_tree->root->cl_head->cl_head, test_ast_node, CIL_TYPE_MEMBER);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}	

void test_cil_gen_type_rule_member_srcnull_neg(CuTest *tc) {
	char *line[] = {"(", "typemember", "foo", "bar", "file", "foobar", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	test_tree->root->cl_head->cl_head->next = NULL;
	
	int rc = cil_gen_type_rule(test_tree->root->cl_head->cl_head, test_ast_node, CIL_TYPE_MEMBER);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_type_rule_member_tgtnull_neg(CuTest *tc) {
	char *line[] = {"(", "typemember", "foo", "bar", "file", "foobar", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	test_tree->root->cl_head->cl_head->next->next = NULL;

	int rc = cil_gen_type_rule(test_tree->root->cl_head->cl_head, test_ast_node, CIL_TYPE_MEMBER);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_type_rule_member_objnull_neg(CuTest *tc) {
	char *line[] = {"(", "typemember", "foo", "bar", "file", "foobar", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	test_tree->root->cl_head->cl_head->next->next->next = NULL;

	int rc = cil_gen_type_rule(test_tree->root->cl_head->cl_head, test_ast_node, CIL_TYPE_MEMBER);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_type_rule_member_resultnull_neg(CuTest *tc) {
	char *line[] = {"(", "typemember", "foo", "bar", "file", "foobar", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	test_tree->root->cl_head->cl_head->next->next->next->next = NULL;

	int rc = cil_gen_type_rule(test_tree->root->cl_head->cl_head, test_ast_node, CIL_TYPE_MEMBER);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_type_rule_member_extra_neg(CuTest *tc) {
	char *line[] = {"(", "typemember", "foo", "bar", "file", "foobar", "extra", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_type_rule(test_tree->root->cl_head->cl_head, test_ast_node, CIL_TYPE_MEMBER);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_user(CuTest *tc) {
	char *line[] = {"(", "user", "sysadm", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_user(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertIntEquals(tc, CIL_USER, test_ast_node->flavor);
	CuAssertPtrNotNull(tc, test_ast_node->data);
	CuAssertPtrEquals(tc, test_ast_node, ((struct cil_symtab_datum*)test_ast_node->data)->node);
	CuAssertStrEquals(tc, test_tree->root->cl_head->cl_head->next->data, ((struct cil_symtab_datum*)test_ast_node->data)->name);
}

void test_cil_gen_user_dbnull_neg(CuTest *tc) {
	char *line[] = {"(", "user", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db = NULL;

	int rc = cil_gen_user(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_user_currnull_neg(CuTest *tc) {
	char *line[] = {"(", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_user(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_user_astnull_neg(CuTest *tc) {
	char *line[] = {"(", "user", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node = NULL;

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_gen_user(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_user_nouser_neg(CuTest *tc) {
	char *line[] = {"(", "user", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_user(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_user_xsinfo_neg(CuTest *tc) {
	char *line[] = {"(", "user", "sysadm", "xsinfo", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_user(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}


void test_cil_gen_sensitivity(CuTest *tc) {
	char *line[] = {"(", "sensitivity", "s0", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_sensitivity(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, test_ast_node->data);
	CuAssertIntEquals(tc, test_ast_node->flavor, CIL_SENS);

}

void test_cil_gen_sensitivity_dbnull_neg(CuTest *tc) {
	char *line[] = {"(", "sensitivity", "s0", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db = NULL;

	int rc = cil_gen_sensitivity(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_sensitivity_currnull_neg(CuTest *tc) {
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_gen_sensitivity(test_db, NULL, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_sensitivity_astnull_neg(CuTest *tc) {
	char *line[] = {"(", "sensitivity", "s0", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node = NULL;

	int rc = cil_gen_sensitivity(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_sensitivity_sensnull_neg(CuTest *tc) {
	char *line[] = {"(", "sensitivity", "s0", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	test_tree->root->cl_head->cl_head->next = NULL;

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_sensitivity(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_sensitivity_senslist_neg(CuTest *tc) {
	char *line[] = {"(", "sensitivity", "(", "s0", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_sensitivity(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_sensitivity_extra_neg(CuTest *tc) {
	char *line[] = {"(", "sensitivity", "s0", "extra", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_sensitivity(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}	

void test_cil_gen_sensalias(CuTest *tc) {
	char *line[] = {"(", "sensitivityalias", "s0", "alias", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_sensalias(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_sensalias_dbnull_neg(CuTest *tc) {
	char *line[] = {"(", "sensitivityalias", "s0", "alias", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db = NULL;

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_sensalias(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_sensalias_currnull_neg(CuTest *tc) {
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_gen_sensalias(test_db, NULL, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_sensalias_astnull_neg(CuTest *tc) {
	char *line[] = {"(", "sensitivityalias", "s0", "alias", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init (&test_db);

	struct cil_tree_node *test_ast_node = NULL;

	int rc = cil_gen_sensalias(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_sensalias_sensnull_neg(CuTest *tc) {
	char *line[] = {"(", "sensitivityalias", "s0", "alias", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	test_tree->root->cl_head->cl_head->next = NULL;

	struct cil_db *test_db;
	cil_db_init(&test_db);
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_sensalias(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_sensalias_senslist_neg(CuTest *tc) {
	char *line[] = {"(", "sensitivityalias", "(", "s0", "s1", ")", "alias", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_sensalias(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_sensalias_aliasnull_neg(CuTest *tc) {
	char *line[] = {"(", "sensitivityalias", "s0", "alias", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	test_tree->root->cl_head->cl_head->next->next = NULL;

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_sensalias(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_sensalias_aliaslist_neg(CuTest *tc) {
	char *line[] = {"(", "sensitivityalias", "s0", "(", "alias", "alias2", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_sensalias(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_sensalias_extra_neg(CuTest *tc) {
	char *line[] = {"(", "sensitivityalias", "s0", "alias", "extra", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_sensalias(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_category(CuTest *tc) {
	char *line[] = {"(", "category", "c0", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_category(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_category_dbnull_neg(CuTest *tc) {
	char *line[] = {"(", "category", "c0", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db = NULL;

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_category(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_category_astnull_neg(CuTest *tc) {
	char *line[] = {"(", "category", "c0", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node = NULL;

	int rc = cil_gen_category(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_category_currnull_neg(CuTest *tc) {
	char *line[] = {"(", "category", "c0", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_category(test_db, NULL, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_category_catnull_neg(CuTest *tc){
	char *line[] = {"(", "category", "c0", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	test_tree->root->cl_head->cl_head->next = NULL;

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_category(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_category_catlist_neg(CuTest *tc){
	char *line[] = {"(", "category", "(", "c0", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_category(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_category_extra_neg(CuTest *tc) {
	char *line[] = {"(", "category", "c0", "extra", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_category(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_catset(CuTest *tc) {
	char *line[] = {"(", "categoryset", "somecats", "(", "c0", "c1", "c2", "(", "c3", "c4", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_catset(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_catset_dbnull_neg(CuTest *tc) {
	char *line[] = {"(", "categoryset", "somecats", "(", "c0", "c1", "c2", "(", "c3", "c4", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db = NULL;

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_catset(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_catset_currnull_neg(CuTest *tc) {
	char *line[] = {"(", "categoryset", "somecats", "(", "c0", "c1", "c2", "(", "c3", "c4", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_catset(test_db, NULL, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_catset_astnull_neg(CuTest *tc) {
	char *line[] = {"(", "categoryset", "somecats", "(", "c0", "c1", "c2", "(", "c3", "c4", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node = NULL;
	
	int rc = cil_gen_catset(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_catset_namenull_neg(CuTest *tc) {
	char *line[] = {"(", "categoryset", "somecats", "(", "c0", "c1", "c2", "(", "c3", "c4", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	test_tree->root->cl_head->cl_head->next = NULL;

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_catset(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_catset_setnull_neg(CuTest *tc) {
	char *line[] = {"(", "categoryset", "somecats", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_catset(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_catset_namelist_neg(CuTest *tc) { //This should fail before gen_node call - additional syntax checks are needed
	char *line[] = {"(", "categoryset", "(", "somecats", ")", "(", "c0", "c1", "c2", "(", "c3", "c4", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_catset(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_catset_extra_neg(CuTest *tc) {
	char *line[] = {"(", "categoryset", "somecats", "(", "c0", "c1", "c2", "(", "c3", "c4", ")", ")", "extra",  ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_catset(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_catset_notset_neg(CuTest *tc) {
	char *line[] = {"(", "categoryset", "somecats", "blah", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_catset(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

// TODO: This doesn't actually test failure of gen_node 
void test_cil_gen_catset_nodefail_neg(CuTest *tc) {
	char *line[] = {"(", "categoryset", "somecats", "(", "c0", "c1", "c2", "(", "c3", "c4", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db = NULL;

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_catset(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_catset_settolistfail_neg(CuTest *tc) {
	char *line[] = {"(", "categoryset", "somecats", "(", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_catset(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_catalias(CuTest *tc) {
	char *line[] = {"(", "categoryalias", "c0", "red", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;
	
	int rc = cil_gen_catalias(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_catalias_dbnull_neg(CuTest *tc) {
	char *line[] = {"(", "categoryalias", "c0", "red", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db = NULL;

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_catalias(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_catalias_currnull_neg(CuTest *tc) {
	char *line[] = {"(", "categoryalias", "c0", "red", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_catalias(test_db, NULL, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_catalias_astnull_neg(CuTest *tc) {
	char *line[] = {"(", "categoryalias", "c0", "red", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node = NULL;

	int rc = cil_gen_catalias(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_catalias_catnull_neg(CuTest *tc) {
	char *line[] = {"(", "categoryalias", "c0", "red", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	test_tree->root->cl_head->cl_head->next = NULL;

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_catalias(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_catalias_aliasnull_neg(CuTest *tc) {
	char *line[] = {"(", "categoryalias", "c0", "red", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	test_tree->root->cl_head->cl_head->next->next = NULL;

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_catalias(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_catalias_extra_neg(CuTest *tc) {
	char *line[] = {"(", "categoryalias", "c0", "red", "extra", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_catalias(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_roletype(CuTest *tc) {
	char *line[] = {"(", "roletype", "admin_r", "admin_t", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_roletype(test_db, test_tree->root->cl_head->cl_head, test_ast_node);

	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_roletype_currnull_neg(CuTest *tc) {
	char *line[] = {"(", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_roletype(test_db, test_tree->root->cl_head->cl_head, test_ast_node);

	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_roletype_dbnull_neg(CuTest *tc) {
	char *line[] = {"(", "roletype", "admin_r", "admin_t", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db = NULL;
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_roletype(test_db, test_tree->root->cl_head->cl_head, test_ast_node);

	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_roletype_astnull_neg(CuTest *tc) {
	char *line[] = {"(", "roletype", "admin_r", "admin_t", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);
	
	struct cil_tree_node *test_ast_node = NULL;

	int rc = cil_gen_roletype(test_db, test_tree->root->cl_head->cl_head, test_ast_node);

	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}


void test_cil_gen_roletype_empty_neg(CuTest *tc) {
	char *line[] = {"(", "roletype", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_roletype(test_db, test_tree->root->cl_head->cl_head, test_ast_node);

	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_roletype_rolelist_neg(CuTest *tc) {
	char *line[] = {"(", "roletype", "(", "admin_r", ")", "admin_t", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_roletype(test_db, test_tree->root->cl_head->cl_head, test_ast_node);

	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

// TODO
// Not sure this is actually testing roletype
// I think this will just test that type is null
void test_cil_gen_roletype_roletype_sublist_neg(CuTest *tc) {
	char *line[] = {"(", "(", "roletype", "admin_r", ")", "admin_t", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_roletype(test_db, test_tree->root->cl_head->cl_head, test_ast_node);

	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_roletype_typelist_neg(CuTest *tc) {
	char *line[] = {"(", "roletype", "admin_r", "(", "admin_t", ")", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_roletype(test_db, test_tree->root->cl_head->cl_head, test_ast_node);

	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_userrole(CuTest *tc) {
	char *line[] = {"(", "userrole", "staff_u", "staff_r", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_userrole(test_db, test_tree->root->cl_head->cl_head, test_ast_node);

	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_userrole_currnull_neg(CuTest *tc) {
	char *line[] = {"(", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_userrole(test_db, test_tree->root->cl_head->cl_head, test_ast_node);

	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_userrole_dbnull_neg(CuTest *tc) {
	char *line[] = {"(", "userrole", "staff_u", "staff_r", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db = NULL;
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_userrole(test_db, test_tree->root->cl_head->cl_head, test_ast_node);

	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_userrole_astnull_neg(CuTest *tc) {
	char *line[] = {"(", "userrole", "staff_u", "staff_r", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);
	
	struct cil_tree_node *test_ast_node = NULL;

	int rc = cil_gen_userrole(test_db, test_tree->root->cl_head->cl_head, test_ast_node);

	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_userrole_empty_neg(CuTest *tc) {
	char *line[] = {"(", "userrole", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_userrole(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_userrole_userlist_neg(CuTest *tc) {
	char *line[] = {"(", "userrole", "(", "staff_u", ")", "staff_r", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_userrole(test_db, test_tree->root->cl_head->cl_head, test_ast_node);

	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}


//TODO: see above
void test_cil_gen_userrole_userrole_sublist_neg(CuTest *tc) {
	char *line[] = {"(", "(", "userrole", "staff_u", ")", "staff_r", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_userrole(test_db, test_tree->root->cl_head->cl_head, test_ast_node);

	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_userrole_rolelist_neg(CuTest *tc) {
	char *line[] = {"(", "userrole", "staff_u", "(", "staff_r", ")", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_userrole(test_db, test_tree->root->cl_head->cl_head, test_ast_node);

	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_classcommon(CuTest *tc) {
	char *line[] = {"(", "classcommon", "file", "(", "read", "write", "open", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        char *test_key = test_tree->root->cl_head->cl_head->next->data;
        struct cil_class *test_cls = malloc(sizeof(struct cil_class));
        symtab_init(&test_cls->perms, CIL_SYM_SIZE);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        cil_symtab_insert(&test_db->symtab[CIL_SYM_CLASSES], (hashtab_key_t)test_key, (struct cil_symtab_datum*)test_cls, test_ast_node);

        test_ast_node->data = test_cls;
        test_ast_node->flavor = CIL_CLASS;

        int rc = cil_gen_classcommon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_classcommon_dbnull_neg(CuTest *tc) {
	char *line[] = {"(", "classcommon", "file", "(", "read", "write", "open", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db = NULL;

        int rc = cil_gen_classcommon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_classcommon_currnull_neg(CuTest *tc) {
	char *line[] = {"(", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        int rc = cil_gen_classcommon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_classcommon_astnull_neg(CuTest *tc) {
	char *line[] = {"(", "classcommon", "file", "(", "read", "write", "open", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node = NULL;

        struct cil_db *test_db;
        cil_db_init(&test_db);

        int rc = cil_gen_classcommon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_classcommon_missingclassname_neg(CuTest *tc) {
	char *line[] = {"(", "classcommon", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        int rc = cil_gen_classcommon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_classcommon_noperms_neg(CuTest *tc) {
	char *line[] = {"(", "classcommon", "file", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        char *test_key = test_tree->root->cl_head->cl_head->next->data;
        struct cil_class *test_cls = malloc(sizeof(struct cil_class));
        symtab_init(&test_cls->perms, CIL_SYM_SIZE);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        cil_symtab_insert(&test_db->symtab[CIL_SYM_CLASSES], (hashtab_key_t)test_key, (struct cil_symtab_datum*)test_cls, test_ast_node);

        test_ast_node->data = test_cls;
        test_ast_node->flavor = CIL_CLASS;

        int rc = cil_gen_classcommon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_classcommon_extraperms_neg(CuTest *tc) {
	char *line[] = {"(", "classcommon", "file", "(", "read", "write", ")", "(", "open", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        char *test_key = test_tree->root->cl_head->cl_head->next->data;
        struct cil_class *test_cls = malloc(sizeof(struct cil_class));
        symtab_init(&test_cls->perms, CIL_SYM_SIZE);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        cil_symtab_insert(&test_db->symtab[CIL_SYM_CLASSES], (hashtab_key_t)test_key, (struct cil_symtab_datum*)test_cls, test_ast_node);

        test_ast_node->data = test_cls;
        test_ast_node->flavor = CIL_CLASS;

        int rc = cil_gen_classcommon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_catorder(CuTest *tc) {
	char *line[] = {"(", "category", "c0", ")",
			"(", "category", "c255", ")",
			"(", "categoryorder", "(", "c0", "c255", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_catorder(test_db, test_tree->root->cl_head->next->next->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_catorder_dbnull_neg(CuTest *tc) {
	char *line[] = {"(", "category", "c0", ")",
			"(", "category", "c255", ")",
			"(", "categoryorder", "(", "c0", "c255", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db = NULL;

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_catorder(test_db, test_tree->root->cl_head->next->next->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_catorder_currnull_neg(CuTest *tc) {
	char *line[] = {"(", "category", "c0", ")",
			"(", "category", "c255", ")",
			"(", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_catorder(test_db, test_tree->root->cl_head->next->next->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_catorder_astnull_neg(CuTest *tc) {
	char *line[] = {"(", "category", "c0", ")",
			"(", "category", "c255", ")",
			"(", "categoryorder", "(", "c0", "c255", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node = NULL;

	int rc = cil_gen_catorder(test_db, test_tree->root->cl_head->next->next->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_catorder_missingcats_neg(CuTest *tc) {
	char *line[] = {"(", "category", "c0", ")",
			"(", "category", "c255", ")",
			"(", "categoryorder", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_catorder(test_db, test_tree->root->cl_head->next->next->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_catorder_nosublist_neg(CuTest *tc) {
	char *line[] = {"(", "category", "c0", ")",
			"(", "category", "c255", ")",
			"(", "categoryorder", "c0", "c255", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_catorder(test_db, test_tree->root->cl_head->next->next->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_catorder_nestedcat_neg(CuTest *tc) {
	char *line[] = {"(", "category", "c0", ")",
			"(", "category", "c255", ")",
			"(", "categoryorder", "(", "c0", "(", "c255", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_catorder(test_db, test_tree->root->cl_head->next->next->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_dominance(CuTest *tc) {
        char *line[] = {"(", "sensitivity", "s0", ")",
                        "(", "sensitivity", "s1", ")",
                        "(", "sensitivity", "s2", ")",
                        "(", "dominance", "(", "s0", "s1", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_dominance(test_db, test_tree->root->cl_head->next->next->next->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_dominance_dbnull_neg(CuTest *tc) {
	char *line[] = {"(", "sensitivity", "s0", ")",
			"(", "sensitivity", "s1", ")",
			"(", "sensitivity", "s2", ")",
			"(", "dominance", "(", "s0", "s1", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db = NULL;

        int rc = cil_gen_dominance(test_db, test_tree->root->cl_head->next->next->next->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_dominance_currnull_neg(CuTest *tc) {
	char *line[] = {"(", "sensitivity", "s0", ")",
			"(", "sensitivity", "s1", ")",
			"(", "sensitivity", "s2", ")",
			"(", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_dominance(test_db, test_tree->root->cl_head->next->next->next->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_dominance_astnull_neg(CuTest *tc) {
	char *line[] = {"(", "sensitivity", "s0", ")",
			"(", "sensitivity", "s1", ")",
			"(", "sensitivity", "s2", ")",
			"(", "dominance", "(", "s0", "s1", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node = NULL;

        struct cil_db *test_db;
        cil_db_init(&test_db);

        int rc = cil_gen_dominance(test_db, test_tree->root->cl_head->next->next->next->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_dominance_nosensitivities_neg(CuTest *tc) {
	char *line[] = {"(", "sensitivity", "s0", ")",
			"(", "sensitivity", "s1", ")",
			"(", "sensitivity", "s2", ")",
			"(", "dominance", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_dominance(test_db, test_tree->root->cl_head->next->next->next->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_dominance_nosublist_neg(CuTest *tc) {
	char *line[] = {"(", "sensitivity", "s0", ")",
			"(", "sensitivity", "s1", ")",
			"(", "sensitivity", "s2", ")",
			"(", "dominance", "s0", "s2", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_dominance(test_db, test_tree->root->cl_head->next->next->next->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_senscat(CuTest *tc) {
	char *line[] = {"(", "sensitivity", "s0", ")",
                        "(", "sensitivity", "s1", ")",
                        "(", "dominance", "(", "s0", "s1", ")", ")",
			"(", "category", "c0", ")",
			"(", "category", "c255", ")",
			"(", "categoryorder", "(", "c0", "c255", ")", ")",
			"(", "sensitivitycategory", "s1", "(", "c0", "c255", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_senscat(test_db, test_tree->root->cl_head->next->next->next->next->next->next->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_senscat_dbnull_neg(CuTest *tc) {
	char *line[] = {"(", "sensitivity", "s0", ")",
                        "(", "sensitivity", "s1", ")",
                        "(", "dominance", "(", "s0", "s1", ")", ")",
			"(", "category", "c0", ")",
			"(", "category", "c255", ")",
			"(", "categoryorder", "(", "c0", "c255", ")", ")",
			"(", "sensitivitycategory", "s1", "(", "c0", "c255", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db = NULL;

        int rc = cil_gen_senscat(test_db, test_tree->root->cl_head->next->next->next->next->next->next->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_senscat_currnull_neg(CuTest *tc) {
	char *line[] = {"(", "sensitivity", "s0", ")",
                        "(", "sensitivity", "s1", ")",
                        "(", "dominance", "(", "s0", "s1", ")", ")",
			"(", "category", "c0", ")",
			"(", "category", "c255", ")",
			"(", "categoryorder", "(", "c0", "c255", ")", ")",
			"(", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_senscat(test_db, test_tree->root->cl_head->next->next->next->next->next->next->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_senscat_astnull_neg(CuTest *tc) {
	char *line[] = {"(", "sensitivity", "s0", ")",
                        "(", "sensitivity", "s1", ")",
                        "(", "dominance", "(", "s0", "s1", ")", ")",
			"(", "category", "c0", ")",
			"(", "category", "c255", ")",
			"(", "categoryorder", "(", "c0", "c255", ")", ")",
			"(", "sensitivitycategory", "s1", "(", "c0", "c255", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node = NULL;

        struct cil_db *test_db;
        cil_db_init(&test_db);

        int rc = cil_gen_senscat(test_db, test_tree->root->cl_head->next->next->next->next->next->next->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_senscat_nosensitivities_neg(CuTest *tc) {
	char *line[] = {"(", "sensitivity", "s0", ")",
                        "(", "sensitivity", "s1", ")",
                        "(", "dominance", "(", "s0", "s1", ")", ")",
			"(", "category", "c0", ")",
			"(", "category", "c255", ")",
			"(", "categoryorder", "(", "c0", "c255", ")", ")",
			"(", "sensitivitycategory", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_senscat(test_db, test_tree->root->cl_head->next->next->next->next->next->next->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_senscat_nosublist_neg(CuTest *tc) {
	char *line[] = {"(", "sensitivity", "s0", ")",
                        "(", "sensitivity", "s1", ")",
                        "(", "dominance", "(", "s0", "s1", ")", ")",
			"(", "category", "c0", ")",
			"(", "category", "c255", ")",
			"(", "categoryorder", "(", "c0", "c255", ")", ")",
			"(", "sensitivitycategory", "s1", "c0", "c255", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_senscat(test_db, test_tree->root->cl_head->next->next->next->next->next->next->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_senscat_sublist_neg(CuTest *tc) {
      char *line[] = {"(", "sensitivity", "s0", ")",
                        "(", "sensitivity", "s1", ")",
                        "(", "dominance", "(", "s0", "s1", ")", ")",
                        "(", "category", "c0", ")",
                        "(", "category", "c255", ")",
                        "(", "categoryorder", "(", "c0", "c255", ")", ")",
                        "(", "sensitivitycategory", "s1", "(", "c0", "(", "c255", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_gen_senscat(test_db, test_tree->root->cl_head->next->next->next->next->next->next->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_fill_level(CuTest *tc) {
	char *line[] = {"(", "sensitivity", "s0", ")",
			"(", "category", "c1", ")",
			"(", "level", "low", "s0", "(", "c1", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

	struct cil_level *test_level;
	cil_level_init(&test_level);

        int rc = cil_fill_level(test_tree->root->cl_head->next->next->cl_head->next->next, test_level);
        CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_fill_level_sensnull_neg(CuTest *tc) {
	char *line[] = {"(", "sensitivity", "s0", ")",
			"(", "category", "c1", ")",
			"(", "level", "low", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

	struct cil_level *test_level;
	cil_level_init(&test_level);

        int rc = cil_fill_level(test_tree->root->cl_head->next->next->cl_head->next->next, test_level);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_fill_level_levelnull_neg(CuTest *tc) {
	char *line[] = {"(", "sensitivity", "s0", ")",
			"(", "category", "c1", ")",
			"(", "level", "low", "s0", "(", "c1", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

	struct cil_level *test_level = NULL;

        int rc = cil_fill_level(test_tree->root->cl_head->next->next->cl_head->next->next, test_level);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_fill_level_nocat(CuTest *tc) {
	char *line[] = {"(", "sensitivity", "s0", ")",
			"(", "category", "c1", ")",
			"(", "level", "low", "s0", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

	struct cil_level *test_level;
	cil_level_init(&test_level);

        int rc = cil_fill_level(test_tree->root->cl_head->next->next->cl_head->next->next, test_level);
        CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_fill_level_emptycat_neg(CuTest *tc) {
	char *line[] = {"(", "sensitivity", "s0", ")",
			"(", "category", "c1", ")",
			"(", "level", "low", "s0", "(", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

	struct cil_level *test_level;
	cil_level_init(&test_level);

        int rc = cil_fill_level(test_tree->root->cl_head->next->next->cl_head->next->next, test_level);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_level(CuTest *tc) {
	char *line[] = {"(", "sensitivity", "s0", ")",
			"(", "category", "c1", ")",
			"(", "level", "low", "s0", "(", "c1", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_level(test_db, test_tree->root->cl_head->next->next->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_level_emptycat_neg(CuTest *tc) {
	char *line[] = {"(", "sensitivity", "s0", ")",
			"(", "category", "c1", ")",
			"(", "level", "low", "s0", "(", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_level(test_db, test_tree->root->cl_head->next->next->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_level_noname_neg(CuTest *tc) {
	char *line[] = {"(", "sensitivity", "s0", ")",
			"(", "category", "c1", ")",
			"(", "level", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_level(test_db, test_tree->root->cl_head->next->next->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_level_nosens_neg(CuTest *tc) {
	char *line[] = {"(", "sensitivity", "s0", ")",
			"(", "category", "c1", ")",
			"(", "level", "low", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_level(test_db, test_tree->root->cl_head->next->next->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_level_dbnull_neg(CuTest *tc) {
	char *line[] = {"(", "sensitivity", "s0", ")",
			"(", "category", "c1", ")",
			"(", "level", "low", "s0", "(", "c1", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db = NULL;

        int rc = cil_gen_level(test_db, test_tree->root->cl_head->next->next->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_level_currnull_neg(CuTest *tc) {
	char *line[] = {"(", "sensitivity", "s0", ")",
			"(", "category", "c1", ")",
			"(", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_level(test_db, test_tree->root->cl_head->next->next->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_level_astnull_neg(CuTest *tc) {
	char *line[] = {"(", "sensitivity", "s0", ")",
			"(", "category", "c1", ")",
			"(", "level", "low", "s0", "(", "c1", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node = NULL;

        struct cil_db *test_db;
        cil_db_init(&test_db);

        int rc = cil_gen_level(test_db, test_tree->root->cl_head->next->next->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

/*void test__cil_build_constrain_tree(CuTest *tc) {
	char *line[] = {"(", "eq", "12", "h2", ")", NULL};
	
        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

	struct cil_constrain *test_con;
	cil_constrain_init(&test_con);
	cil_list_init(&test_con->class_list_str);
	cil_parse_to_list(test_tree->root->cl_head->cl_head, test_con->class_list_str, CIL_AST_STR); 
	cil_list_init(&test_con->perm_list_str);
	cil_parse_to_list(test_tree->root->cl_head->cl_head, test_con->perm_list_str, CIL_AST_STR);
	cil_tree_init(&test_con->expr);

//	int rc = __cil_build_constrain_tree(test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test__cil_build_constrain_tree_unknown_neg(CuTest *tc) {
	char *line[] = {"(", "dne", "l1", "l2", ")", NULL};
	
        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

	struct cil_constrain *test_con;
	cil_constrain_init(&test_con);
	cil_list_init(&test_con->class_list_str);
	cil_parse_to_list(test_tree->root->cl_head->cl_head, test_con->class_list_str, CIL_AST_STR); 
	cil_list_init(&test_con->perm_list_str);
	cil_parse_to_list(test_tree->root->cl_head->cl_head, test_con->perm_list_str, CIL_AST_STR);
	cil_tree_init(&test_con->expr);

//	int rc = __cil_build_constrain_tree(test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test__cil_build_constrain_tree_multi_constrain(CuTest *tc) {
	char *line[] = {"(", "or", "(", "domby", "l1", "l2", ")", "(", "==", "t1", "mlsfilewritedown", ")", ")", NULL};
	
        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

	struct cil_constrain *test_con;
	cil_constrain_init(&test_con);
	cil_list_init(&test_con->class_list_str);
	cil_parse_to_list(test_tree->root->cl_head->cl_head, test_con->class_list_str, CIL_AST_STR); 
	cil_list_init(&test_con->perm_list_str);
	cil_parse_to_list(test_tree->root->cl_head->cl_head, test_con->perm_list_str, CIL_AST_STR);
	cil_tree_init(&test_con->expr);

//	int rc = __cil_build_constrain_tree(test_tree->root->cl_head->cl_head, test_ast_node, CIL_CONSTRAIN);
        CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test__cil_build_constrain_tree_currnull_neg(CuTest *tc) {
	char *line[] = {"(", ")", NULL};
	
        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

	struct cil_constrain *test_con;
	cil_constrain_init(&test_con);
	cil_list_init(&test_con->class_list_str);
	cil_parse_to_list(test_tree->root->cl_head->cl_head, test_con->class_list_str, CIL_AST_STR); 
	cil_list_init(&test_con->perm_list_str);
	cil_parse_to_list(test_tree->root->cl_head->cl_head, test_con->perm_list_str, CIL_AST_STR);
	cil_tree_init(&test_con->expr);

//	int rc = __cil_build_constrain_tree(test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test__cil_build_constrain_tree_exprnull_neg(CuTest *tc) {
	char *line[] = {"(", "eq", "12", "h2", ")", NULL};
	
        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node = NULL;

        struct cil_db *test_db;
        cil_db_init(&test_db);

	struct cil_constrain *test_con;
	cil_constrain_init(&test_con);
	cil_list_init(&test_con->class_list_str);
	cil_parse_to_list(test_tree->root->cl_head->cl_head, test_con->class_list_str, CIL_AST_STR); 
	cil_list_init(&test_con->perm_list_str);
	cil_parse_to_list(test_tree->root->cl_head->cl_head, test_con->perm_list_str, CIL_AST_STR);
	cil_tree_init(&test_con->expr);

	int rc = __cil_build_constrain_tree(test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}*/

void test_cil_gen_constrain(CuTest *tc) {
	char *line[] = {"(", "mlsconstrain", "(", "file", "dir", ")", "(", "create", "relabelto", ")", "(", "eq", "12", "h2", ")", ")", NULL};
	
        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_constrain(test_db, test_tree->root->cl_head->cl_head, test_ast_node, CIL_MLSCONSTRAIN);
        CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_constrain_neg(CuTest *tc) {
	char *line[] = {"(", "mlsconstrain", "(", "file", "dir", ")", "(", "create", "relabelto", ")", "(", "dne", "l1", "l2", ")", ")", NULL};
	
        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_constrain(test_db, test_tree->root->cl_head->cl_head, test_ast_node, CIL_MLSCONSTRAIN);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_constrain_classset_neg(CuTest *tc) {
	char *line[] = {"(", "mlsconstrain", ")", NULL};
	
        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_constrain(test_db, test_tree->root->cl_head->cl_head, test_ast_node, CIL_MLSCONSTRAIN);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_constrain_classset_noclass_neg(CuTest *tc) {
	char *line[] = {"(", "mlsconstrain", "(", ")", ")", NULL};
	
        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_constrain(test_db, test_tree->root->cl_head->cl_head, test_ast_node, CIL_MLSCONSTRAIN);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_constrain_classset_noperm_neg(CuTest *tc) {
	char *line[] = {"(", "mlsconstrain", "(", "file", ")", ")", NULL};
	
        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_constrain(test_db, test_tree->root->cl_head->cl_head, test_ast_node, CIL_MLSCONSTRAIN);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_constrain_permset_neg(CuTest *tc) {
	char *line[] = {"(", "mlsconstrain", "(", "file", "dir", ")", ")", NULL};
	
        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_constrain(test_db, test_tree->root->cl_head->cl_head, test_ast_node, CIL_MLSCONSTRAIN);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_constrain_permset_noclass_neg(CuTest *tc) {
	char *line[] = {"(", "mlsconstrain", "(", "file", "dir", ")", "(", ")", ")", NULL};
	
        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_constrain(test_db, test_tree->root->cl_head->cl_head, test_ast_node, CIL_MLSCONSTRAIN);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_constrain_permset_noperm_neg(CuTest *tc) {
	char *line[] = {"(", "mlsconstrain", "(", "file", "dir", ")", "(", "create", ")", ")", NULL};
	
        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_constrain(test_db, test_tree->root->cl_head->cl_head, test_ast_node, CIL_MLSCONSTRAIN);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_constrain_expression_neg(CuTest *tc) {
	char *line[] = {"(", "mlsconstrain", "(", "file", "dir", ")", "(", "create", "relabelto", ")", "(", ")", ")", NULL};
	
        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_constrain(test_db, test_tree->root->cl_head->cl_head, test_ast_node, CIL_MLSCONSTRAIN);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_constrain_dbnull_neg(CuTest *tc) {
	char *line[] = {"(", "mlsconstrain", "(", "file", "dir", ")", "(", "create", "relabelto", ")", "(", "eq", "12", "h2", ")", ")", NULL};
	
        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db = NULL;

        int rc = cil_gen_constrain(test_db, test_tree->root->cl_head->cl_head, test_ast_node, CIL_MLSCONSTRAIN);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_constrain_currnull_neg(CuTest *tc) {
	char *line[] = {"(", ")", NULL};
	
        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_constrain(test_db, test_tree->root->cl_head->cl_head, test_ast_node, CIL_MLSCONSTRAIN);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_constrain_astnull_neg(CuTest *tc) {
	char *line[] = {"(", "mlsconstrain", "(", "file", "dir", ")", "(", "create", "relabelto", ")", "(", "eq", "12", "h2", ")", ")", NULL};
	
        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node = NULL;

        struct cil_db *test_db;
        cil_db_init(&test_db);

        int rc = cil_gen_constrain(test_db, test_tree->root->cl_head->cl_head, test_ast_node, CIL_MLSCONSTRAIN);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_fill_context(CuTest *tc) {
	char *line[] = {"(", "context", "localhost_node_label", "(", "system_u", "object_r", "node_lo_t", "low", "high", ")", ")", NULL};
	
        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

	struct cil_context *test_context;
	cil_context_init(&test_context);

        int rc = cil_fill_context(test_tree->root->cl_head->cl_head->next->next->cl_head, test_context);
        CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_fill_context_unnamedlvl(CuTest *tc) {
	char *line[] = {"(", "context", "localhost_node_label", "(", "system_u", "object_r", "node_lo_t", "(", "s0", ")", "(", "s0", ")", ")", ")", NULL};
	
        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

	struct cil_context *test_context;
	cil_context_init(&test_context);

        int rc = cil_fill_context(test_tree->root->cl_head->cl_head->next->next->cl_head, test_context);
        CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_fill_context_nocontext_neg(CuTest *tc) {
	char *line[] = {"(", "context", "localhost_node_label", "(", "system_u", "object_r", "node_lo_t", "low", "high", ")", ")", NULL};
	
        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

	struct cil_context *test_context = NULL;

        int rc = cil_fill_context(test_tree->root->cl_head->cl_head->next->next->cl_head, test_context);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_fill_context_nouser_neg(CuTest *tc) {
	char *line[] = {"(", "context", "localhost_node_label", "(", ")", ")", NULL};
	
        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

	struct cil_context *test_context;
	cil_context_init(&test_context);

	int rc = cil_fill_context(test_tree->root->cl_head->cl_head->next->next->cl_head, test_context);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_fill_context_norole_neg(CuTest *tc) {
	char *line[] = {"(", "context", "localhost_node_label", "(", "system_u", ")", ")", NULL};
	
        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

	struct cil_context *test_context;
	cil_context_init(&test_context);

	int rc = cil_fill_context(test_tree->root->cl_head->cl_head->next->next->cl_head, test_context);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_fill_context_notype_neg(CuTest *tc) {
	char *line[] = {"(", "context", "localhost_node_label", "(", "system_u", "object_r", ")", ")", NULL};
	
        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

	struct cil_context *test_context;
	cil_context_init(&test_context);

	int rc = cil_fill_context(test_tree->root->cl_head->cl_head->next->next->cl_head, test_context);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_fill_context_nolowlvl_neg(CuTest *tc) {
	char *line[] = {"(", "context", "localhost_node_label", "(", "system_u", "object_r", "type_t", ")", ")", NULL};
	
        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

	struct cil_context *test_context;
	cil_context_init(&test_context);

	int rc = cil_fill_context(test_tree->root->cl_head->cl_head->next->next->cl_head, test_context);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_fill_context_nohighlvl_neg(CuTest *tc) {
	char *line[] = {"(", "context", "localhost_node_label", "(", "system_u", "object_r", "type_t", "low", ")", ")", NULL};
	
        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

	struct cil_context *test_context;
	cil_context_init(&test_context);

	int rc = cil_fill_context(test_tree->root->cl_head->cl_head->next->next->cl_head, test_context);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_fill_context_unnamedlvl_nocontextlow_neg(CuTest *tc) {
	char *line[] = {"(", "context", "localhost_node_label", "(", "system_u", "object_r", "type_t", "(", "s0", "(", ")", ")", "high", ")", ")", NULL};
	
        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

	struct cil_context *test_context;
	cil_context_init(&test_context);

	int rc = cil_fill_context(test_tree->root->cl_head->cl_head->next->next->cl_head, test_context);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_fill_context_unnamedlvl_nocontexthigh_neg(CuTest *tc) {
	char *line[] = {"(", "context", "localhost_node_label", "(", "system_u", "object_r", "type_t", "low", "(", "s0", "(", ")", ")", ")", ")", NULL};
	
        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

	struct cil_context *test_context;
	cil_context_init(&test_context);

	int rc = cil_fill_context(test_tree->root->cl_head->cl_head->next->next->cl_head, test_context);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_context(CuTest *tc) {
	char *line[] = {"(", "context", "packet_default", "(", "system_u", "object_r", "etc_t", "low", "high", ")", ")", NULL};
	
        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_context(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_context_extralevel_neg(CuTest *tc) {
	char *line[] = {"(", "context", "packet_default", "(", "system_u", "object_r", "etc_t", "low", "high", "extra", ")", ")", NULL};
	
        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_context(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_context_emptycontext_neg(CuTest *tc) {
	char *line[] = {"(", "context", "packet_default", "(", ")", ")", NULL};
	
        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_context(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_context_extra_neg(CuTest *tc) {
	char *line[] = {"(", "context", "packet_default", "(", "system_u", "object_r", "etc_t", "low", "high", ")", "(", "extra", ")", ")", NULL};
	
        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_context(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_context_doubleparen_neg(CuTest *tc) {
	char *line[] = {"(", "context", "packet_default", "(", "(", "system_u", ")", ")", ")", NULL};
	
        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_context(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_context_norole_neg(CuTest *tc) {
	char *line[] = {"(", "context", "packet_default", "(", "system_u", ")", ")", NULL};
	
        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_context(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_context_roleinparens_neg(CuTest *tc) {
	char *line[] = {"(", "context", "packet_default", "(", "system_u", "(", "role_r", ")", ")", ")", NULL};
	
        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_context(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_context_notype_neg(CuTest *tc) {
	char *line[] = {"(", "context", "packet_default", "(", "system_u", "role_r", ")", ")", NULL};
	
        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_context(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_context_typeinparens_neg(CuTest *tc) {
	char *line[] = {"(", "context", "packet_default", "(", "system_u", "role_r", "(", "type_t", ")", ")", ")", NULL};
	
        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_context(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_context_nolevels_neg(CuTest *tc) {
	char *line[] = {"(", "context", "packet_default", "(", "system_u", "role_r", "type_t", ")", ")", NULL};
	
        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_context(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_context_nosecondlevel_neg(CuTest *tc) {
	char *line[] = {"(", "context", "packet_default", "(", "system_u", "role_r", "type_t", "low", ")", ")", NULL};
	
        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_context(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_context_noname_neg(CuTest *tc) {
	char *line[] = {"(", "context", ")", NULL};
	
        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_context(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_context_nouser_neg(CuTest *tc) {
	char *line[] = {"(", "context", "localhost_node_label", ")", NULL};
	
        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_context(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_context_dbnull_neg(CuTest *tc) {
	char *line[] = {"(", "context", "localhost_node_label", "(", "system_u", "object_r", "node_lo_t", "(", "s0", ")", "(", "s0", ")", ")", ")", NULL};
	
        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db = NULL;

        int rc = cil_gen_context(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_context_currnull_neg(CuTest *tc) {
	char *line[] = {"(", ")", NULL};
	
        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_context(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_context_astnull_neg(CuTest *tc) {
	char *line[] = {"(", "context", "localhost_node_label", "system_u", "object_r", "node_lo_t", "(", "s0", ")", "(", "s0", ")", ")", ")", NULL};
	
        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node = NULL;

        struct cil_db *test_db;
        cil_db_init(&test_db);

        int rc = cil_gen_context(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_filecon_dir(CuTest *tc) {
	char *line[] = {"(", "filecon", "root", "path", "dir", "context", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_filecon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_filecon_file(CuTest *tc) {
	char *line[] = {"(", "filecon", "root", "path", "file", "context", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_filecon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_filecon_char(CuTest *tc) {
	char *line[] = {"(", "filecon", "root", "path", "char", "context", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_filecon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_filecon_block(CuTest *tc) {
	char *line[] = {"(", "filecon", "root", "path", "block", "context", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_filecon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_filecon_socket(CuTest *tc) {
	char *line[] = {"(", "filecon", "root", "path", "socket", "context", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_filecon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_filecon_pipe(CuTest *tc) {
	char *line[] = {"(", "filecon", "root", "path", "pipe", "context", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_filecon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_filecon_symlink(CuTest *tc) {
	char *line[] = {"(", "filecon", "root", "path", "symlink", "context", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_filecon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_filecon_any(CuTest *tc) {
	char *line[] = {"(", "filecon", "root", "path", "any", "context", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_filecon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_filecon_neg(CuTest *tc) {
	char *line[] = {"(", "filecon", "root", "path", "dne", "context", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_filecon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_filecon_anon_context(CuTest *tc) {
	char *line[] = {"(", "filecon", "root", "path", "file", "(", "system_u", "object_r", "etc_t", "low", "high", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_filecon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_filecon_dbnull_neg(CuTest *tc) {
	char *line[] = {"(", "filecon", "root", "path", "file", "(", "system_u", "object_r", "etc_t", "low", "high", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db = NULL;

        int rc = cil_gen_filecon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_filecon_currnull_neg(CuTest *tc) {
	char *line[] = {"(", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_filecon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_filecon_astnull_neg(CuTest *tc) {
	char *line[] = {"(", "filecon", "root", "path", "file", "(", "system_u", "object_r", "etc_t", "low", "high", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node = NULL; 

        struct cil_db *test_db;
        cil_db_init(&test_db);

        int rc = cil_gen_filecon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_filecon_str1null_neg(CuTest *tc) {
	char *line[] = {"(", "filecon", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_filecon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_filecon_str1_inparens_neg(CuTest *tc) {
	char *line[] = {"(", "filecon", "(", "root", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_filecon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_filecon_str2null_neg(CuTest *tc) {
	char *line[] = {"(", "filecon", "root", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_filecon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_filecon_str2_inparens_neg(CuTest *tc) {
	char *line[] = {"(", "filecon", "root", "(", "path", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_filecon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_filecon_classnull_neg(CuTest *tc) {
	char *line[] = {"(", "filecon", "root", "path", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_filecon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_filecon_class_inparens_neg(CuTest *tc) {
	char *line[] = {"(", "filecon", "root", "path", "(", "file", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_filecon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_filecon_contextnull_neg(CuTest *tc) {
	char *line[] = {"(", "filecon", "root", "path", "file", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_filecon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_filecon_context_neg(CuTest *tc) {
	char *line[] = {"(", "filecon", "root", "path", "file", "(", "system_u", "object_r", "low", "high", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_filecon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_filecon_extra_neg(CuTest *tc) {
	char *line[] = {"(", "filecon", "root", "path", "file", "context", "extra", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_filecon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_portcon(CuTest *tc) {
	char *line[] = {"(", "portcon", "type", "port", "con", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_portcon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_portcon_anon_context(CuTest *tc) {
	char *line[] = {"(", "portcon", "type", "port", "(", "system_u", "object_r", "etc_t", "low", "high", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_portcon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_portcon_portrange(CuTest *tc) {
	char *line[] = {"(", "portcon", "type", "(", "25", "75", ")", "con", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_portcon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_portcon_portrange_one_neg(CuTest *tc) {
	char *line[] = {"(", "portcon", "type", "(", "0", ")", "con", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_portcon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_portcon_portrange_morethanone_neg(CuTest *tc) {
	char *line[] = {"(", "portcon", "type", "(", "0", "1", "2", ")", "con", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_portcon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_portcon_dbnull_neg(CuTest *tc) {
	char *line[] = {"(", "portcon", "type", "(", "0", "1", "2", ")", "con", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db = NULL;

        int rc = cil_gen_portcon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_portcon_currnull_neg(CuTest *tc) {
	char *line[] = {"(", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_portcon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_portcon_astnull_neg(CuTest *tc) {
	char *line[] = {"(", "portcon", "type", "(", "0", "1", "2", ")", "con", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node = NULL;

        struct cil_db *test_db;
        cil_db_init(&test_db);

        int rc = cil_gen_portcon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_portcon_str1null_neg(CuTest *tc) {
	char *line[] = {"(", "portcon", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_portcon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_portcon_str1parens_neg(CuTest *tc) {
	char *line[] = {"(", "portcon", "(", "type", ")", "port", "con", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_portcon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_portcon_portnull_neg(CuTest *tc) {
	char *line[] = {"(", "portcon", "type", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_portcon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_portcon_contextnull_neg(CuTest *tc) {
	char *line[] = {"(", "portcon", "type", "port", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_portcon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_portcon_context_neg(CuTest *tc) {
	char *line[] = {"(", "portcon", "type", "port", "(", "system_u", "object_r", "low", "high", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_portcon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_portcon_extra_neg(CuTest *tc) {
	char *line[] = {"(", "portcon", "type", "port", "con", "extra", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_portcon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_nodecon(CuTest *tc) {
	char *line[] = {"(", "nodecon", "ipaddr", "ipaddr", "con", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_nodecon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_nodecon_anon_context(CuTest *tc) {
	char *line[] = {"(", "nodecon", "ipaddr", "ipaddr", "(", "system_u", "object_r", "etc_t", "low", "high", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_nodecon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_nodecon_dbnull_neg(CuTest *tc) {
	char *line[] = {"(", "nodecon", "ipaddr", "ipaddr", "con", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db = NULL;

        int rc = cil_gen_nodecon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_nodecon_currnull_neg(CuTest *tc) {
	char *line[] = {"(", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_nodecon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_nodecon_astnull_neg(CuTest *tc) {
	char *line[] = {"(", "nodecon", "ipaddr", "ipaddr", "con", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node = NULL;

        struct cil_db *test_db;
        cil_db_init(&test_db);

        int rc = cil_gen_nodecon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_nodecon_ip1null_neg(CuTest *tc) {
	char *line[] = {"(", "nodecon", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_nodecon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_nodecon_ip1parens_neg(CuTest *tc) {
	char *line[] = {"(", "nodecon", "(", "ipaddr", ")", "ipaddr", "con", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_nodecon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_nodecon_ip2null_neg(CuTest *tc) {
	char *line[] = {"(", "nodecon", "ipaddr", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_nodecon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_nodecon_ip2parens_neg(CuTest *tc) {
	char *line[] = {"(", "nodecon", "ipaddr", "(", "ipaddr", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_nodecon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_nodecon_contextnull_neg(CuTest *tc) {
	char *line[] = {"(", "nodecon", "ipaddr", "ipaddr", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_nodecon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_nodecon_context_neg(CuTest *tc) {
	char *line[] = {"(", "nodecon", "ipaddr", "ipaddr", "(", "system_u", "object_r", "low", "high", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_nodecon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_nodecon_extra_neg(CuTest *tc) {
	char *line[] = {"(", "nodecon", "ipaddr", "ipaddr", "(", "system_u", "object_r", "type_t", "low", "high", ")", "extra", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_nodecon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_genfscon(CuTest *tc) {
	char *line[] = {"(", "genfscon", "type", "path", "con", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_genfscon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_genfscon_anon_context(CuTest *tc) {
	char *line[] = {"(", "genfscon", "type", "path", "(", "system_u", "object_r", "etc_t", "low", "high", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_genfscon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_genfscon_dbnull_neg(CuTest *tc) {
	char *line[] = {"(", "genfscon", "type", "path", "con", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db = NULL;

        int rc = cil_gen_genfscon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_genfscon_currnull_neg(CuTest *tc) {
	char *line[] = {"(", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_genfscon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_genfscon_astnull_neg(CuTest *tc) {
	char *line[] = {"(", "genfscon", "type", "path", "con", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node = NULL;

        struct cil_db *test_db;
        cil_db_init(&test_db);

        int rc = cil_gen_genfscon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_genfscon_typenull_neg(CuTest *tc) {
	char *line[] = {"(", "genfscon", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_genfscon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_genfscon_typeparens_neg(CuTest *tc) {
	char *line[] = {"(", "genfscon", "(", "type", ")", "path", "con", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_genfscon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_genfscon_pathnull_neg(CuTest *tc) {
	char *line[] = {"(", "genfscon", "type", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_genfscon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_genfscon_pathparens_neg(CuTest *tc) {
	char *line[] = {"(", "genfscon", "type", "(", "path", ")", "con", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_genfscon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_genfscon_contextnull_neg(CuTest *tc) {
	char *line[] = {"(", "genfscon", "type", "path", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_genfscon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_genfscon_context_neg(CuTest *tc) {
	char *line[] = {"(", "genfscon", "type", "path", "(", "system_u", "object_r", "low", "high", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_genfscon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_genfscon_extra_neg(CuTest *tc) {
	char *line[] = {"(", "genfscon", "type", "path", "con", "extra", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_genfscon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_netifcon(CuTest *tc) {
	char *line[] = {"(", "netifcon", "eth0", "if_default", "packet_default", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_netifcon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_netifcon_nested(CuTest *tc) {
	char *line[] = {"(", "netifcon", "eth1", 
			"(", "system_u", "object_r", "netif_t", "low", "high", ")",
			"(", "system_u", "object_r", "netif_t", "low", "high", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_netifcon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_netifcon_nested_neg(CuTest *tc) {
	char *line[] = {"(", "netifcon", "(", "eth1", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_netifcon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_netifcon_nested_emptysecondlist_neg(CuTest *tc) {
	char *line[] = {"(", "netifcon", "eth1", 
			"(", "system_u", "object_r", "netif_t", "low", "high", ")",
			"(", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_netifcon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_netifcon_extra_nested_secondlist_neg(CuTest *tc) {
	char *line[] = {"(", "netifcon", "eth0", "extra",  
			"(", "system_u", "object_r", "netif_t", "low", "high", ")",
			"(", "foo", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_netifcon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_netifcon_nested_missingobjects_neg(CuTest *tc) {
	char *line[] = {"(", "netifcon", "eth1", 
			"(", "system_u", ")",
			"(", "system_u", "object_r", "netif_t", "low", "high", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_netifcon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_netifcon_nested_secondnested_missingobjects_neg(CuTest *tc) {
	char *line[] = {"(", "netifcon", "eth1", 
			"(", "system_u", "object_r", "netif_t", "low", "high", ")",
			"(", "system_u", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_netifcon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_netifcon_dbnull_neg(CuTest *tc) {
	char *line[] = {"(", "netifcon", "eth0", "if_default", "packet_default", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db = NULL;

        int rc = cil_gen_netifcon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_netifcon_currnull_neg(CuTest *tc) {
	char *line[] = {"(", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_netifcon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_netifcon_astnull_neg(CuTest *tc) {
	char *line[] = {"(", "netifcon", "eth0", "if_default", "packet_default", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node = NULL;

        struct cil_db *test_db;
        cil_db_init(&test_db);

        int rc = cil_gen_netifcon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_netifcon_ethmissing_neg(CuTest *tc) {
	char *line[] = {"(", "netifcon", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_netifcon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_netifcon_interfacemissing_neg(CuTest *tc) {
	char *line[] = {"(", "netifcon", "eth0", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_netifcon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_netifcon_packetmissing_neg(CuTest *tc) {
	char *line[] = {"(", "netifcon", "eth0", "if_default", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_netifcon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_macro_type(CuTest *tc) {
	char *line[] = {"(", "macro", "mm", "(", "(", "type", "a", ")", ")", "(", "type", "b", ")", "(", "call", "m", "(", "a", "b", ")", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_macro(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_macro_role(CuTest *tc) {
	char *line[] = {"(", "macro", "mm", "(", "(", "role", "a", ")", ")", "(", "role", "b", ")", "(", "call", "m", "(", "a", "b", ")", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_macro(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_macro_user(CuTest *tc) {
	char *line[] = {"(", "macro", "mm", "(", "(", "user", "a", ")", ")", "(", "user", "b", ")", "(", "call", "m", "(", "a", "b", ")", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_macro(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_macro_sensitivity(CuTest *tc) {
	char *line[] = {"(", "macro", "mm", "(", "(", "sensitivity", "a", ")", ")", "(", "sensitivity", "b", ")", "(", "call", "m", "(", "a", "b", ")", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_macro(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_macro_category(CuTest *tc) {
	char *line[] = {"(", "macro", "mm", "(", "(", "category", "a", ")", ")", "(", "category", "b", ")", "(", "call", "m", "(", "a", "b", ")", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_macro(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_macro_catset(CuTest *tc) {
	char *line[] = {"(", "macro", "mm", "(", "(", "categoryset", "a", ")", ")", "(", "categoryset", "b", ")", "(", "call", "m", "(", "a", "b", ")", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_macro(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_macro_level(CuTest *tc) {
	char *line[] = {"(", "macro", "mm", "(", "(", "level", "a", ")", ")", "(", "level", "b", ")", "(", "call", "m", "(", "a", "b", ")", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_macro(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_macro_class(CuTest *tc) {
	char *line[] = {"(", "macro", "mm", "(", "(", "class", "a", ")", ")", "(", "class", "b", ")", "(", "call", "m", "(", "a", "b", ")", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_macro(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_macro_duplicate(CuTest *tc) {
	char *line[] = {"(", "macro", "mm", "(", "(", "class", "a",")", "(", "class", "x", ")", ")", "(", "class", "b", ")", "(", "call", "m", "(", "a", "b", ")", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_macro(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_macro_duplicate_neg(CuTest *tc) {
	char *line[] = {"(", "macro", "mm", "(", "(", "class", "a",")", "(", "class", "a", ")", ")", "(", "class", "b", "(", "read," ")", ")", "(", "call", "m", "(", "a", "b", ")", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_macro(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_macro_unknown_neg(CuTest *tc) {
	char *line[] = {"(", "macro", "mm", "(", "(", "foo", "a", ")", ")", "(", "foo", "b", ")", "(", "call", "m", "(", "a", "b", ")", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_macro(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_macro_dbnull_neg(CuTest *tc) {
	char *line[] = {"(", "macro", "mm", "(", "(", "foo", "a", ")", ")", "(", "foo", "b", ")", "(", "call", "m", "(", "a", "b", ")", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db = NULL;

        int rc = cil_gen_macro(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_macro_currnull_neg(CuTest *tc) {
	char *line[] = {"(", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_macro(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_macro_astnull_neg(CuTest *tc) {
	char *line[] = {"(", "macro", "mm", "(", "(", "foo", "a", ")", ")", "(", "foo", "b", ")", "(", "call", "m", "(", "a", "b", ")", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node = NULL;

        int rc = cil_gen_macro(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_macro_unnamed_neg(CuTest *tc) {
	char *line[] = {"(", "macro", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_macro(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_macro_noparam_neg(CuTest *tc) {
	char *line[] = {"(", "macro", "mm", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_macro(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_macro_nosecondparam_neg(CuTest *tc) {
	char *line[] = {"(", "macro", "mm", "(", "(", "foo", "a", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_macro(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_macro_noparam_name_neg(CuTest *tc) {
	char *line[] = {"(", "macro", "mm", "(", "(", "type", ")", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_macro(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_macro_emptyparam_neg(CuTest *tc) {
	char *line[] = {"(", "macro", "mm", "(", "(", ")", ")", "(", "foo", "b", ")", "(", "call", "m", "(", "a", "b", ")", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_macro(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_call(CuTest *tc) {
	char *line[] = {"(", "call", "mm", "(", "foo", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_call(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_call_anon(CuTest *tc) {
	char *line[] = {"(", "call", "mm", "(", "(", "s0", "(", "c0", ")", ")", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_call(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_call_empty_call_neg(CuTest *tc) {
	char *line[] = {"(", "call", "mm", "(", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_call(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_call_dbnull_neg(CuTest *tc) {
	char *line[] = {"(", "call", "mm", "(", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db = NULL;

        int rc = cil_gen_call(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_call_currnull_neg(CuTest *tc) {
	char *line[] = {"(", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_call(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_call_astnull_neg(CuTest *tc) {
	char *line[] = {"(", "call", "mm", "(", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node = NULL;

        struct cil_db *test_db;
        cil_db_init(&test_db);

        int rc = cil_gen_call(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_call_name_inparens_neg(CuTest *tc) {
	char *line[] = {"(", "call", "(", "mm", ")", "(", "foo", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_call(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_call_noname_neg(CuTest *tc) {
	char *line[] = {"(", "call", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_call(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_call_noparams_neg(CuTest *tc) {
	char *line[] = {"(", "call", "mm", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_call(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_optional(CuTest *tc) {
	char *line[] = {"(", "optional", "opt", "(", "allow", "foo", "bar", "baz", "file", "(", "read", ")", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_optional(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_optional_dbnull_neg(CuTest *tc) {
	char *line[] = {"(", "optional", "opt", "(", "allow", "foo", "bar", "baz", "file", "(", "read", ")", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db = NULL;

        int rc = cil_gen_optional(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_optional_currnull_neg(CuTest *tc) {
	char *line[] = {"(", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_optional(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_optional_astnull_neg(CuTest *tc) {
	char *line[] = {"(", "optional", "opt", "(", "allow", "foo", "bar", "baz", "file", "(", "read", ")", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node = NULL;

        struct cil_db *test_db;
        cil_db_init(&test_db);

        int rc = cil_gen_optional(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_optional_unnamed_neg(CuTest *tc) {
	char *line[] = {"(", "optional", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_optional(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_optional_nameinparens_neg(CuTest *tc) {
	char *line[] = {"(", "optional", "(", "opt", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        int rc = cil_gen_optional(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
        CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

/*
	cil_build_ast test cases
*/

void test_cil_build_ast(CuTest *tc) {
	char *line[] = {"(", "type", "foo", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_build_ast_dbnull_neg(CuTest *tc) {
	char *line[] = {"(", "test", "\"qstring\"", ")", ";comment", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *null_db = NULL;

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(null_db, test_tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_build_ast_astnull_neg(CuTest *tc) {
	char *line[] = {"(", "test", "\"qstring\"", ")", ";comment", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_db->ast->root = NULL;

	int rc = cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_build_ast_suberr_neg(CuTest *tc) {
	char *line[] = {"(", "block", "test", "(", "block", "(", "type", "log", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_build_ast_treenull_neg(CuTest *tc) {
	char *line[] = {"(", "allow", "test", "foo", "bar", "(", "read", "write", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	test_tree->root = NULL;

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_db->ast->root = NULL;

	int rc = cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_build_ast_node_helper_block(CuTest *tc) {
	char *line[] = {"(", "block", "test", "(", "type", "log", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB; 

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertIntEquals(tc, 0, finished);
}

void test_cil_build_ast_node_helper_block_neg(CuTest *tc) {
	char *line[] = {"(", "block", "(", "type", "log", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB; 

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
	CuAssertIntEquals(tc, 0, finished);

}

void test_cil_build_ast_node_helper_class(CuTest *tc) {
	char *line[] = {"(", "class", "file", "(", "read", "write", "open", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB; 

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertIntEquals(tc, 1, finished);
}

void test_cil_build_ast_node_helper_class_neg(CuTest *tc) {
	char *line[] = {"(", "class", "(", "read", "write", "open", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB; 

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
	CuAssertIntEquals(tc, 0, finished);
}

void test_cil_build_ast_node_helper_common(CuTest *tc) {
	char *line[] = {"(", "common", "test", "(", "read", "write", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB; 

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertIntEquals(tc, 1, finished);
}

void test_cil_build_ast_node_helper_common_neg(CuTest *tc) {
	char *line[] = {"(", "common", "(", "read", "write", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB; 

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
	CuAssertIntEquals(tc, 0, finished);
}

void test_cil_build_ast_node_helper_sidcontext(CuTest *tc) {
	char *line[] = {"(", "sidcontext", "test", "(", "blah", "blah", "blah", "(", "s0", "(", "c0", ")", ")", "(", "s0", "(", "c0", ")", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB; 

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertIntEquals(tc, 1, finished);
}

void test_cil_build_ast_node_helper_sidcontext_neg(CuTest *tc) {
	char *line[] = {"(", "sidcontext", "(", "blah", "blah", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB; 

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
	CuAssertIntEquals(tc, 0, finished);
}

void test_cil_build_ast_node_helper_user(CuTest *tc) {
	char *line[] = {"(", "user", "jimmypage", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB; 

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertIntEquals(tc, 0, finished);
}

void test_cil_build_ast_node_helper_user_neg(CuTest *tc) {
	char *line[] = {"(", "user", "foo", "bar", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB; 

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
	CuAssertIntEquals(tc, 0, finished);
}

void test_cil_build_ast_node_helper_type(CuTest *tc) {
	char *line[] = {"(", "type", "test", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB; 

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertIntEquals(tc, 0, finished);
}

void test_cil_build_ast_node_helper_type_neg(CuTest *tc) {
	char *line[] = {"(", "type", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB; 

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
	CuAssertIntEquals(tc, 0, finished);
}

void test_cil_build_ast_node_helper_type_attribute(CuTest *tc) {
	char *line[] = {"(", "attribute", "test", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB; 

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertIntEquals(tc, 0, finished);
}

void test_cil_build_ast_node_helper_type_attribute_neg(CuTest *tc) {
	char *line[] = {"(", "attribute", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB; 

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
	CuAssertIntEquals(tc, 0, finished);
}

void test_cil_build_ast_node_helper_typeattr(CuTest *tc) {
	char *line[] = {"(", "typeattribute", "foo", "bar", ")", NULL};
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);
	
	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB; 

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertIntEquals(tc, 0, finished);
}

void test_cil_build_ast_node_helper_typeattr_neg(CuTest *tc) {
	char *line[] = {"(", "typeattribute", "bar", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);
	
	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB; 

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
	CuAssertIntEquals(tc, 0, finished);
}	

void test_cil_build_ast_node_helper_boolif(CuTest *tc) {
	char *line[] = {"(", "booleanif", "(", "&&", "foo", "bar", ")",
			"(", "allow", "foo", "bar", "read", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB; 

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertIntEquals(tc, 0, finished);
}

void test_cil_build_ast_node_helper_boolif_neg(CuTest *tc) {
	char *line[] = {"(", "booleanif", "(", "*&", "foo", "bar", ")",
			"(", "allow", "foo", "bar", "read", ")", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);
	
	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB; 

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
	CuAssertIntEquals(tc, 0, finished);
}	

void test_cil_build_ast_node_helper_tunif(CuTest *tc) {
	char *line[] = {"(", "tunableif", "(", "&&", "foo", "bar", ")",
			"(", "allow", "foo", "bar", "read", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB; 

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertIntEquals(tc, 0, finished);
}

void test_cil_build_ast_node_helper_tunif_neg(CuTest *tc) {
	char *line[] = {"(", "tunableif", "(", "*&", "foo", "bar", ")",
			"(", "allow", "foo", "bar", "read", ")", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);
	
	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB; 

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
	CuAssertIntEquals(tc, 0, finished);
}	

void test_cil_build_ast_node_helper_typealias(CuTest *tc) {
	char *line[] = {"(", "typealias", ".test.type", "type_t", ")", "(", "type", "test", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB; 

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertIntEquals(tc, 0, finished);
}

void test_cil_build_ast_node_helper_typealias_notype_neg(CuTest *tc) {
	char *line[] = {"(", "typealias", ".test.type", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB; 

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
	CuAssertIntEquals(tc, 0, finished);
}

void test_cil_build_ast_node_helper_role(CuTest *tc) {
	char *line[] = {"(", "role", "test_r", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB; 

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertIntEquals(tc, 0, finished);
}

void test_cil_build_ast_node_helper_role_neg(CuTest *tc) {
	char *line[] = {"(", "role", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB; 

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
	CuAssertIntEquals(tc, 0, finished);
}

void test_cil_build_ast_node_helper_roletrans(CuTest *tc) {
	char *line[] = {"(", "roletransition", "foo_r", "bar_t", "foobar_r", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB; 

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertIntEquals(tc, 0, finished);
}

void test_cil_build_ast_node_helper_roletrans_neg(CuTest *tc) {
	char *line[] = {"(", "roletransition", "foo_r", "bar_t", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB; 

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
	CuAssertIntEquals(tc, 0, finished);
}

void test_cil_build_ast_node_helper_roleallow(CuTest *tc) {
        char *line[] = {"(", "roleallow", "staff_r", "sysadm_r", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB; 

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertIntEquals(tc, 0, finished);
}

void test_cil_build_ast_node_helper_roleallow_neg(CuTest *tc) {
        char *line[] = {"(", "roleallow", "staff_r", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB; 

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
	CuAssertIntEquals(tc, 0, finished);
}

void test_cil_build_ast_node_helper_avrule_allow(CuTest *tc) {
	char *line[] = {"(", "allow", "test", "foo", "bar", "(", "read", "write", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB; 

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertIntEquals(tc, 1, finished);
}

void test_cil_build_ast_node_helper_avrule_allow_neg(CuTest *tc) {
	char *line[] = {"(", "allow", "foo", "bar", "(", "read", "write", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB; 

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
	CuAssertIntEquals(tc, 0, finished);
}

void test_cil_build_ast_node_helper_avrule_auditallow(CuTest *tc) {
	char *line[] = {"(", "auditallow", "test", "foo", "bar", "(", "read", "write", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB; 

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertIntEquals(tc, 1, finished);
}

void test_cil_build_ast_node_helper_avrule_auditallow_neg(CuTest *tc) {
	char *line[] = {"(", "auditallow", "foo", "bar", "(", "read", "write", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB; 

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
	CuAssertIntEquals(tc, 0, finished);
}

void test_cil_build_ast_node_helper_avrule_dontaudit(CuTest *tc) {
	char *line[] = {"(", "dontaudit", "test", "foo", "bar", "(", "read", "write", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB; 

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertIntEquals(tc, 1, finished);
}

void test_cil_build_ast_node_helper_avrule_dontaudit_neg(CuTest *tc) {
	char *line[] = {"(", "dontaudit", "foo", "bar", "(", "read", "write", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB; 

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
	CuAssertIntEquals(tc, 0, finished);
}

void test_cil_build_ast_node_helper_avrule_neverallow(CuTest *tc) {
	char *line[] = {"(", "neverallow", "test", "foo", "bar", "(", "read", "write", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB; 

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertIntEquals(tc, 1, finished);
}

void test_cil_build_ast_node_helper_avrule_neverallow_neg(CuTest *tc) {
	char *line[] = {"(", "neverallow", "foo", "bar", "(", "read", "write", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB; 

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
	CuAssertIntEquals(tc, 0, finished);
}

void test_cil_build_ast_node_helper_type_rule_transition(CuTest *tc) {
	char *line[] = {"(", "typetransition", "foo", "bar", "file", "foobar", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);	
	
	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB; 

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertIntEquals(tc, 0, finished);
}

void test_cil_build_ast_node_helper_type_rule_transition_neg(CuTest *tc) {
	char *line[] = {"(", "typetransition", "foo", "bar", "file", "foobar", "extra",  ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);	
	
	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB; 

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
	CuAssertIntEquals(tc, 0, finished);
}

void test_cil_build_ast_node_helper_type_rule_change(CuTest *tc) {
	char *line[] = {"(", "typechange", "foo", "bar", "file", "foobar", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);	
	
	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB; 

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertIntEquals(tc, 0, finished);
}

void test_cil_build_ast_node_helper_type_rule_change_neg(CuTest *tc) {
	char *line[] = {"(", "typechange", "foo", "bar", "file", "foobar", "extra",  ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);	
	
	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB; 

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
	CuAssertIntEquals(tc, 0, finished);
}

void test_cil_build_ast_node_helper_type_rule_member(CuTest *tc) {
	char *line[] = {"(", "typemember", "foo", "bar", "file", "foobar", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);	
	
	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB; 

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertIntEquals(tc, 0, finished);
}

void test_cil_build_ast_node_helper_type_rule_member_neg(CuTest *tc) {
	char *line[] = {"(", "typemember", "foo", "bar", "file", "foobar", "extra",  ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);	
	
	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB; 

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
	CuAssertIntEquals(tc, 0, finished);
}

void test_cil_build_ast_node_helper_bool(CuTest *tc) {
	char *line[] = {"(", "bool", "foo", "true", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB; 

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertIntEquals(tc, 0, finished);
}

void test_cil_build_ast_node_helper_bool_neg(CuTest *tc) {
	char *line[] = {"(", "bool", "foo", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB; 

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
	CuAssertIntEquals(tc, 0, finished);
}

void test_cil_build_ast_node_helper_bool_tunable(CuTest *tc) {
	char *line[] = {"(", "tunable", "foo", "true", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB; 

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertIntEquals(tc, 0, finished);
}

void test_cil_build_ast_node_helper_bool_tunable_neg(CuTest *tc) {
	char *line[] = {"(", "tunable", "foo", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB; 

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
	CuAssertIntEquals(tc, 0, finished);
}

void test_cil_build_ast_node_helper_sensitivity(CuTest *tc) {
	char *line[] = {"(", "sensitivity", "s0", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB; 

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertIntEquals(tc, 0, finished);
}

void test_cil_build_ast_node_helper_sensitivity_neg(CuTest *tc) {
	char *line[] = {"(", "sensitivity", "s0", "extra", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB; 

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
	CuAssertIntEquals(tc, 0, finished);
}

void test_cil_build_ast_node_helper_sensalias(CuTest *tc) {
	char *line[] = {"(", "sensitivityalias", "s0", "alias", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB; 

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertIntEquals(tc, 0, finished);
}

void test_cil_build_ast_node_helper_sensalias_neg(CuTest *tc) {
	char *line[] = {"(", "sensitivityalias", "s0", "alias", "extra", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB; 

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
	CuAssertIntEquals(tc, 0, finished);
}

void test_cil_build_ast_node_helper_catset(CuTest *tc) {
	char *line[] = {"(", "categoryset", "somecats", "(", "c0", "c1", "c2", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB;

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertIntEquals(tc, 1, finished); 
}

void test_cil_build_ast_node_helper_catset_neg(CuTest *tc) {
	char *line[] = {"(", "categoryset", "somecats", "(", "c0", "c1", "c2", ")", "extra", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB;

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
	CuAssertIntEquals(tc, 0, finished); 
}

void test_cil_build_ast_node_helper_catorder(CuTest *tc) {
	char *line[] = {"(", "categoryorder", "(", "c0", "c1", "c2", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB;

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertIntEquals(tc, 1, finished); 
}

void test_cil_build_ast_node_helper_catorder_neg(CuTest *tc) {
	char *line[] = {"(", "categoryorder", "c0", "c1", "c2", "extra", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB;

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
	CuAssertIntEquals(tc, 0, finished); 
}

void test_cil_build_ast_node_helper_catalias(CuTest *tc) {
	char *line[] = {"(", "categoryalias", "c0", "red", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB;

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertIntEquals(tc, 0, finished);
}

void test_cil_build_ast_node_helper_catalias_neg(CuTest *tc) {
	char *line[] = {"(", "categoryalias", "c0", "red", "extra", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db->ast->root;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = test_db;
	other->head->next->flavor = CIL_DB;

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, other);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
	CuAssertIntEquals(tc, 0, finished);
}

void test_cil_build_ast_node_helper_roletype(CuTest *tc) {
	char *line[] = {"(", "roletype", "admin_r", "admin_t", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *cil_l;
	cil_list_init(&cil_l);

	uint32_t finished = 0;

	cil_list_item_init(&cil_l->head);
	cil_list_item_init(&cil_l->head->next);
	cil_l->head->data = test_db->ast->root;
	cil_l->head->flavor = CIL_AST_NODE;
	cil_l->head->next->flavor = CIL_DB;
	cil_l->head->next->data = test_db;
	
	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, cil_l);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_build_ast_node_helper_roletype_neg(CuTest *tc) {
	char *line[] = {"(", "roletype", "(", "admin_r", ")", "admin_t", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *cil_l;
	cil_list_init(&cil_l);

	uint32_t finished = 0;

	cil_list_item_init(&cil_l->head);
	cil_list_item_init(&cil_l->head->next);
	cil_l->head->data = test_db->ast->root;
	cil_l->head->flavor = CIL_AST_NODE;
	cil_l->head->next->flavor = CIL_DB;
	cil_l->head->next->data = test_db;
	
	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, cil_l);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_build_ast_node_helper_userrole(CuTest *tc) {
	char *line[] = {"(", "userrole", "staff_u", "staff_r", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *cil_l;
	cil_list_init(&cil_l);

	uint32_t finished = 0;

	cil_list_item_init(&cil_l->head);
	cil_list_item_init(&cil_l->head->next);
	cil_l->head->data = test_db->ast->root;
	cil_l->head->flavor = CIL_AST_NODE;
	cil_l->head->next->flavor = CIL_DB;
	cil_l->head->next->data = test_db;

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, cil_l);
	CuAssertIntEquals(tc, 0, finished);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_build_ast_node_helper_userrole_neg(CuTest *tc) {
	char *line[] = {"(", "userrole", "staff_u", "(", "staff_r", ")", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *cil_l;
	cil_list_init(&cil_l);

	uint32_t finished = 0;

	cil_list_item_init(&cil_l->head);
	cil_list_item_init(&cil_l->head->next);
	cil_l->head->data = test_db->ast->root;
	cil_l->head->flavor = CIL_AST_NODE;
	cil_l->head->next->flavor = CIL_DB;
	cil_l->head->next->data = test_db;
	
	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, cil_l);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_build_ast_node_helper_gen_classcommon(CuTest *tc) {
	char *line[] = {"(", "classcommon", "foo", "(", "staff_r", ")", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *cil_l;
	cil_list_init(&cil_l);

	uint32_t finished = 0;

	cil_list_item_init(&cil_l->head);
	cil_list_item_init(&cil_l->head->next);
	cil_l->head->data = test_db->ast->root;
	cil_l->head->flavor = CIL_AST_NODE;
	cil_l->head->next->flavor = CIL_DB;
	cil_l->head->next->data = test_db;
	
	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, cil_l);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_build_ast_node_helper_gen_classcommon_neg(CuTest *tc) {
	char *line[] = {"(", "classcommon", "staff_u", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *cil_l;
	cil_list_init(&cil_l);

	uint32_t finished = 0;

	cil_list_item_init(&cil_l->head);
	cil_list_item_init(&cil_l->head->next);
	cil_l->head->data = test_db->ast->root;
	cil_l->head->flavor = CIL_AST_NODE;
	cil_l->head->next->flavor = CIL_DB;
	cil_l->head->next->data = test_db;
	
	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, cil_l);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_build_ast_node_helper_gen_dominance(CuTest *tc) {
	char *line[] = {"(", "sensitivity", "s0", ")",
                        "(", "sensitivity", "s1", ")",
                        "(", "sensitivity", "s2", ")",
                        "(", "dominance", "(", "s0", "s1", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *cil_l;
	cil_list_init(&cil_l);

	uint32_t finished = 0;

	cil_list_item_init(&cil_l->head);
	cil_list_item_init(&cil_l->head->next);
	cil_l->head->data = test_db->ast->root;
	cil_l->head->flavor = CIL_AST_NODE;
	cil_l->head->next->flavor = CIL_DB;
	cil_l->head->next->data = test_db;
	
	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->next->next->next->cl_head, &finished, cil_l);
	CuAssertIntEquals(tc, finished, 1);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_build_ast_node_helper_gen_dominance_neg(CuTest *tc) {
	char *line[] = {"(", "sensitivity", "s0", ")",
                        "(", "sensitivity", "s1", ")",
                        "(", "sensitivity", "s2", ")",
                        "(", "dominance", "(", ")", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *cil_l;
	cil_list_init(&cil_l);

	uint32_t finished = 0;

	cil_list_item_init(&cil_l->head);
	cil_list_item_init(&cil_l->head->next);
	cil_l->head->data = test_db->ast->root;
	cil_l->head->flavor = CIL_AST_NODE;
	cil_l->head->next->flavor = CIL_DB;
	cil_l->head->next->data = test_db;
	
	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->next->next->next->cl_head, &finished, cil_l);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_build_ast_node_helper_gen_senscat(CuTest *tc) {
	char *line[] = {"(", "sensitivity", "s0", ")",
                        "(", "sensitivity", "s1", ")",
                        "(", "dominance", "(", "s0", "s1", ")", ")",
			"(", "category", "c0", ")",
			"(", "category", "c255", ")",
			"(", "categoryorder", "(", "c0", "c255", ")", ")",
			"(", "sensitivitycategory", "s1", "(", "c0", "c255", ")", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *cil_l;
	cil_list_init(&cil_l);

	uint32_t finished = 0;

	cil_list_item_init(&cil_l->head);
	cil_list_item_init(&cil_l->head->next);
	cil_l->head->data = test_db->ast->root;
	cil_l->head->flavor = CIL_AST_NODE;
	cil_l->head->next->flavor = CIL_DB;
	cil_l->head->next->data = test_db;
	
	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->next->next->next->next->next->next->cl_head, &finished, cil_l);
	CuAssertIntEquals(tc, finished, 1);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_build_ast_node_helper_gen_senscat_neg(CuTest *tc) {
	char *line[] = {"(", "sensitivity", "s0", ")",
                        "(", "sensitivity", "s1", ")",
                        "(", "dominance", "(", "s0", "s1", ")", ")",
			"(", "category", "c0", ")",
			"(", "category", "c255", ")",
			"(", "categoryorder", "(", "c0", "c255", ")", ")",
			"(", "sensitivitycategory", "s1", "c0", "c255", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *cil_l;
	cil_list_init(&cil_l);

	uint32_t finished = 0;

	cil_list_item_init(&cil_l->head);
	cil_list_item_init(&cil_l->head->next);
	cil_l->head->data = test_db->ast->root;
	cil_l->head->flavor = CIL_AST_NODE;
	cil_l->head->next->flavor = CIL_DB;
	cil_l->head->next->data = test_db;
	
	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->next->next->next->next->next->next->cl_head, &finished, cil_l);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_build_ast_node_helper_gen_level(CuTest *tc) {
	char *line[] = {"(", "sensitivity", "s0", ")",
			"(", "category", "c1", ")",
			"(", "level", "low", "s0", "(", "c1", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *cil_l;
	cil_list_init(&cil_l);

	uint32_t finished = 0;

	cil_list_item_init(&cil_l->head);
	cil_list_item_init(&cil_l->head->next);
	cil_l->head->data = test_db->ast->root;
	cil_l->head->flavor = CIL_AST_NODE;
	cil_l->head->next->flavor = CIL_DB;
	cil_l->head->next->data = test_db;
	
	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->next->next->cl_head, &finished, cil_l);
	CuAssertIntEquals(tc, finished, 1);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_build_ast_node_helper_gen_level_neg(CuTest *tc) {
	char *line[] = {"(", "sensitivity", "s0", ")",
			"(", "category", "c1", ")",
			"(", "level", "low", "s0", "(", ")", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *cil_l;
	cil_list_init(&cil_l);

	uint32_t finished = 0;

	cil_list_item_init(&cil_l->head);
	cil_list_item_init(&cil_l->head->next);
	cil_l->head->data = test_db->ast->root;
	cil_l->head->flavor = CIL_AST_NODE;
	cil_l->head->next->flavor = CIL_DB;
	cil_l->head->next->data = test_db;
	
	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->next->next->cl_head, &finished, cil_l);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_build_ast_node_helper_gen_constrain(CuTest *tc) {
	char *line[] = {"(", "mlsconstrain", "(", "file", "dir", ")", "(", "create", "relabelto", ")", "(", "eq", "12", "h2", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *cil_l;
	cil_list_init(&cil_l);

	uint32_t finished = 0;

	cil_list_item_init(&cil_l->head);
	cil_list_item_init(&cil_l->head->next);
	cil_l->head->data = test_db->ast->root;
	cil_l->head->flavor = CIL_AST_NODE;
	cil_l->head->next->flavor = CIL_DB;
	cil_l->head->next->data = test_db;
	
	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, cil_l);
	CuAssertIntEquals(tc, finished, 1);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_build_ast_node_helper_gen_constrain_neg(CuTest *tc) {
	char *line[] = {"(", "mlsconstrain", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *cil_l;
	cil_list_init(&cil_l);

	uint32_t finished = 0;

	cil_list_item_init(&cil_l->head);
	cil_list_item_init(&cil_l->head->next);
	cil_l->head->data = test_db->ast->root;
	cil_l->head->flavor = CIL_AST_NODE;
	cil_l->head->next->flavor = CIL_DB;
	cil_l->head->next->data = test_db;
	
	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, cil_l);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_build_ast_node_helper_gen_context(CuTest *tc) {
	char *line[] = {"(", "context", "localhost_node_label", "(", "system_u", "object_r", "node_lo_t", "low", "high", ")", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *cil_l;
	cil_list_init(&cil_l);

	uint32_t finished = 0;

	cil_list_item_init(&cil_l->head);
	cil_list_item_init(&cil_l->head->next);
	cil_l->head->data = test_db->ast->root;
	cil_l->head->flavor = CIL_AST_NODE;
	cil_l->head->next->flavor = CIL_DB;
	cil_l->head->next->data = test_db;
	
	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, cil_l);
	CuAssertIntEquals(tc, finished, 1);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_build_ast_node_helper_gen_context_neg(CuTest *tc) {
	char *line[] = {"(", "context", "localhost_node_label", "(", "system_u", "object_r", ")", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *cil_l;
	cil_list_init(&cil_l);

	uint32_t finished = 0;

	cil_list_item_init(&cil_l->head);
	cil_list_item_init(&cil_l->head->next);
	cil_l->head->data = test_db->ast->root;
	cil_l->head->flavor = CIL_AST_NODE;
	cil_l->head->next->flavor = CIL_DB;
	cil_l->head->next->data = test_db;

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, cil_l);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_build_ast_node_helper_gen_filecon(CuTest *tc) {
	char *line[] = {"(", "filecon", "root", "path", "file", "context", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *cil_l;
	cil_list_init(&cil_l);

	uint32_t finished = 0;

	cil_list_item_init(&cil_l->head);
	cil_list_item_init(&cil_l->head->next);
	cil_l->head->data = test_db->ast->root;
	cil_l->head->flavor = CIL_AST_NODE;
	cil_l->head->next->flavor = CIL_DB;
	cil_l->head->next->data = test_db;
	
	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, cil_l);
	CuAssertIntEquals(tc, finished, 1);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_build_ast_node_helper_gen_filecon_neg(CuTest *tc) {
	char *line[] = {"(", "filecon", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *cil_l;
	cil_list_init(&cil_l);

	uint32_t finished = 0;

	cil_list_item_init(&cil_l->head);
	cil_list_item_init(&cil_l->head->next);
	cil_l->head->data = test_db->ast->root;
	cil_l->head->flavor = CIL_AST_NODE;
	cil_l->head->next->flavor = CIL_DB;
	cil_l->head->next->data = test_db;

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, cil_l);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_build_ast_node_helper_gen_portcon(CuTest *tc) {
	char *line[] = {"(", "portcon", "type", "25", "con", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *cil_l;
	cil_list_init(&cil_l);

	uint32_t finished = 0;

	cil_list_item_init(&cil_l->head);
	cil_list_item_init(&cil_l->head->next);
	cil_l->head->data = test_db->ast->root;
	cil_l->head->flavor = CIL_AST_NODE;
	cil_l->head->next->flavor = CIL_DB;
	cil_l->head->next->data = test_db;
	
	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, cil_l);
	CuAssertIntEquals(tc, finished, 1);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_build_ast_node_helper_gen_portcon_neg(CuTest *tc) {
	char *line[] = {"(", "portcon", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *cil_l;
	cil_list_init(&cil_l);

	uint32_t finished = 0;

	cil_list_item_init(&cil_l->head);
	cil_list_item_init(&cil_l->head->next);
	cil_l->head->data = test_db->ast->root;
	cil_l->head->flavor = CIL_AST_NODE;
	cil_l->head->next->flavor = CIL_DB;
	cil_l->head->next->data = test_db;

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, cil_l);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_build_ast_node_helper_gen_nodecon(CuTest *tc) {
	char *line[] = {"(", "nodecon", "ipaddr", "ipaddr", "con", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *cil_l;
	cil_list_init(&cil_l);

	uint32_t finished = 0;

	cil_list_item_init(&cil_l->head);
	cil_list_item_init(&cil_l->head->next);
	cil_l->head->data = test_db->ast->root;
	cil_l->head->flavor = CIL_AST_NODE;
	cil_l->head->next->flavor = CIL_DB;
	cil_l->head->next->data = test_db;
	
	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, cil_l);
	CuAssertIntEquals(tc, finished, 1);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_build_ast_node_helper_gen_nodecon_neg(CuTest *tc) {
	char *line[] = {"(", "nodecon", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *cil_l;
	cil_list_init(&cil_l);

	uint32_t finished = 0;

	cil_list_item_init(&cil_l->head);
	cil_list_item_init(&cil_l->head->next);
	cil_l->head->data = test_db->ast->root;
	cil_l->head->flavor = CIL_AST_NODE;
	cil_l->head->next->flavor = CIL_DB;
	cil_l->head->next->data = test_db;

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, cil_l);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_build_ast_node_helper_gen_genfscon(CuTest *tc) {
	char *line[] = {"(", "genfscon", "type", "path", "con", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *cil_l;
	cil_list_init(&cil_l);

	uint32_t finished = 0;

	cil_list_item_init(&cil_l->head);
	cil_list_item_init(&cil_l->head->next);
	cil_l->head->data = test_db->ast->root;
	cil_l->head->flavor = CIL_AST_NODE;
	cil_l->head->next->flavor = CIL_DB;
	cil_l->head->next->data = test_db;
	
	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, cil_l);
	CuAssertIntEquals(tc, finished, 1);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_build_ast_node_helper_gen_genfscon_neg(CuTest *tc) {
	char *line[] = {"(", "genfscon", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *cil_l;
	cil_list_init(&cil_l);

	uint32_t finished = 0;

	cil_list_item_init(&cil_l->head);
	cil_list_item_init(&cil_l->head->next);
	cil_l->head->data = test_db->ast->root;
	cil_l->head->flavor = CIL_AST_NODE;
	cil_l->head->next->flavor = CIL_DB;
	cil_l->head->next->data = test_db;

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, cil_l);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_build_ast_node_helper_gen_netifcon(CuTest *tc) {
	char *line[] = {"(", "netifcon", "eth1", 
			"(", "system_u", "object_r", "netif_t", "low", "high", ")",
			"(", "system_u", "object_r", "netif_t", "low", "high", ")", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *cil_l;
	cil_list_init(&cil_l);

	uint32_t finished = 0;

	cil_list_item_init(&cil_l->head);
	cil_list_item_init(&cil_l->head->next);
	cil_l->head->data = test_db->ast->root;
	cil_l->head->flavor = CIL_AST_NODE;
	cil_l->head->next->flavor = CIL_DB;
	cil_l->head->next->data = test_db;
	
	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, cil_l);
	CuAssertIntEquals(tc, finished, 1);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_build_ast_node_helper_gen_netifcon_neg(CuTest *tc) {
	char *line[] = {"(", "netifcon", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *cil_l;
	cil_list_init(&cil_l);

	uint32_t finished = 0;

	cil_list_item_init(&cil_l->head);
	cil_list_item_init(&cil_l->head->next);
	cil_l->head->data = test_db->ast->root;
	cil_l->head->flavor = CIL_AST_NODE;
	cil_l->head->next->flavor = CIL_DB;
	cil_l->head->next->data = test_db;

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, cil_l);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_build_ast_node_helper_gen_macro(CuTest *tc) {
	char *line[] = {"(", "macro", "mm", "(", "(", "type", "a", ")", ")", "(", "type", "b", ")", "(", "call", "m", "(", "a", "b", ")", ")", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *cil_l;
	cil_list_init(&cil_l);

	uint32_t finished = 0;

	cil_list_item_init(&cil_l->head);
	cil_list_item_init(&cil_l->head->next);
	cil_l->head->data = test_db->ast->root;
	cil_l->head->flavor = CIL_AST_NODE;
	cil_l->head->next->flavor = CIL_DB;
	cil_l->head->next->data = test_db;
	
	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, cil_l);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_build_ast_node_helper_gen_macro_neg(CuTest *tc) {
	char *line[] = {"(", "macro", "mm", "(", "(", ")", ")", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *cil_l;
	cil_list_init(&cil_l);

	uint32_t finished = 0;

	cil_list_item_init(&cil_l->head);
	cil_list_item_init(&cil_l->head->next);
	cil_l->head->data = test_db->ast->root;
	cil_l->head->flavor = CIL_AST_NODE;
	cil_l->head->next->flavor = CIL_DB;
	cil_l->head->next->data = test_db;

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, cil_l);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_build_ast_node_helper_gen_optional(CuTest *tc) {
	char *line[] = {"(", "optional", "opt", "(", "allow", "foo", "bar", "baz", "file", "(", "read", ")", ")", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *cil_l;
	cil_list_init(&cil_l);

	uint32_t finished = 0;

	cil_list_item_init(&cil_l->head);
	cil_list_item_init(&cil_l->head->next);
	cil_l->head->data = test_db->ast->root;
	cil_l->head->flavor = CIL_AST_NODE;
	cil_l->head->next->flavor = CIL_DB;
	cil_l->head->next->data = test_db;
	
	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, cil_l);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_build_ast_node_helper_gen_optional_neg(CuTest *tc) {
	char *line[] = {"(", "optional", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *cil_l;
	cil_list_init(&cil_l);

	uint32_t finished = 0;

	cil_list_item_init(&cil_l->head);
	cil_list_item_init(&cil_l->head->next);
	cil_l->head->data = test_db->ast->root;
	cil_l->head->flavor = CIL_AST_NODE;
	cil_l->head->next->flavor = CIL_DB;
	cil_l->head->next->data = test_db;

	int rc = __cil_build_ast_node_helper(test_tree->root->cl_head->cl_head, &finished, cil_l);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

/*
	char *line[] = {"(", "sensitivity", "s0", ")",
                        "(", "sensitivity", "s1", ")",
                        "(", "dominance", "(", "s0", "s1", ")", ")",
			"(", "category", "c0", ")",
			"(", "category", "c255", ")",
			"(", "categoryorder", "(", "c0", "c255", ")", ")",
			"(", "sensitivitycategory", "s1", "(", "c0", "c255", ")", ")", NULL};*/
