#include <sepol/policydb/policydb.h>

#include "CuTest.h"
#include "CilTest.h"
#include "test_cil_build_ast.h"

#include "../../src/cil_build_ast.h"

#include "../../src/cil_tree.h"

// First seen in cil_gen_common
void test_cil_parse_to_list(CuTest *tc) {
	char *line[] = {"(", "allow", "test", "foo", "bar", "(", "read", "write", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_current;
	test_current = tree->root->cl_head->cl_head;

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
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_current;
	test_current = tree->root->cl_head->cl_head;

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
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_current;
	test_current = tree->root->cl_head->cl_head;

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
	struct cil_tree *tree;
	struct cil_list *cil_l;
	struct cil_list *sub_list = NULL;

	gen_test_tree(&tree, line);
	cil_list_init(&cil_l);

	int rc = cil_set_to_list(tree->root->cl_head, cil_l);
	sub_list = (struct cil_list *)cil_l->head->next->next->data;

	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertStrEquals(tc, "foo1", (char*)cil_l->head->data);
	CuAssertStrEquals(tc, "foo2", (char*)cil_l->head->next->data);
	CuAssertStrEquals(tc, "foo3", (char*)sub_list->head->data);
}

void test_cil_set_to_list_tree_node_null_neg(CuTest *tc) {
	struct cil_list *cil_l = NULL;
	int rc = cil_set_to_list(NULL, cil_l);

	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_set_to_list_cl_head_null_neg(CuTest *tc) {
	struct cil_list *cil_l;
	struct cil_tree *tree = NULL;
	char *line[] = {"(", "foo", "bar", ")", NULL};

	cil_list_init(&cil_l);
	gen_test_tree(&tree, line);
	tree->root->cl_head = NULL;

	int rc = cil_set_to_list(tree->root, cil_l);

	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_set_to_list_listnull_neg(CuTest *tc) {
	char *line[] = {"(", "foo1", "foo2", "foo3", ")", NULL};
	struct cil_tree *tree = NULL;
	gen_test_tree(&tree, line);

	int rc = cil_set_to_list(tree->root, NULL);

	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_block(CuTest *tc) {
	char *line[] = {"(", "block", "a", "(", "type", "log", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_block(test_db, tree->root->cl_head->cl_head, test_ast_node, 0, 0, NULL);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, test_ast_node->data);
	CuAssertIntEquals(tc, ((struct cil_block*)test_ast_node->data)->is_abstract, 0);
	CuAssertIntEquals(tc, ((struct cil_block*)test_ast_node->data)->is_optional, 0);
	CuAssertPtrEquals(tc, ((struct cil_block*)test_ast_node->data)->condition, NULL);
	CuAssertIntEquals(tc, test_ast_node->flavor, CIL_BLOCK);
}

void test_cil_gen_block_noname_neg(CuTest *tc) {
	char *line[] = {"(", "block", "(", "type", "log", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_block(test_db, tree->root->cl_head->cl_head, test_ast_node, 0, 0, NULL);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_block_dbnull_neg(CuTest *tc) {
	char *line[] = {"(", "block", "foo", "(", "type", "log", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db = NULL;

	int rc = cil_gen_block(test_db, tree->root->cl_head->cl_head, test_ast_node, 0, 0, NULL);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_block_treenull_neg(CuTest *tc) {
	char *line[] = {"(", "block", "foo", "(", "type", "log", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	tree->root->cl_head->cl_head = NULL;

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_block(test_db, tree->root->cl_head->cl_head, test_ast_node, 0, 0, NULL);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_block_nodenull_neg(CuTest *tc) {
	char *line[] = {"(", "block", "foo", "(", "type", "log", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);
	
	struct cil_tree_node *test_ast_node = NULL;

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_gen_block(test_db, tree->root->cl_head->cl_head, test_ast_node, 0, 0, NULL);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_block_nodeparentnull_neg(CuTest *tc) {
	char *line[] = {"(", "block", "foo", "(", "type", "log", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = NULL;
	test_ast_node->line = 1;

	int rc = cil_gen_block(test_db, tree->root->cl_head->cl_head, test_ast_node, 0, 0, NULL);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_destroy_block(CuTest *tc) {
	char *line[] = {"(", "block", "a", "(", "type", "log", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	cil_gen_block(test_db, tree->root->cl_head->cl_head, test_ast_node, 0, 0, NULL);

	cil_destroy_block((struct cil_block*)test_ast_node->data);
	CuAssertPtrEquals(tc, NULL,test_ast_node->data);
}

void test_cil_gen_perm(CuTest *tc) {
	printf("test_cil_gen_perm\n");
	int rc = 0;
	char *line[] = {"(", "class", "file", "(", "read", "write", "open", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_current_perm = NULL;
	struct cil_tree_node *test_new_ast = NULL;
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	test_current_perm = tree->root->cl_head->cl_head->next->next->cl_head;

	while(test_current_perm != NULL) {
	    cil_tree_node_init(&test_new_ast);
	    test_new_ast->parent = test_ast_node;
	    test_new_ast->line = test_current_perm->line;

	    rc = cil_gen_perm(test_db, test_current_perm, test_new_ast);
	    CuAssertIntEquals(tc, SEPOL_OK, rc);
	    CuAssertPtrNotNull(tc, test_new_ast->data);
	    CuAssertIntEquals(tc, test_new_ast->flavor, CIL_PERM);
	    
	    test_current_perm = test_current_perm->next;

	    if (test_ast_node->cl_head == NULL)
	        test_ast_node->cl_head = test_new_ast;
	    else
	        test_ast_node->cl_tail->next = test_new_ast;

	    test_ast_node->cl_tail = test_new_ast;
	}
	printf("exit test_cil_gen_perm\n");
}

void test_cil_gen_perm_noname_neg(CuTest *tc) {
	int rc = 0;
	char *line[] = {"(", "class", "(", "read", "write", "open", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_current_perm = NULL;
	struct cil_tree_node *test_new_ast = NULL;
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	test_current_perm = tree->root->cl_head->cl_head->next->next->cl_head;

	while(test_current_perm != NULL) {
	    cil_tree_node_init(&test_new_ast);
	    test_new_ast->parent = test_ast_node;
	    test_new_ast->line = test_current_perm->line;

	    rc = cil_gen_perm(test_db, test_current_perm, test_new_ast);
	    CuAssertIntEquals(tc, SEPOL_ERR, rc);
	    
	    test_current_perm = test_current_perm->next;

	    if (test_ast_node->cl_head == NULL)
	        test_ast_node->cl_head = test_new_ast;
	    else
	        test_ast_node->cl_tail->next = test_new_ast;

	    test_ast_node->cl_tail = test_new_ast;
	}
}

void test_cil_gen_perm_dbnull_neg(CuTest *tc) {
	int rc = 0;
	char *line[] = {"(", "class", "file", "(", "read", "write", "open", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_current_perm = NULL;
	struct cil_tree_node *test_new_ast = NULL;
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db = NULL;

	test_current_perm = tree->root->cl_head->cl_head->next->next->cl_head;

	cil_tree_node_init(&test_new_ast);
	test_new_ast->parent = test_ast_node;
	test_new_ast->line = test_current_perm->line;

	rc = cil_gen_perm(test_db, test_current_perm, test_new_ast);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_perm_currnull_neg(CuTest *tc) {
	int rc = 0;
	char *line[] = {"(", "class", "file", "(", "read", "write", "open", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

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

void test_cil_gen_perm_permexists_neg(CuTest *tc) {
	int rc = 0;
	char *line[] = {"(", "class", "file", "(", "read", "write", "open", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_current_perm = NULL;
	struct cil_tree_node *test_new_ast = NULL;
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	test_current_perm = tree->root->cl_head->cl_head->next->next->cl_head;

	cil_tree_node_init(&test_new_ast);
	test_new_ast->parent = test_ast_node;
	test_new_ast->line = test_current_perm->line;

	struct cil_perm *test_perm = malloc(sizeof(struct cil_perm));
	symtab_t *test_symtab = NULL;
	cil_get_parent_symtab(test_db, test_ast_node, &test_symtab, CIL_SYM_UNKNOWN);
	cil_symtab_insert(test_symtab, (hashtab_key_t)"read", (struct cil_symtab_datum*)test_perm, test_new_ast);

	rc = cil_gen_perm(test_db, test_current_perm, test_new_ast);
	CuAssertIntEquals(tc, SEPOL_EEXIST, rc);
}

void test_cil_gen_perm_nodenull_neg(CuTest *tc) {
	int rc = 0;
	char *line[] = {"(", "class", "file", "(", "read", "write", "open", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_current_perm = NULL;
	struct cil_tree_node *test_new_ast = NULL;
	struct cil_tree_node *test_ast_node = NULL;

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_current_perm = tree->root->cl_head->cl_head->next->next->cl_head;

	cil_tree_node_init(&test_new_ast);
	test_new_ast->parent = test_ast_node;
	test_new_ast->line = test_current_perm->line;

	rc = cil_gen_perm(test_db, test_current_perm, test_new_ast);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_perm_nodes(CuTest *tc) {
	char *line[] = {"(", "class", "file", "(", "read", "write", "open", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);
	
	struct cil_db *test_db;
	cil_db_init(&test_db);

	char *test_key = tree->root->cl_head->cl_head->next->data;
	struct cil_class *test_cls = malloc(sizeof(struct cil_class));
	symtab_init(&test_cls->perms, CIL_SYM_SIZE);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	cil_symtab_insert(&test_db->symtab[CIL_SYM_CLASSES], (hashtab_key_t)test_key, (struct cil_symtab_datum*)test_cls, test_ast_node);

	test_ast_node->data = test_cls;
	test_ast_node->flavor = CIL_CLASS;

	int rc = cil_gen_perm_nodes(test_db, tree->root->cl_head->cl_head->next->next->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_perm_nodes_failgen_neg(CuTest *tc) {
	char *line[] = {"(", "class", "file", "(", "read", "write", "open", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	char *test_key = tree->root->cl_head->cl_head->next->data;
	struct cil_class *test_cls = malloc(sizeof(struct cil_class));
	//symtab_init(&test_cls->perms, CIL_SYM_SIZE);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	cil_symtab_insert(&test_db->symtab[CIL_SYM_CLASSES], (hashtab_key_t)test_key, (struct cil_symtab_datum*)test_cls, test_ast_node);

	test_ast_node->data = test_cls;
	test_ast_node->flavor = CIL_CLASS;

	int rc = cil_gen_perm_nodes(test_db, tree->root->cl_head->cl_head->next->next->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_perm_nodes_inval_perm_neg(CuTest *tc) {
	char *line[] = {"(", "class", "file", "(", "read", "(", "write", "open", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	char *test_key = tree->root->cl_head->cl_head->next->data;
	struct cil_class *test_cls = malloc(sizeof(struct cil_class));
	symtab_init(&test_cls->perms, CIL_SYM_SIZE);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	cil_symtab_insert(&test_db->symtab[CIL_SYM_CLASSES], (hashtab_key_t)test_key, (struct cil_symtab_datum*)test_cls, test_ast_node);

	test_ast_node->data = test_cls;
	test_ast_node->flavor = CIL_CLASS;

	int rc = cil_gen_perm_nodes(test_db, tree->root->cl_head->cl_head->next->next->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_class(CuTest *tc) { 
	char *line[] = {"(", "class", "file", "(", "read", "write", "open", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_class(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, test_ast_node->cl_tail);
	CuAssertPtrNotNull(tc, test_ast_node->data);
	CuAssertIntEquals(tc, test_ast_node->flavor, CIL_CLASS);
}

void test_cil_gen_class_noname_neg(CuTest *tc) { 
	char *line[] = {"(", "class", "(", "read", "write", "open", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_class(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_class_nodenull_neg(CuTest *tc) {
	char *line[] = {"(", "class", "(", "read", "write", "open", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node = NULL;

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_gen_class(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_class_dbnull_neg(CuTest *tc) {
	char *line[] = {"(", "class", "(", "read", "write", "open", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db = NULL;

	int rc = cil_gen_class(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_class_currnull_neg(CuTest *tc) {
	char *line[] = {"(", "class", "(", "read", "write", "open", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	tree->root->cl_head->cl_head = NULL;

	int rc = cil_gen_class(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_class_noclass_neg(CuTest *tc) { 
	char *line[] = {"(", "test", "read", "write", "open", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_class(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_class_failgen_neg(CuTest *tc) {
	char *line[] = {"(", "class", "file", "(", "read", "write", "open", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_class(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, test_ast_node->cl_tail);
	CuAssertPtrNotNull(tc, test_ast_node->data);
	CuAssertIntEquals(tc, test_ast_node->flavor, CIL_CLASS);

}

void test_cil_gen_common(CuTest *tc) {
	char *line[] = {"(", "common", "test", "(", "read", "write", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_common(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, test_ast_node->data);
	CuAssertIntEquals(tc, test_ast_node->flavor, CIL_COMMON);
}

void test_cil_gen_sid(CuTest *tc) {
	char *line[] = {"(", "sid", "test", "(", "blah", "blah", "blah", "(", "s0", "(", "c0", ")", ")", "(", "s0", "(", "c0", ")", ")", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_sid(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, test_ast_node->data);
	CuAssertIntEquals(tc, test_ast_node->flavor, CIL_SID);
}

void test_cil_gen_sid_namedcontext(CuTest *tc) {
	char *line[] = {"(", "sid", "test", "something", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_sid(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, test_ast_node->data);
	CuAssertIntEquals(tc, test_ast_node->flavor, CIL_SID);
}

void test_cil_gen_sid_halfcontext_neg(CuTest *tc) {
	char *line[] = {"(", "sid", "test", "(", "blah", "blah", "blah", "(", "s0", "(", "c0", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_sid(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_sid_noname_neg(CuTest *tc) {
	char *line[] = {"(", "sid", "(", "blah", "blah", "blah", "(", "s0", "(", "c0", ")", ")", "(", "s0", "(", "c0", ")", ")", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_sid(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_sid_empty_neg(CuTest *tc) {
	char *line[] = {"(", "sid", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_sid(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_sid_nocontext_neg(CuTest *tc) {
	char *line[] = {"(", "sid", "test", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_sid(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_sid_dblname_neg(CuTest *tc) {
	char *line[] = {"(", "sid", "test", "test2", "(", "blah", "blah", "blah", "(", "s0", "(", "c0", ")", ")", "(", "s0", "(", "c0", ")", ")", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_sid(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_sid_dbnull_neg(CuTest *tc) {
	char *line[] = {"(", "sid", "test", "(", "blah", "blah", "blah", "(", "s0", "(", "c0", ")", ")", "(", "s0", "(", "c0", ")", ")", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db = NULL;

	int rc = cil_gen_sid(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_sid_pcurrnull_neg(CuTest *tc) {
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_sid(test_db, NULL, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_sid_astnodenull_neg(CuTest *tc) {
	char *line[] = {"(", "sid", "test", "(", "blah", "blah", "blah", "(", "s0", "(", "c0", ")", ")", "(", "s0", "(", "c0", ")", ")", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_sid(test_db, tree->root->cl_head->cl_head, NULL);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_sid_insertnode_neg(CuTest *tc) {
	char *line[] = {"(", "sid", "test", "(", "blah", "blah", "blah", "(", "s0", "(", "c0", ")", ")", "(", "s0", "(", "c0", ")", ")", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	cil_gen_sid(test_db, tree->root->cl_head->cl_head, test_ast_node);
	int rc = cil_gen_sid(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_EEXIST, rc);
}

void test_cil_gen_type(CuTest *tc) {
	char *line[] = {"(", "type", "test", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_type(test_db, tree->root->cl_head->cl_head, test_ast_node, CIL_TYPE);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, test_ast_node->data);
	CuAssertIntEquals(tc, test_ast_node->flavor, CIL_TYPE);
}

void test_cil_gen_type_attribute(CuTest *tc) {
	char *line[] = {"(", "attribute", "test", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_type(test_db, tree->root->cl_head->cl_head, test_ast_node, CIL_ATTR);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, test_ast_node->data);
	CuAssertIntEquals(tc, test_ast_node->flavor, CIL_ATTR);
}

void test_cil_gen_typeattr(CuTest *tc) {
	char *line[] = {"(", "typeattribute", "foo", "bar", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_typeattr(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, test_ast_node->data);
	CuAssertStrEquals(tc, ((struct cil_typeattribute*)test_ast_node->data)->type_str, tree->root->cl_head->cl_head->next->data);
	CuAssertStrEquals(tc, ((struct cil_typeattribute*)test_ast_node->data)->attr_str, tree->root->cl_head->cl_head->next->next->data);
	CuAssertIntEquals(tc, test_ast_node->flavor, CIL_TYPE_ATTR);
}

void test_cil_gen_typeattr_dbnull_neg (CuTest *tc) {
	char *line[] = {"(", "typeattribute", "foo", "bar", ")", NULL};
	struct  cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db = NULL;

	int rc = cil_gen_typeattr(test_db, tree->root->cl_head->cl_head, test_ast_node);
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
	struct  cil_tree *tree;
	gen_test_tree(&tree, line);
	
	struct cil_tree_node *test_ast_node = NULL;

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_gen_typeattr(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_typeattr_typenull_neg (CuTest *tc) {
	char *line[] = {"(", "typeattribute", "foo", "bar" ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	tree->root->cl_head->cl_head->next = NULL;

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_gen_typeattr(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);	
}

void test_cil_gen_typeattr_attrnull_neg (CuTest *tc) {
	char *line[] = {"(", "typeattribute", "foo", "bar" ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	tree->root->cl_head->cl_head->next->next = NULL;

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_gen_typeattr(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);	
}

void test_cil_gen_typeattr_attrlist_neg (CuTest *tc) {
	char *line[] = {"(", "typeattribute", "foo", "(", "bar", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_gen_typeattr(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_typeattr_extra_neg (CuTest *tc) {
	char *line[] = {"(", "typeattribute", "foo", "bar", "extra", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_gen_typeattr(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_typealias(CuTest *tc) {
	char *line[] = {"(", "typealias", ".test.type", "type_t", ")", "(", "type", "test", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_typealias(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, test_ast_node->data);
	CuAssertStrEquals(tc, ((struct cil_typealias*)test_ast_node->data)->type_str, tree->root->cl_head->cl_head->next->data);
	CuAssertIntEquals(tc, test_ast_node->flavor, CIL_TYPEALIAS);
}

void test_cil_gen_typealias_incomplete_neg(CuTest *tc) {
	char *line[] = {"(", "typealias", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_typealias(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_typealias_incomplete_neg2(CuTest *tc) {
	char *line[] = {"(", "typealias", ".test.type", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_typealias(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_role(CuTest *tc) {
	char *line[] = {"(", "role", "test_r", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_role(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, test_ast_node->data);
	CuAssertIntEquals(tc, test_ast_node->flavor, CIL_ROLE);
}

void test_cil_gen_roletrans(CuTest *tc) {
	char *line[] = {"(", "roletransition", "foo_r",  "bar_t",  "foobar_r", ")", NULL};
	
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_roletrans(tree->root->cl_head->cl_head, test_ast_node);
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
	struct  cil_tree *tree;
	gen_test_tree(&tree, line);
	
	struct cil_tree_node *test_ast_node = NULL;

	int rc = cil_gen_roletrans(tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_roletrans_srcnull_neg(CuTest *tc) {
	char *line[] = {"(", "roletransition", "foo_r", "bar_t", "foobar_r", ")", NULL};
	
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	tree->root->cl_head->cl_head->next = NULL;

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_roletrans(tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_roletrans_tgtnull_neg(CuTest *tc) {
	char *line[] = {"(", "roletransition", "foo_r", "bar_t", "foobar_r", ")", NULL};
	
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	tree->root->cl_head->cl_head->next->next = NULL;

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_roletrans(tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_roletrans_resultnull_neg(CuTest *tc) {
	char *line[] = {"(", "roletransition", "foo_r", "bar_t", "foobar_r", ")", NULL};
	
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	tree->root->cl_head->cl_head->next->next->next = NULL;

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_roletrans(tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_roletrans_extra_neg(CuTest *tc) {
	char *line[] = {"(", "roletransition", "foo_r", "bar_t", "foobar_r", "extra", ")", NULL};
	
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_roletrans(tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_bool_true(CuTest *tc) {
	char *line[] = {"(", "bool", "foo", "true", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_bool(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, test_ast_node->data);
	CuAssertIntEquals(tc, ((struct cil_bool*)test_ast_node->data)->value, 1);
	CuAssertIntEquals(tc, test_ast_node->flavor, CIL_BOOL);
}

void test_cil_gen_bool_false(CuTest *tc) {
	char *line[] = {"(", "bool", "bar", "false", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_bool(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, test_ast_node->data);
	CuAssertIntEquals(tc, ((struct cil_bool*)test_ast_node->data)->value, 0);
	CuAssertIntEquals(tc, test_ast_node->flavor, CIL_BOOL);
}

void test_cil_gen_bool_none_neg(CuTest *tc) {
	char *line[] = {"(", "bool", "foo", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_bool(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_bool_notbool_neg(CuTest *tc) {
	char *line[] = {"(", "bool", "foo", "bar", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_bool(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_roleallow(CuTest *tc) {
	char *line[] = {"(", "roleallow", "staff_r", "sysadm_r", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);
	
	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_current;
	test_current = tree->root->cl_head->cl_head;

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;
	
	int rc = cil_gen_roleallow(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertPtrNotNull(tc, test_ast_node->data);
	CuAssertStrEquals(tc, ((struct cil_role_allow*)test_ast_node->data)->src_str, test_current->next->data);
	CuAssertStrEquals(tc, ((struct cil_role_allow*)test_ast_node->data)->tgt_str, test_current->next->next->data);
	CuAssertIntEquals(tc, test_ast_node->flavor, CIL_ROLEALLOW);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_roleallow_dbnull_neg(CuTest *tc) {
	char *line[] = {"(", "roleallow", "foo", "bar", ")", NULL};
	
	struct cil_tree *tree;
	gen_test_tree(&tree, line);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db = NULL;

	int rc = cil_gen_roleallow(test_db, tree->root->cl_head->cl_head, test_ast_node);
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
	
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node = NULL;

	int rc = cil_gen_roleallow(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_roleallow_srcnull_neg(CuTest *tc) {
	char *line[] = {"(", "roleallow", "foo", "bar", ")", NULL};
	
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	tree->root->cl_head->cl_head->next = NULL;

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_roleallow(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_roleallow_tgtnull_neg(CuTest *tc) {
	char *line[] = {"(", "roleallow", "foo", "bar", ")", NULL};
	
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	tree->root->cl_head->cl_head->next->next = NULL;

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_roleallow(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_roleallow_extra_neg(CuTest *tc) {
	char *line[] = {"(", "roleallow", "foo", "bar", "extra", ")", NULL};
	
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_roleallow(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_avrule(CuTest *tc) {
	char *line[] = {"(", "allow", "test", "foo", "bar", "(", "read", "write", ")", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	struct cil_tree_node *test_current;
	test_current = tree->root->cl_head->cl_head;

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

void test_cil_gen_avrule_notlist_neg(CuTest *tc) {
	char *line[] = {"(", "allow", "test", "foo", "bar", "write", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	struct cil_tree_node *test_current;
	test_current = tree->root->cl_head->cl_head;

	int rc = cil_gen_avrule(test_current, test_ast_node, CIL_AVRULE_ALLOWED);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_type_rule_transition(CuTest *tc) {
	char *line[] = {"(", "typetransition", "foo", "bar", "file", "foobar", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_type_rule(tree->root->cl_head->cl_head, test_ast_node, CIL_TYPE_TRANSITION);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertStrEquals(tc, ((struct cil_type_rule*)test_ast_node->data)->src_str, tree->root->cl_head->cl_head->next->data);
	CuAssertStrEquals(tc, ((struct cil_type_rule*)test_ast_node->data)->tgt_str, tree->root->cl_head->cl_head->next->next->data);
	CuAssertStrEquals(tc, ((struct cil_type_rule*)test_ast_node->data)->obj_str, tree->root->cl_head->cl_head->next->next->next->data);
	CuAssertStrEquals(tc, ((struct cil_type_rule*)test_ast_node->data)->result_str, tree->root->cl_head->cl_head->next->next->next->next->data);
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
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node = NULL;

	int rc = cil_gen_type_rule(tree->root->cl_head->cl_head, test_ast_node, CIL_TYPE_TRANSITION);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}	

void test_cil_gen_type_rule_transition_srcnull_neg(CuTest *tc) {
	char *line[] = {"(", "typetransition", "foo", "bar", "file", "foobar", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	tree->root->cl_head->cl_head->next = NULL;
	
	int rc = cil_gen_type_rule(tree->root->cl_head->cl_head, test_ast_node, CIL_TYPE_TRANSITION);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_type_rule_transition_tgtnull_neg(CuTest *tc) {
	char *line[] = {"(", "typetransition", "foo", "bar", "file", "foobar", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	tree->root->cl_head->cl_head->next->next = NULL;

	int rc = cil_gen_type_rule(tree->root->cl_head->cl_head, test_ast_node, CIL_TYPE_TRANSITION);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_type_rule_transition_objnull_neg(CuTest *tc) {
	char *line[] = {"(", "typetransition", "foo", "bar", "file", "foobar", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	tree->root->cl_head->cl_head->next->next->next = NULL;

	int rc = cil_gen_type_rule(tree->root->cl_head->cl_head, test_ast_node, CIL_TYPE_TRANSITION);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_type_rule_transition_resultnull_neg(CuTest *tc) {
	char *line[] = {"(", "typetransition", "foo", "bar", "file", "foobar", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	tree->root->cl_head->cl_head->next->next->next->next = NULL;

	int rc = cil_gen_type_rule(tree->root->cl_head->cl_head, test_ast_node, CIL_TYPE_TRANSITION);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_type_rule_transition_extra_neg(CuTest *tc) {
	char *line[] = {"(", "typetransition", "foo", "bar", "file", "foobar", "extra", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_type_rule(tree->root->cl_head->cl_head, test_ast_node, CIL_TYPE_TRANSITION);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_type_rule_change(CuTest *tc) {
	char *line[] = {"(", "typechange", "foo", "bar", "file", "foobar", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_type_rule(tree->root->cl_head->cl_head, test_ast_node, CIL_TYPE_CHANGE);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertStrEquals(tc, ((struct cil_type_rule*)test_ast_node->data)->src_str, tree->root->cl_head->cl_head->next->data);
	CuAssertStrEquals(tc, ((struct cil_type_rule*)test_ast_node->data)->tgt_str, tree->root->cl_head->cl_head->next->next->data);
	CuAssertStrEquals(tc, ((struct cil_type_rule*)test_ast_node->data)->obj_str, tree->root->cl_head->cl_head->next->next->next->data);
	CuAssertStrEquals(tc, ((struct cil_type_rule*)test_ast_node->data)->result_str, tree->root->cl_head->cl_head->next->next->next->next->data);
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
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node = NULL;

	int rc = cil_gen_type_rule(tree->root->cl_head->cl_head, test_ast_node, CIL_TYPE_CHANGE);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}	

void test_cil_gen_type_rule_change_srcnull_neg(CuTest *tc) {
	char *line[] = {"(", "typechange", "foo", "bar", "file", "foobar", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	tree->root->cl_head->cl_head->next = NULL;
	
	int rc = cil_gen_type_rule(tree->root->cl_head->cl_head, test_ast_node, CIL_TYPE_CHANGE);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_type_rule_change_tgtnull_neg(CuTest *tc) {
	char *line[] = {"(", "typechange", "foo", "bar", "file", "foobar", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	tree->root->cl_head->cl_head->next->next = NULL;

	int rc = cil_gen_type_rule(tree->root->cl_head->cl_head, test_ast_node, CIL_TYPE_CHANGE);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_type_rule_change_objnull_neg(CuTest *tc) {
	char *line[] = {"(", "typechange", "foo", "bar", "file", "foobar", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	tree->root->cl_head->cl_head->next->next->next = NULL;

	int rc = cil_gen_type_rule(tree->root->cl_head->cl_head, test_ast_node, CIL_TYPE_CHANGE);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_type_rule_change_resultnull_neg(CuTest *tc) {
	char *line[] = {"(", "typechange", "foo", "bar", "file", "foobar", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	tree->root->cl_head->cl_head->next->next->next->next = NULL;

	int rc = cil_gen_type_rule(tree->root->cl_head->cl_head, test_ast_node, CIL_TYPE_CHANGE);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_type_rule_change_extra_neg(CuTest *tc) {
	char *line[] = {"(", "typechange", "foo", "bar", "file", "foobar", "extra", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_type_rule(tree->root->cl_head->cl_head, test_ast_node, CIL_TYPE_CHANGE);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_type_rule_member(CuTest *tc) {
	char *line[] = {"(", "typemember", "foo", "bar", "file", "foobar", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_type_rule(tree->root->cl_head->cl_head, test_ast_node, CIL_TYPE_MEMBER);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertStrEquals(tc, ((struct cil_type_rule*)test_ast_node->data)->src_str, tree->root->cl_head->cl_head->next->data);
	CuAssertStrEquals(tc, ((struct cil_type_rule*)test_ast_node->data)->tgt_str, tree->root->cl_head->cl_head->next->next->data);
	CuAssertStrEquals(tc, ((struct cil_type_rule*)test_ast_node->data)->obj_str, tree->root->cl_head->cl_head->next->next->next->data);
	CuAssertStrEquals(tc, ((struct cil_type_rule*)test_ast_node->data)->result_str, tree->root->cl_head->cl_head->next->next->next->next->data);
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
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node = NULL;

	int rc = cil_gen_type_rule(tree->root->cl_head->cl_head, test_ast_node, CIL_TYPE_MEMBER);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}	

void test_cil_gen_type_rule_member_srcnull_neg(CuTest *tc) {
	char *line[] = {"(", "typemember", "foo", "bar", "file", "foobar", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	tree->root->cl_head->cl_head->next = NULL;
	
	int rc = cil_gen_type_rule(tree->root->cl_head->cl_head, test_ast_node, CIL_TYPE_MEMBER);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_type_rule_member_tgtnull_neg(CuTest *tc) {
	char *line[] = {"(", "typemember", "foo", "bar", "file", "foobar", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	tree->root->cl_head->cl_head->next->next = NULL;

	int rc = cil_gen_type_rule(tree->root->cl_head->cl_head, test_ast_node, CIL_TYPE_MEMBER);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_type_rule_member_objnull_neg(CuTest *tc) {
	char *line[] = {"(", "typemember", "foo", "bar", "file", "foobar", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	tree->root->cl_head->cl_head->next->next->next = NULL;

	int rc = cil_gen_type_rule(tree->root->cl_head->cl_head, test_ast_node, CIL_TYPE_MEMBER);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_type_rule_member_resultnull_neg(CuTest *tc) {
	char *line[] = {"(", "typemember", "foo", "bar", "file", "foobar", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	tree->root->cl_head->cl_head->next->next->next->next = NULL;

	int rc = cil_gen_type_rule(tree->root->cl_head->cl_head, test_ast_node, CIL_TYPE_MEMBER);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_type_rule_member_extra_neg(CuTest *tc) {
	char *line[] = {"(", "typemember", "foo", "bar", "file", "foobar", "extra", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_type_rule(tree->root->cl_head->cl_head, test_ast_node, CIL_TYPE_MEMBER);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_user(CuTest *tc) {
	char *line[] = {"(", "user", "sysadm", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_user(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertIntEquals(tc, CIL_USER, test_ast_node->flavor);
	CuAssertPtrNotNull(tc, test_ast_node->data);
	CuAssertPtrEquals(tc, test_ast_node, ((struct cil_symtab_datum*)test_ast_node->data)->node);
	CuAssertStrEquals(tc, tree->root->cl_head->cl_head->next->data, ((struct cil_symtab_datum*)test_ast_node->data)->name);
}

void test_cil_gen_user_nouser_neg(CuTest *tc) {
	char *line[] = {"(", "user", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_user(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_user_xsinfo_neg(CuTest *tc) {
	char *line[] = {"(", "user", "sysadm", "xsinfo", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_user(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}


void test_cil_gen_sensitivity(CuTest *tc) {
	char *line[] = {"(", "sensitivity", "s0", ")", NULL};
	
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_sensitivity(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, test_ast_node->data);
	CuAssertIntEquals(tc, test_ast_node->flavor, CIL_SENS);

}

void test_cil_gen_sensitivity_dbnull_neg(CuTest *tc) {
	char *line[] = {"(", "sensitivity", "s0", ")", NULL};

	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db = NULL;

	int rc = cil_gen_sensitivity(test_db, tree->root->cl_head->cl_head, test_ast_node);
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

	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node = NULL;

	int rc = cil_gen_sensitivity(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_sensitivity_sensnull_neg(CuTest *tc) {
	char *line[] = {"(", "sensitivity", "s0", ")", NULL};
	
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	tree->root->cl_head->cl_head->next = NULL;

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_sensitivity(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_sensitivity_senslist_neg(CuTest *tc) {
	char *line[] = {"(", "sensitivity", "(", "s0", ")", ")", NULL};

	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_sensitivity(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_sensitivity_extra_neg(CuTest *tc) {
	char *line[] = {"(", "sensitivity", "s0", "extra", ")", NULL};
	
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_sensitivity(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}	

void test_cil_gen_sensalias(CuTest *tc) {
	char *line[] = {"(", "sensitivityalias", "s0", "alias", ")", NULL};

	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_sensalias(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_sensalias_dbnull_neg(CuTest *tc) {
	char *line[] = {"(", "sensitivityalias", "s0", "alias", ")", NULL};

	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_db *test_db = NULL;

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_sensalias(test_db, tree->root->cl_head->cl_head, test_ast_node);
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

	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_db *test_db;
	cil_db_init (&test_db);

	struct cil_tree_node *test_ast_node = NULL;

	int rc = cil_gen_sensalias(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_sensalias_sensnull_neg(CuTest *tc) {
	char *line[] = {"(", "sensitivityalias", "s0", "alias", ")", NULL};

	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	tree->root->cl_head->cl_head->next = NULL;

	struct cil_db *test_db;
	cil_db_init(&test_db);
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_sensalias(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_sensalias_senslist_neg(CuTest *tc) {
	char *line[] = {"(", "sensitivityalias", "(", "s0", "s1", ")", "alias", ")", NULL};

	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_sensalias(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_sensalias_aliasnull_neg(CuTest *tc) {
	char *line[] = {"(", "sensitivityalias", "s0", "alias", ")", NULL};

	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	tree->root->cl_head->cl_head->next->next = NULL;

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_sensalias(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_sensalias_aliaslist_neg(CuTest *tc) {
	char *line[] = {"(", "sensitivityalias", "s0", "(", "alias", "alias2", ")", ")", NULL};

	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_sensalias(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_sensalias_extra_neg(CuTest *tc) {
	char *line[] = {"(", "sensitivityalias", "s0", "alias", "extra", ")", NULL};

	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_sensalias(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_category(CuTest *tc) {
	char *line[] = {"(", "category", "c0", ")", NULL};

	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_category(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_category_dbnull_neg(CuTest *tc) {
	char *line[] = {"(", "category", "c0", ")", NULL};

	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_db *test_db = NULL;

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_category(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_category_astnull_neg(CuTest *tc) {
	char *line[] = {"(", "category", "c0", ")", NULL};

	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node = NULL;

	int rc = cil_gen_category(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_category_currnull_neg(CuTest *tc) {
	char *line[] = {"(", "category", "c0", ")", NULL};

	struct cil_tree *tree;
	gen_test_tree(&tree, line);

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

	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	tree->root->cl_head->cl_head->next = NULL;

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_category(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_category_catlist_neg(CuTest *tc){
	char *line[] = {"(", "category", "(", "c0", ")", ")", NULL};

	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_category(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_category_extra_neg(CuTest *tc) {
	char *line[] = {"(", "category", "c0", "extra", ")", NULL};

	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	int rc = cil_gen_category(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_build_ast(CuTest *tc) {
	char *line[] = {"(", "test", "\"qstring\"", ")", ";comment", NULL};

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

void test_cil_build_ast_block(CuTest *tc) {
	char *line[] = {"(", "block", "test", "(", "type", "log", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_build_ast_block_neg(CuTest *tc) {
	char *line[] = {"(", "block", "(", "type", "log", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);

}

void test_cil_build_ast_class(CuTest *tc) {
	char *line[] = {"(", "class", "file", "(", "read", "write", "open", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_build_ast_class_neg(CuTest *tc) {
	char *line[] = {"(", "class", "(", "read", "write", "open", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_build_ast_common(CuTest *tc) {
	char *line[] = {"(", "common", "test", "(", "read", "write", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_build_ast_common_neg(CuTest *tc) {
	char *line[] = {"(", "common", "(", "read", "write", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_build_ast_sid(CuTest *tc) {
	char *line[] = {"(", "sid", "test", "(", "blah", "blah", "blah", "(", "s0", "(", "c0", ")", ")", "(", "s0", "(", "c0", ")", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_build_ast_sid_neg(CuTest *tc) {
	char *line[] = {"(", "sid", "(", "blah", "blah", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_build_ast_type(CuTest *tc) {
	char *line[] = {"(", "type", "test", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_build_ast_type_neg(CuTest *tc) {
	char *line[] = {"(", "type", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_build_ast_type_attribute(CuTest *tc) {
	char *line[] = {"(", "attribute", "test", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_build_ast_type_attribute_neg(CuTest *tc) {
	char *line[] = {"(", "attribute", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_build_ast_typeattr(CuTest *tc) {
	char *line[] = {"(", "typeattribute", "foo", "bar", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);
	
	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_build_ast_typeattr_neg(CuTest *tc) {
	char *line[] = {"(", "typeattribute", "bar", ")", NULL};
	struct cil_tree *tree;
	gen_test_tree(&tree, line);
	
	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}	

void test_cil_build_ast_typealias(CuTest *tc) {
	char *line[] = {"(", "typealias", ".test.type", "type_t", ")", "(", "type", "test", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_build_ast_typealias_notype_neg(CuTest *tc) {
	char *line[] = {"(", "typealias", ".test.type", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_build_ast_role(CuTest *tc) {
	char *line[] = {"(", "role", "test_r", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_build_ast_role_neg(CuTest *tc) {
	char *line[] = {"(", "role", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_build_ast_roletrans(CuTest *tc) {
	char *line[] = {"{", "roletransition", "foo_r", "bar_t", "foobar_r", ")", NULL};

	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_build_ast_roletrans_neg(CuTest *tc) {
	char *line[] = {"(", "roletransition", "foo_r", "bar_t", ")", NULL};

	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_build_ast_avrule(CuTest *tc) {
	char *line[] = {"(", "allow", "test", "foo", "bar", "(", "read", "write", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_build_ast_avrule_neg(CuTest *tc) {
	char *line[] = {"(", "allow", "foo", "bar", "(", "read", "write", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_build_ast_type_rule_transition(CuTest *tc) {
	char *line[] = {"(", "typetransition", "foo", "bar", "file", "foobar", ")", NULL};
	
	struct cil_tree *tree;
	gen_test_tree(&tree, line);	
	
	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_build_ast_type_rule_transition_neg(CuTest *tc) {
	char *line[] = {"(", "typetransition", "foo", "bar", "file", "foobar", "extra",  ")", NULL};
	
	struct cil_tree *tree;
	gen_test_tree(&tree, line);	
	
	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_build_ast_type_rule_change(CuTest *tc) {
	char *line[] = {"(", "typechange", "foo", "bar", "file", "foobar", ")", NULL};
	
	struct cil_tree *tree;
	gen_test_tree(&tree, line);	
	
	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_build_ast_type_rule_change_neg(CuTest *tc) {
	char *line[] = {"(", "typechange", "foo", "bar", "file", "foobar", "extra",  ")", NULL};
	
	struct cil_tree *tree;
	gen_test_tree(&tree, line);	
	
	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_build_ast_type_rule_member(CuTest *tc) {
	char *line[] = {"(", "typemember", "foo", "bar", "file", "foobar", ")", NULL};
	
	struct cil_tree *tree;
	gen_test_tree(&tree, line);	
	
	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_build_ast_type_rule_member_neg(CuTest *tc) {
	char *line[] = {"(", "typemember", "foo", "bar", "file", "foobar", "extra",  ")", NULL};
	
	struct cil_tree *tree;
	gen_test_tree(&tree, line);	
	
	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_build_ast_bool(CuTest *tc) {
	char *line[] = {"(", "bool", "foo", "true", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_build_ast_bool_neg(CuTest *tc) {
	char *line[] = {"(", "bool", "foo", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_build_ast_sensitivity(CuTest *tc) {
	char *line[] = {"(", "sensitivity", "s0", ")", NULL};

	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_build_ast_sensitivity_neg(CuTest *tc) {
	char *line[] = {"(", "sensitivity", "s0", "extra", ")", NULL};

	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_build_ast_sensalias(CuTest *tc) {
	char *line[] = {"(", "sensitivityalias", "s0", "alias", ")", NULL};

	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_build_ast_sensalias_neg(CuTest *tc) {
	char *line[] = {"(", "sensitivityalias", "s0", "alias", "extra", ")", NULL};

	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	int rc = cil_build_ast(test_db, tree->root, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_userrole(CuTest *tc) {
	char *line[] = {"(", "userrole", "staff_u", "staff_r", ")", NULL};
	
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_userrole(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_userrole_parse_current_NULL(CuTest *tc) {
	char *line[] = {"(", "userrole", "staff_u", "staff_r", ")", NULL};
	
	struct cil_tree *tree = NULL;

	struct cil_db *test_db;
	cil_db_init(&test_db);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_userrole(test_db, tree, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_userrole_cil_db_NULL(CuTest *tc) {
	char *line[] = {"(", "userrole", "staff_u", "staff_r", ")", NULL};
	
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_db *test_db = NULL;
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_userrole(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_userrole_ast_node_NULL(CuTest *tc) {
	char *line[] = {"(", "userrole", "staff_u", "staff_r", ")", NULL};
	
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);
	
	struct cil_tree_node *test_ast_node = NULL;

	int rc = cil_gen_userrole(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_userrole_parse_current_next_null(CuTest *tc) {
	char *line[] = {"(", "userrole", ")", NULL};
	
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_userrole(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}
//2nd case okay
void test_cil_gen_userrole_parse_curr_next_cl_head_not_null(CuTest *tc) {
	char *line[] = {"(", "userrole", "(", "staff_u", ")", "staff_r", ")", NULL};
	
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_userrole(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}
// 3rd case okay
void test_cil_gen_userrole_parse_curr_next_next_null(CuTest *tc) {
	char *line[] = {"(", "(", "userrole", "staff_u", ")", "staff_r", ")", NULL};
	
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_userrole(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}
void test_cil_gen_userrole_parse_curr_next_next_cl_head_not_null(CuTest *tc) {
	char *line[] = {"(", "userrole", "staff_u", "(", "staff_r", ")", ")", NULL};
	
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_userrole(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

// roletypes
void test_cil_gen_roletype(CuTest *tc) {
	char *line[] = {"(", "roletype", "admin_r", "admin_t", ")", NULL};
	
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_roletype(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_gen_roletype_parse_current_NULL(CuTest *tc) {
	char *line[] = {"(", "roletype", "admin_r", "admin_t", ")", NULL};
	
	struct cil_tree *tree = NULL;

	struct cil_db *test_db;
	cil_db_init(&test_db);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_roletype(test_db, tree, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_roletype_cil_db_NULL(CuTest *tc) {
	char *line[] = {"(", "roletype", "admin_r", "admin_t", ")", NULL};
	
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_db *test_db = NULL;
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_roletype(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_gen_roletype_ast_node_NULL(CuTest *tc) {
	char *line[] = {"(", "roletype", "admin_r", "admin_t", ")", NULL};
	
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);
	
	struct cil_tree_node *test_ast_node = NULL;

	int rc = cil_gen_roletype(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}


void test_cil_gen_roletype_parse_current_next_null(CuTest *tc) {
	char *line[] = {"(", "roletype", ")", NULL};
	
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_roletype(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}
//2nd case okay
void test_cil_gen_roletype_parse_curr_next_cl_head_not_null(CuTest *tc) {
	char *line[] = {"(", "roletype", "(", "admin_r", ")", "admin_t", ")", NULL};
	
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_roletype(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}
// 3rd case okay
void test_cil_gen_roletype_parse_curr_next_next_null(CuTest *tc) {
	char *line[] = {"(", "(", "roletype", "admin_r", ")", "admin_t", ")", NULL};
	
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_roletype(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}
void test_cil_gen_roletype_parse_curr_next_next_cl_head_not_null(CuTest *tc) {
	char *line[] = {"(", "roletype", "admin_r", "(", "admin_t", ")", ")", NULL};
	
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	int rc = cil_gen_roletype(test_db, tree->root->cl_head->cl_head, test_ast_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_build_ast_node_helper_userrole_neg(CuTest *tc) {
	char *line[] = {"(", "userrole", "staff_u", "(", "staff_r", ")", ")", NULL};
	
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *cil_l;
	cil_list_init(&cil_l);

	cil_list_item_init(&cil_l->head);
	cil_list_item_init(&cil_l->head->next);
	cil_l->head->data = cil_l->head->next;
	cil_l->head->flavor = CIL_AST_NODE;
	cil_l->head->next->flavor = CIL_DB;
	cil_l->head->next->data = test_db;
	
	cil_build_ast(test_db, tree->root, test_db->ast->root);

	uint32_t *finished = NULL;

	int rc = __cil_build_ast_node_helper(tree->root->cl_head->cl_head, finished, cil_l);

	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_build_ast_node_helper_roletype_neg(CuTest *tc) {
	char *line[] = {"(", "roletype", "(", "admin_r", ")", "admin_t", ")", NULL};
	
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *cil_l;
	cil_list_init(&cil_l);

	cil_list_item_init(&cil_l->head);
	cil_list_item_init(&cil_l->head->next);
	cil_l->head->data = cil_l->head->next;
	cil_l->head->flavor = CIL_AST_NODE;
	cil_l->head->next->flavor = CIL_DB;
	cil_l->head->next->data = test_db;
	
	cil_build_ast(test_db, tree->root, test_db->ast->root);

	uint32_t *finished = NULL;

	int rc = __cil_build_ast_node_helper(tree->root->cl_head->cl_head, finished, cil_l);

	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_build_ast_node_helper_userrole(CuTest *tc) {
	char *line[] = {"(", "userrole", "staff_u", "staff_r", ")", NULL};
	
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *cil_l;
	cil_list_init(&cil_l);

	cil_list_item_init(&cil_l->head);
	cil_list_item_init(&cil_l->head->next);
	cil_l->head->data = cil_l->head->next;
	cil_l->head->flavor = CIL_AST_NODE;
	cil_l->head->next->flavor = CIL_DB;
	cil_l->head->next->data = test_db;

	cil_build_ast(test_db, tree->root, test_db->ast->root);

	uint32_t *finished = NULL;

	int rc = __cil_build_ast_node_helper(tree->root->cl_head->cl_head, finished, cil_l);

	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_build_ast_node_helper_roletype(CuTest *tc) {
	char *line[] = {"(", "roletype", "admin_r", "admin_t", ")", NULL};
	
	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *cil_l;
	cil_list_init(&cil_l);

	cil_list_item_init(&cil_l->head);
	cil_list_item_init(&cil_l->head->next);
	cil_l->head->data = cil_l->head->next;
	cil_l->head->flavor = CIL_AST_NODE;
	cil_l->head->next->flavor = CIL_DB;
	cil_l->head->next->data = test_db;
	
	cil_build_ast(test_db, tree->root, test_db->ast->root);

	uint32_t *finished = NULL;

	int rc = __cil_build_ast_node_helper(tree->root->cl_head->cl_head, finished, cil_l);

	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

