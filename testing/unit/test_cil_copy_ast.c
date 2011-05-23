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

	cil_set_to_list(test_tree->root->cl_head, cil_l, 1);

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

	cil_set_to_list(test_tree->root->cl_head, cil_l, 1);
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

	cil_set_to_list(test_tree->root->cl_head, cil_l, 1);
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

void test_cil_copy_block(CuTest *tc) {
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
	
	struct cil_tree_node *test_copy;
	cil_tree_node_init(&test_copy);

	symtab_t sym;
	symtab_init(&sym, CIL_SYM_SIZE);

	int rc = cil_copy_block(test_ast_node, test_copy, &sym);
	CuAssertIntEquals(tc, rc, SEPOL_OK);
	CuAssertStrEquals(tc, ((struct cil_block *)test_copy->data)->datum.name, 
		((struct cil_block *)test_ast_node->data)->datum.name);
}

void test_cil_copy_perm(CuTest *tc) {
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

	struct cil_tree_node *test_copy;
	cil_tree_node_init(&test_copy);

	symtab_t sym;
	symtab_init(&sym, CIL_SYM_SIZE);

	cil_gen_perm(test_db, test_tree->root->cl_head->cl_head->next->next->cl_head, test_ast_node);
	int rc = cil_copy_perm(test_ast_node, test_copy, &sym);
	CuAssertIntEquals(tc, rc, SEPOL_OK);
	CuAssertStrEquals(tc, ((struct cil_perm *)test_copy->data)->datum.name, 
		((struct cil_perm *)test_ast_node->data)->datum.name);
	cil_gen_perm(test_db, test_tree->root->cl_head->cl_head->next->next->cl_head->next, test_ast_node);
	cil_copy_perm(test_ast_node, test_copy, &sym);
	CuAssertIntEquals(tc, rc, SEPOL_OK);
	CuAssertStrEquals(tc, ((struct cil_perm *)test_copy->data)->datum.name, 
		((struct cil_perm *)test_ast_node->data)->datum.name);
	cil_gen_perm(test_db, test_tree->root->cl_head->cl_head->next->next->cl_head->next->next, test_ast_node);
	cil_copy_perm(test_ast_node, test_copy, &sym);
	CuAssertIntEquals(tc, rc, SEPOL_OK);
	CuAssertStrEquals(tc, ((struct cil_perm *)test_copy->data)->datum.name, 
		((struct cil_perm *)test_ast_node->data)->datum.name);
	
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

void test_cil_copy_common(CuTest *tc) {
	char *line[] = {"(", "common", "test", "(", "read", "write", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	cil_gen_common(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	
	struct cil_tree_node *test_copy;
	cil_tree_node_init(&test_copy);

	symtab_t sym;
	symtab_init(&sym, CIL_SYM_SIZE);

	int rc = cil_copy_common(test_ast_node, test_copy, &sym);
	CuAssertIntEquals(tc, rc, SEPOL_OK);
	CuAssertStrEquals(tc, ((struct cil_common *)test_copy->data)->datum.name, 
		((struct cil_common *)test_ast_node->data)->datum.name);
}

void test_cil_copy_classcommon(CuTest *tc) {
	char *line[] = {"(", "classcommon", "file", "(", "read", "write", "open", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        char *test_key = test_tree->root->cl_head->cl_head->next->data;
        struct cil_class *test_cls;
	cil_class_init(&test_cls);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        cil_symtab_insert(&test_db->symtab[CIL_SYM_CLASSES], (hashtab_key_t)test_key, (struct cil_symtab_datum*)test_cls, test_ast_node);

        test_ast_node->data = test_cls;
        test_ast_node->flavor = CIL_CLASS;

        cil_gen_classcommon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	
	struct cil_classcommon *test_copy;
	cil_classcommon_init(&test_copy);

	cil_copy_classcommon((struct cil_classcommon *)test_ast_node->data, &test_copy);
	CuAssertStrEquals(tc, ((struct cil_classcommon *)test_ast_node->data)->class_str, test_copy->class_str);
	CuAssertStrEquals(tc, ((struct cil_classcommon *)test_ast_node->data)->common_str, test_copy->common_str);
}

void test_cil_copy_user(CuTest *tc) {
	char *line[] = {"(", "user", "sysadm", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	cil_gen_user(test_db, test_tree->root->cl_head->cl_head, test_ast_node);

	struct cil_tree_node *test_copy;
	cil_tree_node_init(&test_copy);

	symtab_t sym;
	symtab_init(&sym, CIL_SYM_SIZE);

	int rc = cil_copy_user(test_ast_node, test_copy, &sym);
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

void test_cil_copy_avrule(CuTest *tc) {
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

	cil_gen_avrule(test_current, test_ast_node, CIL_AVRULE_ALLOWED);

	struct cil_avrule *test_copy;
	cil_avrule_init(&test_copy);

	cil_copy_avrule((struct cil_avrule *)test_ast_node->data, &test_copy);
	CuAssertIntEquals(tc, ((struct cil_avrule *)test_ast_node->data)->rule_kind, test_copy->rule_kind);
	CuAssertStrEquals(tc, ((struct cil_avrule *)test_ast_node->data)->src_str, test_copy->src_str);
	CuAssertStrEquals(tc, ((struct cil_avrule *)test_ast_node->data)->tgt_str, test_copy->tgt_str);
	CuAssertStrEquals(tc, ((struct cil_avrule *)test_ast_node->data)->obj_str, test_copy->obj_str);
	CuAssertIntEquals(tc, ((struct cil_avrule *)test_ast_node->data)->perms_str->head->flavor, test_copy->perms_str->head->flavor);
	CuAssertStrEquals(tc, (char*)((struct cil_avrule *)test_ast_node->data)->perms_str->head->data, (char*)test_copy->perms_str->head->data);
	CuAssertIntEquals(tc, ((struct cil_avrule *)test_ast_node->data)->perms_str->head->next->flavor, test_copy->perms_str->head->next->flavor);
	CuAssertStrEquals(tc, (char*)((struct cil_avrule *)test_ast_node->data)->perms_str->head->next->data, (char*)test_copy->perms_str->head->next->data);
}

void test_cil_copy_cat(CuTest *tc) {
	char *line[] = {"(", "category", "c0", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	cil_gen_category(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	
	struct cil_tree_node *test_copy;
	cil_tree_node_init(&test_copy);

	symtab_t sym;
	symtab_init(&sym, CIL_SYM_SIZE);

	int rc = cil_copy_cat(test_ast_node, test_copy, &sym);
	CuAssertIntEquals(tc, rc, SEPOL_OK);
	CuAssertStrEquals(tc, ((struct cil_class *)test_copy->data)->datum.name, 
		((struct cil_class *)test_ast_node->data)->datum.name);
}

void test_cil_copy_catalias(CuTest *tc) {
	char *line[] = {"(", "categoryalias", "c0", "red", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;
	
	cil_gen_catalias(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	
	struct cil_tree_node *test_copy;
	cil_tree_node_init(&test_copy);

	symtab_t sym;
	symtab_init(&sym, CIL_SYM_SIZE);

	int rc = cil_copy_catalias(test_ast_node, test_copy, &sym);
	CuAssertIntEquals(tc, rc, SEPOL_OK);
	CuAssertStrEquals(tc, ((struct cil_class *)test_copy->data)->datum.name, 
		((struct cil_class *)test_ast_node->data)->datum.name);
}

void test_cil_copy_level(CuTest *tc) {
	char *line[] = {"(", "level", "low", "s0", "(", "c1", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        cil_gen_level(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	
	struct cil_tree_node *test_copy;
	cil_tree_node_init(&test_copy);

	symtab_t sym;
	symtab_init(&sym, CIL_SYM_SIZE);

	int rc = cil_copy_level(test_ast_node, test_copy, &sym);
	CuAssertIntEquals(tc, rc, SEPOL_OK);
	CuAssertStrEquals(tc, ((struct cil_class *)test_copy->data)->datum.name, 
		((struct cil_class *)test_ast_node->data)->datum.name);
}

void test_cil_copy_fill_level(CuTest *tc) {
	char *line[] = {"(", "level", "low", "s0", "(", "c1", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        cil_gen_level(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	
	struct cil_tree_node *test_copy;
	cil_tree_node_init(&test_copy);
	cil_level_init((struct cil_level**)&test_copy->data);

	symtab_t sym;
	symtab_init(&sym, CIL_SYM_SIZE);

	cil_copy_fill_level((struct cil_level*)test_ast_node->data, (struct cil_level*)test_copy->data);
	CuAssertStrEquals(tc, ((struct cil_level *)test_copy->data)->sens_str,
		((struct cil_level *)test_ast_node->data)->sens_str);
}

void test_cil_copy_context(CuTest *tc) {
	char *line[] = {"(", "context", "packet_default", "(", "system_u", "object_r", "etc_t", "low", "high", ")", ")", NULL};
	
        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

	cil_gen_context(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	
	struct cil_tree_node *test_copy;
	cil_tree_node_init(&test_copy);

	symtab_t sym;
	symtab_init(&sym, CIL_SYM_SIZE);

	int rc = cil_copy_context(test_ast_node, test_copy, &sym);
	CuAssertIntEquals(tc, rc, SEPOL_OK);
	CuAssertStrEquals(tc, ((struct cil_class *)test_copy->data)->datum.name, 
		((struct cil_class *)test_ast_node->data)->datum.name);
}

void test_cil_copy_fill_context(CuTest *tc) {
	char *line[] = {"(", "context", "packet_default", "(", "system_u", "object_r", "etc_t", "low", "high", ")", ")", NULL};
	
        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

	cil_gen_context(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	
	struct cil_tree_node *test_copy;
	cil_tree_node_init(&test_copy);
	cil_context_init((struct cil_context**)&test_copy->data);

	symtab_t sym;
	symtab_init(&sym, CIL_SYM_SIZE);

	cil_copy_fill_context((struct cil_context*)test_ast_node->data, (struct cil_context*)test_copy->data);
	CuAssertStrEquals(tc, ((struct cil_context *)test_copy->data)->user_str,
		((struct cil_context *)test_ast_node->data)->user_str);
	CuAssertStrEquals(tc, ((struct cil_context *)test_copy->data)->role_str,
		((struct cil_context *)test_ast_node->data)->role_str);
	CuAssertStrEquals(tc, ((struct cil_context *)test_copy->data)->type_str,
		((struct cil_context *)test_ast_node->data)->type_str);
	CuAssertStrEquals(tc, ((struct cil_context *)test_copy->data)->low_str,
		((struct cil_context *)test_ast_node->data)->low_str);
	CuAssertStrEquals(tc, ((struct cil_context *)test_copy->data)->high_str,
		((struct cil_context *)test_ast_node->data)->high_str);
}

void test_cil_copy_fill_context_anonlow(CuTest *tc) {
	char *line[] = {"(", "context", "packet_default", "(", "system_u", "object_r", "etc_t", "(", "s0", "(", "c0", ")", ")", "high", ")", ")", NULL};
	
        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

	int rc = cil_gen_context(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	rc = rc;
	
	struct cil_tree_node *test_copy;
	cil_tree_node_init(&test_copy);
	cil_context_init((struct cil_context**)&test_copy->data);

	symtab_t sym;
	symtab_init(&sym, CIL_SYM_SIZE);

	cil_copy_fill_context((struct cil_context*)test_ast_node->data, (struct cil_context*)test_copy->data);
	CuAssertStrEquals(tc, ((struct cil_context *)test_copy->data)->user_str,
		((struct cil_context *)test_ast_node->data)->user_str);
	CuAssertStrEquals(tc, ((struct cil_context *)test_copy->data)->role_str,
		((struct cil_context *)test_ast_node->data)->role_str);
	CuAssertStrEquals(tc, ((struct cil_context *)test_copy->data)->type_str,
		((struct cil_context *)test_ast_node->data)->type_str);
	CuAssertStrEquals(tc, ((struct cil_context *)test_copy->data)->low_str,
		((struct cil_context *)test_ast_node->data)->low_str);
	CuAssertStrEquals(tc, ((struct cil_context *)test_copy->data)->high_str,
		((struct cil_context *)test_ast_node->data)->high_str);
}

void test_cil_copy_fill_context_anonhigh(CuTest *tc) {
	char *line[] = {"(", "context", "packet_default", "(", "system_u", "object_r", "etc_t", "low", "(", "s0", "(", "c0", ")", ")", ")", ")", NULL};
	
        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

	int rc = cil_gen_context(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	rc = rc;
	
	struct cil_tree_node *test_copy;
	cil_tree_node_init(&test_copy);
	cil_context_init((struct cil_context**)&test_copy->data);

	symtab_t sym;
	symtab_init(&sym, CIL_SYM_SIZE);

	cil_copy_fill_context((struct cil_context*)test_ast_node->data, (struct cil_context*)test_copy->data);
	CuAssertStrEquals(tc, ((struct cil_context *)test_copy->data)->user_str,
		((struct cil_context *)test_ast_node->data)->user_str);
	CuAssertStrEquals(tc, ((struct cil_context *)test_copy->data)->role_str,
		((struct cil_context *)test_ast_node->data)->role_str);
	CuAssertStrEquals(tc, ((struct cil_context *)test_copy->data)->type_str,
		((struct cil_context *)test_ast_node->data)->type_str);
	CuAssertStrEquals(tc, ((struct cil_context *)test_copy->data)->low_str,
		((struct cil_context *)test_ast_node->data)->low_str);
	CuAssertStrEquals(tc, ((struct cil_context *)test_copy->data)->high_str,
		((struct cil_context *)test_ast_node->data)->high_str);
}

void test_cil_copy_constrain(CuTest *tc) {
	char *line[] = {"(", "mlsconstrain", "(", "file", "dir", ")", "(", "create", "relabelto", ")", "(", "eq", "12", "h2", ")", ")", NULL};
	
        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        cil_gen_constrain(test_db, test_tree->root->cl_head->cl_head, test_ast_node, CIL_MLSCONSTRAIN);

	struct cil_tree_node *test_current;
	test_current = test_tree->root->cl_head->cl_head;

	struct cil_constrain *test_copy;
	cil_constrain_init(&test_copy);

	cil_copy_constrain(test_db, (struct cil_constrain *)test_ast_node->data, &test_copy);
}

