/*
 * Copyright 2011 Tresys Technology, LLC. All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 *    1. Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 * 
 *    2. Redistributions in binary form must reproduce the above copyright notice,
 *       this list of conditions and the following disclaimer in the documentation
 *       and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY TRESYS TECHNOLOGY, LLC ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
 * EVENT SHALL TRESYS TECHNOLOGY, LLC OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 * The views and conclusions contained in the software and documentation are those
 * of the authors and should not be interpreted as representing official policies,
 * either expressed or implied, of Tresys Technology, LLC.
 */

#include "CuTest.h"
#include "CilTest.h"

#include "../../src/cil.h"
#include "../../src/cil_copy_ast.h"
#include "../../src/cil_build_ast.h"
#include "../../src/cil_resolve_ast.h"

int __cil_copy_node_helper(struct cil_tree_node *orig, uint32_t *finished, void *extra_args);
int __cil_copy_data_helper(struct cil_db *db, struct cil_tree_node *orig, struct cil_tree_node *new, symtab_t *symtab, uint32_t index, int (*copy_data)(struct cil_tree_node *orig_node, struct cil_tree_node *new_node, symtab_t *sym));

struct cil_args_copy {
	struct cil_tree_node *dest;
	struct cil_db *db;
};

struct cil_args_copy *gen_copy_args(struct cil_tree_node *node, struct cil_db *db)
{
	struct cil_args_copy *args = cil_malloc(sizeof(*args));
	args->dest = node;
	args->db = db;

	return args;
}

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
	char *line[] = {"(", "classcommon", "file", "file", NULL};

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

void test_cil_copy_sid(CuTest *tc) {
	char *line[] = {"(", "sid", "test", "(", "blah_u", "blah_r", "blah_t", "low", "high", ")", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	cil_gen_sid(test_db, test_tree->root->cl_head->cl_head, test_ast_node);

	struct cil_tree_node *test_copy;
	cil_tree_node_init(&test_copy);

	symtab_t sym;
	symtab_init(&sym, CIL_SYM_SIZE);

	int rc = cil_copy_sid(test_ast_node, test_copy, &sym);
	CuAssertIntEquals(tc, rc, SEPOL_OK);
	//CuAssertStrEquals(tc, ((struct cil_user *)test_copy->data)->datum.name, 
	//	((struct cil_user *)test_ast_node->data)->datum.name);
}

void test_cil_copy_sidcontext(CuTest *tc) {
	char *line[] = {"(", "sidcontext", "test", "(", "blah_u", "blah_r", "blah_t", "(", "low", "high", ")", ")", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	cil_gen_sidcontext(test_db, test_tree->root->cl_head->cl_head, test_ast_node);

	struct cil_tree_node *test_copy;
	cil_tree_node_init(&test_copy);

	symtab_t sym;
	symtab_init(&sym, CIL_SYM_SIZE);

	int rc = cil_copy_sidcontext(test_ast_node, test_copy, &sym);
	CuAssertIntEquals(tc, rc, SEPOL_OK);
	CuAssertStrEquals(tc, ((struct cil_user *)test_copy->data)->datum.name, 
		((struct cil_user *)test_ast_node->data)->datum.name);
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
	CuAssertStrEquals(tc, ((struct cil_user *)test_copy->data)->datum.name, 
		((struct cil_user *)test_ast_node->data)->datum.name);
}

void test_cil_copy_role(CuTest *tc) {
	char *line[] = {"(", "role", "role_r", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	cil_gen_role(test_db, test_tree->root->cl_head->cl_head, test_ast_node);

	struct cil_tree_node *test_copy;
	cil_tree_node_init(&test_copy);

	symtab_t sym;
	symtab_init(&sym, CIL_SYM_SIZE);

	int rc = cil_copy_role(test_ast_node, test_copy, &sym);
	CuAssertIntEquals(tc, rc, SEPOL_OK);
	CuAssertStrEquals(tc, ((struct cil_role *)test_copy->data)->datum.name, 
		((struct cil_role *)test_ast_node->data)->datum.name);
}

void test_cil_copy_userrole(CuTest *tc) {
	char *line[] = {"(", "userrole", "staff_u", "staff_r", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	cil_gen_userrole(test_db, test_tree->root->cl_head->cl_head, test_ast_node);

	struct cil_userrole *test_copy;
	cil_userrole_init(&test_copy);

	cil_copy_userrole((struct cil_userrole *)test_ast_node->data, &test_copy);
	CuAssertStrEquals(tc, ((struct cil_userrole *)test_ast_node->data)->user_str, test_copy->user_str);
	CuAssertStrEquals(tc, ((struct cil_userrole *)test_ast_node->data)->role_str, test_copy->role_str);
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

void test_cil_copy_typealias(CuTest *tc) {
	char *line[] = {"(", "typealias", ".test.type", "type_t", ")", "(", "type", "test", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	cil_gen_typealias(test_db, test_tree->root->cl_head->cl_head, test_ast_node);

	struct cil_tree_node *test_copy;
	cil_tree_node_init(&test_copy);

	symtab_t sym;
	symtab_init(&sym, CIL_SYM_SIZE);

	int rc = cil_copy_typealias(test_ast_node, test_copy, &sym);
	CuAssertIntEquals(tc, rc, SEPOL_OK);
	CuAssertStrEquals(tc, ((struct cil_typealias *)test_copy->data)->type_str,
		((struct cil_typealias *)test_ast_node->data)->type_str);
}

void test_cil_copy_bool(CuTest *tc) {
	char *line[] = {"(", "bool", "foo", "true", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	cil_gen_bool(test_db, test_tree->root->cl_head->cl_head, test_ast_node, CIL_BOOL);

	struct cil_tree_node *test_copy;
	cil_tree_node_init(&test_copy);

	symtab_t sym;
	symtab_init(&sym, CIL_SYM_SIZE);

	int rc = cil_copy_bool(test_ast_node, test_copy, &sym);
	CuAssertIntEquals(tc, rc, SEPOL_OK);
	CuAssertIntEquals(tc, ((struct cil_bool *)test_copy->data)->value,
		((struct cil_bool *)test_ast_node->data)->value);
	CuAssertStrEquals(tc, ((struct cil_bool *)test_copy->data)->datum.name,
		((struct cil_bool *)test_ast_node->data)->datum.name);
}

void test_cil_copy_type_rule(CuTest *tc) {
	char *line[] = {"(", "typetransition", "foo", "bar", "file", "foobar", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	cil_gen_type_rule(test_tree->root->cl_head->cl_head, test_ast_node, CIL_TYPE_TRANSITION);

	struct cil_type_rule *test_copy;
	cil_type_rule_init(&test_copy);

	cil_copy_type_rule((struct cil_type_rule *)test_ast_node->data, &test_copy);
	CuAssertIntEquals(tc, ((struct cil_type_rule *)test_ast_node->data)->rule_kind, test_copy->rule_kind);
	CuAssertStrEquals(tc, ((struct cil_type_rule *)test_ast_node->data)->src_str, test_copy->src_str);
	CuAssertStrEquals(tc, ((struct cil_type_rule *)test_ast_node->data)->tgt_str, test_copy->tgt_str);
	CuAssertStrEquals(tc, ((struct cil_type_rule *)test_ast_node->data)->obj_str, test_copy->obj_str);
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
	CuAssertIntEquals(tc, ((struct cil_avrule *)test_ast_node->data)->perms_list_str->head->flavor, test_copy->perms_list_str->head->flavor);
	CuAssertStrEquals(tc, (char*)((struct cil_avrule *)test_ast_node->data)->perms_list_str->head->data, (char*)test_copy->perms_list_str->head->data);
	CuAssertIntEquals(tc, ((struct cil_avrule *)test_ast_node->data)->perms_list_str->head->next->flavor, test_copy->perms_list_str->head->next->flavor);
	CuAssertStrEquals(tc, (char*)((struct cil_avrule *)test_ast_node->data)->perms_list_str->head->next->data, (char*)test_copy->perms_list_str->head->next->data);
}

void test_cil_copy_sens(CuTest *tc) {
	char *line[] = {"(", "sensitivity", "s0", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	cil_gen_sensitivity(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	
	struct cil_tree_node *test_copy;
	cil_tree_node_init(&test_copy);

	symtab_t sym;
	symtab_init(&sym, CIL_SYM_SIZE);

	int rc = cil_copy_sens(test_ast_node, test_copy, &sym);
	CuAssertIntEquals(tc, rc, SEPOL_OK);
	CuAssertStrEquals(tc, ((struct cil_sensalias *)test_copy->data)->datum.name, 
		((struct cil_sensalias *)test_ast_node->data)->datum.name);
}

void test_cil_copy_sensalias(CuTest *tc) {
	char *line[] = {"(", "sensitivityalias", "s0", "alias", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	test_ast_node->parent = test_db->ast->root;
	test_ast_node->line = 1;

	cil_gen_sensalias(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	
	struct cil_tree_node *test_copy;
	cil_tree_node_init(&test_copy);

	symtab_t sym;
	symtab_init(&sym, CIL_SYM_SIZE);

	int rc = cil_copy_sensalias(test_ast_node, test_copy, &sym);
	CuAssertIntEquals(tc, rc, SEPOL_OK);
	CuAssertStrEquals(tc, ((struct cil_sensalias *)test_copy->data)->sens_str,
		((struct cil_sensalias *)test_ast_node->data)->sens_str);
	CuAssertStrEquals(tc, ((struct cil_sensalias *)test_copy->data)->datum.name, 
		((struct cil_sensalias *)test_ast_node->data)->datum.name);
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

void test_cil_copy_senscat(CuTest *tc) {
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

        cil_gen_senscat(test_db, test_tree->root->cl_head->next->next->next->next->next->next->cl_head, test_ast_node);

	struct cil_senscat *test_copy;
	cil_senscat_init(&test_copy);

	cil_copy_senscat((struct cil_senscat *)test_ast_node->data, &test_copy);
	CuAssertStrEquals(tc, ((struct cil_senscat *)test_ast_node->data)->sens_str, test_copy->sens_str);
	CuAssertStrEquals(tc, (char*)((struct cil_senscat *)test_ast_node->data)->cat_list_str->head->data, (char*)test_copy->cat_list_str->head->data);
	CuAssertStrEquals(tc, (char*)((struct cil_senscat *)test_ast_node->data)->cat_list_str->head->next->data, (char*)test_copy->cat_list_str->head->next->data);
}

void test_cil_copy_catorder(CuTest *tc) {
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

	cil_gen_catorder(test_db, test_tree->root->cl_head->next->next->cl_head, test_ast_node);

	struct cil_catorder *test_copy;
	cil_catorder_init(&test_copy);

	cil_copy_catorder((struct cil_catorder *)test_ast_node->data, &test_copy);
	CuAssertStrEquals(tc, (char*)((struct cil_catorder *)test_ast_node->data)->cat_list_str->head->data, (char*)test_copy->cat_list_str->head->data);
	CuAssertStrEquals(tc, (char*)((struct cil_catorder *)test_ast_node->data)->cat_list_str->head->next->data, (char*)test_copy->cat_list_str->head->next->data);
}

void test_cil_copy_dominance(CuTest *tc) {
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

        cil_gen_dominance(test_db, test_tree->root->cl_head->next->next->next->cl_head, test_ast_node);

	struct cil_sens_dominates *test_copy;
	cil_sens_dominates_init(&test_copy);

	cil_copy_dominance((struct cil_sens_dominates*)test_ast_node->data, &test_copy);
	CuAssertStrEquals(tc, (char*)((struct cil_sens_dominates *)test_ast_node->data)->sens_list_str->head->data, (char*)test_copy->sens_list_str->head->data);
	CuAssertStrEquals(tc, (char*)((struct cil_sens_dominates *)test_ast_node->data)->sens_list_str->head->next->data, (char*)test_copy->sens_list_str->head->next->data);
}

void test_cil_copy_level(CuTest *tc) {
	char *line[] = {"(", "level", "low", "(", "s0", "(", "c1", ")", ")", ")", NULL};

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
	char *line[] = {"(", "level", "low", "(", "s0", "(", "c1", ")", ")", ")", NULL};

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

void test_cil_copy_netifcon(CuTest *tc) {
	char *line[] = {"(", "netifcon", "eth0", "if_default", "packet_default", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        cil_gen_netifcon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	
	struct cil_tree_node *test_copy;
	cil_tree_node_init(&test_copy);

	symtab_t sym;
	symtab_init(&sym, CIL_SYM_SIZE);

	int rc = cil_copy_netifcon(test_ast_node, test_copy, &sym);
	CuAssertIntEquals(tc, rc, SEPOL_OK);
	CuAssertStrEquals(tc, ((struct cil_netifcon *)test_copy->data)->interface_str, 
		((struct cil_netifcon *)test_ast_node->data)->interface_str);
	CuAssertStrEquals(tc, ((struct cil_netifcon *)test_copy->data)->if_context_str,
		((struct cil_netifcon *)test_ast_node->data)->if_context_str);
	CuAssertStrEquals(tc, ((struct cil_netifcon *)test_copy->data)->packet_context_str,
		((struct cil_netifcon *)test_ast_node->data)->packet_context_str);
}

void test_cil_copy_netifcon_nested(CuTest *tc) {
	char *line[] = {"(", "netifcon", "eth1", 
			"(", "system_u", "object_r", "netif_t", "(", "low", "high", ")", ")",
			"(", "system_u", "object_r", "netif_t", "(", "low", "high", ")", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        cil_gen_netifcon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	
	struct cil_tree_node *test_copy;
	cil_tree_node_init(&test_copy);

	symtab_t sym;
	symtab_init(&sym, CIL_SYM_SIZE);

	int rc = cil_copy_netifcon(test_ast_node, test_copy, &sym);
	CuAssertIntEquals(tc, rc, SEPOL_OK);
	CuAssertStrEquals(tc, ((struct cil_netifcon*)test_copy->data)->interface_str, 
		((struct cil_netifcon *)test_ast_node->data)->interface_str);
	CuAssertStrEquals(tc, ((struct cil_netifcon *)test_copy->data)->if_context_str,
		((struct cil_netifcon *)test_ast_node->data)->if_context_str);
	CuAssertStrEquals(tc, ((struct cil_netifcon *)test_copy->data)->packet_context_str,
		((struct cil_netifcon *)test_ast_node->data)->packet_context_str);
	CuAssertStrEquals(tc, ((struct cil_netifcon *)test_copy->data)->packet_context->user_str,
		((struct cil_netifcon *)test_ast_node->data)->packet_context->user_str);
	CuAssertStrEquals(tc, ((struct cil_netifcon *)test_copy->data)->packet_context->role_str,
		((struct cil_netifcon *)test_ast_node->data)->packet_context->role_str);
	CuAssertStrEquals(tc, ((struct cil_netifcon *)test_copy->data)->packet_context->type_str,
		((struct cil_netifcon *)test_ast_node->data)->packet_context->type_str);
	CuAssertStrEquals(tc, ((struct cil_netifcon *)test_copy->data)->packet_context->range_str,
		((struct cil_netifcon *)test_ast_node->data)->packet_context->range_str);
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
	CuAssertStrEquals(tc, ((struct cil_context *)test_copy->data)->range_str,
		((struct cil_context *)test_ast_node->data)->range_str);
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
	CuAssertStrEquals(tc, ((struct cil_context *)test_copy->data)->range_str,
		((struct cil_context *)test_ast_node->data)->range_str);
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
	CuAssertStrEquals(tc, ((struct cil_context *)test_copy->data)->range_str,
		((struct cil_context *)test_ast_node->data)->range_str);
}

void test_cil_copy_call(CuTest *tc) {
	char *line[] = {"(", "call", "mm", "(", "foo", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        cil_gen_call(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	
	struct cil_call *test_copy;
	cil_call_init(&test_copy);

	cil_copy_call(test_db, (struct cil_call *)test_ast_node->data, &test_copy);
	CuAssertStrEquals(tc, test_copy->macro_str, ((struct cil_call *)test_ast_node->data)->macro_str);
}

void test_cil_copy_optional(CuTest *tc) {
	char *line[] = {"(", "optional", "opt", "(", "allow", "foo", "bar", "baz", "file", "(", "read", ")", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        cil_gen_optional(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	
	struct cil_tree_node *test_copy;
	cil_tree_node_init(&test_copy);

	symtab_t sym;
	symtab_init(&sym, CIL_SYM_SIZE);

	int rc = cil_copy_optional(test_ast_node, test_copy, &sym);
	CuAssertIntEquals(tc, rc, SEPOL_OK);
	CuAssertStrEquals(tc, ((struct cil_optional *)test_copy->data)->datum.name, 
		((struct cil_optional *)test_ast_node->data)->datum.name);
}

void test_cil_copy_nodecon(CuTest *tc) {
	char *line[] = {"(", "nodecon", "ipaddr", "ipaddr", "con", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        cil_gen_nodecon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);

	struct cil_nodecon *test_copy;
	cil_nodecon_init(&test_copy);

	int rc = cil_copy_nodecon((struct cil_nodecon *)test_ast_node->data, &test_copy);
	CuAssertIntEquals(tc, rc, SEPOL_OK);
}

void test_cil_copy_nodecon_anon(CuTest *tc) {
	char *line[] = {"(", "nodecon", "(", "192.168.1.1", ")", "(", "192.168.1.1", ")", "(", "user", "role", "type", "(", "low", "high", ")", ")", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        cil_gen_nodecon(test_db, test_tree->root->cl_head->cl_head, test_ast_node);

	struct cil_nodecon *test_copy;
	cil_nodecon_init(&test_copy);

	int rc = cil_copy_nodecon((struct cil_nodecon *)test_ast_node->data, &test_copy);
	CuAssertIntEquals(tc, rc, SEPOL_OK);
}

void test_cil_copy_fill_ipaddr(CuTest *tc) {
	char *line[] = {"(", "ipaddr", "ip", "192.168.1.1", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        cil_gen_ipaddr(test_db, test_tree->root->cl_head->cl_head, test_ast_node);
	
	symtab_t sym;
	symtab_init(&sym, CIL_SYM_SIZE);

	struct cil_ipaddr *new;
	cil_ipaddr_init(&new);
	struct cil_ipaddr *old;
	cil_ipaddr_init(&new);

	old = (struct cil_ipaddr*)test_ast_node->data;
	cil_copy_fill_ipaddr(old, new);

	CuAssertIntEquals(tc, old->family, new->family);
}

void test_cil_copy_ipaddr(CuTest *tc) {
	char *line[] = {"(", "ipaddr", "ip", "192.168.1.1", ")", NULL};

        struct cil_tree *test_tree;
        gen_test_tree(&test_tree, line);

        struct cil_tree_node *test_ast_node;
        cil_tree_node_init(&test_ast_node);

        struct cil_db *test_db;
        cil_db_init(&test_db);

        test_ast_node->parent = test_db->ast->root;
        test_ast_node->line = 1;

        cil_gen_ipaddr(test_db, test_tree->root->cl_head->cl_head, test_ast_node);

	struct cil_tree_node *test_copy;
	cil_tree_node_init(&test_copy);

	symtab_t sym;
	symtab_init(&sym, CIL_SYM_SIZE);

	int rc = cil_copy_ipaddr(test_ast_node, test_copy, &sym);
	CuAssertIntEquals(tc, rc, SEPOL_OK);
}

void test_cil_copy_conditional(CuTest *tc) {
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

	cil_gen_boolif(test_db, test_tree->root->cl_head->cl_head, test_ast_node);

	struct cil_list_item *curr_old;
	curr_old = ((struct cil_booleanif*)test_ast_node->data)->expr_stack->head;

	struct cil_conditional *cond_new;
	cil_conditional_init(&cond_new);
	cil_copy_conditional(curr_old->data, cond_new);

	CuAssertStrEquals(tc, ((struct cil_conditional*)curr_old->data)->str, cond_new->str);
	CuAssertIntEquals(tc, ((struct cil_conditional*)curr_old->data)->flavor, cond_new->flavor);
}

void test_cil_copy_boolif(CuTest *tc) {
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

	cil_gen_boolif(test_db, test_tree->root->cl_head->cl_head, test_ast_node);

	struct cil_booleanif *test_copy;
	cil_boolif_init(&test_copy);

	int rc = cil_copy_boolif((struct cil_booleanif *)test_ast_node->data, &test_copy);
	CuAssertIntEquals(tc, rc, SEPOL_OK);
}

void test_cil_copy_constrain(CuTest *tc) {
	char *line[] = {"(", "mlsconstrain", "(", "file", "dir", ")", "(", "create", "relabelto", ")", "(", "eq", "l2", "h2", ")", ")", NULL};
	
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

	cil_copy_constrain((struct cil_constrain *)test_ast_node->data, &test_copy);
	CuAssertStrEquals(tc, (char*)test_copy->class_list_str->head->data, (char*)((struct cil_constrain *)test_ast_node->data)->class_list_str->head->data);
}
/*
void test_cil_copy_ast(CuTest *tc) {
	char *line[] = {"(", "mlsconstrain", "(", "file", "dir", ")", "(", "create", "relabelto", ")", "(", "eq", "l2", "h2", ")", ")", NULL};
	
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
	cil_list_init(&test_copy->expr);

	int rc = cil_copy_ast(((struct cil_constrain *)test_ast_node->data)->expr, test_copy->expr);
	CuAssertIntEquals(tc, rc, SEPOL_OK);
}

void test_cil_copy_ast_neg(CuTest *tc) {
	char *line[] = {"(", "mlsconstrain", ")", NULL};
	
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
	cil_list_init(&test_copy->expr);

	int rc = cil_copy_ast(((struct cil_constrain *)test_ast_node->data)->expr, test_copy->expr);
	CuAssertIntEquals(tc, rc, SEPOL_ERR);
}
*/
/* node_helper functions */

void test_cil_copy_node_helper_block(CuTest *tc) {
	char *line[] = {"(", "block", "a", "(", "type", "log", ")", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_db *test_db2;
	cil_db_init(&test_db2);

	uint32_t finished = 0;

	struct cil_args_copy *extra_args = gen_copy_args(test_db2->ast->root, test_db2);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	int rc = __cil_copy_node_helper(test_db->ast->root->cl_head, &finished, extra_args);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_copy_node_helper_block_neg(CuTest *tc) {
	char *line[] = {"(", "block", "a", "(", "type", "log", ")", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_args_copy *extra_args = gen_copy_args(test_db->ast->root, test_db);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	int rc = __cil_copy_node_helper(test_db->ast->root->cl_head, &finished, extra_args);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_EEXIST, rc);
}

void test_cil_copy_node_helper_perm(CuTest *tc) {
	char *line[] = {"(", "class", "foo", "(", "read", "write", "open", ")", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_db *test_db2;
	cil_db_init(&test_db2);

	uint32_t finished = 0;

	struct cil_class *test_class;
	cil_class_init(&test_class);
	
	struct cil_tree_node *parent_node;
	cil_tree_node_init(&parent_node);
	parent_node->flavor = CIL_CLASS;
	parent_node->data = test_class;

	struct cil_args_copy *extra_args = gen_copy_args(parent_node, test_db2);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	int rc = __cil_copy_node_helper(test_db->ast->root->cl_head->cl_head, &finished, extra_args);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_copy_node_helper_perm_neg(CuTest *tc) {
	char *line[] = {"(", "class", "foo", "(", "read", "write", "open", ")", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_args_copy *extra_args = gen_copy_args(test_db->ast->root, test_db);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	int rc = __cil_copy_node_helper(test_db->ast->root->cl_head->cl_head, &finished, extra_args);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_copy_node_helper_class(CuTest *tc) {
	char *line[] = {"(", "class", "file", "(", "read", "write", "open", ")", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_db *test_db2;
	cil_db_init(&test_db2);

	uint32_t finished = 0;

	struct cil_args_copy *extra_args = gen_copy_args(test_db2->ast->root, test_db2);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	int rc = __cil_copy_node_helper(test_db->ast->root->cl_head, &finished, extra_args);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_copy_node_helper_class_neg(CuTest *tc) {
	char *line[] = {"(", "common", "test", "(", "read", "write", ")", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_args_copy *extra_args = gen_copy_args(test_db->ast->root, test_db);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	int rc = __cil_copy_node_helper(test_db->ast->root->cl_head, &finished, extra_args);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_EEXIST, rc);
}

void test_cil_copy_node_helper_common(CuTest *tc) {
	char *line[] = {"(", "common", "test", "(", "read", "write", ")", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_db *test_db2;
	cil_db_init(&test_db2);

	uint32_t finished = 0;

	struct cil_args_copy *extra_args = gen_copy_args(test_db2->ast->root, test_db2);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	int rc = __cil_copy_node_helper(test_db->ast->root->cl_head, &finished, extra_args);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_copy_node_helper_common_neg(CuTest *tc) {
	char *line[] = {"(", "class", "file", "(", "read", "write", "open", ")", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_args_copy *extra_args = gen_copy_args(test_db->ast->root, test_db);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	int rc = __cil_copy_node_helper(test_db->ast->root->cl_head, &finished, extra_args);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_EEXIST, rc);
}

void test_cil_copy_node_helper_classcommon(CuTest *tc) {
	char *line[] = {"(", "classcommon", "file", "file", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_db *test_db2;
	cil_db_init(&test_db2);

	uint32_t finished = 0;

	struct cil_args_copy *extra_args = gen_copy_args(test_db2->ast->root, test_db2);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	int rc = __cil_copy_node_helper(test_db->ast->root->cl_head, &finished, extra_args);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_copy_node_helper_sid(CuTest *tc) {
	char *line[] = {"(", "sid", "test", "(", "blah_u", "blah_r", "blah_t", "low", "high", ")", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_db *test_db2;
	cil_db_init(&test_db2);

	uint32_t finished = 0;

	struct cil_args_copy *extra_args = gen_copy_args(test_db2->ast->root, test_db2);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	int rc = __cil_copy_node_helper(test_db->ast->root->cl_head, &finished, extra_args);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_copy_node_helper_sid_neg(CuTest *tc) {
	char *line[] = {"(", "sid", "test", "(", "blah_u", "blah_r", "blah_t", "low", "high", ")", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_args_copy *extra_args = gen_copy_args(test_db->ast->root, test_db);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	int rc = __cil_copy_node_helper(test_db->ast->root->cl_head, &finished, extra_args);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_EEXIST, rc);
}

void test_cil_copy_node_helper_sidcontext(CuTest *tc) {
	char *line[] = {"(", "sidcontext", "test", "(", "blah_u", "blah_r", "blah_t", "(", "low", "high", ")", ")", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_db *test_db2;
	cil_db_init(&test_db2);

	uint32_t finished = 0;

	struct cil_args_copy *extra_args = gen_copy_args(test_db2->ast->root, test_db2);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	int rc = __cil_copy_node_helper(test_db->ast->root->cl_head, &finished, extra_args);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_copy_node_helper_user(CuTest *tc) {
	char *line[] = {"(", "user", "sysadm", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_db *test_db2;
	cil_db_init(&test_db2);

	uint32_t finished = 0;

	struct cil_args_copy *extra_args = gen_copy_args(test_db2->ast->root, test_db2);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	int rc = __cil_copy_node_helper(test_db->ast->root->cl_head, &finished, extra_args);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_copy_node_helper_user_neg(CuTest *tc) {
	char *line[] = {"(", "user", "sysadm", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_args_copy *extra_args = gen_copy_args(test_db->ast->root, test_db);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	int rc = __cil_copy_node_helper(test_db->ast->root->cl_head, &finished, extra_args);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_EEXIST, rc);
}

void test_cil_copy_node_helper_role(CuTest *tc) {
	char *line[] = {"(", "role", "role_r", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_db *test_db2;
	cil_db_init(&test_db2);

	uint32_t finished = 0;

	struct cil_args_copy *extra_args = gen_copy_args(test_db2->ast->root, test_db2);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	int rc = __cil_copy_node_helper(test_db->ast->root->cl_head, &finished, extra_args);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_copy_node_helper_role_neg(CuTest *tc) {
	char *line[] = {"(", "role", "role_r", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_args_copy *extra_args = gen_copy_args(test_db->ast->root, test_db);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	int rc = __cil_copy_node_helper(test_db->ast->root->cl_head, &finished, extra_args);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_EEXIST, rc);
}

void test_cil_copy_node_helper_userrole(CuTest *tc) {
	char *line[] = {"(", "userrole", "staff_u", "staff_r", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_db *test_db2;
	cil_db_init(&test_db2);

	uint32_t finished = 0;

	struct cil_args_copy *extra_args = gen_copy_args(test_db2->ast->root, test_db2);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	int rc = __cil_copy_node_helper(test_db->ast->root->cl_head, &finished, extra_args);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_copy_node_helper_type(CuTest *tc) {
	char *line[] = {"(", "type", "type_t", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_db *test_db2;
	cil_db_init(&test_db2);

	uint32_t finished = 0;

	struct cil_args_copy *extra_args = gen_copy_args(test_db2->ast->root, test_db2);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	int rc = __cil_copy_node_helper(test_db->ast->root->cl_head, &finished, extra_args);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_copy_node_helper_type_neg(CuTest *tc) {
	char *line[] = {"(", "type", "type_t", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_args_copy *extra_args = gen_copy_args(test_db->ast->root, test_db);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	int rc = __cil_copy_node_helper(test_db->ast->root->cl_head, &finished, extra_args);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_EEXIST, rc);
}

void test_cil_copy_node_helper_attr(CuTest *tc) {
	char *line[] = {"(", "attribute", "bar", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_db *test_db2;
	cil_db_init(&test_db2);

	uint32_t finished = 0;

	struct cil_args_copy *extra_args = gen_copy_args(test_db2->ast->root, test_db2);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	int rc = __cil_copy_node_helper(test_db->ast->root->cl_head, &finished, extra_args);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_copy_node_helper_attr_neg(CuTest *tc) {
	char *line[] = {"(", "attribute", "bar", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_args_copy *extra_args = gen_copy_args(test_db->ast->root, test_db);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	int rc = __cil_copy_node_helper(test_db->ast->root->cl_head, &finished, extra_args);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_EEXIST, rc);
}

void test_cil_copy_node_helper_typealias(CuTest *tc) {
	char *line[] = {"(", "typealias", ".test.type", "type_t", ")", "(", "type", "test", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_db *test_db2;
	cil_db_init(&test_db2);

	uint32_t finished = 0;

	struct cil_args_copy *extra_args = gen_copy_args(test_db2->ast->root, test_db2);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	int rc = __cil_copy_node_helper(test_db->ast->root->cl_head, &finished, extra_args);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_copy_node_helper_typealias_neg(CuTest *tc) {
	char *line[] = {"(", "typealias", ".test.type", "type_t", ")", "(", "type", "test", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_args_copy *extra_args = gen_copy_args(test_db->ast->root, test_db);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	int rc = __cil_copy_node_helper(test_db->ast->root->cl_head, &finished, extra_args);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_EEXIST, rc);
}

void test_cil_copy_node_helper_bool(CuTest *tc) {
	char *line[] = {"(", "bool", "foo", "true", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_db *test_db2;
	cil_db_init(&test_db2);

	uint32_t finished = 0;

	struct cil_args_copy *extra_args = gen_copy_args(test_db2->ast->root, test_db2);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	int rc = __cil_copy_node_helper(test_db->ast->root->cl_head, &finished, extra_args);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_copy_node_helper_bool_neg(CuTest *tc) {
	char *line[] = {"(", "bool", "foo", "true", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_args_copy *extra_args = gen_copy_args(test_db->ast->root, test_db);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	int rc = __cil_copy_node_helper(test_db->ast->root->cl_head, &finished, extra_args);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_EEXIST, rc);
}

void test_cil_copy_node_helper_avrule(CuTest *tc) {
	char *line[] = {"(", "allow", "test", "foo", "bar", "(", "read", "write", ")", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_db *test_db2;
	cil_db_init(&test_db2);

	uint32_t finished = 0;

	struct cil_args_copy *extra_args = gen_copy_args(test_db2->ast->root, test_db2);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	int rc = __cil_copy_node_helper(test_db->ast->root->cl_head, &finished, extra_args);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_copy_node_helper_type_rule(CuTest *tc) {
	char *line[] = {"(", "typetransition", "foo", "bar", "file", "foobar", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_db *test_db2;
	cil_db_init(&test_db2);

	uint32_t finished = 0;

	struct cil_args_copy *extra_args = gen_copy_args(test_db2->ast->root, test_db2);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	int rc = __cil_copy_node_helper(test_db->ast->root->cl_head, &finished, extra_args);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_copy_node_helper_sens(CuTest *tc) {
	char *line[] = {"(", "sensitivity", "s0", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_db *test_db2;
	cil_db_init(&test_db2);

	uint32_t finished = 0;

	struct cil_args_copy *extra_args = gen_copy_args(test_db2->ast->root, test_db2);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	int rc = __cil_copy_node_helper(test_db->ast->root->cl_head, &finished, extra_args);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_copy_node_helper_sens_neg(CuTest *tc) {
	char *line[] = {"(", "sensitivity", "s0", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_args_copy *extra_args = gen_copy_args(test_db->ast->root, test_db);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	int rc = __cil_copy_node_helper(test_db->ast->root->cl_head, &finished, extra_args);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_EEXIST, rc);
}

void test_cil_copy_node_helper_sensalias(CuTest *tc) {
	char *line[] = {"(", "sensitivityalias", "s0", "alias", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_db *test_db2;
	cil_db_init(&test_db2);

	uint32_t finished = 0;

	struct cil_args_copy *extra_args = gen_copy_args(test_db2->ast->root, test_db2);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	int rc = __cil_copy_node_helper(test_db->ast->root->cl_head, &finished, extra_args);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_copy_node_helper_sensalias_neg(CuTest *tc) {
	char *line[] = {"(", "sensitivityalias", "s0", "alias", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_args_copy *extra_args = gen_copy_args(test_db->ast->root, test_db);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	int rc = __cil_copy_node_helper(test_db->ast->root->cl_head, &finished, extra_args);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_EEXIST, rc);
}

void test_cil_copy_node_helper_cat(CuTest *tc) {
	char *line[] = {"(", "category", "c0", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_db *test_db2;
	cil_db_init(&test_db2);

	uint32_t finished = 0;

	struct cil_args_copy *extra_args = gen_copy_args(test_db2->ast->root, test_db2);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	int rc = __cil_copy_node_helper(test_db->ast->root->cl_head, &finished, extra_args);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_copy_node_helper_cat_neg(CuTest *tc) {
	char *line[] = {"(", "category", "c0", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_args_copy *extra_args = gen_copy_args(test_db->ast->root, test_db);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	int rc = __cil_copy_node_helper(test_db->ast->root->cl_head, &finished, extra_args);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_EEXIST, rc);
}

void test_cil_copy_node_helper_catalias(CuTest *tc) {
	char *line[] = {"(", "categoryalias", "c0", "red", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_db *test_db2;
	cil_db_init(&test_db2);

	uint32_t finished = 0;

	struct cil_args_copy *extra_args = gen_copy_args(test_db2->ast->root, test_db2);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	int rc = __cil_copy_node_helper(test_db->ast->root->cl_head, &finished, extra_args);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_copy_node_helper_catalias_neg(CuTest *tc) {
	char *line[] = {"(", "categoryalias", "c0", "red", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_args_copy *extra_args = gen_copy_args(test_db->ast->root, test_db);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	int rc = __cil_copy_node_helper(test_db->ast->root->cl_head, &finished, extra_args);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_EEXIST, rc);
}

void test_cil_copy_node_helper_senscat(CuTest *tc) {
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

	struct cil_db *test_db2;
	cil_db_init(&test_db2);

	uint32_t finished = 0;

	struct cil_senscat *test_senscat;
	cil_senscat_init(&test_senscat);
	
	struct cil_tree_node *parent_node;
	cil_tree_node_init(&parent_node);
	parent_node->flavor = CIL_SENSCAT;
	parent_node->data = test_senscat;

	struct cil_args_copy *extra_args = gen_copy_args(parent_node, test_db2);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	int rc = __cil_copy_node_helper(test_db->ast->root->cl_head->next->next->next->next->next->next, &finished, extra_args);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_copy_node_helper_catorder(CuTest *tc) {
	char *line[] = {"(", "category", "c0", ")",
			"(", "category", "c255", ")",
			"(", "categoryorder", "(", "c0", "c255", ")", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_db *test_db2;
	cil_db_init(&test_db2);

	uint32_t finished = 0;

	struct cil_catorder *test_catorder;
	cil_catorder_init(&test_catorder);
	
	struct cil_tree_node *parent_node;
	cil_tree_node_init(&parent_node);
	parent_node->flavor = CIL_CATORDER;
	parent_node->data = test_catorder;

	struct cil_args_copy *extra_args = gen_copy_args(parent_node, test_db2);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	int rc = __cil_copy_node_helper(test_db->ast->root->cl_head->next->next, &finished, extra_args);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_copy_node_helper_dominance(CuTest *tc) {
        char *line[] = {"(", "sensitivity", "s0", ")",
                        "(", "sensitivity", "s1", ")",
                        "(", "sensitivity", "s2", ")",
                        "(", "dominance", "(", "s0", "s1", ")", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_db *test_db2;
	cil_db_init(&test_db2);

	uint32_t finished = 0;

	struct cil_sens *test_sens;
	cil_sens_init(&test_sens);
	
	struct cil_tree_node *parent_node;
	cil_tree_node_init(&parent_node);
	parent_node->flavor = CIL_SENS;
	parent_node->data = test_sens;

	struct cil_args_copy *extra_args = gen_copy_args(parent_node, test_db2);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	int rc = __cil_copy_node_helper(test_db->ast->root->cl_head->next->next->next, &finished, extra_args);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_copy_node_helper_level(CuTest *tc) {
	char *line[] = {"(", "level", "low", "(", "s0", "(", "c1", ")", ")", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_db *test_db2;
	cil_db_init(&test_db2);

	uint32_t finished = 0;

	struct cil_args_copy *extra_args = gen_copy_args(test_db2->ast->root, test_db2);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	int rc = __cil_copy_node_helper(test_db->ast->root->cl_head, &finished, extra_args);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_copy_node_helper_level_neg(CuTest *tc) {
	char *line[] = {"(", "level", "low", "(", "s0", "(", "c1", ")", ")", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_args_copy *extra_args = gen_copy_args(test_db->ast->root, test_db);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	int rc = __cil_copy_node_helper(test_db->ast->root->cl_head, &finished, extra_args);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_EEXIST, rc);
}

void test_cil_copy_node_helper_context(CuTest *tc) {
	char *line[] = {"(", "context", "packet_default", "(", "system_u", "object_r", "etc_t", "low", "high", ")", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_db *test_db2;
	cil_db_init(&test_db2);

	uint32_t finished = 0;

	struct cil_args_copy *extra_args = gen_copy_args(test_db2->ast->root, test_db2);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	int rc = __cil_copy_node_helper(test_db->ast->root->cl_head, &finished, extra_args);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_copy_node_helper_context_neg(CuTest *tc) {
	char *line[] = {"(", "context", "packet_default", "(", "system_u", "object_r", "etc_t", "low", "high", ")", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_args_copy *extra_args = gen_copy_args(test_db->ast->root, test_db);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	int rc = __cil_copy_node_helper(test_db->ast->root->cl_head, &finished, extra_args);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_EEXIST, rc);
}

void test_cil_copy_node_helper_netifcon(CuTest *tc) {
	char *line[] = {"(", "netifcon", "eth0", "if_default", "packet_default", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_db *test_db2;
	cil_db_init(&test_db2);

	uint32_t finished = 0;

	struct cil_args_copy *extra_args = gen_copy_args(test_db2->ast->root, test_db2);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	int rc = __cil_copy_node_helper(test_db->ast->root->cl_head, &finished, extra_args);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_copy_node_helper_call(CuTest *tc) {
	char *line[] = {"(", "call", "mm", "(", "foo", ")", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_db *test_db2;
	cil_db_init(&test_db2);

	uint32_t finished = 0;

	struct cil_args_copy *extra_args = gen_copy_args(test_db2->ast->root, test_db2);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	int rc = __cil_copy_node_helper(test_db->ast->root->cl_head, &finished, extra_args);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_copy_node_helper_optional(CuTest *tc) {
	char *line[] = {"(", "optional", "opt", "(", "allow", "foo", "bar", "baz", "file", "(", "read", ")", ")", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_db *test_db2;
	cil_db_init(&test_db2);

	uint32_t finished = 0;

	struct cil_args_copy *extra_args = gen_copy_args(test_db2->ast->root, test_db2);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	int rc = __cil_copy_node_helper(test_db->ast->root->cl_head, &finished, extra_args);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_copy_node_helper_optional_neg(CuTest *tc) {
	char *line[] = {"(", "optional", "opt", "(", "allow", "foo", "bar", "baz", "file", "(", "read", ")", ")", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_args_copy *extra_args = gen_copy_args(test_db->ast->root, test_db);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	int rc = __cil_copy_node_helper(test_db->ast->root->cl_head, &finished, extra_args);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_EEXIST, rc);
}

void test_cil_copy_node_helper_ipaddr(CuTest *tc) {
	char *line[] = {"(", "ipaddr", "ip", "192.168.1.1", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_db *test_db2;
	cil_db_init(&test_db2);

	uint32_t finished = 0;

	struct cil_args_copy *extra_args = gen_copy_args(test_db2->ast->root, test_db2);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	int rc = __cil_copy_node_helper(test_db->ast->root->cl_head, &finished, extra_args);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_copy_node_helper_ipaddr_neg(CuTest *tc) {
	char *line[] = {"(", "ipaddr", "ip", "192.168.1.1", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	uint32_t finished = 0;

	struct cil_args_copy *extra_args = gen_copy_args(test_db->ast->root, test_db);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	int rc = __cil_copy_node_helper(test_db->ast->root->cl_head, &finished, extra_args);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_EEXIST, rc);
}

void test_cil_copy_node_helper_boolif(CuTest *tc) {
	char *line[] = {"(", "booleanif", "(", "&&", "foo", "bar", ")",
			"(", "allow", "foo", "bar", "(", "read", ")", ")", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_db *test_db2;
	cil_db_init(&test_db2);

	uint32_t finished = 0;

	struct cil_args_copy *extra_args = gen_copy_args(test_db2->ast->root, test_db2);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	int rc = __cil_copy_node_helper(test_db->ast->root->cl_head, &finished, extra_args);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_copy_node_helper_mlsconstrain(CuTest *tc) {
	char *line[] = {"(", "mlsconstrain", "(", "file", "dir", ")", "(", "create", "relabelto", ")", "(", "eq", "l1", "l2", ")", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_db *test_db2;
	cil_db_init(&test_db2);

	uint32_t finished = 0;

	struct cil_args_copy *extra_args = gen_copy_args(test_db2->ast->root, test_db2);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	int rc = __cil_copy_node_helper(test_db->ast->root->cl_head, &finished, extra_args);
	CuAssertIntEquals(tc, finished, 0);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_copy_node_helper_orignull_neg(CuTest *tc) {
	char *line[] = {"(", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_db *test_db2;
	cil_db_init(&test_db2);

	uint32_t finished = 0;

	struct cil_args_copy *extra_args = gen_copy_args(test_db2->ast->root, test_db2);
	
	int rc = __cil_copy_node_helper(test_db->ast->root->cl_head, &finished, extra_args);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_copy_node_helper_extraargsnull_neg(CuTest *tc) {
	char *line[] = {"(", "mlsconstrain", "(", "file", "dir", ")", "(", "create", "relabelto", ")", "(", "eq", "l1", "l2", ")", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_db *test_db2;
	cil_db_init(&test_db2);

	struct cil_args_copy *extra_args = NULL;

	uint32_t finished = 0;

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	int rc = __cil_copy_node_helper(test_db->ast->root->cl_head, &finished, extra_args);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}


void test_cil_copy_data_helper(CuTest *tc) {
	char *line[] = {"(", "user", "sysadm", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_db *test_db2;
	cil_db_init(&test_db2);

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	struct cil_tree_node *orig = test_db->ast->root->cl_head;
	
	struct cil_tree_node *new;
	cil_tree_node_init(&new);
	new->parent = test_db2->ast->root;
	new->line = orig->line;
	new->flavor = orig->flavor;

	struct cil_db *db = test_db2;

	symtab_t *symtab = NULL;

	int rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_USERS, &cil_copy_user);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_copy_data_helper_getparentsymtab_neg(CuTest *tc) {
	char *line[] = {"(", "user", "sysadm", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_db *test_db2;
	cil_db_init(&test_db2);

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	struct cil_tree_node *orig = test_db->ast->root->cl_head;
	
	struct cil_tree_node *new;
	cil_tree_node_init(&new);
	new->parent = test_db2->ast->root;
	new->line = orig->line;
	new->flavor = orig->flavor;

	struct cil_db *db = test_db2;

	symtab_t *symtab = NULL;

	int rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_USER, &cil_copy_user);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_copy_data_helper_duplicatedb_neg(CuTest *tc) {
	char *line[] = {"(", "user", "sysadm", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	struct cil_tree_node *orig = test_db->ast->root->cl_head;
	
	struct cil_tree_node *new;
	cil_tree_node_init(&new);
	new->parent = test_db->ast->root;
	new->line = orig->line;
	new->flavor = orig->flavor;

	symtab_t *symtab = NULL;

	int rc = __cil_copy_data_helper(test_db, orig, new, symtab, CIL_SYM_USERS, &cil_copy_user);
	CuAssertIntEquals(tc, SEPOL_EEXIST, rc);
}

