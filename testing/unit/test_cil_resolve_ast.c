#include <sepol/policydb/policydb.h>

#include "CuTest.h"
#include "CilTest.h"

#include "../../src/cil_build_ast.h"
#include "../../src/cil_resolve_ast.h"

int __cil_resolve_ast_node_helper(struct cil_tree_node *, uint32_t *, struct cil_list *);

void test_cil_resolve_name(CuTest *tc) {
	char *line[] = { "(", "block", "foo", 
				"(", "typealias", "test", "type_t", ")", 
				"(", "type", "test", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	struct cil_tree_node *test_curr = test_db->ast->root->cl_head->cl_head;
	struct cil_typealias *test_alias = (struct cil_typealias*)test_curr->data;
	struct cil_tree_node *type_node = NULL;

	int rc = cil_resolve_name(test_db, test_curr, test_alias->type_str, CIL_SYM_TYPES, &type_node);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_resolve_name_invalid_type_neg(CuTest *tc) {
	char *line[] = { "(", "block", "foo", 
				"(", "typealias", "foo.test2", "type_t", ")", 
				"(", "type", "test", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	struct cil_tree_node *test_curr = test_db->ast->root->cl_head->cl_head;
	struct cil_typealias *test_alias = (struct cil_typealias*)test_curr->data;
	struct cil_tree_node *type_node = NULL;

	int rc = cil_resolve_name(test_db, test_curr, test_alias->type_str, CIL_SYM_TYPES, &type_node);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_resolve_ast_curr_null_neg(CuTest *tc) {
	struct cil_db *test_db;
	cil_db_init(&test_db);

	test_db->ast->root = NULL;

	int rc = cil_resolve_ast(test_db, test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}


/*
	cil_resolve test cases
*/

void test_cil_resolve_roleallow(CuTest *tc) {
	char *line[] = {"(", "role", "foo", ")", \
			"(", "role", "bar", ")", \
			"(", "roleallow", "foo", "bar", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = cil_resolve_roleallow(test_db, test_db->ast->root->cl_head->next->next);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_resolve_roleallow_srcdecl_neg(CuTest *tc) {
	char *line[] = {"(", "role", "bar", ")", \
			"(", "roleallow", "foo", "bar", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = cil_resolve_roleallow(test_db, test_db->ast->root->cl_head->next);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_resolve_roleallow_tgtdecl_neg(CuTest *tc) {
	char *line[] = {"(", "role", "foo", ")", \
			"(", "roleallow", "foo", "bar", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = cil_resolve_roleallow(test_db, test_db->ast->root->cl_head->next);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_resolve_sensalias(CuTest *tc) {
	char *line[] = {"(", "sensitivity", "s0", ")",
			"(", "sensitivityalias", "s0", "alias", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = cil_resolve_sensalias(test_db, test_db->ast->root->cl_head->next);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_resolve_sensalias_sensdecl_neg(CuTest *tc) {
	char *line[] = {"(", "sensitivityalias", "s0", "alias", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = cil_resolve_sensalias(test_db, test_db->ast->root->cl_head);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_resolve_catalias(CuTest *tc) {
	char *line[] = {"(", "category", "c0", ")", 
			"(", "categoryalias", "c0", "red", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = cil_resolve_catalias(test_db, test_db->ast->root->cl_head->next);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_resolve_catalias_catdecl_neg(CuTest *tc) {
	char *line[] = {"(", "categoryalias", "c0", "red", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = cil_resolve_catalias(test_db, test_db->ast->root->cl_head);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);	
}

void test_cil_resolve_catset(CuTest *tc) {
	char *line[] = {"(", "category", "c0", ")",
			"(", "category", "c1", ")",
			"(", "category", "c2", ")",
			"(", "categoryset", "somecats", "(", "c0", "c1", "c2", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = cil_resolve_catset(test_db, test_db->ast->root->cl_head->next->next->next);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_resolve_catset_catlist_neg(CuTest *tc) {
	char *line[] = {"(", "category", "c0", ")",
			"(", "category", "c1", ")",
			"(", "category", "c2", ")",
			"(", "categoryset", "somecats", "(", "c0", "c1", "c2", "c4", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = cil_resolve_catset(test_db, test_db->ast->root->cl_head->next->next->next);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_resolve_roletrans(CuTest *tc) {
	char *line[] = {"(", "role", "foo_r", ")",
			"(", "type", "bar_t", ")",
			"(", "role", "foobar_r", ")", 
			"(", "roletransition", "foo_r", "bar_t", "foobar_r", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = cil_resolve_roletrans(test_db, test_db->ast->root->cl_head->next->next->next);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_resolve_roletrans_srcdecl_neg(CuTest *tc) {
	char *line[] = {"(", "type", "bar_t", ")",
			"(", "role", "foobar_r", ")", 
			"(", "roletransition", "foo_r", "bar_t", "foobar_r", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = cil_resolve_roletrans(test_db, test_db->ast->root->cl_head->next->next);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_resolve_roletrans_tgtdecl_neg(CuTest *tc) {
	char *line[] = {"(", "role", "foo_r", ")",
			"(", "role", "foobar_r", ")", 
			"(", "roletransition", "foo_r", "bar_t", "foobar_r", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = cil_resolve_roletrans(test_db, test_db->ast->root->cl_head->next->next);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_resolve_roletrans_resultdecl_neg(CuTest *tc) {
	char *line[] = {"(", "role", "foo_r", ")",
			"(", "type", "bar_t", ")", 
			"(", "roletransition", "foo_r", "bar_t", "foobar_r", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = cil_resolve_roletrans(test_db, test_db->ast->root->cl_head->next->next);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_resolve_typeattr(CuTest *tc) {
	char *line[] = {"(", "type", "foo", ")", 
			"(", "attribute", "bar", ")", 
			"(", "typeattribute", "foo", "bar", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = cil_resolve_typeattr(test_db, test_db->ast->root->cl_head->next->next);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_resolve_typeattr_typedecl_neg(CuTest *tc) {
	char *line[] = {"(", "attribute", "bar", ")", 
			"(", "typeattribute", "foo", "bar", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = cil_resolve_typeattr(test_db, test_db->ast->root->cl_head->next);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_resolve_typeattr_attrdecl_neg(CuTest *tc) {
	char *line[] = {"(", "type", "foo", ")", 
			"(", "typeattribute", "foo", "bar", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = cil_resolve_typeattr(test_db, test_db->ast->root->cl_head->next);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_resolve_typealias(CuTest *tc) {
	char *line[] = {"(", "block", "foo", 
				"(", "typealias", ".foo.test", "type_t", ")", 
				"(", "type", "test", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);


	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = cil_resolve_typealias(test_db, test_db->ast->root->cl_head->cl_head);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_resolve_avrule(CuTest *tc) {
	char *line[] = {"(", "class", "bar", "(", "read", "write", "open", ")", ")", 
	                "(", "type", "test", ")", 
			"(", "type", "foo", ")", 
	                "(", "allow", "test", "foo", "bar", "(", "read", "write", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = cil_resolve_avrule(test_db, test_db->ast->root->cl_head->next->next->next);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_resolve_type_rule_transition(CuTest *tc) {
	char *line[] = {"(", "type", "foo", ")",
			"(", "type", "bar", ")",
			"(", "class", "file", "(", "write", ")", ")",
			"(", "type", "foobar", ")", 
			"(", "typetransition", "foo", "bar", "file", "foobar", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = cil_resolve_type_rule(test_db, test_db->ast->root->cl_head->next->next->next->next);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_resolve_type_rule_transition_srcdecl_neg(CuTest *tc) {
	char *line[] = {"(", "type", "bar", ")",
			"(", "class", "file", "(", "write", ")", ")",
			"(", "type", "foobar", ")", 
			"(", "typetransition", "foo", "bar", "file", "foobar", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = cil_resolve_type_rule(test_db, test_db->ast->root->cl_head->next->next->next);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_resolve_type_rule_transition_tgtdecl_neg(CuTest *tc) {
	char *line[] = {"(", "type", "foo", ")",
			"(", "class", "file", "(", "write", ")", ")",
			"(", "type", "foobar", ")", 
			"(", "typetransition", "foo", "bar", "file", "foobar", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = cil_resolve_type_rule(test_db, test_db->ast->root->cl_head->next->next->next);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_resolve_type_rule_transition_objdecl_neg(CuTest *tc) {
	char *line[] = {"(", "type", "foo", ")",
			"(", "type", "bar", ")",
			"(", "type", "foobar", ")", 
			"(", "typetransition", "foo", "bar", "file", "foobar", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = cil_resolve_type_rule(test_db, test_db->ast->root->cl_head->next->next->next);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_resolve_type_rule_transition_resultdecl_neg(CuTest *tc) {
	char *line[] = {"(", "type", "foo", ")",
			"(", "type", "bar", ")",
			"(", "class", "file", "(", "write", ")", ")",
			"(", "typetransition", "foo", "bar", "file", "foobar", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = cil_resolve_type_rule(test_db, test_db->ast->root->cl_head->next->next->next);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_resolve_type_rule_change(CuTest *tc) {
	char *line[] = {"(", "type", "foo", ")",
			"(", "type", "bar", ")",
			"(", "class", "file", "(", "write", ")", ")",
			"(", "type", "foobar", ")", 
			"(", "typechange", "foo", "bar", "file", "foobar", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = cil_resolve_type_rule(test_db, test_db->ast->root->cl_head->next->next->next->next);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_resolve_type_rule_change_srcdecl_neg(CuTest *tc) {
	char *line[] = {"(", "type", "bar", ")",
			"(", "class", "file", "(", "write", ")", ")",
			"(", "type", "foobar", ")", 
			"(", "typechange", "foo", "bar", "file", "foobar", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = cil_resolve_type_rule(test_db, test_db->ast->root->cl_head->next->next->next);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_resolve_type_rule_change_tgtdecl_neg(CuTest *tc) {
	char *line[] = {"(", "type", "foo", ")",
			"(", "class", "file", "(", "write", ")", ")",
			"(", "type", "foobar", ")", 
			"(", "typechange", "foo", "bar", "file", "foobar", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = cil_resolve_type_rule(test_db, test_db->ast->root->cl_head->next->next->next);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_resolve_type_rule_change_objdecl_neg(CuTest *tc) {
	char *line[] = {"(", "type", "foo", ")",
			"(", "type", "bar", ")",
			"(", "type", "foobar", ")", 
			"(", "typechange", "foo", "bar", "file", "foobar", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = cil_resolve_type_rule(test_db, test_db->ast->root->cl_head->next->next->next);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_resolve_type_rule_change_resultdecl_neg(CuTest *tc) {
	char *line[] = {"(", "type", "foo", ")",
			"(", "type", "bar", ")",
			"(", "class", "file", "(", "write", ")", ")",
			"(", "typechange", "foo", "bar", "file", "foobar", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = cil_resolve_type_rule(test_db, test_db->ast->root->cl_head->next->next->next);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_resolve_type_rule_member(CuTest *tc) {
	char *line[] = {"(", "type", "foo", ")",
			"(", "type", "bar", ")",
			"(", "class", "file", "(", "write", ")", ")",
			"(", "type", "foobar", ")", 
			"(", "typemember", "foo", "bar", "file", "foobar", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = cil_resolve_type_rule(test_db, test_db->ast->root->cl_head->next->next->next->next);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_resolve_type_rule_member_srcdecl_neg(CuTest *tc) {
	char *line[] = {"(", "type", "bar", ")",
			"(", "class", "file", "(", "write", ")", ")",
			"(", "type", "foobar", ")", 
			"(", "typemember", "foo", "bar", "file", "foobar", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = cil_resolve_type_rule(test_db, test_db->ast->root->cl_head->next->next->next);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_resolve_type_rule_member_tgtdecl_neg(CuTest *tc) {
	char *line[] = {"(", "type", "foo", ")",
			"(", "class", "file", "(", "write", ")", ")",
			"(", "type", "foobar", ")", 
			"(", "typemember", "foo", "bar", "file", "foobar", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = cil_resolve_type_rule(test_db, test_db->ast->root->cl_head->next->next->next);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_resolve_type_rule_member_objdecl_neg(CuTest *tc) {
	char *line[] = {"(", "type", "foo", ")",
			"(", "type", "bar", ")",
			"(", "type", "foobar", ")", 
			"(", "typemember", "foo", "bar", "file", "foobar", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = cil_resolve_type_rule(test_db, test_db->ast->root->cl_head->next->next->next);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_resolve_type_rule_member_resultdecl_neg(CuTest *tc) {
	char *line[] = {"(", "type", "foo", ")",
			"(", "type", "bar", ")",
			"(", "class", "file", "(", "write", ")", ")",
			"(", "typemember", "foo", "bar", "file", "foobar", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = cil_resolve_type_rule(test_db, test_db->ast->root->cl_head->next->next->next);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_resolve_sid(CuTest *tc) {
	char *line[] = {"(", "category", "c0", ")",
			"(", "categoryorder", "(", "c0", ")", ")",
			"(", "sensitivity", "s0", ")",
			"(", "sensitivitycategory", "s0", "(", "c0", ")", ")",
			"(", "type", "blah_t", ")",
			"(", "role", "blah_r", ")",
			"(", "user", "blah_u", ")",
			"(", "sid", "test", "(", "blah_u", "blah_r", "blah_t", "(", "s0", "(", "c0", ")", ")", "(", "s0", "(", "c0", ")", ")", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	cil_resolve_senscat(test_db, test_db->ast->root->cl_head->next->next->next);

	int rc = cil_resolve_sid(test_db, test_db->ast->root->cl_head->next->next->next->next->next->next->next);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_resolve_sid_named_levels(CuTest *tc) {
	char *line[] = {"(", "category", "c0", ")",
			"(", "categoryorder", "(", "c0", ")", ")",
			"(", "sensitivity", "s0", ")",
			"(", "sensitivitycategory", "s0", "(", "c0", ")", ")",
			"(", "type", "blah_t", ")",
			"(", "role", "blah_r", ")",
			"(", "user", "blah_u", ")",
			"(", "level", "low", "s0", "(", "c0", ")", ")",
			"(", "level", "high", "s0", "(", "c0", ")", ")",
			"(", "sid", "test", "(", "blah_u", "blah_r", "blah_t", "low", "high", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	cil_resolve_senscat(test_db, test_db->ast->root->cl_head->next->next->next);
	struct cil_tree_node *level = test_db->ast->root->cl_head->next->next->next->next->next->next->next;
	cil_resolve_level(test_db, level, (struct cil_level*)level->data);
	cil_resolve_level(test_db, level->next, (struct cil_level*)level->next->data);
	int rc = cil_resolve_sid(test_db, test_db->ast->root->cl_head->next->next->next->next->next->next->next->next->next);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_resolve_sid_named_context(CuTest *tc) {
	char *line[] = {"(", "category", "c0", ")",
			"(", "categoryorder", "(", "c0", ")", ")",
			"(", "sensitivity", "s0", ")",
			"(", "sensitivitycategory", "s0", "(", "c0", ")", ")",
			"(", "type", "blah_t", ")",
			"(", "role", "blah_r", ")",
			"(", "user", "blah_u", ")",
			"(", "context", "con", "(", "blah_u", "blah_r", "blah_t", "(", "s0", "(", "c0", ")", ")", "(", "s0", "(", "c0", ")", ")", ")", ")",
			"(", "sid", "test", "con", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	cil_resolve_senscat(test_db, test_db->ast->root->cl_head->next->next->next);
	struct cil_tree_node *context = test_db->ast->root->cl_head->next->next->next->next->next->next->next;
	cil_resolve_context(test_db, context, (struct cil_context*)context->data);

	int rc = cil_resolve_sid(test_db, test_db->ast->root->cl_head->next->next->next->next->next->next->next->next);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_resolve_roletype(CuTest *tc) {
	char *line[] = {"(", "role",  "admin_r", ")",
			"(", "type", "admin_t", ")",
			"(", "roletype", "admin_r", "admin_t", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = cil_resolve_roletype(test_db, test_db->ast->root->cl_head->next->next);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_resolve_roletype_type_neg(CuTest *tc) {
	char *line[] = {"(", "role",  "admin_r", ")",
			"(", "roletype", "admin_r", "admin_t", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = cil_resolve_roletype(test_db, test_db->ast->root->cl_head->next);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_resolve_roletype_role_neg(CuTest *tc) {
	char *line[] = {"(", "type", "admin_t", ")",
			"(", "roletype", "admin_r", "admin_t", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = cil_resolve_roletype(test_db, test_db->ast->root->cl_head->next);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_resolve_userrole(CuTest *tc) {
	char *line[] = {"(", "role",  "staff_r", ")",
			"(", "user", "staff_u", ")",
			"(", "userrole", "staff_u", "staff_r", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = cil_resolve_userrole(test_db, test_db->ast->root->cl_head->next->next);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_resolve_userrole_user_neg(CuTest *tc) {
	char *line[] = {"(", "role",  "staff_r", ")",
			"(", "userrole", "staff_u", "staff_r", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = cil_resolve_userrole(test_db, test_db->ast->root->cl_head->next);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_resolve_userrole_role_neg(CuTest *tc) {
	char *line[] = {"(", "user", "staff_u", ")",
			"(", "userrole", "staff_u", "staff_r", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = cil_resolve_userrole(test_db, test_db->ast->root->cl_head->next);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}


/*
	__cil_resolve_ast_node_helper test cases
*/

void test_cil_resolve_ast_node_helper_roleallow(CuTest *tc) {
	char *line[] = {"(", "role", "foo", ")", \
			"(", "role", "bar", ")", \
			"(", "roleallow", "foo", "bar", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db;
	other->head->flavor = CIL_DB;
	cil_list_item_init(&other->head->next);
	other->head->next->flavor = CIL_INT;
	int pass = 3;
	other->head->next->data = &pass;

	uint32_t *finished = NULL;

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = __cil_resolve_ast_node_helper(test_db->ast->root->cl_head->next->next, finished, other);	
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrEquals(tc, NULL, finished);
}

void test_cil_resolve_ast_node_helper_roleallow_neg(CuTest *tc) {
	char *line[] = {"(", "role", "foo", ")", \
			"(", "roleallow", "foo", "bar", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db;
	other->head->flavor = CIL_DB;
	cil_list_item_init(&other->head->next);
	other->head->next->flavor = CIL_INT;
	int pass = 3;
	other->head->next->data = &pass;

	uint32_t *finished = NULL;
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = __cil_resolve_ast_node_helper(test_db->ast->root->cl_head->next, finished, other);	
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
	CuAssertPtrEquals(tc, NULL, finished);
}

void test_cil_resolve_ast_node_helper_sensalias(CuTest *tc) {
	char *line[] = {"(", "sensitivity", "s0", ")",
			"(", "sensitivityalias", "s0", "alias", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db;
	other->head->flavor = CIL_DB;
	cil_list_item_init(&other->head->next);
	other->head->next->flavor = CIL_INT;
	int pass = 3;
	other->head->next->data = &pass;

	uint32_t *finished = NULL;
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = __cil_resolve_ast_node_helper(test_db->ast->root->cl_head->next, finished, other);	
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrEquals(tc, NULL, finished);
}

void test_cil_resolve_ast_node_helper_sensalias_neg(CuTest *tc) {
	char *line[] = {"(", "sensitivityalias", "s0", "alias", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db;
	other->head->flavor = CIL_DB;
	cil_list_item_init(&other->head->next);
	other->head->next->flavor = CIL_INT;
	int pass = 3;
	other->head->next->data = &pass;

	uint32_t *finished = NULL;
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = __cil_resolve_ast_node_helper(test_db->ast->root->cl_head, finished, other);	
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
	CuAssertPtrEquals(tc, NULL, finished);
}

void test_cil_resolve_ast_node_helper_catalias(CuTest *tc) {
	char *line[] = {"(", "category", "c0", ")", 
			"(", "categoryalias", "c0", "red", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db;
	other->head->flavor = CIL_DB;
	cil_list_item_init(&other->head->next);
	other->head->next->flavor = CIL_INT;
	int pass = 3;
	other->head->next->data = &pass;

	uint32_t *finished = NULL;

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = __cil_resolve_ast_node_helper(test_db->ast->root->cl_head->next, finished, other);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrEquals(tc, NULL, finished);
}

void test_cil_resolve_ast_node_helper_catalias_neg(CuTest *tc) {
	char *line[] = {"(", "categoryalias", "c0", "red", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db;
	other->head->flavor = CIL_DB;
	cil_list_item_init(&other->head->next);
	other->head->next->flavor = CIL_INT;
	int pass = 3;
	other->head->next->data = &pass;

	uint32_t *finished = NULL;

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = __cil_resolve_ast_node_helper(test_db->ast->root->cl_head, finished, other);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
	CuAssertPtrEquals(tc, NULL, finished);	
}

void test_cil_resolve_ast_node_helper_catset(CuTest *tc) {
	char *line[] = {"(", "category", "c0", ")",
			"(", "category", "c1", ")",
			"(", "category", "c2", ")",
			"(", "categoryset", "somecats", "(", "c0", "c1", "c2", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db;
	other->head->flavor = CIL_DB;
	cil_list_item_init(&other->head->next);
	other->head->next->flavor = CIL_INT;
	int pass = 3;
	other->head->next->data = &pass;

	uint32_t *finished = NULL;

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = __cil_resolve_ast_node_helper(test_db->ast->root->cl_head->next->next->next, finished, other);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrEquals(tc, NULL, finished);
}

void test_cil_resolve_ast_node_helper_catset_catlist_neg(CuTest *tc) {
	char *line[] = {"(", "category", "c0", ")",
			"(", "category", "c1", ")",
			"(", "categoryset", "somecats", "(", "c0", "c1", "c2", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db;
	other->head->flavor = CIL_DB;
	cil_list_item_init(&other->head->next);
	other->head->next->flavor = CIL_INT;
	int pass = 3;
	other->head->next->data = &pass;

	uint32_t *finished = NULL;

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = __cil_resolve_ast_node_helper(test_db->ast->root->cl_head->next->next, finished, other);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
	CuAssertPtrEquals(tc, NULL, finished);
}

void test_cil_resolve_ast_node_helper_roletrans(CuTest *tc) {
	char *line[] = {"(", "role", "foo_r", ")",
			"(", "type", "bar_t", ")",
			"(", "role", "foobar_r", ")", 
			"(", "roletransition", "foo_r", "bar_t", "foobar_r", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db;
	other->head->flavor = CIL_DB;
	cil_list_item_init(&other->head->next);
	other->head->next->flavor = CIL_INT;
	int pass = 3;
	other->head->next->data = &pass;

	uint32_t *finished = NULL;
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = __cil_resolve_ast_node_helper(test_db->ast->root->cl_head->next->next->next, finished, other);	
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrEquals(tc, NULL, finished);
}

void test_cil_resolve_ast_node_helper_roletrans_srcdecl_neg(CuTest *tc) {
	char *line[] = {"(", "type", "bar_t", ")",
			"(", "role", "foobar_r", ")", 
			"(", "roletransition", "foo_r", "bar_t", "foobar_r", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db;
	other->head->flavor = CIL_DB;
	cil_list_item_init(&other->head->next);
	other->head->next->flavor = CIL_INT;
	int pass = 3;
	other->head->next->data = &pass;

	uint32_t *finished = NULL;
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = __cil_resolve_ast_node_helper(test_db->ast->root->cl_head->next->next, finished, other);	
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
	CuAssertPtrEquals(tc, NULL, finished);
}

void test_cil_resolve_ast_node_helper_roletrans_tgtdecl_neg(CuTest *tc) {
	char *line[] = {"(", "role", "foo_r", ")",
			"(", "role", "foobar_r", ")", 
			"(", "roletransition", "foo_r", "bar_t", "foobar_r", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db;
	other->head->flavor = CIL_DB;
	cil_list_item_init(&other->head->next);
	other->head->next->flavor = CIL_INT;
	int pass = 3;
	other->head->next->data = &pass;

	uint32_t *finished = NULL;
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = __cil_resolve_ast_node_helper(test_db->ast->root->cl_head->next->next, finished, other);	
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
	CuAssertPtrEquals(tc, NULL, finished);
}

void test_cil_resolve_ast_node_helper_roletrans_resultdecl_neg(CuTest *tc) {
	char *line[] = {"(", "role", "foo_r", ")",
			"(", "type", "bar_t", ")",
			"(", "roletransition", "foo_r", "bar_t", "foobar_r", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db;
	other->head->flavor = CIL_DB;
	cil_list_item_init(&other->head->next);
	other->head->next->flavor = CIL_INT;
	int pass = 3;
	other->head->next->data = &pass;

	uint32_t *finished = NULL;
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = __cil_resolve_ast_node_helper(test_db->ast->root->cl_head->next->next, finished, other);	
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
	CuAssertPtrEquals(tc, NULL, finished);
}

void test_cil_resolve_ast_node_helper_typeattr(CuTest *tc) {
	char *line[] = {"(", "type", "foo", ")",
			"(", "attribute", "bar", ")",
			"(", "typeattribute", "foo", "bar", ")", NULL};
		
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db;
	other->head->flavor = CIL_DB;
	cil_list_item_init(&other->head->next);
	other->head->next->flavor = CIL_INT;
	int pass = 3;
	other->head->next->data = &pass;

	uint32_t *finished = NULL;
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = __cil_resolve_ast_node_helper(test_db->ast->root->cl_head->next->next, finished, other);	
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrEquals(tc, NULL, finished);
}

void test_cil_resolve_ast_node_helper_typeattr_neg(CuTest *tc) {
	char *line[] = {"(", "type", "foo", ")",
			"(", "typeattribute", "foo", "bar", ")", NULL};
		
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db;
	other->head->flavor = CIL_DB;
	cil_list_item_init(&other->head->next);
	other->head->next->flavor = CIL_INT;
	int pass = 3;
	other->head->next->data = &pass;

	uint32_t *finished = NULL;
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = __cil_resolve_ast_node_helper(test_db->ast->root->cl_head->next, finished, other);	
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
	CuAssertPtrEquals(tc, NULL, finished);
}

void test_cil_resolve_ast_node_helper_typealias(CuTest *tc) {
	char *line[] = {"(", "block", "foo", 
				"(", "typealias", ".foo.test", "type_t", ")", 
				"(", "type", "test", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db;
	other->head->flavor = CIL_DB;
	cil_list_item_init(&other->head->next);
	other->head->next->flavor = CIL_INT;
	int pass = 3;
	other->head->next->data = &pass;

	uint32_t *finished = NULL;
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = __cil_resolve_ast_node_helper(test_db->ast->root->cl_head->cl_head, finished, other);	
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrEquals(tc, NULL, finished);
}

void test_cil_resolve_ast_node_helper_typealias_notype_neg(CuTest *tc) {
	char *line[] = {"(", "block", "bar", 
				"(", "typealias", ".bar.test", "type_t", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db;
	other->head->flavor = CIL_DB;
	cil_list_item_init(&other->head->next);
	other->head->next->flavor = CIL_INT;
	int pass = 3;
	other->head->next->data = &pass;

	uint32_t *finished = NULL;
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = __cil_resolve_ast_node_helper(test_db->ast->root->cl_head->cl_head, finished, other);	
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
	CuAssertPtrEquals(tc, NULL, finished);
}

void test_cil_resolve_ast_node_helper_avrule(CuTest *tc) {
	char *line[] = {"(", "class", "bar", "(", "read", "write", "open", ")", ")", 
	                "(", "type", "test", ")", 
			"(", "type", "foo", ")", 
	                "(", "allow", "test", "foo", "bar", "(", "read", "write", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db;
	other->head->flavor = CIL_DB;
	cil_list_item_init(&other->head->next);
	other->head->next->flavor = CIL_INT;
	int pass = 3;
	other->head->next->data = &pass;

	uint32_t *finished = NULL;
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = __cil_resolve_ast_node_helper(test_db->ast->root->cl_head->next->next->next, finished, other);	
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrEquals(tc, NULL, finished);
}

void test_cil_resolve_ast_node_helper_avrule_src_nores_neg(CuTest *tc) {
	char *line[] = {"(", "allow", "test", "foo", "bar", "(", "read", "write", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db;
	other->head->flavor = CIL_DB;
	cil_list_item_init(&other->head->next);
	other->head->next->flavor = CIL_INT;
	int pass = 3;
	other->head->next->data = &pass;

	uint32_t *finished = NULL;
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = __cil_resolve_ast_node_helper(test_db->ast->root->cl_head, finished, other);	
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
	CuAssertPtrEquals(tc, NULL, finished);
}

void test_cil_resolve_ast_node_helper_avrule_tgt_nores_neg(CuTest *tc) {
	char *line[] = {"(", "type", "test", ")", 
			"(", "allow", "test", "foo", "bar", "(", "read", "write", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);
	
	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db;
	other->head->flavor = CIL_DB;
	cil_list_item_init(&other->head->next);
	other->head->next->flavor = CIL_INT;
	int pass = 3;
	other->head->next->data = &pass;

	uint32_t *finished = NULL;
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = __cil_resolve_ast_node_helper(test_db->ast->root->cl_head->next, finished, other);	
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
	CuAssertPtrEquals(tc, NULL, finished);
}

void test_cil_resolve_ast_node_helper_avrule_class_nores_neg(CuTest *tc) {
	char *line[] = {"(", "type", "test", ")", 
			"(", "type", "foo", ")", 
			"(", "allow", "test", "foo", "bar", "(", "read", "write", ")", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);
	
	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db;
	other->head->flavor = CIL_DB;
	cil_list_item_init(&other->head->next);
	other->head->next->flavor = CIL_INT;
	int pass = 3;
	other->head->next->data = &pass;

	uint32_t *finished = NULL;
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = __cil_resolve_ast_node_helper(test_db->ast->root->cl_head->next->next, finished, other);	
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
	CuAssertPtrEquals(tc, NULL, finished);
}

void test_cil_resolve_ast_node_helper_avrule_datum_null_neg(CuTest *tc) {
	char *line[] = {"(", "class", "bar", "(", "read", "write", "open", ")", ")", \
	                "(", "type", "test", ")", "(", "type", "foo", ")", \
	                "(", "allow", "test", "foo", "bar", "(","fake", ")", ")", NULL};

	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);
	
	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db;
	other->head->flavor = CIL_DB;
	cil_list_item_init(&other->head->next);
	other->head->next->flavor = CIL_INT;
	int pass = 3;
	other->head->next->data = &pass;

	uint32_t *finished = NULL;
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = __cil_resolve_ast_node_helper(test_db->ast->root->cl_head->next->next->next, finished, other);	
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
	CuAssertPtrEquals(tc, NULL, finished);
}

void test_cil_resolve_ast_node_helper_type_rule_transition(CuTest *tc) {
	char *line[] = {"(", "type", "foo", ")",
			"(", "type", "bar", ")",
			"(", "class", "file", "(", "write", ")", ")",
			"(", "type", "foobar", ")",
			"(", "typetransition", "foo", "bar", "file", "foobar", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db;
	other->head->flavor = CIL_DB;
	cil_list_item_init(&other->head->next);
	other->head->next->flavor = CIL_INT;
	int pass = 3;
	other->head->next->data = &pass;

	uint32_t *finished = NULL;
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = __cil_resolve_ast_node_helper(test_db->ast->root->cl_head->next->next->next->next, finished, other);	
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrEquals(tc, NULL, finished);
}

void test_cil_resolve_ast_node_helper_type_rule_transition_neg(CuTest *tc) {
	char *line[] = {"(", "type", "foo", ")",
			"(", "class", "file", "(", "write", ")", ")",
			"(", "type", "foobar", ")",
			"(", "typetransition", "foo", "bar", "file", "foobar", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db;
	other->head->flavor = CIL_DB;
	cil_list_item_init(&other->head->next);
	other->head->next->flavor = CIL_INT;
	int pass = 3;
	other->head->next->data = &pass;

	uint32_t *finished = NULL;
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = __cil_resolve_ast_node_helper(test_db->ast->root->cl_head->next->next->next, finished, other);	
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
	CuAssertPtrEquals(tc, NULL, finished);
}

void test_cil_resolve_ast_node_helper_type_rule_change(CuTest *tc) {
	char *line[] = {"(", "type", "foo", ")",
			"(", "type", "bar", ")",
			"(", "class", "file", "(", "write", ")", ")",
			"(", "type", "foobar", ")",
			"(", "typechange", "foo", "bar", "file", "foobar", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db;
	other->head->flavor = CIL_DB;
	cil_list_item_init(&other->head->next);
	other->head->next->flavor = CIL_INT;
	int pass = 3;
	other->head->next->data = &pass;

	uint32_t *finished = NULL;
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = __cil_resolve_ast_node_helper(test_db->ast->root->cl_head->next->next->next->next, finished, other);	
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrEquals(tc, NULL, finished);
}

void test_cil_resolve_ast_node_helper_type_rule_change_neg(CuTest *tc) {
	char *line[] = {"(", "type", "foo", ")",
			"(", "class", "file", "(", "write", ")", ")",
			"(", "type", "foobar", ")",
			"(", "typechange", "foo", "bar", "file", "foobar", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db;
	other->head->flavor = CIL_DB;
	cil_list_item_init(&other->head->next);
	other->head->next->flavor = CIL_INT;
	int pass = 3;
	other->head->next->data = &pass;

	uint32_t *finished = NULL;
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = __cil_resolve_ast_node_helper(test_db->ast->root->cl_head->next->next->next, finished, other);	
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
	CuAssertPtrEquals(tc, NULL, finished);
}

void test_cil_resolve_ast_node_helper_type_rule_member(CuTest *tc) {
	char *line[] = {"(", "type", "foo", ")",
			"(", "type", "bar", ")",
			"(", "class", "file", "(", "write", ")", ")",
			"(", "type", "foobar", ")",
			"(", "typemember", "foo", "bar", "file", "foobar", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db;
	other->head->flavor = CIL_DB;
	cil_list_item_init(&other->head->next);
	other->head->next->flavor = CIL_INT;
	int pass = 3;
	other->head->next->data = &pass;

	uint32_t *finished = NULL;
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = __cil_resolve_ast_node_helper(test_db->ast->root->cl_head->next->next->next->next, finished, other);	
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrEquals(tc, NULL, finished);
}

void test_cil_resolve_ast_node_helper_type_rule_member_neg(CuTest *tc) {
	char *line[] = {"(", "type", "foo", ")",
			"(", "class", "file", "(", "write", ")", ")",
			"(", "type", "foobar", ")",
			"(", "typemember", "foo", "bar", "file", "foobar", ")", NULL};
	
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = test_db;
	other->head->flavor = CIL_DB;
	cil_list_item_init(&other->head->next);
	other->head->next->flavor = CIL_INT;
	int pass = 3;
	other->head->next->data = &pass;

	uint32_t *finished = NULL;
	
	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = __cil_resolve_ast_node_helper(test_db->ast->root->cl_head->next->next->next, finished, other);	
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
	CuAssertPtrEquals(tc, NULL, finished);
}

void test_cil_resolve_ast_node_helper_roletype(CuTest *tc) {
	char *line[] = {"(", "role",  "admin_r", ")",
			"(", "type", "admin_t", ")",
			"(", "roletype", "admin_r", "admin_t", ")", NULL};
		
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_list *cil_l;
	cil_list_init(&cil_l);

	uint32_t *finished = NULL;

	cil_list_item_init(&cil_l->head);
	cil_l->head->data = test_db;
	cil_l->head->flavor = CIL_DB;
	cil_list_item_init(&cil_l->head->next);
	cil_l->head->next->flavor = CIL_INT;
	int pass = 3;
	cil_l->head->next->data = &pass;

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	int rc = __cil_resolve_ast_node_helper(test_db->ast->root->cl_head->next->next, finished, cil_l);
	CuAssertPtrEquals(tc, NULL, finished);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_resolve_ast_node_helper_roletype_role_neg(CuTest *tc) {
	char *line[] = {"(", "type", "admin_t", ")",
			"(", "roletype", "admin_r", "admin_t", ")", NULL};
		
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_list *cil_l;
	cil_list_init(&cil_l);

	uint32_t *finished = NULL;

	cil_list_item_init(&cil_l->head);
	cil_l->head->data = test_db;
	cil_l->head->flavor = CIL_DB;
	cil_list_item_init(&cil_l->head->next);
	cil_l->head->next->flavor = CIL_INT;
	int pass = 3;
	cil_l->head->next->data = &pass;

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = __cil_resolve_ast_node_helper(test_db->ast->root->cl_head->next, finished, cil_l);
	CuAssertPtrEquals(tc, NULL, finished);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_resolve_ast_node_helper_roletype_type_neg(CuTest *tc) {
	char *line[] = {"(", "role", "admin_r", ")",
			"(", "roletype", "admin_r", "admin_t", ")", NULL};
		
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_list *cil_l;
	cil_list_init(&cil_l);

	uint32_t *finished = NULL;

	cil_list_item_init(&cil_l->head);
	cil_l->head->data = test_db;
	cil_l->head->flavor = CIL_DB;
	cil_list_item_init(&cil_l->head->next);
	cil_l->head->next->flavor = CIL_INT;
	int pass = 3;
	cil_l->head->next->data = &pass;

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = __cil_resolve_ast_node_helper(test_db->ast->root->cl_head->next, finished, cil_l);
	CuAssertPtrEquals(tc, NULL, finished);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_resolve_ast_node_helper_userrole(CuTest *tc) {
	char *line[] = {"(", "role",  "staff_r", ")",
			"(", "user", "staff_u", ")",
			"(", "userrole", "staff_u", "staff_r", ")", NULL};
		
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_list *cil_l;
	cil_list_init(&cil_l);

	uint32_t *finished = NULL;

	cil_list_item_init(&cil_l->head);
	cil_l->head->data = test_db;
	cil_l->head->flavor = CIL_DB;
	cil_list_item_init(&cil_l->head->next);
	cil_l->head->next->flavor = CIL_INT;
	int pass = 3;
	cil_l->head->next->data = &pass;

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);
	
	int rc = __cil_resolve_ast_node_helper(test_db->ast->root->cl_head->next->next, finished, cil_l);
	CuAssertPtrEquals(tc, NULL, finished);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_resolve_ast_node_helper_userrole_user_neg(CuTest *tc) {
	char *line[] = {"(", "role",  "staff_r", ")",
			"(", "userrole", "staff_u", "staff_r", ")", NULL};
		
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_list *cil_l;
	cil_list_init(&cil_l);

	uint32_t *finished = NULL;

	cil_list_item_init(&cil_l->head);
	cil_l->head->data = test_db;
	cil_l->head->flavor = CIL_DB;
	cil_list_item_init(&cil_l->head->next);
	cil_l->head->next->flavor = CIL_INT;
	int pass = 3;
	cil_l->head->next->data = &pass;

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = __cil_resolve_ast_node_helper(test_db->ast->root->cl_head->next, finished, cil_l);
	CuAssertPtrEquals(tc, NULL, finished);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}

void test_cil_resolve_ast_node_helper_userrole_role_neg(CuTest *tc) {
	char *line[] = {"(", "user",  "staff_u", ")",
			"(", "userrole", "staff_u", "staff_r", ")", NULL};
		
	struct cil_tree *test_tree;
	gen_test_tree(&test_tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);
	
	struct cil_tree_node *test_ast_node;
	cil_tree_node_init(&test_ast_node);

	struct cil_list *cil_l;
	cil_list_init(&cil_l);

	uint32_t *finished = NULL;

	cil_list_item_init(&cil_l->head);
	cil_l->head->data = test_db;
	cil_l->head->flavor = CIL_DB;
	cil_list_item_init(&cil_l->head->next);
	cil_l->head->next->flavor = CIL_INT;
	int pass = 3;
	cil_l->head->next->data = &pass;

	cil_build_ast(test_db, test_tree->root, test_db->ast->root);

	int rc = __cil_resolve_ast_node_helper(test_db->ast->root->cl_head->next, finished, cil_l);
	CuAssertPtrEquals(tc, NULL, finished);
	CuAssertIntEquals(tc, SEPOL_ERR, rc);
}
