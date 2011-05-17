#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sepol/policydb/symtab.h>
#include <sepol/policydb/policydb.h>

#include "CuTest.h"
#include "CilTest.h"

#include "../../src/cil.h"

#include "test_cil.h"
#include "test_cil_tree.h"
#include "test_cil_list.h"
#include "test_cil_symtab.h"
#include "test_cil_parser.h"
#include "test_cil_lexer.h"
#include "test_cil_build_ast.h"
#include "test_cil_resolve_ast.h"
#include "test_cil_fqn.h"
#include "test_cil_copy_ast.h"

void set_cil_file_data(struct cil_file_data **data) {
	struct cil_file_data *new_data = malloc(sizeof(struct cil_file_data));
	FILE *file;
	struct stat filedata;
	uint32_t file_size;
	char *buffer;

	file = fopen("testing/test.txt", "r");
	if (!file) {
	    fprintf(stderr, "Could not open file\n");
	    exit(1);
	}
	if (stat("testing/test.txt", &filedata) == -1) {
	    printf("Could not stat file\n");
	    exit(1);
	}
	file_size = filedata.st_size;

	buffer = malloc(file_size + 2);
	fread(buffer, file_size, 1, file);
	memset(buffer+file_size, 0, 2);
	fclose(file);


	new_data->buffer = buffer;
	new_data->file_size = file_size;

	*data = new_data;

}

void gen_test_tree(struct cil_tree **test_root, char *line[]) {
	struct cil_tree *new_tree = malloc(sizeof(struct cil_tree));
	struct cil_tree_node *node, *item, *current;

	cil_tree_init(&new_tree);
	new_tree->root->flavor = CIL_ROOT;
	current = new_tree->root;
	
	char **i = line;
	do {
	    if (*i[0] == '(') {
	        cil_tree_node_init(&node);
	        node->parent = current;
	        node->flavor = CIL_PARSE_NODE;
	        node->line = 0;
	        if (current->cl_head == NULL)
	            current->cl_head = node;
	        else
	            current->cl_tail->next = node;
	        current->cl_tail = node;
	        current = node;
	    }
	    else if (*i[0] == ')')
	        current = current->parent;
	    else {
	        cil_tree_node_init(&item);
	        item->parent = current;
	        item->data = cil_strdup(*i);
	        item->flavor = CIL_PARSE_NODE;
	        item->line = 0;
	        if (current->cl_head == NULL) {
	            current->cl_head = item;
	        }
	        else {
	            current->cl_tail->next = item;
	        }
	        current->cl_tail = item;
	    }
	    i++;
	} while(*i != NULL);

	*test_root = new_tree;
}

void test_symtab_init(CuTest *tc) {
	struct cil_db *test_new_db;
	test_new_db = malloc(sizeof(struct cil_db));

	uint32_t rc = 0, i =0;
	
	for (i=0; i<CIL_SYM_NUM; i++) {
	    rc = symtab_init(&test_new_db->symtab[i], CIL_SYM_SIZE);
	    CuAssertIntEquals(tc, 0, rc);
	    // TODO CDS add checks to make sure the symtab looks correct
	}

	free(test_new_db);
}

void test_symtab_init_no_table_neg(CuTest *tc) {
	struct cil_db *test_new_db;
	test_new_db = malloc(sizeof(struct cil_db));

	int rc = symtab_init(&test_new_db->symtab[0], (uint32_t)SIZE_MAX);
	CuAssertIntEquals(tc, -1, rc);

	free(test_new_db);
}

CuSuite* CilTreeGetSuite() {
	CuSuite* suite = CuSuiteNew();

	/* CilTest.c */
	SUITE_ADD_TEST(suite, test_symtab_init);
	SUITE_ADD_TEST(suite, test_symtab_init_no_table_neg);


	/* test_cil.c */
	SUITE_ADD_TEST(suite, test_cil_symtab_array_init);

	SUITE_ADD_TEST(suite, test_cil_db_init);

	SUITE_ADD_TEST(suite, test_cil_get_parent_symtab_block);
	SUITE_ADD_TEST(suite, test_cil_get_parent_symtab_class);
	SUITE_ADD_TEST(suite, test_cil_get_parent_symtab_root);
	SUITE_ADD_TEST(suite, test_cil_get_parent_symtab_other_neg);
	SUITE_ADD_TEST(suite, test_cil_get_parent_symtab_null_neg);
	SUITE_ADD_TEST(suite, test_cil_get_parent_symtab_node_null_neg);
	SUITE_ADD_TEST(suite, test_cil_get_parent_symtab_parent_null_neg);


	/* test_cil_list.c */
	SUITE_ADD_TEST(suite, test_cil_list_append_item);
	SUITE_ADD_TEST(suite, test_cil_list_append_item_append);
	SUITE_ADD_TEST(suite, test_cil_list_append_item_append_extra);
	SUITE_ADD_TEST(suite, test_cil_list_append_item_listnull_neg);
	SUITE_ADD_TEST(suite, test_cil_list_append_item_itemnull_neg);
	SUITE_ADD_TEST(suite, test_cil_list_prepend_item_prepend);
	SUITE_ADD_TEST(suite, test_cil_list_prepend_item_prepend_neg);
	SUITE_ADD_TEST(suite, test_cil_list_prepend_item_listnull_neg);
	SUITE_ADD_TEST(suite, test_cil_list_prepend_item_itemnull_neg);


	/* test_cil_symtab.c */
	SUITE_ADD_TEST(suite, test_cil_symtab_insert);


	/* test_cil_tree.c */
	SUITE_ADD_TEST(suite, test_cil_tree_init);
	SUITE_ADD_TEST(suite, test_cil_tree_node_init);


	/* test_cil_lexer.c */
	SUITE_ADD_TEST(suite, test_cil_lexer_setup);
	SUITE_ADD_TEST(suite, test_cil_lexer_next);


	/* test_cil_parser.c */
	SUITE_ADD_TEST(suite, test_cil_parser);


	/* test_cil_build_ast.c */
	SUITE_ADD_TEST(suite, test_cil_build_ast);
	SUITE_ADD_TEST(suite, test_cil_build_ast_dbnull_neg);
	SUITE_ADD_TEST(suite, test_cil_build_ast_astnull_neg);
	SUITE_ADD_TEST(suite, test_cil_build_ast_treenull_neg);
	SUITE_ADD_TEST(suite, test_cil_build_ast_suberr_neg);

	SUITE_ADD_TEST(suite, test_cil_parse_to_list);
	SUITE_ADD_TEST(suite, test_cil_parse_to_list_currnull_neg);
	SUITE_ADD_TEST(suite, test_cil_parse_to_list_listnull_neg);

	SUITE_ADD_TEST(suite, test_cil_set_to_list);
	SUITE_ADD_TEST(suite, test_cil_set_to_list_listnull_neg);
	SUITE_ADD_TEST(suite, test_cil_set_to_list_tree_node_null_neg);
	SUITE_ADD_TEST(suite, test_cil_set_to_list_cl_head_null_neg);

	SUITE_ADD_TEST(suite, test_cil_gen_block);
	SUITE_ADD_TEST(suite, test_cil_gen_block_justblock_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_block_noname_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_block_dbnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_block_treenull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_block_nodenull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_block_nodeparentnull_neg);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_block);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_block_neg);

	//SUITE_ADD_TEST(suite, test_cil_gen_perm);
	SUITE_ADD_TEST(suite, test_cil_gen_perm_dbnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_perm_currnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_perm_nodenull_neg);
	//This needs to be fixed. Looks for perms in CIL_ROOT should be CLASS or COMMON
	//SUITE_ADD_TEST(suite, test_cil_gen_perm_permexists_neg);
	// Causes a segfault
	//SUITE_ADD_TEST(suite, test_cil_gen_perm_noname_neg);

	SUITE_ADD_TEST(suite, test_cil_gen_perm_nodes);
	SUITE_ADD_TEST(suite, test_cil_gen_perm_nodes_failgen_neg);

	SUITE_ADD_TEST(suite, test_cil_gen_class);
	SUITE_ADD_TEST(suite, test_cil_gen_class_noname_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_class_nodenull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_class_dbnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_class_currnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_class_noclassname_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_class_namesublist_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_class_noperms_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_class_permsnotinlist_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_class_extrapermlist_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_class_listinlist_neg);
	//test_cil_gen_class_failgen_neg
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_class);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_class_neg);

	SUITE_ADD_TEST(suite, test_cil_gen_common);
	SUITE_ADD_TEST(suite, test_cil_gen_common_dbnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_common_currnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_common_astnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_common_noname_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_common_twoperms_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_common_permsublist_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_common_noperms_neg);
	
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_common);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_common_neg);

	SUITE_ADD_TEST(suite, test_cil_gen_sid);
	SUITE_ADD_TEST(suite, test_cil_gen_sid_namedcontext);
	SUITE_ADD_TEST(suite, test_cil_gen_sid_halfcontext_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_sid_noname_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_sid_empty_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_sid_nocontext_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_sid_dblname_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_sid_dbnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_sid_pcurrnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_sid_astnodenull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_sid_insertnode_neg);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_sid);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_sid_neg);

	SUITE_ADD_TEST(suite, test_cil_gen_type);
	SUITE_ADD_TEST(suite, test_cil_gen_type_dbnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_type_currnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_type_astnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_type_extra_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_type_invalid_node_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_type_extratype_nottypeorattr_neg);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_type);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_type_neg);
	
	SUITE_ADD_TEST(suite, test_cil_gen_type_attribute);
	SUITE_ADD_TEST(suite, test_cil_gen_type_attribute_dbnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_type_attribute_currnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_type_attribute_astnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_type_attribute_extra_neg);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_type_attribute);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_type_attribute_neg);

	SUITE_ADD_TEST(suite, test_cil_gen_typeattr);
	SUITE_ADD_TEST(suite, test_cil_gen_typeattr_dbnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_typeattr_currnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_typeattr_astnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_typeattr_typenull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_typeattr_attrnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_typeattr_attrlist_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_typeattr_extra_neg);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_typeattr);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_typeattr_neg);

	SUITE_ADD_TEST(suite, test_cil_gen_typealias);
	SUITE_ADD_TEST(suite, test_cil_gen_typealias_incomplete_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_typealias_incomplete_neg2);
	SUITE_ADD_TEST(suite, test_cil_gen_typealias_extratype_neg);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_typealias);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_typealias_notype_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_typealias_dbnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_typealias_currnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_typealias_astnull_neg);

	SUITE_ADD_TEST(suite, test_cil_gen_role);
	SUITE_ADD_TEST(suite, test_cil_gen_role_dbnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_role_currnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_role_astnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_role_extrarole_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_role_noname_neg);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_role);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_role_neg);

	SUITE_ADD_TEST(suite, test_cil_gen_roletrans);	
	SUITE_ADD_TEST(suite, test_cil_gen_roletrans_currnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_roletrans_astnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_roletrans_srcnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_roletrans_tgtnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_roletrans_resultnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_roletrans_extra_neg);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_roletrans);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_roletrans_neg);

	SUITE_ADD_TEST(suite, test_cil_gen_bool_true);
	SUITE_ADD_TEST(suite, test_cil_gen_bool_false);
	SUITE_ADD_TEST(suite, test_cil_gen_bool_none_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_bool_dbnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_bool_currnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_bool_astnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_bool_notbool_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_bool_boolname_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_bool_extraname_false_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_bool_extraname_true_neg);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_bool);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_bool_neg);

	SUITE_ADD_TEST(suite, test_cil_gen_roleallow);
	SUITE_ADD_TEST(suite, test_cil_gen_roleallow_dbnull_neg);
        SUITE_ADD_TEST(suite, test_cil_gen_roleallow_currnull_neg);
        SUITE_ADD_TEST(suite, test_cil_gen_roleallow_astnull_neg);
        SUITE_ADD_TEST(suite, test_cil_gen_roleallow_srcnull_neg);
        SUITE_ADD_TEST(suite, test_cil_gen_roleallow_tgtnull_neg);
        SUITE_ADD_TEST(suite, test_cil_gen_roleallow_extra_neg);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_roleallow_neg);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_roleallow_neg);

	SUITE_ADD_TEST(suite, test_cil_gen_avrule);
	SUITE_ADD_TEST(suite, test_cil_gen_avrule_currnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_avrule_astnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_avrule_sourcedomainnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_avrule_targetdomainnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_avrule_objectclassnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_avrule_permsnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_avrule_notlist_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_avrule_twolists_neg);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_avrule_allow);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_avrule_allow_neg);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_avrule_auditallow);
// TODO: uncomment
//	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_avrule_auditallow_neg);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_avrule_dontaudit);
// TODO: uncomment
//	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_avrule_dontaudit_neg);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_avrule_neverallow);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_avrule_neverallow_neg);

	SUITE_ADD_TEST(suite, test_cil_gen_type_rule_transition);
	SUITE_ADD_TEST(suite, test_cil_gen_type_rule_transition_currnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_type_rule_transition_astnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_type_rule_transition_srcnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_type_rule_transition_tgtnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_type_rule_transition_objnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_type_rule_transition_resultnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_type_rule_transition_extra_neg);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_type_rule_transition);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_type_rule_transition_neg);

	SUITE_ADD_TEST(suite, test_cil_gen_type_rule_change);
	SUITE_ADD_TEST(suite, test_cil_gen_type_rule_change_currnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_type_rule_change_astnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_type_rule_change_srcnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_type_rule_change_tgtnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_type_rule_change_objnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_type_rule_change_resultnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_type_rule_change_extra_neg);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_type_rule_change);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_type_rule_change_neg);

	SUITE_ADD_TEST(suite, test_cil_gen_type_rule_member);
	SUITE_ADD_TEST(suite, test_cil_gen_type_rule_member_extra_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_type_rule_member_currnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_type_rule_member_astnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_type_rule_member_srcnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_type_rule_member_tgtnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_type_rule_member_objnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_type_rule_member_resultnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_type_rule_member_extra_neg);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_type_rule_member);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_type_rule_member_neg);

	SUITE_ADD_TEST(suite, test_cil_gen_user);
	SUITE_ADD_TEST(suite, test_cil_gen_user_dbnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_user_currnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_user_astnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_user_nouser_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_user_xsinfo_neg);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_user);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_user_neg);

	SUITE_ADD_TEST(suite, test_cil_gen_sensitivity);
	SUITE_ADD_TEST(suite, test_cil_gen_sensitivity_dbnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_sensitivity_currnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_sensitivity_astnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_sensitivity_sensnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_sensitivity_senslist_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_sensitivity_extra_neg);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_sensitivity);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_sensitivity_neg);

	SUITE_ADD_TEST(suite, test_cil_gen_sensalias);
	SUITE_ADD_TEST(suite, test_cil_gen_sensalias_dbnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_sensalias_currnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_sensalias_astnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_sensalias_sensnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_sensalias_senslist_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_sensalias_aliasnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_sensalias_aliaslist_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_sensalias_extra_neg);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_sensalias);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_sensalias_neg);

	SUITE_ADD_TEST(suite, test_cil_gen_category);
	SUITE_ADD_TEST(suite, test_cil_gen_category_dbnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_category_currnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_category_astnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_category_catnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_category_catlist_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_category_extra_neg);

	SUITE_ADD_TEST(suite, test_cil_gen_catset);
	SUITE_ADD_TEST(suite, test_cil_gen_catset_dbnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_catset_currnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_catset_astnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_catset_namenull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_catset_setnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_catset_namelist_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_catset_extra_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_catset_nodefail_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_catset_notset_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_catset_settolistfail_neg);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_catset);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_catset_neg);

	SUITE_ADD_TEST(suite, test_cil_gen_catalias);
	SUITE_ADD_TEST(suite, test_cil_gen_catalias_dbnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_catalias_currnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_catalias_astnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_catalias_catnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_catalias_aliasnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_catalias_extra_neg);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_catalias);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_catalias_neg);
	
	SUITE_ADD_TEST(suite, test_cil_gen_roletype);
	SUITE_ADD_TEST(suite, test_cil_gen_roletype_currnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_roletype_dbnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_roletype_astnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_roletype_empty_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_roletype_rolelist_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_roletype_roletype_sublist_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_roletype_typelist_neg);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_roletype);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_roletype_neg);

	SUITE_ADD_TEST(suite, test_cil_gen_userrole);
	SUITE_ADD_TEST(suite, test_cil_gen_userrole_currnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_userrole_dbnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_userrole_astnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_userrole_empty_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_userrole_userlist_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_userrole_userrole_sublist_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_userrole_rolelist_neg);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_userrole);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_userrole_neg);

	SUITE_ADD_TEST(suite, test_cil_gen_classcommon);
	SUITE_ADD_TEST(suite, test_cil_gen_classcommon_dbnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_classcommon_currnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_classcommon_astnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_classcommon_missingclassname_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_classcommon_noperms_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_classcommon_extraperms_neg);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_gen_classcommon);	
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_gen_classcommon_neg);	

	SUITE_ADD_TEST(suite, test_cil_gen_catorder);
	SUITE_ADD_TEST(suite, test_cil_gen_catorder_dbnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_catorder_currnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_catorder_astnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_catorder_missingcats_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_catorder_nosublist_neg);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_catorder);	
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_catorder_neg);	

	SUITE_ADD_TEST(suite, test_cil_gen_dominance);
	SUITE_ADD_TEST(suite, test_cil_gen_dominance_dbnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_dominance_currnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_dominance_astnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_dominance_nosensitivities_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_dominance_nosublist_neg);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_gen_dominance);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_gen_dominance_neg);
	
	SUITE_ADD_TEST(suite, test_cil_gen_senscat);
	SUITE_ADD_TEST(suite, test_cil_gen_senscat_dbnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_senscat_currnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_senscat_astnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_senscat_nosensitivities_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_senscat_nosublist_neg);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_gen_senscat);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_gen_senscat_neg);
	
	SUITE_ADD_TEST(suite, test_cil_fill_level);
	SUITE_ADD_TEST(suite, test_cil_fill_level_sensnull_neg);
	SUITE_ADD_TEST(suite, test_cil_fill_level_levelnull_neg);
	SUITE_ADD_TEST(suite, test_cil_fill_level_nocat);
	SUITE_ADD_TEST(suite, test_cil_fill_level_emptycat_neg);
	
	SUITE_ADD_TEST(suite, test_cil_gen_level);
	SUITE_ADD_TEST(suite, test_cil_gen_level_emptycat_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_level_noname_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_level_nosens_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_level_dbnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_level_currnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_level_astnull_neg);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_gen_level);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_gen_level_neg);

	SUITE_ADD_TEST(suite, test__cil_build_constrain_tree);
	SUITE_ADD_TEST(suite, test__cil_build_constrain_tree_multi_constrain);
	SUITE_ADD_TEST(suite, test__cil_build_constrain_tree_currnull_neg);
	SUITE_ADD_TEST(suite, test__cil_build_constrain_tree_exprnull_neg);
	
	SUITE_ADD_TEST(suite, test_cil_gen_mlsconstrain);
	SUITE_ADD_TEST(suite, test_cil_gen_mlsconstrain_classset_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_mlsconstrain_classset_noperm_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_mlsconstrain_classset_noclass_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_mlsconstrain_permset_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_mlsconstrain_permset_noclass_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_mlsconstrain_permset_noperm_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_mlsconstrain_expression_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_mlsconstrain_dbnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_mlsconstrain_currnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_mlsconstrain_astnull_neg);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_gen_mlsconstrain);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_gen_mlsconstrain_neg);
	
	SUITE_ADD_TEST(suite, test_cil_fill_context);
	SUITE_ADD_TEST(suite, test_cil_fill_context_unnamedlvl);
	SUITE_ADD_TEST(suite, test_cil_fill_context_nocontext_neg);
	SUITE_ADD_TEST(suite, test_cil_fill_context_nouser_neg);
	SUITE_ADD_TEST(suite, test_cil_fill_context_norole_neg);
	SUITE_ADD_TEST(suite, test_cil_fill_context_notype_neg);
	SUITE_ADD_TEST(suite, test_cil_fill_context_nolowlvl_neg);
	SUITE_ADD_TEST(suite, test_cil_fill_context_nohighlvl_neg);
	SUITE_ADD_TEST(suite, test_cil_fill_context_unnamedlvl_nocontextlow_neg);
	SUITE_ADD_TEST(suite, test_cil_fill_context_unnamedlvl_nocontexthigh_neg);
	
	SUITE_ADD_TEST(suite, test_cil_gen_context);
	SUITE_ADD_TEST(suite, test_cil_gen_context_extra_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_context_doubleparen_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_context_norole_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_context_roleinparens_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_context_notype_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_context_typeinparens_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_context_nolevels_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_context_nosecondlevel_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_context_noname_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_context_nouser_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_context_dbnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_context_currnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_context_astnull_neg);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_gen_context);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_gen_context_neg);
	
	SUITE_ADD_TEST(suite, test_cil_gen_netifcon);
	SUITE_ADD_TEST(suite, test_cil_gen_netifcon_nested);
	SUITE_ADD_TEST(suite, test_cil_gen_netifcon_nested_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_netifcon_nested_emptysecondlist_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_netifcon_extra_nested_secondlist_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_netifcon_nested_missingobjects_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_netifcon_nested_secondnested_missingobjects_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_netifcon_dbnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_netifcon_currnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_netifcon_astnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_netifcon_ethmissing_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_netifcon_interfacemissing_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_netifcon_packetmissing_neg);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_gen_netifcon);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_gen_netifcon_neg);
	
	SUITE_ADD_TEST(suite, test_cil_gen_macro_type);
	SUITE_ADD_TEST(suite, test_cil_gen_macro_role);
	SUITE_ADD_TEST(suite, test_cil_gen_macro_user);
	SUITE_ADD_TEST(suite, test_cil_gen_macro_sensitivity);
	SUITE_ADD_TEST(suite, test_cil_gen_macro_category);
	SUITE_ADD_TEST(suite, test_cil_gen_macro_catset);
	SUITE_ADD_TEST(suite, test_cil_gen_macro_level);
	SUITE_ADD_TEST(suite, test_cil_gen_macro_class);
	SUITE_ADD_TEST(suite, test_cil_gen_macro_duplicate);
	SUITE_ADD_TEST(suite, test_cil_gen_macro_duplicate_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_macro_unknown_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_macro_dbnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_macro_currnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_macro_astnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_macro_unnamed_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_macro_noparam_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_macro_nosecondparam_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_macro_emptyparam_neg);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_gen_macro);
	SUITE_ADD_TEST(suite, test_cil_build_ast_node_helper_gen_macro_neg);
	
	SUITE_ADD_TEST(suite, test_cil_gen_call);
	SUITE_ADD_TEST(suite, test_cil_gen_call_anon);
	SUITE_ADD_TEST(suite, test_cil_gen_call_empty);
	SUITE_ADD_TEST(suite, test_cil_gen_call_dbnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_call_currnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_call_astnull_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_call_noname_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_call_noparams_neg);
	/* test_cil_resolve_ast.c */
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_curr_null_neg);
	SUITE_ADD_TEST(suite, test_cil_gen_perm_nodes_inval_perm_neg);

	SUITE_ADD_TEST(suite, test_cil_resolve_name);
	SUITE_ADD_TEST(suite, test_cil_resolve_name_invalid_type_neg);

	SUITE_ADD_TEST(suite, test_cil_resolve_typealias);
	SUITE_ADD_TEST(suite, test_cil_resolve_typealias_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_node_helper_typealias);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_node_helper_typealias_notype_neg);

	SUITE_ADD_TEST(suite, test_cil_resolve_classcommon);
	SUITE_ADD_TEST(suite, test_cil_resolve_classcommon_no_class_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_classcommon_no_common_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_node_helper_classcommon);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_node_helper_classcommon_neg);

	SUITE_ADD_TEST(suite, test_cil_resolve_typeattr);
	SUITE_ADD_TEST(suite, test_cil_resolve_typeattr_typedecl_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_typeattr_attrdecl_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_node_helper_typeattr);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_node_helper_typeattr_neg);

	SUITE_ADD_TEST(suite, test_cil_resolve_sensalias);
	SUITE_ADD_TEST(suite, test_cil_resolve_sensalias_sensdecl_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_node_helper_sensalias);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_node_helper_sensalias_neg);

	SUITE_ADD_TEST(suite, test_cil_resolve_catalias);
	SUITE_ADD_TEST(suite, test_cil_resolve_catalias_catdecl_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_node_helper_catalias);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_node_helper_catalias_neg);

	SUITE_ADD_TEST(suite, test_cil_resolve_catorder);
	SUITE_ADD_TEST(suite, test_cil_resolve_catorder_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_node_helper_catorder);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_node_helper_catorder_neg);

	SUITE_ADD_TEST(suite, test_cil_resolve_dominance);
	SUITE_ADD_TEST(suite, test_cil_resolve_dominance_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_node_helper_dominance);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_node_helper_dominance_neg);
	//TODO: test for __cil_set_order

	SUITE_ADD_TEST(suite, test_cil_resolve_cat_list);
	SUITE_ADD_TEST(suite, test_cil_resolve_cat_list_catrange);
	SUITE_ADD_TEST(suite, test_cil_resolve_cat_list_catname_neg);
	
	SUITE_ADD_TEST(suite, test_cil_resolve_catset);
	SUITE_ADD_TEST(suite, test_cil_resolve_catset_catlist_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_node_helper_catset);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_node_helper_catset_catlist_neg);

	SUITE_ADD_TEST(suite, test_cil_resolve_senscat);
	SUITE_ADD_TEST(suite, test_cil_resolve_senscat_sublist);
	SUITE_ADD_TEST(suite, test_cil_resolve_senscat_missingsens_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_senscat_sublist_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_senscat_category_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_senscat_currrangecat);
	SUITE_ADD_TEST(suite, test_cil_resolve_senscat_currrangecat_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_node_helper_senscat);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_node_helper_senscat_neg);
	
	SUITE_ADD_TEST(suite, test_cil_resolve_level);
	SUITE_ADD_TEST(suite, test_cil_resolve_level_sens_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_level_cat_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_level_senscat_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_node_helper_level);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_node_helper_level_neg);
	
	SUITE_ADD_TEST(suite, test_cil_resolve_mlsconstrain);
	SUITE_ADD_TEST(suite, test_cil_resolve_mlsconstrain_class_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_mlsconstrain_perm_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_mlsconstrain_perm_resolve_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_mlsconstrain_expr_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_node_helper_mlsconstrain);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_node_helper_mlsconstrain_neg);
	
	SUITE_ADD_TEST(suite, test_cil_resolve_context);
	SUITE_ADD_TEST(suite, test_cil_resolve_context_user_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_context_role_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_context_type_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_context_low_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_context_high_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_context_low_unnamed_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_context_high_unnamed_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_context_lownull_unnamed_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_context_highnull_unnamed_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_node_helper_context);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_node_helper_context_neg);
	
	SUITE_ADD_TEST(suite, test_cil_resolve_roletrans);
	SUITE_ADD_TEST(suite, test_cil_resolve_roletrans_srcdecl_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_roletrans_tgtdecl_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_roletrans_resultdecl_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_node_helper_roletrans);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_node_helper_roletrans_srcdecl_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_node_helper_roletrans_tgtdecl_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_node_helper_roletrans_resultdecl_neg);

	SUITE_ADD_TEST(suite, test_cil_resolve_roleallow);
	SUITE_ADD_TEST(suite, test_cil_resolve_roleallow_srcdecl_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_roleallow_tgtdecl_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_node_helper_roleallow);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_node_helper_roleallow_neg);

	SUITE_ADD_TEST(suite, test_cil_resolve_avrule);
	SUITE_ADD_TEST(suite, test_cil_resolve_avrule_firsttype_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_avrule_secondtype_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_avrule_class_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_avrule_perm_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_node_helper_avrule);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_node_helper_avrule_src_nores_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_node_helper_avrule_tgt_nores_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_node_helper_avrule_class_nores_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_node_helper_avrule_datum_null_neg);

	SUITE_ADD_TEST(suite, test_cil_resolve_type_rule_transition);
	SUITE_ADD_TEST(suite, test_cil_resolve_type_rule_transition_srcdecl_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_type_rule_transition_tgtdecl_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_type_rule_transition_objdecl_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_type_rule_transition_resultdecl_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_node_helper_type_rule_transition);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_node_helper_type_rule_transition_neg);

	SUITE_ADD_TEST(suite, test_cil_resolve_type_rule_change);
	SUITE_ADD_TEST(suite, test_cil_resolve_type_rule_change_srcdecl_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_type_rule_change_tgtdecl_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_type_rule_change_objdecl_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_type_rule_change_resultdecl_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_node_helper_type_rule_change);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_node_helper_type_rule_change_neg);

	SUITE_ADD_TEST(suite, test_cil_resolve_type_rule_member);
	SUITE_ADD_TEST(suite, test_cil_resolve_type_rule_member_srcdecl_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_type_rule_member_tgtdecl_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_type_rule_member_objdecl_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_type_rule_member_resultdecl_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_node_helper_type_rule_member);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_node_helper_type_rule_member_neg);

	SUITE_ADD_TEST(suite, test_cil_resolve_netifcon);
	SUITE_ADD_TEST(suite, test_cil_resolve_netifcon_otf_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_netifcon_interface_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_netifcon_unnamed);
	SUITE_ADD_TEST(suite, test_cil_resolve_netifcon_unnamed_packet_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_netifcon_unnamed_otf_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_node_helper_netifcon);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_node_helper_netifcon_neg);

	SUITE_ADD_TEST(suite, test_cil_resolve_sid);
	SUITE_ADD_TEST(suite, test_cil_resolve_sid_named_levels);
	SUITE_ADD_TEST(suite, test_cil_resolve_sid_named_context);
	SUITE_ADD_TEST(suite, test_cil_resolve_sid_named_context_wrongname_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_sid_named_context_invaliduser_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_sid_named_context_sidcontextnull_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_node_helper_sid); 
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_node_helper_sid_neg); 

	SUITE_ADD_TEST(suite, test_cil_resolve_call1_type);
	SUITE_ADD_TEST(suite, test_cil_resolve_call1_role);
	SUITE_ADD_TEST(suite, test_cil_resolve_call1_user);
	SUITE_ADD_TEST(suite, test_cil_resolve_call1_sens);
	SUITE_ADD_TEST(suite, test_cil_resolve_call1_cat);
	SUITE_ADD_TEST(suite, test_cil_resolve_call1_catset);
	SUITE_ADD_TEST(suite, test_cil_resolve_call1_catset_anon);
	SUITE_ADD_TEST(suite, test_cil_resolve_call1_class);
	SUITE_ADD_TEST(suite, test_cil_resolve_call1_level);
	SUITE_ADD_TEST(suite, test_cil_resolve_call1_level_anon);
	SUITE_ADD_TEST(suite, test_cil_resolve_call1_unknown_neg);
	//SUITE_ADD_TEST(suite, test_cil_resolve_call1_noname_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_call1_unknowncall_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_call1_extraargs_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_call1_copy_neg);
	
	SUITE_ADD_TEST(suite, test_cil_resolve_call2_type);
	SUITE_ADD_TEST(suite, test_cil_resolve_call2_role);
	SUITE_ADD_TEST(suite, test_cil_resolve_call2_user);
	SUITE_ADD_TEST(suite, test_cil_resolve_call2_sens);
	SUITE_ADD_TEST(suite, test_cil_resolve_call2_cat);
	SUITE_ADD_TEST(suite, test_cil_resolve_call2_catset);
	SUITE_ADD_TEST(suite, test_cil_resolve_call2_catset_anon);
	SUITE_ADD_TEST(suite, test_cil_resolve_call2_class);
	SUITE_ADD_TEST(suite, test_cil_resolve_call2_level);
	//SUITE_ADD_TEST(suite, test_cil_resolve_call2_level_anon);
	SUITE_ADD_TEST(suite, test_cil_resolve_call2_unknown_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_call2_name_neg);
	
	SUITE_ADD_TEST(suite, test_cil_resolve_roletype);
	SUITE_ADD_TEST(suite, test_cil_resolve_roletype_type_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_roletype_role_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_node_helper_roletype);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_node_helper_roletype_role_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_node_helper_roletype_type_neg);

	SUITE_ADD_TEST(suite, test_cil_resolve_userrole);	
	SUITE_ADD_TEST(suite, test_cil_resolve_userrole_user_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_userrole_role_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_node_helper_userrole);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_node_helper_userrole_user_neg);
	SUITE_ADD_TEST(suite, test_cil_resolve_ast_node_helper_userrole_role_neg);


	
	/* test_cil_fqn.c */
	SUITE_ADD_TEST(suite, test_cil_qualify_name);
	SUITE_ADD_TEST(suite, test_cil_qualify_name_cil_flavor);

	/* test cil_copy_ast.c */
	/*SUITE_ADD_TEST(suite, test_cil_copy_list);
	SUITE_ADD_TEST(suite, test_cil_copy_list_sublist);
	SUITE_ADD_TEST(suite, test_cil_copy_list_sublist_extra);
	SUITE_ADD_TEST(suite, test_cil_copy_list_orignull_neg);*/
	
	SUITE_ADD_TEST(suite, test_cil_copy_class);

	SUITE_ADD_TEST(suite, test_cil_copy_type);
	
	SUITE_ADD_TEST(suite, test_cil_copy_avrule);
	
	SUITE_ADD_TEST(suite, test_cil_copy_cat);
	
	SUITE_ADD_TEST(suite, test_cil_copy_catalias);
	
	SUITE_ADD_TEST(suite, test_cil_copy_level);
	
	SUITE_ADD_TEST(suite, test_cil_copy_fill_level);
	
	SUITE_ADD_TEST(suite, test_cil_copy_context);
	
	SUITE_ADD_TEST(suite, test_cil_copy_fill_context);
	SUITE_ADD_TEST(suite, test_cil_copy_fill_context_anonlow);
	SUITE_ADD_TEST(suite, test_cil_copy_fill_context_anonhigh);
	
	SUITE_ADD_TEST(suite, test_cil_copy_mlsconstrain);
	
	return suite;
}
