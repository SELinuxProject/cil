#ifndef TEST_CIL_COPY_AST_H_
#define TEST_CIL_COPY_AST_H_

#include "CuTest.h"

void test_cil_copy_list(CuTest *);
void test_cil_copy_list_sublist(CuTest *);
void test_cil_copy_list_sublist_extra(CuTest *);
void test_cil_copy_list_orignull_neg(CuTest *);

void test_cil_copy_block(CuTest *);
void test_cil_copy_node_helper_block(CuTest *tc); 
void test_cil_copy_node_helper_block_neg(CuTest *tc); 

void test_cil_copy_perm(CuTest *);
void test_cil_copy_node_helper_perm(CuTest *tc); 
void test_cil_copy_node_helper_perm_neg(CuTest *tc); 

void test_cil_copy_class(CuTest *);
void test_cil_copy_node_helper_class(CuTest *tc); 
void test_cil_copy_node_helper_class_neg(CuTest *tc); 

void test_cil_copy_common(CuTest *);
void test_cil_copy_node_helper_common(CuTest *tc); 
void test_cil_copy_node_helper_common_neg(CuTest *tc); 

void test_cil_copy_classcommon(CuTest *);
void test_cil_copy_node_helper_classcommon(CuTest *tc); 

void test_cil_copy_sid(CuTest *);
void test_cil_copy_node_helper_sid(CuTest *tc); 
void test_cil_copy_node_helper_sid_neg(CuTest *tc); 

void test_cil_copy_sidcontext(CuTest *);
void test_cil_copy_node_helper_sidcontext(CuTest *tc); 

void test_cil_copy_user(CuTest *);
void test_cil_copy_node_helper_user(CuTest *tc); 
void test_cil_copy_node_helper_user_neg(CuTest *tc); 

void test_cil_copy_role(CuTest *);
void test_cil_copy_node_helper_role(CuTest *tc); 
void test_cil_copy_node_helper_role_neg(CuTest *tc); 

void test_cil_copy_userrole(CuTest *);
void test_cil_copy_node_helper_userrole(CuTest *tc); 

void test_cil_copy_type(CuTest *);
void test_cil_copy_node_helper_type(CuTest *tc); 
void test_cil_copy_node_helper_type_neg(CuTest *tc); 

void test_cil_copy_typeattr(CuTest *);
void test_cil_copy_node_helper_typeattr(CuTest *tc); 

void test_cil_copy_typealias(CuTest *);
void test_cil_copy_node_helper_typealias(CuTest *tc); 
void test_cil_copy_node_helper_typealias_neg(CuTest *tc); 

void test_cil_copy_bool(CuTest *);
void test_cil_copy_node_helper_bool(CuTest *tc); 
void test_cil_copy_node_helper_bool_neg(CuTest *tc); 

void test_cil_copy_avrule(CuTest *);
void test_cil_copy_node_helper_avrule(CuTest *tc); 

void test_cil_copy_type_rule(CuTest *);
void test_cil_copy_node_helper_type_rule(CuTest *tc); 

void test_cil_copy_sens(CuTest *);
void test_cil_copy_node_helper_sens(CuTest *tc); 
void test_cil_copy_node_helper_sens_neg(CuTest *tc); 

void test_cil_copy_sensalias(CuTest *);
void test_cil_copy_node_helper_sensalias(CuTest *tc); 
void test_cil_copy_node_helper_sensalias_neg(CuTest *tc); 

void test_cil_copy_cat(CuTest *);
void test_cil_copy_node_helper_cat(CuTest *tc); 
void test_cil_copy_node_helper_cat_neg(CuTest *tc); 

void test_cil_copy_catalias(CuTest *);
void test_cil_copy_node_helper_catalias(CuTest *tc); 
void test_cil_copy_node_helper_catalias_neg(CuTest *tc); 

void test_cil_copy_senscat(CuTest *);
void test_cil_copy_node_helper_senscat(CuTest *tc); 

void test_cil_copy_catorder(CuTest *);
void test_cil_copy_node_helper_catorder(CuTest *tc); 

void test_cil_copy_dominance(CuTest *);
void test_cil_copy_node_helper_dominance(CuTest *tc); 

void test_cil_copy_level(CuTest *);
void test_cil_copy_node_helper_level(CuTest *tc); 
void test_cil_copy_node_helper_level_neg(CuTest *tc); 

void test_cil_copy_fill_level(CuTest *);

void test_cil_copy_context(CuTest *);
void test_cil_copy_node_helper_context(CuTest *tc); 
void test_cil_copy_node_helper_context_neg(CuTest *tc); 

void test_cil_copy_netifcon(CuTest *);
void test_cil_copy_netifcon_nested(CuTest *);
void test_cil_copy_node_helper_netifcon(CuTest *tc); 
void test_cil_copy_node_helper_netifcon_neg(CuTest *tc); 

void test_cil_copy_fill_context(CuTest *);
void test_cil_copy_fill_context_anonlow(CuTest *);
void test_cil_copy_fill_context_anonhigh(CuTest *);

void test_cil_copy_call(CuTest *);
void test_cil_copy_node_helper_call(CuTest *tc); 

void test_cil_copy_optional(CuTest *);
void test_cil_copy_node_helper_optional(CuTest *tc); 
void test_cil_copy_node_helper_optional_neg(CuTest *tc); 

void test_cil_copy_constrain(CuTest *);

void test_cil_copy_ast(CuTest *);
void test_cil_copy_ast_neg(CuTest *);

#endif
