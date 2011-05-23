#ifndef TEST_CIL_RESOLVE_AST_H_
#define TEST_CIL_RESOLVE_AST_H_

#include "CuTest.h"

void test_cil_resolve_name(CuTest *);
void test_cil_resolve_name_invalid_type_neg(CuTest *);

void test_cil_resolve_ast_curr_null_neg(CuTest *);


/*
	cil_resolve test cases
*/

void test_cil_resolve_roleallow(CuTest *);
void test_cil_resolve_roleallow_srcdecl_neg(CuTest *);
void test_cil_resolve_roleallow_tgtdecl_neg(CuTest *);

void test_cil_resolve_sensalias(CuTest *);
void test_cil_resolve_sensalias_sensdecl_neg(CuTest *);

void test_cil_resolve_catalias(CuTest *);
void test_cil_resolve_catalias_catdecl_neg(CuTest *);

void test_cil_resolve_catorder(CuTest *);
void test_cil_resolve_catorder_neg(CuTest *);

void test_cil_resolve_dominance(CuTest *);
void test_cil_resolve_dominance_neg(CuTest *);

void test_cil_resolve_cat_list(CuTest *);
void test_cil_resolve_cat_list_catrange(CuTest *);
void test_cil_resolve_cat_list_catname_neg(CuTest *);

void test_cil_resolve_catset(CuTest *);
void test_cil_resolve_catset_catlist_neg(CuTest *);

void test_cil_resolve_senscat(CuTest *);
void test_cil_resolve_senscat_sublist(CuTest *);
void test_cil_resolve_senscat_missingsens_neg(CuTest *);
void test_cil_resolve_senscat_sublist_neg(CuTest *);
void test_cil_resolve_senscat_category_neg(CuTest *);
void test_cil_resolve_senscat_currrangecat(CuTest *);
void test_cil_resolve_senscat_currrangecat_neg(CuTest *);

void test_cil_resolve_level(CuTest *);
void test_cil_resolve_level_sens_neg(CuTest *);
void test_cil_resolve_level_cat_neg(CuTest *);
void test_cil_resolve_level_senscat_neg(CuTest *);

void test_cil_resolve_constrain(CuTest *);
void test_cil_resolve_constrain_class_neg(CuTest *);
void test_cil_resolve_constrain_perm_neg(CuTest *);
void test_cil_resolve_constrain_perm_resolve_neg(CuTest *);
void test_cil_resolve_constrain_expr_neg(CuTest *);

void test_cil_resolve_context(CuTest *);
void test_cil_resolve_context_user_neg(CuTest *);
void test_cil_resolve_context_role_neg(CuTest *);
void test_cil_resolve_context_type_neg(CuTest *);
void test_cil_resolve_context_low_neg(CuTest *);
void test_cil_resolve_context_high_neg(CuTest *);
void test_cil_resolve_context_low_unnamed_neg(CuTest *);
void test_cil_resolve_context_high_unnamed_neg(CuTest *);
void test_cil_resolve_context_lownull_unnamed_neg(CuTest *);
void test_cil_resolve_context_highnull_unnamed_neg(CuTest *);

void test_cil_resolve_roletrans(CuTest *);
void test_cil_resolve_roletrans_srcdecl_neg(CuTest *);
void test_cil_resolve_roletrans_tgtdecl_neg(CuTest *);
void test_cil_resolve_roletrans_resultdecl_neg(CuTest *);

void test_cil_resolve_typeattr(CuTest *);
void test_cil_resolve_typeattr_typedecl_neg(CuTest *);
void test_cil_resolve_typeattr_attrdecl_neg(CuTest *);

void test_cil_resolve_typealias(CuTest *);
void test_cil_resolve_typealias_neg(CuTest *);

void test_cil_resolve_classcommon(CuTest *);
void test_cil_resolve_classcommon_no_class_neg(CuTest *);
void test_cil_resolve_classcommon_neg(CuTest *);
void test_cil_resolve_classcommon_no_common_neg(CuTest *);

void test_cil_resolve_avrule(CuTest *);
void test_cil_resolve_avrule_firsttype_neg(CuTest *);
void test_cil_resolve_avrule_secondtype_neg(CuTest *);
void test_cil_resolve_avrule_class_neg(CuTest *);
void test_cil_resolve_avrule_perm_neg(CuTest *);

void test_cil_resolve_type_rule_transition(CuTest *);
void test_cil_resolve_type_rule_transition_srcdecl_neg(CuTest *);
void test_cil_resolve_type_rule_transition_tgtdecl_neg(CuTest *);
void test_cil_resolve_type_rule_transition_objdecl_neg(CuTest *);
void test_cil_resolve_type_rule_transition_resultdecl_neg(CuTest *);

void test_cil_resolve_type_rule_change(CuTest *);
void test_cil_resolve_type_rule_change_srcdecl_neg(CuTest *);
void test_cil_resolve_type_rule_change_tgtdecl_neg(CuTest *);
void test_cil_resolve_type_rule_change_objdecl_neg(CuTest *);
void test_cil_resolve_type_rule_change_resultdecl_neg(CuTest *);

void test_cil_resolve_type_rule_member(CuTest *);
void test_cil_resolve_type_rule_member_srcdecl_neg(CuTest *);
void test_cil_resolve_type_rule_member_tgtdecl_neg(CuTest *);
void test_cil_resolve_type_rule_member_objdecl_neg(CuTest *);
void test_cil_resolve_type_rule_member_resultdecl_neg(CuTest *);

void test_cil_resolve_netifcon(CuTest *);
void test_cil_resolve_netifcon_otf_neg(CuTest *);
void test_cil_resolve_netifcon_interface_neg(CuTest *);
void test_cil_resolve_netifcon_unnamed(CuTest *);
void test_cil_resolve_netifcon_unnamed_packet_neg(CuTest *);
void test_cil_resolve_netifcon_unnamed_otf_neg(CuTest *);
void test_cil_resolve_ast_node_helper_netifcon(CuTest *tc);
void test_cil_resolve_ast_node_helper_netifcon_neg(CuTest *tc);

void test_cil_resolve_sidcontext(CuTest *);
void test_cil_resolve_sidcontext_named_levels(CuTest *);
void test_cil_resolve_sidcontext_named_context(CuTest *);
void test_cil_resolve_sidcontext_named_context_wrongname_neg(CuTest *tc);
void test_cil_resolve_sidcontext_named_context_invaliduser_neg(CuTest *tc);
void test_cil_resolve_sidcontext_named_context_sidcontextnull_neg(CuTest *tc);
void test_cil_resolve_ast_node_helper_sidcontext(CuTest *tc);
void test_cil_resolve_ast_node_helper_sidcontext_neg(CuTest *tc);

void test_cil_resolve_call1_type(CuTest *);
void test_cil_resolve_call1_role(CuTest *);
void test_cil_resolve_call1_user(CuTest *);
void test_cil_resolve_call1_sens(CuTest *);
void test_cil_resolve_call1_cat(CuTest *);
void test_cil_resolve_call1_catset(CuTest *);
void test_cil_resolve_call1_catset_anon(CuTest *);
void test_cil_resolve_call1_level(CuTest *);
void test_cil_resolve_call1_class(CuTest *);
void test_cil_resolve_call1_level(CuTest *);
void test_cil_resolve_call1_level_anon(CuTest *);
void test_cil_resolve_call1_unknown_neg(CuTest *);
void test_cil_resolve_call1_noname_neg(CuTest *);
void test_cil_resolve_call1_unknowncall_neg(CuTest *);
void test_cil_resolve_call1_extraargs_neg(CuTest *);
void test_cil_resolve_call1_copy_neg(CuTest *);

void test_cil_resolve_call2_type(CuTest *);
void test_cil_resolve_call2_role(CuTest *);
void test_cil_resolve_call2_user(CuTest *);
void test_cil_resolve_call2_sens(CuTest *);
void test_cil_resolve_call2_cat(CuTest *);
void test_cil_resolve_call2_catset(CuTest *);
void test_cil_resolve_call2_catset_anon(CuTest *);
void test_cil_resolve_call2_level(CuTest *);
void test_cil_resolve_call2_class(CuTest *);
void test_cil_resolve_call2_level(CuTest *);
void test_cil_resolve_call2_level_anon(CuTest *);
void test_cil_resolve_call2_unknown_neg(CuTest *);
void test_cil_resolve_call2_name_neg(CuTest *);

void test_cil_resolve_name_call_args(CuTest *);
void test_cil_resolve_name_call_args_extraparams(CuTest *);
void test_cil_resolve_name_call_args_diffflavor(CuTest *);
void test_cil_resolve_name_call_args_callnull_neg(CuTest *);
void test_cil_resolve_name_call_args_namenull_neg(CuTest *);
void test_cil_resolve_name_call_args_callargsnull_neg(CuTest *);
void test_cil_resolve_name_call_args_name_neg(CuTest *);

void test_cil_resolve_expr_stack(CuTest *);
void test_cil_resolve_expr_stack_neg(CuTest *);

void test_cil_resolve_boolif(CuTest *);
void test_cil_resolve_boolif_neg(CuTest *);

void test_cil_evaluate_expr_stack_and(CuTest *);
void test_cil_evaluate_expr_stack_not(CuTest *);
void test_cil_evaluate_expr_stack_or(CuTest *);
void test_cil_evaluate_expr_stack_xor(CuTest *);
void test_cil_evaluate_expr_stack_eq(CuTest *);
void test_cil_evaluate_expr_stack_neq(CuTest *);
void test_cil_evaluate_expr_stack_oper1(CuTest *);
void test_cil_evaluate_expr_stack_neg(CuTest *);

void test_cil_resolve_tunif_false(CuTest *);
void test_cil_resolve_tunif_true(CuTest *);
void test_cil_resolve_tunif_resolveexpr_neg(CuTest *);
void test_cil_resolve_tunif_evaluateexpr_neg(CuTest *);

void test_cil_resolve_roletype(CuTest *tc);
void test_cil_resolve_roletype_type_neg(CuTest *tc);
void test_cil_resolve_roletype_role_neg(CuTest *tc);

void test_cil_resolve_userrole(CuTest *tc);
void test_cil_resolve_userrole_user_neg(CuTest *tc);
void test_cil_resolve_userrole_role_neg(CuTest *tc);


/*
	__cil_resolve_ast_node_helper test cases
*/

void test_cil_resolve_ast_node_helper_call1(CuTest *);
void test_cil_resolve_ast_node_helper_call1_neg(CuTest *);

void test_cil_resolve_ast_node_helper_call2(CuTest *);
void test_cil_resolve_ast_node_helper_call2_neg(CuTest *);

void test_cil_resolve_ast_node_helper_boolif(CuTest *);
void test_cil_resolve_ast_node_helper_boolif_neg(CuTest *);

void test_cil_resolve_ast_node_helper_tunif(CuTest *);
void test_cil_resolve_ast_node_helper_tunif_neg(CuTest *);

void test_cil_resolve_ast_node_helper_catorder(CuTest *);
void test_cil_resolve_ast_node_helper_catorder_neg(CuTest *);

void test_cil_resolve_ast_node_helper_dominance(CuTest *);
void test_cil_resolve_ast_node_helper_dominance_neg(CuTest *);

void test_cil_resolve_ast_node_helper_roleallow(CuTest *);
void test_cil_resolve_ast_node_helper_roleallow_neg(CuTest *);

void test_cil_resolve_ast_node_helper_sensalias(CuTest *);
void test_cil_resolve_ast_node_helper_sensalias_neg(CuTest *);

void test_cil_resolve_ast_node_helper_catalias(CuTest *);
void test_cil_resolve_ast_node_helper_catalias_neg(CuTest *);

void test_cil_resolve_ast_node_helper_catset(CuTest *);
void test_cil_resolve_ast_node_helper_catset_catlist_neg(CuTest *);

void test_cil_resolve_ast_node_helper_level(CuTest *);
void test_cil_resolve_ast_node_helper_level_neg(CuTest *);

void test_cil_resolve_ast_node_helper_constrain(CuTest *);
void test_cil_resolve_ast_node_helper_constrain_neg(CuTest *);

void test_cil_resolve_ast_node_helper_context(CuTest *);
void test_cil_resolve_ast_node_helper_context_neg(CuTest *);

void test_cil_resolve_ast_node_helper_senscat(CuTest *tc);
void test_cil_resolve_ast_node_helper_senscat_neg(CuTest *tc);

void test_cil_resolve_ast_node_helper_roletrans(CuTest *);
void test_cil_resolve_ast_node_helper_roletrans_srcdecl_neg(CuTest *);
void test_cil_resolve_ast_node_helper_roletrans_tgtdecl_neg(CuTest *);
void test_cil_resolve_ast_node_helper_roletrans_resultdecl_neg(CuTest *);

void test_cil_resolve_ast_node_helper_typeattr(CuTest *);
void test_cil_resolve_ast_node_helper_typeattr_neg(CuTest *);

void test_cil_resolve_ast_node_helper_typealias(CuTest *);
void test_cil_resolve_ast_node_helper_typealias_notype_neg(CuTest *);

void test_cil_resolve_ast_node_helper_avrule(CuTest *);
void test_cil_resolve_ast_node_helper_avrule_src_nores_neg(CuTest *);
void test_cil_resolve_ast_node_helper_avrule_tgt_nores_neg(CuTest *);
void test_cil_resolve_ast_node_helper_avrule_class_nores_neg(CuTest *);
void test_cil_resolve_ast_node_helper_avrule_datum_null_neg(CuTest *);

void test_cil_resolve_ast_node_helper_type_rule_transition(CuTest *);
void test_cil_resolve_ast_node_helper_type_rule_transition_neg(CuTest *);

void test_cil_resolve_ast_node_helper_type_rule_change(CuTest *);
void test_cil_resolve_ast_node_helper_type_rule_change_neg(CuTest *);

void test_cil_resolve_ast_node_helper_type_rule_member(CuTest *);
void test_cil_resolve_ast_node_helper_type_rule_member_neg(CuTest *);

void test_cil_resolve_ast_node_helper_roletype(CuTest *tc);
void test_cil_resolve_ast_node_helper_roletype_role_neg(CuTest *tc);
void test_cil_resolve_ast_node_helper_roletype_type_neg(CuTest *tc);

void test_cil_resolve_ast_node_helper_userrole(CuTest *tc);
void test_cil_resolve_ast_node_helper_userrole_user_neg(CuTest *tc);
void test_cil_resolve_ast_node_helper_userrole_role_neg(CuTest *tc);

void test_cil_resolve_ast_node_helper_classcommon(CuTest *tc);
void test_cil_resolve_ast_node_helper_classcommon_neg(CuTest *tc);
#endif
