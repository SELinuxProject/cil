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

#ifndef CIL_BUILD_AST_H_
#define CIL_BUILD_AST_H_

#include <stdint.h>

#include "cil.h"
#include "cil_tree.h"
#include "cil_list.h"

enum cil_syntax {
	SYM_STRING = 1,
	SYM_LIST = 2,
	SYM_EMPTY_LIST = 4,
	SYM_N_LISTS = 8,
	SYM_END = 16
};

int cil_gen_node(struct cil_db *db, struct cil_tree_node *ast_node, struct cil_symtab_datum *datum, hashtab_key_t key, enum cil_sym_index sflavor, enum cil_flavor nflavor);
int cil_parse_to_list(struct cil_tree_node *parse_cl_head, struct cil_list *ast_cl, enum cil_flavor flavor);

int cil_gen_block(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node, uint16_t is_abstract, char *condition);
void cil_destroy_block(struct cil_block *block);
int cil_gen_class(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_class(struct cil_class *class);
int cil_gen_perm(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_perm(struct cil_perm *perm);
int cil_gen_perm_nodes(struct cil_db *db, struct cil_tree_node *current_perm, struct cil_tree_node *ast_node);
int cil_gen_permset(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_permset(struct cil_permset *permset);
int cil_gen_common(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_common(struct cil_common *common);
int cil_gen_classcommon(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_classcommon(struct cil_classcommon *clscom);
int cil_gen_sid(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_sid(struct cil_sid *sid);
int cil_gen_sidcontext(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_sidcontext(struct cil_sidcontext *sidcon);
int cil_gen_user(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_user(struct cil_user *user);
int cil_gen_role(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_role(struct cil_role *role);
int cil_gen_roletype(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_roletype(struct cil_roletype *roletype);
int cil_gen_userrole(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_userrole(struct cil_userrole *userrole);
int cil_gen_roletrans(struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_roletrans(struct cil_role_trans *roletrans);
int cil_gen_roleallow(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_roleallow(struct cil_role_allow *roleallow);
int cil_gen_roledominance(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_roledominance(struct cil_roledominance *roledom);
int cil_gen_avrule(struct cil_tree_node *parse_current, struct cil_tree_node *ast_node, uint32_t rule_kind);
void cil_destroy_avrule(struct cil_avrule *rule);
int cil_gen_type_rule(struct cil_tree_node *parse_current, struct cil_tree_node *ast_node, uint32_t rule_kind);
void cil_destroy_type_rule(struct cil_type_rule *rule);
int cil_gen_type(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node, enum cil_flavor flavor);
void cil_destroy_type(struct cil_type *type);
int cil_gen_bool(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node, enum cil_flavor flavor);
void cil_destroy_bool(struct cil_bool *boolean);
int cil_gen_constrain_expr_stack(struct cil_tree_node *current, enum cil_flavor flavor, struct cil_tree_node **stack);
int cil_gen_expr_stack(struct cil_tree_node *current, enum cil_flavor flavor, struct cil_tree_node **stack);
int cil_gen_boolif(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_boolif(struct cil_booleanif *bif);
void cil_destroy_conditional(struct cil_conditional *cond);
int cil_gen_else(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
int cil_gen_tunif(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_tunif(struct cil_tunableif *tif);
int cil_gen_typealias(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_typealias(struct cil_typealias *alias);
int cil_gen_typeattr(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_typeattr(struct cil_typeattribute *typeattr);
int cil_gen_typebounds(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_typebounds(struct cil_typebounds *typebnds);
int cil_gen_typepermissive(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_typepermissive(struct cil_typepermissive *typeperm);
int cil_gen_filetransition(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_filetransition(struct cil_filetransition *filetrans);
int cil_gen_sensitivity(struct cil_db *idb, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_sensitivity(struct cil_sens *sens);
int cil_gen_sensalias(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_sensalias(struct cil_sensalias *alias);
int cil_gen_category(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_category(struct cil_cat *cat);
int cil_gen_catalias(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_catalias(struct cil_catalias *alias);
int cil_set_to_list(struct cil_tree_node *parse_current, struct cil_list *ast_cl, uint8_t sublists);
int cil_fill_cat_list(struct cil_tree_node *start, struct cil_list *list);
int cil_gen_catset(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_catset(struct cil_catset *catset);
int cil_gen_catorder(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_catorder(struct cil_catorder *catorder);
int cil_gen_dominance(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_dominance(struct cil_sens_dominates *dom);
int cil_gen_senscat(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_senscat(struct cil_senscat *senscat);
int cil_fill_level(struct cil_tree_node *sens, struct cil_level *level);
int cil_gen_level(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_level(struct cil_level *level);
void cil_destroy_constrain_node(struct cil_tree_node *cons_node);
int cil_gen_constrain(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node, enum cil_flavor flavor);
void cil_destroy_constrain(struct cil_constrain *cons);
int cil_fill_context(struct cil_tree_node *user_node, struct cil_context *context);
int cil_gen_context(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_context(struct cil_context *context);
int cil_gen_filecon(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_filecon(struct cil_filecon *filecon);
int cil_gen_portcon(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_portcon(struct cil_portcon *portcon);
int cil_fill_ipaddr(struct cil_tree_node *addr_node, struct cil_ipaddr *addr);
int cil_gen_nodecon(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_nodecon(struct cil_nodecon *nodecon);
int cil_gen_genfscon(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_genfscon(struct cil_genfscon *genfscon);
int cil_gen_netifcon(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_netifcon(struct cil_netifcon *netifcon);
int cil_gen_fsuse(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_fsuse(struct cil_fsuse *fsuse);
void cil_destroy_param(struct cil_param *param);
int cil_gen_macro(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_macro(struct cil_macro *macro);
int cil_gen_call(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_call(struct cil_call *call);
void cil_destroy_args(struct cil_args *args);
int cil_gen_optional(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_optional(struct cil_optional *optional);
int cil_gen_policycap(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_policycap(struct cil_policycap *polcap);
int cil_gen_ipaddr(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_ipaddr(struct cil_ipaddr *ipaddr);

int cil_build_ast(struct cil_db *db, struct cil_tree_node *parse_tree, struct cil_tree_node *ast);

#endif /* CIL_BUILD_AST_H_ */
