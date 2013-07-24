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

#include "cil_internal.h"
#include "cil_tree.h"
#include "cil_list.h"

int cil_gen_node(struct cil_db *db, struct cil_tree_node *ast_node, struct cil_symtab_datum *datum, hashtab_key_t key, enum cil_sym_index sflavor, enum cil_flavor nflavor);
int cil_parse_to_list(struct cil_tree_node *parse_cl_head, struct cil_list *ast_cl, enum cil_flavor flavor);

int cil_gen_block(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node, uint16_t is_abstract);
void cil_destroy_block(struct cil_block *block);
int cil_gen_blockinherit(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_blockinherit(struct cil_blockinherit *inherit);
int cil_gen_blockabstract(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_blockabstract(struct cil_blockabstract *abstract);
int cil_gen_in(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_in(struct cil_in *in);
int cil_gen_class(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_class(struct cil_class *class);
int cil_gen_perm(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node, unsigned int *num_perms);
void cil_destroy_perm(struct cil_perm *perm);
int cil_gen_perm_nodes(struct cil_db *db, struct cil_tree_node *current_perm, struct cil_tree_node *ast_node, enum cil_flavor flavor, unsigned int *num_perms);
int cil_fill_perms(struct cil_tree_node *start_perm, struct cil_list **perm_strs, int allow_expr_ops);
int cil_fill_classpermset(struct cil_tree_node *class_node, struct cil_classpermset *cps);
int cil_gen_classpermset(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_classpermset(struct cil_classpermset *cps);
int cil_fill_classperms(struct cil_tree_node *parse_current, struct cil_classperms **cp, int allow_set, int allow_expr_ops);
void cil_destroy_classperms(struct cil_classperms *cp);
int cil_fill_classperms_list(struct cil_tree_node *parse_current, struct cil_list **expr_list, int allow_sets, int allow_expr_ops);
int cil_gen_map_perm(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node, unsigned int *num_perms);
void cil_destroy_map_perm(struct cil_map_perm *cmp);
int cil_gen_map_class(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_map_class(struct cil_map_class *map);
int cil_gen_classmapping(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_classmapping(struct cil_classmapping *mapping);
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
int cil_gen_userlevel(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_userlevel(struct cil_userlevel *usrlvl);
int cil_gen_userrange(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_userrange(struct cil_userrange *userrange);
int cil_gen_userbounds(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_userbounds(struct cil_userbounds *userbnds);
int cil_gen_userprefix(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_userprefix(struct cil_userprefix *userprefix);
int cil_gen_selinuxuser(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
int cil_gen_selinuxuserdefault(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_selinuxuser(struct cil_selinuxuser *selinuxuser);
int cil_gen_role(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_role(struct cil_role *role);
int cil_gen_roletype(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_roletype(struct cil_roletype *roletype);
int cil_gen_userrole(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_userrole(struct cil_userrole *userrole);
int cil_gen_roletransition(struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_roletransition(struct cil_roletransition *roletrans);
int cil_gen_roleallow(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_roleallow(struct cil_roleallow *roleallow);
int cil_gen_roleattribute(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_roleattribute(struct cil_roleattribute *role);
int cil_gen_roleattributeset(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_roleattributeset(struct cil_roleattributeset *attrset);
int cil_gen_rolebounds(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_rolebounds(struct cil_rolebounds *rolebnds);
int cil_gen_avrule(struct cil_tree_node *parse_current, struct cil_tree_node *ast_node, uint32_t rule_kind);
void cil_destroy_avrule(struct cil_avrule *rule);
int cil_gen_type_rule(struct cil_tree_node *parse_current, struct cil_tree_node *ast_node, uint32_t rule_kind);
void cil_destroy_type_rule(struct cil_type_rule *rule);
int cil_gen_type(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_type(struct cil_type *type);
int cil_gen_typeattribute(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_typeattribute(struct cil_typeattribute *type);
int cil_gen_bool(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node, enum cil_flavor flavor);
void cil_destroy_bool(struct cil_bool *boolean);
int cil_gen_constrain_expr(struct cil_tree_node *current, enum cil_flavor flavor, struct cil_list **stack);
int cil_gen_expr(struct cil_tree_node *current, enum cil_flavor flavor, struct cil_list **stack, int allow_ops);
int cil_gen_boolif(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_boolif(struct cil_booleanif *bif);
int cil_gen_tunif(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_tunif(struct cil_tunableif *tif);
int cil_gen_condblock(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node, enum cil_flavor flavor);
void cil_destroy_condblock(struct cil_condblock *cb);
int cil_gen_typealias(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_typealias(struct cil_typealias *alias);
int cil_gen_typeattributeset(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_typeattributeset(struct cil_typeattributeset *attrtypes);
int cil_gen_typebounds(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_typebounds(struct cil_typebounds *typebnds);
int cil_gen_typepermissive(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_typepermissive(struct cil_typepermissive *typeperm);
int cil_gen_nametypetransition(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_nametypetransition(struct cil_nametypetransition *nametypetrans);
int cil_gen_rangetransition(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_rangetransition(struct cil_rangetransition *rangetrans);
int cil_gen_sensitivity(struct cil_db *idb, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_sensitivity(struct cil_sens *sens);
int cil_gen_sensalias(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_sensalias(struct cil_sensalias *alias);
int cil_gen_category(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_category(struct cil_cat *cat);
int cil_gen_catalias(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_catalias(struct cil_catalias *alias);
int cil_set_to_list(struct cil_tree_node *parse_current, struct cil_list *ast_cl);
int cil_gen_catrange(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_catrange(struct cil_catrange *catrange);
int cil_gen_catset(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_catset(struct cil_catset *catset);
int cil_gen_catorder(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_catorder(struct cil_catorder *catorder);
int cil_gen_dominance(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_dominance(struct cil_sens_dominates *dom);
int cil_gen_senscat(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_senscat(struct cil_senscat *senscat);
int cil_gen_level(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_level(struct cil_level *level);
int cil_fill_levelrange(struct cil_tree_node *low, struct cil_levelrange *lvlrange);
int cil_gen_levelrange(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_levelrange(struct cil_levelrange *lvlrange);
void cil_destroy_constrain_node(struct cil_tree_node *cons_node);
int cil_gen_constrain(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node, enum cil_flavor flavor);
void cil_destroy_constrain(struct cil_constrain *cons);
int cil_gen_validatetrans(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node, enum cil_flavor flavor);
void cil_destroy_validatetrans(struct cil_validatetrans *validtrans);
int cil_fill_context(struct cil_tree_node *user_node, struct cil_context *context);
int cil_gen_context(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_context(struct cil_context *context);
int cil_gen_filecon(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_filecon(struct cil_filecon *filecon);
int cil_gen_portcon(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_portcon(struct cil_portcon *portcon);
int cil_gen_nodecon(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_nodecon(struct cil_nodecon *nodecon);
int cil_gen_genfscon(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_genfscon(struct cil_genfscon *genfscon);
int cil_gen_netifcon(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_netifcon(struct cil_netifcon *netifcon);
int cil_gen_pirqcon(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_pirqcon(struct cil_pirqcon *pirqcon);
int cil_gen_iomemcon(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_iomemcon(struct cil_iomemcon *iomemcon);
int cil_gen_ioportcon(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_ioportcon(struct cil_ioportcon *ioportcon);
int cil_gen_pcidevicecon(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node);
void cil_destroy_pcidevicecon(struct cil_pcidevicecon *pcidevicecon);
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

int cil_fill_catset(struct cil_tree_node *cats, struct cil_catset *catset);
int cil_fill_catrange(struct cil_tree_node *cats, struct cil_catrange *catrange);
int cil_fill_context(struct cil_tree_node *user_node, struct cil_context *context);
int cil_fill_integer(struct cil_tree_node *int_node, uint32_t *integer);
int cil_fill_ipaddr(struct cil_tree_node *addr_node, struct cil_ipaddr *addr);
int cil_fill_level(struct cil_tree_node *sens, struct cil_level *level);

int cil_build_ast(struct cil_db *db, struct cil_tree_node *parse_tree, struct cil_tree_node *ast);

#endif /* CIL_BUILD_AST_H_ */
