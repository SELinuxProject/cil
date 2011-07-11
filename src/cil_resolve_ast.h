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

#ifndef CIL_RESOLVE_AST_H_
#define CIL_RESOLVE_AST_H_

#include <stdint.h>

#include "cil.h"
#include "cil_tree.h"

int cil_resolve_avrule(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call);
int cil_resolve_type_rule(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call);
int cil_resolve_list(struct cil_db *db, struct cil_list *str_list, struct cil_list *res_list, struct cil_tree_node *current, enum cil_sym_index sym_index, struct cil_call *call);
int cil_resolve_attrtypes(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call);
int cil_resolve_typealias(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call);
int cil_resolve_typebounds(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call);
int cil_resolve_typepermissive(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call);
int cil_resolve_filetransition(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call);
int cil_resolve_rangetransition(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call);
int cil_resolve_classcommon(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call);
int cil_reset_class(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call);
int cil_reset_sens(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call);
int cil_resolve_userrole(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call);
int cil_resolve_userbounds(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call);
int cil_resolve_roletype(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call);
int cil_resolve_roletrans(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call);
int cil_resolve_roleallow(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call);
int cil_resolve_roledominance(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call);
int cil_resolve_rolebounds(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call);
int cil_resolve_sensalias(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call);
int cil_resolve_catalias(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call);
int cil_resolve_catorder(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call);
int cil_resolve_dominance(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call);
int cil_resolve_cat_list(struct cil_db *db, struct cil_tree_node *current, struct cil_list *cat_list, struct cil_list *res_cat_list, struct cil_call *call);
int cil_resolve_catset(struct cil_db *db, struct cil_tree_node *current, struct cil_catset *catset, struct cil_call *call);
int cil_resolve_senscat(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call);
int cil_resolve_level(struct cil_db *db, struct cil_tree_node *current, struct cil_level *level, struct cil_call *call); 
int cil_resolve_constrain(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call);
int cil_resolve_context(struct cil_db *db, struct cil_tree_node *current, struct cil_context *context, struct cil_call *call);
int cil_resolve_filecon(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call);
int cil_resolve_portcon(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call);
int cil_resolve_genfscon(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call);
int cil_resolve_nodecon(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call);
int cil_resolve_netifcon(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call);
int cil_resolve_fsuse(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call);
int cil_resolve_sidcontext(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call);
int cil_resolve_call1(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call);
int cil_resolve_call2(struct cil_db *, struct cil_tree_node *, struct cil_call *);
int cil_resolve_name_call_args(struct cil_call *call, char *name, enum cil_sym_index sym_index, struct cil_tree_node **node);
int cil_resolve_expr_stack(struct cil_db *db, struct cil_tree_node *expr_stack, struct cil_tree_node *parent, struct cil_call *call);
int cil_resolve_boolif(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call);
int cil_evaluate_expr_stack(struct cil_tree_node *stack, uint16_t *result);
int cil_resolve_tunif(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call);

int cil_resolve_ast(struct cil_db *db, struct cil_tree_node *current);
int cil_resolve_name(struct cil_db *db, struct cil_tree_node *ast_node, char *name, enum cil_sym_index sym_index, struct cil_call *call, struct cil_tree_node **node);

#endif /* CIL_RESOLVE_AST_H_ */
