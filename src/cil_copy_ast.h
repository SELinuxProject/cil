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

#ifndef CIL_COPY_H_
#define CIL_COPY_H_

#include "cil.h"
#include "cil_tree.h"
#include "cil_symtab.h"

void cil_copy_list(struct cil_list *, struct cil_list **);
int cil_copy_block(struct cil_tree_node *, struct cil_tree_node *, symtab_t *);
int cil_copy_perm(struct cil_tree_node *, struct cil_tree_node *, symtab_t *);
int cil_copy_class(struct cil_tree_node *, struct cil_tree_node *, symtab_t *);
int cil_copy_common(struct cil_tree_node *, struct cil_tree_node *, symtab_t *);
void cil_copy_classcommon(struct cil_classcommon *, struct cil_classcommon **);
int cil_copy_sid(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab);
int cil_copy_sidcontext(struct cil_tree_node *, struct cil_tree_node *, symtab_t *);
int cil_copy_user(struct cil_tree_node *, struct cil_tree_node *, symtab_t *);
int cil_copy_role(struct cil_tree_node *, struct cil_tree_node *, symtab_t *);
void cil_copy_userrole(struct cil_userrole *, struct cil_userrole **);
int cil_copy_type(struct cil_tree_node *, struct cil_tree_node *, symtab_t *);
void cil_copy_typeattr(struct cil_typeattribute *, struct cil_typeattribute **);
int cil_copy_typealias(struct cil_tree_node *, struct cil_tree_node *, symtab_t *);
void cil_copy_filetransition(struct cil_filetransition *, struct cil_filetransition **);
int cil_copy_bool(struct cil_tree_node *, struct cil_tree_node *, symtab_t *);
void cil_copy_avrule(struct cil_avrule *, struct cil_avrule **);
void cil_copy_type_rule(struct cil_type_rule *, struct cil_type_rule **);
int cil_copy_sens(struct cil_tree_node *, struct cil_tree_node *, symtab_t *);
int cil_copy_sensalias(struct cil_tree_node *, struct cil_tree_node *, symtab_t *);
int cil_copy_cat(struct cil_tree_node *, struct cil_tree_node *, symtab_t *);
int cil_copy_catalias(struct cil_tree_node *, struct cil_tree_node *, symtab_t *);
void cil_copy_senscat(struct cil_senscat *, struct cil_senscat **);
void cil_copy_catorder(struct cil_catorder *, struct cil_catorder **);
void cil_copy_dominance(struct cil_sens_dominates *, struct cil_sens_dominates **);
void cil_copy_fill_level(struct cil_level *, struct cil_level *);
int cil_copy_level(struct cil_tree_node *, struct cil_tree_node *, symtab_t *);
void cil_copy_fill_context(struct cil_context *, struct cil_context *);
int cil_copy_context(struct cil_tree_node *, struct cil_tree_node *, symtab_t *);
int cil_copy_netifcon(struct cil_tree_node *, struct cil_tree_node *, symtab_t *);
void cil_copy_conditional(struct cil_conditional *orig, struct cil_conditional *new);
int cil_copy_boolif(struct cil_booleanif *orig, struct cil_booleanif **copy);
void cil_copy_constrain(struct cil_db *, struct cil_constrain *, struct cil_constrain **);
void cil_copy_call(struct cil_db *, struct cil_call *, struct cil_call **);
int cil_copy_optional(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab);
int cil_copy_nodecon(struct cil_nodecon *, struct cil_nodecon **);
void cil_copy_fill_ipaddr(struct cil_ipaddr *, struct cil_ipaddr *);
int cil_copy_ipaddr(struct cil_tree_node *, struct cil_tree_node *, symtab_t *);

int cil_copy_ast(struct cil_db *, struct cil_tree_node *, struct cil_tree_node *);

#endif
