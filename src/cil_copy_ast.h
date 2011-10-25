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

int cil_copy_list(struct cil_list *orig, struct cil_list **copy);

int cil_copy_block(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_perm(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_class(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_classmap_perm(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_classmap(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_classmapping(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_permset(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_fill_classpermset(struct cil_classpermset *orig, struct cil_classpermset *new);
int cil_copy_classpermset(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_common(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_classcommon(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_sid(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_sidcontext(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_user(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_userrole(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_userlevel(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_userrange(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_userbounds(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_userprefix(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_role(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_roletype(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_rolebounds(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_roledominance(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_roleallow(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_type(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_typebounds(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_typepermissive(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_typeattribute(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_typeattributetypes(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_typealias(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_filetransition(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_rangetransition(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_bool(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_avrule(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_type_rule(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_sens(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_sensalias(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_cat(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_catalias(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_catrange(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_catset(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_senscat(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_catorder(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_dominance(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_fill_level(struct cil_level *orig, struct cil_level *new);
int cil_copy_level(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_fill_levelrange(struct cil_levelrange *orig, struct cil_levelrange *new);
int cil_copy_levelrange(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_fill_context(struct cil_context *orig, struct cil_context *new);
int cil_copy_context(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_netifcon(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_genfscon(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_filecon(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_nodecon(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_portcon(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_pirqcon(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_iomemcon(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_ioportcon(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_pcidevicecon(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_fsuse(struct cil_db *db, void *data, void **copy, symtab_t *symtab); 
int cil_copy_exrp(struct cil_db *db, struct cil_list *orig, struct cil_list **new);
int cil_copy_constrain(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_validatetrans(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_call(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_optional(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_fill_ipaddr(struct cil_ipaddr *orig, struct cil_ipaddr *new);
int cil_copy_ipaddr(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_conditional(struct cil_db *db, void *data, void **copy, symtab_t *symtab);
int cil_copy_boolif(struct cil_db *db, void *data, void **copy, symtab_t *symtab);

int cil_copy_ast(struct cil_db *db, struct cil_tree_node *orig, struct cil_tree_node *dest);

#endif
