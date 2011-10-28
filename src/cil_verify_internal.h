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

#ifndef CIL_VERIFY_H_
#define CIL_VERIFY_H_

#include <stdint.h>

#include "cil.h"
#include "cil_tree.h"
#include "cil_list.h"

enum cil_syntax {
	SYM_STRING = 1,
	SYM_LIST = 2,
	SYM_EMPTY_LIST = 4,
	SYM_N_LISTS = 8,
	SYM_N_STRINGS = 16,
	SYM_END = 32
};

struct cil_args_verify {
	struct cil_db *db;
	struct cil_complex_symtab *csymtab;
	symtab_t *senstab;
	int *avrule_cnt;
	int *nseuserdflt;
};

struct cil_args_verify_order {
	struct cil_list *order;
	struct cil_list_item *ordered;
	uint32_t *found;
	uint32_t *empty;
	uint32_t *flavor;
};

int __cil_verify_name(const char *name);
int __cil_verify_syntax(struct cil_tree_node *parse_current, enum cil_syntax s[], int len);
int __cil_verify_expr_syntax(struct cil_tree_node *node, enum cil_flavor nflavor, enum cil_flavor eflavor);
int __cil_verify_constrain_expr(struct cil_tree_node *current, enum cil_flavor flavor, struct cil_conditional *cond, struct cil_list *stack);
int __cil_verify_expr_oper_flavor(const char *key, struct cil_conditional *cond, enum cil_flavor flavor);
int __cil_verify_ranges(struct cil_list *list);
int __cil_verify_order_node_helper(struct cil_tree_node *node, uint32_t *finished, void *extra_args);
int __cil_verify_order(struct cil_list *order, struct cil_tree_node *current, enum cil_flavor flavor);
int __cil_verify_catrange(struct cil_db *db, struct cil_catrange *catrange, struct cil_cat *cat);
int __cil_verify_senscat(struct cil_db *db, struct cil_sens *sens, struct cil_cat *cat);
int __cil_verify_senscatset(struct cil_db *db, struct cil_sens *sens, struct cil_catset *catset);
int __cil_verify_helper(struct cil_tree_node *node, __attribute__((unused)) uint32_t *finished, void *extra_args);

#endif
