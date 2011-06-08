/* 
 * Copyright (C) 2011 Tresys Technology, LLC
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef __CIL_SYMTAB_H_
#define __CIL_SYMTAB_H_

#include <sepol/policydb/symtab.h>
#include <sepol/policydb/hashtab.h>

#define CIL_STATE_ENABLED 1
#define CIL_STATE_DISABLED 2
#define CIL_STATE_DISABLING 3
struct cil_symtab_datum {
	struct cil_tree_node *node;
	char *name;
	int state;
};

void cil_symtab_datum_init(struct cil_symtab_datum *);
void cil_symtab_datum_destroy(struct cil_symtab_datum);
int cil_symtab_insert(symtab_t *, hashtab_key_t, struct cil_symtab_datum *, struct cil_tree_node *);
int cil_symtab_get_node(symtab_t *, char *, struct cil_tree_node **);
void cil_symtab_destroy(symtab_t *);

#endif
