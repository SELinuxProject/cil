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

#ifndef CIL_POLICY_H_
#define CIL_POLICY_H_

#include "cil_tree.h"
#include "cil_list.h"
#include "cil.h"

struct cil_multimap_item {
	struct cil_symtab_datum *key;
	struct cil_list *values;
};

struct fc_data {
	int meta;
	int stem_len;
	int str_len;
};

int cil_combine_policy(FILE **, FILE *);
int cil_name_to_policy(FILE **, struct cil_tree_node *);
void cil_context_to_policy(FILE **, uint32_t, struct cil_context *);
int cil_gen_policy(struct cil_db *);
int cil_nodecon_compare(const void *a, const void *b);
int cil_filecon_compare(const void *a, const void *b);
int cil_portcon_compare(const void *a, const void *b);
int cil_genfscon_compare(const void *a, const void *b);
int cil_netifcon_compare(const void *a, const void *b);
int cil_fsuse_compare(const void *a, const void *b);

#endif
