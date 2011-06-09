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

#ifndef CIL_LIST_H_
#define CIL_LIST_H_

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

struct cil_list {
	struct cil_list_item *head;
};

struct cil_list_item {
	struct cil_list_item *next;
	uint32_t flavor;
	void *data;
};

void cil_list_init(struct cil_list **);
void cil_list_destroy (struct cil_list **, uint8_t);
void cil_list_item_init(struct cil_list_item **);
void cil_list_item_destroy(struct cil_list_item **, uint8_t);
int cil_list_get_tail(struct cil_list *, struct cil_list_item **);
int cil_list_append_item(struct cil_list *, struct cil_list_item *);
int cil_list_prepend_item(struct cil_list *, struct cil_list_item *);
void cil_print_list_lists(struct cil_list *);

#endif
