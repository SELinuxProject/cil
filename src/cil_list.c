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

#include <stdlib.h>
#include <stdio.h>

#include <sepol/policydb/policydb.h>
#include <sepol/policydb/symtab.h>

#include "cil.h"
#include "cil_mem.h"
#include "cil_tree.h"
#include "cil_symtab.h"
#include "cil_build_ast.h"

void cil_list_init(struct cil_list **list)
{
	struct cil_list *new_list = cil_malloc(sizeof(*new_list));
	new_list->head = NULL;

	*list = new_list;
}

void cil_list_destroy(struct cil_list **list, uint8_t destroy_data)
{
	struct cil_list_item *item = (*list)->head;
	struct cil_list_item *next = NULL;
	while (item != NULL)
	{
		if (item->flavor == CIL_LIST) {
			cil_list_destroy((struct cil_list**)&(item->data), destroy_data);
		}
		next = item->next;
		cil_list_item_destroy(&item, destroy_data);
		item = next;
	}
	free(*list);
	*list = NULL;	
}

void cil_list_item_init(struct cil_list_item **item)
{
	struct cil_list_item *new_item = cil_malloc(sizeof(*new_item));
	new_item->next = NULL;
	new_item->flavor = 0;
	new_item->data = NULL;

	*item = new_item;
}

void cil_list_item_destroy(struct cil_list_item **item, uint8_t destroy_data)
{
	if (destroy_data) {
		cil_destroy_data(&(*item)->data, (*item)->flavor);
	}
	free(*item);
	*item = NULL;
}


int cil_list_get_tail(struct cil_list *list, struct cil_list_item **tail)
{
	struct cil_list_item *curr = NULL;
	int rc = SEPOL_ERR;

	if (list == NULL || tail == NULL) {
		goto list_get_tail_out;
	}

	curr = list->head;
	while (curr->next != NULL) {
		curr = curr->next;
	}

	*tail = curr;
	return SEPOL_OK;

list_get_tail_out:
	return rc;
}

int cil_list_append_item(struct cil_list *list, struct cil_list_item *item)
{
	struct cil_list_item *curr_item = NULL;
	int rc = SEPOL_ERR;

	if (list == NULL || item == NULL) {
		goto list_append_item_out;
	}

	if (list->head == NULL) {
		list->head = item;
		rc = SEPOL_OK;
		goto list_append_item_out;
	}

	curr_item = list->head;

	while (curr_item->next != NULL) {
		curr_item = curr_item->next;
	}
	
	curr_item->next = item;

	return SEPOL_OK;

list_append_item_out:
	return rc;
}

int cil_list_prepend_item(struct cil_list *list, struct cil_list_item *item) 
{
	struct cil_list_item *old_head = NULL;
	struct cil_list_item *new_head = NULL;
	int rc = SEPOL_ERR;

	if (list == NULL || item == NULL) {
		goto list_prepend_item_out;
	}

	if (item->next != NULL) {
		printf("Error: List item to prepend has next\n");
		goto list_prepend_item_out;
	}

	old_head = list->head;
	new_head = item;

	list->head = new_head;
	new_head->next = old_head;

	return SEPOL_OK;

list_prepend_item_out:
	return rc;
}

void cil_print_list_lists(struct cil_list *list_list)
{
	struct cil_list_item *list_item = NULL;
	struct cil_list_item *sub_list_item = NULL;
	
	list_item = list_list->head;
	while (list_item != NULL) {
		sub_list_item = ((struct cil_list*)list_item->data)->head;
		printf("(");
		while (sub_list_item != NULL) {
			printf(" %p:%s ", sub_list_item->data, ((struct cil_symtab_datum*)sub_list_item->data)->name);
			sub_list_item = sub_list_item->next;
		}
		printf(")\n");
		list_item = list_item->next;
	}
}


