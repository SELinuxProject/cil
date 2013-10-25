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
#include <string.h>

#include <sepol/errcodes.h>
#include <sepol/policydb/hashtab.h>
#include <sepol/policydb/symtab.h>

#include "cil_internal.h"
#include "cil_tree.h"
#include "cil_symtab.h"
#include "cil_mem.h"

__attribute__((noreturn)) void cil_symtab_error(const char* msg)
{
	cil_log(CIL_ERR, "%s\n",msg);
	exit(1);
}

void cil_symtab_init(symtab_t *symtab, unsigned int size)
{
	int rc = symtab_init(symtab, size);
	if (rc != SEPOL_OK) {
		cil_symtab_error("Failed to create symtab\n");
	}
}

void cil_symtab_datum_init(struct cil_symtab_datum *datum)
{
	datum->name = NULL;
	cil_list_init(&datum->nodes, CIL_LIST_ITEM);
	datum->state = CIL_STATE_ENABLED;
}

void cil_symtab_datum_destroy(struct cil_symtab_datum *datum)
{
	free(datum->name);
	cil_list_destroy(&datum->nodes, 0);
}

/* This both initializes the datum and inserts it into the symtab.
   Note that cil_symtab_datum_destroy() is the analog to the initializer portion */
int cil_symtab_insert(symtab_t *symtab, hashtab_key_t key, struct cil_symtab_datum *datum, struct cil_tree_node *node)
{
	char *newkey = cil_strdup(key);
	int rc = hashtab_insert(symtab->table, newkey, (hashtab_datum_t)datum);
	if (rc != SEPOL_OK && rc != SEPOL_EEXIST) {
		free(newkey);
		cil_symtab_error("Failed to insert datum into hashtab\n");
	} else {
		cil_list_append(datum->nodes, CIL_AST_NODE, node);
		datum->name = newkey;
	}

	return rc;
}

void cil_symtab_remove_datum_destroy(__attribute__((unused))hashtab_key_t key, hashtab_datum_t datum, __attribute__((unused))void *args)
{
	cil_symtab_datum_destroy((struct cil_symtab_datum *)datum);
	free(datum);
}

void cil_symtab_datum_remove(struct cil_symtab_datum *datum, struct cil_tree_node *node)
{
	if (datum->nodes != NULL) {
		struct cil_list_item *item;
		struct cil_list_item *previous = NULL;
		cil_list_for_each(item, datum->nodes) {
			if (item->data == node) {
				if (previous == NULL) {
					datum->nodes->head = item->next;
				} else {
					previous->next = item->next;
				}
				cil_list_item_destroy(&item, 0);
				break;
			}
			previous = item;
		}
	}
}

int cil_symtab_get_datum(symtab_t *symtab, char *key, struct cil_symtab_datum **datum)
{
	*datum = (struct cil_symtab_datum*)hashtab_search(symtab->table, (hashtab_key_t)key);
	if (*datum == NULL || (*datum)->state != CIL_STATE_ENABLED) {
		return SEPOL_ENOENT;
	}

	return SEPOL_OK;
}

int cil_symtab_map(symtab_t *symtab,
				   int (*apply) (hashtab_key_t k, hashtab_datum_t d, void *args),
				   void *args)
{
	return hashtab_map(symtab->table, apply, args);
}

void cil_symtab_destroy(symtab_t *symtab)
{
	if (symtab->table != NULL){
		hashtab_destroy(symtab->table);
		symtab->table = NULL;
	}
}

void cil_complex_symtab_hash(struct cil_complex_symtab_key *ckey, int mask, intptr_t *hash)
{
	intptr_t sum = ckey->key1 + ckey->key2 + ckey->key3 + ckey->key4;
	*hash = (intptr_t)((sum >> 2) & mask);
}

void cil_complex_symtab_init(struct cil_complex_symtab *symtab, unsigned int size)
{
	symtab->htable = cil_calloc(size, sizeof(struct cil_complex_symtab *));

	symtab->nelems = 0;
	symtab->nslots = size;
	symtab->mask = size - 1;
}

int cil_complex_symtab_insert(struct cil_complex_symtab *symtab,
			struct cil_complex_symtab_key *ckey,
			struct cil_complex_symtab_datum *datum)
{
	intptr_t hash;
	struct cil_complex_symtab_node *node = NULL;
	struct cil_complex_symtab_node *prev = NULL;
	struct cil_complex_symtab_node *curr = NULL;

	node = cil_malloc(sizeof(*node));
	memset(node, 0, sizeof(*node));

	node->ckey = ckey;
	node->datum = datum;

	cil_complex_symtab_hash(ckey, symtab->mask, &hash);

	for (prev = NULL, curr = symtab->htable[hash]; curr != NULL;
		prev = curr, curr = curr->next) {
		if (ckey->key1 == curr->ckey->key1 &&
			ckey->key2 == curr->ckey->key2 &&
			ckey->key3 == curr->ckey->key3 &&
			ckey->key4 == curr->ckey->key4) {
			return SEPOL_EEXIST;
		}

		if (ckey->key1 == curr->ckey->key1 &&
			ckey->key2 < curr->ckey->key2) {
			break;
		}

		if (ckey->key1 == curr->ckey->key1 &&
			ckey->key2 == curr->ckey->key2 &&
			ckey->key3 < curr->ckey->key3) {
			break;
		}

		if (ckey->key1 == curr->ckey->key1 &&
			ckey->key2 == curr->ckey->key2 &&
			ckey->key3 == curr->ckey->key3 &&
			ckey->key4 < curr->ckey->key4) {
			break;
		}
	}

	if (prev != NULL) {
		node->next = prev->next;
		prev->next = node;
	} else {
		node->next = symtab->htable[hash];
		symtab->htable[hash] = node;
	}

	symtab->nelems++;

	return SEPOL_OK;
}

void cil_complex_symtab_search(struct cil_complex_symtab *symtab,
			       struct cil_complex_symtab_key *ckey,
			       struct cil_complex_symtab_datum **out)
{
	intptr_t hash;
	struct cil_complex_symtab_node *curr = NULL;

	cil_complex_symtab_hash(ckey, symtab->mask, &hash);
	for (curr = symtab->htable[hash]; curr != NULL; curr = curr->next) {
		if (ckey->key1 == curr->ckey->key1 &&
			ckey->key2 == curr->ckey->key2 &&
			ckey->key3 == curr->ckey->key3 &&
			ckey->key4 == curr->ckey->key4) {
			*out = curr->datum;
			return;
		}

		if (ckey->key1 == curr->ckey->key1 &&
			ckey->key2 < curr->ckey->key2) {
			break;
		}

		if (ckey->key1 == curr->ckey->key1 &&
			ckey->key2 == curr->ckey->key2 &&
			ckey->key3 < curr->ckey->key3) {
			break;
		}

		if (ckey->key1 == curr->ckey->key1 &&
			ckey->key2 == curr->ckey->key2 &&
			ckey->key3 == curr->ckey->key3 &&
			ckey->key4 < curr->ckey->key4) {
			break;
		}
	}

	*out = NULL;
}

void cil_complex_symtab_destroy(struct cil_complex_symtab *symtab)
{
	struct cil_complex_symtab_node *curr = NULL;
	struct cil_complex_symtab_node *temp = NULL;
	unsigned int i;

	if (symtab == NULL) {
		return;
	}

	for (i = 0; i < symtab->nslots; i++) {
		curr = symtab->htable[i];
		while (curr != NULL) {
			temp = curr;
			curr = curr->next;
			free(temp);
		}
		symtab->htable[i] = NULL;
	}
	free(symtab->htable);
	symtab->htable = NULL;
	symtab->nelems = 0;
	symtab->nslots = 0;
	symtab->mask = 0;
}
