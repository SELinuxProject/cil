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

#include "cil_tree.h"
#include "cil_symtab.h"
#include "cil_mem.h"

void cil_symtab_init(symtab_t *symtab, unsigned int size)
{
	int rc = symtab_init(symtab, size);
	if (rc != SEPOL_OK) {
		(*cil_malloc_error_handler)();
	}
}

void cil_symtab_datum_init(struct cil_symtab_datum *datum)
{
	datum->name = NULL;
	datum->node = NULL;
	datum->state = CIL_STATE_ENABLED;
}

void cil_symtab_datum_destroy(struct cil_symtab_datum datum)
{
	free(datum.name);
}

/* This both initializes the datum and inserts it into the symtab.
   Note that cil_symtab_datum_destroy() is the analog to the initializer portion */
int cil_symtab_insert(symtab_t *symtab, hashtab_key_t key, struct cil_symtab_datum *datum, struct cil_tree_node *node)
{
	char *newkey = cil_strdup(key);
	int rc = hashtab_insert(symtab->table, newkey, (hashtab_datum_t)datum);
	if (rc != SEPOL_OK) {
		free(newkey);
		goto exit;
	} else {
		datum->node = node;
		datum->name = newkey;
	}
	
	return SEPOL_OK;

exit:
	return rc;
}

void cil_symtab_remove_datum_destroy(__attribute__((unused))hashtab_key_t key, hashtab_datum_t datum, __attribute__((unused))void *args)
{
	cil_symtab_datum_destroy(*(struct cil_symtab_datum *)datum);
	free(datum);
}

int cil_symtab_remove(symtab_t *symtab, hashtab_key_t key)
{
	int rc = hashtab_remove(symtab->table, key, &cil_symtab_remove_datum_destroy, NULL);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	rc = SEPOL_OK;
exit:
	return rc;
}

int cil_symtab_get_node(symtab_t *symtab, char *key, struct cil_tree_node **node)
{
	struct cil_symtab_datum *datum = NULL;
	int rc = SEPOL_ERR;

	if (symtab == NULL || symtab->table == NULL || key == NULL || node == NULL) {
		goto exit;
	}

	datum = (struct cil_symtab_datum*)hashtab_search(symtab->table, (hashtab_key_t)key);
	if (datum == NULL || datum->state != CIL_STATE_ENABLED) {
		rc = SEPOL_ENOENT;
		goto exit;
	}

	*node = datum->node;

	return SEPOL_OK;

exit:
	return rc;
}

void cil_symtab_destroy(symtab_t *symtab)
{
	if (symtab->table != NULL){
		hashtab_destroy(symtab->table);
		symtab->table = NULL;
	}
}

int cil_complex_symtab_hash(struct cil_complex_symtab_key *ckey, int mask, intptr_t *hash)
{
	int rc = SEPOL_ERR;
	intptr_t sum;

	if (ckey == NULL) {
		goto exit;
	}

	sum = ckey->key1 + ckey->key2 + ckey->key3 + ckey->key4;

	*hash = (intptr_t)((sum >> 2) & mask);

	rc = SEPOL_OK;
exit:
	return rc;
}

int cil_complex_symtab_init(struct cil_complex_symtab *symtab, unsigned int size)
{
	int rc = SEPOL_ERR;

	symtab->htable = calloc(size, sizeof(struct cil_complex_symtab *));
	if (symtab->htable == NULL) {
		goto exit;
	}

	symtab->nelems = 0;
	symtab->nslots = size;
	symtab->mask = size - 1;

	rc = SEPOL_OK;
exit:
	return rc;
}

int cil_complex_symtab_insert(struct cil_complex_symtab *symtab,
			struct cil_complex_symtab_key *ckey,
			struct cil_complex_symtab_datum *datum)
{
	int rc = SEPOL_ERR;
	intptr_t hash = 0;
	struct cil_complex_symtab_node *node = NULL;
	struct cil_complex_symtab_node *prev = NULL;
	struct cil_complex_symtab_node *curr = NULL;
	struct cil_complex_symtab_key *_ckey = NULL;
	struct cil_complex_symtab_datum *_datum = NULL;

	if (symtab == NULL || symtab->htable == NULL) {
		goto exit;
	}

	node = cil_malloc(sizeof(*node));
	memset(node, 0, sizeof(*node));

	node->ckey = ckey;
	node->datum = datum;

	rc = cil_complex_symtab_hash(ckey, symtab->mask, &hash);
	if (rc != SEPOL_OK) {
		free(_ckey);
		free(_datum);
		free(node);
		goto exit;
	}

	for (prev = NULL, curr = symtab->htable[hash]; curr != NULL;
		prev = curr, curr = curr->next) {
		if (ckey->key1 == curr->ckey->key1 &&
			ckey->key2 == curr->ckey->key2 &&
			ckey->key3 == curr->ckey->key3 &&
			ckey->key4 == curr->ckey->key4) {
			rc = SEPOL_EEXIST;
			goto exit;
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

	rc = SEPOL_OK;
exit:
	return rc;
}

int cil_complex_symtab_search(struct cil_complex_symtab *symtab,
			struct cil_complex_symtab_key *ckey,
			struct cil_complex_symtab_datum **out)
{
	int rc = SEPOL_ERR;
	intptr_t hash = 0;
	struct cil_complex_symtab_node *prev = NULL;
	struct cil_complex_symtab_node *curr = NULL;

	if (symtab == NULL || symtab->htable == NULL || *out != NULL) {
		goto exit;
	}

	hash = cil_complex_symtab_hash(ckey, symtab->mask, &hash);
	for (prev = NULL, curr = symtab->htable[hash]; curr != NULL;
		prev = curr, curr = curr->next) {
		if (ckey->key1 == curr->ckey->key1 &&
			ckey->key2 == curr->ckey->key2 &&
			ckey->key3 == curr->ckey->key3 &&
			ckey->key4 == curr->ckey->key4) {
			*out = curr->datum;
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

	rc = SEPOL_OK;
exit:
	return rc;
}

int cil_complex_symtab_destroy(struct cil_complex_symtab *symtab)
{
	int rc = SEPOL_ERR;
	struct cil_complex_symtab_node *curr = NULL;
	struct cil_complex_symtab_node *temp = NULL;
	unsigned int i;

	if (symtab == NULL) {
		goto exit;
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

	rc = SEPOL_OK;
exit:
	return rc;
}
