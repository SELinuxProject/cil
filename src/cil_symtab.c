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

#include "cil_tree.h"
#include "cil_symtab.h"
#include "cil_mem.h"

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
		goto symtab_insert_out;
	} else {
		datum->node = node;
		datum->name = newkey;
	}
	
	return SEPOL_OK;

symtab_insert_out:
	return rc;
}

int cil_symtab_get_node(symtab_t *symtab, char *key, struct cil_tree_node **node)
{
	struct cil_symtab_datum *datum = NULL;
	int rc = SEPOL_ERR;

	if (symtab == NULL || symtab->table == NULL || key == NULL || node == NULL) {
		goto symtab_get_node_out;
	}

	datum = (struct cil_symtab_datum*)hashtab_search(symtab->table, (hashtab_key_t)key);
	if (datum == NULL || datum->state != CIL_STATE_ENABLED) {
		rc = SEPOL_ENOENT;
		goto symtab_get_node_out;
	}

	*node = datum->node;

	return SEPOL_OK;

symtab_get_node_out:
	return rc;
}

void cil_symtab_destroy(symtab_t *symtab)
{
	if (symtab->table != NULL){
		hashtab_destroy(symtab->table);
		symtab->table = NULL;
	}
}

