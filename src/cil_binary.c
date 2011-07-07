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
#include <assert.h>
#include <sepol/policydb/policydb.h>

#include "cil.h"
#include "cil_mem.h"
#include "cil_tree.h"

struct cil_args_binary {
	const struct cil_db *db;
	policydb_t *pdb;
	int pass;
};

int cil_class_to_policydb(policydb_t *pdb, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	uint32_t value = 0;
	struct cil_class *cil_class = node->data;
	struct cil_tree_node *cil_perm = node->cl_head;
	class_datum_t *sepol_class = cil_malloc(sizeof(*sepol_class));
	memset(sepol_class, 0, sizeof(class_datum_t));
	rc = symtab_insert(pdb, SYM_CLASSES, cil_class->datum.name, sepol_class, SCOPE_DECL, 0, &value);
	if (rc != SEPOL_OK) {
		goto class_to_policydb_out;
	}
	sepol_class->s.value = value;
	rc = symtab_init(&sepol_class->permissions, PERM_SYMTAB_SIZE);
	if (rc != SEPOL_OK) {
		goto class_to_policydb_out;
	}
	while (cil_perm != NULL) {
		struct cil_perm *curr = cil_perm->data;
		perm_datum_t *sepol_perm = cil_malloc(sizeof(*sepol_perm));
		memset(sepol_perm, 0, sizeof(perm_datum_t));
		sepol_perm->s.value = sepol_class->permissions.nprim + 1;
		rc = hashtab_insert(sepol_class->permissions.table,
					curr->datum.name,
					sepol_perm);
		if (rc != SEPOL_OK) {
			goto class_to_policydb_out;
		}
		sepol_class->permissions.nprim++;
		cil_perm = cil_perm->next;
	}
	return SEPOL_OK;

class_to_policydb_out:
	return rc;
}

int __cil_node_to_policydb(const struct cil_db *db, policydb_t *pdb, struct cil_tree_node *node, int pass)
{
	int rc = SEPOL_OK;

	if (db == NULL || &pdb == NULL || node == NULL) {
		goto node_to_policydb_out;
	}

	switch (pass) {
	case 1:
		switch (node->flavor) {
		case CIL_CLASS:
			rc = cil_class_to_policydb(pdb, node);
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}
	return SEPOL_OK;

node_to_policydb_out:
	return rc;
}

int __cil_binary_create_helper(struct cil_tree_node *node, __attribute__((unused)) uint32_t *finished, void *extra_args)
{
	int rc = SEPOL_ERR;
	int pass;
	const struct cil_db *db = NULL;
	struct cil_args_binary *args = extra_args;
	policydb_t *pdb;

	if (node == NULL || extra_args == NULL) {
		goto binary_create_helper_out;
	}

	db = args->db;
	pdb = args->pdb;
	pass = args->pass;

	rc = __cil_node_to_policydb(db, pdb, node, pass);
	if (rc != SEPOL_OK) {
		goto binary_create_helper_out;
	}

	return SEPOL_OK;

binary_create_helper_out:
	return rc;
}

int cil_binary_create(const struct cil_db *db, policydb_t *pdb, const char *fname)
{
	int rc = SEPOL_ERR;
	int i;
	FILE *binary;
	struct policy_file pf;
	struct cil_args_binary extra_args;

	if (db == NULL || &pdb == NULL || fname == NULL) {
		goto binary_create_out;
	}

	extra_args.db = db;
	extra_args.pdb = pdb;
	for (i = 1; i <= 1; i++) {
		extra_args.pass = i;
		rc = cil_tree_walk(db->ast->root, __cil_binary_create_helper, NULL, NULL, &extra_args);
		if (rc != SEPOL_OK) {
			goto binary_create_out;
		}
	}

	binary = fopen(fname, "w");
	if (binary == NULL) {
		fprintf(stderr, "Failure creating binary file\n");
		rc = SEPOL_ERR;
		goto binary_create_out;
	}
	policy_file_init(&pf);
	pf.type = PF_USE_STDIO;
	pf.fp = binary;
	rc = policydb_write(pdb, &pf);
	if (rc != 0) {
		fprintf(stderr, "Failed writing binary policy\n");
		goto binary_create_out;
	}
	fclose(binary);

	return SEPOL_OK;

binary_create_out:
	return rc;
}
