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
#include <sepol/policydb/polcaps.h>

#include "cil.h"
#include "cil_mem.h"
#include "cil_tree.h"

struct cil_args_binary {
	const struct cil_db *db;
	policydb_t *pdb;
	int pass;
};

int cil_common_to_policydb(policydb_t *pdb, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	uint32_t value = 0;
	char *key = NULL;
	struct cil_common *cil_common = node->data;
	struct cil_tree_node *cil_perm = node->cl_head;
	common_datum_t *sepol_common = cil_malloc(sizeof(*sepol_common));
	memset(sepol_common, 0, sizeof(common_datum_t));

	key = cil_strdup(cil_common->datum.name);
	rc = symtab_insert(pdb, SYM_COMMONS, key, sepol_common, SCOPE_DECL, 0, &value);
	if (rc != SEPOL_OK) {
		goto common_to_binary_out;
	}
	sepol_common->s.value = value;

	rc = symtab_init(&sepol_common->permissions, PERM_SYMTAB_SIZE);
	if (rc != SEPOL_OK) {
		goto common_to_binary_out;
	}

	while (cil_perm != NULL) {
		struct cil_perm *curr = cil_perm->data;
		perm_datum_t *sepol_perm = cil_malloc(sizeof(*sepol_perm));
		memset(sepol_perm, 0, sizeof(perm_datum_t));

		key = cil_strdup(curr->datum.name);
		rc = hashtab_insert(sepol_common->permissions.table, key, sepol_perm);
		if (rc != SEPOL_OK) {
			goto common_to_binary_out;
		}
		sepol_perm->s.value = sepol_common->permissions.nprim + 1;
		sepol_common->permissions.nprim++;
		cil_perm = cil_perm->next;
	}

	return SEPOL_OK;

common_to_binary_out:
	return rc;
}

int cil_class_to_policydb(policydb_t *pdb, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	uint32_t value = 0;
	char *key = NULL;
	struct cil_class *cil_class = node->data;
	struct cil_tree_node *cil_perm = node->cl_head;
	class_datum_t *sepol_class = cil_malloc(sizeof(*sepol_class));
	memset(sepol_class, 0, sizeof(class_datum_t));

	key = cil_strdup(cil_class->datum.name);
	rc = symtab_insert(pdb, SYM_CLASSES, key, sepol_class, SCOPE_DECL, 0, &value);
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

		key = cil_strdup(curr->datum.name);
		rc = hashtab_insert(sepol_class->permissions.table, key, sepol_perm);
		if (rc != SEPOL_OK) {
			goto class_to_policydb_out;
		}
		sepol_perm->s.value = sepol_class->permissions.nprim + 1;

		sepol_class->permissions.nprim++;
		cil_perm = cil_perm->next;
	}

	return SEPOL_OK;

class_to_policydb_out:
	return rc;
}

int cil_classcommon_to_policydb(policydb_t *pdb, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	struct cil_classcommon *cil_classcom = node->data;
	class_datum_t *sepol_class;
	common_datum_t *sepol_common;

	sepol_class = hashtab_search(pdb->p_classes.table, cil_classcom->class_str);
	if (sepol_class == NULL) {
		goto classcommon_to_policydb_out;
	}

	sepol_common = hashtab_search(pdb->p_commons.table, cil_classcom->common_str);
	if (sepol_common == NULL) {
		goto classcommon_to_policydb_out;
	}

	sepol_class->comdatum = sepol_common;

	return SEPOL_OK;

classcommon_to_policydb_out:
	return rc;
}

int cil_role_to_policydb(policydb_t *pdb, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	uint32_t value = 0;
	char *key = NULL;
	struct cil_role *cil_role = node->data;
	role_datum_t *sepol_role = cil_malloc(sizeof(*sepol_role));
	role_datum_init(sepol_role);

	key = cil_strdup(cil_role->datum.name);
	if (!strcmp(key, "object_r")) {
		/* special case
		 * object_r defaults to 1 in libsepol symtab */
		rc = SEPOL_OK;
		goto role_to_policydb_out;
	}

	rc = symtab_insert(pdb, SYM_ROLES, (hashtab_key_t)key, sepol_role, SCOPE_DECL, 0, &value);
	if (rc != SEPOL_OK) {
		goto role_to_policydb_out;
	}
	sepol_role->s.value = value;
	return SEPOL_OK;

role_to_policydb_out:
	return rc;
}

int cil_roletype_to_policydb(policydb_t *pdb, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	struct cil_role *cil_role;
	struct cil_type *cil_type;
	struct cil_roletype *cil_roletype;
	role_datum_t *sepol_role;
	type_datum_t *sepol_type;

	cil_roletype = node->data;
	cil_role = cil_roletype->role;
	cil_type = cil_roletype->type;

	sepol_role = hashtab_search(pdb->p_roles.table, cil_role->datum.name);
	if (sepol_role == NULL) {
		goto roletype_to_policydb_out;
	}

	sepol_type = hashtab_search(pdb->p_types.table, cil_type->datum.name);
	if (sepol_type == NULL) {
		goto roletype_to_policydb_out;
	}

	if (ebitmap_set_bit(&sepol_role->types.types, sepol_type->s.value - 1, 1)) {
		goto roletype_to_policydb_out;
	}

	return SEPOL_OK;

roletype_to_policydb_out:
	return rc;
}

int cil_roledominance_to_policydb(policydb_t *pdb, struct cil_tree_node *node)
{
        int rc = SEPOL_ERR;
        struct cil_role *cil_doming;
        struct cil_role *cil_domed;
        struct cil_roledominance *cil_roledom;
        role_datum_t *sepol_doming;
        role_datum_t *sepol_domed;

	cil_roledom = node->data;
	cil_doming = cil_roledom->role;
	cil_domed = cil_roledom->domed;

	sepol_doming = hashtab_search(pdb->p_roles.table, cil_doming->datum.name);
	if (sepol_doming == NULL) {
		goto roledominance_to_policydb_out;
	}

	sepol_domed = hashtab_search(pdb->p_roles.table, cil_domed->datum.name);
	if (sepol_domed == NULL) {
		goto roledominance_to_policydb_out;
	}

	if (ebitmap_set_bit(&sepol_domed->dominates, sepol_doming->s.value - 1, 1)) {
		goto roledominance_to_policydb_out;
	}

	return SEPOL_OK;

roledominance_to_policydb_out:
        return rc;
}

int cil_rolebounds_to_policydb(policydb_t *pdb, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	struct cil_rolebounds *cil_rolebnds = node->data;
	role_datum_t *sepol_role;
	role_datum_t *sepol_rolebnds;

	sepol_role = hashtab_search(pdb->p_roles.table, cil_rolebnds->role_str);
	if (sepol_role == NULL) {
		goto rolebounds_to_policydb_out;
	}

	sepol_rolebnds = hashtab_search(pdb->p_roles.table, cil_rolebnds->bounds_str);
	if (sepol_rolebnds == NULL) {
		goto rolebounds_to_policydb_out;
	}
	sepol_role->bounds = sepol_rolebnds->s.value;

        return SEPOL_OK;

rolebounds_to_policydb_out:
	return rc;
}

int cil_type_to_policydb(policydb_t *pdb, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	uint32_t value = 0;
	char *key = NULL;
	struct cil_type *cil_type = node->data;
	type_datum_t *sepol_type = cil_malloc(sizeof(*sepol_type));
	type_datum_init(sepol_type);

	sepol_type->primary = 1;
	sepol_type->flavor = TYPE_TYPE;

	key = cil_strdup(cil_type->datum.name);
	rc = symtab_insert(pdb, SYM_TYPES, key, sepol_type, SCOPE_DECL, 0, &value);
	if (rc != SEPOL_OK) {
		goto type_to_binary_out;
	}
	sepol_type->s.value = value;

	return SEPOL_OK;

type_to_binary_out:
	return rc;
}

int policydb_type_ebitmap_init(policydb_t *pdb)
{
	int rc = SEPOL_ERR;
	uint32_t i;

	if (pdb->attr_type_map != NULL && pdb->type_attr_map != NULL) {
		rc = SEPOL_OK;
		goto type_ebitmap_out;
        }

	pdb->attr_type_map = cil_malloc(pdb->p_types.nprim * sizeof(ebitmap_t));
	pdb->type_attr_map = cil_malloc(pdb->p_types.nprim * sizeof(ebitmap_t));

	for (i = 0; i < pdb->p_types.nprim; i++) {
		ebitmap_init(&pdb->attr_type_map[i]);
		ebitmap_init(&pdb->type_attr_map[i]);
		if (ebitmap_set_bit(&pdb->type_attr_map[i], i, 1)) {
			goto type_ebitmap_out;
		}
	}

	return SEPOL_OK;

type_ebitmap_out:
	return rc;
}

int cil_policycap_to_policydb(policydb_t *pdb, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	int capnum;
	struct cil_policycap *cil_polcap = node->data;

	capnum = sepol_polcap_getnum(cil_polcap->datum.name);
	if (capnum == -1) {
		goto policycap_to_policydb_out;
	}

	if (ebitmap_set_bit(&pdb->policycaps, capnum, 1)) {
		goto policycap_to_policydb_out;
	}

	return SEPOL_OK;

policycap_to_policydb_out:
	return rc;
}

int cil_user_to_policydb(policydb_t *pdb, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	uint32_t value = 0;
	char *key = NULL;
	struct cil_user *cil_user = node->data;
	user_datum_t *sepol_user = cil_malloc(sizeof(*sepol_user));
	user_datum_init(sepol_user);

	key = cil_user->datum.name;
	rc = symtab_insert(pdb, SYM_USERS, key, sepol_user, SCOPE_DECL, 0, &value);
	if (rc != SEPOL_OK) {
		goto user_to_policydb_out;
	}
	sepol_user->s.value = value;

	return SEPOL_OK;

user_to_policydb_out:
	return rc;
}

int cil_userrole_to_policydb(policydb_t *pdb, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	uint32_t value = 0;
	char *key = NULL;
	struct cil_user *cil_user;
	struct cil_role *cil_role;
	struct cil_userrole *cil_userrole;
	user_datum_t *sepol_user;
	role_datum_t *sepol_role;

	cil_userrole = node->data;
	cil_user = cil_userrole->user;

	key = cil_user->datum.name;
	sepol_user = hashtab_search(pdb->p_users.table, key);
	if (sepol_user == NULL) {
		goto userrole_to_policydb_out;
	}
	cil_role = cil_userrole->role;

	key = cil_role->datum.name;
	sepol_role = hashtab_search(pdb->p_roles.table, key);
	if (sepol_role == NULL) {
		goto userrole_to_policydb_out;
	}

	value = sepol_role->s.value;
	if (ebitmap_set_bit(&sepol_user->roles.roles, value - 1, 1)) {
		goto userrole_to_policydb_out;
	}

	return SEPOL_OK;

userrole_to_policydb_out:
	return rc;
}

int cil_bool_to_policydb(policydb_t *pdb, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	uint32_t value = 0;
	char *key = NULL;
	struct cil_bool *cil_bool = node->data;
	cond_bool_datum_t *sepol_bool = cil_malloc(sizeof(*sepol_bool));
	memset(sepol_bool, 0, sizeof(cond_bool_datum_t));

	key = cil_strdup(cil_bool->datum.name);
	rc = symtab_insert(pdb, SYM_BOOLS, key, sepol_bool, SCOPE_DECL, 0, &value);
	if (rc != SEPOL_OK) {
		goto bool_to_policydb_out;
	}
	sepol_bool->s.value = value;
	sepol_bool->state = cil_bool->value;

	return SEPOL_OK;

bool_to_policydb_out:
	return rc;
}

int cil_catorder_to_policydb(policydb_t *pdb, const struct cil_db *db)
{
	int rc = SEPOL_ERR;
	uint32_t value = 0;
	char *key = NULL;
	struct cil_list_item *curr_cat = db->catorder->head;
	struct cil_cat *cil_cat = NULL;
	cat_datum_t *sepol_cat = NULL;

	while (curr_cat != NULL) {
		cil_cat = curr_cat->data;
		sepol_cat = cil_malloc(sizeof(*sepol_cat));
		cat_datum_init(sepol_cat);

		key = cil_strdup(cil_cat->datum.name);
		rc = symtab_insert(pdb, SYM_CATS, key, sepol_cat, SCOPE_DECL, 0, &value);
		if (rc != SEPOL_OK) {
			goto cat_to_binary_out;
		}
		sepol_cat->s.value = value;
		curr_cat = curr_cat->next;
	}

	return SEPOL_OK;

cat_to_binary_out:
	free(key);
	cat_datum_destroy(sepol_cat);
	free(sepol_cat);
	return rc;
}

int cil_catalias_to_policydb(policydb_t *pdb, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	char *key = NULL;
	struct cil_catalias *cil_alias = node->data;
	cat_datum_t *sepol_cat;
	cat_datum_t *sepol_alias = cil_malloc(sizeof(*sepol_cat));
	cat_datum_init(sepol_alias);

	key = cil_alias->cat_str;
	sepol_cat = hashtab_search(pdb->p_cats.table, key);
	if (sepol_cat == NULL) {
		goto catalias_to_policydb_out;
	}

	key = cil_strdup(cil_alias->datum.name);
	rc = symtab_insert(pdb, SYM_CATS, key, sepol_alias, SCOPE_DECL, 0, &sepol_cat->s.value);
	if (rc != SEPOL_OK) {
		free(key);
		goto catalias_to_policydb_out;
	}
	sepol_alias->s.value = sepol_cat->s.value;
	sepol_alias->isalias = 1;

	return SEPOL_OK;

catalias_to_policydb_out:
	return rc;
}

int cil_dominance_to_policydb(policydb_t *pdb, const struct cil_db *db)
{
	int rc = SEPOL_ERR;
	uint32_t value = 0;
	char *key = NULL;
	struct cil_list_item *curr = db->dominance->head;
	struct cil_sens *cil_sens = NULL;
	level_datum_t *sepol_level = NULL;
	mls_level_t *mls_level = NULL;

	while (curr != NULL) {
		cil_sens = curr->data;
		sepol_level = cil_malloc(sizeof(*sepol_level));
		mls_level = cil_malloc(sizeof(*mls_level));
		level_datum_init(sepol_level);
		mls_level_init(mls_level);

		key = cil_strdup(cil_sens->datum.name);
		rc = symtab_insert(pdb, SYM_LEVELS, key, sepol_level, SCOPE_DECL, 0, &value);
		if (rc != SEPOL_OK) {
			goto dominance_to_binary_out;
		}
		sepol_level->isalias = 0;
		sepol_level->defined = 1;
		mls_level->sens = value;
		sepol_level->level = mls_level;

		curr = curr->next;
	}

	return SEPOL_OK;

dominance_to_binary_out:
	level_datum_destroy(sepol_level);
	mls_level_destroy(mls_level);
	free(sepol_level);
	free(mls_level);
	free(key);
	return rc;
}

int cil_type_rule_to_policydb(policydb_t *pdb, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	char *key = NULL;
	struct cil_type_rule *cil_rule = node->data;
	uint16_t kind = cil_rule->rule_kind;
	type_datum_t *sepol_src = NULL;
	type_datum_t *sepol_tgt = NULL;
	type_datum_t *sepol_result = NULL;
	class_datum_t *sepol_obj = NULL;
	avtab_ptr_t avtab_ptr = NULL;
	avtab_datum_t *avtab_datum = cil_malloc(sizeof(*avtab_datum));
	memset(avtab_datum, 0, sizeof(avtab_datum_t));
	avtab_key_t *avtab_key = cil_malloc(sizeof(*avtab_key));
	memset(avtab_key, 0, sizeof(avtab_key_t));

	key = ((struct cil_symtab_datum *)cil_rule->src)->name;
	sepol_src = hashtab_search(pdb->p_types.table, key);
	if (sepol_src == NULL) {
		rc = SEPOL_ERR;
		goto type_rule_to_policydb_out;
	}
	avtab_key->source_type = sepol_src->s.value;

	key = ((struct cil_symtab_datum *)cil_rule->tgt)->name;
	sepol_tgt = hashtab_search(pdb->p_types.table, key);
	if (sepol_tgt == NULL) {
		rc = SEPOL_ERR;
		goto type_rule_to_policydb_out;
	}
	avtab_key->target_type = sepol_tgt->s.value;

	key = ((struct cil_symtab_datum *)cil_rule->obj)->name;
	sepol_obj = hashtab_search(pdb->p_classes.table, key);
	if (sepol_obj == NULL) {
		rc = SEPOL_ERR;
		goto type_rule_to_policydb_out;
	}
	avtab_key->target_class = sepol_obj->s.value;

	key = ((struct cil_symtab_datum *)cil_rule->result)->name;
	sepol_result = hashtab_search(pdb->p_types.table, key);
	if (sepol_result == NULL) {
		rc = SEPOL_ERR;
		goto type_rule_to_policydb_out;
	}
	avtab_datum->data = sepol_result->s.value;

	switch (kind) {
	case CIL_TYPE_TRANSITION:
		avtab_key->specified = AVTAB_TRANSITION;
		break;
	case CIL_TYPE_CHANGE:
		avtab_key->specified = AVTAB_CHANGE;
		break;
	case CIL_TYPE_MEMBER:
		avtab_key->specified = AVTAB_MEMBER;
		break;
	default:
		rc = SEPOL_ERR;
		goto type_rule_to_policydb_out;
		break;
	}

	avtab_ptr = avtab_insert_nonunique(&pdb->te_avtab, avtab_key, avtab_datum);
	if (avtab_ptr == NULL) {
		rc = SEPOL_ERR;
		goto type_rule_to_policydb_out;
	}

	return SEPOL_OK;

type_rule_to_policydb_out:
	free(avtab_datum);
	free(avtab_key);
	avtab_destroy(&pdb->te_avtab);
	return rc;
}

int cil_avrule_to_policydb(policydb_t *pdb, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	char *key = NULL;
	struct cil_avrule *cil_avrule = node->data;
	uint16_t kind = cil_avrule->rule_kind;
	struct cil_class *cil_obj = cil_avrule->obj;
	struct cil_list *cil_perms = cil_avrule->perms_list;
	struct cil_list_item *curr_perm = cil_perms->head;
	struct cil_perm *cil_perm;
	type_datum_t *sepol_src = NULL;
	type_datum_t *sepol_tgt = NULL;
	class_datum_t *sepol_obj = NULL;
	avtab_ptr_t avtab_ptr;
	avtab_datum_t *avtab_datum = cil_malloc(sizeof(*avtab_datum));
	memset(avtab_datum, 0, sizeof(avtab_datum_t));
	avtab_key_t *avtab_key = cil_malloc(sizeof(*avtab_key));
	memset(avtab_key, 0, sizeof(avtab_key_t));

	key = ((struct cil_symtab_datum *)cil_avrule->src)->name;
	sepol_src = hashtab_search(pdb->p_types.table, key);
	if (sepol_src == NULL) {
		rc = SEPOL_ERR;
		goto avrule_to_policydb_out;
	}
	avtab_key->source_type = sepol_src->s.value;

	key = ((struct cil_symtab_datum *)cil_avrule->tgt)->name;
	sepol_tgt = hashtab_search(pdb->p_types.table, key);
	if (sepol_tgt == NULL) {
		rc = SEPOL_ERR;
		goto avrule_to_policydb_out;
	}
	avtab_key->target_type = sepol_tgt->s.value;

	key = cil_obj->datum.name;
	sepol_obj = hashtab_search(pdb->p_classes.table, key);
	if (sepol_obj == NULL) {
		rc = SEPOL_ERR;
		goto avrule_to_policydb_out;
	}
	avtab_key->target_class = sepol_obj->s.value;

	while (curr_perm != NULL) {
		perm_datum_t *sepol_perm;
		cil_perm = curr_perm->data;
		key = cil_perm->datum.name;
		sepol_perm = hashtab_search(sepol_obj->permissions.table, key);
		if (sepol_perm == NULL) {
			rc = SEPOL_ERR;
			goto avrule_to_policydb_out;
		}
		avtab_datum->data ^= 1 << (sepol_perm->s.value - 1);

		curr_perm = curr_perm->next;
	}

	switch (kind) {
	case CIL_AVRULE_ALLOWED:
		avtab_key->specified = AVTAB_ALLOWED;
		break;
	case CIL_AVRULE_AUDITALLOW:
		avtab_key->specified = AVTAB_AUDITALLOW;
		break;
	case CIL_AVRULE_NEVERALLOW:
		avtab_key->specified = AVTAB_NEVERALLOW;
		break;
	case CIL_AVRULE_DONTAUDIT:
		avtab_key->specified = AVTAB_AUDITDENY;
		avtab_datum->data = ~(avtab_datum->data);
		break;
	default:
		rc = SEPOL_ERR;
		goto avrule_to_policydb_out;
		break;
	}

	avtab_ptr = avtab_insert_nonunique(&pdb->te_avtab, avtab_key, avtab_datum);
	if (avtab_ptr == NULL) {
		rc = SEPOL_ERR;
		goto avrule_to_policydb_out;
	}

	return SEPOL_OK;

avrule_to_policydb_out:
	free(avtab_datum);
	free(avtab_key);
	avtab_destroy(&pdb->te_avtab);
	return rc;
}

int cil_roletrans_to_policydb(policydb_t *pdb, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	char *key = NULL;
	struct cil_role_trans *cil_roletrans = node->data;
	role_datum_t *sepol_src = NULL;
	type_datum_t *sepol_tgt = NULL;
	class_datum_t *sepol_obj = NULL;
	role_datum_t *sepol_result = NULL;
	role_trans_t *sepol_roletrans = cil_malloc(sizeof(*sepol_roletrans));
	memset(sepol_roletrans, 0, sizeof(role_trans_t));

	key = ((struct cil_symtab_datum *)cil_roletrans->src)->name;
	sepol_src = hashtab_search(pdb->p_roles.table, key);
	if (sepol_src == NULL) {
		rc = SEPOL_ERR;
		goto roletrans_to_policydb_out;
	}
	sepol_roletrans->role = sepol_src->s.value;

	key = ((struct cil_symtab_datum *)cil_roletrans->tgt)->name;
	sepol_tgt = hashtab_search(pdb->p_types.table, key);
	if (sepol_tgt == NULL) {
		rc = SEPOL_ERR;
		goto roletrans_to_policydb_out;
	}
	sepol_roletrans->type = sepol_tgt->s.value;

	key = ((struct cil_symtab_datum *)cil_roletrans->obj)->name;
	sepol_obj = hashtab_search(pdb->p_classes.table, key);
	if (sepol_obj == NULL) {
		rc = SEPOL_ERR;
		goto roletrans_to_policydb_out;
	}
	sepol_roletrans->tclass = sepol_obj->s.value;

	key = ((struct cil_symtab_datum *)cil_roletrans->result)->name;
	sepol_result = hashtab_search(pdb->p_roles.table, key);
	if (sepol_result == NULL) {
		rc = SEPOL_ERR;
		goto roletrans_to_policydb_out;
	}
	sepol_roletrans->new_role = sepol_result->s.value;

	if (pdb->role_tr == NULL) {
		pdb->role_tr = sepol_roletrans;
	} else {
		pdb->role_tr->next = sepol_roletrans;
	}

	return SEPOL_OK;

roletrans_to_policydb_out:
	free(sepol_roletrans);
	return rc;

}

int __cil_node_to_policydb(policydb_t *pdb, struct cil_tree_node *node, int pass)
{
	int rc = SEPOL_OK;
	switch (pass) {
	case 1:
		switch (node->flavor) {
		case CIL_COMMON:
			rc = cil_common_to_policydb(pdb, node);
			break;
		case CIL_CLASS:
			rc = cil_class_to_policydb(pdb, node);
			break;
		case CIL_ROLE:
			rc = cil_role_to_policydb(pdb, node);
			break;
		case CIL_TYPE:
			rc = cil_type_to_policydb(pdb, node);
			break;
		case CIL_POLICYCAP:
			rc = cil_policycap_to_policydb(pdb, node);
			break;
		case CIL_USER:
			rc = cil_user_to_policydb(pdb, node);
			break;
		case CIL_BOOL:
			rc = cil_bool_to_policydb(pdb, node);
			break;
		case CIL_CATALIAS:
			rc = cil_catalias_to_policydb(pdb, node);
			break;
		default:
			break;
		}
		break;
	case 2:
		switch (node->flavor) {
		case CIL_CLASSCOMMON:
			rc = cil_classcommon_to_policydb(pdb, node);
			break;
		case CIL_ROLETYPE:
			rc = cil_roletype_to_policydb(pdb, node);
			break;
		case CIL_ROLEDOMINANCE:
			rc = cil_roledominance_to_policydb(pdb, node);
			break;
		case CIL_ROLEBOUNDS:
			rc = cil_rolebounds_to_policydb(pdb, node);
			break;
		case CIL_USERROLE:
			rc = cil_userrole_to_policydb(pdb, node);
			break;
		case CIL_TYPE_RULE:
			rc = cil_type_rule_to_policydb(pdb, node);
			break;
		case CIL_AVRULE:
			rc = cil_avrule_to_policydb(pdb, node);
			break;
		case CIL_ROLETRANS:
			rc = cil_roletrans_to_policydb(pdb, node);
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}
	return rc;
}

int __cil_binary_create_helper(struct cil_tree_node *node, __attribute__((unused)) uint32_t *finished, void *extra_args)
{
	int rc = SEPOL_ERR;
	int pass;
	struct cil_args_binary *args = extra_args;
	policydb_t *pdb;

	pdb = args->pdb;
	pass = args->pass;

	rc = __cil_node_to_policydb(pdb, node, pass);
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

	rc = avtab_alloc(&pdb->te_avtab, MAX_AVTAB_SIZE);
	if (rc != SEPOL_OK) {
		goto binary_create_out;
	}

	rc = cil_catorder_to_policydb(pdb, db);
	if (rc != SEPOL_OK) {
		goto binary_create_out;
	}

	rc = cil_dominance_to_policydb(pdb, db);
	if (rc != SEPOL_OK) {
		goto binary_create_out;
	}

	extra_args.db = db;
	extra_args.pdb = pdb;
	for (i = 1; i <= 2; i++) {
		extra_args.pass = i;
		rc = cil_tree_walk(db->ast->root, __cil_binary_create_helper, NULL, NULL, &extra_args);
		if (rc != SEPOL_OK) {
			goto binary_create_out;
		}
	}

	rc = policydb_type_ebitmap_init(pdb);
	if (rc != SEPOL_OK) {
		goto binary_create_out;
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
