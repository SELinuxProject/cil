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
#include <sepol/policydb/conditional.h>
#include <sepol/policydb/constraint.h>

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

	sepol_type->flavor = TYPE_TYPE;

	key = cil_strdup(cil_type->datum.name);
	rc = symtab_insert(pdb, SYM_TYPES, key, sepol_type, SCOPE_DECL, 0, &value);
	if (rc != SEPOL_OK) {
		goto type_to_policydb_out;
	}
	sepol_type->s.value = value;
	sepol_type->primary = value;

	return SEPOL_OK;

type_to_policydb_out:
	free(key);
	free(sepol_type);
	return rc;
}
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

	key = cil_strdup(cil_user->datum.name);
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

int __cil_type_rule_to_avtab(policydb_t *pdb, struct cil_type_rule *cil_rule,
			avtab_key_t **avtab_key,
			avtab_datum_t **avtab_datum)
{
	int rc = SEPOL_ERR;
	char *key = NULL;
	uint16_t kind = cil_rule->rule_kind;
	type_datum_t *sepol_src = NULL;
	type_datum_t *sepol_tgt = NULL;
	type_datum_t *sepol_result = NULL;
	class_datum_t *sepol_obj = NULL;

	avtab_key_t *new_avtab_key = cil_malloc(sizeof(*new_avtab_key));
	memset(avtab_key, 0, sizeof(avtab_key_t));

	avtab_datum_t *new_avtab_datum = cil_malloc(sizeof(*new_avtab_datum));
	memset(avtab_datum, 0, sizeof(avtab_datum_t));

	key = ((struct cil_symtab_datum *)cil_rule->src)->name;
	sepol_src = hashtab_search(pdb->p_types.table, key);
	if (sepol_src == NULL) {
		rc = SEPOL_ERR;
		goto type_rule_to_avtab_out;
	}
	new_avtab_key->source_type = sepol_src->s.value;

	key = ((struct cil_symtab_datum *)cil_rule->tgt)->name;
	sepol_tgt = hashtab_search(pdb->p_types.table, key);
	if (sepol_tgt == NULL) {
		rc = SEPOL_ERR;
		goto type_rule_to_avtab_out;
	}
	new_avtab_key->target_type = sepol_tgt->s.value;

	key = ((struct cil_symtab_datum *)cil_rule->obj)->name;
	sepol_obj = hashtab_search(pdb->p_classes.table, key);
	if (sepol_obj == NULL) {
		rc = SEPOL_ERR;
		goto type_rule_to_avtab_out;
	}
	new_avtab_key->target_class = sepol_obj->s.value;

	key = ((struct cil_symtab_datum *)cil_rule->result)->name;
	sepol_result = hashtab_search(pdb->p_types.table, key);
	if (sepol_result == NULL) {
		rc = SEPOL_ERR;
		goto type_rule_to_avtab_out;
	}
	new_avtab_datum->data = sepol_result->s.value;

	switch (kind) {
	case CIL_TYPE_TRANSITION:
		new_avtab_key->specified = AVTAB_TRANSITION;
		break;
	case CIL_TYPE_CHANGE:
		new_avtab_key->specified = AVTAB_CHANGE;
		break;
	case CIL_TYPE_MEMBER:
		new_avtab_key->specified = AVTAB_MEMBER;
		break;
	default:
		rc = SEPOL_ERR;
		goto type_rule_to_avtab_out;
		break;
	}

	*avtab_key = new_avtab_key;
	*avtab_datum = new_avtab_datum;

	return SEPOL_OK;

type_rule_to_avtab_out:
	free(new_avtab_key);
	free(new_avtab_datum);
	return rc;
}

int cil_type_rule_to_policydb(policydb_t *pdb, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	struct cil_type_rule *cil_rule = node->data;
	avtab_ptr_t avtab_ptr = NULL;
	avtab_datum_t *avtab_datum = NULL;
	avtab_key_t *avtab_key = NULL;

	rc = __cil_type_rule_to_avtab(pdb, cil_rule, &avtab_key, &avtab_datum);
	if (rc != SEPOL_OK) {
		goto type_rule_to_policydb_out;
	}

	avtab_ptr = avtab_insert_nonunique(&pdb->te_avtab, avtab_key, avtab_datum);
	if (avtab_ptr == NULL) {
		rc = SEPOL_ERR;
		goto type_rule_to_policydb_out;
	}

	return SEPOL_OK;

type_rule_to_policydb_out:
	free(avtab_key);
	free(avtab_datum);
	return rc;
}

int __cil_avrule_to_avtab(policydb_t *pdb, struct cil_avrule *cil_avrule,
			avtab_key_t **avtab_key,
			avtab_datum_t **avtab_datum)
{
	int rc = SEPOL_ERR;
	char *key = NULL;
	uint16_t kind = cil_avrule->rule_kind;
	type_datum_t *sepol_src = NULL;
	type_datum_t *sepol_tgt = NULL;
	class_datum_t *sepol_obj = NULL;
	struct cil_list *cil_perms = cil_avrule->perms_list;
	struct cil_list_item *curr_perm = cil_perms->head;
	struct cil_perm *cil_perm;

	avtab_key_t *new_avtab_key = cil_malloc(sizeof(*avtab_key));
	memset(avtab_key, 0, sizeof(avtab_key_t));

	avtab_datum_t *new_avtab_datum = cil_malloc(sizeof(*avtab_datum));
	memset(avtab_datum, 0, sizeof(avtab_datum_t));

	key = ((struct cil_symtab_datum *)cil_avrule->src)->name;
	sepol_src = hashtab_search(pdb->p_types.table, key);
	if (sepol_src == NULL) {
		rc = SEPOL_ERR;
		goto avrule_to_avtab_out;
	}
	new_avtab_key->source_type = sepol_src->s.value;

	key = ((struct cil_symtab_datum *)cil_avrule->tgt)->name;
	sepol_tgt = hashtab_search(pdb->p_types.table, key);
	if (sepol_tgt == NULL) {
		rc = SEPOL_ERR;
		goto avrule_to_avtab_out;
	}
	new_avtab_key->target_type = sepol_tgt->s.value;

	key = ((struct cil_symtab_datum *)cil_avrule->obj)->name;
	sepol_obj = hashtab_search(pdb->p_classes.table, key);
	if (sepol_obj == NULL) {
		rc = SEPOL_ERR;
		goto avrule_to_avtab_out;
	}
	new_avtab_key->target_class = sepol_obj->s.value;

	while (curr_perm != NULL) {
		perm_datum_t *sepol_perm;
		cil_perm = curr_perm->data;
		key = cil_perm->datum.name;
		sepol_perm = hashtab_search(sepol_obj->permissions.table, key);
		if (sepol_perm == NULL) {
			common_datum_t *sepol_common = sepol_obj->comdatum;
			sepol_perm = hashtab_search(sepol_common->permissions.table, key);
			if (sepol_perm == NULL) {
				rc = SEPOL_ERR;
				goto avrule_to_avtab_out;
			}
		}
		new_avtab_datum->data |= 1 << (sepol_perm->s.value - 1);

		curr_perm = curr_perm->next;
	}

	switch (kind) {
	case CIL_AVRULE_ALLOWED:
		new_avtab_key->specified = AVTAB_ALLOWED;
		break;
	case CIL_AVRULE_AUDITALLOW:
		new_avtab_key->specified = AVTAB_AUDITALLOW;
		break;
	case CIL_AVRULE_NEVERALLOW:
		new_avtab_key->specified = AVTAB_NEVERALLOW;
		break;
	case CIL_AVRULE_DONTAUDIT:
		new_avtab_key->specified = AVTAB_AUDITDENY;
		new_avtab_datum->data = ~(new_avtab_datum->data);
		break;
	default:
		rc = SEPOL_ERR;
		goto avrule_to_avtab_out;
		break;
	}

	*avtab_key = new_avtab_key;
	*avtab_datum = new_avtab_datum;

	return SEPOL_OK;

avrule_to_avtab_out:
	free(new_avtab_key);
	free(new_avtab_datum);
	return rc;
}

int cil_avrule_to_policydb(policydb_t *pdb, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	struct cil_avrule *cil_avrule = node->data;
	avtab_ptr_t avtab_ptr;
	avtab_key_t *avtab_key = NULL;
	avtab_datum_t *avtab_datum = NULL;

	rc = __cil_avrule_to_avtab(pdb, cil_avrule, &avtab_key, &avtab_datum);
	if (rc != SEPOL_OK) {
		goto avrule_to_policydb_out;
	}

	avtab_ptr = avtab_insert_nonunique(&pdb->te_avtab, avtab_key, avtab_datum);
	if (avtab_ptr == NULL) {
		rc = SEPOL_ERR;
		goto avrule_to_policydb_out;
	}

	return SEPOL_OK;

avrule_to_policydb_out:
	free(avtab_key);
	free(avtab_datum);
	return rc;
}

int __cil_cond_to_policydb(policydb_t *pdb, struct cil_tree_node *node, cond_node_t *cond_node)
{
	int rc = SEPOL_ERR;
	enum cil_flavor flavor;
	struct cil_type_rule *cil_type_rule = NULL;
	struct cil_avrule *cil_avrule = NULL;
	struct cil_tree_node *curr_rule = NULL;
	cond_av_list_t *cond_list = NULL;
	avtab_key_t *avtab_key = NULL;
	avtab_datum_t *avtab_datum = NULL;
	avtab_ptr_t avtab_ptr = NULL;

	curr_rule = node->cl_head;
	while (curr_rule != NULL) {
		cond_list = cil_malloc(sizeof(*cond_list));
		memset(cond_list, 0, sizeof(cond_av_list_t));

		flavor = curr_rule->flavor;
		switch (flavor) {
		case CIL_TYPE_RULE:
			cil_type_rule = curr_rule->data;
			rc = __cil_type_rule_to_avtab(pdb, cil_type_rule, &avtab_key, &avtab_datum);
			break;
		case CIL_AVRULE:
			cil_avrule = curr_rule->data;
			rc = __cil_avrule_to_avtab(pdb, cil_avrule, &avtab_key, &avtab_datum);
			break;
		default:
			rc = SEPOL_ERR;
			break;
		}
		if (rc != SEPOL_OK) {
			goto cond_to_policydb_out;
		}

		avtab_ptr = avtab_insert_nonunique(&pdb->te_cond_avtab, avtab_key, avtab_datum);
		if (avtab_ptr == NULL) {
			rc = SEPOL_ERR;
			goto cond_to_policydb_out;
		}
		cond_list->node = avtab_ptr;

		flavor = node->flavor;
		switch (flavor) {
		case CIL_CONDTRUE:
			if (cond_node->true_list == NULL) {
				cond_node->true_list = cond_list;
			} else {
				cond_node->true_list->next = cond_list;
			}
			break;
		case CIL_CONDFALSE:
			if (cond_node->false_list == NULL) {
				cond_node->false_list = cond_list;
			} else {
				cond_node->false_list->next = cond_list;
			}
			break;
		default:
			rc = SEPOL_ERR;
			goto cond_to_policydb_out;
		}
		curr_rule = curr_rule->next;
	}

	return SEPOL_OK;

cond_to_policydb_out:
	free(avtab_key);
	free(avtab_datum);
	cond_av_list_destroy(cond_list);
	return rc;
}

int cil_booleanif_to_policydb(policydb_t *pdb, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	enum cil_flavor flavor;
	struct cil_booleanif *cil_boolif = node->data;
	struct cil_list *expr_stack = cil_boolif->expr_stack;
	struct cil_list_item *curr_expr = expr_stack->head;
	cond_expr_t *cond_expr = NULL;
	cond_expr_t *cond_expr_tmp = NULL;
	cond_node_t *cond_node = NULL;

	cond_node = cond_node_create(pdb, NULL);
	if (cond_node == NULL) {
		rc = SEPOL_ERR;
		goto booleanif_to_policydb_out;
	}

	while (curr_expr != NULL) {
		struct cil_conditional *cil_cond = curr_expr->data;
		cond_bool_datum_t *sepol_bool = NULL;
		cond_expr = cil_malloc(sizeof(*cond_expr));
		memset(cond_expr, 0, sizeof(cond_expr_t));

		flavor = cil_cond->flavor;
		switch (flavor) {
		case CIL_BOOL:
			cond_expr->expr_type = COND_BOOL;
			sepol_bool = hashtab_search(pdb->p_bools.table, cil_cond->str);
			if (sepol_bool == NULL) {
				rc = SEPOL_ERR;
				goto booleanif_to_policydb_out;
			}
			cond_expr->bool = sepol_bool->s.value;
			break;
		case CIL_NOT:
			cond_expr->expr_type = COND_NOT;
			break;
		case CIL_OR:
			cond_expr->expr_type = COND_OR;
			break;
		case CIL_AND:
			cond_expr->expr_type = COND_AND;
			break;
		case CIL_XOR:
			cond_expr->expr_type = COND_XOR;
			break;
		case CIL_EQ:
			cond_expr->expr_type = COND_EQ;
			break;
		case CIL_NEQ:
			cond_expr->expr_type = COND_NEQ;
			break;
		default:
			rc = SEPOL_ERR;
			goto booleanif_to_policydb_out;
		}

		if (cond_expr_tmp != NULL) {
			cond_expr_tmp->next = cond_expr;
		}
		cond_expr_tmp = cond_expr;
		curr_expr = curr_expr->next;
	}

	rc = __cil_cond_to_policydb(pdb, cil_boolif->condtrue, cond_node);
	if (rc != SEPOL_OK) {
		goto booleanif_to_policydb_out;
	}

	rc = __cil_cond_to_policydb(pdb, cil_boolif->condfalse, cond_node);
	if (rc != SEPOL_OK) {
		goto booleanif_to_policydb_out;
	}

	if (pdb->cond_list == NULL) {
		pdb->cond_list = cond_node;
	} else {
		pdb->cond_list->next = cond_node;
	}

	return SEPOL_OK;

booleanif_to_policydb_out:
	cond_node_destroy(cond_node);
	cond_expr_destroy(cond_expr);
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

int cil_roleallow_to_policydb(policydb_t *pdb, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	char *key = NULL;
	struct cil_role_allow *cil_roleallow = node->data;
	role_datum_t *sepol_role = NULL;
	role_datum_t *sepol_new_role = NULL;
	role_allow_t *sepol_roleallow = cil_malloc(sizeof(*sepol_roleallow));
	memset(sepol_roleallow, 0, sizeof(role_allow_t));

	key = ((struct cil_symtab_datum *)cil_roleallow->src)->name;
	sepol_role = hashtab_search(pdb->p_roles.table, key);
	if (sepol_role == NULL) {
		rc = SEPOL_ERR;
		goto roleallow_to_policydb_out;
	}
	sepol_roleallow->role = sepol_role->s.value;

	key = ((struct cil_symtab_datum *)cil_roleallow->tgt)->name;
	sepol_new_role = hashtab_search(pdb->p_roles.table, key);
	if (sepol_new_role == NULL) {
		rc = SEPOL_ERR;
		goto roleallow_to_policydb_out;
	}
	sepol_roleallow->new_role = sepol_new_role->s.value;

	if (pdb->role_allow == NULL) {
		pdb->role_allow = sepol_roleallow;
	} else {
		pdb->role_allow->next = sepol_roleallow;
	}

	return SEPOL_OK;

roleallow_to_policydb_out:
	free(sepol_roleallow);
	return rc;
}

int cil_filetransition_to_policydb(policydb_t *pdb, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	char *key = NULL;
	struct cil_filetransition *cil_filetrans = node->data;
	type_datum_t *sepol_src = NULL;
	type_datum_t *sepol_exec = NULL;
	class_datum_t *sepol_proc = NULL;
	type_datum_t *sepol_dest = NULL;
	filename_trans_t *sepol_filetrans = cil_malloc(sizeof(*sepol_filetrans));
	memset(sepol_filetrans, 0, sizeof(filename_trans_t));

	key = ((struct cil_symtab_datum *)cil_filetrans->src)->name;
	sepol_src = hashtab_search(pdb->p_types.table, key);
	if (sepol_src == NULL) {
		rc = SEPOL_ERR;
		goto filetrans_to_policydb_out;
	}
	sepol_filetrans->stype = sepol_src->s.value;

	key = ((struct cil_symtab_datum *)cil_filetrans->exec)->name;
	sepol_exec = hashtab_search(pdb->p_types.table, key);
	if (sepol_exec == NULL) {
		rc = SEPOL_ERR;
		goto filetrans_to_policydb_out;
	}
	sepol_filetrans->ttype = sepol_exec->s.value;

	key = ((struct cil_symtab_datum *)cil_filetrans->proc)->name;
	sepol_proc = hashtab_search(pdb->p_classes.table, key);
	if (sepol_proc == NULL) {
		rc = SEPOL_ERR;
		goto filetrans_to_policydb_out;
	}
	sepol_filetrans->tclass = sepol_proc->s.value;

	key = ((struct cil_symtab_datum *)cil_filetrans->dest)->name;
	sepol_dest = hashtab_search(pdb->p_types.table, key);
	if (sepol_dest == NULL) {
		rc = SEPOL_ERR;
		goto filetrans_to_policydb_out;
	}
	sepol_filetrans->otype = sepol_dest->s.value;

	sepol_filetrans->name = cil_filetrans->path_str;

	if (pdb->filename_trans == NULL) {
		pdb->filename_trans = sepol_filetrans;
	} else {
		pdb->filename_trans->next = sepol_filetrans;
	}

	return SEPOL_OK;

filetrans_to_policydb_out:
	free(sepol_filetrans);
	return rc;

}

int __cil_constrain_expr_to_sepol_expr(policydb_t *pdb,
					const struct cil_list *cil_expr,
					constraint_expr_t **sepol_expr)
{
	int rc = SEPOL_ERR;
	char *key = NULL;
	uint32_t value = 0;
	struct cil_list_item *curr = cil_expr->head;
	struct cil_conditional *rnode = NULL;
	struct cil_conditional *lnode = NULL;
	struct cil_user *cil_user = NULL;
	struct cil_user *cil_role = NULL;
	struct cil_type *cil_type = NULL;
	constraint_expr_t *new_expr = NULL;
	constraint_expr_t *new_expr_node = NULL;
	constraint_expr_t *curr_expr = NULL;
	user_datum_t *sepol_user = NULL;
	role_datum_t *sepol_role = NULL;
	type_datum_t *sepol_type = NULL;

	while (curr != NULL) {
		struct cil_conditional *cond = curr->data;

		if (cond->flavor == CIL_NOT || cond->flavor == CIL_AND
		|| cond->flavor == CIL_OR || cond->flavor == CIL_EQ
		|| cond->flavor == CIL_NEQ || cond->flavor == CIL_CONS_DOM
		|| cond->flavor == CIL_CONS_DOMBY || cond->flavor == CIL_CONS_INCOMP) {

			new_expr_node = cil_malloc(sizeof(*new_expr_node));
			rc = constraint_expr_init(new_expr_node);
			if (rc != SEPOL_OK) {
				goto cleanup;
			}

			if (new_expr == NULL) {
				new_expr = new_expr_node;
			} else {
				curr_expr->next = new_expr_node;
			}
			curr_expr = new_expr_node;

			switch (cond->flavor) {
			case CIL_NOT:
				curr_expr->expr_type = CEXPR_NOT;
				break;
			case CIL_AND:
				curr_expr->expr_type = CEXPR_AND;
				break;
			case CIL_OR:
				curr_expr->expr_type = CEXPR_OR;
				break;
			case CIL_EQ:
				curr_expr->op = CEXPR_EQ;
				break;
			case CIL_NEQ:
				curr_expr->op = CEXPR_NEQ;
				break;
			case CIL_CONS_DOM:
				curr_expr->op = CEXPR_DOM;
				break;
			case CIL_CONS_DOMBY:
				curr_expr->op = CEXPR_DOMBY;
				break;
			case CIL_CONS_INCOMP:
				curr_expr->op = CEXPR_INCOMP;
				break;
			default:
				break;
			}

			switch (lnode->flavor) {
			case CIL_CONS_U1:
				curr_expr->attr = CEXPR_USER;
				break;
			case CIL_CONS_U2:
				curr_expr->attr = CEXPR_USER | CEXPR_TARGET;
				break;
			case CIL_CONS_R1:
				curr_expr->attr = CEXPR_ROLE;
				break;
			case CIL_CONS_R2:
				curr_expr->attr = CEXPR_ROLE | CEXPR_TARGET;
				break;
			case CIL_CONS_T1:
				curr_expr->attr = CEXPR_TYPE;
				break;
			case CIL_CONS_T2:
				curr_expr->attr = CEXPR_TYPE | CEXPR_TARGET;
				break;
			case CIL_CONS_L1:
				if (rnode->flavor == CIL_CONS_L2) {
					curr_expr->attr = CEXPR_L1L2;
				} else if (rnode->flavor == CIL_CONS_H1) {
					curr_expr->attr = CEXPR_L1H1;
				} else if (rnode->flavor == CIL_CONS_H2) {
					curr_expr->attr = CEXPR_L1H2;
				}
				break;
			case CIL_CONS_L2:
				if (rnode->flavor == CIL_CONS_H2) {
					curr_expr->attr = CEXPR_L2H2;
				}
				break;
			case CIL_CONS_H1:
				if (rnode->flavor == CIL_CONS_L2) {
					curr_expr->attr = CEXPR_H1L2;
				} else if (rnode->flavor == CIL_CONS_H2) {
					curr_expr->attr = CEXPR_H1H2;
				}
				break;
			default:
				break;
			}

			switch (rnode->flavor) {
			case CIL_USER:
				cil_user = rnode->data;
				key = cil_user->datum.name;
				sepol_user = hashtab_search(pdb->p_users.table, key);
				if (sepol_user == NULL) {
					rc = SEPOL_ERR;
					goto cleanup;
				}
				value = sepol_user->s.value;
				if (ebitmap_set_bit(&curr_expr->names, value - 1, 1)) {
					rc = SEPOL_ERR;
					goto cleanup;
				}
				break;
			case CIL_ROLE:
				cil_role = rnode->data;
				key = cil_role->datum.name;
				sepol_role = hashtab_search(pdb->p_roles.table, key);
				if (sepol_role == NULL) {
					rc = SEPOL_ERR;
					goto cleanup;
				}
				value = sepol_role->s.value;
				if (ebitmap_set_bit(&curr_expr->names, value - 1, 1)) {
					rc = SEPOL_ERR;
					goto cleanup;
				}
				break;
			case CIL_TYPE:
				cil_type = rnode->data;
				key = cil_type->datum.name;
				sepol_type = hashtab_search(pdb->p_types.table, key);
				if (sepol_type == NULL) {
				rc = SEPOL_ERR;
					goto cleanup;
				}
				value = sepol_type->s.value;
				type_set_t *type_set = curr_expr->type_names;
				if (ebitmap_set_bit(&type_set->negset, value - 1, 1)) {
					rc = SEPOL_ERR;
					goto cleanup;
				}
				if (ebitmap_set_bit(&type_set->types, value - 1, 1)) {
					rc = SEPOL_ERR;
					goto cleanup;
				}
				break;
			default:
				break;
			}
		}

		lnode = rnode;
		rnode = cond;

		curr = curr->next;
	}

	*sepol_expr = new_expr;

	return SEPOL_OK;

cleanup:
	while (new_expr != NULL) {
		curr_expr = new_expr->next;
		constraint_expr_destroy(new_expr);
		new_expr = curr_expr;
	}
	return rc;
}

int cil_constrain_to_policydb(policydb_t *pdb, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	char *key = NULL;
	struct cil_constrain *cil_constrain = node->data;
	struct cil_list *classes = cil_constrain->class_list;
	struct cil_list *perms = cil_constrain->perm_list;
	struct cil_list *expr = cil_constrain->expr;
	struct cil_list_item *curr_class = classes->head;
	struct cil_list_item *curr_perm = perms->head;
	class_datum_t *sepol_class = NULL;
	perm_datum_t *sepol_perm = NULL;
	constraint_node_t *sepol_constrain = NULL;
	constraint_expr_t *sepol_expr = NULL;

	while (curr_class != NULL) {
		struct cil_class *class = curr_class->data;
		key = class->datum.name;
		sepol_class = hashtab_search(pdb->p_classes.table, key);
		if (sepol_class == NULL) {
			rc = SEPOL_ERR;
			goto constrain_to_policydb_out;
		}

		sepol_constrain = cil_malloc(sizeof(*sepol_constrain));
		memset(sepol_constrain, 0, sizeof(constraint_node_t));

		while (curr_perm != NULL) {
			struct cil_perm *perm = curr_perm->data;
			key = perm->datum.name;
			sepol_perm = hashtab_search(sepol_class->permissions.table, key);
			if (sepol_perm == NULL) {
				rc = SEPOL_ERR;
				goto constrain_to_policydb_out;
			}
			sepol_constrain->permissions |= 1 << (sepol_perm->s.value - 1);

			curr_perm = curr_perm->next;
		}

		rc = __cil_constrain_expr_to_sepol_expr(pdb, expr, &sepol_expr);
		if (rc != SEPOL_OK) {
			goto constrain_to_policydb_out;
		}
		sepol_constrain->expr = sepol_expr;

		if (sepol_class->constraints == NULL) {
			sepol_class->constraints = sepol_constrain;
		} else {
			sepol_class->constraints->next = sepol_constrain;
		}

		sepol_expr = NULL;
		curr_perm = perms->head;
		curr_class = curr_class->next;
	}

	return SEPOL_OK;

constrain_to_policydb_out:
	free(sepol_constrain);
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
		case CIL_ROLEALLOW:
			rc = cil_roleallow_to_policydb(pdb, node);
			break;
		case CIL_FILETRANSITION:
			rc = cil_filetransition_to_policydb(pdb, node);
			break;
		case CIL_BOOLEANIF:
			rc = cil_booleanif_to_policydb(pdb, node);
			break;
		case CIL_CONSTRAIN:
		case CIL_MLSCONSTRAIN:
			rc = cil_constrain_to_policydb(pdb, node);
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

	if (node->flavor == CIL_OPTIONAL) {
		struct cil_optional *opt = node->data;
		if (opt->datum.state != CIL_STATE_ENABLED) {
			*finished = CIL_TREE_SKIP_HEAD;
			rc = SEPOL_OK;
			goto binary_create_helper_out;
		}
	} else if (node->flavor == CIL_MACRO) {
		*finished = CIL_TREE_SKIP_HEAD;
		rc = SEPOL_OK;
		goto binary_create_helper_out;
	}	

	rc = __cil_node_to_policydb(pdb, node, pass);
	if (rc != SEPOL_OK) {
		goto binary_create_helper_out;
	}

	return SEPOL_OK;

binary_create_helper_out:
	return rc;
}

int __cil_policydb_init(policydb_t *pdb, const struct cil_db *db)
{
	int rc = SEPOL_ERR;

	rc = cil_catorder_to_policydb(pdb, db);
	if (rc != SEPOL_OK) {
		goto policydb_init_out;
	}

	rc = cil_dominance_to_policydb(pdb, db);
	if (rc != SEPOL_OK) {
		goto policydb_init_out;
	}

	rc = avtab_alloc(&pdb->te_avtab, MAX_AVTAB_SIZE);
	if (rc != SEPOL_OK) {
		goto policydb_init_out;
	}

	rc = cond_policydb_init(pdb);
	if (rc != SEPOL_OK) {
		goto policydb_init_out;
	}

	rc = avtab_alloc(&pdb->te_cond_avtab, MAX_AVTAB_SIZE);
	if (rc != SEPOL_OK) {
		goto policydb_init_out;
	}

	return SEPOL_OK;

policydb_init_out:
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

	rc = __cil_policydb_init(pdb, db);
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
