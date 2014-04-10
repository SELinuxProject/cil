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
#include <netinet/in.h>

#include <sepol/policydb/policydb.h>
#include <sepol/policydb/polcaps.h>
#include <sepol/policydb/conditional.h>
#include <sepol/policydb/constraint.h>
#include <sepol/policydb/flask.h>

#include "cil_internal.h"
#include "cil_flavor.h"
#include "cil_log.h"
#include "cil_mem.h"
#include "cil_tree.h"
#include "cil_binary.h"

#define DATUM(d) ((struct cil_symtab_datum *)(d))

struct cil_args_binary {
	const struct cil_db *db;
	policydb_t *pdb;
	struct cil_list *neverallows;
	int pass;
};

struct cil_args_booleanif {
	const struct cil_db *db;
	policydb_t *pdb;
	cond_node_t *cond_node;
	enum cil_flavor cond_flavor;
	struct cil_list *neverallows;
};

struct cil_neverallow {
	struct cil_tree_node *node;
	struct cil_list *rules;
};

struct cil_neverallow_rule {
	struct cil_symtab_datum *src;
	struct cil_symtab_datum *tgt;
	uint32_t class;
	uint32_t perms;
};

void cil_neverallows_list_destroy(struct cil_list *neverallows)
{
	struct cil_list_item *i;
	struct cil_list_item *j;

	cil_list_for_each(i, neverallows) {
		struct cil_neverallow *neverallow = i->data;
		cil_list_for_each(j, neverallow->rules) {
			struct cil_neverallow_rule *rule = j->data;
			free(rule);
		}
		cil_list_destroy(&neverallow->rules, CIL_FALSE);
		free(neverallow);
	}
	cil_list_destroy(&neverallows, CIL_FALSE);
}

static int __cil_get_sepol_user_datum(policydb_t *pdb, struct cil_symtab_datum *datum, user_datum_t **sepol_user)
{
	*sepol_user = hashtab_search(pdb->p_users.table, datum->name);
	if (*sepol_user == NULL) {
		cil_log(CIL_INFO, "Failed to find user %s in sepol hashtab\n", datum->name);
		return SEPOL_ERR;
	}

	return SEPOL_OK;
}

static int __cil_get_sepol_role_datum(policydb_t *pdb, struct cil_symtab_datum *datum, role_datum_t **sepol_role)
{
	*sepol_role = hashtab_search(pdb->p_roles.table, datum->name);
	if (*sepol_role == NULL) {
		cil_log(CIL_INFO, "Failed to find role %s in sepol hashtab\n", datum->name);
		return SEPOL_ERR;
	}

	return SEPOL_OK;
}

static int __cil_get_sepol_type_datum(policydb_t *pdb, struct cil_symtab_datum *datum, type_datum_t **sepol_type)
{
	*sepol_type = hashtab_search(pdb->p_types.table, datum->name);
	if (*sepol_type == NULL) {
		cil_log(CIL_INFO, "Failed to find type %s in sepol hashtab\n", datum->name);
		return SEPOL_ERR;
	}

	return SEPOL_OK;
}

static int __cil_get_sepol_class_datum(policydb_t *pdb, struct cil_symtab_datum *datum, class_datum_t **sepol_class)
{
	*sepol_class = hashtab_search(pdb->p_classes.table, datum->name);
	if (*sepol_class == NULL) {
		cil_log(CIL_INFO, "Failed to find class %s in sepol hashtab\n", datum->name);
		return SEPOL_ERR;
	}

	return SEPOL_OK;
}

static int __cil_get_sepol_cat_datum(policydb_t *pdb, struct cil_symtab_datum *datum, cat_datum_t **sepol_cat)
{
	*sepol_cat = hashtab_search(pdb->p_cats.table, datum->name);
	if (*sepol_cat == NULL) {
		cil_log(CIL_INFO, "Failed to find category %s in sepol hashtab\n", datum->name);
		return SEPOL_ERR;
	}

	return SEPOL_OK;
}

static int __cil_get_sepol_level_datum(policydb_t *pdb, struct cil_symtab_datum *datum, level_datum_t **sepol_level)
{
	*sepol_level = hashtab_search(pdb->p_levels.table, datum->name);
	if (*sepol_level == NULL) {
		cil_log(CIL_INFO, "Failed to find level %s in sepol hashtab\n", datum->name);
		return SEPOL_ERR;
	}

	return SEPOL_OK;
}

static int __cil_expand_role(struct cil_symtab_datum *datum, ebitmap_t *new)
{
	struct cil_tree_node *node = datum->nodes->head->data;

	if (node->flavor == CIL_ROLEATTRIBUTE) {
		struct cil_roleattribute *attr = (struct cil_roleattribute *)datum;
		if (ebitmap_cpy(new, attr->roles)) {
			cil_log(CIL_ERR, "Failed to copy role bits\n");
			goto exit;
		}
	} else {
		struct cil_role *role = (struct cil_role *)datum;
		ebitmap_init(new);
		if (ebitmap_set_bit(new, role->value, 1)) {
			cil_log(CIL_ERR, "Failed to set role bit\n");
			ebitmap_destroy(new);
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	return SEPOL_ERR;
}

static int __cil_expand_type(struct cil_symtab_datum *datum, ebitmap_t *new)
{
	struct cil_tree_node *node = datum->nodes->head->data;

	if (node->flavor == CIL_TYPEATTRIBUTE) {
		struct cil_typeattribute *attr = (struct cil_typeattribute *)datum;
		if (ebitmap_cpy(new, attr->types)) {
			cil_log(CIL_ERR, "Failed to copy type bits\n");
			goto exit;
		}
	} else {
		struct cil_type *type = (struct cil_type *)datum;
		ebitmap_init(new);
		if (ebitmap_set_bit(new, type->value, 1)) {
			cil_log(CIL_ERR, "Failed to set type bit\n");
			ebitmap_destroy(new);
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	return SEPOL_ERR;
}
		
int cil_common_to_policydb(policydb_t *pdb, struct cil_common *cil_common, common_datum_t **common_out)
{
	int rc = SEPOL_ERR;
	uint32_t value = 0;
	char *key = NULL;
	struct cil_tree_node *node = cil_common->datum.nodes->head->data;
	struct cil_tree_node *cil_perm = node->cl_head;
	common_datum_t *sepol_common = cil_malloc(sizeof(*sepol_common));
	memset(sepol_common, 0, sizeof(common_datum_t));

	key = cil_strdup(cil_common->datum.name);
	rc = symtab_insert(pdb, SYM_COMMONS, key, sepol_common, SCOPE_DECL, 0, &value);
	if (rc != SEPOL_OK) {
		free(sepol_common);
		goto exit;
	}
	sepol_common->s.value = value;

	rc = symtab_init(&sepol_common->permissions, PERM_SYMTAB_SIZE);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	while (cil_perm != NULL) {
		struct cil_perm *curr = cil_perm->data;
		perm_datum_t *sepol_perm = cil_malloc(sizeof(*sepol_perm));
		memset(sepol_perm, 0, sizeof(perm_datum_t));

		key = cil_strdup(curr->datum.name);
		rc = hashtab_insert(sepol_common->permissions.table, key, sepol_perm);
		if (rc != SEPOL_OK) {
			free(sepol_perm);
			goto exit;
		}
		sepol_perm->s.value = sepol_common->permissions.nprim + 1;
		sepol_common->permissions.nprim++;
		cil_perm = cil_perm->next;
	}

	*common_out = sepol_common;

	return SEPOL_OK;

exit:
	free(key);
	return rc;
}

int cil_class_to_policydb(policydb_t *pdb, struct cil_class *cil_class)
{
	int rc = SEPOL_ERR;
	uint32_t value = 0;
	char *key = NULL;
	struct cil_tree_node *node = cil_class->datum.nodes->head->data;
	struct cil_tree_node *cil_perm = node->cl_head;
	common_datum_t *sepol_common = NULL;
	class_datum_t *sepol_class = cil_malloc(sizeof(*sepol_class));
	memset(sepol_class, 0, sizeof(class_datum_t));

	key = cil_strdup(cil_class->datum.name);
	rc = symtab_insert(pdb, SYM_CLASSES, key, sepol_class, SCOPE_DECL, 0, &value);
	if (rc != SEPOL_OK) {
		free(sepol_class);
		goto exit;
	}
	sepol_class->s.value = value;

	rc = symtab_init(&sepol_class->permissions, PERM_SYMTAB_SIZE);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	if (cil_class->common != NULL) {
		struct cil_common *cil_common = cil_class->common;

		key = cil_class->common->datum.name;
		sepol_common = hashtab_search(pdb->p_commons.table, key);
		if (sepol_common == NULL) {
			rc = cil_common_to_policydb(pdb, cil_common, &sepol_common);
			if (rc != SEPOL_OK) {
				goto exit;
			}
		}
		sepol_class->comdatum = sepol_common;
		sepol_class->comkey = cil_strdup(key);
		sepol_class->permissions.nprim += sepol_common->permissions.nprim;
	}

	while (cil_perm != NULL) {
		struct cil_perm *curr = cil_perm->data;
		perm_datum_t *sepol_perm = cil_malloc(sizeof(*sepol_perm));
		memset(sepol_perm, 0, sizeof(perm_datum_t));

		key = cil_strdup(curr->datum.name);
		rc = hashtab_insert(sepol_class->permissions.table, key, sepol_perm);
		if (rc != SEPOL_OK) {
			free(sepol_perm);
			goto exit;
		}
		sepol_perm->s.value = sepol_class->permissions.nprim + 1;
		sepol_class->permissions.nprim++;
		cil_perm = cil_perm->next;
	}

	return SEPOL_OK;

exit:
	free(key);
	return rc;
}

int cil_role_to_policydb(policydb_t *pdb, struct cil_role *cil_role)
{
	int rc = SEPOL_ERR;
	uint32_t value = 0;
	char *key = NULL;
	role_datum_t *sepol_role = cil_malloc(sizeof(*sepol_role));
	role_datum_init(sepol_role);

	key = cil_strdup(cil_role->datum.name);
	if (!strcmp(key, "object_r")) {
		/* special case
		 * object_r defaults to 1 in libsepol symtab */
		rc = SEPOL_OK;
		goto exit;
	}

	rc = symtab_insert(pdb, SYM_ROLES, (hashtab_key_t)key, sepol_role, SCOPE_DECL, 0, &value);
	if (rc != SEPOL_OK) {
		goto exit;
	}
	sepol_role->s.value = value;
	return SEPOL_OK;

exit:
	free(key);
	role_datum_destroy(sepol_role);
	free(sepol_role);
	return rc;
}

int cil_role_bounds_to_policydb(policydb_t *pdb, struct cil_role *cil_role)
{
	int rc = SEPOL_ERR;
	role_datum_t *sepol_role = NULL;
	role_datum_t *sepol_parent = NULL;

	if (cil_role->bounds) {
		rc = __cil_get_sepol_role_datum(pdb, DATUM(cil_role), &sepol_role);
		if (rc != SEPOL_OK) goto exit;

		rc = __cil_get_sepol_role_datum(pdb, DATUM(cil_role->bounds), &sepol_parent);
		if (rc != SEPOL_OK) goto exit;
	
		sepol_role->bounds = sepol_parent->s.value;
	}

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Failed to insert role bounds for role %s\n", cil_role->datum.name);
	return SEPOL_ERR;
}

int cil_roletype_to_policydb(policydb_t *pdb, const struct cil_db *db, struct cil_role *role)
{
	int rc = SEPOL_ERR;

	if (role->types) {
		role_datum_t *sepol_role = NULL;
		type_datum_t *sepol_type = NULL;
		ebitmap_node_t *tnode;
		unsigned int i;

		rc = __cil_get_sepol_role_datum(pdb, DATUM(role), &sepol_role);
		if (rc != SEPOL_OK) goto exit;

		ebitmap_for_each_bit(role->types, tnode, i) {
			if (!ebitmap_get_bit(role->types, i)) continue;

			rc = __cil_get_sepol_type_datum(pdb, DATUM(db->val_to_type[i]), &sepol_type);
			if (rc != SEPOL_OK) goto exit;

			if (ebitmap_set_bit(&sepol_role->types.types, sepol_type->s.value - 1, 1)) {
				cil_log(CIL_INFO, "Failed to set type bit for role\n");
				rc = SEPOL_ERR;
				goto exit;
			}
		}
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_type_to_policydb(policydb_t *pdb, struct cil_type *cil_type)
{
	int rc = SEPOL_ERR;
	uint32_t value = 0;
	char *key = NULL;
	type_datum_t *sepol_type = cil_malloc(sizeof(*sepol_type));
	type_datum_init(sepol_type);

	sepol_type->flavor = TYPE_TYPE;

	key = cil_strdup(cil_type->datum.name);
	rc = symtab_insert(pdb, SYM_TYPES, key, sepol_type, SCOPE_DECL, 0, &value);
	if (rc != SEPOL_OK) {
		goto exit;
	}
	sepol_type->s.value = value;
	sepol_type->primary = 1;

	return SEPOL_OK;

exit:
	free(key);
	type_datum_destroy(sepol_type);
	free(sepol_type);
	return rc;
}

int cil_type_bounds_to_policydb(policydb_t *pdb, struct cil_type *cil_type)
{
	int rc = SEPOL_ERR;
	type_datum_t *sepol_type = NULL;
	type_datum_t *sepol_parent = NULL;

	if (cil_type->bounds) {
		rc = __cil_get_sepol_type_datum(pdb, DATUM(cil_type), &sepol_type);
		if (rc != SEPOL_OK) goto exit;

		rc = __cil_get_sepol_type_datum(pdb, DATUM(cil_type->bounds), &sepol_parent);
		if (rc != SEPOL_OK) goto exit;
	
		sepol_type->bounds = sepol_parent->s.value;
	}

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Failed to insert type bounds for type %s\n", cil_type->datum.name);
	return SEPOL_ERR;
}

int cil_typealias_to_policydb(policydb_t *pdb, struct cil_alias *cil_alias)
{
	int rc = SEPOL_ERR;
	char *key = NULL;
	type_datum_t *sepol_type = NULL;
	type_datum_t *sepol_alias = cil_malloc(sizeof(*sepol_alias));
	type_datum_init(sepol_alias);

	rc = __cil_get_sepol_type_datum(pdb, DATUM(cil_alias->actual), &sepol_type);
	if (rc != SEPOL_OK) goto exit;

	sepol_alias->flavor = TYPE_TYPE;

	key = cil_strdup(cil_alias->datum.name);
	rc = symtab_insert(pdb, SYM_TYPES, key, sepol_alias, SCOPE_DECL, 0, NULL);
	if (rc != SEPOL_OK) {
		goto exit;
	}
	sepol_alias->s.value = sepol_type->s.value;
	sepol_alias->primary = 0;

	return SEPOL_OK;

exit:
	free(key);
	type_datum_destroy(sepol_alias);
	free(sepol_alias);
	return rc;
}

int cil_typepermissive_to_policydb(policydb_t *pdb, struct cil_typepermissive *cil_typeperm)
{
	int rc = SEPOL_ERR;
	type_datum_t *sepol_type = NULL;

	rc = __cil_get_sepol_type_datum(pdb, DATUM(cil_typeperm->type), &sepol_type);
	if (rc != SEPOL_OK) goto exit;

	if (ebitmap_set_bit(&pdb->permissive_map, sepol_type->s.value, 1)) {
		goto exit;
	}

	return SEPOL_OK;

exit:
	type_datum_destroy(sepol_type);
	free(sepol_type);
	return rc;

}

int cil_typeattribute_to_policydb(policydb_t *pdb, struct cil_typeattribute *cil_attr)
{
	int rc = SEPOL_ERR;
	uint32_t value = 0;
	char *key = NULL;
	type_datum_t *sepol_attr = cil_malloc(sizeof(*sepol_attr));
	type_datum_init(sepol_attr);

	sepol_attr->flavor = TYPE_ATTRIB;

	key = cil_strdup(cil_attr->datum.name);
	rc = symtab_insert(pdb, SYM_TYPES, key, sepol_attr, SCOPE_DECL, 0, &value);
	if (rc != SEPOL_OK) {
		goto exit;
	}
	sepol_attr->s.value = value;
	sepol_attr->primary = 1;

	return SEPOL_OK;

exit:
	type_datum_destroy(sepol_attr);
	free(sepol_attr);
	return rc;
}

int __cil_typeattr_bitmap_init(policydb_t *pdb)
{
	int rc = SEPOL_ERR;

	pdb->type_attr_map = cil_malloc(pdb->p_types.nprim * sizeof(ebitmap_t));

	uint32_t i = 0;
	for (i = 0; i < pdb->p_types.nprim; i++) {
		ebitmap_init(&pdb->type_attr_map[i]);
		if (ebitmap_set_bit(&pdb->type_attr_map[i], i, 1)) {
			rc = SEPOL_ERR;
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_typeattribute_to_bitmap(policydb_t *pdb, const struct cil_db *db, struct cil_typeattribute *cil_attr)
{
	int rc = SEPOL_ERR;
	uint32_t value = 0;
	type_datum_t *sepol_type = NULL;
	ebitmap_node_t *tnode;
	unsigned int i;
	
	if (pdb->type_attr_map == NULL) {
		rc = __cil_typeattr_bitmap_init(pdb);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	rc = __cil_get_sepol_type_datum(pdb, DATUM(cil_attr), &sepol_type);
	if (rc != SEPOL_OK) goto exit;

	value = sepol_type->s.value;

	ebitmap_for_each_bit(cil_attr->types, tnode, i) {
		if (!ebitmap_get_bit(cil_attr->types, i)) continue;

		rc = __cil_get_sepol_type_datum(pdb, DATUM(db->val_to_type[i]), &sepol_type);
		if (rc != SEPOL_OK) goto exit;

		ebitmap_set_bit(&pdb->type_attr_map[sepol_type->s.value - 1], value - 1, 1);
	}

	rc = SEPOL_OK;
exit:
	return rc;
}

int cil_policycap_to_policydb(policydb_t *pdb, struct cil_policycap *cil_polcap)
{
	int rc = SEPOL_ERR;
	int capnum;

	capnum = sepol_polcap_getnum(cil_polcap->datum.name);
	if (capnum == -1) {
		goto exit;
	}

	if (ebitmap_set_bit(&pdb->policycaps, capnum, 1)) {
		goto exit;
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_user_to_policydb(policydb_t *pdb, struct cil_user *cil_user)
{
	int rc = SEPOL_ERR;
	uint32_t value = 0;
	char *key = NULL;
	user_datum_t *sepol_user = cil_malloc(sizeof(*sepol_user));
	user_datum_init(sepol_user);

	key = cil_strdup(cil_user->datum.name);
	rc = symtab_insert(pdb, SYM_USERS, key, sepol_user, SCOPE_DECL, 0, &value);
	if (rc != SEPOL_OK) {
		goto exit;
	}
	sepol_user->s.value = value;

	return SEPOL_OK;

exit:
	free(key);
	user_datum_destroy(sepol_user);
	free(sepol_user);
	return rc;
}

int cil_user_bounds_to_policydb(policydb_t *pdb, struct cil_user *cil_user)
{
	int rc = SEPOL_ERR;
	user_datum_t *sepol_user = NULL;
	user_datum_t *sepol_parent = NULL;

	if (cil_user->bounds) {
		rc = __cil_get_sepol_user_datum(pdb, DATUM(cil_user), &sepol_user);
		if (rc != SEPOL_OK) goto exit;

		rc = __cil_get_sepol_user_datum(pdb, DATUM(cil_user->bounds), &sepol_parent);
		if (rc != SEPOL_OK) goto exit;
	
		sepol_user->bounds = sepol_parent->s.value;
	}

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Failed to insert user bounds for user %s\n", cil_user->datum.name);
	return SEPOL_ERR;
}

int cil_userrole_to_policydb(policydb_t *pdb, const struct cil_db *db, struct cil_userrole *userrole)
{
	int rc = SEPOL_ERR;
	user_datum_t *sepol_user = NULL;
	role_datum_t *sepol_role = NULL;
	ebitmap_t role_bitmap;
	ebitmap_node_t *rnode;
	unsigned int i;

	rc = __cil_get_sepol_user_datum(pdb, DATUM(userrole->user), &sepol_user);
	if (rc != SEPOL_OK) goto exit;

	rc = __cil_expand_role(userrole->role, &role_bitmap);
	if (rc != SEPOL_OK) goto exit;

	ebitmap_for_each_bit(&role_bitmap, rnode, i) {
		if (!ebitmap_get_bit(&role_bitmap, i)) continue;

		rc = __cil_get_sepol_role_datum(pdb, DATUM(db->val_to_role[i]), &sepol_role);
		if (rc != SEPOL_OK) goto exit;

		if (ebitmap_set_bit(&sepol_user->roles.roles, sepol_role->s.value - 1, 1)) {
			cil_log(CIL_INFO, "Failed to set role bit for user\n");
			goto exit;
		}
	}

	rc = SEPOL_OK;

exit:
	ebitmap_destroy(&role_bitmap);
	return rc;
}

int cil_bool_to_policydb(policydb_t *pdb, struct cil_bool *cil_bool)
{
	int rc = SEPOL_ERR;
	uint32_t value = 0;
	char *key = NULL;
	cond_bool_datum_t *sepol_bool = cil_malloc(sizeof(*sepol_bool));
	memset(sepol_bool, 0, sizeof(cond_bool_datum_t));

	key = cil_strdup(cil_bool->datum.name);
	rc = symtab_insert(pdb, SYM_BOOLS, key, sepol_bool, SCOPE_DECL, 0, &value);
	if (rc != SEPOL_OK) {
		goto exit;
	}
	sepol_bool->s.value = value;
	sepol_bool->state = cil_bool->value;

	return SEPOL_OK;

exit:
	free(key);
	free(sepol_bool);
	return rc;
}

int cil_catorder_to_policydb(policydb_t *pdb, const struct cil_db *db)
{
	int rc = SEPOL_ERR;
	uint32_t value = 0;
	char *key = NULL;
	struct cil_list_item *curr_cat;
	struct cil_cat *cil_cat = NULL;
	cat_datum_t *sepol_cat = NULL;

	cil_list_for_each(curr_cat, db->catorder) {
		cil_cat = curr_cat->data;
		sepol_cat = cil_malloc(sizeof(*sepol_cat));
		cat_datum_init(sepol_cat);

		key = cil_strdup(cil_cat->datum.name);
		rc = symtab_insert(pdb, SYM_CATS, key, sepol_cat, SCOPE_DECL, 0, &value);
		if (rc != SEPOL_OK) {
			goto exit;
		}
		sepol_cat->s.value = value;
	}

	return SEPOL_OK;

exit:
	free(key);
	cat_datum_destroy(sepol_cat);
	free(sepol_cat);
	return rc;
}

int cil_catalias_to_policydb(policydb_t *pdb, struct cil_alias *cil_alias)
{
	int rc = SEPOL_ERR;
	char *key = NULL;
	cat_datum_t *sepol_cat;
	cat_datum_t *sepol_alias = cil_malloc(sizeof(*sepol_cat));
	cat_datum_init(sepol_alias);

	rc = __cil_get_sepol_cat_datum(pdb, DATUM(cil_alias->actual), &sepol_cat);
	if (rc != SEPOL_OK) goto exit;

	key = cil_strdup(cil_alias->datum.name);
	rc = symtab_insert(pdb, SYM_CATS, key, sepol_alias, SCOPE_DECL, 0, NULL);
	if (rc != SEPOL_OK) {
		free(key);
		goto exit;
	}
	sepol_alias->s.value = sepol_cat->s.value;
	sepol_alias->isalias = 1;

	return SEPOL_OK;

exit:
	free(key);
	cat_datum_destroy(sepol_alias);
	free(sepol_alias);
	return rc;
}

int cil_sensitivityorder_to_policydb(policydb_t *pdb, const struct cil_db *db)
{
	int rc = SEPOL_ERR;
	uint32_t value = 0;
	char *key = NULL;
	struct cil_list_item *curr;
	struct cil_sens *cil_sens = NULL;
	level_datum_t *sepol_level = NULL;
	mls_level_t *mls_level = NULL;

	cil_list_for_each(curr, db->sensitivityorder) {
		cil_sens = curr->data;
		sepol_level = cil_malloc(sizeof(*sepol_level));
		mls_level = cil_malloc(sizeof(*mls_level));
		level_datum_init(sepol_level);
		mls_level_init(mls_level);

		key = cil_strdup(cil_sens->datum.name);
		rc = symtab_insert(pdb, SYM_LEVELS, key, sepol_level, SCOPE_DECL, 0, &value);
		if (rc != SEPOL_OK) {
			goto exit;
		}
		mls_level->sens = value;
		sepol_level->level = mls_level;
	}

	return SEPOL_OK;

exit:
	level_datum_destroy(sepol_level);
	mls_level_destroy(mls_level);
	free(sepol_level);
	free(mls_level);
	free(key);
	return rc;
}

int cil_sensalias_to_policydb(policydb_t *pdb, struct cil_alias *cil_alias)
{
	int rc = SEPOL_ERR;
	char *key = NULL;
	mls_level_t *mls_level = NULL;
	level_datum_t *sepol_level = NULL;
	level_datum_t *sepol_alias = cil_malloc(sizeof(*sepol_alias));
	level_datum_init(sepol_alias);

	rc = __cil_get_sepol_level_datum(pdb, DATUM(cil_alias->actual), &sepol_level);
	if (rc != SEPOL_OK) goto exit;

	key = cil_strdup(cil_alias->datum.name);
	rc = symtab_insert(pdb, SYM_LEVELS, key, sepol_alias, SCOPE_DECL, 0, NULL);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	mls_level = cil_malloc(sizeof(*mls_level));
	mls_level_init(mls_level);

	rc = mls_level_cpy(mls_level, sepol_level->level);
	if (rc != SEPOL_OK) {
		goto exit;
	}
	sepol_alias->level = mls_level;
	sepol_alias->defined = 1;
	sepol_alias->isalias = 1;

	return SEPOL_OK;

exit:
	level_datum_destroy(sepol_alias);
	free(sepol_level);
	free(key);
	return rc;
}

int __cil_cond_insert_rule(avtab_t *avtab, avtab_key_t *avtab_key, avtab_datum_t *avtab_datum, cond_node_t *cond_node, enum cil_flavor cond_flavor)
{
	int rc = SEPOL_OK;
	avtab_ptr_t avtab_ptr = NULL;
	cond_av_list_t *cond_list = NULL;

	avtab_ptr = avtab_insert_nonunique(avtab, avtab_key, avtab_datum);
	if (!avtab_ptr) {
		rc = SEPOL_ERR;
		goto exit;
	}

	// parse_context needs to be non-NULL for conditional rules to be
	// written to the binary. it is normally used for finding duplicates,
	// but cil checks that earlier, so we don't use it. it just needs to be
	// set
	avtab_ptr->parse_context = (void*)1;

	cond_list = cil_malloc(sizeof(cond_av_list_t));
	memset(cond_list, 0, sizeof(cond_av_list_t));

	cond_list->node = avtab_ptr;

	if (cond_flavor == CIL_CONDTRUE) {
      cond_list->next = cond_node->true_list;
      cond_node->true_list = cond_list;
	} else {
      cond_list->next = cond_node->false_list;
      cond_node->false_list = cond_list;
	}

exit:
	return rc;
}

avtab_datum_t *cil_cond_av_list_search(avtab_key_t *key, cond_av_list_t *cond_list)
{
	cond_av_list_t *cur_av;

	for (cur_av = cond_list; cur_av != NULL; cur_av = cur_av->next) {
		if (cur_av->node->key.source_type == key->source_type &&
		    cur_av->node->key.target_type == key->target_type &&
		    cur_av->node->key.target_class == key->target_class &&
			(cur_av->node->key.specified & key->specified))

			return &cur_av->node->datum;

	}
	return NULL;
}

int __cil_insert_type_rule(policydb_t *pdb, uint32_t kind, uint32_t src, uint32_t tgt, uint32_t obj, uint32_t res, cond_node_t *cond_node, enum cil_flavor cond_flavor)
{
	int rc = SEPOL_OK;
	avtab_key_t avtab_key;
	avtab_datum_t avtab_datum;
	avtab_ptr_t existing;	

	avtab_key.source_type = src;
	avtab_key.target_type = tgt;
	avtab_key.target_class = obj;

	switch (kind) {
	case CIL_TYPE_TRANSITION:
		avtab_key.specified = AVTAB_TRANSITION;
		break;
	case CIL_TYPE_CHANGE:
		avtab_key.specified = AVTAB_CHANGE;
		break;
	case CIL_TYPE_MEMBER:
		avtab_key.specified = AVTAB_MEMBER;
		break;
	default:
		rc = SEPOL_ERR;
		goto exit;
	}

	avtab_datum.data = res;
	
	existing = avtab_search_node(&pdb->te_avtab, &avtab_key);
	if (existing) {
		/* Don't add duplicate type rule.
		 * A warning should have been previously given if there is a
		 * non-duplicate rule using the same key.
		 */
		goto exit;
	}

	if (!cond_node) {
		rc = avtab_insert(&pdb->te_avtab, &avtab_key, &avtab_datum);
	} else {
		existing = avtab_search_node(&pdb->te_cond_avtab, &avtab_key);
		if (existing) {
			cond_av_list_t *cond_list;
			avtab_datum_t *search_datum;

			if (cond_flavor == CIL_CONDTRUE) {
				cond_list = cond_node->true_list;
			} else {
				cond_list = cond_node->false_list;
			}

			search_datum = cil_cond_av_list_search(&avtab_key, cond_list);
			if (search_datum) {
				/* Don't add duplicate type rule.
				 * A warning should have been previously given if there is a
				 * non-duplicate rule using the same key.
				 */
				goto exit;
			}
		}
		rc = __cil_cond_insert_rule(&pdb->te_cond_avtab, &avtab_key, &avtab_datum, cond_node, cond_flavor);
	}

exit:
	return rc;
}

int __cil_type_rule_to_avtab(policydb_t *pdb, const struct cil_db *db, struct cil_type_rule *cil_rule, cond_node_t *cond_node, enum cil_flavor cond_flavor)
{
	int rc = SEPOL_ERR;
	uint16_t kind = cil_rule->rule_kind;
	type_datum_t *sepol_src = NULL;
	type_datum_t *sepol_tgt = NULL;
	class_datum_t *sepol_obj = NULL;
	type_datum_t *sepol_result = NULL;
	ebitmap_t src_bitmap, tgt_bitmap;
	ebitmap_node_t *node1, *node2;
	unsigned int i, j;

	rc = __cil_expand_type(cil_rule->src, &src_bitmap);
	if (rc != SEPOL_OK) goto exit;

	rc = __cil_expand_type(cil_rule->tgt, &tgt_bitmap);
	if (rc != SEPOL_OK) goto exit;

	rc = __cil_get_sepol_class_datum(pdb, DATUM(cil_rule->obj), &sepol_obj);
	if (rc != SEPOL_OK) goto exit;

	rc = __cil_get_sepol_type_datum(pdb, DATUM(cil_rule->result), &sepol_result);
	if (rc != SEPOL_OK) goto exit;

	ebitmap_for_each_bit(&src_bitmap, node1, i) {
		if (!ebitmap_get_bit(&src_bitmap, i)) continue;

		rc = __cil_get_sepol_type_datum(pdb, DATUM(db->val_to_type[i]), &sepol_src);
		if (rc != SEPOL_OK) goto exit;

		ebitmap_for_each_bit(&tgt_bitmap, node2, j) {
			if (!ebitmap_get_bit(&tgt_bitmap, j)) continue;

			rc = __cil_get_sepol_type_datum(pdb, DATUM(db->val_to_type[j]), &sepol_tgt);
			if (rc != SEPOL_OK) goto exit;

			rc = __cil_insert_type_rule(pdb, kind, sepol_src->s.value, sepol_tgt->s.value, sepol_obj->s.value, sepol_result->s.value, cond_node, cond_flavor);
			if (rc != SEPOL_OK) {
				goto exit;
			}
		}
	}

	rc = SEPOL_OK;

exit:
	ebitmap_destroy(&src_bitmap);
	ebitmap_destroy(&tgt_bitmap);
	return rc;
}

int cil_type_rule_to_policydb(policydb_t *pdb, const struct cil_db *db, struct cil_type_rule *cil_rule)
{
	return  __cil_type_rule_to_avtab(pdb, db, cil_rule, NULL, CIL_FALSE);
}

int __cil_typetransition_to_avtab(policydb_t *pdb, const struct cil_db *db, struct cil_nametypetransition *typetrans, cond_node_t *cond_node, enum cil_flavor cond_flavor)
{
	int rc = SEPOL_ERR;
	type_datum_t *sepol_src = NULL;
	type_datum_t *sepol_tgt = NULL;
	class_datum_t *sepol_obj = NULL;
	type_datum_t *sepol_result = NULL;
	filename_trans_t *sepol_nametypetrans = NULL;
	ebitmap_t src_bitmap, tgt_bitmap;
	ebitmap_node_t *node1, *node2;
	unsigned int i, j;
	char *name = DATUM(typetrans->name)->name;

	if (!strcmp(name, "*")) {
		struct cil_type_rule trans;
		trans.rule_kind = CIL_TYPE_TRANSITION;
		trans.src = typetrans->src;
		trans.tgt = typetrans->tgt;
		trans.obj = typetrans->obj;
		trans.result = typetrans->result;
		return __cil_type_rule_to_avtab(pdb, db, &trans, cond_node, cond_flavor);
	}

	rc = __cil_expand_type(typetrans->src, &src_bitmap);
	if (rc != SEPOL_OK) goto exit;

	rc = __cil_expand_type(typetrans->tgt, &tgt_bitmap);
	if (rc != SEPOL_OK) goto exit;

	rc = __cil_get_sepol_class_datum(pdb, DATUM(typetrans->obj), &sepol_obj);
	if (rc != SEPOL_OK) goto exit;

	rc = __cil_get_sepol_type_datum(pdb, DATUM(typetrans->result), &sepol_result);
	if (rc != SEPOL_OK) goto exit;

	ebitmap_for_each_bit(&src_bitmap, node1, i) {
		if (!ebitmap_get_bit(&src_bitmap, i)) continue;

		rc = __cil_get_sepol_type_datum(pdb, DATUM(db->val_to_type[i]), &sepol_src);
		if (rc != SEPOL_OK) goto exit;

		ebitmap_for_each_bit(&tgt_bitmap, node2, j) {
			if (!ebitmap_get_bit(&tgt_bitmap, j)) continue;

			rc = __cil_get_sepol_type_datum(pdb, DATUM(db->val_to_type[j]), &sepol_tgt);
			if (rc != SEPOL_OK) goto exit;

			sepol_nametypetrans = cil_malloc(sizeof(*sepol_nametypetrans));
			memset(sepol_nametypetrans, 0, sizeof(filename_trans_t));
			sepol_nametypetrans->stype = sepol_src->s.value;
			sepol_nametypetrans->ttype = sepol_tgt->s.value;
			sepol_nametypetrans->tclass = sepol_obj->s.value;
			sepol_nametypetrans->otype = sepol_result->s.value;
			sepol_nametypetrans->name = cil_strdup(name);

			sepol_nametypetrans->next = pdb->filename_trans;
			pdb->filename_trans = sepol_nametypetrans;
		}
	}

	rc = SEPOL_OK;

exit:
	ebitmap_destroy(&src_bitmap);
	ebitmap_destroy(&tgt_bitmap);
	return rc;
}

int cil_typetransition_to_policydb(policydb_t *pdb, const struct cil_db *db, struct cil_nametypetransition *typetrans)
{
	return  __cil_typetransition_to_avtab(pdb, db, typetrans, NULL, CIL_FALSE);
}

int __cil_perms_to_datum(struct cil_list *perms, class_datum_t *sepol_class, uint32_t *datum)
{
	int rc = SEPOL_ERR;
	char *key = NULL;
	struct cil_list_item *curr_perm;
	struct cil_perm *cil_perm;
	uint32_t data = 0;

	cil_list_for_each(curr_perm, perms) {
		perm_datum_t *sepol_perm;
		cil_perm = curr_perm->data;
		key = cil_perm->datum.name;
		sepol_perm = hashtab_search(sepol_class->permissions.table, key);
		if (sepol_perm == NULL) {
			common_datum_t *sepol_common = sepol_class->comdatum;
			sepol_perm = hashtab_search(sepol_common->permissions.table, key);
			if (sepol_perm == NULL) {
				cil_log(CIL_ERR, "Failed to find datum for perm %s\n", key);
				rc = SEPOL_ERR;
				goto exit;
			}
		}
		data |= 1 << (sepol_perm->s.value - 1);
	}

	*datum = data;

	return SEPOL_OK;

exit:
	return rc;
}

int __cil_insert_avrule(policydb_t *pdb, uint32_t kind, uint32_t src, uint32_t tgt, uint32_t obj, uint32_t data, cond_node_t *cond_node, enum cil_flavor cond_flavor)
{
	int rc = SEPOL_OK;
	avtab_key_t avtab_key;
	avtab_datum_t avtab_datum;
	avtab_datum_t *avtab_dup = NULL;

	avtab_key.source_type = src;
	avtab_key.target_type = tgt;
	avtab_key.target_class = obj;
	
	switch (kind) {
	case CIL_AVRULE_ALLOWED:
		avtab_key.specified = AVTAB_ALLOWED;
		break;
	case CIL_AVRULE_AUDITALLOW:
		avtab_key.specified = AVTAB_AUDITALLOW;
		break;
	case CIL_AVRULE_DONTAUDIT:
		avtab_key.specified = AVTAB_AUDITDENY;
		break;
	default:
		rc = SEPOL_ERR;
		goto exit;
		break;
	}

	if (!cond_node) {
		avtab_dup = avtab_search(&pdb->te_avtab, &avtab_key);
		if (!avtab_dup) {
			avtab_datum.data = data;
			rc = avtab_insert(&pdb->te_avtab, &avtab_key, &avtab_datum);
		} else {
			if (kind == CIL_AVRULE_DONTAUDIT)
				avtab_dup->data &= data;
			else
				avtab_dup->data |= data;
		}
	} else {
		avtab_datum.data = data;
		rc = __cil_cond_insert_rule(&pdb->te_cond_avtab, &avtab_key, &avtab_datum, cond_node, cond_flavor);
	}

exit:
	return rc;
}

static void __cil_neverallow_handle(struct cil_list *neverallows, struct cil_symtab_datum *src, struct cil_symtab_datum *tgt, uint32_t class, uint32_t perms)
{
	struct cil_neverallow *neverallow = neverallows->head->data;
	struct cil_list *neverallow_rules = neverallow->rules;
	struct cil_neverallow_rule *new = NULL;

	new = cil_malloc(sizeof(*new));
	new->src = src;
	new->tgt = tgt;
	new->class = class;
	new->perms = perms;

	cil_list_append(neverallow_rules, CIL_LIST_ITEM, new);
}

static int __cil_is_type_match(enum cil_flavor f1, struct cil_symtab_datum *t1, enum cil_flavor f2, struct cil_symtab_datum *t2)
{
	if (strcmp(t1->name, t2->name) == 0) {
		return CIL_TRUE;
	} else if (f1 == CIL_TYPEATTRIBUTE && f2 != CIL_TYPEATTRIBUTE) {
		struct cil_typeattribute *a = (struct cil_typeattribute *)t1;
		struct cil_type *t = (struct cil_type *)t2;
		if (ebitmap_get_bit(a->types, t->value)) {
			return CIL_TRUE;
		}
	} else if (f1 != CIL_TYPEATTRIBUTE && f2 == CIL_TYPEATTRIBUTE) {
		struct cil_typeattribute *a = (struct cil_typeattribute *)t2;
		struct cil_type *t = (struct cil_type *)t1;
		if (ebitmap_get_bit(a->types, t->value)) {
			return CIL_TRUE;
		}
	} else if (f1 == CIL_TYPEATTRIBUTE && f2 == CIL_TYPEATTRIBUTE) {
		struct cil_typeattribute *a1 = (struct cil_typeattribute *)t2;
		struct cil_typeattribute *a2 = (struct cil_typeattribute *)t1;
		/* abusing the ebitmap abstraction for speed */
		ebitmap_node_t *n1 = a1->types->node;
		ebitmap_node_t *n2 = a2->types->node;
		while (n1 && n2) {
			if (n1->startbit < n2->startbit) {
				n1 = n1->next;
			} else if (n2->startbit < n1->startbit) {
				n2 = n2->next;
			} else {
				if (n1->map & n2->map) {
					return CIL_TRUE;
				}
				n1 = n1->next;
				n2 = n2->next;
			}
		}
	}
	return CIL_FALSE;
}

static int __cil_check_neverallows(struct cil_list *neverallows, struct cil_symtab_datum *src, struct cil_symtab_datum *tgt, uint32_t class, uint32_t perms)
{
	struct cil_list_item *curr = NULL;
	enum cil_flavor al_src_flavor = ((struct cil_tree_node*)src->nodes->head->data)->flavor;
	enum cil_flavor al_tgt_flavor = ((struct cil_tree_node*)tgt->nodes->head->data)->flavor;
	cil_list_for_each(curr, neverallows) {
		struct cil_neverallow *neverallow = curr->data;
		struct cil_tree_node *node = neverallow->node;
		struct cil_list_item *curr_item = NULL;
		cil_list_for_each(curr_item, neverallow->rules) {
			struct cil_neverallow_rule *curr_rule = curr_item->data;
			enum cil_flavor nv_src_flavor = ((struct cil_tree_node*)curr_rule->src->nodes->head->data)->flavor;
			enum cil_flavor nv_tgt_flavor = ((struct cil_tree_node*)curr_rule->tgt->nodes->head->data)->flavor;
			if ((curr_rule->perms & perms) && (class == curr_rule->class)) {
				int src_match = __cil_is_type_match(al_src_flavor, src, nv_src_flavor, curr_rule->src);
				if (src_match) {
					int tgt_match = __cil_is_type_match(al_tgt_flavor, tgt, nv_tgt_flavor, curr_rule->tgt);
					if (tgt_match) {
						cil_log(CIL_ERR, "Neverallow found that matches avrule at line %d of %s\n", node->line, node->path);
						return SEPOL_ERR;
					}
				}
			}
		}
	}
	return SEPOL_OK;
}

int __cil_avrule_expand_helper(policydb_t *pdb, uint16_t kind, struct cil_symtab_datum *src, struct cil_symtab_datum *tgt, struct cil_classperms *cp, struct cil_list *neverallows, cond_node_t *cond_node, enum cil_flavor cond_flavor)
{
	int rc = SEPOL_ERR;
	type_datum_t *sepol_src = NULL;
	type_datum_t *sepol_tgt = NULL;
	class_datum_t *sepol_class = NULL;
	uint32_t data = 0;

	rc = __cil_get_sepol_type_datum(pdb, src, &sepol_src);
	if (rc != SEPOL_OK) goto exit;

	rc = __cil_get_sepol_type_datum(pdb, tgt, &sepol_tgt);
	if (rc != SEPOL_OK) goto exit;

	rc = __cil_get_sepol_class_datum(pdb, DATUM(cp->r.cp.class), &sepol_class);
	if (rc != SEPOL_OK) goto exit;

	rc = __cil_perms_to_datum(cp->r.cp.perms, sepol_class, &data);
	if (rc != SEPOL_OK) goto exit;

	if (data == 0) {
		/* No permissions, so don't insert rule. Maybe should return an error? */
		return SEPOL_OK;
	}

	if (kind == CIL_AVRULE_NEVERALLOW) {
		__cil_neverallow_handle(neverallows, src, tgt, sepol_class->s.value, data);
	} else {
		if (kind == CIL_AVRULE_DONTAUDIT) {
			data = ~data;
		} else if (neverallows != NULL && kind == CIL_AVRULE_ALLOWED) {
			rc = __cil_check_neverallows(neverallows, src, tgt, sepol_class->s.value, data);
			if (rc != SEPOL_OK) {
				goto exit;
			}
		}

		rc = __cil_insert_avrule(pdb, kind, sepol_src->s.value, sepol_tgt->s.value, sepol_class->s.value, data, cond_node, cond_flavor);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	return rc;
}


int __cil_avrule_expand(policydb_t *pdb, uint16_t kind, struct cil_symtab_datum *src, struct cil_symtab_datum *tgt, struct cil_list *classperms, struct cil_list *neverallows, cond_node_t *cond_node, enum cil_flavor cond_flavor)
{
	int rc = SEPOL_ERR;
	struct cil_list_item *curr;

	cil_list_for_each(curr, classperms) {
		struct cil_classperms *cp = curr->data;
		if (cp->flavor == CIL_CLASSPERMSET) {
			struct cil_classpermset *cps = cp->r.classpermset;
			rc = __cil_avrule_expand(pdb, kind, src, tgt, cps->classperms, neverallows, cond_node, cond_flavor);
			if (rc != SEPOL_OK) {
				goto exit;
			}
		} else if (cp->flavor == CIL_MAP_CLASSPERMS) {
			struct cil_list_item *i = NULL;
			cil_list_for_each(i, cp->r.mcp.perms) {
				struct cil_map_perm *cmp = i->data;
				rc = __cil_avrule_expand(pdb, kind, src, tgt, cmp->classperms, neverallows, cond_node, cond_flavor);
			}
		} else { /* CIL_CLASSPERMS */
			rc = __cil_avrule_expand_helper(pdb, kind, src, tgt, cp, neverallows, cond_node, cond_flavor);
			if (rc != SEPOL_OK) {
				goto exit;
			}	
		}
	}

	return SEPOL_OK;

exit:
	return rc;
}

int __cil_avrule_to_avtab(policydb_t *pdb, const struct cil_db *db, struct cil_avrule *cil_avrule, struct cil_list *neverallows, cond_node_t *cond_node, enum cil_flavor cond_flavor)
{
	int rc = SEPOL_ERR;
	uint16_t kind = cil_avrule->rule_kind;
	struct cil_symtab_datum *src = NULL;
	struct cil_symtab_datum *tgt = NULL;
	struct cil_list *classperms = cil_avrule->classperms;

	if (cil_avrule->rule_kind == CIL_AVRULE_DONTAUDIT && db->disable_dontaudit == CIL_TRUE) {
		// Do not add dontaudit rules to binary
		rc = SEPOL_OK;
		goto exit;
	}

	if (cil_avrule->rule_kind == CIL_AVRULE_NEVERALLOW && db->disable_neverallow == CIL_TRUE) {
		// ignore neverallow rules
		rc = SEPOL_OK;
		goto exit;
	}

	src = cil_avrule->src;
	tgt = cil_avrule->tgt;

	if (!strcmp(tgt->name, CIL_KEY_SELF)) {
		ebitmap_t type_bitmap;
		ebitmap_node_t *tnode;
		unsigned int i;

		rc = __cil_expand_type(src, &type_bitmap);
		if (rc != SEPOL_OK) goto exit;

		ebitmap_for_each_bit(&type_bitmap, tnode, i) {
			if (!ebitmap_get_bit(&type_bitmap, i)) continue;

			src = DATUM(db->val_to_type[i]);
			rc = __cil_avrule_expand(pdb, kind, src, src, classperms, neverallows, cond_node, cond_flavor);
			if (rc != SEPOL_OK) {
				ebitmap_destroy(&type_bitmap);
				goto exit;
			}
		}
		ebitmap_destroy(&type_bitmap);
	} else {
		rc = __cil_avrule_expand(pdb, kind, src, tgt, classperms, neverallows, cond_node, cond_flavor);
		if (rc != SEPOL_OK) goto exit;
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_avrule_to_policydb(policydb_t *pdb, const struct cil_db *db, struct cil_avrule *cil_avrule, struct cil_list *neverallows)
{
	return __cil_avrule_to_avtab(pdb, db, cil_avrule, neverallows, NULL, CIL_FALSE);
}

int __cil_cond_to_policydb_helper(struct cil_tree_node *node, __attribute__((unused)) uint32_t *finished, void *extra_args)
{
	int rc;
	enum cil_flavor flavor;
	struct cil_args_booleanif *args = extra_args;
	const struct cil_db *db = args->db;
	policydb_t *pdb = args->pdb;
	cond_node_t *cond_node = args->cond_node;
	enum cil_flavor cond_flavor = args->cond_flavor;
	struct cil_type_rule *cil_type_rule;
	struct cil_avrule *cil_avrule;
	struct cil_nametypetransition *cil_typetrans;

	flavor = node->flavor;
	switch (flavor) {
	case CIL_NAMETYPETRANSITION:
		cil_typetrans = (struct cil_nametypetransition*)node->data;
		if (strcmp(DATUM(cil_typetrans->name)->name,"*") != 0) {
			cil_log(CIL_ERR, "typetransition with file name not allowed within a booleanif block.\n");
			cil_log(CIL_ERR,"Invalid typetransition statement at line %d of %s\n", 
			node->line, node->path);
			goto exit;
		}
		rc = __cil_typetransition_to_avtab(pdb, db, cil_typetrans, cond_node, cond_flavor);
		if (rc != SEPOL_OK) {
			cil_log(CIL_ERR, "Failed to insert type transition into avtab at line %d of %s\n", node->line, node->path);
			goto exit;
		}
		break;
	case CIL_TYPE_RULE:
		cil_type_rule = node->data;
		rc = __cil_type_rule_to_avtab(pdb, db, cil_type_rule, cond_node, cond_flavor);
		if (rc != SEPOL_OK) {
			cil_log(CIL_ERR, "Failed to insert typerule into avtab at line %d of %s\n", node->line, node->path);
			goto exit;
		}
		break;
	case CIL_AVRULE:
		cil_avrule = node->data;
		rc = __cil_avrule_to_avtab(pdb, db, cil_avrule, args->neverallows, cond_node, cond_flavor);
		if (rc != SEPOL_OK) {
			cil_log(CIL_ERR, "Failed to insert avrule into avtab at line %d of %s\n", node->line, node->path);
			goto exit;
		}
		break;
	case CIL_CALL:
	case CIL_TUNABLEIF:
		break;
	default:
		cil_log(CIL_ERR, "Invalid statement within booleanif at line %d of %s\n", 
			node->line, node->path);
		goto exit;
	}

	return SEPOL_OK;

exit:
	return SEPOL_ERR;
}

static int __cil_cond_expr_to_sepol_expr_helper(policydb_t *pdb, struct cil_list *cil_expr, cond_expr_t **head, cond_expr_t **tail);

static int __cil_cond_item_to_sepol_expr(policydb_t *pdb, struct cil_list_item *item, cond_expr_t **head, cond_expr_t **tail)
{
	if (item == NULL) {
		goto exit;
	} else if (item->flavor == CIL_DATUM) {
		char *key = DATUM(item->data)->name;
		cond_bool_datum_t *sepol_bool = hashtab_search(pdb->p_bools.table, key);
		if (sepol_bool == NULL) {
			cil_log(CIL_INFO, "Failed to find boolean\n");
			goto exit;
		}
		*head = cil_malloc(sizeof(cond_expr_t));
		(*head)->next = NULL;
		(*head)->expr_type = COND_BOOL;
		(*head)->bool = sepol_bool->s.value;
		*tail = *head;
	} else if (item->flavor == CIL_LIST) {
		struct cil_list *l = item->data;
		int rc = __cil_cond_expr_to_sepol_expr_helper(pdb, l, head, tail);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	} else {
		goto exit;
	}

	return SEPOL_OK;

exit:
	return SEPOL_ERR;
}

static int __cil_cond_expr_to_sepol_expr_helper(policydb_t *pdb, struct cil_list *cil_expr, cond_expr_t **head, cond_expr_t **tail)
{
	int rc = SEPOL_ERR;
	struct cil_list_item *item = cil_expr->head;
	enum cil_flavor flavor = cil_expr->flavor;
	cond_expr_t *op, *h1, *h2, *t1, *t2;

	if (flavor != CIL_BOOL) {
		cil_log(CIL_INFO, "Expected boolean expression\n");
		goto exit;
	}

	if (item == NULL) {
		goto exit;
	} else if (item->flavor == CIL_OP) {
		enum cil_flavor cil_op = (enum cil_flavor)item->data;

		op = cil_malloc(sizeof(*op));
		op->bool = 0;
		op->next = NULL;

		switch (cil_op) {
		case CIL_NOT:
			op->expr_type = COND_NOT;
			break;
		case CIL_OR:
			op->expr_type = COND_OR;
			break;
		case CIL_AND:
			op->expr_type = COND_AND;
			break;
		case CIL_XOR:
			op->expr_type = COND_XOR;
			break;
		case CIL_EQ:
			op->expr_type = COND_EQ;
			break;
		case CIL_NEQ:
			op->expr_type = COND_NEQ;
			break;
		default:
			goto exit;
		}

		rc = __cil_cond_item_to_sepol_expr(pdb, item->next, &h1, &t1);
		if (rc != SEPOL_OK) {
			cil_log(CIL_INFO, "Failed to get first operand of conditional expression\n");
			free(op);
			goto exit;
		}

		if (cil_op == CIL_NOT) {
			*head = h1;
			t1->next = op;
			*tail = op;
		} else {
			rc = __cil_cond_item_to_sepol_expr(pdb, item->next->next, &h2, &t2);
			if (rc != SEPOL_OK) {
				cil_log(CIL_INFO, "Failed to get second operand of conditional expression\n");
				free(op);
				cond_expr_destroy(h1);
				goto exit;
			}

			*head = h1;
			t1->next = h2;
			t2->next = op;
			*tail = op;
		}
	} else {
		rc = __cil_cond_item_to_sepol_expr(pdb, item, &h1, &t1);
		if (rc != SEPOL_OK) {
			cil_log(CIL_INFO, "Failed to get initial item in conditional list\n");
			goto exit;
		}
		*head = h1;
		for (item = item->next; item; item = item->next) {
			rc = __cil_cond_item_to_sepol_expr(pdb, item, &h2, &t2);
			if (rc != SEPOL_OK) {
				cil_log(CIL_INFO, "Failed to get item in conditional list\n");
				cond_expr_destroy(*head);
				goto exit;
			}
			op = cil_malloc(sizeof(*op));
			op->bool = 0;
			op->next = NULL;
			op->expr_type = COND_OR;
			t1->next = h2;
			t2->next = op;
			t1 = op;
		}
		*tail = t1;
	}

	return SEPOL_OK;

exit:
	return SEPOL_ERR;
}

static int __cil_cond_expr_to_sepol_expr(policydb_t *pdb, struct cil_list *cil_expr, cond_expr_t **sepol_expr)
{
	int rc;
	cond_expr_t *head, *tail;
	
	rc = __cil_cond_expr_to_sepol_expr_helper(pdb, cil_expr, &head, &tail);
	if (rc != SEPOL_OK) {
		return SEPOL_ERR;
	}
	*sepol_expr = head;

	return SEPOL_OK;
}

int cil_booleanif_to_policydb(policydb_t *pdb, const struct cil_db *db, struct cil_tree_node *node, struct cil_list *neverallows)
{
	int rc = SEPOL_ERR;
	struct cil_args_booleanif bool_args;
	struct cil_booleanif *cil_boolif = (struct cil_booleanif*)node->data;
	struct cil_tree_node *cb_node = node->cl_head;
	struct cil_tree_node *true_node = NULL;
	struct cil_tree_node *false_node = NULL;
	struct cil_tree_node *tmp_node = NULL;
	cond_node_t *tmp_cond = NULL;
	cond_node_t *cond_node = NULL;
	int was_created;
	int swapped = CIL_FALSE;
	cond_av_list_t tmp_cl;

	tmp_cond = cond_node_create(pdb, NULL);
	if (tmp_cond == NULL) {
		rc = SEPOL_ERR;
		cil_log(CIL_INFO, "Failed to create sepol conditional node at line %d of %s\n", 
			node->line, node->path);
		goto exit;
	}
	
	rc = __cil_cond_expr_to_sepol_expr(pdb, cil_boolif->datum_expr, &tmp_cond->expr);
	if (rc != SEPOL_OK) {
		cil_log(CIL_INFO, "Failed to convert CIL conditional expression to sepol expression at line %d of %s\n", node->line, node->path);
		goto exit;
	}

	tmp_cond->true_list = &tmp_cl;

	rc = cond_normalize_expr(pdb, tmp_cond);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	if (tmp_cond->false_list != NULL) {
		tmp_cond->true_list = NULL;
		swapped = CIL_TRUE;
	}

	cond_node = cond_node_find(pdb, tmp_cond, pdb->cond_list, &was_created);
	if (cond_node == NULL) {
		rc = SEPOL_ERR;
		goto exit;
	}

	if (was_created) {
		cond_node->next = pdb->cond_list;
		pdb->cond_list = cond_node;
	}

	cond_expr_destroy(tmp_cond->expr);
	free(tmp_cond);

	for (cb_node = node->cl_head; cb_node != NULL; cb_node = cb_node->next) {
		if (cb_node->flavor == CIL_CONDBLOCK) {
			struct cil_condblock *cb = cb_node->data;
			if (cb->flavor == CIL_CONDTRUE) {
					true_node = cb_node;
			} else if (cb->flavor == CIL_CONDFALSE) {
					false_node = cb_node;
			}
		}
	}

	if (swapped) {
		tmp_node = true_node;
		true_node = false_node;
		false_node = tmp_node;
	}

	bool_args.db = db;
	bool_args.pdb = pdb;
	bool_args.cond_node = cond_node;
	bool_args.neverallows = neverallows;

	if (true_node != NULL) {
		bool_args.cond_flavor = CIL_CONDTRUE;
		rc = cil_tree_walk(true_node, __cil_cond_to_policydb_helper, NULL, NULL, &bool_args);
		if (rc != SEPOL_OK) {
			cil_log(CIL_ERR, "Failure while walking true conditional block at line %d of %s\n", true_node->line, true_node->path);
			goto exit;
		}
	}

	if (false_node != NULL) {
		bool_args.cond_flavor = CIL_CONDFALSE;
		rc = cil_tree_walk(false_node, __cil_cond_to_policydb_helper, NULL, NULL, &bool_args);
		if (rc != SEPOL_OK) {
			cil_log(CIL_ERR, "Failure while walking false conditional block at line %d of %s\n", false_node->line, false_node->path);
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_roletrans_to_policydb(policydb_t *pdb, const struct cil_db *db, struct cil_roletransition *roletrans)
{
	int rc = SEPOL_ERR;
	role_datum_t *sepol_src = NULL;
	type_datum_t *sepol_tgt = NULL;
	class_datum_t *sepol_obj = NULL;
	role_datum_t *sepol_result = NULL;
	role_trans_t *sepol_roletrans = NULL;
	ebitmap_t role_bitmap, type_bitmap;
	ebitmap_node_t *rnode, *tnode;
	unsigned int i, j;

	rc = __cil_expand_role(DATUM(roletrans->src), &role_bitmap);
	if (rc != SEPOL_OK) goto exit;

	rc = __cil_expand_type(roletrans->tgt, &type_bitmap);
	if (rc != SEPOL_OK) goto exit;

	rc = __cil_get_sepol_class_datum(pdb, DATUM(roletrans->obj), &sepol_obj);
	if (rc != SEPOL_OK) goto exit;

	rc = __cil_get_sepol_role_datum(pdb, DATUM(roletrans->result), &sepol_result);
	if (rc != SEPOL_OK) goto exit;

	ebitmap_for_each_bit(&role_bitmap, rnode, i) {
		if (!ebitmap_get_bit(&role_bitmap, i)) continue;

		rc = __cil_get_sepol_role_datum(pdb, DATUM(db->val_to_role[i]), &sepol_src);
		if (rc != SEPOL_OK) goto exit;

		ebitmap_for_each_bit(&type_bitmap, tnode, j) {
			if (!ebitmap_get_bit(&type_bitmap, j)) continue;

			rc = __cil_get_sepol_type_datum(pdb, DATUM(db->val_to_type[j]), &sepol_tgt);
			if (rc != SEPOL_OK) goto exit;

			sepol_roletrans = cil_malloc(sizeof(*sepol_roletrans));
			memset(sepol_roletrans, 0, sizeof(role_trans_t));

			sepol_roletrans->role = sepol_src->s.value;
			sepol_roletrans->type = sepol_tgt->s.value;
			sepol_roletrans->tclass = sepol_obj->s.value;
			sepol_roletrans->new_role = sepol_result->s.value;

			sepol_roletrans->next = pdb->role_tr;
			pdb->role_tr = sepol_roletrans;
		}
	}

	rc = SEPOL_OK;

exit:
	ebitmap_destroy(&role_bitmap);
	ebitmap_destroy(&type_bitmap);
	return rc;
}

int cil_roleallow_to_policydb(policydb_t *pdb, const struct cil_db *db, struct cil_roleallow *roleallow)
{
	int rc = SEPOL_ERR;
	role_datum_t *sepol_src = NULL;
	role_datum_t *sepol_tgt = NULL;
	role_allow_t *sepol_roleallow = NULL;
	ebitmap_t src_bitmap, tgt_bitmap;
	ebitmap_node_t *node1, *node2;
	unsigned int i, j;

	rc = __cil_expand_role(roleallow->src, &src_bitmap);
	if (rc != SEPOL_OK) goto exit;

	rc = __cil_expand_role(roleallow->tgt, &tgt_bitmap);
	if (rc != SEPOL_OK) goto exit;

	ebitmap_for_each_bit(&src_bitmap, node1, i) {
		if (!ebitmap_get_bit(&src_bitmap, i)) continue;

		rc = __cil_get_sepol_role_datum(pdb, DATUM(db->val_to_role[i]), &sepol_src);
		if (rc != SEPOL_OK) goto exit;

		ebitmap_for_each_bit(&tgt_bitmap, node2, j) {
			if (!ebitmap_get_bit(&tgt_bitmap, j)) continue;

			rc = __cil_get_sepol_role_datum(pdb, DATUM(db->val_to_role[j]), &sepol_tgt);
			if (rc != SEPOL_OK) goto exit;

			sepol_roleallow = cil_malloc(sizeof(*sepol_roleallow));
			memset(sepol_roleallow, 0, sizeof(role_allow_t));
			sepol_roleallow->role = sepol_src->s.value;
			sepol_roleallow->new_role = sepol_tgt->s.value;

			sepol_roleallow->next = pdb->role_allow;
			pdb->role_allow = sepol_roleallow;
		}
	}

	rc = SEPOL_OK;

exit:
	ebitmap_destroy(&src_bitmap);
	ebitmap_destroy(&tgt_bitmap);
	return rc;
}

int __cil_constrain_expr_datum_to_sepol_expr(policydb_t *pdb, const struct cil_db *db, struct cil_list_item *item, enum cil_flavor expr_flavor, constraint_expr_t *expr)
{
	int rc = SEPOL_ERR;

	if (expr_flavor == CIL_USER) {
		user_datum_t *sepol_user = NULL;
		rc = __cil_get_sepol_user_datum(pdb, item->data, &sepol_user);
		if (rc != SEPOL_OK) goto exit;

		if (ebitmap_set_bit(&expr->names, sepol_user->s.value - 1, 1)) {
			goto exit;
		}
	} else if (expr_flavor == CIL_ROLE) {
		role_datum_t *sepol_role = NULL;
		ebitmap_t role_bitmap;
		ebitmap_node_t *rnode;
		unsigned int i;

		rc = __cil_expand_role(item->data, &role_bitmap);
		if (rc != SEPOL_OK) goto exit;

		ebitmap_for_each_bit(&role_bitmap, rnode, i) {
			if (!ebitmap_get_bit(&role_bitmap, i)) continue;

			rc = __cil_get_sepol_role_datum(pdb, DATUM(db->val_to_role[i]), &sepol_role);
			if (rc != SEPOL_OK) {
				ebitmap_destroy(&role_bitmap);
				goto exit;
			}

			if (ebitmap_set_bit(&expr->names, sepol_role->s.value - 1, 1)) {
				ebitmap_destroy(&role_bitmap);
				goto exit;
			}
		}
		ebitmap_destroy(&role_bitmap);
	} else if (expr_flavor == CIL_TYPE) {
		type_datum_t *sepol_type = NULL;
		ebitmap_t type_bitmap;
		ebitmap_node_t *tnode;
		unsigned int i;

		if (pdb->policyvers >= POLICYDB_VERSION_CONSTRAINT_NAMES) {
			rc = __cil_get_sepol_type_datum(pdb, item->data, &sepol_type);
			if (rc != SEPOL_OK) {
				ebitmap_destroy(&type_bitmap);
				goto exit;
			}

			if (ebitmap_set_bit(&expr->type_names->types, sepol_type->s.value - 1, 1)) {
				ebitmap_destroy(&type_bitmap);
				goto exit;
			}
		}

		rc = __cil_expand_type(item->data, &type_bitmap);
		if (rc != SEPOL_OK) goto exit;

		ebitmap_for_each_bit(&type_bitmap, tnode, i) {
			if (!ebitmap_get_bit(&type_bitmap, i)) continue;

			rc = __cil_get_sepol_type_datum(pdb, DATUM(db->val_to_type[i]), &sepol_type);
			if (rc != SEPOL_OK) {
				ebitmap_destroy(&type_bitmap);
				goto exit;
			}

			if (ebitmap_set_bit(&expr->names, sepol_type->s.value - 1, 1)) {
				ebitmap_destroy(&type_bitmap);
				goto exit;
			}
		}
		ebitmap_destroy(&type_bitmap);
	} else {
		goto exit;
	}

	return SEPOL_OK;

exit:
	return SEPOL_ERR;
}

int __cil_constrain_expr_leaf_to_sepol_expr(policydb_t *pdb, const struct cil_db *db, struct cil_list_item *op_item, enum cil_flavor expr_flavor, constraint_expr_t *expr)
{
	int rc = SEPOL_ERR;
	struct cil_list_item *l_item = op_item->next;
	struct cil_list_item *r_item = op_item->next->next;
	
	enum cil_flavor l_operand = (enum cil_flavor)l_item->data;

	switch (l_operand) {
	case CIL_CONS_U1:
		expr->attr = CEXPR_USER;
		break;
	case CIL_CONS_U2:
		expr->attr = CEXPR_USER | CEXPR_TARGET;
		break;
	case CIL_CONS_U3:
		expr->attr = CEXPR_USER | CEXPR_XTARGET;
		break;
	case CIL_CONS_R1:
		expr->attr = CEXPR_ROLE;
		break;
	case CIL_CONS_R2:
		expr->attr = CEXPR_ROLE | CEXPR_TARGET;
		break;
	case CIL_CONS_R3:
		expr->attr = CEXPR_ROLE | CEXPR_XTARGET;
		break;
	case CIL_CONS_T1:
		expr->attr = CEXPR_TYPE;
		break;
	case CIL_CONS_T2:
		expr->attr = CEXPR_TYPE | CEXPR_TARGET;
		break;
	case CIL_CONS_T3:
		expr->attr = CEXPR_TYPE | CEXPR_XTARGET;
		break;
	case CIL_CONS_L1: {
		enum cil_flavor r_operand = (enum cil_flavor)r_item->data;

		if (r_operand == CIL_CONS_L2) {
			expr->attr = CEXPR_L1L2;
		} else if (r_operand == CIL_CONS_H1) {
			expr->attr = CEXPR_L1H1;
		} else {
			expr->attr = CEXPR_L1H2;
		}
		break;
	}
	case CIL_CONS_L2:
		expr->attr = CEXPR_L2H2;
		break;
	case CIL_CONS_H1: {
		enum cil_flavor r_operand = (enum cil_flavor)r_item->data;
		if (r_operand == CIL_CONS_L2) {
			expr->attr = CEXPR_H1L2;
		} else {
			expr->attr = CEXPR_H1H2;
		}
		break;
	}
	default:
		goto exit;
		break;
	}

	if (r_item->flavor == CIL_CONS_OPERAND) {
		expr->expr_type = CEXPR_ATTR;
	} else {
		expr->expr_type = CEXPR_NAMES;
		if (r_item->flavor == CIL_DATUM) {
			rc = __cil_constrain_expr_datum_to_sepol_expr(pdb, db, r_item, expr_flavor, expr);
			if (rc != SEPOL_OK) {
				goto exit;
			}
		} else if (r_item->flavor == CIL_LIST) {
			struct cil_list *r_expr = r_item->data;
			struct cil_list_item *curr;
			cil_list_for_each(curr, r_expr) {
				rc = __cil_constrain_expr_datum_to_sepol_expr(pdb, db, curr, expr_flavor, expr);
				if (rc != SEPOL_OK) {
					goto exit;
				}
			}
		} else {
			rc = SEPOL_ERR;
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	return rc;
}

int __cil_constrain_expr_to_sepol_expr_helper(policydb_t *pdb, const struct cil_db *db, const struct cil_list *cil_expr, constraint_expr_t **head, constraint_expr_t **tail)
{
	int rc = SEPOL_ERR;
	struct cil_list_item *item;
	enum cil_flavor flavor;
	constraint_expr_t *op, *h1, *h2, *t1, *t2;
	int is_leaf = CIL_FALSE;

	if (cil_expr == NULL) {
		return SEPOL_ERR;
	}

	item = cil_expr->head;
	flavor = cil_expr->flavor;

	op = cil_malloc(sizeof(constraint_expr_t));
	rc = constraint_expr_init(op);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	enum cil_flavor cil_op = (enum cil_flavor)item->data;
	switch (cil_op) {
	case CIL_NOT:
		op->expr_type = CEXPR_NOT;
		break;
	case CIL_AND:
		op->expr_type = CEXPR_AND;
		break;
	case CIL_OR:
		op->expr_type = CEXPR_OR;
		break;
	case CIL_EQ:
		op->op = CEXPR_EQ;
		is_leaf = CIL_TRUE;
		break;
	case CIL_NEQ:
		op->op = CEXPR_NEQ;
		is_leaf = CIL_TRUE;
		break;
	case CIL_CONS_DOM:
		op->op = CEXPR_DOM;
		is_leaf = CIL_TRUE;
		break;
	case CIL_CONS_DOMBY:
		op->op = CEXPR_DOMBY;
		is_leaf = CIL_TRUE;
		break;
	case CIL_CONS_INCOMP:
		op->op = CEXPR_INCOMP;
		is_leaf = CIL_TRUE;
		break;
	default:
		goto exit;
	}

	if (is_leaf == CIL_TRUE) {
		rc = __cil_constrain_expr_leaf_to_sepol_expr(pdb, db, item, flavor, op);
		if (rc != SEPOL_OK) {
			goto exit;
		}
		*head = op;
		*tail = op;
	} else if (cil_op == CIL_NOT) {
		struct cil_list *l_expr = item->next->data;
		rc = __cil_constrain_expr_to_sepol_expr_helper(pdb, db, l_expr, &h1, &t1);
		if (rc != SEPOL_OK) {
			goto exit;
		}
		t1->next = op;
		*head = h1;
		*tail = op;
	} else {
		struct cil_list *l_expr = item->next->data;
		struct cil_list *r_expr = item->next->next->data;
		rc = __cil_constrain_expr_to_sepol_expr_helper(pdb, db, l_expr, &h1, &t1);
		if (rc != SEPOL_OK) {
			goto exit;
		}
		rc = __cil_constrain_expr_to_sepol_expr_helper(pdb, db, r_expr, &h2, &t2);
		if (rc != SEPOL_OK) {
			constraint_expr_destroy(h1);
			goto exit;
		}
		t1->next = h2;
		t2->next = op;
		*head = h1;
		*tail = op;
	}

	return SEPOL_OK;

exit:
	constraint_expr_destroy(op);
	return SEPOL_ERR;
}

int __cil_constrain_expr_to_sepol_expr(policydb_t *pdb, const struct cil_db *db, const struct cil_list *cil_expr, constraint_expr_t **sepol_expr)
{
	int rc;
	constraint_expr_t *head, *tail;

	rc = __cil_constrain_expr_to_sepol_expr_helper(pdb, db, cil_expr, &head, &tail);
	if (rc != SEPOL_OK) {
		return SEPOL_ERR;
	}

	*sepol_expr = head;

	return SEPOL_OK;
}

int cil_constrain_to_policydb_helper(policydb_t *pdb, const struct cil_db *db, struct cil_symtab_datum *class, struct cil_list *perms, struct cil_list *expr)
{
	int rc = SEPOL_ERR;
	constraint_node_t *sepol_constrain = NULL;
	constraint_expr_t *sepol_expr = NULL;
	class_datum_t *sepol_class = NULL;

	sepol_constrain = cil_malloc(sizeof(*sepol_constrain));
	memset(sepol_constrain, 0, sizeof(constraint_node_t));

	rc = __cil_get_sepol_class_datum(pdb, class, &sepol_class);
	if (rc != SEPOL_OK) goto exit;

	rc = __cil_perms_to_datum(perms, sepol_class, &sepol_constrain->permissions);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	rc = __cil_constrain_expr_to_sepol_expr(pdb, db, expr, &sepol_expr);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	sepol_constrain->expr = sepol_expr;
	sepol_constrain->next = sepol_class->constraints;
	sepol_class->constraints = sepol_constrain;

	return SEPOL_OK;

exit:
	free(sepol_constrain);
	return rc;
}

int cil_constrain_expand(policydb_t *pdb, const struct cil_db *db, struct cil_list *classperms, struct cil_list *expr)
{
	int rc = SEPOL_ERR;
	struct cil_list_item *curr;

	cil_list_for_each(curr, classperms) {
		struct cil_classperms *cp = curr->data;
		if (cp->flavor == CIL_CLASSPERMSET) {
			struct cil_classpermset *cps = cp->r.classpermset;
			rc = cil_constrain_expand(pdb, db, cps->classperms, expr);
			if (rc != SEPOL_OK) {
				goto exit;
			}
		} else if (cp->flavor == CIL_MAP_CLASSPERMS) {
			struct cil_list_item *i = NULL;
			cil_list_for_each(i, cp->r.mcp.perms) {
				struct cil_map_perm *cmp = i->data;
				rc = cil_constrain_expand(pdb, db, cmp->classperms, expr);
				if (rc != SEPOL_OK) {
					goto exit;
				}
			}
		} else { /*CIL_CLASSPERMS */
			rc = cil_constrain_to_policydb_helper(pdb, db, DATUM(cp->r.cp.class), cp->r.cp.perms, expr);
			if (rc != SEPOL_OK) {
				goto exit;
			}
		}
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_constrain_to_policydb(policydb_t *pdb, const struct cil_db *db, struct cil_constrain *cil_constrain)
{
	int rc = SEPOL_ERR;
	rc = cil_constrain_expand(pdb, db, cil_constrain->classperms, cil_constrain->datum_expr);
	if (rc != SEPOL_OK) {
		goto exit;
	}
	
	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Failed to insert constraint into policydb\n");
	return rc;
}

int cil_validatetrans_to_policydb(policydb_t *pdb, const struct cil_db *db, struct cil_validatetrans *cil_validatetrans)
{
	int rc = SEPOL_ERR;
	struct cil_list *expr = cil_validatetrans->datum_expr;
	class_datum_t *sepol_class = NULL;
	constraint_node_t *sepol_validatetrans = NULL;
	constraint_expr_t *sepol_expr = NULL;

	rc = __cil_get_sepol_class_datum(pdb, DATUM(cil_validatetrans->class), &sepol_class);
	if (rc != SEPOL_OK) goto exit;

	sepol_validatetrans = cil_malloc(sizeof(*sepol_validatetrans));
	memset(sepol_validatetrans, 0, sizeof(constraint_node_t));

	rc = __cil_constrain_expr_to_sepol_expr(pdb, db, expr, &sepol_expr);
	if (rc != SEPOL_OK) {
		goto exit;
	}
	sepol_validatetrans->expr = sepol_expr;

	sepol_validatetrans->next = sepol_class->validatetrans;
	sepol_class->validatetrans = sepol_validatetrans;

	return SEPOL_OK;

exit:
	free(sepol_validatetrans);
	return rc;
}

int __cil_cats_to_mls_level(policydb_t *pdb, struct cil_cats *cats, mls_level_t *mls_level)
{
	int rc = SEPOL_ERR;
	struct cil_list_item *i;
	cat_datum_t *sepol_cat = NULL;

	cil_list_for_each(i, cats->datum_expr) {
		struct cil_tree_node *node = DATUM(i->data)->nodes->head->data;
		if (node->flavor == CIL_CATSET) {
			struct cil_list_item *j;
			struct cil_catset *cs = i->data;
			cil_list_for_each(j, cs->cats->datum_expr) {
				rc = __cil_get_sepol_cat_datum(pdb, j->data, &sepol_cat);
				if (rc != SEPOL_OK) goto exit;

				rc = ebitmap_set_bit(&mls_level->cat, sepol_cat->s.value - 1, 1);
				if (rc != SEPOL_OK) goto exit;
			}
		} else {
			rc = __cil_get_sepol_cat_datum(pdb, i->data, &sepol_cat);
			if (rc != SEPOL_OK) goto exit;

			rc = ebitmap_set_bit(&mls_level->cat, sepol_cat->s.value - 1, 1);
			if (rc != SEPOL_OK) goto exit;
		}
	}

	return SEPOL_OK;

exit:
	return SEPOL_ERR;
}

int cil_sepol_level_define(policydb_t *pdb, struct cil_sens *cil_sens)
{
	int rc = SEPOL_ERR;
	struct cil_list_item *curr;
	level_datum_t *sepol_level = NULL;
	mls_level_t *mls_level = NULL;

	rc = __cil_get_sepol_level_datum(pdb, DATUM(cil_sens), &sepol_level);
	if (rc != SEPOL_OK) goto exit;

	mls_level = sepol_level->level;

	ebitmap_init(&mls_level->cat);

	cil_list_for_each(curr, cil_sens->cats_list) {
		struct cil_cats *cats = curr->data;
		rc = __cil_cats_to_mls_level(pdb, cats, mls_level);
		if (rc != SEPOL_OK) {
			cil_log(CIL_INFO, "Failed to insert category set into sepol mls level\n");
			goto exit;
		}
	}

	sepol_level->defined = 1;

	return SEPOL_OK;

exit:
	return rc;
}

int __cil_level_to_mls_level(policydb_t *pdb, struct cil_level *cil_level, mls_level_t *mls_level)
{
	int rc = SEPOL_ERR;
	struct cil_sens *cil_sens = cil_level->sens;
	struct cil_cats *cats = cil_level->cats;
	level_datum_t *sepol_level = NULL;

	rc = __cil_get_sepol_level_datum(pdb, DATUM(cil_sens), &sepol_level);
	if (rc != SEPOL_OK) goto exit;

	mls_level->sens = sepol_level->level->sens;

	ebitmap_init(&mls_level->cat);

	if (cats != NULL) {
		rc = __cil_cats_to_mls_level(pdb, cats, mls_level);
		if (rc != SEPOL_OK) {
			cil_log(CIL_INFO, "Failed to insert category set into sepol mls level\n");
			goto exit;
		}
	}

	rc = SEPOL_OK;
exit:
	return rc;
}

int __cil_levelrange_to_mls_range(policydb_t *pdb, struct cil_levelrange *cil_lvlrange, mls_range_t *mls_range)
{
	int rc = SEPOL_ERR;
	struct cil_level *low = cil_lvlrange->low;
	struct cil_level *high = cil_lvlrange->high;
	mls_level_t *mls_level = NULL;

	mls_level = &mls_range->level[0];

	rc = __cil_level_to_mls_level(pdb, low, mls_level);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	mls_level = &mls_range->level[1];

	rc = __cil_level_to_mls_level(pdb, high, mls_level);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_userlevel_userrange_to_policydb(policydb_t *pdb, struct cil_user *cil_user)
{
	int rc = SEPOL_ERR;
	struct cil_level *cil_level = cil_user->dftlevel;
	struct cil_levelrange *cil_levelrange = cil_user->range;
	user_datum_t *sepol_user = NULL;

	rc = __cil_get_sepol_user_datum(pdb, DATUM(cil_user), &sepol_user);
	if (rc != SEPOL_OK) goto exit;

	rc = __cil_level_to_mls_level(pdb, cil_level, &sepol_user->exp_dfltlevel);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	rc = __cil_levelrange_to_mls_range(pdb, cil_levelrange, &sepol_user->exp_range);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	return SEPOL_OK;

exit:
	return rc;
}

int __cil_context_to_sepol_context(policydb_t *pdb, struct cil_context *cil_context, context_struct_t *sepol_context)
{
	int rc = SEPOL_ERR;
	struct cil_levelrange *cil_lvlrange = cil_context->range;
	user_datum_t *sepol_user = NULL;
	role_datum_t *sepol_role = NULL;
	type_datum_t *sepol_type = NULL;

	rc = __cil_get_sepol_user_datum(pdb, DATUM(cil_context->user), &sepol_user);
	if (rc != SEPOL_OK) goto exit;

	rc = __cil_get_sepol_role_datum(pdb, DATUM(cil_context->role), &sepol_role);
	if (rc != SEPOL_OK) goto exit;

	rc = __cil_get_sepol_type_datum(pdb, DATUM(cil_context->type), &sepol_type);
	if (rc != SEPOL_OK) goto exit;

	sepol_context->user = sepol_user->s.value;
	sepol_context->role = sepol_role->s.value;
	sepol_context->type = sepol_type->s.value;

	if (pdb->mls == CIL_TRUE) {
		mls_context_init(sepol_context);

		rc = __cil_levelrange_to_mls_range(pdb, cil_lvlrange, &sepol_context->range);
		if (rc != SEPOL_OK) {
			cil_log(CIL_ERR,"Problem with MLS\n");
			mls_context_destroy(sepol_context);
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_sidorder_to_policydb(policydb_t *pdb, const struct cil_db *db)
{
	int rc = SEPOL_ERR;
	struct cil_list_item *curr;
	unsigned count = 0;

	if (db->sidorder == NULL || db->sidorder->head == NULL) {
		cil_log(CIL_WARN, "No sidorder statement in policy\n");
		return SEPOL_OK;
	}

	cil_list_for_each(curr, db->sidorder) {
		struct cil_sid *cil_sid = (struct cil_sid*)curr->data;
		struct cil_context *cil_context = cil_sid->context;

		if (cil_context != NULL) {
			ocontext_t *new_sepol_sidcon = cil_malloc(sizeof(*new_sepol_sidcon));
			memset(new_sepol_sidcon, 0, sizeof(ocontext_t));
			count++;
			new_sepol_sidcon->sid[0] = count;
			new_sepol_sidcon->u.name = cil_strdup(cil_sid->datum.name);
			rc = __cil_context_to_sepol_context(pdb, cil_context, &new_sepol_sidcon->context[0]);
			if (rc != SEPOL_OK) {
				cil_log(CIL_ERR,"Problem with context for SID %s\n",cil_sid->datum.name);
				free(new_sepol_sidcon->u.name);
				free(new_sepol_sidcon);
				goto exit;
			}
			new_sepol_sidcon->next = pdb->ocontexts[OCON_ISID];
			pdb->ocontexts[OCON_ISID] = new_sepol_sidcon;
		}
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_rangetransition_to_policydb(policydb_t *pdb, const struct cil_db *db, struct cil_rangetransition *rangetrans)
{
	int rc = SEPOL_ERR;
	type_datum_t *sepol_src = NULL;
	type_datum_t *sepol_tgt = NULL;
	class_datum_t *sepol_class = NULL;
	range_trans_t *new, *curr;
	ebitmap_t src_bitmap, tgt_bitmap;
	ebitmap_node_t *node1, *node2;
	unsigned int i, j;

	rc = __cil_expand_type(rangetrans->src, &src_bitmap);
	if (rc != SEPOL_OK) goto exit;

	rc = __cil_expand_type(rangetrans->exec, &tgt_bitmap);
	if (rc != SEPOL_OK) goto exit;

	rc = __cil_get_sepol_class_datum(pdb, DATUM(rangetrans->obj), &sepol_class);
	if (rc != SEPOL_OK) goto exit;

	ebitmap_for_each_bit(&src_bitmap, node1, i) {
		if (!ebitmap_get_bit(&src_bitmap, i)) continue;

		rc = __cil_get_sepol_type_datum(pdb, DATUM(db->val_to_type[i]), &sepol_src);
		if (rc != SEPOL_OK) goto exit;

		ebitmap_for_each_bit(&tgt_bitmap, node2, j) {
			if (!ebitmap_get_bit(&tgt_bitmap, j)) continue;

			rc = __cil_get_sepol_type_datum(pdb, DATUM(db->val_to_type[j]), &sepol_tgt);
			if (rc != SEPOL_OK) goto exit;

			new = cil_malloc(sizeof(*new));
			memset(new, 0, sizeof(range_trans_t));
			new->source_type = sepol_src->s.value;
			new->target_type = sepol_tgt->s.value;
			new->target_class = sepol_class->s.value;
			rc = __cil_levelrange_to_mls_range(pdb, rangetrans->range, &new->target_range);
			if (rc != SEPOL_OK) {
				free(new);
				goto exit;
			}

			curr = pdb->range_tr;
			while (curr != NULL) {
				if (curr->source_type == new->source_type &&
					curr->target_type == new->target_type &&
					curr->target_class == new->target_class) {
					if (mls_range_eq(&curr->target_range, &new->target_range)) {
						rc = SEPOL_OK;
						mls_range_destroy(&new->target_range);
						free(new);
						goto exit;
					}
					cil_log(CIL_INFO, "Conflicting Range transition rules\n");
					rc = SEPOL_ERR;
					mls_range_destroy(&new->target_range);
					free(new);
					goto exit;
				}
				curr = curr->next;
			}
			new->next = pdb->range_tr;
			pdb->range_tr = new;
		}
	}

	rc = SEPOL_OK;

exit:
	ebitmap_destroy(&src_bitmap);
	ebitmap_destroy(&tgt_bitmap);
	return rc;
}

int cil_portcon_to_policydb(policydb_t *pdb, struct cil_sort *portcons)
{
	int rc = SEPOL_ERR;
	uint32_t i = 0;
	struct cil_portcon *cil_portcon = NULL;
	struct cil_context *cil_context = NULL;
	ocontext_t *sepol_portcon = NULL;
	context_struct_t *sepol_context = NULL;

	for (i = 0; i < portcons->count; i++) {
		cil_portcon = portcons->array[i];
		cil_context = cil_portcon->context;

		sepol_portcon = cil_malloc(sizeof(*sepol_portcon));
		memset(sepol_portcon, 0, sizeof(ocontext_t));

		sepol_portcon->next = pdb->ocontexts[OCON_PORT];
		pdb->ocontexts[OCON_PORT] = sepol_portcon;

		switch (cil_portcon->proto) {
		case CIL_PROTOCOL_UDP:
			sepol_portcon->u.port.protocol = IPPROTO_UDP;
			break;
		case CIL_PROTOCOL_TCP:
			sepol_portcon->u.port.protocol = IPPROTO_TCP;
			break;
		default:
			/* should not get here */
			rc = SEPOL_ERR;
			goto exit;
		}

		sepol_portcon->u.port.low_port = cil_portcon->port_low;
		sepol_portcon->u.port.high_port = cil_portcon->port_high;

		sepol_context = &sepol_portcon->context[0];

		rc = __cil_context_to_sepol_context(pdb, cil_context, sepol_context);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	context_destroy(&sepol_portcon->context[0]);
	free(sepol_portcon);
	return rc;
}

int cil_netifcon_to_policydb(policydb_t *pdb, struct cil_sort *netifcons)
{
	int rc = SEPOL_ERR;
	uint32_t i = 0;
	struct cil_netifcon *cil_netifcon = NULL;
	struct cil_context *cil_context = NULL;
	ocontext_t *sepol_netifcon = NULL;
	context_struct_t *sepol_context = NULL;

	for (i = 0; i < netifcons->count; i++) {
		cil_netifcon = netifcons->array[i];

		sepol_netifcon = cil_malloc(sizeof(*sepol_netifcon));
		memset(sepol_netifcon, 0, sizeof(ocontext_t));

		sepol_netifcon->next = pdb->ocontexts[OCON_NETIF];
		pdb->ocontexts[OCON_NETIF] = sepol_netifcon;

		sepol_netifcon->u.name = cil_strdup(cil_netifcon->interface_str);

		cil_context = cil_netifcon->if_context;
		sepol_context = &sepol_netifcon->context[0];

		rc = __cil_context_to_sepol_context(pdb, cil_context, sepol_context);
		if (rc != SEPOL_OK) {
			goto exit;
		}

		cil_context = cil_netifcon->packet_context;
		sepol_context = &sepol_netifcon->context[1];

		rc = __cil_context_to_sepol_context(pdb, cil_context, sepol_context);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	free(sepol_netifcon->u.name);
	context_destroy(&sepol_netifcon->context[0]);
	free(sepol_netifcon);
	return rc;
}

int cil_nodecon_to_policydb(policydb_t *pdb, struct cil_sort *nodecons)
{
	int rc = SEPOL_ERR;
	uint32_t i = 0;
	struct cil_nodecon *cil_nodecon = NULL;
	struct cil_ipaddr *cil_addr = NULL;
	struct cil_ipaddr *cil_mask = NULL;
	struct cil_context *cil_context = NULL;
	ocontext_t *sepol_nodecon = NULL;
	context_struct_t *sepol_context = NULL;

	for (i = 0; i < nodecons->count; i++) {
		cil_nodecon = nodecons->array[i];
		cil_addr = cil_nodecon->addr;
		cil_mask = cil_nodecon->mask;
		cil_context = cil_nodecon->context;

		sepol_nodecon = cil_malloc(sizeof(*sepol_nodecon));
		memset(sepol_nodecon, 0, sizeof(ocontext_t));

		if (cil_addr->family == AF_INET) {
			sepol_nodecon->next = pdb->ocontexts[OCON_NODE];
			pdb->ocontexts[OCON_NODE] = sepol_nodecon;
			sepol_nodecon->u.node.addr = cil_addr->ip.v4.s_addr;
			sepol_nodecon->u.node.mask = cil_mask->ip.v4.s_addr;
		} else if (cil_addr->family == AF_INET6) {
			sepol_nodecon->next = pdb->ocontexts[OCON_NODE6];
			pdb->ocontexts[OCON_NODE6] = sepol_nodecon;
			memcpy(sepol_nodecon->u.node6.addr, &cil_addr->ip.v6.s6_addr32[0], 16);
			memcpy(sepol_nodecon->u.node6.mask, &cil_mask->ip.v6.s6_addr32[0], 16);
		} else {
			/* should not get here */
			rc = SEPOL_ERR;
			goto exit;
		}

		sepol_context = &sepol_nodecon->context[0];

		rc = __cil_context_to_sepol_context(pdb, cil_context, sepol_context);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	free(sepol_nodecon->u.name);
	context_destroy(&sepol_nodecon->context[0]);
	free(sepol_nodecon);
	return rc;
}

int cil_fsuse_to_policydb(policydb_t *pdb, struct cil_sort *fsuses)
{
	int rc = SEPOL_ERR;
	uint32_t i = 0;
	struct cil_fsuse *cil_fsuse = NULL;
	struct cil_context *cil_context = NULL;
	ocontext_t *sepol_fsuse = NULL;
	context_struct_t *sepol_context = NULL;

	for (i = 0; i < fsuses->count; i++) {
		cil_fsuse = fsuses->array[i];
		cil_context = cil_fsuse->context;

		sepol_fsuse = cil_malloc(sizeof(*sepol_fsuse));
		memset(sepol_fsuse, 0, sizeof(ocontext_t));

		sepol_fsuse->next = pdb->ocontexts[OCON_FSUSE];
		pdb->ocontexts[OCON_FSUSE] = sepol_fsuse;

		sepol_fsuse->u.name = cil_strdup(cil_fsuse->fs_str);
		sepol_fsuse->v.behavior = cil_fsuse->type;

		sepol_context = &sepol_fsuse->context[0];

		rc = __cil_context_to_sepol_context(pdb, cil_context, sepol_context);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	context_destroy(&sepol_fsuse->context[0]);
	free(sepol_fsuse);
	return rc;
}

int cil_genfscon_to_policydb(policydb_t *pdb, struct cil_sort *genfscons)
{
	int rc = SEPOL_ERR;
	uint32_t i = 0;
	struct cil_genfscon *cil_genfscon = NULL;
	struct cil_context *cil_context = NULL;
	genfs_t *sepol_genfs = NULL;
	ocontext_t *sepol_genfscon = NULL;
	context_struct_t *sepol_context = NULL;

	for (i = 0; i < genfscons->count; i++) {
		cil_genfscon = genfscons->array[i];
		cil_context = cil_genfscon->context;

		sepol_genfscon = cil_malloc(sizeof(*sepol_genfscon));
		memset(sepol_genfscon, 0, sizeof(ocontext_t));

		if (pdb->genfs == NULL) {
			sepol_genfs = cil_malloc(sizeof(*sepol_genfs));
			memset(sepol_genfs, 0, sizeof(genfs_t));

			pdb->genfs = sepol_genfs;
			sepol_genfs->fstype = cil_strdup(cil_genfscon->fs_str);
			sepol_genfs->head = sepol_genfscon;
		} else if (strcmp(pdb->genfs->fstype, cil_genfscon->fs_str)) {
			genfs_t *new_sepol_genfs = NULL;
			new_sepol_genfs = cil_malloc(sizeof(*new_sepol_genfs));
			memset(new_sepol_genfs, 0, sizeof(genfs_t));

			new_sepol_genfs->next = sepol_genfs;
			sepol_genfs = new_sepol_genfs;
			pdb->genfs = sepol_genfs;

			sepol_genfs->fstype = cil_strdup(cil_genfscon->fs_str);
			sepol_genfs->head = sepol_genfscon;
		} else {
			sepol_genfscon->next = sepol_genfs->head;
			sepol_genfs->head = sepol_genfscon;
		}

		sepol_genfscon->u.name = cil_strdup(cil_genfscon->path_str);
		sepol_context = &sepol_genfscon->context[0];

		rc = __cil_context_to_sepol_context(pdb, cil_context, sepol_context);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	context_destroy(&sepol_genfscon->context[0]);
	free(sepol_genfscon);
	return rc;
}

int cil_pirqcon_to_policydb(policydb_t *pdb, struct cil_sort *pirqcons)
{
	int rc = SEPOL_ERR;
	uint32_t i = 0;
	struct cil_pirqcon *cil_pirqcon = NULL;
	struct cil_context *cil_context = NULL;
	ocontext_t *sepol_pirqcon = NULL;
	context_struct_t *sepol_context = NULL;

	for (i = 0; i < pirqcons->count; i++) {
		cil_pirqcon = pirqcons->array[i];
		cil_context = cil_pirqcon->context;

		sepol_pirqcon = cil_malloc(sizeof(*sepol_pirqcon));
		memset(sepol_pirqcon, 0, sizeof(ocontext_t));

		sepol_pirqcon->next = pdb->ocontexts[OCON_XEN_PIRQ];
		pdb->ocontexts[OCON_XEN_PIRQ] = sepol_pirqcon;

		sepol_pirqcon->u.pirq = cil_pirqcon->pirq;

		sepol_context = &sepol_pirqcon->context[0];

		rc = __cil_context_to_sepol_context(pdb, cil_context, sepol_context);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	context_destroy(&sepol_pirqcon->context[0]);
	free(sepol_pirqcon);
	return rc;
}

int cil_iomemcon_to_policydb(policydb_t *pdb, struct cil_sort *iomemcons)
{
	int rc = SEPOL_ERR;
	uint32_t i = 0;
	struct cil_iomemcon *cil_iomemcon = NULL;
	struct cil_context *cil_context = NULL;
	ocontext_t *sepol_iomemcon = NULL;
	context_struct_t *sepol_context = NULL;

	for (i = 0; i < iomemcons->count; i++) {
		cil_iomemcon = iomemcons->array[i];
		cil_context = cil_iomemcon->context;

		sepol_iomemcon = cil_malloc(sizeof(*sepol_iomemcon));
		memset(sepol_iomemcon, 0, sizeof(ocontext_t));

		sepol_iomemcon->next = pdb->ocontexts[OCON_XEN_IOMEM];
		pdb->ocontexts[OCON_XEN_IOMEM] = sepol_iomemcon;

		sepol_iomemcon->u.iomem.low_iomem = cil_iomemcon->iomem_low;
		sepol_iomemcon->u.iomem.high_iomem = cil_iomemcon->iomem_high;

		sepol_context = &sepol_iomemcon->context[0];

		rc = __cil_context_to_sepol_context(pdb, cil_context, sepol_context);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	context_destroy(&sepol_iomemcon->context[0]);
	free(sepol_iomemcon);
	return rc;
}

int cil_ioportcon_to_policydb(policydb_t *pdb, struct cil_sort *ioportcons)
{
	int rc = SEPOL_ERR;
	uint32_t i = 0;
	struct cil_ioportcon *cil_ioportcon = NULL;
	struct cil_context *cil_context = NULL;
	ocontext_t *sepol_ioportcon = NULL;
	context_struct_t *sepol_context = NULL;

	for (i = 0; i < ioportcons->count; i++) {
		cil_ioportcon = ioportcons->array[i];
		cil_context = cil_ioportcon->context;

		sepol_ioportcon = cil_malloc(sizeof(*sepol_ioportcon));
		memset(sepol_ioportcon, 0, sizeof(ocontext_t));

		sepol_ioportcon->next = pdb->ocontexts[OCON_XEN_IOPORT];
		pdb->ocontexts[OCON_XEN_IOPORT] = sepol_ioportcon;

		sepol_ioportcon->u.ioport.low_ioport = cil_ioportcon->ioport_low;
		sepol_ioportcon->u.ioport.high_ioport = cil_ioportcon->ioport_high;

		sepol_context = &sepol_ioportcon->context[0];

		rc = __cil_context_to_sepol_context(pdb, cil_context, sepol_context);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	context_destroy(&sepol_ioportcon->context[0]);
	free(sepol_ioportcon);
	return rc;
}

int cil_pcidevicecon_to_policydb(policydb_t *pdb, struct cil_sort *pcidevicecons)
{
	int rc = SEPOL_ERR;
	uint32_t i = 0;
	struct cil_pcidevicecon *cil_pcidevicecon = NULL;
	struct cil_context *cil_context = NULL;
	ocontext_t *sepol_pcidevicecon = NULL;
	context_struct_t *sepol_context = NULL;

	for (i = 0; i < pcidevicecons->count; i++) {
		cil_pcidevicecon = pcidevicecons->array[i];
		cil_context = cil_pcidevicecon->context;

		sepol_pcidevicecon = cil_malloc(sizeof(*sepol_pcidevicecon));
		memset(sepol_pcidevicecon, 0, sizeof(ocontext_t));

		sepol_pcidevicecon->next = pdb->ocontexts[OCON_XEN_PCIDEVICE];
		pdb->ocontexts[OCON_XEN_PCIDEVICE] = sepol_pcidevicecon;

		sepol_pcidevicecon->u.device = cil_pcidevicecon->dev;

		sepol_context = &sepol_pcidevicecon->context[0];

		rc = __cil_context_to_sepol_context(pdb, cil_context, sepol_context);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	context_destroy(&sepol_pcidevicecon->context[0]);
	free(sepol_pcidevicecon);
	return rc;
}

int cil_default_to_policydb(policydb_t *pdb, struct cil_default *def)
{
	struct cil_list_item *curr;
	class_datum_t *sepol_class;

	cil_list_for_each(curr, def->class_datums) {
		char *key = DATUM(curr->data)->name;
		sepol_class = hashtab_search(pdb->p_classes.table, key);
		if (sepol_class == NULL) {
			goto exit;
		}
		switch (def->flavor) {
		case CIL_DEFAULTUSER:
			if (!sepol_class->default_user) { 
				sepol_class->default_user = def->object;
			} else {
				cil_log(CIL_ERR,"User default labeling for class %s already specified\n",key);
				goto exit;
			}
			break;
		case CIL_DEFAULTROLE:
			if (!sepol_class->default_role) { 
				sepol_class->default_role = def->object;
			} else {
				cil_log(CIL_ERR,"Role default labeling for class %s already specified\n",key);
				goto exit;
			}
			break;
		case CIL_DEFAULTTYPE:
			if (!sepol_class->default_type) { 
				sepol_class->default_type = def->object;
			} else {
				cil_log(CIL_ERR,"Type default labeling for class %s already specified\n",key);
				goto exit;
			}
			break;
		default:
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	return SEPOL_ERR;
}

int cil_defaultrange_to_policydb(policydb_t *pdb, struct cil_defaultrange *def)
{
	int rc = SEPOL_ERR;
	struct cil_list_item *curr;
	class_datum_t *sepol_class;

	cil_list_for_each(curr, def->class_datums) {
		rc = __cil_get_sepol_class_datum(pdb, DATUM(curr->data), &sepol_class);
		if (rc != SEPOL_OK) goto exit;

		if (!sepol_class->default_range) { 
			sepol_class->default_range = def->object_range;
		} else {
			cil_log(CIL_ERR,"Range default labeling for class %s already specified\n", DATUM(curr->data)->name);
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	return SEPOL_ERR;
}

int __cil_node_to_policydb(struct cil_tree_node *node, void *extra_args)
{
	int rc = SEPOL_OK;
	int pass;
	struct cil_args_binary *args = extra_args;
	const struct cil_db *db;
	policydb_t *pdb;

	db = args->db;
	pdb = args->pdb;
	pass = args->pass;

	if (node->flavor >= CIL_MIN_DECLARATIVE) {
		if (node != DATUM(node->data)->nodes->head->data) {
			goto exit;
		}
	}

	switch (pass) {
	case 1:
		switch (node->flavor) {
		case CIL_CLASS:
			rc = cil_class_to_policydb(pdb, node->data);
			break;
		case CIL_ROLE:
			rc = cil_role_to_policydb(pdb, node->data);
			break;
		case CIL_TYPE:
			rc = cil_type_to_policydb(pdb, node->data);
			break;
		case CIL_TYPEATTRIBUTE:
			rc = cil_typeattribute_to_policydb(pdb, node->data);
			break;
		case CIL_POLICYCAP:
			rc = cil_policycap_to_policydb(pdb, node->data);
			break;
		case CIL_USER:
			rc = cil_user_to_policydb(pdb, node->data);
			break;
		case CIL_BOOL:
			rc = cil_bool_to_policydb(pdb, node->data);
			break;
		case CIL_CATALIAS:
			if (pdb->mls == CIL_TRUE) {
				rc = cil_catalias_to_policydb(pdb, node->data);
			}
			break;
		case CIL_SENS:
			if (pdb->mls == CIL_TRUE) {
				rc = cil_sepol_level_define(pdb, node->data);
			}
			break;
		default:
			break;
		}
		break;
	case 2:
		switch (node->flavor) {
		case CIL_TYPE:
			rc = cil_type_bounds_to_policydb(pdb, node->data);
			break;
		case CIL_TYPEALIAS:
			rc = cil_typealias_to_policydb(pdb, node->data);
			break;
		case CIL_TYPEPERMISSIVE:
			rc = cil_typepermissive_to_policydb(pdb, node->data);
			break;
		case CIL_TYPEATTRIBUTE:
			rc = cil_typeattribute_to_bitmap(pdb, db, node->data);
			break;
		case CIL_SENSALIAS:
			if (pdb->mls == CIL_TRUE) {
				rc = cil_sensalias_to_policydb(pdb, node->data);
			}
			break;
		case CIL_ROLE:
			rc = cil_role_bounds_to_policydb(pdb, node->data);
			if (rc != SEPOL_OK) goto exit;
			rc = cil_roletype_to_policydb(pdb, db, node->data);
			break;
		case CIL_USER:
			rc = cil_user_bounds_to_policydb(pdb, node->data);
			if (rc != SEPOL_OK) goto exit;
			if (pdb->mls == CIL_TRUE) {
				rc = cil_userlevel_userrange_to_policydb(pdb, node->data);
			}
			break;
		case CIL_USERROLE:
			rc = cil_userrole_to_policydb(pdb, db, node->data);
			break;
		case CIL_TYPE_RULE:
			rc = cil_type_rule_to_policydb(pdb, db, node->data);
			break;
		case CIL_AVRULE: {
			struct cil_avrule *rule = node->data;
			struct cil_list *neverallows = args->neverallows;
			if (rule->rule_kind == CIL_AVRULE_NEVERALLOW) {
				struct cil_neverallow *new_rule = NULL;

				new_rule = cil_malloc(sizeof(*new_rule));
				cil_list_init(&new_rule->rules, CIL_LIST_ITEM);
				new_rule->node = node;

				cil_list_prepend(neverallows, CIL_LIST_ITEM, new_rule);

				rc = cil_avrule_to_policydb(pdb, db, node->data, neverallows);
			}
			break;
		}
		case CIL_ROLETRANSITION:
			rc = cil_roletrans_to_policydb(pdb, db, node->data);
			break;
		case CIL_ROLEATTRIBUTESET:
		  /*rc = cil_roleattributeset_to_policydb(pdb, node->data);*/
			break;
		case CIL_NAMETYPETRANSITION:
			rc = cil_typetransition_to_policydb(pdb, db, node->data);
			break;
		case CIL_CONSTRAIN:
			rc = cil_constrain_to_policydb(pdb, db, node->data);
			break;
		case CIL_MLSCONSTRAIN:
			if (pdb->mls == CIL_TRUE) {
				rc = cil_constrain_to_policydb(pdb, db, node->data);
			}
			break;
		case CIL_VALIDATETRANS:
			rc = cil_validatetrans_to_policydb(pdb, db, node->data);
			break;
		case CIL_MLSVALIDATETRANS:
			if (pdb->mls == CIL_TRUE) {
				rc = cil_validatetrans_to_policydb(pdb, db, node->data);
			}
			break;
		case CIL_RANGETRANSITION:
			if (pdb->mls == CIL_TRUE) {
				rc = cil_rangetransition_to_policydb(pdb, db, node->data);
			}
			break;
		case CIL_DEFAULTUSER:
		case CIL_DEFAULTROLE:
		case CIL_DEFAULTTYPE:
			rc = cil_default_to_policydb(pdb, node->data);
			break;
		case CIL_DEFAULTRANGE:
			rc = cil_defaultrange_to_policydb(pdb, node->data);
			break;
		default:
			break;
		}
		break;
	case 3:
		switch (node->flavor) {
		case CIL_BOOLEANIF:
			rc = cil_booleanif_to_policydb(pdb, db, node, args->neverallows);
			break;
		case CIL_AVRULE: {
				struct cil_avrule *rule = node->data;
				if (rule->rule_kind != CIL_AVRULE_NEVERALLOW) {
					rc = cil_avrule_to_policydb(pdb, db, node->data, args->neverallows);
				}
			}
			break;
		case CIL_ROLEALLOW:
			rc = cil_roleallow_to_policydb(pdb, db, node->data);
			break;
		default:
			break;
		}
	default:
		break;
	}

exit:
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Binary policy creation failed at line %d of %s\n", node->line, node->path);
	}
	return rc;
}

int __cil_binary_create_helper(struct cil_tree_node *node, __attribute__((unused)) uint32_t *finished, void *extra_args)
{
	int rc = SEPOL_ERR;

	if (node->flavor == CIL_BLOCK) {
		struct cil_block *blk = node->data;
		if (blk->is_abstract == CIL_TRUE) {
			*finished = CIL_TREE_SKIP_HEAD;
			rc = SEPOL_OK;
			goto exit;
		}
	} else if (node->flavor == CIL_OPTIONAL) {
		struct cil_optional *opt = node->data;
		if (opt->datum.state != CIL_STATE_ENABLED) {
			*finished = CIL_TREE_SKIP_HEAD;
			rc = SEPOL_OK;
			goto exit;
		}
	} else if (node->flavor == CIL_MACRO) {
		*finished = CIL_TREE_SKIP_HEAD;
		rc = SEPOL_OK;
		goto exit;
	} else if (node->flavor == CIL_BOOLEANIF) {
		*finished = CIL_TREE_SKIP_HEAD;
	}

	rc = __cil_node_to_policydb(node, extra_args);
	if (rc != SEPOL_OK) {
		goto exit;
	}

exit:
	return rc;
}

int __cil_contexts_to_policydb(policydb_t *pdb, const struct cil_db *db)
{
	int rc = SEPOL_ERR;

	rc = cil_portcon_to_policydb(pdb, db->portcon);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	rc = cil_netifcon_to_policydb(pdb, db->netifcon);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	rc = cil_nodecon_to_policydb(pdb, db->nodecon);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	rc = cil_fsuse_to_policydb(pdb, db->fsuse);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	rc = cil_genfscon_to_policydb(pdb, db->genfscon);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	if (pdb->target_platform == SEPOL_TARGET_XEN) {
		rc = cil_pirqcon_to_policydb(pdb, db->pirqcon);
		if (rc != SEPOL_OK) {
			goto exit;
		}

		rc = cil_iomemcon_to_policydb(pdb, db->iomemcon);
		if (rc != SEPOL_OK) {
			goto exit;
		}

		rc = cil_ioportcon_to_policydb(pdb, db->ioportcon);
		if (rc != SEPOL_OK) {
			goto exit;
		}

		rc = cil_pcidevicecon_to_policydb(pdb, db->pcidevicecon);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}
	return SEPOL_OK;
exit:
	return rc;
}

int __cil_common_val_array_insert(hashtab_key_t key, hashtab_datum_t datum, void *data)
{
	policydb_t *pdb = data;
	common_datum_t *common = (common_datum_t *)datum;

	if (common->s.value < 1 || common->s.value > pdb->p_commons.nprim) {
		return -EINVAL;
	}
	pdb->p_common_val_to_name[common->s.value - 1] = (char *)key;

	return 0;
}

int __cil_class_val_array_insert(hashtab_key_t key, hashtab_datum_t datum, void *data)
{
	policydb_t *pdb = data;
	class_datum_t *class = (class_datum_t *)datum;

	if (class->s.value < 1 || class->s.value > pdb->p_classes.nprim) {
		return -EINVAL;
	}
	pdb->p_class_val_to_name[class->s.value - 1] = (char *)key;
	pdb->class_val_to_struct[class->s.value - 1] = class;

	return 0;
}

int __cil_role_val_array_insert(hashtab_key_t key, hashtab_datum_t datum, void *data)
{
	policydb_t *pdb = data;
	role_datum_t *role = (role_datum_t *)datum;

	if (role->s.value < 1 || role->s.value > pdb->p_roles.nprim) {
		return -EINVAL;
	}
	pdb->p_role_val_to_name[role->s.value - 1] = (char *)key;
	pdb->role_val_to_struct[role->s.value - 1] = role;

	return 0;
}

int __cil_type_val_array_insert(hashtab_key_t key, hashtab_datum_t datum, void *data)
{
	policydb_t *pdb = data;
	type_datum_t *type = (type_datum_t *)datum;

	if (type->s.value < 1 || type->s.value > pdb->p_types.nprim) {
		return -EINVAL;
	}
	pdb->p_type_val_to_name[type->s.value - 1] = (char *)key;
	pdb->type_val_to_struct[type->s.value - 1] = type;

	return 0;
}

int __cil_user_val_array_insert(hashtab_key_t key, hashtab_datum_t datum, void *data)
{
	policydb_t *pdb = data;
	user_datum_t *user = (user_datum_t *)datum;

	if (user->s.value < 1 || user->s.value > pdb->p_users.nprim) {
		return -EINVAL;
	}
	pdb->p_user_val_to_name[user->s.value - 1] = (char *)key;
	pdb->user_val_to_struct[user->s.value - 1] = user;

	return 0;
}

int __cil_bool_val_array_insert(hashtab_key_t key, hashtab_datum_t datum, void *data)
{
	policydb_t *pdb = data;
	cond_bool_datum_t *bool = (cond_bool_datum_t *)datum;

	if (bool->s.value < 1 || bool->s.value > pdb->p_bools.nprim) {
		return -EINVAL;
	}
	pdb->p_bool_val_to_name[bool->s.value - 1] = (char *)key;
	pdb->bool_val_to_struct[bool->s.value - 1] = bool;

	return 0;
}

int __cil_level_val_array_insert(hashtab_key_t key, hashtab_datum_t datum, void *data)
{
	policydb_t *pdb = data;
	level_datum_t *level = (level_datum_t *)datum;

	if (level->level->sens < 1 || level->level->sens > pdb->p_levels.nprim) {
		return -EINVAL;
	}
	pdb->p_sens_val_to_name[level->level->sens - 1] = (char *)key;

	return 0;
}

int __cil_cat_val_array_insert(hashtab_key_t key, hashtab_datum_t datum, void *data)
{
	policydb_t *pdb = data;
	cat_datum_t *cat = (cat_datum_t *)datum;

	if (cat->s.value < 1 || cat->s.value > pdb->p_cats.nprim) {
		return -EINVAL;
	}
	pdb->p_cat_val_to_name[cat->s.value - 1] = (char *)key;

	return 0;
}

int __cil_policydb_val_arrays_create(policydb_t *policydb)
{
	int rc = SEPOL_ERR;

	policydb->p_common_val_to_name = cil_malloc(sizeof(char *) * policydb->p_commons.nprim);
	rc = hashtab_map(policydb->p_commons.table, &__cil_common_val_array_insert, policydb);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	policydb->p_class_val_to_name = cil_malloc(sizeof(char *) * policydb->p_classes.nprim);
	policydb->class_val_to_struct = cil_malloc(sizeof(class_datum_t *) * policydb->p_classes.nprim);
	rc = hashtab_map(policydb->p_classes.table, &__cil_class_val_array_insert, policydb);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	policydb->p_role_val_to_name = cil_malloc(sizeof(char *) * policydb->p_roles.nprim);
	policydb->role_val_to_struct = cil_malloc(sizeof(role_datum_t *) * policydb->p_roles.nprim);
	rc = hashtab_map(policydb->p_roles.table, &__cil_role_val_array_insert, policydb);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	policydb->p_type_val_to_name = cil_malloc(sizeof(char *) * policydb->p_types.nprim);
	policydb->type_val_to_struct = cil_malloc(sizeof(type_datum_t *) * policydb->p_types.nprim);
	rc = hashtab_map(policydb->p_types.table, &__cil_type_val_array_insert, policydb);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	policydb->p_user_val_to_name = cil_malloc(sizeof(char *) * policydb->p_users.nprim);
	policydb->user_val_to_struct = cil_malloc(sizeof(user_datum_t *) * policydb->p_users.nprim);
	rc = hashtab_map(policydb->p_users.table, &__cil_user_val_array_insert, policydb);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	policydb->p_bool_val_to_name = cil_malloc(sizeof(char *) * policydb->p_bools.nprim);
	policydb->bool_val_to_struct = cil_malloc(sizeof(cond_bool_datum_t *) * policydb->p_bools.nprim);
	rc = hashtab_map(policydb->p_bools.table, &__cil_bool_val_array_insert, policydb);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	policydb->p_sens_val_to_name = cil_malloc(sizeof(char *) * policydb->p_levels.nprim);
	rc = hashtab_map(policydb->p_levels.table, &__cil_level_val_array_insert, policydb);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	policydb->p_cat_val_to_name = cil_malloc(sizeof(char *) * policydb->p_cats.nprim);
	rc = hashtab_map(policydb->p_cats.table, &__cil_cat_val_array_insert, policydb);
	if (rc != SEPOL_OK) {
		goto exit;
	}

exit:
	return rc;
}

int __cil_policydb_init(policydb_t *pdb, const struct cil_db *db)
{
	int rc = SEPOL_ERR;

	if (pdb->mls == CIL_TRUE) {
		rc = cil_catorder_to_policydb(pdb, db);
		if (rc != SEPOL_OK) {
			goto exit;
		}

		rc = cil_sensitivityorder_to_policydb(pdb, db);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	rc = avtab_alloc(&pdb->te_avtab, MAX_AVTAB_SIZE);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	rc = avtab_alloc(&pdb->te_cond_avtab, MAX_AVTAB_SIZE);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_binary_create(const struct cil_db *db, sepol_policydb_t *policydb)
{
	int rc = SEPOL_ERR;
	int i;
	struct cil_args_binary extra_args;
	policydb_t *pdb = &policydb->p;
	struct cil_list *neverallows = NULL;

	if (db == NULL || policydb == NULL) {
		if (db == NULL) {
			cil_log(CIL_ERR,"db == NULL\n");
		} else if (policydb == NULL) {
			cil_log(CIL_ERR,"policydb == NULL\n");
		}
		return SEPOL_ERR;
	}

	rc = __cil_policydb_init(pdb, db);
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR,"Problem in policydb_init\n");
		return SEPOL_ERR;
	}

	cil_list_init(&neverallows, CIL_LIST_ITEM);

	extra_args.db = db;
	extra_args.pdb = pdb;
	extra_args.neverallows = neverallows;
	for (i = 1; i <= 3; i++) {
		extra_args.pass = i;

		rc = cil_tree_walk(db->ast->root, __cil_binary_create_helper, NULL, NULL, &extra_args);
		if (rc != SEPOL_OK) {
			cil_log(CIL_INFO, "Failure while walking cil database\n");
			goto exit;
		}

		if (i == 1) {
			rc = __cil_policydb_val_arrays_create(pdb);
			if (rc != SEPOL_OK) {
				cil_log(CIL_INFO, "Failure creating val_to_{struct,name} arrays\n");
				goto exit;
			}
		}
	}

	pdb->handle_unknown = db->handle_unknown;

	rc = cil_sidorder_to_policydb(pdb, db);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	rc = __cil_contexts_to_policydb(pdb, db);
	if (rc != SEPOL_OK) {
		cil_log(CIL_INFO, "Failure while inserting cil contexts into sepol policydb\n");
		goto exit;
	}

	if (pdb->type_attr_map == NULL) {
		rc = __cil_typeattr_bitmap_init(pdb);
		if (rc != SEPOL_OK) {
			cil_log(CIL_INFO, "Failure while initializing typeattribute bitmap\n");
			goto exit;
		}
	}

	rc = SEPOL_OK;
exit:
	cil_neverallows_list_destroy(neverallows);
	return rc;
}
