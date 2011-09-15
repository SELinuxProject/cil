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

	return SEPOL_OK;

exit:
	free(key);
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
		free(sepol_class);
		goto exit;
	}
	sepol_class->s.value = value;

	rc = symtab_init(&sepol_class->permissions, PERM_SYMTAB_SIZE);
	if (rc != SEPOL_OK) {
		goto exit;
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

int cil_classcommon_to_policydb(policydb_t *pdb, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	char *key = NULL;
	struct cil_class *cil_class = node->data;
	class_datum_t *sepol_class;
	common_datum_t *sepol_common;

	if (cil_class->common != NULL) {
		key = cil_class->datum.name;
		sepol_class = hashtab_search(pdb->p_classes.table, key);
		if (sepol_class == NULL) {
			goto exit;
		}

		key = cil_class->common->datum.name;
		sepol_common = hashtab_search(pdb->p_commons.table, key);
		if (sepol_common == NULL) {
			goto exit;
		}
		sepol_class->comdatum = sepol_common;
		sepol_class->comkey = cil_strdup(cil_class->common->datum.name);
		sepol_class->permissions.nprim += sepol_class->comdatum->permissions.nprim;
	}

	return SEPOL_OK;

exit:
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

int cil_roletype_to_policydb(policydb_t *pdb, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	char *key = NULL;
	struct cil_roletype *cil_roletype = node->data;
	role_datum_t *sepol_role = NULL;
	type_datum_t *sepol_type = NULL;

	key = ((struct cil_symtab_datum *)cil_roletype->role)->name;
	sepol_role = hashtab_search(pdb->p_roles.table, key);
	if (sepol_role == NULL) {
		goto exit;
	}

	key = ((struct cil_symtab_datum *)cil_roletype->type)->name;
	sepol_type = hashtab_search(pdb->p_types.table, key);
	if (sepol_type == NULL) {
		goto exit;
	}

	if (ebitmap_set_bit(&sepol_role->types.types, sepol_type->s.value - 1, 1)) {
		goto exit;
	}

	return SEPOL_OK;

exit:
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
		goto exit;
	}

	sepol_domed = hashtab_search(pdb->p_roles.table, cil_domed->datum.name);
	if (sepol_domed == NULL) {
		goto exit;
	}

	if (ebitmap_set_bit(&sepol_domed->dominates, sepol_doming->s.value - 1, 1)) {
		goto exit;
	}

	return SEPOL_OK;

exit:
        return rc;
}

int cil_rolebounds_to_policydb(policydb_t *pdb, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	char *key = NULL;
	struct cil_role *cil_role = node->data;
	role_datum_t *sepol_role;
	role_datum_t *sepol_rolebnds;

	if (cil_role->bounds != NULL) {
		key = cil_role->datum.name;
		sepol_role = hashtab_search(pdb->p_roles.table, key);
		if (sepol_role == NULL) {
			goto exit;
		}

		key = cil_role->bounds->datum.name;
		sepol_rolebnds = hashtab_search(pdb->p_roles.table, key);
		if (sepol_rolebnds == NULL) {
			goto exit;
		}
		sepol_role->bounds = sepol_rolebnds->s.value;
	}

        return SEPOL_OK;

exit:
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

int cil_typealias_to_policydb(policydb_t *pdb, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	char *key = NULL;
	struct cil_typealias *cil_alias = node->data;
	type_datum_t *sepol_type = NULL;
	type_datum_t *sepol_alias = cil_malloc(sizeof(*sepol_alias));
	type_datum_init(sepol_alias);

	key = ((struct cil_symtab_datum *)cil_alias->type)->name;
	sepol_type = hashtab_search(pdb->p_types.table, key);
	if (sepol_type == NULL) {
		rc = SEPOL_ERR;
		goto exit;
	}

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

int cil_typepermissive_to_policydb(policydb_t *pdb, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	uint32_t value = 0;
	char *key = NULL;
	struct cil_typepermissive *cil_typeperm = node->data;
	type_datum_t *sepol_type = NULL;

	key = ((struct cil_symtab_datum *)cil_typeperm->type)->name;
	sepol_type = hashtab_search(pdb->p_types.table, key);
	if (sepol_type == NULL) {
		rc = SEPOL_ERR;
		goto exit;
	}
	value = sepol_type->s.value;

	if (ebitmap_set_bit(&pdb->permissive_map, value, 1)) {
		goto exit;
	}

	return SEPOL_OK;

exit:
	type_datum_destroy(sepol_type);
	free(sepol_type);
	return rc;

}

int cil_typeattribute_to_policydb(policydb_t *pdb, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	uint32_t value = 0;
	char *key = NULL;
	struct cil_typeattribute *cil_attr = node->data;
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

int __cil_typeattr_expand_to_policydb(policydb_t *pdb, struct cil_typeattribute *attr, ebitmap_t *out);

int __cil_typeattr_expand_to_bitmap(policydb_t *pdb, struct cil_list *types, ebitmap_t *out)
{
	int rc = SEPOL_ERR;
	uint32_t value = 0;
	char *key = NULL;
	struct cil_list_item *curr_type = types->head;
	enum cil_flavor flavor;
	type_datum_t *sepol_type = NULL;

	while (curr_type != NULL) {
		flavor = curr_type->flavor;

		if (flavor == CIL_TYPEATTRIBUTE) {
			rc = __cil_typeattr_expand_to_policydb(pdb, curr_type->data, out);
			if (rc != SEPOL_OK) {
				goto exit;
			}
			curr_type = curr_type->next;
			continue;
		}

		key = ((struct cil_symtab_datum *)curr_type->data)->name;
		sepol_type = hashtab_search(pdb->p_types.table, key);
		if (sepol_type == NULL) {
			goto exit;
		}
		value = sepol_type->s.value;

		if (ebitmap_set_bit(out, value - 1, 1)) {
			goto exit;
		}

		curr_type = curr_type->next;
	}

	return SEPOL_OK;

exit:
	return rc;

}

int __cil_typeattr_expand_to_policydb(policydb_t *pdb, struct cil_typeattribute *attr, ebitmap_t *types)
{
	int rc = SEPOL_ERR;
	ebitmap_t negtypes;
	ebitmap_init(&negtypes);

	if (attr->types_list != NULL) {
		rc = __cil_typeattr_expand_to_bitmap(pdb, attr->types_list, types);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	} else {
		rc = SEPOL_OK;
		goto exit;
	}

	if (attr->neg_list != NULL) {
		rc = __cil_typeattr_expand_to_bitmap(pdb, attr->neg_list, &negtypes);
		if (rc != SEPOL_OK) {
			goto exit;
		}

		unsigned int i;
		ebitmap_node_t *tnode;
		ebitmap_for_each_bit(types, tnode, i) {
			if (ebitmap_get_bit(&negtypes, i)) {
				if (ebitmap_set_bit(types, i, 0)) {
					goto exit;
				}
			}
		}
	}

	rc = SEPOL_OK;

exit:
	ebitmap_destroy(&negtypes);
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

int cil_typeattribute_to_bitmap(policydb_t *pdb, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	uint32_t value = 0;
	char *key = NULL;
	struct cil_typeattribute *cil_attr = node->data;
	type_datum_t *sepol_type = NULL;
	ebitmap_node_t *tnode;
	unsigned int i;
	ebitmap_t types;
	
	ebitmap_init(&types);

	if (pdb->type_attr_map == NULL) {
		rc = __cil_typeattr_bitmap_init(pdb);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	key = cil_attr->datum.name;
	sepol_type = hashtab_search(pdb->p_types.table, key);
	if (sepol_type == NULL) {
		rc = SEPOL_ERR;
		goto exit;
	}
	value = sepol_type->s.value;

	rc = __cil_typeattr_expand_to_policydb(pdb, cil_attr, &types);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	ebitmap_for_each_bit(&types, tnode, i) {
		if (!ebitmap_get_bit(&types, i)) {
			continue;
		}

		ebitmap_set_bit(&pdb->type_attr_map[i], value - 1, 1);
	}

	rc = SEPOL_OK;

exit:
	ebitmap_destroy(&types);
	return rc;
}

int cil_policycap_to_policydb(policydb_t *pdb, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	int capnum;
	struct cil_policycap *cil_polcap = node->data;

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
		goto exit;
	}
	cil_role = cil_userrole->role;

	key = cil_role->datum.name;
	sepol_role = hashtab_search(pdb->p_roles.table, key);
	if (sepol_role == NULL) {
		goto exit;
	}
	value = sepol_role->s.value;

	if (ebitmap_set_bit(&sepol_user->roles.roles, value - 1, 1)) {
		goto exit;
	}

	return SEPOL_OK;

exit:
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
			goto exit;
		}
		sepol_cat->s.value = value;

		curr_cat = curr_cat->next;
	}

	return SEPOL_OK;

exit:
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

	key = cil_alias->cat->datum.name;
	sepol_cat = hashtab_search(pdb->p_cats.table, key);
	if (sepol_cat == NULL) {
		goto exit;
	}

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
			goto exit;
		}
		mls_level->sens = value;
		sepol_level->level = mls_level;

		curr = curr->next;
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

int cil_sensalias_to_policydb(policydb_t *pdb, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	char *key = NULL;
	struct cil_sensalias *cil_alias = node->data;
	mls_level_t *mls_level = NULL;
	level_datum_t *sepol_level = NULL;
	level_datum_t *sepol_alias = cil_malloc(sizeof(*sepol_alias));
	level_datum_init(sepol_alias);

	key = ((struct cil_symtab_datum *)cil_alias->sens)->name;
	sepol_level = hashtab_search(pdb->p_levels.table, key);
	if (sepol_level == NULL) {
		goto exit;
	}

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

int __cil_insert_type_rule(uint32_t kind, uint32_t src, uint32_t tgt, uint32_t obj, uint32_t res, avtab_t *avtab, avtab_ptr_t *avtab_ptr)
{
	int rc = SEPOL_ERR;
	avtab_key_t avtab_key;
	avtab_datum_t avtab_datum;
	
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

	*avtab_ptr = avtab_insert_nonunique(avtab, &avtab_key, &avtab_datum);
	if (*avtab_ptr == NULL) {
		rc = SEPOL_ERR;
		goto exit;
	}

	return SEPOL_OK;

exit:
	return rc;
}

int __cil_type_rule_to_avtab(policydb_t *pdb, struct cil_type_rule *cil_rule, avtab_t *avtab, avtab_ptr_t *avtab_ptr)
{
	int rc = SEPOL_ERR;
	char *key = NULL;
	uint16_t kind = cil_rule->rule_kind;
	type_datum_t *sepol_src = NULL;
	type_datum_t *sepol_tgt = NULL;
	type_datum_t *sepol_result = NULL;
	class_datum_t *sepol_obj = NULL;

	
	key = ((struct cil_symtab_datum *)cil_rule->src)->name;
	sepol_src = hashtab_search(pdb->p_types.table, key);
	if (sepol_src == NULL) {
		rc = SEPOL_ERR;
		goto exit;
	}
	
	key = ((struct cil_symtab_datum *)cil_rule->tgt)->name;
	sepol_tgt = hashtab_search(pdb->p_types.table, key);
	if (sepol_tgt == NULL) {
		rc = SEPOL_ERR;
		goto exit;
	}

	key = ((struct cil_symtab_datum *)cil_rule->obj)->name;
	sepol_obj = hashtab_search(pdb->p_classes.table, key);
	if (sepol_obj == NULL) {
		rc = SEPOL_ERR;
		goto exit;
	}

	key = ((struct cil_symtab_datum *)cil_rule->result)->name;
	sepol_result = hashtab_search(pdb->p_types.table, key);
	if (sepol_result == NULL) {
		rc = SEPOL_ERR;
		goto exit;
	}

	rc = __cil_insert_type_rule(kind, sepol_src->s.value, sepol_tgt->s.value, sepol_obj->s.value, sepol_result->s.value, avtab, avtab_ptr);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_type_rule_to_policydb(policydb_t *pdb, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	struct cil_type_rule *cil_rule = node->data;
	avtab_ptr_t avtab_ptr = NULL;

	rc = __cil_type_rule_to_avtab(pdb, cil_rule, &pdb->te_avtab, &avtab_ptr);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	return SEPOL_OK;

exit:
	return rc;
}

int __cil_perms_to_datum(struct cil_list *perms, class_datum_t *sepol_class, uint32_t *datum)
{
	int rc = SEPOL_ERR;
	char *key = NULL;
	struct cil_list_item *curr_perm = perms->head;
	struct cil_perm *cil_perm;
	uint32_t data = 0;

	while (curr_perm != NULL) {
		perm_datum_t *sepol_perm;
		cil_perm = curr_perm->data;
		key = cil_perm->datum.name;
		sepol_perm = hashtab_search(sepol_class->permissions.table, key);
		if (sepol_perm == NULL) {
			common_datum_t *sepol_common = sepol_class->comdatum;
			sepol_perm = hashtab_search(sepol_common->permissions.table, key);
			if (sepol_perm == NULL) {
				rc = SEPOL_ERR;
				goto exit;
			}
		}
		data |= 1 << (sepol_perm->s.value - 1);

		curr_perm = curr_perm->next;
	}

	*datum = data;

	return SEPOL_OK;

exit:
	return rc;
}

int __cil_insert_avrule(uint32_t kind, uint32_t src, uint32_t tgt, uint32_t obj, uint32_t data, avtab_t *avtab, avtab_ptr_t *avtab_ptr, uint32_t merge)
{
	int rc = SEPOL_ERR;
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
	case CIL_AVRULE_NEVERALLOW:
		avtab_key.specified = AVTAB_NEVERALLOW;
		break;
	case CIL_AVRULE_DONTAUDIT:
		avtab_key.specified = AVTAB_AUDITDENY;
		break;
	default:
		rc = SEPOL_ERR;
		goto exit;
		break;
	}

	if (merge) {
		avtab_dup = avtab_search(avtab, &avtab_key);
		if (avtab_dup != NULL) {
			avtab_dup->data |= data;
		}
	}

	if (avtab_dup == NULL) {
		avtab_datum.data = data;

		*avtab_ptr = avtab_insert_nonunique(avtab, &avtab_key, &avtab_datum);
		if (*avtab_ptr == NULL) {
			rc = SEPOL_ERR;
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	return rc;
}

/* Before inserting, expand out avrule classpermset if it is a classmap */
int __cil_avrule_expand(policydb_t *pdb, uint32_t src, uint32_t tgt, struct cil_avrule *cil_avrule, avtab_t *avtab, avtab_ptr_t *avtab_ptr, uint32_t merge)
{
	int rc = SEPOL_ERR;
	uint32_t data = 0;
	char *obj = NULL;
	uint16_t kind = cil_avrule->rule_kind;
	class_datum_t *sepol_obj = NULL;
	struct cil_classpermset *classpermset = cil_avrule->classpermset;
	struct cil_list *cil_perms = classpermset->perms;

	if (classpermset->flavor == CIL_CLASS) {
		obj = ((struct cil_symtab_datum *)cil_avrule->classpermset->class)->name;
		sepol_obj = hashtab_search(pdb->p_classes.table, obj);
		if (sepol_obj == NULL) {
			rc = SEPOL_ERR;
			goto exit;
		}

		rc = __cil_perms_to_datum(cil_perms, sepol_obj, &data);
		if (rc != SEPOL_OK) {
			goto exit;
		}

		if (kind == CIL_AVRULE_DONTAUDIT) {
			data = ~data;
		}

		rc = __cil_insert_avrule(kind, src, tgt, sepol_obj->s.value, data, avtab, avtab_ptr, merge);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	} else if (classpermset->flavor == CIL_CLASSMAP) {
		struct cil_list_item *i = NULL;

		for (i = cil_perms->head; i != NULL; i = i->next) {
			struct cil_classmap_perm *cmp = i->data;
			struct cil_list_item *j = NULL;

			for (j = cmp->classperms->head; j != NULL; j = j->next) {
				struct cil_classpermset *cps = j->data;
				struct cil_list *perms = cps->perms;

				obj = ((struct cil_symtab_datum *)cps->class)->name;
				sepol_obj = hashtab_search(pdb->p_classes.table, obj);
				if (sepol_obj == NULL) {
					rc = SEPOL_ERR;
					goto exit;
				}

				rc = __cil_perms_to_datum(perms, sepol_obj, &data);
				if (rc != SEPOL_OK) {
					goto exit;
				}

				if (kind == CIL_AVRULE_DONTAUDIT) {
					data = ~data;
				}

				rc = __cil_insert_avrule(kind, src, tgt, sepol_obj->s.value, data, avtab, avtab_ptr, merge);
				if (rc != SEPOL_OK) {
					goto exit;
				}

				data = 0;
			}
		}
	}

	rc = SEPOL_OK;
exit:
	return rc;
}

int __cil_avrule_to_avtab(policydb_t *pdb, struct cil_avrule *cil_avrule, avtab_t *avtab, avtab_ptr_t *avtab_ptr, uint32_t merge)
{
	int rc = SEPOL_ERR;
	char *src = NULL;
	char *tgt = NULL;
	type_datum_t *sepol_src = NULL;
	type_datum_t *sepol_tgt = NULL;
	ebitmap_t types;
	ebitmap_init(&types);

	src = ((struct cil_symtab_datum *)cil_avrule->src)->name;
	tgt = ((struct cil_symtab_datum *)cil_avrule->tgt)->name;

	sepol_src = hashtab_search(pdb->p_types.table, src);
	if (sepol_src == NULL) {
		rc = SEPOL_ERR;
		goto exit;
	}

	if (!strcmp(tgt, CIL_KEY_SELF)) {
		struct cil_symtab_datum *srcdatum = cil_avrule->src;
		if (srcdatum->node->flavor == CIL_TYPEATTRIBUTE) {
			unsigned int i;
			ebitmap_node_t *tnode;
			rc = __cil_typeattr_expand_to_policydb(pdb, srcdatum->node->data, &types);
			if (rc != SEPOL_OK) {
				goto exit;
			}

			ebitmap_for_each_bit(&types, tnode, i) {
				if (!ebitmap_get_bit(&types, i)) {
					continue;
				}

				rc = __cil_avrule_expand(pdb, i + 1, i + 1, cil_avrule, avtab, avtab_ptr, merge);
				if (rc != SEPOL_OK) {
					goto exit;
				}
			}
		} else {
			rc = __cil_avrule_expand(pdb, sepol_src->s.value, sepol_src->s.value, cil_avrule, avtab, avtab_ptr, merge);
			if (rc != SEPOL_OK) {
				goto exit;
			}
		}
	} else {
		sepol_tgt = hashtab_search(pdb->p_types.table, tgt);
		if (sepol_tgt == NULL) {
			rc = SEPOL_ERR;
			goto exit;
		}

		rc = __cil_avrule_expand(pdb, sepol_src->s.value, sepol_tgt->s.value, cil_avrule, avtab, avtab_ptr, merge);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	rc = SEPOL_OK;

exit:
	ebitmap_destroy(&types);
	return rc;
}

int cil_avrule_to_policydb(policydb_t *pdb, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	struct cil_avrule *cil_avrule = node->data;
	avtab_ptr_t avtab_ptr;

	rc = __cil_avrule_to_avtab(pdb, cil_avrule, &pdb->te_avtab, &avtab_ptr, 1);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	return SEPOL_OK;

exit:
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
	avtab_ptr_t avtab_ptr = NULL;

	curr_rule = node->cl_head;
	while (curr_rule != NULL) {
		cond_list = cil_malloc(sizeof(*cond_list));
		memset(cond_list, 0, sizeof(cond_av_list_t));

		flavor = curr_rule->flavor;
		switch (flavor) {
		case CIL_TYPE_RULE:
			cil_type_rule = curr_rule->data;
			rc = __cil_type_rule_to_avtab(pdb, cil_type_rule, &pdb->te_cond_avtab, &avtab_ptr);
			break;
		case CIL_AVRULE:
			cil_avrule = curr_rule->data;
			rc = __cil_avrule_to_avtab(pdb, cil_avrule, &pdb->te_cond_avtab, &avtab_ptr, 0);
			break;
		default:
			rc = SEPOL_ERR;
			break;
		}
		if (rc != SEPOL_OK) {
			goto exit;
		}

		cond_list->node = avtab_ptr;

		flavor = node->flavor;
		switch (flavor) {
		case CIL_CONDTRUE:
			if (cond_node->true_list == NULL) {
				cond_node->true_list = cond_list;
			} else {
				cond_list->next = cond_node->true_list;
				cond_node->true_list = cond_list;
			}
			break;
		case CIL_CONDFALSE:
			if (cond_node->false_list == NULL) {
				cond_node->false_list = cond_list;
			} else {
				cond_list->next = cond_node->false_list;
				cond_node->false_list = cond_list;
			}
			break;
		default:
			rc = SEPOL_ERR;
			goto exit;
		}
		curr_rule = curr_rule->next;
	}

	return SEPOL_OK;

exit:
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
	cond_expr_t *cond_expr_tail = NULL;
	cond_node_t *cond_node = NULL;

	cond_node = cond_node_create(pdb, NULL);
	if (cond_node == NULL) {
		rc = SEPOL_ERR;
		goto exit;
	}

	while (curr_expr != NULL) {
		char *key = NULL;
		struct cil_conditional *cil_cond = curr_expr->data;
		cond_bool_datum_t *sepol_bool = NULL;
		cond_expr = cil_malloc(sizeof(*cond_expr));
		memset(cond_expr, 0, sizeof(cond_expr_t));

		flavor = cil_cond->flavor;
		switch (flavor) {
		case CIL_BOOL:
			cond_expr->expr_type = COND_BOOL;
			key = ((struct cil_symtab_datum *)cil_cond->data)->name;
			sepol_bool = hashtab_search(pdb->p_bools.table, key);
			if (sepol_bool == NULL) {
				rc = SEPOL_ERR;
				goto exit;
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
			goto exit;
		}

		if (cond_expr_tail == NULL) {
			cond_node->expr = cond_expr;
		} else {
			cond_expr_tail->next = cond_expr;
		}
		cond_expr_tail = cond_expr;

		curr_expr = curr_expr->next;
	}

	if (cil_boolif->condtrue != NULL) {
		rc = __cil_cond_to_policydb(pdb, cil_boolif->condtrue, cond_node);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	if (cil_boolif->condfalse != NULL) {
		rc = __cil_cond_to_policydb(pdb, cil_boolif->condfalse, cond_node);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	if (pdb->cond_list == NULL) {
		pdb->cond_list = cond_node;
	} else {
		cond_node->next = pdb->cond_list;
		pdb->cond_list = cond_node;
	}

	return SEPOL_OK;

exit:
	cond_node_destroy(cond_node);
	cond_expr_destroy(cond_expr);
	return rc;
}

int cil_roletrans_to_policydb(policydb_t *pdb, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	char *key = NULL;
	struct cil_roletransition *cil_roletrans = node->data;
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
		goto exit;
	}
	sepol_roletrans->role = sepol_src->s.value;

	key = ((struct cil_symtab_datum *)cil_roletrans->tgt)->name;
	sepol_tgt = hashtab_search(pdb->p_types.table, key);
	if (sepol_tgt == NULL) {
		rc = SEPOL_ERR;
		goto exit;
	}
	sepol_roletrans->type = sepol_tgt->s.value;

	key = ((struct cil_symtab_datum *)cil_roletrans->obj)->name;
	sepol_obj = hashtab_search(pdb->p_classes.table, key);
	if (sepol_obj == NULL) {
		rc = SEPOL_ERR;
		goto exit;
	}
	sepol_roletrans->tclass = sepol_obj->s.value;

	key = ((struct cil_symtab_datum *)cil_roletrans->result)->name;
	sepol_result = hashtab_search(pdb->p_roles.table, key);
	if (sepol_result == NULL) {
		rc = SEPOL_ERR;
		goto exit;
	}
	sepol_roletrans->new_role = sepol_result->s.value;

	if (pdb->role_tr == NULL) {
		pdb->role_tr = sepol_roletrans;
	} else {
		pdb->role_tr->next = sepol_roletrans;
	}

	return SEPOL_OK;

exit:
	free(sepol_roletrans);
	return rc;

}

int cil_roleallow_to_policydb(policydb_t *pdb, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	char *key = NULL;
	struct cil_roleallow *cil_roleallow = node->data;
	role_datum_t *sepol_role = NULL;
	role_datum_t *sepol_new_role = NULL;
	role_allow_t *sepol_roleallow = cil_malloc(sizeof(*sepol_roleallow));
	memset(sepol_roleallow, 0, sizeof(role_allow_t));

	key = ((struct cil_symtab_datum *)cil_roleallow->src)->name;
	sepol_role = hashtab_search(pdb->p_roles.table, key);
	if (sepol_role == NULL) {
		rc = SEPOL_ERR;
		goto exit;
	}
	sepol_roleallow->role = sepol_role->s.value;

	key = ((struct cil_symtab_datum *)cil_roleallow->tgt)->name;
	sepol_new_role = hashtab_search(pdb->p_roles.table, key);
	if (sepol_new_role == NULL) {
		rc = SEPOL_ERR;
		goto exit;
	}
	sepol_roleallow->new_role = sepol_new_role->s.value;

	if (pdb->role_allow == NULL) {
		pdb->role_allow = sepol_roleallow;
	} else {
		pdb->role_allow->next = sepol_roleallow;
	}

	return SEPOL_OK;

exit:
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
		goto exit;
	}
	sepol_filetrans->stype = sepol_src->s.value;

	key = ((struct cil_symtab_datum *)cil_filetrans->exec)->name;
	sepol_exec = hashtab_search(pdb->p_types.table, key);
	if (sepol_exec == NULL) {
		rc = SEPOL_ERR;
		goto exit;
	}
	sepol_filetrans->ttype = sepol_exec->s.value;

	key = ((struct cil_symtab_datum *)cil_filetrans->proc)->name;
	sepol_proc = hashtab_search(pdb->p_classes.table, key);
	if (sepol_proc == NULL) {
		rc = SEPOL_ERR;
		goto exit;
	}
	sepol_filetrans->tclass = sepol_proc->s.value;

	key = ((struct cil_symtab_datum *)cil_filetrans->dest)->name;
	sepol_dest = hashtab_search(pdb->p_types.table, key);
	if (sepol_dest == NULL) {
		rc = SEPOL_ERR;
		goto exit;
	}
	sepol_filetrans->otype = sepol_dest->s.value;

	sepol_filetrans->name = cil_strdup(cil_filetrans->path_str);

	if (pdb->filename_trans == NULL) {
		pdb->filename_trans = sepol_filetrans;
	} else {
		pdb->filename_trans->next = sepol_filetrans;
	}

	return SEPOL_OK;

exit:
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
				goto exit;
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

			if ( cond->flavor != CIL_NOT && cond->flavor != CIL_AND && cond->flavor != CIL_OR) {
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
					curr_expr->expr_type = CEXPR_NAMES;
					key = ((struct cil_symtab_datum *)rnode->data)->name;
					sepol_user = hashtab_search(pdb->p_users.table, key);
					if (sepol_user == NULL) {
						rc = SEPOL_ERR;
						goto exit;
					}
					value = sepol_user->s.value;
					if (ebitmap_set_bit(&curr_expr->names, value - 1, 1)) {
						rc = SEPOL_ERR;
						goto exit;
					}
					break;
				case CIL_ROLE:
					curr_expr->expr_type = CEXPR_NAMES;
					key = ((struct cil_symtab_datum *)rnode->data)->name;
					sepol_role = hashtab_search(pdb->p_roles.table, key);
					if (sepol_role == NULL) {
						rc = SEPOL_ERR;
						goto exit;
					}
					value = sepol_role->s.value;
					if (ebitmap_set_bit(&curr_expr->names, value - 1, 1)) {
						rc = SEPOL_ERR;
						goto exit;
					}
					break;
				case CIL_TYPE:
					curr_expr->expr_type = CEXPR_NAMES;
					key = ((struct cil_symtab_datum *)rnode->data)->name;
					sepol_type = hashtab_search(pdb->p_types.table, key);
					if (sepol_type == NULL) {
						rc = SEPOL_ERR;
						goto exit;
					}
					value = sepol_type->s.value;
					if (ebitmap_set_bit(&curr_expr->names, value - 1, 1)) {
						rc = SEPOL_ERR;
						goto exit;
					}
					break;
				default:
					curr_expr->expr_type = CEXPR_ATTR;
					break;
				}
			}
		}

		lnode = rnode;
		rnode = cond;

		curr = curr->next;
	}

	*sepol_expr = new_expr;

	return SEPOL_OK;

exit:
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
	class_datum_t *sepol_class = NULL;
	constraint_node_t *sepol_constrain = NULL;
	constraint_expr_t *sepol_expr = NULL;

	while (curr_class != NULL) {
		struct cil_class *class = curr_class->data;
		key = class->datum.name;
		sepol_class = hashtab_search(pdb->p_classes.table, key);
		if (sepol_class == NULL) {
			rc = SEPOL_ERR;
			goto exit;
		}

		sepol_constrain = cil_malloc(sizeof(*sepol_constrain));
		memset(sepol_constrain, 0, sizeof(constraint_node_t));

		rc = __cil_perms_to_datum(perms, sepol_class, &sepol_constrain->permissions);
		if (rc != SEPOL_OK) {
			goto exit;
		}

		rc = __cil_constrain_expr_to_sepol_expr(pdb, expr, &sepol_expr);
		if (rc != SEPOL_OK) {
			goto exit;
		}
		sepol_constrain->expr = sepol_expr;

		if (sepol_class->constraints == NULL) {
			sepol_class->constraints = sepol_constrain;
		} else {
			sepol_constrain->next = sepol_class->constraints;
			sepol_class->constraints = sepol_constrain;
		}

		sepol_expr = NULL;
		curr_class = curr_class->next;
	}

	return SEPOL_OK;

exit:
	free(sepol_constrain);
	return rc;
}

int __cil_catrange_expand_to_bitmap(policydb_t *pdb, struct cil_cat *start, struct cil_cat *end, ebitmap_t *bitmap)
{
	int rc = SEPOL_ERR;
	uint32_t svalue = 0;
	uint32_t evalue = 0;
	unsigned int bit = 0;
	char *key = NULL;
	cat_datum_t *sepol_start = NULL;
	cat_datum_t *sepol_end = NULL;

	key = start->datum.name;
	sepol_start = hashtab_search(pdb->p_cats.table, key);
	if (sepol_start == NULL) {
		goto exit;
	}
	svalue = sepol_start->s.value - 1;

	key = end->datum.name;
	sepol_end = hashtab_search(pdb->p_cats.table, key);
	if (sepol_end == NULL) {
		goto exit;
	}
	evalue = sepol_end->s.value - 1;

	for (bit = svalue; bit <= evalue; bit++) {
		if (ebitmap_set_bit(bitmap, bit, 1)) {
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	return rc;
}

int __cil_mls_level_build(policydb_t *pdb, struct cil_sens *cil_sens, mls_level_t *mls_level)
{
	int rc = SEPOL_ERR;
	char *key = NULL;
	struct cil_list *catsets = cil_sens->catsets;
	struct cil_list_item *curr = NULL;
	level_datum_t *sepol_level = NULL;

	key = cil_sens->datum.name;
	sepol_level = hashtab_search(pdb->p_levels.table, key);
	if (sepol_level == NULL) {
		goto exit;
	}
	mls_level->sens = sepol_level->level->sens;

	ebitmap_init(&mls_level->cat);

	for (curr = catsets->head; curr != NULL; curr = curr->next) {
		struct cil_catset *catset = curr->data;
		struct cil_list *cats = catset->cat_list;
		struct cil_list_item *curr_cat = NULL;

		for (curr_cat = cats->head; curr_cat != NULL; curr_cat = curr_cat->next)  {
			if (curr_cat->flavor == CIL_CATRANGE) {
				struct cil_catrange *catrange = curr_cat->data;
				struct cil_cat *start_cat = catrange->cat_low;
				struct cil_cat *end_cat = catrange->cat_high;

				rc = __cil_catrange_expand_to_bitmap(pdb, start_cat, end_cat, &mls_level->cat);
				if (rc != SEPOL_OK) {
					goto exit;
				}
			} else {
				struct cil_cat *cil_cat = curr_cat->data;
				cat_datum_t *sepol_cat = NULL;

				key = cil_cat->datum.name;
				sepol_cat = hashtab_search(pdb->p_cats.table, key);
				if (sepol_cat == NULL) {
					goto exit;
				}

				if (ebitmap_set_bit(&mls_level->cat, sepol_cat->s.value - 1, 1)) {
					goto exit;
				}
			}
		}
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_sepol_level_define(policydb_t *pdb, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	char *key = NULL;
	struct cil_sens *cil_sens = node->data;
	level_datum_t *sepol_level = NULL;
	mls_level_t *mls_level = NULL;

	key = cil_sens->datum.name;
	sepol_level = hashtab_search(pdb->p_levels.table, key);
	if (sepol_level == NULL) {
		goto exit;
	}
	mls_level = sepol_level->level;

	rc = __cil_mls_level_build(pdb, cil_sens, mls_level);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	sepol_level->defined = 1;

	return SEPOL_OK;

exit:
	return rc;
}

int __cil_levelrange_to_mls_range(policydb_t *pdb, struct cil_levelrange *cil_lvlrange, mls_range_t *mls_range)
{
	int rc = SEPOL_ERR;
	struct cil_sens *low = cil_lvlrange->low->sens;
	struct cil_sens *high = cil_lvlrange->high->sens;
	mls_level_t *mls_level = NULL;

	mls_level = &mls_range->level[0];

	rc = __cil_mls_level_build(pdb, low, mls_level);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	mls_level = &mls_range->level[1];

	rc = __cil_mls_level_build(pdb, high, mls_level);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_userlevel_userrange_to_policydb(policydb_t *pdb, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	char *key = NULL;
	struct cil_user *cil_user = node->data;
	struct cil_level *cil_level = cil_user->dftlevel;
	struct cil_levelrange *cil_levelrange = cil_user->range;
	user_datum_t *sepol_user = NULL;

	key = cil_user->datum.name;
	sepol_user = hashtab_search(pdb->p_users.table, key);
	if (sepol_user == NULL) {
		rc = SEPOL_ERR;
		goto exit;
	}

	rc = __cil_mls_level_build(pdb, cil_level->sens, &sepol_user->exp_dfltlevel);
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
	char *key = NULL;
	struct cil_levelrange *cil_lvlrange = cil_context->range;
	user_datum_t *sepol_user = NULL;
	role_datum_t *sepol_role = NULL;
	type_datum_t *sepol_type = NULL;

	key = ((struct cil_symtab_datum *)cil_context->user)->name;
	sepol_user = hashtab_search(pdb->p_users.table, key);
	if (sepol_user == NULL) {
		goto exit;
	}
	sepol_context->user = sepol_user->s.value;

	key = ((struct cil_symtab_datum *)cil_context->role)->name;
	sepol_role = hashtab_search(pdb->p_roles.table, key);
	if (sepol_role == NULL) {
		goto exit;
	}
	sepol_context->role = sepol_role->s.value;

	key = ((struct cil_symtab_datum *)cil_context->type)->name;
	sepol_type = hashtab_search(pdb->p_types.table, key);
	if (sepol_type == NULL) {
		goto exit;
	}
	sepol_context->type = sepol_type->s.value;

	mls_context_init(sepol_context);

	rc = __cil_levelrange_to_mls_range(pdb, cil_lvlrange, &sepol_context->range);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_sid_to_policydb(policydb_t *pdb, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	struct cil_sid *cil_sid = node->data;
	struct cil_context *cil_context = cil_sid->context;
	ocontext_t *new_sepol_sidcon = NULL;
	context_struct_t *sepol_context = NULL;

	new_sepol_sidcon = cil_malloc(sizeof(*new_sepol_sidcon));
	memset(new_sepol_sidcon, 0, sizeof(ocontext_t));

	new_sepol_sidcon->next = pdb->ocontexts[OCON_ISID];
	pdb->ocontexts[OCON_ISID] = new_sepol_sidcon;

	new_sepol_sidcon->sid[0] = pdb->ocontexts[OCON_ISID]->sid[0] + 1;
	new_sepol_sidcon->u.name = cil_strdup(cil_sid->datum.name);

	sepol_context = &new_sepol_sidcon->context[0];

	if (cil_context != NULL) {
		rc = __cil_context_to_sepol_context(pdb, cil_context, sepol_context);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	free(new_sepol_sidcon->u.name);
	context_destroy(&new_sepol_sidcon->context[0]);
	free(new_sepol_sidcon);
	return rc;
}

int cil_rangetransition_to_policydb(policydb_t *pdb, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	char *key = NULL;
	struct cil_rangetransition *cil_rangetrans = node->data;
	struct cil_levelrange *cil_lvlrange = cil_rangetrans->range;
	type_datum_t *sepol_type = NULL;
	class_datum_t *sepol_class = NULL;
	mls_range_t *mls_range = NULL;
	range_trans_t *sepol_rangetrans = cil_malloc(sizeof(*sepol_rangetrans));
	memset(sepol_rangetrans, 0, sizeof(range_trans_t));

	sepol_rangetrans->next = pdb->range_tr;
	pdb->range_tr = sepol_rangetrans;

	key = ((struct cil_symtab_datum *)cil_rangetrans->src)->name;
	sepol_type = hashtab_search(pdb->p_types.table, key);
	if (sepol_type == NULL) {
		rc = SEPOL_ERR;
		goto exit;
	}
	sepol_rangetrans->source_type = sepol_type->s.value;

	key = ((struct cil_symtab_datum *)cil_rangetrans->exec)->name;
	sepol_type = hashtab_search(pdb->p_types.table, key);
	if (sepol_type == NULL) {
		rc = SEPOL_ERR;
		goto exit;
	}
	sepol_rangetrans->target_type = sepol_type->s.value;

	key = ((struct cil_symtab_datum *)cil_rangetrans->obj)->name;
	sepol_class = hashtab_search(pdb->p_classes.table, key);
	if (sepol_class == NULL) {
		rc = SEPOL_ERR;
		goto exit;
	}
	sepol_rangetrans->target_class = sepol_class->s.value;

	mls_range = &sepol_rangetrans->target_range;

	rc = __cil_levelrange_to_mls_range(pdb, cil_lvlrange, mls_range);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	return SEPOL_OK;

exit:
	free(sepol_rangetrans);
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
		case CIL_TYPEATTRIBUTE:
			rc = cil_typeattribute_to_policydb(pdb, node);
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
		case CIL_SENS:
			rc = cil_sepol_level_define(pdb, node);
			break;
		default:
			break;
		}
		break;
	case 2:
		switch (node->flavor) {
		case CIL_TYPEALIAS:
			rc = cil_typealias_to_policydb(pdb, node);
			break;
		case CIL_TYPEPERMISSIVE:
			rc = cil_typepermissive_to_policydb(pdb, node);
			break;
		case CIL_TYPEATTRIBUTE:
			rc = cil_typeattribute_to_bitmap(pdb, node);
			break;
		case CIL_SENSALIAS:
			rc = cil_sensalias_to_policydb(pdb, node);
			break;
		case CIL_CLASS:
			rc = cil_classcommon_to_policydb(pdb, node);
			break;
		case CIL_ROLETYPE:
			rc = cil_roletype_to_policydb(pdb, node);
			break;
		case CIL_ROLEDOMINANCE:
			rc = cil_roledominance_to_policydb(pdb, node);
			break;
		case CIL_ROLE:
			rc = cil_rolebounds_to_policydb(pdb, node);
			break;
		case CIL_USER:
			rc = cil_userlevel_userrange_to_policydb(pdb, node);
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
		case CIL_ROLETRANSITION:
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
		case CIL_SID:
			rc = cil_sid_to_policydb(pdb, node);
			break;
		case CIL_RANGETRANSITION:
			rc = cil_rangetransition_to_policydb(pdb, node);
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
			goto exit;
		}
	} else if (node->flavor == CIL_MACRO) {
		*finished = CIL_TREE_SKIP_HEAD;
		rc = SEPOL_OK;
		goto exit;
	} else if (node->flavor == CIL_BOOLEANIF) {
		*finished = CIL_TREE_SKIP_HEAD;
	}

	rc = __cil_node_to_policydb(pdb, node, pass);
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

	return SEPOL_OK;

exit:
	return rc;
}

int __cil_policydb_init(policydb_t *pdb, const struct cil_db *db)
{
	int rc = SEPOL_ERR;

	rc = cil_catorder_to_policydb(pdb, db);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	rc = cil_dominance_to_policydb(pdb, db);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	rc = avtab_alloc(&pdb->te_avtab, MAX_AVTAB_SIZE);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	rc = cond_policydb_init(pdb);
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

int cil_binary_create(const struct cil_db *db, policydb_t *pdb, const char *fname)
{
	int rc = SEPOL_ERR;
	int i;
	FILE *binary;
	struct policy_file pf;
	struct cil_args_binary extra_args;

	if (db == NULL || pdb == NULL || fname == NULL) {
		goto exit;
	}

	rc = __cil_policydb_init(pdb, db);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	extra_args.db = db;
	extra_args.pdb = pdb;
	for (i = 1; i <= 2; i++) {
		extra_args.pass = i;
		rc = cil_tree_walk(db->ast->root, __cil_binary_create_helper, NULL, NULL, &extra_args);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	rc = __cil_contexts_to_policydb(pdb, db);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	if (pdb->type_attr_map == NULL) {
		rc = __cil_typeattr_bitmap_init(pdb);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	binary = fopen(fname, "w");
	if (binary == NULL) {
		fprintf(stderr, "Failure creating binary file\n");
		rc = SEPOL_ERR;
		goto exit;
	}

	policy_file_init(&pf);
	pf.type = PF_USE_STDIO;
	pf.fp = binary;

	rc = policydb_write(pdb, &pf);
	if (rc != 0) {
		fprintf(stderr, "Failed writing binary policy\n");
		goto exit;
	}

	fclose(binary);

	return SEPOL_OK;

exit:
	return rc;
}
