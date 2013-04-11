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
#include <string.h>

#include "cil_internal.h"
#include "cil_log.h"
#include "cil_mem.h"
#include "cil_tree.h"
#include "cil_list.h"
#include "cil_symtab.h"
#include "cil_copy_ast.h"
#include "cil_build_ast.h"

struct cil_args_copy {
	struct cil_tree_node *dest;
	struct cil_db *db;
};

void cil_copy_list(struct cil_list *data, struct cil_list **copy)
{
	struct cil_list *new;
	struct cil_list_item *orig_item;

	cil_list_init(&new, CIL_LIST_ITEM);
	cil_list_for_each(orig_item, data) {
		if (orig_item->flavor == CIL_STRING) {
			cil_list_append(new, CIL_STRING, cil_strdup(orig_item->data));
		} else if (orig_item->flavor == CIL_LIST) {
			struct cil_list *new_sub = NULL;
			cil_copy_list((struct cil_list*)orig_item->data, &new_sub);
			cil_list_append(new, CIL_LIST, new_sub);
		}
	}

	*copy = new;
}

int cil_copy_parse(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	char *new = NULL;

	new = cil_strdup(data);
	*copy = new;

	return SEPOL_OK;
}

int cil_copy_block(__attribute__((unused)) struct cil_db *db, void *data, void **copy, symtab_t *symtab)
{
	struct cil_block *orig = data;
	char *key = orig->datum.name;
	struct cil_symtab_datum *datum = NULL;

	cil_symtab_get_datum(symtab, key, &datum);
	if (datum == NULL) {
		struct cil_block *new;
		cil_block_init(&new);
		cil_symtab_array_init(new->symtab, cil_sym_sizes[CIL_SYM_ARRAY_BLOCK]);
		*copy = new;
	} else {
		*copy = datum;;
	}

	return SEPOL_OK;
}

int cil_copy_blockabstract(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_blockabstract *orig = data;
	struct cil_blockabstract *new = NULL;

	cil_blockabstract_init(&new);

	new->block_str = cil_strdup(orig->block_str);

	*copy = new;

	return SEPOL_OK;
}

int cil_copy_blockinherit(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_blockinherit *orig = data;
	struct cil_blockinherit *new = NULL;

	cil_blockinherit_init(&new);

	new->block_str = cil_strdup(orig->block_str);

	*copy = new;

	return SEPOL_OK;
}

int cil_copy_policycap(__attribute__((unused)) struct cil_db *db, void *data, void **copy, symtab_t *symtab)
{
	struct cil_policycap *orig = data;
	char *key = orig->datum.name;
	struct cil_symtab_datum *datum = NULL;

	cil_symtab_get_datum(symtab, key, &datum);
	if (datum == NULL) {
		struct cil_policycap *new;
		cil_policycap_init(&new);
		*copy = new;
	} else {
		*copy = datum;
	}

	return SEPOL_OK;
}

int cil_copy_perm(__attribute__((unused)) struct cil_db *db, void *data, void **copy, symtab_t *symtab)
{
	struct cil_perm *orig = data;
	char *key = orig->datum.name;
	struct cil_symtab_datum *datum = NULL;

	cil_symtab_get_datum(symtab, key, &datum);
	if (datum == NULL) {
		struct cil_perm *new;
		cil_perm_init(&new);
		*copy = new;
	} else {
		*copy = datum;
	}

	return SEPOL_OK;
}

int cil_copy_map_perm(__attribute__((unused)) struct cil_db *db, void *data, void **copy, symtab_t *symtab)
{
	struct cil_map_perm *orig = data;
	struct cil_map_perm *new = NULL;
	char *key = orig->datum.name;
	struct cil_symtab_datum *datum = NULL;

	cil_symtab_get_datum(symtab, key, &datum);
	if (datum != NULL) {
		cil_log(CIL_INFO, "Map permissions cannot be redefined\n");
		return SEPOL_ERR;
	}

	cil_map_perm_init(&new);
	cil_copy_list(orig->classperms, &new->classperms);

	*copy = new;

	return SEPOL_OK;
}

int cil_copy_map_class(__attribute__((unused)) struct cil_db *db, void *data, void **copy, symtab_t *symtab)
{
	struct cil_map_class *orig = data;
	struct cil_map_class *new = NULL;
	char *key = orig->datum.name;
	struct cil_symtab_datum *datum = NULL;

	cil_symtab_get_datum(symtab, key, &datum);
	if (datum != NULL) {
		cil_log(CIL_INFO, "Map class cannot be redefined\n");
		return SEPOL_ERR;
	}

	cil_map_class_init(&new);
	cil_symtab_init(&new->perms, CIL_CLASS_SYM_SIZE);

	*copy = new;

	return SEPOL_OK;
}

int cil_copy_classmapping(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_classmapping *orig = data;
	struct cil_classmapping *new = NULL;
	struct cil_list_item *curr;

	cil_classmapping_init(&new);

	new->map_class_str = cil_strdup(orig->map_class_str);
	new->map_perm_str = cil_strdup(orig->map_perm_str);

	cil_list_init(&new->classpermsets_str, CIL_LIST_ITEM);

	cil_list_for_each(curr, new->classpermsets_str) {
		if (curr->flavor == CIL_STRING) {
			cil_list_append(new->classpermsets_str, CIL_STRING, cil_strdup(curr->data));
		} else if (curr->flavor == CIL_CLASSPERMSET) {
			struct cil_classpermset *cps;
			cil_classpermset_init(&cps);
			cil_copy_fill_classpermset((struct cil_classpermset*)curr->data, cps);
			cil_list_prepend(new->classpermsets_str, CIL_CLASSPERMSET, cps);
		}
	}

	*copy = new;

	return SEPOL_OK;
}

int cil_copy_class(__attribute__((unused)) struct cil_db *db, void *data, void **copy, symtab_t *symtab)
{
	struct cil_class *orig = data;
	struct cil_class *new = NULL;
	char *key = orig->datum.name;
	struct cil_symtab_datum *datum = NULL;

	cil_symtab_get_datum(symtab, key, &datum);
	if (datum != NULL) {
		cil_log(CIL_INFO, "cil_copy_class: class cannot be redefined\n");
		return SEPOL_ERR;
	}

	cil_class_init(&new);
	cil_symtab_init(&new->perms, CIL_CLASS_SYM_SIZE);

	new->common = NULL;
	*copy = new;

	return SEPOL_OK;
}

void cil_copy_fill_classpermset(struct cil_classpermset *data, struct cil_classpermset *new)
{
	new->class_str = cil_strdup(data->class_str);

	if (data->perm_strs != NULL) {
		cil_copy_list(data->perm_strs, &new->perm_strs);

	}
}

int cil_copy_classpermset(__attribute__((unused)) struct cil_db *db, void *data, void **copy, symtab_t *symtab)
{
	struct cil_classpermset *orig = data;
	struct cil_classpermset *new = NULL;
	char *key = orig->datum.name;
	struct cil_symtab_datum *datum = NULL;

	if (key != NULL) {
		cil_symtab_get_datum(symtab, key, &datum);
		if (datum != NULL) {
			cil_log(CIL_INFO, "cil_copy_classpermset: classpermissionset cannot be redefined\n");
			return SEPOL_ERR;
		}
	}

	cil_classpermset_init(&new);
	cil_copy_fill_classpermset(orig, new);
	*copy = new;

	return SEPOL_OK;
}

void cil_copy_fill_classperms(struct cil_classperms *orig, struct cil_classperms **new)
{
	cil_classperms_init(new);

	(*new)->classpermset_str = cil_strdup(orig->classpermset_str);

	if (orig->classpermset != NULL) {
		cil_classpermset_init(&(*new)->classpermset);
		cil_copy_fill_classpermset(orig->classpermset, (*new)->classpermset);
	}
}

int cil_copy_common(__attribute__((unused)) struct cil_db *db, void *data, void **copy, symtab_t *symtab)
{
	struct cil_common *orig = data;
	struct cil_common *new = NULL;
	char *key = orig->datum.name;
	struct cil_symtab_datum *datum = NULL;

	cil_symtab_get_datum(symtab, key, &datum);
	if (datum != NULL) {
		cil_log(CIL_INFO, "cil_copy_common: common cannot be redefined\n");
		return SEPOL_ERR;
	}	

	cil_common_init(&new);
	cil_symtab_init(&new->perms, CIL_CLASS_SYM_SIZE);
	*copy = new;

	return SEPOL_OK;
}

int cil_copy_classcommon(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_classcommon *orig = data;
	struct cil_classcommon *new = NULL;

	cil_classcommon_init(&new);

	new->class_str = cil_strdup(orig->class_str);
	new->common_str = cil_strdup(orig->common_str);

	*copy = new;

	return SEPOL_OK;
}

int cil_copy_sid(__attribute__((unused)) struct cil_db *db, void *data, void **copy, symtab_t *symtab)
{
	struct cil_sid *orig = data;
	char *key = orig->datum.name;
	struct cil_symtab_datum *datum = NULL;

	cil_symtab_get_datum(symtab, key, &datum);
	if (datum == NULL) {
		struct cil_sid *new;
		cil_sid_init(&new);
		*copy = new;
	} else {
		*copy = datum;
	}

	return SEPOL_OK;
}

int cil_copy_sidcontext(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_sidcontext *orig = data;
	struct cil_sidcontext *new = NULL;

	cil_sidcontext_init(&new);

	new->context_str = cil_strdup(orig->context_str);

	if (orig->context != NULL && orig->context_str == NULL) {
		cil_context_init(&new->context);
		cil_copy_fill_context(orig->context, new->context);
	}

	*copy = new;

	return SEPOL_OK;
}

int cil_copy_user(__attribute__((unused)) struct cil_db *db, void *data, void **copy, symtab_t *symtab)
{
	struct cil_user *orig = data;
	char *key = orig->datum.name;
	struct cil_symtab_datum *datum = NULL;

	cil_symtab_get_datum(symtab, key, &datum);
	if (datum == NULL) {
		struct cil_user *new;
		cil_user_init(&new);
		*copy = new;
	} else {
		*copy = datum;
	}

	return SEPOL_OK;
}

int cil_copy_userrole(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_userrole *orig = data;
	struct cil_userrole *new = NULL;

	cil_userrole_init(&new);

	new->user_str = cil_strdup(orig->user_str);
	new->role_str = cil_strdup(orig->role_str);

	*copy = new;

	return SEPOL_OK;
}

int cil_copy_userlevel(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_userlevel *orig = data;
	struct cil_userlevel *new = NULL;

	cil_userlevel_init(&new);

	new->user_str = cil_strdup(orig->user_str);
	new->level_str = cil_strdup(orig->level_str);

	if (orig->level != NULL && orig->level_str == NULL) {
		cil_level_init(&new->level);
		cil_copy_fill_level(orig->level, new->level);
	}

	*copy = new;

	return SEPOL_OK;
}

int cil_copy_userrange(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_userrange *orig = data;
	struct cil_userrange *new = NULL;

	cil_userrange_init(&new);

	new->user_str = cil_strdup(orig->user_str);
	new->range_str = cil_strdup(orig->range_str);

	if (orig->range != NULL && orig->range_str == NULL) {
		cil_levelrange_init(&new->range);
		cil_copy_fill_levelrange(orig->range, new->range);
	}

	*copy = new;

	return SEPOL_OK;
}

int cil_copy_userbounds(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_userbounds *orig = data;
	struct cil_userbounds *new = NULL;

	cil_userbounds_init(&new);

	new->user_str = cil_strdup(orig->user_str);
	new->bounds_str = cil_strdup(orig->bounds_str);

	*copy = new;

	return SEPOL_OK;
}

int cil_copy_userprefix(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_userprefix *orig = data;
	struct cil_userprefix *new = NULL;

	cil_userprefix_init(&new);

	new->user_str = cil_strdup(orig->user_str);
	new->prefix_str = cil_strdup(orig->prefix_str);

	*copy = new;

	return SEPOL_OK;
}

int cil_copy_role(__attribute__((unused)) struct cil_db *db, void *data, void **copy, symtab_t *symtab)
{
	struct cil_role *orig = data;
	char *key = orig->datum.name;
	struct cil_symtab_datum *datum = NULL;

	cil_symtab_get_datum(symtab, key, &datum);
	if (datum == NULL) {
		struct cil_role *new;
		cil_role_init(&new);
		*copy = new;
	} else {
		*copy = datum;
	}

	return SEPOL_OK;
}

int cil_copy_roletype(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_roletype *orig = data;
	struct cil_roletype *new = NULL;

	cil_roletype_init(&new);

	new->role_str = cil_strdup(orig->role_str);
	new->type_str = cil_strdup(orig->type_str);

	*copy = new;

	return SEPOL_OK;
}

int cil_copy_rolebounds(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_rolebounds *orig = data;
	struct cil_rolebounds *new = NULL;

	cil_rolebounds_init(&new);

	new->role_str = cil_strdup(orig->role_str);
	new->bounds_str = cil_strdup(orig->bounds_str);

	*copy = new;

	return SEPOL_OK;
}

int cil_copy_roleattribute(__attribute__((unused)) struct cil_db *db, void *data, void **copy, symtab_t *symtab)
{
	struct cil_roleattribute *orig = data;
	char *key = orig->datum.name;
	struct cil_symtab_datum *datum = NULL;

	cil_symtab_get_datum(symtab, key, &datum);
	if (datum == NULL) {
		struct cil_roleattribute *new;
		cil_roleattribute_init(&new);
		*copy = new;
	} else {
		*copy = datum;
	}

	return SEPOL_OK;
}

int cil_copy_roleattributeset(struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_roleattributeset *orig = data;
	struct cil_roleattributeset *new = NULL;

	cil_roleattributeset_init(&new);

	new->attr_str = cil_strdup(orig->attr_str);
	
	cil_copy_expr(db, orig->str_expr, &new->str_expr);
	cil_copy_expr(db, orig->datum_expr, &new->datum_expr);

	*copy = new;

	return SEPOL_OK;
}

int cil_copy_roleallow(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_roleallow *orig = data;
	struct cil_roleallow *new = NULL;

	cil_roleallow_init(&new);

	new->src_str = cil_strdup(orig->src_str);
	new->tgt_str = cil_strdup(orig->tgt_str);

	*copy = new;

	return SEPOL_OK;
}

int cil_copy_type(__attribute__((unused)) struct cil_db *db, void *data, void **copy, symtab_t *symtab)
{
	struct cil_type *orig = data;
	char *key = orig->datum.name;
	struct cil_symtab_datum *datum = NULL;

	cil_symtab_get_datum(symtab, key, &datum);
	if (datum == NULL) {
		struct cil_type *new;
		cil_type_init(&new);
		*copy = new;
	} else {
		*copy = datum;
	}

	return SEPOL_OK;
}

int cil_copy_typebounds(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_typebounds *orig = data;
	struct cil_typebounds *new = NULL;

	cil_typebounds_init(&new);

	new->type_str = cil_strdup(orig->type_str);
	new->bounds_str = cil_strdup(orig->bounds_str);

	*copy = new;

	return SEPOL_OK;
}

int cil_copy_typepermissive(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_typepermissive *orig = data;
	struct cil_typepermissive *new = NULL;

	cil_typepermissive_init(&new);

	new->type_str = cil_strdup(orig->type_str);

	*copy = new;

	return SEPOL_OK;
}

int cil_copy_typeattribute(__attribute__((unused)) struct cil_db *db, void *data, void **copy, symtab_t *symtab)
{
	struct cil_typeattribute *orig = data;
	char *key = orig->datum.name;
	struct cil_symtab_datum *datum = NULL;

	cil_symtab_get_datum(symtab, key, &datum);
	if (datum == NULL) {
		struct cil_typeattribute *new;
		cil_typeattribute_init(&new);
		*copy = new;
	} else {
		*copy = datum;
	}

	return SEPOL_OK;
}

int cil_copy_typeattributeset(struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_typeattributeset *orig = data;
	struct cil_typeattributeset *new = NULL;

	cil_typeattributeset_init(&new);

	new->attr_str = cil_strdup(orig->attr_str);

	cil_copy_expr(db, orig->str_expr, &new->str_expr);
	cil_copy_expr(db, orig->datum_expr, &new->datum_expr);

	*copy = new;

	return SEPOL_OK;
}

int cil_copy_typealias(__attribute__((unused)) struct cil_db *db, void *data, void **copy, symtab_t *symtab)
{
	struct cil_typealias *orig = data;
	struct cil_typealias *new = NULL;
	char *key = orig->datum.name;
	struct cil_symtab_datum *datum = NULL;

	cil_symtab_get_datum(symtab, key, &datum);
	if (datum != NULL) {
		cil_log(CIL_INFO, "cil_copy_typealias: alias cannot be redefined\n");
		return SEPOL_ERR;
	}

	cil_typealias_init(&new);
	new->type_str = cil_strdup(orig->type_str);
	*copy = new;

	return SEPOL_OK;
}

int cil_copy_roletransition(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_roletransition *orig = data;
	struct cil_roletransition *new = NULL;

	cil_roletransition_init(&new);

	new->src_str = cil_strdup(orig->src_str);
	new->tgt_str = cil_strdup(orig->tgt_str);
	new->obj_str = cil_strdup(orig->obj_str);
	new->result_str = cil_strdup(orig->result_str);

	*copy = new;

	return SEPOL_OK;
}

int cil_copy_nametypetransition(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_nametypetransition *orig = data;
	struct cil_nametypetransition *new = NULL;

	cil_nametypetransition_init(&new);

	new->src_str = cil_strdup(orig->src_str);
	new->exec_str = cil_strdup(orig->exec_str);
	new->proc_str = cil_strdup(orig->proc_str);
	new->dest_str = cil_strdup(orig->dest_str);
	new->path_str = cil_strdup(orig->path_str);

	*copy = new;

	return SEPOL_OK;
}

int cil_copy_rangetransition(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_rangetransition *orig = data;
	struct cil_rangetransition *new = NULL;

	cil_rangetransition_init(&new);

	new->src_str = cil_strdup(orig->src_str);
	new->exec_str = cil_strdup(orig->exec_str);
	new->obj_str = cil_strdup(orig->obj_str);
	new->range_str = cil_strdup(orig->range_str);

	if (orig->range != NULL && orig->range_str == NULL) {
		cil_levelrange_init(&new->range);
		cil_copy_fill_levelrange(orig->range, new->range);
	}

	*copy = new;

	return SEPOL_OK;
}

int cil_copy_bool(__attribute__((unused)) struct cil_db *db, void *data, void **copy, symtab_t *symtab)
{
	struct cil_bool *orig = data;
	struct cil_bool *new = NULL;
	char *key = orig->datum.name;
	struct cil_symtab_datum *datum = NULL;

	cil_symtab_get_datum(symtab, key, &datum);
	if (datum != NULL) {
		cil_log(CIL_INFO, "cil_copy_bool: boolean/tunable cannot be redefined\n");
		return SEPOL_ERR;
	}

	cil_bool_init(&new);
	new->value = orig->value;
	*copy = new;

	return SEPOL_OK;
}

int cil_copy_avrule(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_avrule *orig = data;
	struct cil_avrule *new = NULL;

	cil_avrule_init(&new);

	new->rule_kind = orig->rule_kind;
	new->src_str = cil_strdup(orig->src_str);
	new->tgt_str = cil_strdup(orig->tgt_str);

	cil_copy_fill_classperms(orig->classperms, &new->classperms);

	*copy = new;

	return SEPOL_OK;
}

int cil_copy_type_rule(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_type_rule  *orig = data;
	struct cil_type_rule *new = NULL;

	cil_type_rule_init(&new);

	new->rule_kind = orig->rule_kind;
	new->src_str = cil_strdup(orig->src_str);
	new->tgt_str = cil_strdup(orig->tgt_str);
	new->obj_str = cil_strdup(orig->obj_str);
	new->result_str = cil_strdup(orig->result_str);

	*copy = new;

	return SEPOL_OK;
}

int cil_copy_sens(__attribute__((unused)) struct cil_db *db, void *data, void **copy, symtab_t *symtab)
{
	struct cil_sens *orig = data;
	char *key = orig->datum.name;
	struct cil_symtab_datum *datum = NULL;

	cil_symtab_get_datum(symtab, key, &datum);
	if (datum == NULL) {
		struct cil_sens *new;
		cil_sens_init(&new);
		*copy = new;
	} else {
		*copy = datum;
	}

	return SEPOL_OK;
}

int cil_copy_sensalias(__attribute__((unused)) struct cil_db *db, void *data, void **copy, symtab_t *symtab)
{
	struct cil_sensalias *orig = data;
	struct cil_sensalias *new = NULL;
	char *key = orig->datum.name;
	struct cil_symtab_datum *datum = NULL;

	cil_symtab_get_datum(symtab, key, &datum);
	if (datum != NULL) {
		cil_log(CIL_INFO, "cil_copy_sensalias: sensitivityalias cannot be redefined\n");
		return SEPOL_ERR;
	}

	cil_sensalias_init(&new);
	new->sens_str = cil_strdup(orig->sens_str);
	*copy = new;

	return SEPOL_OK;
}

int cil_copy_cat(__attribute__((unused)) struct cil_db *db, void *data, void **copy, symtab_t *symtab)
{
	struct cil_cat *orig = data;
	char *key = orig->datum.name;
	struct cil_symtab_datum *datum = NULL;

	cil_symtab_get_datum(symtab, key, &datum);
	if (datum == NULL) {
		struct cil_cat *new;
		cil_cat_init(&new);
		*copy = new;
	} else {
		*copy = datum;
	}

	return SEPOL_OK;
}

int cil_copy_catalias(__attribute__((unused)) struct cil_db *db, void *data, void **copy, symtab_t *symtab)
{
	struct cil_catalias *orig = data;
	struct cil_catalias *new = NULL;
	char *key = orig->datum.name;
	struct cil_symtab_datum *datum = NULL;

	cil_symtab_get_datum(symtab, key, &datum);
	if (datum != NULL) {
		cil_log(CIL_INFO, "cil_copy_catalias: categoryalias cannot be redefined\n");
		return SEPOL_ERR;
	}

	cil_catalias_init(&new);
	new->cat_str = cil_strdup(orig->cat_str);
	*copy = new;

	return SEPOL_OK;
}

void cil_copy_fill_catrange(struct cil_catrange *data, struct cil_catrange *new)
{
	new->cat_low_str = cil_strdup(data->cat_low_str);
	new->cat_high_str = cil_strdup(data->cat_high_str);
}

int cil_copy_catrange(__attribute__((unused)) struct cil_db *db, void *data, void **copy, symtab_t *symtab)
{
	struct cil_catrange *orig = data;
	struct cil_catrange *new = NULL;
	char *key = orig->datum.name;
	struct cil_symtab_datum *datum = NULL;

	cil_symtab_get_datum(symtab, key, &datum);
	if (datum != NULL) {
		cil_log(CIL_INFO, "cil_copy_catrange: categoryrange cannot be redefined\n");
		return SEPOL_ERR;
	}

	cil_catrange_init(&new);
	new->cat_low_str = cil_strdup(orig->cat_low_str);
	new->cat_high_str = cil_strdup(orig->cat_high_str);
	*copy = new;

	return SEPOL_OK;
}

void cil_copy_fill_catset(struct cil_catset *data, struct cil_catset *new)
{
	struct cil_list_item *orig_item;

	cil_list_init(&new->cat_list_str, CIL_LIST_ITEM);

	cil_list_for_each(orig_item, data->cat_list_str) {
		switch (orig_item->flavor) {
		case CIL_CATRANGE: {
			struct cil_catrange *catrange = NULL;
			cil_catrange_init(&catrange);
			cil_copy_fill_catrange(orig_item->data, catrange);
			cil_list_append(new->cat_list_str, CIL_CATRANGE, catrange);
			break;
		}
		case CIL_STRING: {
			cil_list_append(new->cat_list_str, CIL_STRING, cil_strdup(orig_item->data));
			break;
		}
		default:
			break;
		}
	}
}

int cil_copy_catset(__attribute__((unused)) struct cil_db *db, void *data, void **copy, symtab_t *symtab)
{
	struct cil_catset *orig = data;
	struct cil_catset *new = NULL;
	char *key = orig->datum.name;
	struct cil_symtab_datum *datum = NULL;

	cil_symtab_get_datum(symtab, key, &datum);
	if (datum != NULL) {
		cil_log(CIL_INFO, "cil_copy_catset: categoryset cannot be redefined\n");
		return SEPOL_ERR;
	}

	cil_catset_init(&new);
	cil_copy_fill_catset(orig, new);

	*copy = new;

	return SEPOL_OK;
}

int cil_copy_senscat(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_senscat *orig = data;
	struct cil_senscat *new = NULL;

	cil_senscat_init(&new);

	new->sens_str = cil_strdup(orig->sens_str);
	new->catset_str = cil_strdup(orig->catset_str);

	if (orig->catset != NULL && orig->catset_str == NULL) {
		cil_catset_init(&new->catset);
		cil_copy_fill_catset(orig->catset, new->catset);
	}

	*copy = new;

	return SEPOL_OK;
}

int cil_copy_catorder(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_catorder *orig = data;
	struct cil_catorder *new = NULL;

	cil_catorder_init(&new);
	if (orig->cat_list_str != NULL) {
		cil_copy_list(orig->cat_list_str, &new->cat_list_str);
	}

	*copy = new;

	return SEPOL_OK;
}

int cil_copy_dominance(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_sens_dominates *orig = data;
	struct cil_sens_dominates *new = NULL;

	cil_sens_dominates_init(&new);
	if (orig->sens_list_str != NULL) {
		cil_copy_list(orig->sens_list_str, &new->sens_list_str);
	}

	*copy = new;

	return SEPOL_OK;
}

void cil_copy_fill_level(struct cil_level *data, struct cil_level *new)
{
	new->sens_str = cil_strdup(data->sens_str);
	new->catset_str = cil_strdup(data->catset_str);

	if (data->catset != NULL && data->catset_str == NULL) {
		cil_catset_init(&new->catset);
		cil_copy_fill_catset(data->catset, new->catset);
	}
}

int cil_copy_level(__attribute__((unused)) struct cil_db *db, void *data, void **copy, symtab_t *symtab)
{
	struct cil_level *orig = data;
	struct cil_level *new = NULL;
	char *key = orig->datum.name;
	struct cil_symtab_datum *datum = NULL;

	if (key != NULL) {
		cil_symtab_get_datum(symtab, key, &datum);
		if (datum != NULL) {
			cil_log(CIL_INFO, "cil_copy_level: level cannot be redefined\n");
			return SEPOL_ERR;
		}
	}

	cil_level_init(&new);
	cil_copy_fill_level(orig, new);

	*copy = new;

	return SEPOL_OK;
}

void cil_copy_fill_levelrange(struct cil_levelrange *data, struct cil_levelrange *new)
{
	new->low_str = cil_strdup(data->low_str);
	new->high_str = cil_strdup(data->high_str);

	if (data->low != NULL && data->low_str == NULL) {
		cil_level_init(&new->low);
		cil_copy_fill_level(data->low, new->low);
	}

	if (data->high != NULL && data->high_str == NULL) {
		cil_level_init(&new->high);
		cil_copy_fill_level(data->high, new->high);
	}
}

int cil_copy_levelrange(__attribute__((unused)) struct cil_db *db, void *data, void **copy, symtab_t *symtab)
{
	struct cil_levelrange *orig = data;
	struct cil_levelrange *new = NULL;
	char *key = orig->datum.name;
	struct cil_symtab_datum *datum = NULL;

	if (key != NULL) {
		cil_symtab_get_datum(symtab, key, &datum);
		if (datum != NULL) {
			cil_log(CIL_INFO, "cil_copy_levelrange: levelrange cannot be redefined\n");
			return SEPOL_ERR;
		}
	}

	cil_levelrange_init(&new);
	cil_copy_fill_levelrange(orig, new);

	*copy = new;

	return SEPOL_OK;
}

void cil_copy_fill_context(struct cil_context *data, struct cil_context *new)
{
	new->user_str = cil_strdup(data->user_str);
	new->role_str = cil_strdup(data->role_str);
	new->type_str = cil_strdup(data->type_str);
	new->range_str = cil_strdup(data->range_str);

	if (data->range != NULL && data->range_str == NULL) {
		cil_levelrange_init(&new->range);
		cil_copy_fill_levelrange(data->range, new->range);
	}
}

int cil_copy_context(__attribute__((unused)) struct cil_db *db, void *data, void **copy, symtab_t *symtab)
{
	struct cil_context *orig = data;
	struct cil_context *new = NULL;
	char *key = orig->datum.name;
	struct cil_symtab_datum *datum = NULL;

	if (key != NULL) {
		cil_symtab_get_datum(symtab, key, &datum);
		if (datum != NULL) {
			cil_log(CIL_INFO, "cil_copy_context: context cannot be redefined\n");
			return SEPOL_ERR;
		}
	}

	cil_context_init(&new);
	cil_copy_fill_context(orig, new);

	*copy = new;

	return SEPOL_OK;
}

int cil_copy_netifcon(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_netifcon *orig = data;
	struct cil_netifcon *new = NULL;

	cil_netifcon_init(&new);

	new->interface_str = cil_strdup(orig->interface_str);
	new->if_context_str = cil_strdup(orig->if_context_str);
	new->packet_context_str = cil_strdup(orig->packet_context_str);

	if (orig->if_context != NULL && orig->if_context_str == NULL) {
		cil_context_init(&new->if_context);
		cil_copy_fill_context(orig->if_context, new->if_context);
	}

	if (orig->packet_context != NULL && orig->packet_context_str == NULL) {
		cil_context_init(&new->packet_context);
		cil_copy_fill_context(orig->packet_context, new->packet_context);
	}

	*copy = new;

	return SEPOL_OK;
}

int cil_copy_genfscon(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_genfscon *orig = data;
	struct cil_genfscon *new = NULL;

	cil_genfscon_init(&new);

	new->fs_str = cil_strdup(orig->fs_str);
	new->path_str = cil_strdup(orig->path_str);
	new->context_str = cil_strdup(orig->context_str);

	if (orig->context != NULL && orig->context_str == NULL) {
		cil_context_init(&new->context);
		cil_copy_fill_context(orig->context, new->context);
	}

	*copy = new;

	return SEPOL_OK;
}

int cil_copy_filecon(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_filecon *orig = data;
	struct cil_filecon *new = NULL;

	cil_filecon_init(&new);

	new->root_str = cil_strdup(orig->root_str);
	new->path_str = cil_strdup(orig->path_str);
	new->type = orig->type;
	new->context_str = cil_strdup(orig->context_str);

	if (orig->context != NULL && orig->context_str == NULL) {
		cil_context_init(&new->context);
		cil_copy_fill_context(orig->context, new->context);
	}

	*copy = new;

	return SEPOL_OK;
}

int cil_copy_nodecon(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_nodecon *orig = data;
	struct cil_nodecon *new = NULL;

	cil_nodecon_init(&new);

	new->addr_str = cil_strdup(orig->addr_str);
	new->mask_str = cil_strdup(orig->mask_str);
	new->context_str = cil_strdup(orig->context_str);

	if (orig->addr != NULL && orig->addr_str == NULL) {
		cil_ipaddr_init(&new->addr);
		cil_copy_fill_ipaddr(orig->addr, new->addr);
	}

	if (orig->mask != NULL && orig->mask_str == NULL) {
		cil_ipaddr_init(&new->mask);
		cil_copy_fill_ipaddr(orig->mask, new->mask);
	}

	if (orig->context != NULL && orig->context_str == NULL) {
		cil_context_init(&new->context);
		cil_copy_fill_context(orig->context, new->context);
	}

	*copy = new;

	return SEPOL_OK;
}

int cil_copy_portcon(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_portcon *orig = data;
	struct cil_portcon *new = NULL;

	cil_portcon_init(&new);

	new->proto = orig->proto;
	new->port_low = orig->port_low;
	new->port_high = orig->port_high;
	new->context_str = cil_strdup(orig->context_str);

	if (orig->context != NULL && orig->context_str == NULL) {
		cil_context_init(&new->context);
		cil_copy_fill_context(orig->context, new->context);
	}

	*copy = new;

	return SEPOL_OK;
}

int cil_copy_pirqcon(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_pirqcon *orig = data;
	struct cil_pirqcon *new = NULL;

	cil_pirqcon_init(&new);

	new->pirq = orig->pirq;
	new->context_str = cil_strdup(orig->context_str);

	if (orig->context != NULL && orig->context_str == NULL) {
		cil_context_init(&new->context);
		cil_copy_fill_context(orig->context, new->context);
	}

	*copy = new;

	return SEPOL_OK;
}

int cil_copy_iomemcon(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_iomemcon *orig = data;
	struct cil_iomemcon *new = NULL;

	cil_iomemcon_init(&new);

	new->iomem_low = orig->iomem_low;
	new->iomem_high = orig->iomem_high;
	new->context_str = cil_strdup(orig->context_str);

	if (orig->context != NULL && orig->context_str == NULL) {
		cil_context_init(&new->context);
		cil_copy_fill_context(orig->context, new->context);
	}

	*copy = new;

	return SEPOL_OK;
}

int cil_copy_ioportcon(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_ioportcon *orig = data;
	struct cil_ioportcon *new = NULL;

	cil_ioportcon_init(&new);

	new->ioport_low = orig->ioport_low;
	new->ioport_high = orig->ioport_high;
	new->context_str = cil_strdup(orig->context_str);

	if (orig->context != NULL && orig->context_str == NULL) {
		cil_context_init(&new->context);
		cil_copy_fill_context(orig->context, new->context);
	}

	*copy = new;

	return SEPOL_OK;
}

int cil_copy_pcidevicecon(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_pcidevicecon *orig = data;
	struct cil_pcidevicecon *new = NULL;

	cil_pcidevicecon_init(&new);

	new->dev = orig->dev;
	new->context_str = cil_strdup(orig->context_str);

	if (orig->context != NULL && orig->context_str == NULL) {
		cil_context_init(&new->context);
		cil_copy_fill_context(orig->context, new->context);
	}

	*copy = new;

	return SEPOL_OK;
}

int cil_copy_fsuse(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_fsuse *orig = data;
	struct cil_fsuse *new = NULL;

	cil_fsuse_init(&new);

	new->type = orig->type;
	new->fs_str = cil_strdup(orig->fs_str);
	new->context_str = cil_strdup(orig->context_str);

	if (orig->context != NULL && orig->context_str == NULL) {
		cil_context_init(&new->context);
		cil_copy_fill_context(orig->context, new->context);
	}

	*copy = new;

	return SEPOL_OK;
}

int cil_copy_expr(struct cil_db *db, struct cil_list *orig, struct cil_list **new)
{
	struct cil_list_item *curr;

	if (orig == NULL) {
		*new = NULL;
		return SEPOL_OK;
	}

	cil_list_init(new, orig->flavor);

	cil_list_for_each(curr, orig) {
		switch (curr->flavor) {
		case CIL_LIST: {
			struct cil_list *sub_list;
			cil_copy_expr(db, curr->data, &sub_list);
			cil_list_append(*new, CIL_LIST, sub_list);
			break;
		}
		case CIL_STRING:
			cil_list_append(*new, CIL_STRING, cil_strdup(curr->data));
			break;
		case CIL_DATUM:
			cil_list_append(*new, curr->flavor, curr->data);
			break;
		case CIL_OP:
			cil_list_append(*new, curr->flavor,
							cil_flavordup(*((enum cil_flavor *)curr->data)));
			break;
		case CIL_CONS_OPERAND:
			cil_list_append(*new, curr->flavor,
							cil_flavordup(*((enum cil_flavor *)curr->data)));
			break;
		default:
			cil_log(CIL_INFO, "Unknown flavor %d in expression being copied\n",curr->flavor);
			cil_list_append(*new, curr->flavor, curr->data);
			break;
		}
	}

	return SEPOL_OK;
}

int cil_copy_constrain(struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_constrain *orig = data;
	struct cil_constrain *new = NULL;

	cil_constrain_init(&new);

	cil_copy_fill_classperms(orig->classperms, &new->classperms);

	cil_copy_expr(db, orig->str_expr, &new->str_expr);
	cil_copy_expr(db, orig->datum_expr, &new->datum_expr);

	*copy = new;

	return SEPOL_OK;
}

int cil_copy_validatetrans(struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_validatetrans *orig = data;
	struct cil_validatetrans *new = NULL;

	cil_validatetrans_init(&new);

	new->class_str = cil_strdup(orig->class_str);

	cil_copy_expr(db, orig->str_expr, &new->str_expr);
	cil_copy_expr(db, orig->datum_expr, &new->datum_expr);

	*copy = new;

	return SEPOL_OK;
}

int cil_copy_call(struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_call *orig = data;
	struct cil_call *new = NULL;
	int rc = SEPOL_ERR;

	cil_call_init(&new);

	new->macro_str = cil_strdup(orig->macro_str);

	if (orig->args_tree != NULL) {
		cil_tree_init(&new->args_tree);
		cil_tree_node_init(&new->args_tree->root);
		rc = cil_copy_ast(db, orig->args_tree->root, new->args_tree->root);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}
	
	new->copied = orig->copied;

	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_call(new);
	return rc;
}

int cil_copy_macro(__attribute__((unused)) struct cil_db *db, void *data, void **copy, symtab_t *symtab)
{
	struct cil_macro *orig = data;
	char *key = orig->datum.name;
	struct cil_symtab_datum *datum = NULL;

	cil_symtab_get_datum(symtab, key, &datum);
	if (datum == NULL) {
		struct cil_macro *new;
		cil_macro_init(&new);
		cil_symtab_array_init(new->symtab, cil_sym_sizes[CIL_SYM_ARRAY_MACRO]);
		cil_copy_list(orig->params, &new->params);

		*copy = new;

	} else {
		struct cil_list_item *curr_orig = NULL;
		struct cil_list_item *curr_new = NULL;
		struct cil_param *param_orig = NULL;
		struct cil_param *param_new = NULL;

		if (((struct cil_macro*)datum)->params != NULL) {
			curr_new = ((struct cil_macro*)datum)->params->head;
		}

		if (orig->params != NULL) {
			curr_orig = orig->params->head;
		}

		if (curr_orig != NULL && curr_new != NULL) {
			while (curr_orig != NULL) {
				if (curr_new == NULL) {
					goto exit;
				}

				param_orig = (struct cil_param*)curr_orig->data;
				param_new = (struct cil_param*)curr_new->data;
				if (strcmp(param_orig->str, param_new->str)) {
					goto exit;
				} else if (param_orig->flavor != param_new->flavor) {
					goto exit;
				}

				curr_orig = curr_orig->next;
				curr_new = curr_new->next;
			}

			if (curr_new != NULL) {
				goto exit;
			}
		} else if (!(curr_orig == NULL && curr_new == NULL)) {
			goto exit;
		}

		*copy = datum;
	}

	return SEPOL_OK;

exit:
	cil_log(CIL_INFO, "cil_copy_macro: macro cannot be redefined\n");
	return SEPOL_ERR;
}

int cil_copy_optional(__attribute__((unused)) struct cil_db *db, void *data, void **copy, symtab_t *symtab)
{
	struct cil_optional *orig = data;
	char *key = orig->datum.name;
	struct cil_symtab_datum *datum = NULL;

	cil_symtab_get_datum(symtab, key, &datum);
	if (datum == NULL) {
		struct cil_optional *new;
		cil_optional_init(&new);
		*copy = new;
	} else {
		*copy = datum;
	}

	return SEPOL_OK;
}

void cil_copy_fill_ipaddr(struct cil_ipaddr *data, struct cil_ipaddr *new)
{
	new->family = data->family;
	memcpy(&new->ip, &data->ip, sizeof(data->ip));
}

int cil_copy_ipaddr(__attribute__((unused)) struct cil_db *db, void *data, void **copy, symtab_t *symtab)
{
	struct cil_ipaddr *orig = data;
	struct cil_ipaddr *new = NULL;
	char * key = orig->datum.name;	
	struct cil_symtab_datum *datum = NULL;

	cil_symtab_get_datum(symtab, key, &datum);
	if (datum != NULL) {
		cil_log(CIL_INFO, "cil_copy_ipaddr: ipaddress cannot be redefined\n");
		return SEPOL_ERR;
	}

	cil_ipaddr_init(&new);
	cil_copy_fill_ipaddr(orig, new);

	*copy = new;

	return SEPOL_OK;
}

int cil_copy_condblock(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_condblock *orig = data;
	struct cil_condblock *new = *copy;
	cil_condblock_init(&new);
	new->flavor = orig->flavor;
	*copy = new;

	return SEPOL_OK;
}

int cil_copy_boolif(struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_booleanif *orig = data;
	struct cil_booleanif *new = NULL;

	cil_boolif_init(&new);

	cil_copy_expr(db, orig->str_expr, &new->str_expr);
	cil_copy_expr(db, orig->datum_expr, &new->datum_expr);

	*copy = new;

	return SEPOL_OK;
}

int cil_copy_tunif(struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_tunableif *orig = data;
	struct cil_tunableif *new = NULL;

	cil_tunif_init(&new);

	cil_copy_expr(db, orig->str_expr, &new->str_expr);
	cil_copy_expr(db, orig->datum_expr, &new->datum_expr);

	*copy = new;

	return SEPOL_OK;
}

int __cil_copy_node_helper(struct cil_tree_node *orig, __attribute__((unused)) uint32_t *finished, void *extra_args)
{
	int rc = SEPOL_ERR;
	struct cil_tree_node *parent = NULL;
	struct cil_tree_node *new = NULL;
	struct cil_db *db = NULL;
	struct cil_args_copy *args = NULL;
	struct cil_tree_node *namespace = NULL;
	struct cil_param *param = NULL;
	enum cil_sym_index sym_index = CIL_SYM_UNKNOWN;
	symtab_t *symtab = NULL;
	void *data = NULL;
	int (*copy_func)(struct cil_db *db, void *data, void **copy, symtab_t *symtab) = NULL;

	if (orig == NULL || extra_args == NULL) {
		goto exit;
	}

	args = extra_args;
	parent = args->dest;
	db = args->db;


	switch (orig->flavor) {
	case CIL_BLOCK:
		copy_func = &cil_copy_block;
		break;
	case CIL_BLOCKABSTRACT:
		copy_func = &cil_copy_blockabstract;
		break;
	case CIL_BLOCKINHERIT:
		copy_func = &cil_copy_blockinherit;
		break;
	case CIL_POLICYCAP:
		copy_func = &cil_copy_policycap;
		break;
	case CIL_PERM:
		copy_func = &cil_copy_perm;
		break;
	case CIL_MAP_PERM:
		copy_func =  &cil_copy_map_perm;
		break;
	case CIL_MAP_CLASS:
		copy_func = &cil_copy_map_class;
		break;
	case CIL_CLASSMAPPING:
		copy_func = &cil_copy_classmapping;
		break;
	case CIL_CLASS:
		copy_func = &cil_copy_class;
		break;
	case CIL_CLASSPERMSET:
		copy_func = &cil_copy_classpermset;
		break;
	case CIL_COMMON:
		copy_func = &cil_copy_common;
		break;
	case CIL_CLASSCOMMON:
		copy_func = &cil_copy_classcommon;
		break;
	case CIL_SID:
		copy_func = &cil_copy_sid;
		break;
	case CIL_SIDCONTEXT:
		copy_func = &cil_copy_sidcontext;
		break;
	case CIL_USER:
		copy_func = &cil_copy_user;
		break;
	case CIL_USERROLE:
		copy_func = &cil_copy_userrole;
		break;
	case CIL_USERLEVEL:
		copy_func = &cil_copy_userlevel;
		break;
	case CIL_USERRANGE:
		copy_func = &cil_copy_userrange;
		break;
	case CIL_USERBOUNDS:
		copy_func = &cil_copy_userbounds;
		break;
	case CIL_USERPREFIX:
		copy_func = &cil_copy_userprefix;
		break;
	case CIL_ROLE:
		copy_func = &cil_copy_role;
		break;
	case CIL_ROLETYPE:
		copy_func = &cil_copy_roletype;
		break;
	case CIL_ROLEBOUNDS:
		copy_func = &cil_copy_rolebounds;
		break;
	case CIL_ROLEATTRIBUTE:
		copy_func = &cil_copy_roleattribute;
		break;
	case CIL_ROLEATTRIBUTESET:
		copy_func = &cil_copy_roleattributeset;
		break;
	case CIL_ROLEALLOW:
		copy_func = &cil_copy_roleallow;
		break;
	case CIL_TYPE:
		copy_func = &cil_copy_type;
		break;
	case CIL_TYPEBOUNDS:
		copy_func = &cil_copy_typebounds;
		break;
	case CIL_TYPEPERMISSIVE:
		copy_func = cil_copy_typepermissive;
		break;
	case CIL_TYPEATTRIBUTE:
		copy_func = &cil_copy_typeattribute;
		break;
	case CIL_TYPEATTRIBUTESET:
		copy_func = &cil_copy_typeattributeset;
		break;
	case CIL_TYPEALIAS:
		copy_func = &cil_copy_typealias;
		break;
	case CIL_ROLETRANSITION:
		copy_func = &cil_copy_roletransition;
		break;
	case CIL_NAMETYPETRANSITION:
		copy_func = &cil_copy_nametypetransition;
		break;
	case CIL_RANGETRANSITION:
		copy_func = &cil_copy_rangetransition;
		break;
	case CIL_TUNABLE:
		copy_func = &cil_copy_bool;
		break;
	case CIL_BOOL:
		copy_func = &cil_copy_bool;
		break;
	case CIL_AVRULE:
		copy_func = &cil_copy_avrule;
		break;
	case CIL_TYPE_RULE:
		copy_func = &cil_copy_type_rule;
		break;
	case CIL_SENS:
		copy_func = &cil_copy_sens;
		break;
	case CIL_SENSALIAS:
		copy_func = &cil_copy_sensalias;
		break;
	case CIL_CAT:
		copy_func = &cil_copy_cat;
		break;
	case CIL_CATALIAS:
		copy_func = &cil_copy_catalias;
		break;
	case CIL_CATRANGE:
		copy_func = &cil_copy_catrange;
		break;
	case CIL_CATSET:
		copy_func = &cil_copy_catset;
		break;
	case CIL_SENSCAT:
		copy_func = &cil_copy_senscat;
		break;
	case CIL_CATORDER:
		copy_func = &cil_copy_catorder;
		break;
	case CIL_DOMINANCE:
		copy_func = &cil_copy_dominance;
		break;
	case CIL_LEVEL:
		copy_func = &cil_copy_level;
		break;
	case CIL_LEVELRANGE:
		copy_func = &cil_copy_levelrange;
		break;
	case CIL_CONTEXT:
		copy_func = &cil_copy_context;
		break;
	case CIL_NETIFCON:
		copy_func = &cil_copy_netifcon;
		break;
	case CIL_GENFSCON:
		copy_func = &cil_copy_genfscon;
		break;
	case CIL_FILECON:
		copy_func = &cil_copy_filecon;
		break;
	case CIL_NODECON:
		copy_func = &cil_copy_nodecon;
		break;
	case CIL_PORTCON:
		copy_func = &cil_copy_portcon;
		break;
	case CIL_PIRQCON:
		copy_func = &cil_copy_pirqcon;
		break;
	case CIL_IOMEMCON:
		copy_func = &cil_copy_iomemcon;
		break;
	case CIL_IOPORTCON:
		copy_func = &cil_copy_ioportcon;
		break;
	case CIL_PCIDEVICECON:
		copy_func = &cil_copy_pcidevicecon;
		break;
	case CIL_FSUSE:
		copy_func = &cil_copy_fsuse;
		break;
	case CIL_CONSTRAIN:
	case CIL_MLSCONSTRAIN:
		copy_func = &cil_copy_constrain;
		break;
	case CIL_VALIDATETRANS:
	case CIL_MLSVALIDATETRANS:
		copy_func = &cil_copy_validatetrans;
		break;
	case CIL_CALL:
		copy_func = &cil_copy_call;
		break;
	case CIL_MACRO:
		copy_func = &cil_copy_macro;
		break;
	case CIL_PARSE_NODE:
		copy_func = &cil_copy_parse;
		break;
	case CIL_OPTIONAL:
		copy_func = &cil_copy_optional;
		break;
	case CIL_IPADDR:
		copy_func = &cil_copy_ipaddr;
		break;
	case CIL_CONDBLOCK:
		copy_func = &cil_copy_condblock;
		break;
	case CIL_BOOLEANIF:
		copy_func = &cil_copy_boolif;
		break;
	case CIL_TUNABLEIF:
		copy_func = &cil_copy_tunif;
		break;
	default:
		goto exit;
	}

	if (orig->flavor >= CIL_MIN_DECLARATIVE) {
		rc = cil_flavor_to_symtab_index(orig->flavor, &sym_index);
		if (rc != SEPOL_OK) {
			goto exit;
		}

		rc = cil_get_symtab(db, parent, &symtab, sym_index);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	rc = (*copy_func)(db, orig->data, &data, symtab);
	if (rc == SEPOL_OK) {
		cil_tree_node_init(&new);

		new->parent = parent;
		new->line = orig->line;
		new->path = orig->path;
		new->flavor = orig->flavor;
		new->data = data;

		if (orig->flavor >= CIL_MIN_DECLARATIVE) {
			rc = cil_symtab_insert(symtab, ((struct cil_symtab_datum*)orig->data)->name, ((struct cil_symtab_datum*)data), new);

			namespace = new;
			while (namespace->flavor != CIL_MACRO && namespace->flavor != CIL_BLOCK && namespace->flavor != CIL_ROOT) {
				namespace = namespace->parent;
			}

			if (namespace->flavor == CIL_MACRO) {
				struct cil_macro *macro = namespace->data;
				struct cil_list *param_list = macro->params;
				if (param_list != NULL) {
					struct cil_list_item *item;
					cil_list_for_each(item, param_list) {
						param = item->data;
						if (param->flavor == new->flavor) {
							if (!strcmp(param->str, ((struct cil_symtab_datum*)new->data)->name)) {
								cil_log(CIL_ERR, "%s %s shadows a macro parameter (%s line:%d)\n", cil_node_to_string(new), ((struct cil_symtab_datum*)orig->data)->name, orig->path, orig->line);
								cil_log(CIL_ERR, "Note: macro declaration (%s line:%d)\n", namespace->path, namespace->line);
								rc = SEPOL_ERR;
								goto exit;
							}
						}
					}
				}
			}
		}

		if (parent->cl_head == NULL) {
			parent->cl_head = new;
			parent->cl_tail = new;
		} else {
			parent->cl_tail->next = new;
			parent->cl_tail = new;
		}

		if (orig->cl_head != NULL) {
			args->dest = new;
		}
	} else {
		goto exit;
	}

	return SEPOL_OK;

exit:
	cil_tree_node_destroy(&new);
	return rc;
}

int __cil_copy_last_child_helper(__attribute__((unused)) struct cil_tree_node *orig, void *extra_args)
{
	struct cil_tree_node *node = NULL;
	struct cil_args_copy *args = NULL;

	args = extra_args;
	node = args->dest;

	if (node->flavor != CIL_ROOT) {
		args->dest = node->parent;
	}

	return SEPOL_OK;
}

// dest is the parent node to copy into
// if the copy is for a call to a macro, dest should be a pointer to the call
int cil_copy_ast(struct cil_db *db, struct cil_tree_node *orig, struct cil_tree_node *dest)
{
	int rc = SEPOL_ERR;
	struct cil_args_copy extra_args;

	extra_args.dest = dest;
	extra_args.db = db;

	rc = cil_tree_walk(orig, __cil_copy_node_helper, NULL,  __cil_copy_last_child_helper, &extra_args);
	if (rc != SEPOL_OK) {
		cil_log(CIL_INFO, "cil_tree_walk failed, rc: %d\n", rc);
		goto exit;
	}

	return SEPOL_OK;

exit:
	return rc;
}

