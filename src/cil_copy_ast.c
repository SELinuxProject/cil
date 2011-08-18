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

#include "cil.h"
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

void cil_copy_list(struct cil_list *orig, struct cil_list **copy)
{
	struct cil_list *new = NULL;
	struct cil_list *new_sub = NULL;
	struct cil_list_item *new_item = NULL;
	struct cil_list_item *orig_item = NULL;

	if (orig == NULL) {
		return;
	}

	orig_item = orig->head;
	cil_list_init(&new);
	while(orig_item != NULL) {
		if (new_item == NULL) {
			cil_list_item_init(&new_item);
			new->head = new_item;
		} else {
			cil_list_item_init(&new_item->next);
			new_item = new_item->next;
		}

		if (orig_item->flavor == CIL_AST_STR) {
			new_item->data = cil_strdup(orig_item->data);
		} else if (orig_item->flavor == CIL_LIST) {
			cil_copy_list((struct cil_list*)orig_item->data, &new_sub);
			new_item->data = new_sub;
		}	
		new_item->flavor = orig_item->flavor;
		orig_item = orig_item->next;
	}

	*copy = new;
}

int cil_copy_block(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_block *new = NULL;
	int rc = SEPOL_ERR;
	char *key = NULL;

	rc = cil_block_init(&new);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	key = ((struct cil_symtab_datum *)orig->data)->name;

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_block: cil_symtab_insert failed, rc: %d\n", rc);
		cil_destroy_block(new);
		goto exit;
	}

	rc = cil_symtab_array_init(new->symtab, CIL_SYM_NUM);
	if (rc != SEPOL_OK) {
		printf("cil_copy_block: cil_symtab_array_init failed, rc: %d\n", rc);
		cil_destroy_block(new);
		goto exit;
	}

	copy->data = new;

	return SEPOL_OK;

exit:
	return rc;
}

int cil_copy_perm(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_perm *new = NULL;
	int rc = SEPOL_ERR;
	char *key = NULL;

	rc = cil_perm_init(&new);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	key = ((struct cil_symtab_datum *)orig->data)->name;

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_perm: cil_symtab_insert failed, rc: %d\n", rc);
		free(new);
		goto exit;
	}

	copy->data = new;

	return SEPOL_OK;

exit:
	return rc;
}

int cil_copy_class(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_class *new = NULL;
	int rc = SEPOL_ERR;
	char *key = NULL;

	rc = cil_class_init(&new);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	key = ((struct cil_symtab_datum *)orig->data)->name;

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_class: cil_symtab_insert failed, rc: %d\n", rc);
		cil_destroy_class(new);
		goto exit;
	}

	rc = symtab_init(&new->perms, CIL_SYM_SIZE);
	if (rc != SEPOL_OK) {
		printf("cil_copy_class: symtab_init failed, rc: %d\n", rc);
		cil_destroy_class(new);
		goto exit;
	}

	new->common = NULL;
	copy->data = new;
		
	return SEPOL_OK;

exit:
	return rc;
}

int cil_copy_common(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_common *new;
	int rc = cil_common_init(&new);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	char *key = ((struct cil_symtab_datum *)orig->data)->name;
	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_common: cil_symtab_insert failed, rc: %d\n", rc);
		cil_destroy_common(new);
		goto exit;
	}
	rc = symtab_init(&new->perms, CIL_SYM_SIZE);
	if (rc != SEPOL_OK) {
		printf("cil_copy_common: symtab_init failed, rc: %d\n", rc);
		cil_destroy_common(new);
		goto exit;
	}
	copy->data = new;

	return SEPOL_OK;

exit:
	return rc;
}

void cil_copy_classcommon(struct cil_classcommon *orig, struct cil_classcommon **copy)
{
	struct cil_classcommon *new = NULL;
	int rc = SEPOL_ERR;

	rc = cil_classcommon_init(&new);
	if (rc != SEPOL_OK) {
		return;
	}

	new->class_str = cil_strdup(orig->class_str);
	new->common_str = cil_strdup(orig->common_str);

	*copy = new;
}

int cil_copy_sid(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_sid *new = NULL;
	int rc = SEPOL_ERR;
	char *key = NULL;

	rc = cil_sid_init(&new);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	key = ((struct cil_symtab_datum*)orig->data)->name;

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_sid: cil_symtab_insert failed, rc: %d\n", rc);
		free(new);
		goto exit;
	}

	copy->data = new;

	return SEPOL_OK;

exit:
	return rc;
}

int cil_copy_sidcontext(struct cil_tree_node *orig, struct cil_tree_node *copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_sidcontext *new = NULL;
	int rc = SEPOL_ERR;

	rc = cil_sidcontext_init(&new);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	new->context_str = cil_strdup(((struct cil_sidcontext*)orig->data)->context_str);
	
	if (((struct cil_sidcontext*)orig->data)->context != NULL) {
		rc = cil_context_init(&new->context);

		if (rc != SEPOL_OK) {
			cil_destroy_sidcontext(new);
			goto exit;
		}

		cil_copy_fill_context(((struct cil_sidcontext*)orig->data)->context, new->context);
	}

	copy->data = new;
	
	return SEPOL_OK;

exit:
	return rc;
}

int cil_copy_user(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_user *new = NULL;
	int rc = SEPOL_ERR;
	char *key = NULL;

	rc = cil_user_init(&new);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	key = ((struct cil_symtab_datum *)orig->data)->name;

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_user: cil_symtab_insert failed, rc: %d\n", rc);
		free(new);
		goto exit;
	}

	copy->data = new;

	return SEPOL_OK;

exit:
	return rc;
}

int cil_copy_role(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_role *new = NULL;
	int rc = SEPOL_ERR;
	char *key = NULL;

	rc = cil_role_init(&new);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	key = ((struct cil_symtab_datum *)orig->data)->name;

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_role: cil_symtab_insert failed, rc: %d\n", rc);
		free(new);
		goto exit;
	}

	copy->data = new;

	return SEPOL_OK;

exit:
	return rc;
}

void cil_copy_userrole(struct cil_userrole *orig, struct cil_userrole **copy)
{
	struct cil_userrole *new = NULL;
	int rc = SEPOL_ERR;

	rc = cil_userrole_init(&new);
	if (rc != SEPOL_OK) {
		return;
	}

	new->user_str = cil_strdup(orig->user_str);
	new->role_str = cil_strdup(orig->role_str);

	*copy = new;
}

void cil_copy_userlevel(struct cil_userlevel *orig, struct cil_userlevel **copy)
{
	struct cil_userlevel *new = NULL;
	int rc = SEPOL_ERR;

	rc = cil_userlevel_init(&new);
	if (rc != SEPOL_OK) {
		return;
	}

	new->user_str = cil_strdup(orig->user_str);
	new->level_str = cil_strdup(orig->level_str);

	if (orig->level != NULL) {
		rc = cil_level_init(&new->level);
		if (rc != SEPOL_OK) {
			goto exit;
		}

		cil_copy_fill_level(orig->level, new->level);
	}

	*copy = new;

exit:
	return;
}

void cil_copy_userrange(struct cil_userrange *orig, struct cil_userrange **copy)
{
	struct cil_userrange *new = NULL;
	int rc = SEPOL_ERR;

	rc = cil_userrange_init(&new);
	if (rc != SEPOL_OK) {
		return;
	}

	new->user_str = cil_strdup(orig->user_str);
	new->range_str = cil_strdup(orig->range_str);

	if (orig->range != NULL) {
		rc = cil_levelrange_init(&new->range);
		if (rc != SEPOL_OK) {
			goto exit;
		}

		cil_copy_fill_levelrange(orig->range, new->range);
	}

	*copy = new;

exit:
	return;
}

int cil_copy_type(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_type *new = NULL;
	int rc = SEPOL_ERR;
	char *key = NULL;

	rc = cil_type_init(&new);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	key = ((struct cil_symtab_datum *)orig->data)->name;

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_type: cil_symtab_insert failed, rc: %d\n", rc);
		free(new);
		goto exit;
	}

	copy->data = new;

	return SEPOL_OK;

exit:
	return rc;
}

int cil_copy_typeattribute(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_typeattribute *new = NULL;
	int rc = SEPOL_ERR;
	char *key = NULL;

	rc = cil_typeattribute_init(&new);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	key = ((struct cil_symtab_datum *)orig->data)->name;

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_typeattribute: cil_symtab_insert failed, rc: %d\n", rc);
		free(new);
		goto exit;
	}

	copy->data = new;

	return SEPOL_OK;

exit:
	return rc;
}

void cil_copy_typeattributetypes(struct cil_typeattributetypes *orig, struct cil_typeattributetypes **copy)
{
	struct cil_typeattributetypes *new = NULL;
	int rc = SEPOL_ERR;

	rc = cil_typeattributetypes_init(&new);
	if (rc != SEPOL_OK) {
		return;
	}

	new->attr_str = cil_strdup(orig->attr_str);

	cil_copy_list(orig->types_list_str, &new->types_list_str);
	cil_copy_list(orig->neg_list_str, &new->neg_list_str);

	*copy = new;
}

int cil_copy_typealias(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_typealias *new = NULL;
	int rc = SEPOL_ERR;
	char *key = NULL;

	rc = cil_typealias_init(&new);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	key = ((struct cil_symtab_datum*)orig->data)->name;

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_typealias: cil_symtab_insert failed, rc: %d\n", rc);
		cil_destroy_typealias(new);
		goto exit;
	}

	new->type_str = cil_strdup(((struct cil_typealias*)orig->data)->type_str);
	copy->data = new;
	
	return SEPOL_OK;

exit:
	return rc;
}

void cil_copy_filetransition(struct cil_filetransition *orig, struct cil_filetransition **copy)
{
	struct cil_filetransition *new = NULL;
	int rc = SEPOL_ERR;

	rc = cil_filetransition_init(&new);
	if (rc != SEPOL_OK) {
		return;
	}

	new->src_str = cil_strdup(orig->src_str);
	new->exec_str = cil_strdup(orig->exec_str);
	new->proc_str = cil_strdup(orig->proc_str);
	new->dest_str = cil_strdup(orig->dest_str);
	new->path_str = cil_strdup(orig->path_str);

	*copy = new;
}

void cil_copy_rangetransition(struct cil_rangetransition *orig, struct cil_rangetransition **copy)
{
	struct cil_rangetransition *new = NULL;
	int rc = SEPOL_ERR;

	rc = cil_rangetransition_init(&new);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	new->src_str = cil_strdup(orig->src_str);
	new->exec_str = cil_strdup(orig->exec_str);
	new->obj_str = cil_strdup(orig->obj_str);
	new->range_str = cil_strdup(orig->range_str);

	if (orig->range != NULL) {
		rc = cil_levelrange_init(&new->range);
		if (rc != SEPOL_OK) {
			goto exit;
		}

		cil_copy_fill_levelrange(orig->range, new->range);
	}

	*copy = new;

exit:
	return;
}

int cil_copy_bool(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_bool *new = NULL;
	int rc = SEPOL_ERR;
	char *key = NULL;

	rc = cil_bool_init(&new);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	key = ((struct cil_symtab_datum *)orig->data)->name;

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_bool: cil_symtab_insert failed, rc: %d\n", rc);
		cil_destroy_bool(new);
		goto exit;
	}

	new->value = ((struct cil_bool *)orig->data)->value;
	copy->data = new;

	return SEPOL_OK;

exit:
	return rc;
}

void cil_copy_avrule(struct cil_avrule *orig, struct cil_avrule **copy)
{
	struct cil_avrule *new = NULL;
	int rc = SEPOL_ERR;

	rc = cil_avrule_init(&new);
	if (rc != SEPOL_OK) {
		return;
	}

	new->rule_kind = orig->rule_kind;
	new->src_str = cil_strdup(orig->src_str);
	new->tgt_str = cil_strdup(orig->tgt_str);
	new->obj_str = cil_strdup(orig->obj_str);
	cil_copy_list(orig->perms_list_str, &new->perms_list_str);
	new->permset_str = cil_strdup(orig->permset_str);
	
	*copy = new;
}

void cil_copy_type_rule(struct cil_type_rule *orig, struct cil_type_rule **copy)
{
	struct cil_type_rule *new = NULL;
	int rc = SEPOL_ERR;

	rc = cil_type_rule_init(&new);
	if (rc != SEPOL_OK) {
		return;
	}

	new->rule_kind = orig->rule_kind;
	new->src_str = cil_strdup(orig->src_str);
	new->tgt_str = cil_strdup(orig->tgt_str);
	new->obj_str = cil_strdup(orig->obj_str);
	new->result_str = cil_strdup(orig->result_str);

	*copy = new;
}

int cil_copy_sens(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_sens *new = NULL;
	int rc = SEPOL_ERR;
	char *key = NULL;

	rc = cil_sens_init(&new);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	key = ((struct cil_symtab_datum*)orig->data)->name;

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_sens: cil_symtab_insert failed, rc: %d\n", rc);
		cil_destroy_sensitivity(new);
		goto exit;
	}

	copy->data = new;

	return SEPOL_OK;

exit:
	return rc;
}

int cil_copy_sensalias(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_sensalias *new = NULL;
	int rc = SEPOL_ERR;
	char *key = NULL;

	rc = cil_sensalias_init(&new);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	key = ((struct cil_symtab_datum*)orig->data)->name;

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_sensalias: cil_symtab_insert failed, rc: %d\n", rc);
		cil_destroy_sensalias(new);
		goto exit;
	}

	new->sens_str = cil_strdup(((struct cil_sensalias*)orig->data)->sens_str);
	copy->data = new;

	return SEPOL_OK;

exit:
	return rc;
}

int cil_copy_cat(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_cat *new = NULL;
	int rc = SEPOL_ERR;
	char *key = NULL;

	rc = cil_cat_init(&new);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	key = ((struct cil_symtab_datum*)orig->data)->name;

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_cat: cil_symtab_insert failed, rc: %d\n", rc);
		free(new);
		goto exit;
	}

	copy->data = new;

	return SEPOL_OK;

exit:
	return rc;
}

int cil_copy_catalias(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_catalias *new = NULL;
	int rc = SEPOL_ERR;
	char *key = NULL;

	rc = cil_catalias_init(&new);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	key = ((struct cil_symtab_datum*)orig->data)->name;

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_catalias: cil_symtab_insert failed, rc: %d\n", rc);
		cil_destroy_catalias(new);
		goto exit;
	}

	new->cat_str = cil_strdup(((struct cil_catalias*)orig->data)->cat_str);
	copy->data = new;

	return SEPOL_OK;

exit:
	return rc;
}

void cil_copy_fill_catrange(struct cil_catrange *orig, struct cil_catrange *new)
{
	new->cat_low_str = cil_strdup(orig->cat_low_str);
	new->cat_high_str = cil_strdup(orig->cat_high_str);
}

int cil_copy_catrange(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_catrange *new = NULL;
	struct cil_catrange *old = NULL;
	int rc = SEPOL_ERR;
	char *key = NULL;

	rc = cil_catrange_init(&new);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	old = orig->data;
	key = old->datum.name;

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_catrange: cil_symtab_insert failed, rc: %d\n", rc);
		cil_destroy_catrange(new);
		goto exit;
	}

	new->cat_low_str = cil_strdup(old->cat_low_str);
	new->cat_high_str = cil_strdup(old->cat_high_str);
	copy->data = new;

	return SEPOL_OK;

exit:
	return rc;
}

void cil_copy_fill_catset(struct cil_catset *orig, struct cil_catset *new)
{
	struct cil_list_item *orig_item;
	struct cil_list_item *new_item;

	cil_list_init(&new->cat_list_str);

	for (orig_item = orig->cat_list_str->head; orig_item != NULL; orig_item = orig_item->next) {
		cil_list_item_init(&new_item);

		switch (orig_item->flavor) {
		case CIL_CATRANGE: {
			struct cil_catrange *catrange = NULL;
			cil_catrange_init(&catrange);
			cil_copy_fill_catrange(orig_item->data, catrange);
			new_item->flavor = CIL_CATRANGE;
			new_item->data = catrange;
			break;
		}
		case CIL_AST_STR: {
			new_item->flavor = CIL_AST_STR;
			new_item->data = cil_strdup(orig_item->data);
			break;
		}
		default:
			break;
		}

		cil_list_append_item(new->cat_list_str, new_item);
	}
}

int cil_copy_catset(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_catset *new = NULL;
	struct cil_catset *old = NULL;
	int rc = SEPOL_ERR;
	char *key = NULL;

	rc = cil_catset_init(&new);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	old = orig->data;
	key = old->datum.name;

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_catset: cil_symtab_insert failed, rc: %d\n", rc);
		cil_destroy_catset(new);
		goto exit;
	}

	cil_copy_fill_catset(old, new);

	copy->data = new;

	return SEPOL_OK;

exit:
	return rc;

}

void cil_copy_senscat(struct cil_senscat *orig, struct cil_senscat **copy)
{
	struct cil_senscat *new = NULL;
	int rc = SEPOL_ERR;

	rc = cil_senscat_init(&new);
	if (rc != SEPOL_OK) {
		return;
	}

	new->sens_str = cil_strdup(orig->sens_str);
	new->catset_str = cil_strdup(orig->catset_str);

	if (orig->catset != NULL) {
		cil_catset_init(&new->catset);
		cil_copy_fill_catset(orig->catset, new->catset);
	}

	*copy = new;
}

void cil_copy_catorder(struct cil_catorder *orig, struct cil_catorder **copy)
{
	struct cil_catorder *new = NULL;
	int rc = SEPOL_ERR;

	rc = cil_catorder_init(&new);
	if (rc != SEPOL_OK) {
		return;
	}

	cil_copy_list(orig->cat_list_str, &new->cat_list_str);

	*copy = new;
}

void cil_copy_dominance(struct cil_sens_dominates *orig, struct cil_sens_dominates **copy)
{
	struct cil_sens_dominates *new = NULL;
	int rc = SEPOL_ERR;

	rc = cil_sens_dominates_init(&new);
	if (rc != SEPOL_OK) {
		return;
	}

	cil_copy_list(orig->sens_list_str, &new->sens_list_str);

	*copy = new;
}

void cil_copy_fill_level(struct cil_level *orig, struct cil_level *new)
{
	new->sens_str = cil_strdup(orig->sens_str);
	new->catset_str = cil_strdup(orig->catset_str);

	if (orig->catset != NULL) {
		cil_catset_init(&new->catset);
		cil_copy_fill_catset(orig->catset, new->catset);
	}
}

int cil_copy_level(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_level *new = NULL;
	int rc = SEPOL_ERR;

	rc = cil_level_init(&new);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	if (((struct cil_level*)orig->data)->datum.name != NULL) {
		char *key = ((struct cil_symtab_datum*)orig->data)->name;
		rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
		if (rc != SEPOL_OK) {
			printf("cil_copy_level: cil_symtab_insert failed, rc: %d\n", rc);
			free(new);
			goto exit;
		}
	}

	cil_copy_fill_level((struct cil_level*)orig->data, new);

	copy->data = new;

	return SEPOL_OK;

exit:
	return rc;
}

void cil_copy_fill_levelrange(struct cil_levelrange *orig, struct cil_levelrange *new)
{
	int rc = SEPOL_ERR;

	new->low_str = cil_strdup(orig->low_str);
	new->high_str = cil_strdup(orig->high_str);

	if (orig->low != NULL) {
		rc = cil_level_init(&new->low);
		if (rc != SEPOL_OK) {
			goto exit;
		}

		cil_copy_fill_level(orig->low, new->low);
	}

	if (orig->high != NULL) {
		rc = cil_level_init(&new->high);
		if (rc != SEPOL_OK) {
			goto exit;
		}

		cil_copy_fill_level(orig->high, new->high);
	}

exit:
	return;
}

int cil_copy_levelrange(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_levelrange *new = NULL;
	int rc = SEPOL_ERR;

	rc = cil_levelrange_init(&new);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	if (((struct cil_levelrange*)orig->data)->datum.name != NULL) {
		char *key = ((struct cil_symtab_datum*)orig->data)->name;
		rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
		if (rc != SEPOL_OK) {
			printf("cil_copy_levelrange: cil_symtab_insert failed, rc: %d\n", rc);
			free(new);
			goto exit;
		}
	}

	cil_copy_fill_levelrange((struct cil_levelrange*)orig->data, new);

	copy->data = new;

	return SEPOL_OK;

exit:
	return rc;
}

void cil_copy_fill_context(struct cil_context *orig, struct cil_context *new)
{
	int rc = SEPOL_ERR;	

	new->user_str = cil_strdup(orig->user_str);
	new->role_str = cil_strdup(orig->role_str);
	new->type_str = cil_strdup(orig->type_str);
	new->range_str = cil_strdup(orig->range_str);

	if (orig->range != NULL) {
		rc = cil_levelrange_init(&new->range);
		if (rc != SEPOL_OK) {
			goto exit;
		}

		cil_copy_fill_levelrange(orig->range, new->range);
	}

exit:
	return;
}

int cil_copy_context(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_context *new = NULL;
	int rc = SEPOL_ERR;

	rc = cil_context_init(&new);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	if (((struct cil_context*)orig->data)->datum.name != NULL) {
		char *key = ((struct cil_symtab_datum*)orig->data)->name;
		rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
		if (rc != SEPOL_OK) {
			printf("cil_copy_context: cil_symtab_insert failed, rc: %d\n", rc);
			cil_destroy_context(new);
			goto exit;
		}
	}

	cil_copy_fill_context(((struct cil_context*)orig->data), new);

	copy->data = new;

	return SEPOL_OK;

exit:
	return rc;
}

int cil_copy_netifcon(struct cil_netifcon *orig, struct cil_netifcon **copy)
{
	struct cil_netifcon *new = NULL;
	int rc = SEPOL_ERR;

	rc = cil_netifcon_init(&new);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	new->interface_str = cil_strdup(orig->interface_str);
	new->if_context_str = cil_strdup(orig->if_context_str);
	new->packet_context_str = cil_strdup(orig->packet_context_str);

	if (orig->if_context != NULL) {
		rc = cil_context_init(&new->if_context);
		if (rc != SEPOL_OK) {
			cil_destroy_netifcon(new);
			goto exit;
		}
		
		cil_copy_fill_context(orig->if_context, new->if_context);
	}
	
	if (orig->packet_context != NULL) {
		rc = cil_context_init(&new->packet_context);
		if (rc != SEPOL_OK) {
			cil_destroy_netifcon(new);
			goto exit;
		}

		cil_copy_fill_context(orig->packet_context, new->packet_context);
	}

	*copy = new;

	return SEPOL_OK;

exit:
	return rc;
}

int cil_copy_genfscon(struct cil_genfscon *orig, struct cil_genfscon **copy)
{
	struct cil_genfscon *new = NULL;
	int rc = SEPOL_ERR;

	rc = cil_genfscon_init(&new);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	new->type_str = cil_strdup(orig->type_str);
	new->path_str = cil_strdup(orig->path_str);
	new->context_str = cil_strdup(orig->context_str);

	if (orig->context != NULL) {
		rc = cil_context_init(&new->context);
		if (rc != SEPOL_OK) {
			cil_destroy_genfscon(new);
			goto exit;
		}

		cil_copy_fill_context(orig->context, new->context);
	}

	*copy = new;

	return SEPOL_OK;

exit:
	return rc;
}

int cil_copy_filecon(struct cil_filecon *orig, struct cil_filecon **copy)
{
	struct cil_filecon *new = NULL;
	int rc = SEPOL_ERR;

	rc = cil_filecon_init(&new);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	new->root_str = cil_strdup(orig->root_str);
	new->path_str = cil_strdup(orig->path_str);
	new->type = orig->type;
	new->context_str = cil_strdup(orig->context_str);

	if (orig->context != NULL) {
		rc = cil_context_init(&new->context);
		if (rc != SEPOL_OK) {
			cil_destroy_filecon(new);
			goto exit;
		}

		cil_copy_fill_context(orig->context, new->context);
	}

	*copy = new;

	return SEPOL_OK;

exit:
	return rc;
	
}

int cil_copy_nodecon(struct cil_nodecon *orig, struct cil_nodecon **copy)
{
	struct cil_nodecon *new = NULL;
	int rc = SEPOL_ERR;

	rc = cil_nodecon_init(&new);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	new->addr_str = cil_strdup(orig->addr_str);
	new->mask_str = cil_strdup(orig->mask_str);
	new->context_str = cil_strdup(orig->context_str);

	if (orig->addr != NULL) {
		rc = cil_ipaddr_init(&new->addr);
		if (rc != SEPOL_OK) {
			cil_destroy_nodecon(new);
			goto exit;
		}

		cil_copy_fill_ipaddr(orig->addr, new->addr);
	}

	if (orig->mask != NULL) {
		rc = cil_ipaddr_init(&new->mask);
		if (rc != SEPOL_OK) {
			cil_destroy_nodecon(new);
			goto exit;
		}

		cil_copy_fill_ipaddr(orig->mask, new->mask);
	}

	if (orig->context != NULL) {
		rc = cil_context_init(&new->context);
		if (rc != SEPOL_OK) {
			cil_destroy_nodecon(new);
			goto exit;
		}

		cil_copy_fill_context(orig->context, new->context);
	}

	*copy = new;

	return SEPOL_OK;

exit:
	return rc;
}

int cil_copy_portcon(struct cil_portcon *orig, struct cil_portcon **copy)
{
	struct cil_portcon *new = NULL;
	int rc = SEPOL_ERR;

	rc = cil_portcon_init(&new);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	new->proto = orig->proto;
	new->port_low = orig->port_low;
	new->port_high = orig->port_high;
	new->context_str = cil_strdup(orig->context_str);

	if (orig->context != NULL) {
		rc = cil_context_init(&new->context);
		if (rc != SEPOL_OK) {
			cil_destroy_portcon(new);
			goto exit;
		}

		cil_copy_fill_context(orig->context, new->context);
	}

	*copy = new;

	return SEPOL_OK;

exit:
	return rc;
}

int cil_copy_pirqcon(struct cil_pirqcon *orig, struct cil_pirqcon **copy)
{
	struct cil_pirqcon *new = NULL;
	int rc = SEPOL_ERR;

	rc = cil_pirqcon_init(&new);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	new->pirq = new->pirq;
	new->context_str = cil_strdup(orig->context_str);

	if (orig->context != NULL) {
		rc = cil_context_init(&new->context);
		if (rc != SEPOL_OK) {
			cil_destroy_pirqcon(new);
			goto exit;
		}

		cil_copy_fill_context(orig->context, new->context);
	}

	*copy = new;

	return SEPOL_OK;

exit:
	return rc;

}

int cil_copy_iomemcon(struct cil_iomemcon *orig, struct cil_iomemcon **copy)
{
	struct cil_iomemcon *new = NULL;
	int rc = SEPOL_ERR;

	rc = cil_iomemcon_init(&new);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	new->iomem_low = orig->iomem_low;
	new->iomem_high = orig->iomem_high;
	new->context_str = cil_strdup(orig->context_str);

	if (orig->context != NULL) {
		rc = cil_context_init(&new->context);
		if (rc != SEPOL_OK) {
			cil_destroy_iomemcon(new);
			goto exit;
		}

		cil_copy_fill_context(orig->context, new->context);
	}

	*copy = new;

	return SEPOL_OK;

exit:
	return rc;
}

int cil_copy_ioportcon(struct cil_ioportcon *orig, struct cil_ioportcon **copy)
{
	struct cil_ioportcon *new = NULL;
	int rc = SEPOL_ERR;

	rc = cil_ioportcon_init(&new);
	if (rc != SEPOL_OK){
		goto exit;
	}

	new->ioport_low = orig->ioport_low;
	new->ioport_high = orig->ioport_high;
	new->context_str = cil_strdup(orig->context_str);

	if (orig->context != NULL) {
		rc = cil_context_init(&new->context);
		if (rc != SEPOL_OK) {
			cil_destroy_ioportcon(new);
			goto exit;
		}

		cil_copy_fill_context(orig->context, new->context);
	}

	*copy = new;

	return SEPOL_OK;

exit:
	return rc;
}

int cil_copy_pcidevicecon(struct cil_pcidevicecon *orig, struct cil_pcidevicecon **copy)
{
	struct cil_pcidevicecon *new = NULL;
	int rc = SEPOL_ERR;

	rc = cil_pcidevicecon_init(&new);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	new->dev = orig->dev;
	new->context_str = cil_strdup(orig->context_str);

	if (orig->context != NULL) {
		rc = cil_context_init(&new->context);
		if (rc != SEPOL_OK) {
			cil_destroy_pcidevicecon(new);
			goto exit;
		}

		cil_copy_fill_context(orig->context, new->context);
	}

	*copy = new;

	return SEPOL_OK;

exit:
	return rc;
}

int cil_copy_fsuse(struct cil_fsuse *orig, struct cil_fsuse **copy)
{
	struct cil_fsuse *new = NULL;
	int rc = SEPOL_ERR;

	rc = cil_fsuse_init(&new);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	new->type = orig->type;
	new->fs_str = cil_strdup(orig->fs_str);
	new->context_str = cil_strdup(orig->context_str);

	if (orig->context != NULL) {
		rc = cil_context_init(&new->context);
		if (rc != SEPOL_OK) {
			cil_destroy_fsuse(new);
			goto exit;
		}

		cil_copy_fill_context(orig->context, new->context);
	}

	*copy = new;

	return SEPOL_OK;

exit:
	return rc;
}

void cil_copy_constrain(struct cil_constrain *orig, struct cil_constrain **copy)
{
	struct cil_list_item *curr_old = NULL;
	struct cil_list *new_list = NULL;
	struct cil_list_item *curr_new = NULL;
	struct cil_constrain *new = NULL;
	struct cil_conditional *cond_new = NULL;
	int rc = SEPOL_ERR;

	rc = cil_constrain_init(&new);
	if (rc != SEPOL_OK) {
		return;
	}

	cil_copy_list(orig->class_list_str, &new->class_list_str);
	cil_copy_list(orig->perm_list_str, &new->perm_list_str);

	cil_list_init(&new_list);
	curr_old = orig->expr->head;

	while (curr_old != NULL) {
		cil_list_item_init(&curr_new);

		rc = cil_conditional_init(&cond_new);
		if (rc != SEPOL_OK) {
			return;
		}

		cil_copy_conditional(curr_old->data, cond_new);
		curr_new->data = cond_new;
		curr_new->flavor = curr_old->flavor;

		rc = cil_list_append_item(new_list, curr_new);
		if (rc != SEPOL_OK) {
			return;
		}

		curr_old = curr_old->next;
	}
	new->expr = new_list;

	*copy = new;
}

void cil_copy_call(struct cil_db *db, struct cil_call *orig, struct cil_call **copy)
{
	struct cil_call *new = cil_malloc(sizeof(*new));
	new->macro_str = cil_strdup(orig->macro_str);

	cil_tree_init(&new->args_tree);
	cil_tree_node_init(&new->args_tree->root);
	cil_copy_ast(db, orig->args_tree->root, new->args_tree->root);

	*copy = new;

}

int cil_copy_optional(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_optional *new = NULL;
	int rc = SEPOL_ERR;
	char *key = NULL;

	rc = cil_optional_init(&new);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	key = ((struct cil_symtab_datum *)orig->data)->name;
	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_optional: cil_symtab_insert failed, rc: %d\n", rc);
		cil_destroy_optional(new);
		goto exit;
	}

	copy->data = new;

	return SEPOL_OK;

exit:
	return rc;
}

void cil_copy_fill_ipaddr(struct cil_ipaddr *orig, struct cil_ipaddr *new)
{
	new->family = orig->family;
	memcpy(&new->ip, &orig->ip, sizeof(orig->ip));
}

int cil_copy_ipaddr(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_ipaddr *new = NULL;
	struct cil_ipaddr *old = NULL;
	char * key = NULL;
	int rc = SEPOL_ERR;

	rc = cil_ipaddr_init(&new);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	old = (struct cil_ipaddr*)orig->data;

	key = old->datum.name;
	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_ipaddr: cil_symtab_insert failed, rc: %d\n", rc);
		free(new);
		goto exit;
	}

	cil_copy_fill_ipaddr(old, new);

	copy->data = new;

	return SEPOL_OK;

exit:
	return rc;
}

void cil_copy_conditional(struct cil_conditional *orig, struct cil_conditional *new)
{
	new->str = cil_strdup(orig->str);
	new->flavor = orig->flavor;
}

int cil_copy_boolif(struct cil_booleanif *orig, struct cil_booleanif **copy)
{
	int rc = SEPOL_ERR;
	struct cil_list_item *curr_old = NULL;
	struct cil_list *new_list = NULL;
	struct cil_list_item *curr_new = NULL;
	struct cil_conditional *cond_new = NULL;
	struct cil_booleanif *new = NULL;

	rc = cil_boolif_init(&new);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	cil_list_init(&new_list);
	curr_old = orig->expr_stack->head;

	while (curr_old != NULL) {
		cil_list_item_init(&curr_new);

		rc = cil_conditional_init(&cond_new);
		if (rc != SEPOL_OK) {
			goto exit;
		}

		cil_copy_conditional(curr_old->data, cond_new);
		curr_new->data = cond_new;
		curr_new->flavor = curr_old->flavor;

		rc = cil_list_append_item(new_list, curr_new);
		if (rc != SEPOL_OK) {
			goto exit;
		}

		curr_old = curr_old->next;
	}
	new->expr_stack = new_list;

	*copy = new;

	return SEPOL_OK;

exit:
	return rc;
}

int __cil_copy_data_helper(struct cil_db *db, struct cil_tree_node *orig, struct cil_tree_node *new, symtab_t *symtab, enum cil_sym_index sym_index, int (*copy_data)(struct cil_tree_node *orig_node, struct cil_tree_node *new_node, symtab_t *sym))
{
	int rc = SEPOL_ERR;

	rc = cil_get_parent_symtab(db, new, &symtab, sym_index);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	rc = (*copy_data)(orig, new, symtab);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	return SEPOL_OK;

exit:
	return rc;
}

int __cil_copy_node_helper(struct cil_tree_node *orig, __attribute__((unused)) uint32_t *finished, void *extra_args)
{
	int rc = SEPOL_ERR;
	struct cil_tree_node *parent = NULL;
	struct cil_tree_node *new = NULL;
	struct cil_db *db = NULL;
	struct cil_args_copy *args = NULL;

	if (orig == NULL || extra_args == NULL) {
		goto exit;
	}

	args = extra_args;
	parent = args->dest;
	db = args->db;

	rc = cil_tree_node_init(&new);
	if (rc != SEPOL_OK) {
		printf("Failed to init tree node, rc: %d\n", rc);
		cil_tree_node_destroy(&new);
		goto exit;
	}

	new->parent = parent;
	new->line = orig->line;
	new->flavor = orig->flavor;

	if (parent->cl_head == NULL) {
		parent->cl_head = new;
		parent->cl_tail = new;
	} else {
		parent->cl_tail->next = new;
		parent->cl_tail = new;
	}

	symtab_t *symtab = NULL;
	switch (orig->flavor) {
	case CIL_BLOCK:
		rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_BLOCKS, &cil_copy_block);
		if (rc != SEPOL_OK) {
			free(new);
			goto exit;
		}
		break;
	case CIL_PERM:
		rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_UNKNOWN, &cil_copy_perm);
		if (rc != SEPOL_OK) {
			free(new);
			goto exit;
		}
		break;
	case CIL_CLASS:
		rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_CLASSES, &cil_copy_class);
		if (rc != SEPOL_OK) {
			free(new);
			goto exit;
		}
		break;
	case CIL_COMMON:
		rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_COMMONS, &cil_copy_common);
		if (rc != SEPOL_OK) {
			free(new);
			goto exit;
		}
		break;
	case CIL_CLASSCOMMON:
		cil_copy_classcommon((struct cil_classcommon*)orig->data, (struct cil_classcommon**)&new->data); 
		break;
	case CIL_SID:
		rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_SIDS, &cil_copy_sid);
		if (rc != SEPOL_OK) {
			free(new);
			goto exit;
		}
		break;
	case CIL_SIDCONTEXT:
		rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_SIDS, &cil_copy_sidcontext);
		if (rc != SEPOL_OK) {
			free(new);
			goto exit;
		}
		break;
	case CIL_USER:
		rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_USERS, &cil_copy_user);
		if (rc != SEPOL_OK) {
			free(new);
			goto exit;
		}
		break;
	case CIL_ROLE:
		rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_ROLES, &cil_copy_role);
		if (rc != SEPOL_OK) {
			free(new);
			goto exit;
		}
		break;
	case CIL_USERROLE:
		cil_copy_userrole((struct cil_userrole*)orig->data, (struct cil_userrole**)&new->data);
		break;
	case CIL_USERLEVEL:
		cil_copy_userlevel((struct cil_userlevel*)orig->data, (struct cil_userlevel**)&new->data);
		break;
	case CIL_USERRANGE:
		cil_copy_userrange((struct cil_userrange*)orig->data, (struct cil_userrange**)&new->data);
		break;
	case CIL_TYPE:
		rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_TYPES, &cil_copy_type);
		if (rc != SEPOL_OK) {
			free(new);
			goto exit;
		}
		break;
	case CIL_TYPEATTRIBUTE:
		rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_TYPES, &cil_copy_typeattribute);
		if (rc != SEPOL_OK) {
			free(new);
			goto exit;
		}
		break;
	case CIL_TYPEATTRIBUTETYPES:
		cil_copy_typeattributetypes((struct cil_typeattributetypes*)orig->data, (struct cil_typeattributetypes**)&new->data);
		break;
	case CIL_TYPEALIAS:
		rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_TYPES, &cil_copy_typealias);
		if (rc != SEPOL_OK) {
			free(new);
			goto exit;
		}
		break;
	case CIL_FILETRANSITION:
		cil_copy_filetransition((struct cil_filetransition*)orig->data, (struct cil_filetransition**)&new->data);
		break;
	case CIL_RANGETRANSITION:
		cil_copy_rangetransition((struct cil_rangetransition*)orig->data, (struct cil_rangetransition**)&new->data);
		break;
	case CIL_BOOL:
		rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_BOOLS, &cil_copy_bool);
		if (rc != SEPOL_OK) {
			free(new);
			goto exit;
		}
		break;
	case CIL_AVRULE:
		cil_copy_avrule((struct cil_avrule*)orig->data, (struct cil_avrule**)&new->data);
		break;
	case CIL_TYPE_RULE:
		cil_copy_type_rule((struct cil_type_rule*)orig->data, (struct cil_type_rule**)&new->data);
		break;
	case CIL_SENS:
		rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_SENS, &cil_copy_sens);
		if (rc != SEPOL_OK) {
			free(new);
			goto exit;
		}
		break;
	case CIL_SENSALIAS:
		rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_SENS, &cil_copy_sensalias);
		if (rc != SEPOL_OK) {
			free(new);
			goto exit;
		}
		break;
	case CIL_CAT:
		rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_CATS, &cil_copy_cat);
		if (rc != SEPOL_OK) {
			free(new);
			goto exit;
		}
		break;
	case CIL_CATALIAS:
		rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_CATS, &cil_copy_catalias);
		if (rc != SEPOL_OK) {
			free(new);
			goto exit;
		}
		break;
	case CIL_CATRANGE:
		rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_CATS, &cil_copy_catrange);
		if (rc != SEPOL_OK) {
			free(new);
			goto exit;
		}
	case CIL_CATSET:
		rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_CATS, &cil_copy_catset);
		if (rc != SEPOL_OK) {
			free(new);
			goto exit;
		}
	case CIL_SENSCAT:
		cil_copy_senscat((struct cil_senscat*)orig->data, (struct cil_senscat**)&new->data);
		break;
	case CIL_CATORDER:
		cil_copy_catorder((struct cil_catorder*)orig->data, (struct cil_catorder**)&new->data);
		break;
	case CIL_DOMINANCE:
		cil_copy_dominance((struct cil_sens_dominates*)orig->data, (struct cil_sens_dominates**)&new->data);
		break;
	case CIL_LEVEL:
		rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_LEVELS, &cil_copy_level);
		if (rc != SEPOL_OK) {
			free(new);
			goto exit;
		}
		break;
	case CIL_LEVELRANGE:
		rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_LEVELRANGES, &cil_copy_levelrange);
		if (rc != SEPOL_OK) {
			free(new);
			goto exit;
		}
		break;
	case CIL_CONTEXT:
		rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_CONTEXTS, &cil_copy_context);
		if (rc != SEPOL_OK) {
			free(new);
			goto exit;
		}
		break;
	case CIL_NETIFCON:
		rc = cil_copy_netifcon((struct cil_netifcon*)orig->data, (struct cil_netifcon**)&new->data);
		if (rc != SEPOL_OK) {
			free(new);
			goto exit;
		}
		break;
	case CIL_GENFSCON:
		rc = cil_copy_genfscon((struct cil_genfscon*)orig->data, (struct cil_genfscon**)&new->data);
		if (rc != SEPOL_OK) {
			free(new);
			goto exit;
		}
		break;
	case CIL_FILECON:
		rc = cil_copy_filecon((struct cil_filecon*)orig->data, (struct cil_filecon**)&new->data);
		if (rc != SEPOL_OK) {
			free(new);
			goto exit;
		}
		break;
	case CIL_NODECON:
		rc = cil_copy_nodecon((struct cil_nodecon*)orig->data, (struct cil_nodecon**)&new->data);
		if (rc != SEPOL_OK) {
			free(new);
			goto exit;
		}
		break;
	case CIL_PORTCON:
		rc = cil_copy_portcon((struct cil_portcon*)orig->data, (struct cil_portcon**)&new->data);
		if (rc != SEPOL_OK) {
			free(new);
			goto exit;
		}
		break;
	case CIL_PIRQCON:
		rc = cil_copy_pirqcon((struct cil_pirqcon*)orig->data, (struct cil_pirqcon**)&new->data);
		if (rc != SEPOL_OK) {
			free(new);
			goto exit;
		}
		break;
	case CIL_IOMEMCON:
		rc = cil_copy_iomemcon((struct cil_iomemcon*)orig->data, (struct cil_iomemcon**)&new->data);
		if (rc != SEPOL_OK) {
			free(new);
			goto exit;
		}
		break;
	case CIL_IOPORTCON:
		rc = cil_copy_ioportcon((struct cil_ioportcon*)orig->data, (struct cil_ioportcon**)&new->data);
		if (rc != SEPOL_OK) {
			free(new);
			goto exit;
		}
		break;
	case CIL_PCIDEVICECON:
		rc = cil_copy_pcidevicecon((struct cil_pcidevicecon*)orig->data, (struct cil_pcidevicecon**)&new->data);
		if (rc != SEPOL_OK) {
			free(new);
			goto exit;
		}
		break;
	case CIL_FSUSE:
		rc = cil_copy_fsuse((struct cil_fsuse*)orig->data, (struct cil_fsuse**)&new->data);
		if (rc != SEPOL_OK) {
			free(new);
			goto exit;
		}
		break;
	case CIL_MLSCONSTRAIN:
		cil_copy_constrain((struct cil_constrain*)orig->data, (struct cil_constrain**)&new->data);
		break;
	case CIL_CALL:
		cil_copy_call(db, (struct cil_call*)orig->data, (struct cil_call**)&new->data);
		break;
	case CIL_PARSE_NODE:
		new->data = cil_strdup(((char*)orig->data));
		break;
	case CIL_OPTIONAL:
		rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_OPTIONALS, &cil_copy_optional);
		if (rc != SEPOL_OK) {
			free(new);
			goto exit;
		}
		break;
	case CIL_IPADDR:
		rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_IPADDRS, &cil_copy_ipaddr);
		if (rc != SEPOL_OK) {
			free(new);
			goto exit;
		}
		break;
	case CIL_BOOLEANIF:
		cil_copy_boolif((struct cil_booleanif*)orig->data, (struct cil_booleanif**)&new->data);
		break;
	default:
		rc = SEPOL_OK;
		goto exit;
	}

	if (orig->cl_head != NULL) {
		args->dest = new;
	}

	return SEPOL_OK;

exit:
	return rc;
}

int __cil_copy_last_child_helper(__attribute__((unused)) struct cil_tree_node *orig, void *extra_args)
{
	int rc = SEPOL_ERR;
	struct cil_tree_node *node = NULL;
	struct cil_args_copy *args = NULL;

	if (extra_args == NULL) {
		goto exit;
	}

	args = extra_args;
	node = args->dest;
	
	if (node->flavor != CIL_ROOT) {
		args->dest = node->parent;
	}

	return SEPOL_OK;

exit:
	return rc;
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
		printf("cil_tree_walk failed, rc: %d\n", rc);
		goto exit;
	}

	return SEPOL_OK;

exit:
	return rc;
}

