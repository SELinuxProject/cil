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

enum args_copy {
	ARGS_COPY_DEST,
	ARGS_COPY_DB,
	ARGS_COPY_COUNT,
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
		goto copy_block_out;
	}

	key = ((struct cil_symtab_datum *)orig->data)->name;

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_block: cil_symtab_insert failed, rc: %d\n", rc);
		cil_destroy_block(new);
		goto copy_block_out;
	}

	rc = cil_symtab_array_init(new->symtab, CIL_SYM_NUM);
	if (rc != SEPOL_OK) {
		printf("cil_copy_block: cil_symtab_array_init failed, rc: %d\n", rc);
		cil_destroy_block(new);
		goto copy_block_out;
	}

	copy->data = new;

	return SEPOL_OK;

copy_block_out:
	return rc;
}

int cil_copy_perm(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_perm *new = NULL;
	int rc = SEPOL_ERR;
	char *key = NULL;

	rc = cil_perm_init(&new);
	if (rc != SEPOL_OK) {
		goto copy_perm_out;
	}

	key = ((struct cil_symtab_datum *)orig->data)->name;

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_perm: cil_symtab_insert failed, rc: %d\n", rc);
		free(new);
		goto copy_perm_out;
	}

	copy->data = new;

	return SEPOL_OK;

copy_perm_out:
	return rc;
}

int cil_copy_class(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_class *new = NULL;
	int rc = SEPOL_ERR;
	char *key = NULL;

	rc = cil_class_init(&new);
	if (rc != SEPOL_OK) {
		goto copy_class_out;
	}

	key = ((struct cil_symtab_datum *)orig->data)->name;

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_class: cil_symtab_insert failed, rc: %d\n", rc);
		cil_destroy_class(new);
		goto copy_class_out;
	}

	rc = symtab_init(&new->perms, CIL_SYM_SIZE);
	if (rc != SEPOL_OK) {
		printf("cil_copy_class: symtab_init failed, rc: %d\n", rc);
		cil_destroy_class(new);
		goto copy_class_out;
	}

	new->common = NULL;
	copy->data = new;
		
	return SEPOL_OK;

copy_class_out:
	return rc;
}

int cil_copy_common(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_common *new;
	int rc = cil_common_init(&new);
	if (rc != SEPOL_OK) {
		goto copy_common_out;
	}

	char *key = ((struct cil_symtab_datum *)orig->data)->name;
	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_common: cil_symtab_insert failed, rc: %d\n", rc);
		cil_destroy_common(new);
		goto copy_common_out;
	}
	rc = symtab_init(&new->perms, CIL_SYM_SIZE);
	if (rc != SEPOL_OK) {
		printf("cil_copy_common: symtab_init failed, rc: %d\n", rc);
		cil_destroy_common(new);
		goto copy_common_out;
	}
	copy->data = new;

	return SEPOL_OK;

copy_common_out:
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
		goto copy_sid_out;
	}

	key = ((struct cil_symtab_datum*)orig->data)->name;

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_sid: cil_symtab_insert failed, rc: %d\n", rc);
		free(new);
		goto copy_sid_out;
	}

	copy->data = new;

	return SEPOL_OK;

copy_sid_out:
	return rc;
}

int cil_copy_sidcontext(struct cil_tree_node *orig, struct cil_tree_node *copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_sidcontext *new = NULL;
	int rc = SEPOL_ERR;

	rc = cil_sidcontext_init(&new);
	if (rc != SEPOL_OK) {
		goto copy_sidcontext_out;
	}

	new->context_str = cil_strdup(((struct cil_sidcontext*)orig->data)->context_str);
	
	if (((struct cil_sidcontext*)orig->data)->context != NULL) {
		rc = cil_context_init(&new->context);

		if (rc != SEPOL_OK) {
			cil_destroy_sidcontext(new);
			goto copy_sidcontext_out;
		}

		cil_copy_fill_context(((struct cil_sidcontext*)orig->data)->context, new->context);
	}

	copy->data = new;
	
	return SEPOL_OK;

copy_sidcontext_out:
	return rc;
}

int cil_copy_user(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_user *new = NULL;
	int rc = SEPOL_ERR;
	char *key = NULL;

	rc = cil_user_init(&new);
	if (rc != SEPOL_OK) {
		goto copy_user_out;
	}

	key = ((struct cil_symtab_datum *)orig->data)->name;

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_user: cil_symtab_insert failed, rc: %d\n", rc);
		free(new);
		goto copy_user_out;
	}

	copy->data = new;

	return SEPOL_OK;

copy_user_out:
	return rc;
}

int cil_copy_role(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_role *new = NULL;
	int rc = SEPOL_ERR;
	char *key = NULL;

	rc = cil_role_init(&new);
	if (rc != SEPOL_OK) {
		goto copy_role_out;
	}

	key = ((struct cil_symtab_datum *)orig->data)->name;

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_role: cil_symtab_insert failed, rc: %d\n", rc);
		free(new);
		goto copy_role_out;
	}

	copy->data = new;

	return SEPOL_OK;

copy_role_out:
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

int cil_copy_type(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_type *new = NULL;
	int rc = SEPOL_ERR;
	char *key = NULL;

	rc = cil_type_init(&new);
	if (rc != SEPOL_OK) {
		goto copy_type_out;
	}

	key = ((struct cil_symtab_datum *)orig->data)->name;

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_type: cil_symtab_insert failed, rc: %d\n", rc);
		free(new);
		goto copy_type_out;
	}

	copy->data = new;

	return SEPOL_OK;

copy_type_out:
	return rc;
}

void cil_copy_typeattr(struct cil_typeattribute *orig, struct cil_typeattribute **copy)
{
	struct cil_typeattribute *new = NULL;
	int rc = SEPOL_ERR;

	rc = cil_typeattribute_init(&new);
	if (rc != SEPOL_OK) {
		return;
	}

	new->type_str = cil_strdup(orig->type_str);
	new->attr_str = cil_strdup(orig->attr_str);

	*copy = new;
}

int cil_copy_typealias(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_typealias *new = NULL;
	int rc = SEPOL_ERR;
	char *key = NULL;

	rc = cil_typealias_init(&new);
	if (rc != SEPOL_OK) {
		goto copy_typealias_out;
	}

	key = ((struct cil_symtab_datum*)orig->data)->name;

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_typealias: cil_symtab_insert failed, rc: %d\n", rc);
		cil_destroy_typealias(new);
		goto copy_typealias_out;
	}

	new->type_str = cil_strdup(((struct cil_typealias*)orig->data)->type_str);
	copy->data = new;
	
	return SEPOL_OK;

copy_typealias_out:
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

int cil_copy_bool(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_bool *new = NULL;
	int rc = SEPOL_ERR;
	char *key = NULL;

	rc = cil_bool_init(&new);
	if (rc != SEPOL_OK) {
		goto copy_bool_out;
	}

	key = ((struct cil_symtab_datum *)orig->data)->name;

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_bool: cil_symtab_insert failed, rc: %d\n", rc);
		cil_destroy_bool(new);
		goto copy_bool_out;
	}

	new->value = ((struct cil_bool *)orig->data)->value;
	copy->data = new;

	return SEPOL_OK;

copy_bool_out:
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
		goto copy_sens_out;
	}

	key = ((struct cil_symtab_datum*)orig->data)->name;

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_sens: cil_symtab_insert failed, rc: %d\n", rc);
		cil_destroy_sensitivity(new);
		goto copy_sens_out;
	}

	copy->data = new;

	return SEPOL_OK;

copy_sens_out:
	return rc;
}

int cil_copy_sensalias(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_sensalias *new = NULL;
	int rc = SEPOL_ERR;
	char *key = NULL;

	rc = cil_sensalias_init(&new);
	if (rc != SEPOL_OK) {
		goto copy_sensalias_out;
	}

	key = ((struct cil_symtab_datum*)orig->data)->name;

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_sensalias: cil_symtab_insert failed, rc: %d\n", rc);
		cil_destroy_sensalias(new);
		goto copy_sensalias_out;
	}

	new->sens_str = cil_strdup(((struct cil_sensalias*)orig->data)->sens_str);
	copy->data = new;

	return SEPOL_OK;

copy_sensalias_out:
	return rc;
}

int cil_copy_cat(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_cat *new = NULL;
	int rc = SEPOL_ERR;
	char *key = NULL;

	rc = cil_cat_init(&new);
	if (rc != SEPOL_OK) {
		goto copy_cat_out;
	}

	key = ((struct cil_symtab_datum*)orig->data)->name;

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_cat: cil_symtab_insert failed, rc: %d\n", rc);
		free(new);
		goto copy_cat_out;
	}

	copy->data = new;

	return SEPOL_OK;

copy_cat_out:
	return rc;
}

int cil_copy_catalias(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_catalias *new = NULL;
	int rc = SEPOL_ERR;
	char *key = NULL;

	rc = cil_catalias_init(&new);
	if (rc != SEPOL_OK) {
		goto copy_catalias_out;
	}

	key = ((struct cil_symtab_datum*)orig->data)->name;

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_catalias: cil_symtab_insert failed, rc: %d\n", rc);
		cil_destroy_catalias(new);
		goto copy_catalias_out;
	}

	new->cat_str = cil_strdup(((struct cil_catalias*)orig->data)->cat_str);
	copy->data = new;

	return SEPOL_OK;

copy_catalias_out:
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
	cil_copy_list(orig->cat_list_str, &new->cat_list_str);

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
	cil_copy_list(orig->cat_list_str, &new->cat_list_str);
}

int cil_copy_level(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_level *new = NULL;
	int rc = SEPOL_ERR;

	rc = cil_level_init(&new);
	if (rc != SEPOL_OK) {
		goto copy_level_out;
	}

	if (((struct cil_level*)orig->data)->datum.name != NULL) {
		char *key = ((struct cil_symtab_datum*)orig->data)->name;
		rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
		if (rc != SEPOL_OK) {
			printf("cil_copy_level: cil_symtab_insert failed, rc: %d\n", rc);
			free(new);
			goto copy_level_out;
		}
	}

	cil_copy_fill_level((struct cil_level*)orig->data, new);

	copy->data = new;

	return SEPOL_OK;

copy_level_out:
	return rc;
}

void cil_copy_fill_context(struct cil_context *orig, struct cil_context *new)
{
	int rc = SEPOL_ERR;	

	new->user_str = cil_strdup(orig->user_str);
	new->role_str = cil_strdup(orig->role_str);
	new->type_str = cil_strdup(orig->type_str);
	new->low_str = cil_strdup(orig->low_str);
	new->high_str = cil_strdup(orig->high_str);

	if (orig->low != NULL) {
		rc = cil_level_init(&new->low);
		if (rc != SEPOL_OK) {
			goto copy_fill_context_out;
		}
		
		cil_copy_fill_level(orig->low, new->low);
	}

	if (orig->high != NULL) {
		rc = cil_level_init(&new->high);
		if (rc != SEPOL_OK) {
			goto copy_fill_context_out;
		}
	
		cil_copy_fill_level(orig->high, new->high);
	}

copy_fill_context_out:
	return;
}

int cil_copy_context(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_context *new = NULL;
	int rc = SEPOL_ERR;

	rc = cil_context_init(&new);
	if (rc != SEPOL_OK) {
		goto copy_context_out;
	}

	if (((struct cil_context*)orig->data)->datum.name != NULL) {
		char *key = ((struct cil_symtab_datum*)orig->data)->name;
		rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
		if (rc != SEPOL_OK) {
			printf("cil_copy_context: cil_symtab_insert failed, rc: %d\n", rc);
			cil_destroy_context(new);
			goto copy_context_out;
		}
	}

	cil_copy_fill_context(((struct cil_context*)orig->data), new);

	copy->data = new;

	return SEPOL_OK;

copy_context_out:
	return rc;
}

int cil_copy_netifcon(struct cil_tree_node *orig, struct cil_tree_node *copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_netifcon *new = NULL;
	int rc = SEPOL_ERR;

	rc = cil_netifcon_init(&new);
	if (rc != SEPOL_OK) {
		goto copy_netifcon_out;
	}

	new->interface_str = cil_strdup(((struct cil_netifcon*)orig->data)->interface_str);
	new->if_context_str = cil_strdup(((struct cil_netifcon*)orig->data)->if_context_str);
	new->packet_context_str = cil_strdup(((struct cil_netifcon*)orig->data)->packet_context_str);

	if (((struct cil_netifcon*)orig->data)->if_context != NULL) {
		rc = cil_context_init(&new->if_context);
		if (rc != SEPOL_OK) {
			cil_destroy_netifcon(new);
			goto copy_netifcon_out;
		}
		
		cil_copy_fill_context(((struct cil_netifcon*)orig->data)->if_context, new->if_context);
	}
	
	if (((struct cil_netifcon*)orig->data)->packet_context != NULL) {
		rc = cil_context_init(&new->packet_context);
		if (rc != SEPOL_OK) {
			cil_destroy_netifcon(new);
			goto copy_netifcon_out;
		}

		cil_copy_fill_context(((struct cil_netifcon*)orig->data)->packet_context, new->packet_context);
	}

	copy->data = new;

	return SEPOL_OK;

copy_netifcon_out:
	return rc;
}

void cil_copy_constrain(struct cil_db *db, struct cil_constrain *orig, struct cil_constrain **copy)
{
	struct cil_constrain *new = NULL;
	int rc = SEPOL_ERR;

	rc = cil_constrain_init(&new);
	if (rc != SEPOL_OK) {
		return;
	}

	cil_copy_list(orig->class_list_str, &new->class_list_str);
	cil_copy_list(orig->perm_list_str, &new->perm_list_str);

	cil_tree_node_init(&new->expr);
	cil_copy_ast(db, orig->expr, new->expr);

	*copy = new;
}

void cil_copy_call(struct cil_db *db, struct cil_call *orig, struct cil_call **copy)
{
	struct cil_call *new = cil_malloc(sizeof(struct cil_call));
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
		goto copy_optional_out;
	}

	key = ((struct cil_symtab_datum *)orig->data)->name;
	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_optional: cil_symtab_insert failed, rc: %d\n", rc);
		cil_destroy_optional(new);
		goto copy_optional_out;
	}

	copy->data = new;

	return SEPOL_OK;

copy_optional_out:
	return rc;
}

int cil_copy_nodecon(struct cil_nodecon *orig, struct cil_nodecon **copy)
{
	struct cil_nodecon *new = NULL;
	int rc = SEPOL_ERR;

	rc = cil_nodecon_init(&new);
	if (rc != SEPOL_OK) {
		goto copy_nodecon_out;
	}

	new->addr_str = cil_strdup(orig->addr_str);
	new->mask_str = cil_strdup(orig->mask_str);
	new->context_str = cil_strdup(orig->context_str);

	if (orig->addr != NULL) {
		rc = cil_ipaddr_init(&new->addr);
		if (rc != SEPOL_OK) {
			cil_destroy_nodecon(new);
			goto copy_nodecon_out;
		}

		cil_copy_fill_ipaddr(orig->addr, new->addr);
	}

	if (orig->mask != NULL) {
		rc = cil_ipaddr_init(&new->mask);
		if (rc != SEPOL_OK) {
			cil_destroy_nodecon(new);
			goto copy_nodecon_out;
		}

		cil_copy_fill_ipaddr(orig->mask, new->mask);
	}

	if (orig->context != NULL) {
		rc = cil_context_init(&new->context);
		if (rc != SEPOL_OK) {
			cil_destroy_nodecon(new);
			goto copy_nodecon_out;
		}

		cil_copy_fill_context(orig->context, new->context);
	}

	*copy = new;

	return SEPOL_OK;

copy_nodecon_out:
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
		goto copy_ipaddr_out;
	}

	old = (struct cil_ipaddr*)orig->data;

	key = old->datum.name;
	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_ipaddr: cil_symtab_insert failed, rc: %d\n", rc);
		free(new);
		goto copy_ipaddr_out;
	}

	cil_copy_fill_ipaddr(old, new);

	copy->data = new;

	return SEPOL_OK;

copy_ipaddr_out:
	return rc;
}

void cil_copy_conditional(struct cil_conditional *orig, struct cil_conditional *new)
{
	new->str = cil_strdup(orig->str);
	new->flavor = orig->flavor;
}

int cil_copy_boolif(struct cil_booleanif *orig, struct cil_booleanif **copy)
{
	struct cil_booleanif *new = NULL;
	struct cil_conditional *cond_new = NULL;
	struct cil_tree_node *curr_new = NULL;
	struct cil_tree_node *curr_old = NULL;
	struct cil_tree_node *temp = NULL;
	int rc = SEPOL_ERR;

	rc = cil_boolif_init(&new);
	if (rc != SEPOL_OK) {
		goto copy_boolif_out;
	}

	curr_old = orig->expr_stack;

	while (curr_old != NULL) {
		rc = cil_tree_node_init(&curr_new);
		if (rc != SEPOL_OK) {
			goto copy_boolif_out;
		}

		rc = cil_conditional_init(&cond_new);
		if (rc != SEPOL_OK) {
			goto copy_boolif_out;
		}

		cil_copy_conditional(curr_old->data, cond_new);
		curr_new->data = cond_new;
		curr_new->flavor = curr_old->flavor;

		if (temp != NULL) {
			temp->cl_head = curr_new;
			curr_new->parent = temp;
		} else {
			new->expr_stack = curr_new;
		}

		temp = curr_new;
		curr_old = curr_old->cl_head;
	}

	*copy = new;

	return SEPOL_OK;

copy_boolif_out:
	return rc;
}

int __cil_copy_data_helper(struct cil_db *db, struct cil_tree_node *orig, struct cil_tree_node *new, symtab_t *symtab, enum cil_sym_index sym_index, int (*copy_data)(struct cil_tree_node *orig_node, struct cil_tree_node *new_node, symtab_t *sym))
{
	int rc = SEPOL_ERR;

	rc = cil_get_parent_symtab(db, new, &symtab, sym_index);
	if (rc != SEPOL_OK) {
		goto copy_data_helper_out;
	}

	rc = (*copy_data)(orig, new, symtab);
	if (rc != SEPOL_OK) {
		goto copy_data_helper_out;
	}

	return SEPOL_OK;

copy_data_helper_out:
	return rc;
}

int __cil_copy_node_helper(struct cil_tree_node *orig, __attribute__((unused)) uint32_t *finished, void **extra_args)
{
	int rc = SEPOL_ERR;
	struct cil_tree_node *parent = NULL;
	struct cil_tree_node *new = NULL;
	struct cil_db *db = NULL;

	if (orig == NULL || extra_args == NULL) {
		goto copy_node_helper_out;
	}

	parent = extra_args[ARGS_COPY_DEST];
	db = extra_args[ARGS_COPY_DB];

	rc = cil_tree_node_init(&new);
	if (rc != SEPOL_OK) {
		printf("Failed to init tree node, rc: %d\n", rc);
		cil_tree_node_destroy(&new);
		goto copy_node_helper_out;
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
			goto copy_node_helper_out;
		}
		break;
	case CIL_PERM:
		rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_UNKNOWN, &cil_copy_perm);
		if (rc != SEPOL_OK) {
			free(new);
			goto copy_node_helper_out;
		}
		break;
	case CIL_CLASS:
		rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_CLASSES, &cil_copy_class);
		if (rc != SEPOL_OK) {
			free(new);
			goto copy_node_helper_out;
		}
		break;
	case CIL_COMMON:
		rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_COMMONS, &cil_copy_common);
		if (rc != SEPOL_OK) {
			free(new);
			goto copy_node_helper_out;
		}
		break;
	case CIL_CLASSCOMMON:
		cil_copy_classcommon((struct cil_classcommon*)orig->data, (struct cil_classcommon**)&new->data); 
		break;
	case CIL_SID:
		rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_SIDS, &cil_copy_sid);
		if (rc != SEPOL_OK) {
			free(new);
			goto copy_node_helper_out;
		}
		break;
	case CIL_SIDCONTEXT:
		rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_SIDS, &cil_copy_sidcontext);
		if (rc != SEPOL_OK) {
			free(new);
			goto copy_node_helper_out;
		}
		break;
	case CIL_USER:
		rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_USERS, &cil_copy_user);
		if (rc != SEPOL_OK) {
			free(new);
			goto copy_node_helper_out;
		}
		break;
	case CIL_ROLE:
		rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_ROLES, &cil_copy_role);
		if (rc != SEPOL_OK) {
			free(new);
			goto copy_node_helper_out;
		}
		break;
	case CIL_USERROLE:
		cil_copy_userrole((struct cil_userrole*)orig->data, (struct cil_userrole**)&new->data);
		break;
	case CIL_TYPE:
		rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_TYPES, &cil_copy_type);
		if (rc != SEPOL_OK) {
			free(new);
			goto copy_node_helper_out;
		}
		break;
	case CIL_ATTR:
		rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_TYPES, &cil_copy_type);
		if (rc != SEPOL_OK) {
			free(new);
			goto copy_node_helper_out;
		}
		break;
	case CIL_TYPE_ATTR:
		cil_copy_typeattr((struct cil_typeattribute*)orig->data, (struct cil_typeattribute**)&new->data);
		break;
	case CIL_TYPEALIAS:
		rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_TYPES, &cil_copy_typealias);
		if (rc != SEPOL_OK) {
			free(new);
			goto copy_node_helper_out;
		}
		break;
	case CIL_FILETRANSITION:
		cil_copy_filetransition((struct cil_filetransition*)orig->data, (struct cil_filetransition**)&new->data);
		break;
	case CIL_BOOL:
		rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_BOOLS, &cil_copy_bool);
		if (rc != SEPOL_OK) {
			free(new);
			goto copy_node_helper_out;
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
			goto copy_node_helper_out;
		}
		break;
	case CIL_SENSALIAS:
		rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_SENS, &cil_copy_sensalias);
		if (rc != SEPOL_OK) {
			free(new);
			goto copy_node_helper_out;
		}
		break;
	case CIL_CAT:
		rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_CATS, &cil_copy_cat);
		if (rc != SEPOL_OK) {
			free(new);
			goto copy_node_helper_out;
		}
		break;
	case CIL_CATALIAS:
		rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_CATS, &cil_copy_catalias);
		if (rc != SEPOL_OK) {
			free(new);
			goto copy_node_helper_out;
		}
		break;
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
			goto copy_node_helper_out;
		}
		break;
	case CIL_CONTEXT:
		rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_CONTEXTS, &cil_copy_context);
		if (rc != SEPOL_OK) {
			free(new);
			goto copy_node_helper_out;
		}
		break;
	case CIL_NETIFCON:
		rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_NETIFCONS, &cil_copy_netifcon);
		if (rc != SEPOL_OK) {
			free(new);
			goto copy_node_helper_out;
		}
		break;
	case CIL_MLSCONSTRAIN:
		cil_copy_constrain(db, (struct cil_constrain*)orig->data, (struct cil_constrain**)&new->data);
		break;
	case CIL_CONSTRAIN_NODE:
		new->data = cil_strdup(((char*)orig->data));
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
			goto copy_node_helper_out;
		}
		break;
	case CIL_NODECON:
		cil_copy_nodecon((struct cil_nodecon*)orig->data, (struct cil_nodecon**)&new->data);
		break;
	case CIL_IPADDR:
		rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_IPADDRS, &cil_copy_ipaddr);
		if (rc != SEPOL_OK) {
			free(new);
			goto copy_node_helper_out;
		}
		break;
	case CIL_BOOLEANIF:
		cil_copy_boolif((struct cil_booleanif*)orig->data, (struct cil_booleanif**)&new->data);
		break;
	default:
		rc = SEPOL_OK;
		goto copy_node_helper_out;
	}

	if (orig->cl_head != NULL) {
		extra_args[ARGS_COPY_DEST] = new;
	}

	return SEPOL_OK;

copy_node_helper_out:
	return rc;
}

int __cil_copy_branch_helper(__attribute__((unused)) struct cil_tree_node *orig, void **extra_args)
{
	int rc = SEPOL_ERR;
	struct cil_tree_node *node = NULL;

	if (extra_args == NULL) {
		goto copy_branch_helper_out;
	}

	node = extra_args[ARGS_COPY_DEST];
	
	if (node->flavor != CIL_ROOT) {
		extra_args[ARGS_COPY_DEST] = node->parent;
	}

	return SEPOL_OK;

copy_branch_helper_out:
	return rc;
}
	
// dest is the parent node to copy into
// if the copy is for a call to a macro, dest should be a pointer to the call
int cil_copy_ast(struct cil_db *db, struct cil_tree_node *orig, struct cil_tree_node *dest)
{
	int rc = SEPOL_ERR;
	void **extra_args = NULL;

	extra_args = cil_malloc(sizeof(*extra_args) * ARGS_COPY_COUNT);
	extra_args[ARGS_COPY_DEST] = dest;
	extra_args[ARGS_COPY_DB] = db;

	rc = cil_tree_walk(orig, __cil_copy_node_helper, NULL,  __cil_copy_branch_helper, extra_args);
	if (rc != SEPOL_OK) {
		printf("cil_tree_walk failed, rc: %d\n", rc);
		goto copy_ast_out;
	}

	free(extra_args);

	return SEPOL_OK;

copy_ast_out:
	return rc;
}

