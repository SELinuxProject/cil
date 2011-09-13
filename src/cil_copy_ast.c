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

int cil_copy_list(struct cil_list *orig, struct cil_list **copy)
{
	struct cil_list *new = NULL;
	struct cil_list *new_sub = NULL;
	struct cil_list_item *new_item = NULL;
	struct cil_list_item *orig_item = NULL;
	int rc = SEPOL_ERR;

	if (orig == NULL) {
		goto exit;
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
			rc = cil_copy_list((struct cil_list*)orig_item->data, &new_sub);
			if (rc != SEPOL_OK) {
				goto exit;
			}
			new_item->data = new_sub;
		}
		new_item->flavor = orig_item->flavor;
		orig_item = orig_item->next;
	}

	*copy = new;

	return SEPOL_OK;

exit:
	return rc;
}

int cil_copy_block(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_block *new = NULL;
	int rc = SEPOL_ERR;
	char *key = NULL;

	cil_block_init(&new);

	key = ((struct cil_symtab_datum *)orig->data)->name;

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_block: cil_symtab_insert failed, rc: %d\n", rc);
		cil_destroy_block(new);
		goto exit;
	}

	cil_symtab_array_init(new->symtab, CIL_SYM_NUM);

	copy->data = new;

	return SEPOL_OK;

exit:
	return rc;
}

int cil_copy_policycap(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_policycap *new = NULL;
	int rc = SEPOL_ERR;
	char *key = ((struct cil_symtab_datum*)orig->data)->name;

	cil_policycap_init(&new);

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_policycap: cil_symtab_insert failed, rc: %d\n", rc);
		goto exit;
	}

	copy->data = new;

	return SEPOL_OK;
exit:
	cil_destroy_policycap(new);
	return rc;
}

int cil_copy_perm(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_perm *new = NULL;
	int rc = SEPOL_ERR;
	char *key = NULL;

	cil_perm_init(&new);

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
	cil_destroy_perm(new);
	return rc;
}

int cil_copy_classmap_perm(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_classmap_perm *new = NULL;
	int rc = SEPOL_ERR;
	char *key = NULL;

	cil_classmap_perm_init(&new);

	key = ((struct cil_symtab_datum*)orig->data)->name;

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_classmap_perm: cil_symtab_insert failed, rc: %d\n", rc);
		free(new);
		goto exit;
	}

	copy->data = new;

	return SEPOL_OK;

exit:
	return rc;
}

int cil_copy_classmap(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_classmap *new = NULL;
	int rc = SEPOL_ERR;
	char *key = NULL;

	cil_classmap_init(&new);

	key = ((struct cil_symtab_datum*)orig->data)->name;

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_classmap: cil_symtab_insert failed, rc: %d\n", rc);
		cil_destroy_classmap(new);
		goto exit;
	}

	rc = symtab_init(&new->perms, CIL_SYM_SIZE);
	if (rc != SEPOL_OK) {
		printf("cil_copy_classmap: symtab_init failed, rc: %d\n", rc);
		cil_destroy_classmap(new);
		goto exit;
	}

	copy->data = new;

	return SEPOL_OK;

exit:
	return rc;
}

int cil_copy_classmapping(struct cil_classmapping *orig, struct cil_classmapping **copy)
{
	struct cil_classmapping *new = NULL;
	struct cil_list_item *curr = NULL;
	struct cil_list_item *new_item = NULL;
	int rc = SEPOL_ERR;

	cil_classmapping_init(&new);

	new->classmap_str = cil_strdup(orig->classmap_str);
	new->classmap_perm_str = cil_strdup(orig->classmap_perm_str);

	curr = orig->classpermsets_str->head;

	cil_list_init(&new->classpermsets_str);

	while (curr != NULL) {
		cil_list_item_init(&new_item);
		new_item->flavor = curr->flavor;
		if (curr->flavor == CIL_AST_STR) {
			new_item->data = cil_strdup(curr->data);
		} else if (curr->flavor == CIL_CLASSPERMSET) {
			cil_classpermset_init((struct cil_classpermset**)&new_item->data);
			rc = cil_copy_fill_classpermset((struct cil_classpermset*)curr->data, (struct cil_classpermset*)new_item->data);
			if (rc != SEPOL_OK) {
				goto exit;
			}
		}

		rc = cil_list_prepend_item(new->classpermsets_str, new_item);
		if (rc != SEPOL_OK) {
			goto exit;
		}

		curr = curr->next;
	}

	*copy = new;

	return SEPOL_OK;

exit:
	return rc;
}

int cil_copy_permset(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_permset *new = NULL;
	int rc = SEPOL_ERR;
	char *key = NULL;

	cil_permset_init(&new);

	if (((struct cil_symtab_datum*)orig->data)->name != NULL) {
		key = ((struct cil_symtab_datum*)orig->data)->name;
		rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
		if (rc != SEPOL_OK) {
			printf("cil_copy_permset: cil_symtab_insert failed, rc: %d\n", rc);
			goto exit;
		}
	}

	if (((struct cil_permset*)orig->data)->perms_list_str != NULL) {
		rc = cil_copy_list(((struct cil_permset*)orig->data)->perms_list_str, &new->perms_list_str);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	copy->data = new;

	return SEPOL_OK;

exit:
	cil_destroy_permset(new);
	return rc;
}

int cil_copy_class(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_class *new = NULL;
	int rc = SEPOL_ERR;
	char *key = NULL;

	cil_class_init(&new);

	key = ((struct cil_symtab_datum *)orig->data)->name;

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_class: cil_symtab_insert failed, rc: %d\n", rc);
		goto exit;
	}

	cil_symtab_init(&new->perms, CIL_SYM_SIZE);

	new->common = NULL;
	copy->data = new;

	return SEPOL_OK;

exit:
	cil_destroy_class(new);
	return rc;
}

int cil_copy_fill_classpermset(struct cil_classpermset *orig, struct cil_classpermset *new)
{
	int rc = SEPOL_ERR;

	new->class_str = cil_strdup(orig->class_str);
	new->permset_str = cil_strdup(orig->permset_str);

	if (orig->permset != NULL) {
		cil_permset_init(&new->permset);

		rc = cil_copy_list(orig->permset->perms_list_str, &new->permset->perms_list_str);
		if (rc != SEPOL_OK) {
			goto exit;
		}

	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_copy_classpermset(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_classpermset *new = NULL;
	char *key = NULL;
	int rc = SEPOL_ERR;

	cil_classpermset_init(&new);

	if (((struct cil_symtab_datum*)orig->data)->name != NULL) {
		key = ((struct cil_symtab_datum*)orig->data)->name;
		rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
		if (rc != SEPOL_OK) {
			printf("cil_copy_classpermset: cil_symtab_insert failed, rc: %d\n", rc);
			goto exit;
		}
	}

	rc = cil_copy_fill_classpermset((struct cil_classpermset*)orig->data, new);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	copy->data = new;

	return SEPOL_OK;

exit:
	cil_destroy_classpermset(new);
	return rc;
}

int cil_copy_common(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_common *new = NULL;
	int rc = SEPOL_ERR;

	cil_common_init(&new);

	char *key = ((struct cil_symtab_datum *)orig->data)->name;
	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_common: cil_symtab_insert failed, rc: %d\n", rc);
		goto exit;
	}
	cil_symtab_init(&new->perms, CIL_SYM_SIZE);
	copy->data = new;

	return SEPOL_OK;

exit:
	cil_destroy_common(new);
	return rc;
}

int cil_copy_classcommon(struct cil_classcommon *orig, struct cil_classcommon **copy)
{
	struct cil_classcommon *new = NULL;

	cil_classcommon_init(&new);

	new->class_str = cil_strdup(orig->class_str);
	new->common_str = cil_strdup(orig->common_str);

	*copy = new;

	return SEPOL_OK;
}

int cil_copy_sid(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_sid *new = NULL;
	int rc = SEPOL_ERR;
	char *key = NULL;

	cil_sid_init(&new);

	key = ((struct cil_symtab_datum*)orig->data)->name;

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_sid: cil_symtab_insert failed, rc: %d\n", rc);
		goto exit;
	}

	copy->data = new;

	return SEPOL_OK;

exit:
	cil_destroy_sid(new);
	return rc;
}

int cil_copy_sidcontext(struct cil_tree_node *orig, struct cil_tree_node *copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_sidcontext *new = NULL;
	int rc = SEPOL_ERR;

	cil_sidcontext_init(&new);

	new->context_str = cil_strdup(((struct cil_sidcontext*)orig->data)->context_str);

	if (((struct cil_sidcontext*)orig->data)->context != NULL) {
		cil_context_init(&new->context);
		rc = cil_copy_fill_context(((struct cil_sidcontext*)orig->data)->context, new->context);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	copy->data = new;

	return SEPOL_OK;

exit:
	cil_destroy_sidcontext(new);
	return rc;
}

int cil_copy_user(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_user *new = NULL;
	int rc = SEPOL_ERR;
	char *key = NULL;

	cil_user_init(&new);

	key = ((struct cil_symtab_datum *)orig->data)->name;

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_user: cil_symtab_insert failed, rc: %d\n", rc);
		goto exit;
	}

	copy->data = new;

	return SEPOL_OK;

exit:
	cil_destroy_user(new);
	return rc;
}

int cil_copy_userrole(struct cil_userrole *orig, struct cil_userrole **copy)
{
	struct cil_userrole *new = NULL;

	cil_userrole_init(&new);

	new->user_str = cil_strdup(orig->user_str);
	new->role_str = cil_strdup(orig->role_str);

	*copy = new;

	return SEPOL_OK;
}

int cil_copy_userlevel(struct cil_userlevel *orig, struct cil_userlevel **copy)
{
	struct cil_userlevel *new = NULL;
	int rc = SEPOL_ERR;

	cil_userlevel_init(&new);

	new->user_str = cil_strdup(orig->user_str);
	new->level_str = cil_strdup(orig->level_str);

	if (orig->level != NULL) {
		cil_level_init(&new->level);
		rc = cil_copy_fill_level(orig->level, new->level);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_userlevel(new);
	return rc;
}

int cil_copy_userrange(struct cil_userrange *orig, struct cil_userrange **copy)
{
	struct cil_userrange *new = NULL;
	int rc = SEPOL_ERR;

	cil_userrange_init(&new);

	new->user_str = cil_strdup(orig->user_str);
	new->range_str = cil_strdup(orig->range_str);

	if (orig->range != NULL) {
		cil_levelrange_init(&new->range);
		rc = cil_copy_fill_levelrange(orig->range, new->range);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_userrange(new);
	return rc;
}

int cil_copy_userbounds(struct cil_userbounds *orig, struct cil_userbounds **copy)
{
	struct cil_userbounds *new = NULL;

	cil_userbounds_init(&new);

	new->user_str = cil_strdup(orig->user_str);
	new->bounds_str = cil_strdup(orig->bounds_str);

	*copy = new;

	return SEPOL_OK;
}

int cil_copy_role(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_role *new = NULL;
	int rc = SEPOL_ERR;
	char *key = NULL;

	cil_role_init(&new);

	key = ((struct cil_symtab_datum *)orig->data)->name;

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_role: cil_symtab_insert failed, rc: %d\n", rc);
		goto exit;
	}

	copy->data = new;

	return SEPOL_OK;

exit:
	cil_destroy_role(new);
	return rc;
}

int cil_copy_roletype(struct cil_roletype *orig, struct cil_roletype **copy)
{
	struct cil_roletype *new = NULL;

	cil_roletype_init(&new);

	new->role_str = cil_strdup(orig->role_str);
	new->type_str = cil_strdup(orig->type_str);

	*copy = new;

	return SEPOL_OK;
}

int cil_copy_rolebounds(struct cil_rolebounds *orig, struct cil_rolebounds **copy)
{
	struct cil_rolebounds *new = NULL;

	cil_rolebounds_init(&new);

	new->role_str = cil_strdup(orig->role_str);
	new->bounds_str = cil_strdup(orig->bounds_str);

	*copy = new;

	return SEPOL_OK;
}

int cil_copy_roledominance(struct cil_roledominance *orig, struct cil_roledominance **copy)
{
	struct cil_roledominance *new = NULL;

	cil_roledominance_init(&new);

	new->role_str = cil_strdup(orig->role_str);
	new->domed_str = cil_strdup(orig->domed_str);

	*copy = new;

	return SEPOL_OK;
}

int cil_copy_roleallow(struct cil_roleallow *orig, struct cil_roleallow **copy)
{
	struct cil_roleallow *new = NULL;

	cil_roleallow_init(&new);

	new->src_str = cil_strdup(orig->src_str);
	new->tgt_str = cil_strdup(orig->tgt_str);

	*copy = new;

	return SEPOL_OK;
}

int cil_copy_type(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_type *new = NULL;
	int rc = SEPOL_ERR;
	char *key = NULL;

	cil_type_init(&new);

	key = ((struct cil_symtab_datum *)orig->data)->name;

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_type: cil_symtab_insert failed, rc: %d\n", rc);
		goto exit;
	}

	copy->data = new;

	return SEPOL_OK;

exit:
	cil_destroy_type(new);
	return rc;
}

int cil_copy_typebounds(struct cil_typebounds *orig, struct cil_typebounds **copy)
{
	struct cil_typebounds *new = NULL;

	cil_typebounds_init(&new);

	new->type_str = cil_strdup(orig->type_str);
	new->bounds_str = cil_strdup(orig->bounds_str);

	*copy = new;

	return SEPOL_OK;
}

int cil_copy_typepermissive(struct cil_typepermissive *orig, struct cil_typepermissive **copy)
{
	struct cil_typepermissive *new = NULL;

	cil_typepermissive_init(&new);

	new->type_str = cil_strdup(orig->type_str);

	*copy = new;

	return SEPOL_OK;
}

int cil_copy_typeattribute(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_typeattribute *new = NULL;
	int rc = SEPOL_ERR;
	char *key = NULL;

	cil_typeattribute_init(&new);

	key = ((struct cil_symtab_datum *)orig->data)->name;

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_typeattribute: cil_symtab_insert failed, rc: %d\n", rc);
		goto exit;
	}

	copy->data = new;

	return SEPOL_OK;

exit:
	cil_destroy_typeattribute(new);
	return rc;
}

int cil_copy_typeattributetypes(struct cil_typeattributetypes *orig, struct cil_typeattributetypes **copy)
{
	struct cil_typeattributetypes *new = NULL;
	int rc = SEPOL_ERR;

	cil_typeattributetypes_init(&new);

	new->attr_str = cil_strdup(orig->attr_str);

	if (orig->types_list_str != NULL) {
		rc = cil_copy_list(orig->types_list_str, &new->types_list_str);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	if (orig->neg_list_str != NULL) {
		rc = cil_copy_list(orig->neg_list_str, &new->neg_list_str);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_typeattributetypes(new);
	return rc;
}

int cil_copy_typealias(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_typealias *new = NULL;
	int rc = SEPOL_ERR;
	char *key = NULL;

	cil_typealias_init(&new);

	key = ((struct cil_symtab_datum*)orig->data)->name;

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_typealias: cil_symtab_insert failed, rc: %d\n", rc);
		goto exit;
	}

	new->type_str = cil_strdup(((struct cil_typealias*)orig->data)->type_str);
	copy->data = new;

	return SEPOL_OK;

exit:
	cil_destroy_typealias(new);
	return rc;
}

int cil_copy_roletransition(struct cil_roletransition *orig, struct cil_roletransition **copy)
{
	struct cil_roletransition *new = NULL;

	cil_roletransition_init(&new);

	new->src_str = cil_strdup(orig->src_str);
	new->tgt_str = cil_strdup(orig->tgt_str);
	new->obj_str = cil_strdup(orig->obj_str);
	new->result_str = cil_strdup(orig->result_str);

	*copy = new;

	return SEPOL_OK;
}

int cil_copy_filetransition(struct cil_filetransition *orig, struct cil_filetransition **copy)
{
	struct cil_filetransition *new = NULL;

	cil_filetransition_init(&new);

	new->src_str = cil_strdup(orig->src_str);
	new->exec_str = cil_strdup(orig->exec_str);
	new->proc_str = cil_strdup(orig->proc_str);
	new->dest_str = cil_strdup(orig->dest_str);
	new->path_str = cil_strdup(orig->path_str);

	*copy = new;

	return SEPOL_OK;
}

int cil_copy_rangetransition(struct cil_rangetransition *orig, struct cil_rangetransition **copy)
{
	struct cil_rangetransition *new = NULL;
	int rc = SEPOL_ERR;

	cil_rangetransition_init(&new);

	new->src_str = cil_strdup(orig->src_str);
	new->exec_str = cil_strdup(orig->exec_str);
	new->obj_str = cil_strdup(orig->obj_str);
	new->range_str = cil_strdup(orig->range_str);

	if (orig->range != NULL) {
		cil_levelrange_init(&new->range);
		rc = cil_copy_fill_levelrange(orig->range, new->range);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_rangetransition(new);
	return rc;
}

int cil_copy_bool(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_bool *new = NULL;
	int rc = SEPOL_ERR;
	char *key = NULL;

	cil_bool_init(&new);

	key = ((struct cil_symtab_datum *)orig->data)->name;

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_bool: cil_symtab_insert failed, rc: %d\n", rc);
		goto exit;
	}

	new->value = ((struct cil_bool *)orig->data)->value;
	copy->data = new;

	return SEPOL_OK;

exit:
	cil_destroy_bool(new);
	return rc;
}

int cil_copy_avrule(struct cil_avrule *orig, struct cil_avrule **copy)
{
	struct cil_avrule *new = NULL;
	int rc = SEPOL_ERR;

	cil_avrule_init(&new);

	new->rule_kind = orig->rule_kind;
	new->src_str = cil_strdup(orig->src_str);
	new->tgt_str = cil_strdup(orig->tgt_str);
	new->classpermset_str = cil_strdup(orig->classpermset_str);
	cil_classpermset_init(&new->classpermset);
	rc = cil_copy_fill_classpermset(orig->classpermset, new->classpermset);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_avrule(new);
	return rc;
}

int cil_copy_type_rule(struct cil_type_rule *orig, struct cil_type_rule **copy)
{
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

int cil_copy_sens(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_sens *new = NULL;
	int rc = SEPOL_ERR;
	char *key = NULL;

	cil_sens_init(&new);

	key = ((struct cil_symtab_datum*)orig->data)->name;

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_sens: cil_symtab_insert failed, rc: %d\n", rc);
		goto exit;
	}

	copy->data = new;

	return SEPOL_OK;

exit:
	cil_destroy_sensitivity(new);
	return rc;
}

int cil_copy_sensalias(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_sensalias *new = NULL;
	int rc = SEPOL_ERR;
	char *key = NULL;

	cil_sensalias_init(&new);

	key = ((struct cil_symtab_datum*)orig->data)->name;

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_sensalias: cil_symtab_insert failed, rc: %d\n", rc);
		goto exit;
	}

	new->sens_str = cil_strdup(((struct cil_sensalias*)orig->data)->sens_str);
	copy->data = new;

	return SEPOL_OK;

exit:
	cil_destroy_sensalias(new);
	return rc;
}

int cil_copy_cat(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_cat *new = NULL;
	int rc = SEPOL_ERR;
	char *key = NULL;

	cil_cat_init(&new);

	key = ((struct cil_symtab_datum*)orig->data)->name;

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_cat: cil_symtab_insert failed, rc: %d\n", rc);
		goto exit;
	}

	copy->data = new;

	return SEPOL_OK;

exit:
	cil_destroy_category(new);
	return rc;
}

int cil_copy_catalias(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_catalias *new = NULL;
	int rc = SEPOL_ERR;
	char *key = NULL;

	cil_catalias_init(&new);

	key = ((struct cil_symtab_datum*)orig->data)->name;

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_catalias: cil_symtab_insert failed, rc: %d\n", rc);
		goto exit;
	}

	new->cat_str = cil_strdup(((struct cil_catalias*)orig->data)->cat_str);
	copy->data = new;

	return SEPOL_OK;

exit:
	cil_destroy_catalias(new);
	return rc;
}

int cil_copy_fill_catrange(struct cil_catrange *orig, struct cil_catrange *new)
{
	new->cat_low_str = cil_strdup(orig->cat_low_str);
	new->cat_high_str = cil_strdup(orig->cat_high_str);

	return SEPOL_OK;
}

int cil_copy_catrange(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_catrange *new = NULL;
	struct cil_catrange *old = NULL;
	int rc = SEPOL_ERR;
	char *key = NULL;

	cil_catrange_init(&new);

	old = orig->data;
	key = old->datum.name;

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_catrange: cil_symtab_insert failed, rc: %d\n", rc);
		goto exit;
	}

	new->cat_low_str = cil_strdup(old->cat_low_str);
	new->cat_high_str = cil_strdup(old->cat_high_str);
	copy->data = new;

	return SEPOL_OK;

exit:
	cil_destroy_catrange(new);
	return rc;
}

int cil_copy_fill_catset(struct cil_catset *orig, struct cil_catset *new)
{
	struct cil_list_item *orig_item;
	struct cil_list_item *new_item;
	int rc = SEPOL_ERR;

	cil_list_init(&new->cat_list_str);

	for (orig_item = orig->cat_list_str->head; orig_item != NULL; orig_item = orig_item->next) {
		cil_list_item_init(&new_item);

		switch (orig_item->flavor) {
		case CIL_CATRANGE: {
			struct cil_catrange *catrange = NULL;
			cil_catrange_init(&catrange);
			rc = cil_copy_fill_catrange(orig_item->data, catrange);
			if (rc != SEPOL_OK) {
				goto exit;
			}
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

		rc = cil_list_append_item(new->cat_list_str, new_item);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	cil_list_destroy(&new->cat_list_str, 1);
	return rc;
}

int cil_copy_catset(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_catset *new = NULL;
	struct cil_catset *old = NULL;
	int rc = SEPOL_ERR;
	char *key = NULL;

	cil_catset_init(&new);

	old = orig->data;
	key = old->datum.name;

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_catset: cil_symtab_insert failed, rc: %d\n", rc);
		goto exit;
	}

	rc = cil_copy_fill_catset(old, new);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	copy->data = new;

	return SEPOL_OK;

exit:
	cil_destroy_catset(new);
	return rc;

}

int cil_copy_senscat(struct cil_senscat *orig, struct cil_senscat **copy)
{
	struct cil_senscat *new = NULL;
	int rc = SEPOL_ERR;

	cil_senscat_init(&new);

	new->sens_str = cil_strdup(orig->sens_str);
	new->catset_str = cil_strdup(orig->catset_str);

	if (orig->catset != NULL) {
		cil_catset_init(&new->catset);
		rc = cil_copy_fill_catset(orig->catset, new->catset);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_senscat(new);
	return rc;
}

int cil_copy_catorder(struct cil_catorder *orig, struct cil_catorder **copy)
{
	struct cil_catorder *new = NULL;
	int rc = SEPOL_ERR;

	cil_catorder_init(&new);
	if (orig->cat_list_str != NULL) {
		rc = cil_copy_list(orig->cat_list_str, &new->cat_list_str);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_catorder(new);
	return rc;
}

int cil_copy_dominance(struct cil_sens_dominates *orig, struct cil_sens_dominates **copy)
{
	struct cil_sens_dominates *new = NULL;
	int rc = SEPOL_ERR;

	cil_sens_dominates_init(&new);
	if (orig->sens_list_str != NULL) {
		rc = cil_copy_list(orig->sens_list_str, &new->sens_list_str);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_dominance(new);
	return rc;
}

int cil_copy_fill_level(struct cil_level *orig, struct cil_level *new)
{
	int rc = SEPOL_ERR;

	new->sens_str = cil_strdup(orig->sens_str);
	new->catset_str = cil_strdup(orig->catset_str);

	if (orig->catset != NULL) {
		cil_catset_init(&new->catset);
		rc = cil_copy_fill_catset(orig->catset, new->catset);
		if (rc != SEPOL_OK) {
			cil_destroy_catset(new->catset);
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_copy_level(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_level *new = NULL;
	int rc = SEPOL_ERR;

	cil_level_init(&new);

	if (((struct cil_level*)orig->data)->datum.name != NULL) {
		char *key = ((struct cil_symtab_datum*)orig->data)->name;
		rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
		if (rc != SEPOL_OK) {
			printf("cil_copy_level: cil_symtab_insert failed, rc: %d\n", rc);
			goto exit;
		}
	}

	rc = cil_copy_fill_level((struct cil_level*)orig->data, new);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	copy->data = new;

	return SEPOL_OK;

exit:
	cil_destroy_level(new);
	return rc;
}

int cil_copy_fill_levelrange(struct cil_levelrange *orig, struct cil_levelrange *new)
{
	int rc = SEPOL_ERR;

	new->low_str = cil_strdup(orig->low_str);
	new->high_str = cil_strdup(orig->high_str);

	if (orig->low != NULL) {
		cil_level_init(&new->low);
		rc = cil_copy_fill_level(orig->low, new->low);
		if (rc != SEPOL_OK) {
			cil_destroy_level(new->low);
			goto exit;
		}
	}

	if (orig->high != NULL) {
		cil_level_init(&new->high);
		rc = cil_copy_fill_level(orig->high, new->high);
		if (rc != SEPOL_OK) {
			cil_destroy_level(new->high);
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_copy_levelrange(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_levelrange *new = NULL;
	int rc = SEPOL_ERR;

	cil_levelrange_init(&new);

	if (((struct cil_levelrange*)orig->data)->datum.name != NULL) {
		char *key = ((struct cil_symtab_datum*)orig->data)->name;
		rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
		if (rc != SEPOL_OK) {
			printf("cil_copy_levelrange: cil_symtab_insert failed, rc: %d\n", rc);
			goto exit;
		}
	}

	rc = cil_copy_fill_levelrange((struct cil_levelrange*)orig->data, new);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	copy->data = new;

	return SEPOL_OK;

exit:
	cil_destroy_levelrange(new);
	return rc;
}

int cil_copy_fill_context(struct cil_context *orig, struct cil_context *new)
{
	int rc = SEPOL_ERR;

	new->user_str = cil_strdup(orig->user_str);
	new->role_str = cil_strdup(orig->role_str);
	new->type_str = cil_strdup(orig->type_str);
	new->range_str = cil_strdup(orig->range_str);

	if (orig->range != NULL) {
		cil_levelrange_init(&new->range);
		rc = cil_copy_fill_levelrange(orig->range, new->range);
		if (rc != SEPOL_OK) {
			cil_destroy_levelrange(new->range);
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_copy_context(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_context *new = NULL;
	int rc = SEPOL_ERR;

	cil_context_init(&new);

	if (((struct cil_context*)orig->data)->datum.name != NULL) {
		char *key = ((struct cil_symtab_datum*)orig->data)->name;
		rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
		if (rc != SEPOL_OK) {
			printf("cil_copy_context: cil_symtab_insert failed, rc: %d\n", rc);
			goto exit;
		}
	}

	rc = cil_copy_fill_context(((struct cil_context*)orig->data), new);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	copy->data = new;

	return SEPOL_OK;

exit:
	cil_destroy_context(new);
	return rc;
}

int cil_copy_netifcon(struct cil_netifcon *orig, struct cil_netifcon **copy)
{
	struct cil_netifcon *new = NULL;
	int rc = SEPOL_ERR;

	cil_netifcon_init(&new);

	new->interface_str = cil_strdup(orig->interface_str);
	new->if_context_str = cil_strdup(orig->if_context_str);
	new->packet_context_str = cil_strdup(orig->packet_context_str);

	if (orig->if_context != NULL) {
		cil_context_init(&new->if_context);
		rc = cil_copy_fill_context(orig->if_context, new->if_context);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	if (orig->packet_context != NULL) {
		cil_context_init(&new->packet_context);
		rc = cil_copy_fill_context(orig->packet_context, new->packet_context);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_netifcon(new);
	return rc;
}

int cil_copy_genfscon(struct cil_genfscon *orig, struct cil_genfscon **copy)
{
	struct cil_genfscon *new = NULL;
	int rc = SEPOL_ERR;

	cil_genfscon_init(&new);

	new->fs_str = cil_strdup(orig->fs_str);
	new->path_str = cil_strdup(orig->path_str);
	new->context_str = cil_strdup(orig->context_str);

	if (orig->context != NULL) {
		cil_context_init(&new->context);
		rc = cil_copy_fill_context(orig->context, new->context);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_genfscon(new);
	return rc;
}

int cil_copy_filecon(struct cil_filecon *orig, struct cil_filecon **copy)
{
	struct cil_filecon *new = NULL;
	int rc = SEPOL_ERR;

	cil_filecon_init(&new);

	new->root_str = cil_strdup(orig->root_str);
	new->path_str = cil_strdup(orig->path_str);
	new->type = orig->type;
	new->context_str = cil_strdup(orig->context_str);

	if (orig->context != NULL) {
		cil_context_init(&new->context);
		rc = cil_copy_fill_context(orig->context, new->context);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_filecon(new);
	return rc;
}

int cil_copy_nodecon(struct cil_nodecon *orig, struct cil_nodecon **copy)
{
	struct cil_nodecon *new = NULL;
	int rc = SEPOL_ERR;

	cil_nodecon_init(&new);

	new->addr_str = cil_strdup(orig->addr_str);
	new->mask_str = cil_strdup(orig->mask_str);
	new->context_str = cil_strdup(orig->context_str);

	if (orig->addr != NULL) {
		cil_ipaddr_init(&new->addr);
		rc = cil_copy_fill_ipaddr(orig->addr, new->addr);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	if (orig->mask != NULL) {
		cil_ipaddr_init(&new->mask);
		rc = cil_copy_fill_ipaddr(orig->mask, new->mask);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	if (orig->context != NULL) {
		cil_context_init(&new->context);
		rc = cil_copy_fill_context(orig->context, new->context);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_nodecon(new);
	return rc;
}

int cil_copy_portcon(struct cil_portcon *orig, struct cil_portcon **copy)
{
	struct cil_portcon *new = NULL;
	int rc = SEPOL_ERR;

	cil_portcon_init(&new);

	new->proto = orig->proto;
	new->port_low = orig->port_low;
	new->port_high = orig->port_high;
	new->context_str = cil_strdup(orig->context_str);

	if (orig->context != NULL) {
		cil_context_init(&new->context);
		rc = cil_copy_fill_context(orig->context, new->context);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_portcon(new);
	return rc;
}

int cil_copy_pirqcon(struct cil_pirqcon *orig, struct cil_pirqcon **copy)
{
	struct cil_pirqcon *new = NULL;
	int rc = SEPOL_ERR;

	cil_pirqcon_init(&new);

	new->pirq = orig->pirq;
	new->context_str = cil_strdup(orig->context_str);

	if (orig->context != NULL) {
		cil_context_init(&new->context);
		rc = cil_copy_fill_context(orig->context, new->context);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_pirqcon(new);
	return rc;
}

int cil_copy_iomemcon(struct cil_iomemcon *orig, struct cil_iomemcon **copy)
{
	struct cil_iomemcon *new = NULL;
	int rc = SEPOL_ERR;

	cil_iomemcon_init(&new);

	new->iomem_low = orig->iomem_low;
	new->iomem_high = orig->iomem_high;
	new->context_str = cil_strdup(orig->context_str);

	if (orig->context != NULL) {
		cil_context_init(&new->context);
		rc = cil_copy_fill_context(orig->context, new->context);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_iomemcon(new);
	return rc;
}

int cil_copy_ioportcon(struct cil_ioportcon *orig, struct cil_ioportcon **copy)
{
	struct cil_ioportcon *new = NULL;
	int rc = SEPOL_ERR;

	cil_ioportcon_init(&new);

	new->ioport_low = orig->ioport_low;
	new->ioport_high = orig->ioport_high;
	new->context_str = cil_strdup(orig->context_str);

	if (orig->context != NULL) {
		cil_context_init(&new->context);
		rc = cil_copy_fill_context(orig->context, new->context);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_ioportcon(new);
	return rc;
}

int cil_copy_pcidevicecon(struct cil_pcidevicecon *orig, struct cil_pcidevicecon **copy)
{
	struct cil_pcidevicecon *new = NULL;
	int rc = SEPOL_ERR;

	cil_pcidevicecon_init(&new);

	new->dev = orig->dev;
	new->context_str = cil_strdup(orig->context_str);

	if (orig->context != NULL) {
		cil_context_init(&new->context);
		rc = cil_copy_fill_context(orig->context, new->context);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_pcidevicecon(new);
	return rc;
}

int cil_copy_fsuse(struct cil_fsuse *orig, struct cil_fsuse **copy)
{
	struct cil_fsuse *new = NULL;
	int rc = SEPOL_ERR;

	cil_fsuse_init(&new);

	new->type = orig->type;
	new->fs_str = cil_strdup(orig->fs_str);
	new->context_str = cil_strdup(orig->context_str);

	if (orig->context != NULL) {
		cil_context_init(&new->context);
		rc = cil_copy_fill_context(orig->context, new->context);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_fsuse(new);
	return rc;
}

int cil_copy_constrain(struct cil_constrain *orig, struct cil_constrain **copy)
{
	struct cil_constrain *new = NULL;
	struct cil_list_item *curr_old = NULL;
	struct cil_list *new_list = NULL;
	struct cil_list_item *curr_new = NULL;
	struct cil_conditional *cond_new = NULL;
	int rc = SEPOL_ERR;

	cil_constrain_init(&new);

	if (orig->class_list_str != NULL) {
		rc = cil_copy_list(orig->class_list_str, &new->class_list_str);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	if (orig->perm_list_str != NULL) {
		rc = cil_copy_list(orig->perm_list_str, &new->perm_list_str);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	cil_list_init(&new_list);
	curr_old = orig->expr->head;

	while (curr_old != NULL) {
		cil_list_item_init(&curr_new);

		cil_conditional_init(&cond_new);

		cil_copy_conditional(curr_old->data, cond_new);
		curr_new->data = cond_new;
		curr_new->flavor = curr_old->flavor;

		rc = cil_list_append_item(new_list, curr_new);
		if (rc != SEPOL_OK) {
			goto exit;
		}

		curr_old = curr_old->next;
	}
	new->expr = new_list;

	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_constrain(new);
	return rc;
}

int cil_copy_call(struct cil_db *db, struct cil_call *orig, struct cil_call **copy)
{
	struct cil_call *new = NULL;
	int rc = SEPOL_ERR;

	cil_call_init(&new);

	new->macro_str = cil_strdup(orig->macro_str);

	cil_tree_init(&new->args_tree);
	cil_tree_node_init(&new->args_tree->root);
	rc = cil_copy_ast(db, orig->args_tree->root, new->args_tree->root);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_call(new);
	return rc;
}

int cil_copy_macro(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_macro *new = NULL;
	int rc = SEPOL_ERR;
	char *key = NULL;

	cil_macro_init(&new);

	key = ((struct cil_symtab_datum*)orig->data)->name;
	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_macro: cil_symtab_insert failed, rc: %d\n", rc);
		goto exit;
	}

	cil_symtab_array_init(new->symtab, CIL_SYM_NUM);
	rc = cil_copy_list(((struct cil_macro*)orig->data)->params, &new->params);

	copy->data = new;

	return SEPOL_OK;

exit:
	cil_destroy_macro(new);
	return rc;
}

int cil_copy_optional(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_optional *new = NULL;
	int rc = SEPOL_ERR;
	char *key = NULL;

	cil_optional_init(&new);

	key = ((struct cil_symtab_datum *)orig->data)->name;
	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_optional: cil_symtab_insert failed, rc: %d\n", rc);
		goto exit;
	}

	copy->data = new;

	return SEPOL_OK;

exit:
	cil_destroy_optional(new);
	return rc;
}

int cil_copy_fill_ipaddr(struct cil_ipaddr *orig, struct cil_ipaddr *new)
{
	new->family = orig->family;
	memcpy(&new->ip, &orig->ip, sizeof(orig->ip));

	return SEPOL_OK;
}

int cil_copy_ipaddr(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_ipaddr *new = NULL;
	struct cil_ipaddr *old = NULL;
	char * key = NULL;
	int rc = SEPOL_ERR;

	cil_ipaddr_init(&new);

	old = (struct cil_ipaddr*)orig->data;

	key = old->datum.name;
	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_ipaddr: cil_symtab_insert failed, rc: %d\n", rc);
		goto exit;
	}

	rc = cil_copy_fill_ipaddr(old, new);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	copy->data = new;

	return SEPOL_OK;

exit:
	cil_destroy_ipaddr(new);
	return rc;
}

int cil_copy_conditional(struct cil_conditional *orig, struct cil_conditional *new)
{
	new->str = cil_strdup(orig->str);
	new->flavor = orig->flavor;

	return SEPOL_OK;
}

int cil_copy_boolif(struct cil_booleanif *orig, struct cil_booleanif **copy)
{
	int rc = SEPOL_ERR;
	struct cil_list_item *curr_old = NULL;
	struct cil_list *new_list = NULL;
	struct cil_list_item *curr_new = NULL;
	struct cil_conditional *cond_new = NULL;
	struct cil_booleanif *new = NULL;

	cil_boolif_init(&new);

	cil_list_init(&new_list);
	curr_old = orig->expr_stack->head;

	while (curr_old != NULL) {
		cil_list_item_init(&curr_new);

		cil_conditional_init(&cond_new);

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
	cil_destroy_boolif(new);
	return rc;
}

int __cil_copy_data_helper(struct cil_db *db, struct cil_tree_node *orig, struct cil_tree_node *new, enum cil_sym_index sym_index, int (*copy_data)(struct cil_tree_node *orig_node, struct cil_tree_node *new_node, symtab_t *sym))
{
	int rc = SEPOL_ERR;
	symtab_t *symtab = NULL;

	rc = cil_get_symtab(db, new->parent, &symtab, sym_index);
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
	new->path = orig->path;
	new->flavor = orig->flavor;

	if (parent->cl_head == NULL) {
		parent->cl_head = new;
		parent->cl_tail = new;
	} else {
		parent->cl_tail->next = new;
		parent->cl_tail = new;
	}

	switch (orig->flavor) {
	case CIL_BLOCK:
		rc = __cil_copy_data_helper(db, orig, new, CIL_SYM_BLOCKS, &cil_copy_block);
		break;
	case CIL_POLICYCAP:
		rc = __cil_copy_data_helper(db, orig, new, CIL_SYM_POLICYCAPS, &cil_copy_policycap);
		break;
	case CIL_PERM:
		rc = __cil_copy_data_helper(db, orig, new, CIL_SYM_UNKNOWN, &cil_copy_perm);
		break;
	case CIL_CLASSMAPPERM:
		rc = __cil_copy_data_helper(db, orig, new, CIL_SYM_UNKNOWN, &cil_copy_classmap_perm);
		break;
	case CIL_CLASSMAP:
		rc = __cil_copy_data_helper(db, orig, new, CIL_SYM_CLASSES, &cil_copy_classmap);
		break;
	case CIL_CLASSMAPPING:
		cil_copy_classmapping((struct cil_classmapping*)orig->data, (struct cil_classmapping**)&new->data);
		break;
	case CIL_PERMSET:
		rc = __cil_copy_data_helper(db, orig, new, CIL_SYM_PERMSETS, &cil_copy_permset);
		break;
	case CIL_CLASS:
		rc = __cil_copy_data_helper(db, orig, new, CIL_SYM_CLASSES, &cil_copy_class);
		break;
	case CIL_CLASSPERMSET:
		rc = __cil_copy_data_helper(db, orig, new, CIL_SYM_CLASSPERMSETS, &cil_copy_classpermset);
		break;
	case CIL_COMMON:
		rc = __cil_copy_data_helper(db, orig, new, CIL_SYM_COMMONS, &cil_copy_common);
		break;
	case CIL_CLASSCOMMON:
		rc = cil_copy_classcommon((struct cil_classcommon*)orig->data, (struct cil_classcommon**)&new->data); 
		break;
	case CIL_SID:
		rc = __cil_copy_data_helper(db, orig, new, CIL_SYM_SIDS, &cil_copy_sid);
		break;
	case CIL_SIDCONTEXT:
		rc = __cil_copy_data_helper(db, orig, new, CIL_SYM_SIDS, &cil_copy_sidcontext);
		break;
	case CIL_USER:
		rc = __cil_copy_data_helper(db, orig, new, CIL_SYM_USERS, &cil_copy_user);
		break;
	case CIL_USERROLE:
		rc = cil_copy_userrole((struct cil_userrole*)orig->data, (struct cil_userrole**)&new->data);
		break;
	case CIL_USERLEVEL:
		rc = cil_copy_userlevel((struct cil_userlevel*)orig->data, (struct cil_userlevel**)&new->data);
		break;
	case CIL_USERRANGE:
		rc = cil_copy_userrange((struct cil_userrange*)orig->data, (struct cil_userrange**)&new->data);
		break;
	case CIL_USERBOUNDS:
		rc = cil_copy_userbounds((struct cil_userbounds*)orig->data, (struct cil_userbounds**)&new->data);
		break;
	case CIL_ROLE:
		rc = __cil_copy_data_helper(db, orig, new, CIL_SYM_ROLES, &cil_copy_role);
		break;
	case CIL_ROLETYPE:
		rc = cil_copy_roletype((struct cil_roletype*)orig->data, (struct cil_roletype**)&new->data);
		break;
	case CIL_ROLEBOUNDS:
		rc = cil_copy_rolebounds((struct cil_rolebounds*)orig->data, (struct cil_rolebounds**)&new->data);
		break;
	case CIL_ROLEDOMINANCE:
		rc = cil_copy_roledominance((struct cil_roledominance*)orig->data, (struct cil_roledominance**)&new->data);
		break;
	case CIL_ROLEALLOW:
		rc = cil_copy_roleallow((struct cil_roleallow*)orig->data, (struct cil_roleallow**)&new->data);
		break;
	case CIL_TYPE:
		rc = __cil_copy_data_helper(db, orig, new, CIL_SYM_TYPES, &cil_copy_type);
		break;
	case CIL_TYPEBOUNDS:
		rc = cil_copy_typebounds((struct cil_typebounds*)orig->data, (struct cil_typebounds**)&new->data);
		break;
	case CIL_TYPEPERMISSIVE:
		rc = cil_copy_typepermissive((struct cil_typepermissive*)orig->data, (struct cil_typepermissive**)&new->data);
		break;
	case CIL_TYPEATTRIBUTE:
		rc = __cil_copy_data_helper(db, orig, new, CIL_SYM_TYPES, &cil_copy_typeattribute);
		break;
	case CIL_TYPEATTRIBUTETYPES:
		rc = cil_copy_typeattributetypes((struct cil_typeattributetypes*)orig->data, (struct cil_typeattributetypes**)&new->data);
		break;
	case CIL_TYPEALIAS:
		rc = __cil_copy_data_helper(db, orig, new, CIL_SYM_TYPES, &cil_copy_typealias);
		break;
	case CIL_ROLETRANSITION:
		rc = cil_copy_roletransition((struct cil_roletransition*)orig->data, (struct cil_roletransition**)&new->data);
		break;
	case CIL_FILETRANSITION:
		rc = cil_copy_filetransition((struct cil_filetransition*)orig->data, (struct cil_filetransition**)&new->data);
		break;
	case CIL_RANGETRANSITION:
		rc = cil_copy_rangetransition((struct cil_rangetransition*)orig->data, (struct cil_rangetransition**)&new->data);
		break;
	case CIL_TUNABLE:
		rc = __cil_copy_data_helper(db, orig, new, CIL_SYM_TUNABLES, &cil_copy_bool);
		break;
	case CIL_BOOL:
		rc = __cil_copy_data_helper(db, orig, new, CIL_SYM_BOOLS, &cil_copy_bool);
		break;
	case CIL_AVRULE:
		rc = cil_copy_avrule((struct cil_avrule*)orig->data, (struct cil_avrule**)&new->data);
		break;
	case CIL_TYPE_RULE:
		rc = cil_copy_type_rule((struct cil_type_rule*)orig->data, (struct cil_type_rule**)&new->data);
		break;
	case CIL_SENS:
		rc = __cil_copy_data_helper(db, orig, new, CIL_SYM_SENS, &cil_copy_sens);
		break;
	case CIL_SENSALIAS:
		rc = __cil_copy_data_helper(db, orig, new, CIL_SYM_SENS, &cil_copy_sensalias);
		break;
	case CIL_CAT:
		rc = __cil_copy_data_helper(db, orig, new, CIL_SYM_CATS, &cil_copy_cat);
		break;
	case CIL_CATALIAS:
		rc = __cil_copy_data_helper(db, orig, new, CIL_SYM_CATS, &cil_copy_catalias);
		break;
	case CIL_CATRANGE:
		rc = __cil_copy_data_helper(db, orig, new, CIL_SYM_CATS, &cil_copy_catrange);
		break;
	case CIL_CATSET:
		rc = __cil_copy_data_helper(db, orig, new, CIL_SYM_CATS, &cil_copy_catset);
		break;
	case CIL_SENSCAT:
		rc = cil_copy_senscat((struct cil_senscat*)orig->data, (struct cil_senscat**)&new->data);
		break;
	case CIL_CATORDER:
		rc = cil_copy_catorder((struct cil_catorder*)orig->data, (struct cil_catorder**)&new->data);
		break;
	case CIL_DOMINANCE:
		rc = cil_copy_dominance((struct cil_sens_dominates*)orig->data, (struct cil_sens_dominates**)&new->data);
		break;
	case CIL_LEVEL:
		rc = __cil_copy_data_helper(db, orig, new, CIL_SYM_LEVELS, &cil_copy_level);
		break;
	case CIL_LEVELRANGE:
		rc = __cil_copy_data_helper(db, orig, new, CIL_SYM_LEVELRANGES, &cil_copy_levelrange);
		break;
	case CIL_CONTEXT:
		rc = __cil_copy_data_helper(db, orig, new, CIL_SYM_CONTEXTS, &cil_copy_context);
		break;
	case CIL_NETIFCON:
		rc = cil_copy_netifcon((struct cil_netifcon*)orig->data, (struct cil_netifcon**)&new->data);
		break;
	case CIL_GENFSCON:
		rc = cil_copy_genfscon((struct cil_genfscon*)orig->data, (struct cil_genfscon**)&new->data);
		break;
	case CIL_FILECON:
		rc = cil_copy_filecon((struct cil_filecon*)orig->data, (struct cil_filecon**)&new->data);
		break;
	case CIL_NODECON:
		rc = cil_copy_nodecon((struct cil_nodecon*)orig->data, (struct cil_nodecon**)&new->data);
		break;
	case CIL_PORTCON:
		rc = cil_copy_portcon((struct cil_portcon*)orig->data, (struct cil_portcon**)&new->data);
		break;
	case CIL_PIRQCON:
		rc = cil_copy_pirqcon((struct cil_pirqcon*)orig->data, (struct cil_pirqcon**)&new->data);
		break;
	case CIL_IOMEMCON:
		rc = cil_copy_iomemcon((struct cil_iomemcon*)orig->data, (struct cil_iomemcon**)&new->data);
		break;
	case CIL_IOPORTCON:
		rc = cil_copy_ioportcon((struct cil_ioportcon*)orig->data, (struct cil_ioportcon**)&new->data);
		break;
	case CIL_PCIDEVICECON:
		rc = cil_copy_pcidevicecon((struct cil_pcidevicecon*)orig->data, (struct cil_pcidevicecon**)&new->data);
		break;
	case CIL_FSUSE:
		rc = cil_copy_fsuse((struct cil_fsuse*)orig->data, (struct cil_fsuse**)&new->data);
		break;
	case CIL_MLSCONSTRAIN:
		rc = cil_copy_constrain((struct cil_constrain*)orig->data, (struct cil_constrain**)&new->data);
		break;
	case CIL_CALL:
		rc = cil_copy_call(db, (struct cil_call*)orig->data, (struct cil_call**)&new->data);
		break;
	case CIL_MACRO:
		rc = __cil_copy_data_helper(db, orig, new, CIL_SYM_MACROS, &cil_copy_macro);
		break;
	case CIL_PARSE_NODE:
		new->data = cil_strdup(((char*)orig->data));
		rc = SEPOL_OK;
		break;
	case CIL_OPTIONAL:
		rc = __cil_copy_data_helper(db, orig, new, CIL_SYM_OPTIONALS, &cil_copy_optional);
		break;
	case CIL_IPADDR:
		rc = __cil_copy_data_helper(db, orig, new, CIL_SYM_IPADDRS, &cil_copy_ipaddr);
		break;
	case CIL_BOOLEANIF:
		rc = cil_copy_boolif((struct cil_booleanif*)orig->data, (struct cil_booleanif**)&new->data);
		break;
	default:
		goto exit;
	}

	if (rc != SEPOL_OK) {
		free(new);
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

