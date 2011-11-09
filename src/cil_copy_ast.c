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

int cil_copy_list(struct cil_list *data, struct cil_list **copy)
{
	struct cil_list *new = NULL;
	struct cil_list *new_sub = NULL;
	struct cil_list_item *new_item = NULL;
	struct cil_list_item *orig_item = NULL;
	int rc = SEPOL_ERR;

	if (data == NULL) {
		goto exit;
	}

	orig_item = data->head;
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
	struct cil_block *new = NULL;
	int rc = SEPOL_ERR;
	char *key = orig->datum.name;
	struct cil_tree_node *node = NULL;

	cil_block_init(&new);


	rc = cil_symtab_get_node(symtab, key, &node);
	if (rc != SEPOL_OK && rc != SEPOL_ENOENT) {
		cil_log(CIL_INFO, "cil_copy_block: cil_symtab_get_node failed, rc: %d\n", rc);
		goto exit;
	} else if (node != NULL){
		rc = SEPOL_EEXIST;
		goto exit;
	}

	cil_symtab_array_init(new->symtab, CIL_SYM_NUM);

	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_block(new);
	return rc;
}

int cil_copy_policycap(__attribute__((unused)) struct cil_db *db, void *data, void **copy, symtab_t *symtab)
{
	struct cil_policycap *orig = data;
	struct cil_policycap *new = NULL;
	int rc = SEPOL_ERR;
	char *key = orig->datum.name;
	struct cil_tree_node *node = NULL;

	cil_policycap_init(&new);

	rc = cil_symtab_get_node(symtab, key, &node);
	if (rc != SEPOL_OK && rc != SEPOL_ENOENT) {
		cil_log(CIL_INFO, "cil_copy_policycap: cil_symtab_get_node failed, rc: %d\n", rc);
		goto exit;
	} else if (node != NULL) {
		rc = SEPOL_EEXIST;
		goto exit;
	}

	*copy = new;

	return SEPOL_OK;
exit:
	cil_destroy_policycap(new);
	return rc;
}

int cil_copy_perm(__attribute__((unused)) struct cil_db *db, void *data, void **copy, symtab_t *symtab)
{
	struct cil_perm *orig = data;
	struct cil_perm *new = NULL;
	int rc = SEPOL_ERR;
	char *key = orig->datum.name;
	struct cil_tree_node *node = NULL;

	cil_perm_init(&new);

	rc = cil_symtab_get_node(symtab, key, &node);
	if (rc != SEPOL_OK && rc != SEPOL_ENOENT) {
		cil_log(CIL_INFO, "cil_copy_perm: cil_symtab_get_node failed, rc: %d\n", rc);
		goto exit;
	} else if (node != NULL) {
		rc = SEPOL_EEXIST;
		goto exit;
	}

	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_perm(new);
	return rc;
}

int cil_copy_classmap_perm(__attribute__((unused)) struct cil_db *db, void *data, void **copy, symtab_t *symtab)
{
	struct cil_classmap_perm *orig = data;
	struct cil_classmap_perm *new = NULL;
	int rc = SEPOL_ERR;
	char *key = orig->datum.name;
	struct cil_tree_node *node = NULL;

	cil_classmap_perm_init(&new);

	rc = cil_symtab_get_node(symtab, key, &node);
	if (rc != SEPOL_OK && rc != SEPOL_ENOENT) {
		cil_log(CIL_INFO, "cil_copy_classmap_perm: cil_symtab_get_node failed, rc: %d\n", rc);
		goto exit;
	} else if (node != NULL) {
		cil_log(CIL_INFO, "cil_copy_classmap_perm: classmap permissions cannot be redefined\n");
		rc = SEPOL_ERR;
		goto exit;
	}

	rc = cil_copy_list(orig->classperms, &new->classperms);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_classmap_perm(new);
	return rc;
}

int cil_copy_classmap(__attribute__((unused)) struct cil_db *db, void *data, void **copy, symtab_t *symtab)
{
	struct cil_classmap *orig = data;
	struct cil_classmap *new = NULL;
	int rc = SEPOL_ERR;
	char *key = orig->datum.name;
	struct cil_tree_node *node = NULL;

	cil_classmap_init(&new);

	rc = cil_symtab_get_node(symtab, key, &node);
	if (rc != SEPOL_OK && rc != SEPOL_ENOENT) {
		cil_log(CIL_INFO, "cil_copy_classmap: cil_symtab_get_node failed, rc: %d\n", rc);
		goto exit;
	} else if (node != NULL) {
		rc = SEPOL_ERR;
		cil_log(CIL_INFO, "cil_copy_classmap: classmap cannot be redefined\n");
		goto exit;
	}

	rc = symtab_init(&new->perms, CIL_SYM_SIZE);
	if (rc != SEPOL_OK) {
		cil_log(CIL_INFO, "cil_copy_classmap: symtab_init failed, rc: %d\n", rc);
		goto exit;
	}

	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_classmap(new);
	return rc;
}

int cil_copy_classmapping(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_classmapping *orig = data;
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

int cil_copy_permset(__attribute__((unused)) struct cil_db *db, void *data, void **copy, symtab_t *symtab)
{
	struct cil_permset *orig = data;
	struct cil_permset *new = NULL;
	int rc = SEPOL_ERR;
	char *key = orig->datum.name;
	struct cil_tree_node *node = NULL;

	cil_permset_init(&new);

	if (key != NULL) {
		rc = cil_symtab_get_node(symtab, key, &node);
		if (rc != SEPOL_OK && rc != SEPOL_ENOENT) {
			cil_log(CIL_INFO, "cil_copy_permset: cil_symtab_get_node failed, rc: %d\n", rc);
			goto exit;
		} else if (node != NULL) {
			cil_log(CIL_INFO, "cil_copy_permset: permset cannot be redefined\n");
			rc = SEPOL_ERR;
			goto exit;
		}
	}

	if (orig->perms_list_str != NULL) {
		rc = cil_copy_list(orig->perms_list_str, &new->perms_list_str);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_permset(new);
	return rc;
}

int cil_copy_class(__attribute__((unused)) struct cil_db *db, void *data, void **copy, symtab_t *symtab)
{
	struct cil_class *orig = data;
	struct cil_class *new = NULL;
	int rc = SEPOL_ERR;
	char *key = orig->datum.name;
	struct cil_tree_node *node = NULL;

	cil_class_init(&new);

	rc = cil_symtab_get_node(symtab, key, &node);
	if (rc != SEPOL_OK && rc != SEPOL_ENOENT) {
		cil_log(CIL_INFO, "cil_copy_class: failed to get symtab node\n");
		goto exit;
	} else if (node != NULL) {
		cil_log(CIL_INFO, "cil_copy_class: class cannot be redefined\n");
		rc = SEPOL_ERR;
		goto exit;
	}

	cil_symtab_init(&new->perms, CIL_SYM_SIZE);

	new->common = NULL;
	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_class(new);
	return rc;
}

int cil_copy_fill_classpermset(struct cil_classpermset *data, struct cil_classpermset *new)
{
	int rc = SEPOL_ERR;

	new->class_str = cil_strdup(data->class_str);
	new->permset_str = cil_strdup(data->permset_str);

	if (data->permset != NULL && data->permset_str == NULL) {
		cil_permset_init(&new->permset);

		rc = cil_copy_list(data->permset->perms_list_str, &new->permset->perms_list_str);
		if (rc != SEPOL_OK) {
			goto exit;
		}

	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_copy_classpermset(__attribute__((unused)) struct cil_db *db, void *data, void **copy, symtab_t *symtab)
{
	struct cil_classpermset *orig = data;
	struct cil_classpermset *new = NULL;
	char *key = orig->datum.name;
	int rc = SEPOL_ERR;
	struct cil_tree_node *node = NULL;

	cil_classpermset_init(&new);

	if (key != NULL) {
		rc = cil_symtab_get_node(symtab, key, &node);
		if (rc != SEPOL_OK && rc != SEPOL_ENOENT) {
			cil_log(CIL_INFO, "cil_copy_classpermset: cil_symtab_get_node failed, rc: %d\n", rc);
			goto exit;
		} else if (node != NULL) {
			rc = SEPOL_ERR;
			cil_log(CIL_INFO, "cil_copy_classpermset: classpermissionset cannot be redefined\n");
			goto exit;
		}
	}

	rc = cil_copy_fill_classpermset(orig, new);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_classpermset(new);
	return rc;
}

int cil_copy_common(__attribute__((unused)) struct cil_db *db, void *data, void **copy, symtab_t *symtab)
{
	struct cil_common *orig = data;
	struct cil_common *new = NULL;
	int rc = SEPOL_ERR;
	char *key = orig->datum.name;
	struct cil_tree_node *node = NULL;

	cil_common_init(&new);

	rc = cil_symtab_get_node(symtab, key, &node);
	if (rc != SEPOL_OK && rc != SEPOL_ENOENT) {
		cil_log(CIL_INFO, "cil_copy_common: cil_symtab_insert failed, rc: %d\n", rc);
		goto exit;
	} else if (node != NULL) {
		cil_log(CIL_INFO, "cil_copy_common: common cannot be redefined\n");
		goto exit;
	}	

	cil_symtab_init(&new->perms, CIL_SYM_SIZE);
	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_common(new);
	return rc;
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
	struct cil_sid *new = NULL;
	int rc = SEPOL_ERR;
	char *key = orig->datum.name;
	struct cil_tree_node *node = NULL;

	cil_sid_init(&new);

	rc = cil_symtab_get_node(symtab, key, &node);
	if (rc != SEPOL_OK && rc != SEPOL_ENOENT) {
		cil_log(CIL_INFO, "cil_copy_sid: cil_symtab_get_node failed, rc: %d\n", rc);
		goto exit;
	} else if (node != NULL) {
		rc = SEPOL_EEXIST;
		goto exit;
	}

	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_sid(new);
	return rc;
}

int cil_copy_sidcontext(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_sidcontext *orig = data;
	struct cil_sidcontext *new = NULL;
	int rc = SEPOL_ERR;

	cil_sidcontext_init(&new);

	new->context_str = cil_strdup(orig->context_str);

	if (orig->context != NULL && orig->context_str == NULL) {
		cil_context_init(&new->context);
		rc = cil_copy_fill_context(orig->context, new->context);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_sidcontext(new);
	return rc;
}

int cil_copy_user(__attribute__((unused)) struct cil_db *db, void *data, void **copy, symtab_t *symtab)
{
	struct cil_user *orig = data;
	struct cil_user *new = NULL;
	int rc = SEPOL_ERR;
	char *key = orig->datum.name;
	struct cil_tree_node *node = NULL;

	cil_user_init(&new);

	rc = cil_symtab_get_node(symtab, key, &node);
	if (rc != SEPOL_OK && rc != SEPOL_ENOENT) {
		cil_log(CIL_INFO, "cil_copy_user: cil_symtab_get_node failed, rc: %d\n", rc);
		goto exit;
	} else if (node != NULL) {
		rc = SEPOL_EEXIST;
		goto exit;
	}

	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_user(new);
	return rc;
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
	int rc = SEPOL_ERR;

	cil_userlevel_init(&new);

	new->user_str = cil_strdup(orig->user_str);
	new->level_str = cil_strdup(orig->level_str);

	if (orig->level != NULL && orig->level_str == NULL) {
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

int cil_copy_userrange(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_userrange *orig = data;
	struct cil_userrange *new = NULL;
	int rc = SEPOL_ERR;

	cil_userrange_init(&new);

	new->user_str = cil_strdup(orig->user_str);
	new->range_str = cil_strdup(orig->range_str);

	if (orig->range != NULL && orig->range_str == NULL) {
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
	struct cil_role *new = NULL;
	int rc = SEPOL_ERR;
	char *key = orig->datum.name;
	struct cil_tree_node *node = NULL;

	cil_role_init(&new);

	rc = cil_symtab_get_node(symtab, key, &node);
	if (rc != SEPOL_OK && rc != SEPOL_ENOENT) {
		cil_log(CIL_INFO, "cil_copy_role: cil_symtab_get_node failed, rc: %d\n", rc);
		goto exit;
	} else if (node != NULL) {
		rc = SEPOL_EEXIST;
		goto exit;
	}

	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_role(new);
	return rc;
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

int cil_copy_roledominance(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_roledominance *orig = data;
	struct cil_roledominance *new = NULL;

	cil_roledominance_init(&new);

	new->role_str = cil_strdup(orig->role_str);
	new->domed_str = cil_strdup(orig->domed_str);

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
	struct cil_type *new = NULL;
	int rc = SEPOL_ERR;
	char *key = orig->datum.name;
	struct cil_tree_node *node = NULL;

	cil_type_init(&new);

	rc = cil_symtab_get_node(symtab, key, &node);
	if (rc != SEPOL_OK && rc != SEPOL_ENOENT) {
		cil_log(CIL_INFO, "cil_copy_type: cil_symtab_get_node failed, rc: %d\n", rc);
		goto exit;
	} else if (node != NULL) {
		rc = SEPOL_EEXIST;
		goto exit;
	}

	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_type(new);
	return rc;
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
	struct cil_typeattribute *new = NULL;
	int rc = SEPOL_ERR;
	char *key = orig->datum.name;
	struct cil_tree_node *node = NULL;

	cil_typeattribute_init(&new);

	rc = cil_symtab_get_node(symtab, key, &node);
	if (rc != SEPOL_OK && rc != SEPOL_ENOENT) {
		cil_log(CIL_INFO, "cil_copy_typeattribute: cil_symtab_insert failed, rc: %d\n", rc);
		goto exit;
	} else if (node != NULL) {
		rc = SEPOL_EEXIST;
		goto exit;
	}

	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_typeattribute(new);
	return rc;
}

int cil_copy_typeattributeset(struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_typeattributeset *orig = data;
	struct cil_typeattributeset *new = NULL;
	int rc = SEPOL_ERR;

	cil_typeattributeset_init(&new);

	new->attr_str = cil_strdup(orig->attr_str);

	rc = cil_copy_expr(db, orig->expr_stack, &new->expr_stack);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_typeattributeset(new);
	return rc;
}

int cil_copy_typealias(__attribute__((unused)) struct cil_db *db, void *data, void **copy, symtab_t *symtab)
{
	struct cil_typealias *orig = data;
	struct cil_typealias *new = NULL;
	int rc = SEPOL_ERR;
	char *key = orig->datum.name;
	struct cil_tree_node *node = NULL;

	cil_typealias_init(&new);

	rc = cil_symtab_get_node(symtab, key, &node);
	if (rc != SEPOL_OK && rc != SEPOL_ENOENT) {
		cil_log(CIL_INFO, "cil_copy_typealias: cil_symtab_get_node failed, rc: %d\n", rc);
		goto exit;
	} else if (node != NULL) {
		cil_log(CIL_INFO, "cil_copy_typealias: alias cannot be redefined\n");
		rc = SEPOL_ERR;
		goto exit;
	}

	new->type_str = cil_strdup(orig->type_str);
	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_typealias(new);
	return rc;
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

int cil_copy_filetransition(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_filetransition *orig = data;
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

int cil_copy_rangetransition(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_rangetransition *orig = data;
	struct cil_rangetransition *new = NULL;
	int rc = SEPOL_ERR;

	cil_rangetransition_init(&new);

	new->src_str = cil_strdup(orig->src_str);
	new->exec_str = cil_strdup(orig->exec_str);
	new->obj_str = cil_strdup(orig->obj_str);
	new->range_str = cil_strdup(orig->range_str);

	if (orig->range != NULL && orig->range_str == NULL) {
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

int cil_copy_bool(__attribute__((unused)) struct cil_db *db, void *data, void **copy, symtab_t *symtab)
{
	struct cil_bool *orig = data;
	struct cil_bool *new = NULL;
	int rc = SEPOL_ERR;
	char *key = orig->datum.name;
	struct cil_tree_node *node = NULL;

	cil_bool_init(&new);

	rc = cil_symtab_get_node(symtab, key, &node);
	if (rc != SEPOL_OK && rc != SEPOL_ENOENT) {
		cil_log(CIL_INFO, "cil_copy_bool: cil_symtab_get_node failed, rc: %d\n", rc);
		goto exit;
	} else if (node != NULL) {
		cil_log(CIL_INFO, "cil_copy_bool: boolean/tunable cannot be redefined\n");
		rc = SEPOL_ERR;
		goto exit;
	}

	new->value = orig->value;
	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_bool(new);
	return rc;
}

int cil_copy_avrule(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_avrule *orig = data;
	struct cil_avrule *new = NULL;
	int rc = SEPOL_ERR;

	cil_avrule_init(&new);

	new->rule_kind = orig->rule_kind;
	new->src_str = cil_strdup(orig->src_str);
	new->tgt_str = cil_strdup(orig->tgt_str);
	new->classpermset_str = cil_strdup(orig->classpermset_str);

	if (orig->classpermset != NULL && orig->classpermset_str == NULL) {
		cil_classpermset_init(&new->classpermset);
		rc = cil_copy_fill_classpermset(orig->classpermset, new->classpermset);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_avrule(new);
	return rc;
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
	struct cil_sens *new = NULL;
	int rc = SEPOL_ERR;
	char *key = orig->datum.name;
	struct cil_tree_node *node = NULL;

	cil_sens_init(&new);

	rc = cil_symtab_get_node(symtab, key, &node);
	if (rc != SEPOL_OK && rc != SEPOL_ENOENT) {
		cil_log(CIL_INFO, "cil_copy_sens: cil_symtab_get_node failed, rc: %d\n", rc);
		goto exit;
	} else if (node != NULL) {
		rc = SEPOL_EEXIST;
		goto exit;
	}

	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_sensitivity(new);
	return rc;
}

int cil_copy_sensalias(__attribute__((unused)) struct cil_db *db, void *data, void **copy, symtab_t *symtab)
{
	struct cil_sensalias *orig = data;
	struct cil_sensalias *new = NULL;
	int rc = SEPOL_ERR;
	char *key = orig->datum.name;
	struct cil_tree_node *node = NULL;

	cil_sensalias_init(&new);

	rc = cil_symtab_get_node(symtab, key, &node);
	if (rc != SEPOL_OK && rc != SEPOL_ENOENT) {
		cil_log(CIL_INFO, "cil_copy_sensalias: cil_symtab_get_node failed, rc: %d\n", rc);
		goto exit;
	} else if (node != NULL) {
		cil_log(CIL_INFO, "cil_copy_sensalias: sensitivityalias cannot be redefined\n");
		rc = SEPOL_ERR;
		goto exit;
	}

	new->sens_str = cil_strdup(orig->sens_str);
	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_sensalias(new);
	return rc;
}

int cil_copy_cat(__attribute__((unused)) struct cil_db *db, void *data, void **copy, symtab_t *symtab)
{
	struct cil_cat *orig = data;
	struct cil_cat *new = NULL;
	int rc = SEPOL_ERR;
	char *key = orig->datum.name;
	struct cil_tree_node *node = NULL;

	cil_cat_init(&new);

	rc = cil_symtab_get_node(symtab, key, &node);
	if (rc != SEPOL_OK && rc != SEPOL_ENOENT) {
		cil_log(CIL_INFO, "cil_copy_cat: cil_symtab_get_node failed, rc: %d\n", rc);
		goto exit;
	} else if (node != NULL) {
		rc = SEPOL_EEXIST;
		goto exit;
	}

	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_category(new);
	return rc;
}

int cil_copy_catalias(__attribute__((unused)) struct cil_db *db, void *data, void **copy, symtab_t *symtab)
{
	struct cil_catalias *orig = data;
	struct cil_catalias *new = NULL;
	int rc = SEPOL_ERR;
	char *key = orig->datum.name;
	struct cil_tree_node *node = NULL;

	cil_catalias_init(&new);

	rc = cil_symtab_get_node(symtab, key, &node);
	if (rc != SEPOL_OK && rc != SEPOL_ENOENT) {
		cil_log(CIL_INFO, "cil_copy_catalias: cil_symtab_get_node failed, rc: %d\n", rc);
		goto exit;
	} else if (node != NULL) {
		cil_log(CIL_INFO, "cil_copy_catalias: categoryalias cannot be redefined\n");
		rc = SEPOL_ERR;
		goto exit;
	}

	new->cat_str = cil_strdup(orig->cat_str);
	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_catalias(new);
	return rc;
}

int cil_copy_fill_catrange(struct cil_catrange *data, struct cil_catrange *new)
{
	new->cat_low_str = cil_strdup(data->cat_low_str);
	new->cat_high_str = cil_strdup(data->cat_high_str);

	return SEPOL_OK;
}

int cil_copy_catrange(__attribute__((unused)) struct cil_db *db, void *data, void **copy, symtab_t *symtab)
{
	struct cil_catrange *orig = data;
	struct cil_catrange *new = NULL;
	int rc = SEPOL_ERR;
	char *key = orig->datum.name;
	struct cil_tree_node *node = NULL;

	cil_catrange_init(&new);

	rc = cil_symtab_get_node(symtab, key, &node);
	if (rc != SEPOL_OK && rc != SEPOL_ENOENT) {
		cil_log(CIL_INFO, "cil_copy_catrange: cil_symtab_get_node failed, rc: %d\n", rc);
		goto exit;
	} else if (node != NULL) {
		cil_log(CIL_INFO, "cil_copy_catrange: categoryrange cannot be redefined\n");
		rc = SEPOL_ERR;
		goto exit;
	}

	new->cat_low_str = cil_strdup(orig->cat_low_str);
	new->cat_high_str = cil_strdup(orig->cat_high_str);
	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_catrange(new);
	return rc;
}

int cil_copy_fill_catset(struct cil_catset *data, struct cil_catset *new)
{
	struct cil_list_item *orig_item;
	struct cil_list_item *new_item;
	int rc = SEPOL_ERR;

	cil_list_init(&new->cat_list_str);

	for (orig_item = data->cat_list_str->head; orig_item != NULL; orig_item = orig_item->next) {
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

int cil_copy_catset(__attribute__((unused)) struct cil_db *db, void *data, void **copy, symtab_t *symtab)
{
	struct cil_catset *orig = data;
	struct cil_catset *new = NULL;
	int rc = SEPOL_ERR;
	char *key = orig->datum.name;
	struct cil_tree_node *node = NULL;

	cil_catset_init(&new);

	rc = cil_symtab_get_node(symtab, key, &node);
	if (rc != SEPOL_OK && rc != SEPOL_ENOENT) {
		cil_log(CIL_INFO, "cil_copy_catset: cil_symtab_get_node failed, rc: %d\n", rc);
		goto exit;
	} else if (node != NULL) {
		cil_log(CIL_INFO, "cil_copy_catset: categoryset cannot be redefined\n");
		rc = SEPOL_ERR;
		goto exit;
	}

	rc = cil_copy_fill_catset(orig, new);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_catset(new);
	return rc;

}

int cil_copy_senscat(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_senscat *orig = data;
	struct cil_senscat *new = NULL;
	int rc = SEPOL_ERR;

	cil_senscat_init(&new);

	new->sens_str = cil_strdup(orig->sens_str);
	new->catset_str = cil_strdup(orig->catset_str);

	if (orig->catset != NULL && orig->catset_str == NULL) {
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

int cil_copy_catorder(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_catorder *orig = data;
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

int cil_copy_dominance(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_sens_dominates *orig = data;
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

int cil_copy_fill_level(struct cil_level *data, struct cil_level *new)
{
	int rc = SEPOL_ERR;

	new->sens_str = cil_strdup(data->sens_str);
	new->catset_str = cil_strdup(data->catset_str);

	if (data->catset != NULL && data->catset_str == NULL) {
		cil_catset_init(&new->catset);
		rc = cil_copy_fill_catset(data->catset, new->catset);
		if (rc != SEPOL_OK) {
			cil_destroy_catset(new->catset);
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_copy_level(__attribute__((unused)) struct cil_db *db, void *data, void **copy, symtab_t *symtab)
{
	struct cil_level *orig = data;
	struct cil_level *new = NULL;
	char *key = orig->datum.name;
	int rc = SEPOL_ERR;
	struct cil_tree_node *node = NULL;

	cil_level_init(&new);

	if (key != NULL) {
		rc = cil_symtab_get_node(symtab, key, &node);
		if (rc != SEPOL_OK && rc != SEPOL_ENOENT) {
			cil_log(CIL_INFO, "cil_copy_level: cil_symtab_get_node failed, rc: %d\n", rc);
			goto exit;
		} else if (node != NULL) {
			cil_log(CIL_INFO, "cil_copy_level: level cannot be redefined\n");
			rc = SEPOL_ERR;
			goto exit;
		}
	}

	rc = cil_copy_fill_level(orig, new);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_level(new);
	return rc;
}

int cil_copy_fill_levelrange(struct cil_levelrange *data, struct cil_levelrange *new)
{
	int rc = SEPOL_ERR;

	new->low_str = cil_strdup(data->low_str);
	new->high_str = cil_strdup(data->high_str);

	if (data->low != NULL && data->low_str == NULL) {
		cil_level_init(&new->low);
		rc = cil_copy_fill_level(data->low, new->low);
		if (rc != SEPOL_OK) {
			cil_destroy_level(new->low);
			goto exit;
		}
	}

	if (data->high != NULL && data->high_str == NULL) {
		cil_level_init(&new->high);
		rc = cil_copy_fill_level(data->high, new->high);
		if (rc != SEPOL_OK) {
			cil_destroy_level(new->high);
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_copy_levelrange(__attribute__((unused)) struct cil_db *db, void *data, void **copy, symtab_t *symtab)
{
	struct cil_levelrange *orig = data;
	struct cil_levelrange *new = NULL;
	int rc = SEPOL_ERR;
	char *key = orig->datum.name;
	struct cil_tree_node *node = NULL;

	cil_levelrange_init(&new);

	if (key != NULL) {
		rc = cil_symtab_get_node(symtab, key, &node);
		if (rc != SEPOL_OK && rc != SEPOL_ENOENT) {
			cil_log(CIL_INFO, "cil_copy_levelrange: cil_symtab_get_node failed, rc: %d\n", rc);
			goto exit;
		} else if (node != NULL) {
			cil_log(CIL_INFO, "cil_copy_levelrange: levelrange cannot be redefined\n");
			rc = SEPOL_ERR;
			goto exit;
		}
	}

	rc = cil_copy_fill_levelrange(orig, new);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_levelrange(new);
	return rc;
}

int cil_copy_fill_context(struct cil_context *data, struct cil_context *new)
{
	int rc = SEPOL_ERR;

	new->user_str = cil_strdup(data->user_str);
	new->role_str = cil_strdup(data->role_str);
	new->type_str = cil_strdup(data->type_str);
	new->range_str = cil_strdup(data->range_str);

	if (data->range != NULL && data->range_str == NULL) {
		cil_levelrange_init(&new->range);
		rc = cil_copy_fill_levelrange(data->range, new->range);
		if (rc != SEPOL_OK) {
			cil_destroy_levelrange(new->range);
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_copy_context(__attribute__((unused)) struct cil_db *db, void *data, void **copy, symtab_t *symtab)
{
	struct cil_context *orig = data;
	struct cil_context *new = NULL;
	int rc = SEPOL_ERR;
	char *key = orig->datum.name;
	struct cil_tree_node *node = NULL;

	cil_context_init(&new);

	if (key != NULL) {
		rc = cil_symtab_get_node(symtab, key, &node);
		if (rc != SEPOL_OK && rc != SEPOL_ENOENT) {
			cil_log(CIL_INFO, "cil_copy_context: cil_symtab_get_node failed, rc: %d\n", rc);
			goto exit;
		} else if (node != NULL) {
			cil_log(CIL_INFO, "cil_copy_context: context cannot be redefined\n");
			rc = SEPOL_ERR;
			goto exit;
		}
	}

	rc = cil_copy_fill_context(orig, new);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_context(new);
	return rc;
}

int cil_copy_netifcon(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_netifcon *orig = data;
	struct cil_netifcon *new = NULL;
	int rc = SEPOL_ERR;

	cil_netifcon_init(&new);

	new->interface_str = cil_strdup(orig->interface_str);
	new->if_context_str = cil_strdup(orig->if_context_str);
	new->packet_context_str = cil_strdup(orig->packet_context_str);

	if (orig->if_context != NULL && orig->if_context_str == NULL) {
		cil_context_init(&new->if_context);
		rc = cil_copy_fill_context(orig->if_context, new->if_context);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	if (orig->packet_context != NULL && orig->packet_context_str == NULL) {
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

int cil_copy_genfscon(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_genfscon *orig = data;
	struct cil_genfscon *new = NULL;
	int rc = SEPOL_ERR;

	cil_genfscon_init(&new);

	new->fs_str = cil_strdup(orig->fs_str);
	new->path_str = cil_strdup(orig->path_str);
	new->context_str = cil_strdup(orig->context_str);

	if (orig->context != NULL && orig->context_str == NULL) {
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

int cil_copy_filecon(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_filecon *orig = data;
	struct cil_filecon *new = NULL;
	int rc = SEPOL_ERR;

	cil_filecon_init(&new);

	new->root_str = cil_strdup(orig->root_str);
	new->path_str = cil_strdup(orig->path_str);
	new->type = orig->type;
	new->context_str = cil_strdup(orig->context_str);

	if (orig->context != NULL && orig->context_str == NULL) {
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

int cil_copy_nodecon(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_nodecon *orig = data;
	struct cil_nodecon *new = NULL;
	int rc = SEPOL_ERR;

	cil_nodecon_init(&new);

	new->addr_str = cil_strdup(orig->addr_str);
	new->mask_str = cil_strdup(orig->mask_str);
	new->context_str = cil_strdup(orig->context_str);

	if (orig->addr != NULL && orig->addr_str == NULL) {
		cil_ipaddr_init(&new->addr);
		rc = cil_copy_fill_ipaddr(orig->addr, new->addr);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	if (orig->mask != NULL && orig->mask_str == NULL) {
		cil_ipaddr_init(&new->mask);
		rc = cil_copy_fill_ipaddr(orig->mask, new->mask);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	if (orig->context != NULL && orig->context_str == NULL) {
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

int cil_copy_portcon(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_portcon *orig = data;
	struct cil_portcon *new = NULL;
	int rc = SEPOL_ERR;

	cil_portcon_init(&new);

	new->proto = orig->proto;
	new->port_low = orig->port_low;
	new->port_high = orig->port_high;
	new->context_str = cil_strdup(orig->context_str);

	if (orig->context != NULL && orig->context_str == NULL) {
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

int cil_copy_pirqcon(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_pirqcon *orig = data;
	struct cil_pirqcon *new = NULL;
	int rc = SEPOL_ERR;

	cil_pirqcon_init(&new);

	new->pirq = orig->pirq;
	new->context_str = cil_strdup(orig->context_str);

	if (orig->context != NULL && orig->context_str == NULL) {
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

int cil_copy_iomemcon(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_iomemcon *orig = data;
	struct cil_iomemcon *new = NULL;
	int rc = SEPOL_ERR;

	cil_iomemcon_init(&new);

	new->iomem_low = orig->iomem_low;
	new->iomem_high = orig->iomem_high;
	new->context_str = cil_strdup(orig->context_str);

	if (orig->context != NULL && orig->context_str == NULL) {
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

int cil_copy_ioportcon(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_ioportcon *orig = data;
	struct cil_ioportcon *new = NULL;
	int rc = SEPOL_ERR;

	cil_ioportcon_init(&new);

	new->ioport_low = orig->ioport_low;
	new->ioport_high = orig->ioport_high;
	new->context_str = cil_strdup(orig->context_str);

	if (orig->context != NULL && orig->context_str == NULL) {
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

int cil_copy_pcidevicecon(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_pcidevicecon *orig = data;
	struct cil_pcidevicecon *new = NULL;
	int rc = SEPOL_ERR;

	cil_pcidevicecon_init(&new);

	new->dev = orig->dev;
	new->context_str = cil_strdup(orig->context_str);

	if (orig->context != NULL && orig->context_str == NULL) {
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

int cil_copy_fsuse(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_fsuse *orig = data;
	struct cil_fsuse *new = NULL;
	int rc = SEPOL_ERR;

	cil_fsuse_init(&new);

	new->type = orig->type;
	new->fs_str = cil_strdup(orig->fs_str);
	new->context_str = cil_strdup(orig->context_str);

	if (orig->context != NULL && orig->context_str == NULL) {
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

int cil_copy_expr(struct cil_db *db, struct cil_list *orig, struct cil_list **new)
{
	struct cil_list_item *curr_old = NULL;
	struct cil_list_item *curr_new = NULL;
	struct cil_conditional *cond_new = NULL;
	int rc = SEPOL_ERR;

	if (orig == NULL) {
		return SEPOL_OK;
	}

	curr_old = orig->head;

	cil_list_init(new);

	while (curr_old != NULL) {
		cil_list_item_init(&curr_new);

		cil_copy_conditional(db, curr_old->data, ((void**)&cond_new), NULL);
		curr_new->data = cond_new;
		curr_new->flavor = curr_old->flavor;

		rc = cil_list_append_item(*new, curr_new);
		if (rc != SEPOL_OK) {
			goto exit;
		}

		curr_old = curr_old->next;
	}

	return SEPOL_OK;

exit:
	cil_list_destroy(new, 1);
	return rc;
}

int cil_copy_constrain(struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_constrain *orig = data;
	struct cil_constrain *new = NULL;
	struct cil_list *new_list = NULL;
	int rc = SEPOL_ERR;

	cil_constrain_init(&new);

	new->classpermset_str = cil_strdup(orig->classpermset_str);

	if (orig->classpermset != NULL && orig->classpermset_str == NULL) {
		cil_classpermset_init(&new->classpermset);
		rc = cil_copy_fill_classpermset(orig->classpermset, new->classpermset);
		if (rc != SEPOL_OK) {
			cil_log(CIL_INFO, "Failed to copy classpermset\n");
			goto exit;
		}
	}

	rc = cil_copy_expr(db, orig->expr, &new_list);
	if (rc != SEPOL_OK) {
		cil_log(CIL_INFO, "Failed to copy expression stack\n");
		goto exit;
	}

	new->expr = new_list;

	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_constrain(new);
	return rc;
}

int cil_copy_validatetrans(struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_validatetrans *orig = data;
	struct cil_validatetrans *new = NULL;
	struct cil_list *new_list = NULL;
	int rc = SEPOL_ERR;

	cil_validatetrans_init(&new);

	new->class_str = cil_strdup(orig->class_str);

	rc = cil_copy_expr(db, orig->expr, &new_list);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	new->expr = new_list;

	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_validatetrans(new);
	return rc;
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

	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_call(new);
	return rc;
}

int cil_copy_macro(__attribute__((unused)) struct cil_db *db, void *data, void **copy, symtab_t *symtab)
{
	struct cil_macro *orig = data;
	struct cil_macro *new = NULL;
	int rc = SEPOL_ERR;
	char *key = orig->datum.name;
	struct cil_tree_node *node = NULL;
	struct cil_list_item *curr_orig = NULL;
	struct cil_list_item *curr_new = NULL;
	struct cil_param *param_orig = NULL;
	struct cil_param *param_new = NULL;

	cil_macro_init(&new);

	rc = cil_symtab_get_node(symtab, key, &node);
	if (rc != SEPOL_OK && rc != SEPOL_ENOENT) {
		cil_log(CIL_INFO, "cil_copy_macro: cil_symtab_get_node failed, rc: %d\n", rc);
		goto exit;
	} else if (node != NULL) {
		if (((struct cil_macro*)node->data)->params != NULL) {
			curr_new = ((struct cil_macro*)node->data)->params->head;
		}

		if (orig->params != NULL) {
			curr_orig = orig->params->head;
		}

		if (curr_orig != NULL && curr_new != NULL) {
			while (curr_orig != NULL) {
				if (curr_new == NULL) {
					goto redef_error;
				}

				param_orig = (struct cil_param*)curr_orig->data;
				param_new = (struct cil_param*)curr_new->data;
				if (strcmp(param_orig->str, param_new->str)) {
					goto redef_error;
				} else if (param_orig->flavor != param_new->flavor) {
					goto redef_error;
				}

				curr_orig = curr_orig->next;
				curr_new = curr_new->next;
			}

			if (curr_new != NULL) {
				goto redef_error;
			}
		} else if (!(curr_orig == NULL && curr_new == NULL)) {
			goto redef_error;
		}

		rc = SEPOL_EEXIST;
		goto exit;
	}

	cil_symtab_array_init(new->symtab, CIL_SYM_NUM);
	rc = cil_copy_list(orig->params, &new->params);

	*copy = new;

	return SEPOL_OK;

redef_error:
	cil_log(CIL_INFO, "cil_copy_macro: macro cannot be redefined\n");
	rc = SEPOL_ERR;

exit:
	cil_destroy_macro(new);
	return rc;
}

int cil_copy_optional(__attribute__((unused)) struct cil_db *db, void *data, void **copy, symtab_t *symtab)
{
	struct cil_optional *orig = data;
	struct cil_optional *new = NULL;
	int rc = SEPOL_ERR;
	char *key = orig->datum.name;
	struct cil_tree_node *node = NULL;

	cil_optional_init(&new);

	rc = cil_symtab_get_node(symtab, key, &node);
	if (rc != SEPOL_OK && rc != SEPOL_ENOENT) {
		cil_log(CIL_INFO, "cil_copy_optional: cil_symtab_get_node failed, rc: %d\n", rc);
		goto exit;
	} else if (node != NULL) {
		rc = SEPOL_EEXIST;
		goto exit;
	}

	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_optional(new);
	return rc;
}

int cil_copy_fill_ipaddr(struct cil_ipaddr *data, struct cil_ipaddr *new)
{
	new->family = data->family;
	memcpy(&new->ip, &data->ip, sizeof(data->ip));

	return SEPOL_OK;
}

int cil_copy_ipaddr(__attribute__((unused)) struct cil_db *db, void *data, void **copy, symtab_t *symtab)
{
	struct cil_ipaddr *orig = data;
	struct cil_ipaddr *new = NULL;
	char * key = orig->datum.name;	
	int rc = SEPOL_ERR;
	struct cil_tree_node *node = NULL;

	cil_ipaddr_init(&new);

	rc = cil_symtab_get_node(symtab, key, &node);
	if (rc != SEPOL_OK && rc != SEPOL_ENOENT) {
		cil_log(CIL_INFO, "cil_copy_ipaddr: cil_symtab_get_node failed, rc: %d\n", rc);
		goto exit;
	} else if (node != NULL) {
		cil_log(CIL_INFO, "cil_copy_ipaddr: ipaddress cannot be redefined\n");
		rc = SEPOL_ERR;
		goto exit;
	}

	rc = cil_copy_fill_ipaddr(orig, new);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_ipaddr(new);
	return rc;
}

int cil_copy_conditional(__attribute__((unused)) struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_conditional *orig = data;
	struct cil_conditional *new = NULL;

	cil_conditional_init(&new);

	new->str = cil_strdup(orig->str);
	new->flavor = orig->flavor;

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
	int rc = SEPOL_ERR;

	cil_boolif_init(&new);

	rc = cil_copy_expr(db, orig->expr_stack, &new->expr_stack);
	if (rc != SEPOL_OK) {
		cil_log(CIL_INFO, "cil_copy_boolif: Failed to copy expression\n");
		goto exit;
	}

	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_boolif(new);
	return rc;
}

int cil_copy_tunif(struct cil_db *db, void *data, void **copy, __attribute__((unused)) symtab_t *symtab)
{
	struct cil_tunableif *orig = data;
	struct cil_tunableif *new = NULL;
	int rc = SEPOL_ERR;

	cil_tunif_init(&new);

	rc = cil_copy_expr(db, orig->expr_stack, &new->expr_stack);
	if (rc != SEPOL_OK) {
		cil_log(CIL_INFO, "cil_copy_tunif: Failed to copy expression\n");
		goto exit;
	}

	*copy = new;

	return SEPOL_OK;

exit:
	cil_destroy_tunif(new);
	return rc;
}

int __cil_copy_node_helper(struct cil_tree_node *orig, __attribute__((unused)) uint32_t *finished, void *extra_args)
{
	int rc = SEPOL_ERR;
	struct cil_tree_node *parent = NULL;
	struct cil_tree_node *new = NULL;
	struct cil_tree_node *node = NULL;
	struct cil_db *db = NULL;
	struct cil_args_copy *args = NULL;
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
	case CIL_POLICYCAP:
		copy_func = &cil_copy_policycap;
		break;
	case CIL_PERM:
		copy_func = &cil_copy_perm;
		break;
	case CIL_CLASSMAPPERM:
		copy_func =  &cil_copy_classmap_perm;
		break;
	case CIL_CLASSMAP:
		copy_func = &cil_copy_classmap;
		break;
	case CIL_CLASSMAPPING:
		copy_func = &cil_copy_classmapping;
		break;
	case CIL_PERMSET:
		copy_func = &cil_copy_permset;
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
	case CIL_ROLEDOMINANCE:
		copy_func = &cil_copy_roledominance;
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
	case CIL_FILETRANSITION:
		copy_func = &cil_copy_filetransition;
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
			if (rc != SEPOL_OK) {
				goto exit;
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
	} else if (rc == SEPOL_EEXIST) {
		//If blocklike, change parent
		if (orig->flavor == CIL_BLOCK || orig->flavor == CIL_OPTIONAL || orig->flavor == CIL_MACRO) {
			rc = cil_symtab_get_node(symtab, ((struct cil_symtab_datum*)orig->data)->name, &node);
			if (rc != SEPOL_OK) {
				goto exit;
			}
			args->dest = node;
		}

		//Else, ignore/merge
	} else {
		goto exit;
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
		cil_log(CIL_INFO, "cil_tree_walk failed, rc: %d\n", rc);
		goto exit;
	}

	return SEPOL_OK;

exit:
	return rc;
}

