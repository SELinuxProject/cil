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
#include "cil_build_ast.h"
#include "cil_resolve_ast.h"
#include "cil_copy_ast.h"
	
	
enum args_resolve {
	ARGS_RESOLVE_DB,
	ARGS_RESOLVE_PASS,
	ARGS_RESOLVE_CHANGED,
	ARGS_RESOLVE_CALLS,
	ARGS_RESOLVE_OPTIONALS,
	ARGS_RESOLVE_MACRO,
	ARGS_RESOLVE_COUNT,
};

enum args_verify_order {
	ARGS_VERIFY_ORDER,
	ARGS_VERIFY_ORDERED,
	ARGS_VERIFY_FOUND,
	ARGS_VERIFY_EMPTY,
	ARGS_VERIFY_FLAVOR,
	ARGS_VERIFY_COUNT,
};

static int __cil_resolve_perm_list(struct cil_class *class, struct cil_list *perm_list_str, struct cil_list *res_list_perms)
{
	struct cil_tree_node *perm_node = NULL;
	struct cil_list_item *perm = perm_list_str->head;
	struct cil_list_item *list_item = NULL;
	struct cil_list_item *list_tail = NULL;
	int rc = SEPOL_ERR;

	while (perm != NULL) {
		rc = cil_symtab_get_node(&class->perms, (char*)perm->data, &perm_node);
		if (rc == SEPOL_ENOENT) {
			if (class->common != NULL) {
				rc = cil_symtab_get_node(&class->common->perms, (char*)perm->data, &perm_node);
				if (rc != SEPOL_OK) {
					printf("Failed to find perm in class or common symtabs\n");
					goto resolve_perm_list_out;
				}
			} else {
				printf("Failed to find perm in class symtab\n");
				goto resolve_perm_list_out;
			}
		} else if (rc != SEPOL_OK) {
			goto resolve_perm_list_out;
		}

		if (res_list_perms != NULL) {
			cil_list_item_init(&list_item);
			list_item->flavor = CIL_PERM;
			list_item->data = perm_node->data;
			if (res_list_perms->head == NULL) {
				res_list_perms->head = list_item;
			} else {
				list_tail->next = list_item;
			}
			list_tail = list_item;
		}
		perm = perm->next;
	}

	return SEPOL_OK;

resolve_perm_list_out:
	return rc;
}

int cil_resolve_avrule(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call)
{
	struct cil_avrule *rule = (struct cil_avrule*)current->data;
	struct cil_tree_node *src_node = NULL;
	struct cil_tree_node *tgt_node = NULL;
	struct cil_tree_node *obj_node = NULL;
	struct cil_tree_node *permset_node = NULL;
	struct cil_list *perms_list = NULL;
	int rc = SEPOL_ERR;
	
	rc = cil_resolve_name(db, current, rule->src_str, CIL_SYM_TYPES, CIL_TYPE, call, &src_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", rule->src_str);
		goto resolve_avrule_out;
	}
	rule->src = (struct cil_type*)(src_node->data);
					
	rc = cil_resolve_name(db, current, rule->tgt_str, CIL_SYM_TYPES, CIL_TYPE, call, &tgt_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", rule->tgt_str);
		goto resolve_avrule_out;
	}
	rule->tgt = (struct cil_type*)(tgt_node->data);

	rc = cil_resolve_name(db, current, rule->obj_str, CIL_SYM_CLASSES, CIL_CLASS, call, &obj_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", rule->obj_str);
		goto resolve_avrule_out;
	}
	rule->obj = (struct cil_class*)(obj_node->data);


	cil_list_init(&perms_list);

	if (rule->permset_str != NULL) {
		rc = cil_resolve_name(db, current, rule->permset_str, CIL_SYM_PERMSETS, CIL_PERMSET, call, &permset_node);
		if (rc != SEPOL_OK) {
			printf("Failed to resolve permissionset name\n");
			goto resolve_avrule_out;
		}
		rc = __cil_resolve_perm_list(rule->obj, ((struct cil_permset*)permset_node->data)->perms_list_str, perms_list);
	} else {
		rc = __cil_resolve_perm_list(rule->obj, rule->perms_list_str, perms_list);
	}

	if (rc != SEPOL_OK) {
		printf("Failed to resolve perm list\n");
		goto resolve_avrule_out;
	}

	if (rule->perms_list != NULL) {
		/* clean up because of re-resolve */
		cil_list_destroy(&rule->perms_list, 0);
	}
	rule->perms_list = perms_list;

	return SEPOL_OK;

resolve_avrule_out:
	return rc;
}

int cil_resolve_type_rule(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call)
{
	struct cil_type_rule *rule = (struct cil_type_rule*)current->data;
	struct cil_tree_node *src_node = NULL;
	struct cil_tree_node *tgt_node = NULL;
	struct cil_tree_node *obj_node = NULL;
	struct cil_tree_node *result_node = NULL;
	int rc = SEPOL_ERR;
	
	rc = cil_resolve_name(db, current, rule->src_str, CIL_SYM_TYPES, CIL_TYPE, call, &src_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", rule->src_str);
		goto resolve_type_rule_out;
	}
	rule->src = (struct cil_type*)(src_node->data);
					
	rc = cil_resolve_name(db, current, rule->tgt_str, CIL_SYM_TYPES, CIL_TYPE, call, &tgt_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", rule->tgt_str);
		goto resolve_type_rule_out;
	}
	rule->tgt = (struct cil_type*)(tgt_node->data);

	rc = cil_resolve_name(db, current, rule->obj_str, CIL_SYM_CLASSES, CIL_CLASS, call, &obj_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", rule->obj_str);
		goto resolve_type_rule_out;
	}
	rule->obj = (struct cil_class*)(obj_node->data);

	rc = cil_resolve_name(db, current, rule->result_str, CIL_SYM_TYPES, CIL_TYPE, call, &result_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", rule->result_str);
		goto resolve_type_rule_out;
	}
	rule->result = (struct cil_type*)(result_node->data);

	return SEPOL_OK;

resolve_type_rule_out:
	return rc;
}

int cil_resolve_typeattr(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call)
{
	struct cil_typeattribute *typeattr = (struct  cil_typeattribute*)current->data;
	struct cil_tree_node *type_node = NULL;
	struct cil_tree_node *attr_node = NULL;
	int rc = SEPOL_ERR;

	rc = cil_resolve_name(db, current, typeattr->type_str, CIL_SYM_TYPES, CIL_TYPE, call, &type_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", typeattr->type_str);
		goto resolve_typeattr_out;
	}
	typeattr->type = (struct cil_type*)(type_node->data);

	rc = cil_resolve_name(db, current, typeattr->attr_str, CIL_SYM_TYPES, CIL_TYPE, call, &attr_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", typeattr->attr_str);
		goto resolve_typeattr_out;
	}
	typeattr->attr = (struct cil_type*)(attr_node->data);

	return SEPOL_OK;

resolve_typeattr_out:
	return rc;
}

int cil_resolve_typealias(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call)
{
	struct cil_typealias *alias = (struct cil_typealias*)current->data;
	struct cil_tree_node *type_node = NULL;
	int rc = SEPOL_ERR;

	rc = cil_resolve_name(db, current, alias->type_str, CIL_SYM_TYPES, CIL_TYPE, call, &type_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", alias->type_str);
		goto resolve_typealias_out;
	}
	alias->type = (struct cil_type*)(type_node->data);

	return SEPOL_OK;

resolve_typealias_out:
	return rc;
}

int cil_resolve_typebounds(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call)
{
	struct cil_typebounds *typebnds = (struct cil_typebounds*)current->data;
	struct cil_tree_node *parent_node = NULL;
	struct cil_tree_node *child_node = NULL;
	int rc = SEPOL_ERR;

	rc = cil_resolve_name(db, current, typebnds->parent_str, CIL_SYM_TYPES, CIL_TYPE, call, &parent_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", typebnds->parent_str);
		goto resolve_typebounds_out;
	}
	typebnds->parent = (struct cil_type*)(parent_node->data);

	rc = cil_resolve_name(db, current, typebnds->child_str, CIL_SYM_TYPES, CIL_TYPE, call, &child_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", typebnds->child_str);
		goto resolve_typebounds_out;
	}
	typebnds->child = (struct cil_type*)(child_node->data);

	return SEPOL_OK;

resolve_typebounds_out:
	return rc;
}

int cil_resolve_typepermissive(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call)
{
	struct cil_typepermissive *typeperm = (struct cil_typepermissive*)current->data;
	struct cil_tree_node *type_node = NULL;
	int rc = SEPOL_ERR;

	rc = cil_resolve_name(db, current, typeperm->type_str, CIL_SYM_TYPES, CIL_TYPE, call, &type_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", typeperm->type_str);
		goto resolve_typepermissive_out;
	}
	typeperm->type = (struct cil_type*)(type_node->data);

	return SEPOL_OK;

resolve_typepermissive_out:
	return rc;
}

int cil_resolve_filetransition(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call)
{
	struct cil_filetransition *filetrans = (struct cil_filetransition*)current->data;
	struct cil_tree_node *src_node = NULL;
	struct cil_tree_node *exec_node = NULL;
	struct cil_tree_node *proc_node = NULL;
	struct cil_tree_node *dest_node = NULL;
	int rc = SEPOL_ERR;

	rc = cil_resolve_name(db, current, filetrans->src_str, CIL_SYM_TYPES, CIL_TYPE, call, &src_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", filetrans->src_str);
		goto resolve_filetransition_out;
	}
	filetrans->src = (struct cil_type*)(src_node->data);

	rc = cil_resolve_name(db, current, filetrans->exec_str, CIL_SYM_TYPES, CIL_TYPE, call, &exec_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", filetrans->exec_str);
		goto resolve_filetransition_out;
	}
	filetrans->exec = (struct cil_type*)(exec_node->data);

	rc = cil_resolve_name(db, current, filetrans->proc_str, CIL_SYM_CLASSES, CIL_CLASS, call, &proc_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", filetrans->proc_str);
		goto resolve_filetransition_out;
	}
	filetrans->proc = (struct cil_class*)(proc_node->data);

	rc = cil_resolve_name(db, current, filetrans->dest_str, CIL_SYM_TYPES, CIL_TYPE, call, &dest_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", filetrans->dest_str);
		goto resolve_filetransition_out;
	}
	filetrans->dest = (struct cil_type*)(dest_node->data);

	return SEPOL_OK;

resolve_filetransition_out:
	return rc;
}

int cil_resolve_classcommon(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call)
{
	struct cil_classcommon *clscom = (struct cil_classcommon*)current->data;
	struct cil_tree_node *class_node = NULL;
	struct cil_tree_node *common_node = NULL;
	int rc = SEPOL_ERR;

	rc = cil_resolve_name(db, current, clscom->class_str, CIL_SYM_CLASSES, CIL_CLASS, call, &class_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", clscom->class_str);
		goto resolve_classcommon_out;
	}
	clscom->class = (struct cil_class*)(class_node->data);

	rc = cil_resolve_name(db, current, clscom->common_str, CIL_SYM_COMMONS, CIL_COMMON, call, &common_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", clscom->common_str);
		goto resolve_classcommon_out;
	}
	clscom->common = (struct cil_common*)(common_node->data);

	if (clscom->class->common != NULL) {
		printf("class cannot be associeated with more than one common\n");
		goto resolve_classcommon_out;
	}

	clscom->class->common = clscom->common;

	return SEPOL_OK;

resolve_classcommon_out:
	return rc;
}

int cil_reset_class(__attribute__((unused)) struct cil_db *db, struct cil_tree_node *current, __attribute__((unused)) struct cil_call *call)
{
	struct cil_class *class = (struct cil_class *)current->data;
	
	/* during a re-resolve, we need to reset the common, so a classcommon
	 * statement isn't seen as a duplicate */
	class->common = NULL;

	return SEPOL_OK;
}

int cil_reset_sens(__attribute__((unused)) struct cil_db *db, struct cil_tree_node *current, __attribute__((unused)) struct cil_call *call)
{
	struct cil_sens *sens = (struct cil_sens *)current->data;
	int rc = SEPOL_ERR;
	/* during a re-resolve, we need to reset the categories associated with
	 * this sensitivity from a (sensitivitycategory) statement */
	cil_symtab_destroy(&sens->cats);
	rc = symtab_init(&sens->cats, CIL_SYM_SIZE);
	if (rc != SEPOL_OK) {
		goto reset_sens_out;
	}

	return SEPOL_OK;

reset_sens_out:
	return rc;
}

int cil_resolve_userrole(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call)
{
	struct cil_userrole *userrole = (struct cil_userrole*)current->data;
	struct cil_tree_node *user_node = NULL;
	struct cil_tree_node *role_node = NULL;
	int rc = SEPOL_ERR;

	rc = cil_resolve_name(db, current, userrole->user_str, CIL_SYM_USERS, CIL_USER, call, &user_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", userrole->user_str);
		goto resolve_userrole_out;
	} 
	userrole->user = (struct cil_user*)(user_node->data);

	rc = cil_resolve_name(db, current, userrole->role_str, CIL_SYM_ROLES, CIL_ROLE, call, &role_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", userrole->role_str);
		goto resolve_userrole_out;
	} 
	userrole->role = (struct cil_role*)(role_node->data);

	return SEPOL_OK;

resolve_userrole_out:
	return rc;
}

int cil_resolve_roletype(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call)
{
	struct cil_roletype *roletype = (struct cil_roletype*)current->data;
	struct cil_tree_node *role_node = NULL;
	struct cil_tree_node *type_node = NULL;
	int rc = SEPOL_ERR;

	rc = cil_resolve_name(db, current, roletype->role_str, CIL_SYM_ROLES, CIL_ROLE, call, &role_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", roletype->role_str);
		goto resolve_roletype_out;
	}
	roletype->role = (struct cil_role*)(role_node->data);
	
	rc = cil_resolve_name(db, current, roletype->type_str, CIL_SYM_TYPES, CIL_TYPE, call, &type_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", roletype->type_str);
		goto resolve_roletype_out;
	}
	roletype->type = (struct cil_type*)(type_node->data);

	return SEPOL_OK;

resolve_roletype_out:
	return rc;
}

int cil_resolve_roletrans(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call)
{
	struct cil_role_trans *roletrans = (struct cil_role_trans*)current->data;
	struct cil_tree_node *src_node = NULL;
	struct cil_tree_node *tgt_node = NULL;
	struct cil_tree_node *obj_node = NULL;
	struct cil_tree_node *result_node = NULL;
	int rc = SEPOL_ERR;

	rc = cil_resolve_name(db, current, roletrans->src_str, CIL_SYM_ROLES, CIL_ROLE, call, &src_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", roletrans->src_str);
		goto resolve_roletrans_out;
	}
	roletrans->src = (struct cil_role*)(src_node->data);
					
	rc = cil_resolve_name(db, current, roletrans->tgt_str, CIL_SYM_TYPES, CIL_TYPE, call, &tgt_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", roletrans->tgt_str);
		goto resolve_roletrans_out;
	}
	roletrans->tgt = (struct cil_type*)(tgt_node->data);

	rc = cil_resolve_name(db, current, roletrans->obj_str, CIL_SYM_CLASSES, CIL_CLASS, call, &obj_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", roletrans->obj_str);
		goto resolve_roletrans_out;
	}
	roletrans->obj = (struct cil_class*)(obj_node->data);

	rc = cil_resolve_name(db, current, roletrans->result_str, CIL_SYM_ROLES, CIL_ROLE, call, &result_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", roletrans->result_str);
		goto resolve_roletrans_out;
	}
	roletrans->result = (struct cil_role*)(result_node->data);

	return SEPOL_OK;

resolve_roletrans_out:
	return rc;
}

int cil_resolve_roleallow(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call)
{
	struct cil_role_allow *roleallow = (struct cil_role_allow*)current->data;
	struct cil_tree_node *src_node = NULL;
	struct cil_tree_node *tgt_node = NULL;
	int rc = SEPOL_ERR;
	
	rc = cil_resolve_name(db, current, roleallow->src_str, CIL_SYM_ROLES, CIL_ROLE, call, &src_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", roleallow->src_str);
		goto resolve_roleallow_out;
	}
	roleallow->src = (struct cil_role*)(src_node->data);

	rc = cil_resolve_name(db, current, roleallow->tgt_str, CIL_SYM_ROLES, CIL_ROLE, call, &tgt_node);	
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", roleallow->tgt_str);
		goto resolve_roleallow_out;
	}
	roleallow->tgt = (struct cil_role*)(tgt_node->data);

	return SEPOL_OK;

resolve_roleallow_out:
	return rc;
}

int cil_resolve_roledominance(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call)
{
	struct cil_roledominance *roledom = (struct cil_roledominance*)current->data;
	struct cil_tree_node *role_node = NULL;
	struct cil_tree_node *domed_node = NULL;
	int rc = SEPOL_ERR;

	rc = cil_resolve_name(db, current, roledom->role_str, CIL_SYM_ROLES, CIL_ROLE, call, &role_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", roledom->role_str);
		goto resolve_roledominance_out;
	}
	roledom->role = (struct cil_role*)(role_node->data);

	rc = cil_resolve_name(db, current, roledom->domed_str, CIL_SYM_ROLES, CIL_ROLE, call, &domed_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", roledom->domed_str);
		goto resolve_roledominance_out;
	}
	roledom->domed = (struct cil_role*)(domed_node->data);

	return SEPOL_OK;

resolve_roledominance_out:
	return rc;
}

int cil_resolve_sensalias(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call)
{
	struct cil_sensalias *alias = (struct cil_sensalias*)current->data;
	struct cil_tree_node *sens_node = NULL;
	int rc = SEPOL_ERR;

	rc = cil_resolve_name(db, current, alias->sens_str, CIL_SYM_SENS, CIL_SENS, call, &sens_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", alias->sens_str);
		goto resolve_sensalias_out;
	}
	alias->sens = (struct cil_sens*)(sens_node->data);

	return SEPOL_OK;

resolve_sensalias_out:
	return rc;
}

int cil_resolve_catalias(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call)
{
	struct cil_catalias *alias = (struct cil_catalias*)current->data;
	struct cil_tree_node *cat_node = NULL;
	int rc = SEPOL_ERR;

	rc = cil_resolve_name(db, current, alias->cat_str, CIL_SYM_CATS, CIL_CAT, call, &cat_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", alias->cat_str);
		goto resolve_catalias_out;
	}
	alias->cat = (struct cil_cat*)(cat_node->data);

	return SEPOL_OK;

resolve_catalias_out:
	return rc;
}

int __cil_set_append(struct cil_list_item *main_list_item, struct cil_list_item *new_list_item, int *success)
{
	int rc = SEPOL_ERR;

	if (main_list_item == NULL || new_list_item == NULL) {
		goto set_append_out;
	}

	if (main_list_item->data == new_list_item->data && main_list_item->next == NULL) { 
		main_list_item->next = new_list_item->next;
		*success = 1;
		rc = SEPOL_OK;
		goto set_append_out;
	} else {
		while (main_list_item != NULL || new_list_item != NULL) {
			if (main_list_item->data != new_list_item->data) {
				printf("Error: categoryorder adjacency mismatch\n");
				rc = SEPOL_ERR;
				goto set_append_out;
			}
			main_list_item = main_list_item->next;
			new_list_item = new_list_item->next;
		}
		*success = 1;
		rc = SEPOL_OK;
		goto set_append_out;
	}

	return SEPOL_OK;

set_append_out:
	return rc;
}

int __cil_set_prepend(struct cil_list *main_list, struct cil_list *new_list, struct cil_list_item *main_list_item, struct cil_list_item *new_list_item, int *success)
{
	struct cil_list_item *new_list_iter = NULL;
	int rc = SEPOL_ERR;

	if (main_list_item == NULL || new_list_item == NULL) {
		goto set_prepend_out;
	}

	if (new_list_item->next != NULL) {
		printf("Invalid list item given to prepend to list: Has next item\n");
		goto set_prepend_out;
	}

	if (main_list_item == main_list->head) {
		new_list_iter = new_list->head;
		while (new_list_iter != NULL) {
			if (new_list_iter->next == new_list_item) {
				new_list_iter->next = NULL;
				rc = cil_list_prepend_item(main_list, new_list_iter);
				if (rc != SEPOL_OK) {
					printf("Failed to prepend item to list\n");
					goto set_prepend_out;
				}
				*success = 1;
				goto set_prepend_out;
			}
		}
		rc = SEPOL_ERR;
		goto set_prepend_out;
	} else {
		printf("Error: Attempting to prepend to not the head of the list\n");
		goto set_prepend_out;
	}

	return SEPOL_OK;

set_prepend_out:
	return rc;
}

int __cil_set_merge_lists(struct cil_list *primary, struct cil_list *new, int *success)
{
	struct cil_list_item *curr_main = primary->head;
	struct cil_list_item *curr_new = NULL;
	int rc = SEPOL_ERR;

	if (primary == NULL && new == NULL) {
		goto set_merge_lists_out;
	}

	while (curr_main != NULL) {
		curr_new = new->head;
		while (curr_new != NULL) {
			if (curr_main->data == curr_new->data) {
				if (curr_new->next == NULL) {
					rc = __cil_set_prepend(primary, new, curr_main, curr_new, success);
					if (rc != SEPOL_OK) {
						printf("Failed to prepend categoryorder sublist to primary list\n");
					}
					goto set_merge_lists_out;
				} else {
					rc = __cil_set_append(curr_main, curr_new, success);
					if (rc != SEPOL_OK) {
						printf("Failed to append categoryorder sublist to primary list\n");
					}
					goto set_merge_lists_out;
				}
			}
			curr_new = curr_new->next;
		}
		curr_main = curr_main->next;
	}

	return SEPOL_OK;

set_merge_lists_out:
	return rc;
}

int __cil_set_remove_list(struct cil_list *catorder, struct cil_list *remove_item)
{
	struct cil_list_item *list_item = NULL;
	int rc = SEPOL_ERR;

	list_item = catorder->head;
	while (list_item->next != NULL) {
		if (list_item->next->data == remove_item) {
			list_item->next = list_item->next->next;
			rc = SEPOL_OK;
			goto set_remove_list_out;
		}
		list_item = list_item->next;
	}

	return SEPOL_OK;

set_remove_list_out:
	return rc;
}

int __cil_set_order(struct cil_list *order, struct cil_list *edges)
{
	struct cil_list_item *order_head = NULL;
	struct cil_list_item *order_sublist = NULL;
	struct cil_list_item *order_lists = NULL;
	struct cil_list_item *edge_node = NULL;
	int success = 0;
	int rc = SEPOL_ERR;

	order_head = order->head;
	order_sublist = order_head;
	edge_node = edges->head;
	while (edge_node != NULL) {
		while (order_sublist != NULL) {
			if (order_sublist->data == NULL) {
				order_sublist->data = edge_node->data;
				break;
			} else {
				rc = __cil_set_merge_lists(order_sublist->data, edge_node->data, &success);
				if (rc != SEPOL_OK) {
					printf("Failed to merge categoryorder sublist with main list\n");
					goto set_order_out;
				}
			}

			if (success) {
				break;
			} else if (order_sublist->next == NULL) {
				order_sublist->next = edge_node;
				break;
			}
			order_sublist = order_sublist->next;
		}

		if (success) {
			success = 0;
			order_sublist = order_head;
			while (order_sublist != NULL) {
				order_lists = order_head;
				while (order_lists != NULL) {
					if (order_sublist != order_lists) {
						rc = __cil_set_merge_lists(order_sublist->data, order_lists->data, &success);
						if (rc != SEPOL_OK) {
							printf("Failed combining categoryorder lists into one\n");
							goto set_order_out;
						}
						if (success) {
							__cil_set_remove_list(order, order_lists->data);
						}
					}
					order_lists = order_lists->next;
				}
				order_sublist = order_sublist->next; 
			}
		}
		order_sublist = order_head;
		edge_node = edge_node->next;
	}
	return SEPOL_OK;

set_order_out:
	return rc;
}

int __cil_verify_order_node_helper(struct cil_tree_node *node, __attribute__((unused)) uint32_t *finished, void **extra_args)
{
	struct cil_list *order = NULL;	
	struct cil_list_item *ordered = NULL;
	uint32_t *found = NULL;
	uint32_t *empty = NULL;
	uint32_t *flavor = NULL;
	int rc = SEPOL_ERR;

	if (node == NULL || extra_args == NULL) {
		goto verify_order_node_helper_out;
	}

	order = extra_args[ARGS_VERIFY_ORDER];
	ordered = extra_args[ARGS_VERIFY_ORDERED];
	found = extra_args[ARGS_VERIFY_FOUND];
	empty = extra_args[ARGS_VERIFY_EMPTY];
	flavor = extra_args[ARGS_VERIFY_FLAVOR];

	if (node->flavor == *flavor) {
		if (*empty) {
			printf("Error: ordering is empty\n");
			goto verify_order_node_helper_out;
		}
		ordered = order->head;
		while (ordered != NULL) {
			if (ordered->data == node->data) {
				*found = 1;
				break;
			}
			ordered = ordered->next;
		}
		if (!(*found)) {
			printf("Item not ordered: %s\n", ((struct cil_symtab_datum*)node->data)->name);
			goto verify_order_node_helper_out;
		}
		*found = 0;
	}
	
	return SEPOL_OK;

verify_order_node_helper_out:
	return rc;
}

int __cil_verify_order(struct cil_list *order, struct cil_tree_node *current, uint32_t flavor)
{

	struct cil_list_item *ordered = NULL;
	void **extra_args = NULL;
	int found = 0;
	int empty = 0;
	int rc = SEPOL_ERR;

	if (order == NULL || current == NULL) {
		goto verify_order_out;
	}

	if (order->head == NULL) {
		empty = 1;
	} else {
		ordered = order->head;
		if (ordered->next != NULL) {
			printf("Disjoint category ordering exists\n");
			goto verify_order_out;
		}
		
		if (ordered->data != NULL) {
			order->head = ((struct cil_list*)ordered->data)->head;
		}
	}

	extra_args = cil_malloc(sizeof(*extra_args) * ARGS_VERIFY_COUNT);
	extra_args[ARGS_VERIFY_ORDER] = order;
	extra_args[ARGS_VERIFY_ORDERED] = ordered;
	extra_args[ARGS_VERIFY_FOUND] = &found;
	extra_args[ARGS_VERIFY_EMPTY] = &empty;
	extra_args[ARGS_VERIFY_FLAVOR] = &flavor;

	rc = cil_tree_walk(current, __cil_verify_order_node_helper, NULL, NULL, extra_args); 
	if (rc != SEPOL_OK) {
		printf("Failed to verify category order\n");
		goto verify_order_out;
	}
	
	return SEPOL_OK;

verify_order_out:
	return rc;
}

int __cil_create_edge_list(struct cil_db *db, struct cil_tree_node *current, struct cil_list *order, uint32_t sym_flavor, uint32_t flavor, struct cil_list *edge_list, struct cil_call *call)
{

	struct cil_tree_node *node = NULL;
	struct cil_list *edge_nodes = NULL;
	struct cil_list_item *edge = NULL;
	struct cil_list_item *edge_node = NULL;
	struct cil_list_item *copy_node = NULL;
	struct cil_list_item *edge_tail = NULL;
	struct cil_list_item *edge_list_tail = NULL;
	struct cil_list_item *curr = NULL;
	int rc = SEPOL_ERR;

	if (order == NULL || order->head == NULL || edge_list == NULL) {
		goto create_edge_list_out;
	}

	curr = order->head;

	while (curr != NULL) {
		rc = cil_resolve_name(db, current, (char*)curr->data, sym_flavor, flavor, call, &node);
		if (rc != SEPOL_OK) {
			printf("Failed to resolve name: %s\n", (char*)curr->data);
			goto create_edge_list_out;
		}
		cil_list_item_init(&edge_node);
		edge_node->flavor = node->flavor;
		edge_node->data = node->data;
		if (edge_nodes == NULL) {
			cil_list_init(&edge_nodes);
			cil_list_item_init(&edge);
			if (edge_list->head == NULL) {
				edge_list->head = edge;
			} else {
				edge_list_tail->next = edge;
			}
			edge_list_tail = edge;
			edge_list_tail->flavor = CIL_LIST;
			edge_list_tail->data = edge_nodes;
			if (edge_tail != NULL) {
				cil_list_item_init(&copy_node);
				copy_node->flavor = edge_tail->flavor;
				copy_node->data = edge_tail->data;
				edge_nodes->head = copy_node;
				edge_nodes->head->next = edge_node;
				edge_tail = edge_node;
				edge_nodes = NULL;
			} else {
				edge_nodes->head = edge_node;
			}
		} else {
			edge_nodes->head->next = edge_node;
			edge_tail = edge_node;
			edge_nodes = NULL;
		}
		curr = curr->next;
	}
	return SEPOL_OK;

create_edge_list_out:
	return rc;
}

int cil_resolve_catorder(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call)
{
	struct cil_catorder *catorder = (struct cil_catorder*)current->data;
	struct cil_list_item *list_item = NULL;
	struct cil_list *edge_list = NULL;
	int rc = SEPOL_ERR;

	cil_list_init(&edge_list);

	rc = __cil_create_edge_list(db, current, catorder->cat_list_str, CIL_SYM_CATS, CIL_CAT, edge_list, call);
	if (rc != SEPOL_OK) {
		printf("Failed to create category edge list\n");
		goto resolve_catorder_out;
	}

	if (db->catorder->head == NULL) {
		cil_list_item_init(&list_item);
		db->catorder->head = list_item;
	}
	rc = __cil_set_order(db->catorder, edge_list);
	if (rc != SEPOL_OK) {
		printf("Failed to order categoryorder\n");
		goto resolve_catorder_out;
	}

	return SEPOL_OK;

resolve_catorder_out:
	return rc;
}

int cil_resolve_dominance(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call)
{
	struct cil_sens_dominates *dom = (struct cil_sens_dominates*)current->data;
	struct cil_list_item *list_item = NULL;
	struct cil_list *edge_list = NULL;
	int rc = SEPOL_ERR;
	
	cil_list_init(&edge_list);
	
	rc = __cil_create_edge_list(db, current, dom->sens_list_str, CIL_SYM_SENS, CIL_SENS, edge_list, call);
	if (rc != SEPOL_OK) {
		printf("Failed to create sensitivity edge list\n");
		goto resolve_dominance_out;
	}

	if (db->dominance->head == NULL) {
		cil_list_item_init(&list_item);
		db->dominance->head = list_item;
	}

	rc = __cil_set_order(db->dominance, edge_list);
	if (rc != SEPOL_OK) {
		printf("Failed to order dominance\n");
		goto resolve_dominance_out;
	}
	
	return SEPOL_OK;

resolve_dominance_out:
	return rc;
}

int __cil_resolve_cat_range(struct cil_db *db, struct cil_list *cat_list, struct cil_list *res_list)
{
	struct cil_list_item *curr_cat = NULL;
	struct cil_list_item *catorder = NULL;
	struct cil_list_item *curr_catorder = NULL;
	struct cil_list_item *new_item;
	struct cil_list_item *list_tail;
	int rc = SEPOL_ERR;

	if (cat_list == NULL || res_list == NULL || db->catorder->head == NULL) {
		goto resolve_cat_range_out;
	}

	if (cat_list->head == NULL || cat_list->head->next == NULL || cat_list->head->next->next != NULL) {
		printf("Invalid category list passed into category range resolution\n");
		goto resolve_cat_range_out;
	}

	curr_cat = cat_list->head;
	catorder = db->catorder->head;
	curr_catorder = catorder;

	while (curr_catorder != NULL) {
		if (!strcmp((char*)curr_cat->data, (char*)((struct cil_cat*)curr_catorder->data)->datum.name)) {
			while (curr_catorder != NULL) {
				cil_list_item_init(&new_item);
				new_item->flavor = curr_catorder->flavor;
				new_item->data = curr_catorder->data;
				if (res_list->head == NULL) {
					res_list->head = new_item;
				} else {
					list_tail->next = new_item;
				}
				list_tail = new_item;
				if (!strcmp((char*)curr_cat->next->data, (char*)((struct cil_cat*)curr_catorder->data)->datum.name)) {
					rc =  SEPOL_OK;
					goto resolve_cat_range_out;
				}
				curr_catorder = curr_catorder->next;
			}
			printf("Invalid category range\n");
			rc = SEPOL_ERR;
			goto resolve_cat_range_out;
		}
		curr_catorder = curr_catorder->next;
	}

	return SEPOL_OK;

resolve_cat_range_out:
	return rc;
}

int cil_resolve_cat_list(struct cil_db *db, struct cil_tree_node *current, struct cil_list *cat_list, struct cil_list *res_cat_list, struct cil_call *call)
{
	struct cil_tree_node *cat_node = NULL;
	struct cil_list *sub_list = NULL;
	struct cil_list_item *new_item = NULL;
	struct cil_list_item *list_tail = NULL;
	struct cil_list_item *curr = NULL;
	int rc = SEPOL_ERR;
	
	if (cat_list == NULL || res_cat_list == NULL) {
		goto resolve_cat_list_out;
	}

	curr = cat_list->head;

	while (curr != NULL) {
		cil_list_item_init(&new_item);
		if (curr->flavor == CIL_LIST) {
			cil_list_init(&sub_list);
			new_item->flavor = CIL_LIST;
			new_item->data = sub_list;
			rc = __cil_resolve_cat_range(db, (struct cil_list*)curr->data, sub_list);
			if (rc != SEPOL_OK) {
				printf("Failed to resolve category range\n");
				goto resolve_cat_list_out;
			}
		} else {
			rc = cil_resolve_name(db, current, (char*)curr->data, CIL_SYM_CATS, CIL_CATSET, call, &cat_node);
			if (rc != SEPOL_OK) {
				printf("Failed to resolve category name: %s\n", (char*)curr->data);
				goto resolve_cat_list_out;
			}
			if (cat_node->flavor == CIL_CATSET) {
				printf("categorysets are not allowed inside category lists\n");
				rc = SEPOL_ERR;
				goto resolve_cat_list_out;
                        } else {
				new_item->flavor = cat_node->flavor;
				new_item->data = cat_node->data;
			}
		}
		if (res_cat_list->head == NULL) {
			res_cat_list->head = new_item;
		} else {
			list_tail->next = new_item;
		}

		while (new_item->next != NULL) {
			new_item = new_item->next;
		}
		list_tail = new_item;
		curr = curr->next;
	}

	return SEPOL_OK;

resolve_cat_list_out:
	return rc;
}

int cil_resolve_catset(struct cil_db *db, struct cil_tree_node *current, struct cil_catset *catset, struct cil_call *call)
{
	struct cil_list *res_cat_list = NULL;
	int rc = SEPOL_ERR;

	cil_list_init(&res_cat_list);
	rc = cil_resolve_cat_list(db, current, catset->cat_list_str, res_cat_list, call);
	if (rc != SEPOL_OK) {
		printf("Failed to resolve category list\n");
		goto resolve_catset_out;
	}

	if (catset->cat_list != NULL) {
		/* clean up because of re-resolve */
		cil_list_destroy(&catset->cat_list, 0);
	}
	catset->cat_list = res_cat_list;
	
	return SEPOL_OK;

resolve_catset_out:
	return rc;
}

int __cil_senscat_insert(struct cil_db *db, struct cil_tree_node *current, hashtab_t hashtab, char *key, struct cil_call *call)
{
	struct cil_tree_node *cat_node = NULL;
	int rc = SEPOL_ERR;

	rc = cil_resolve_name(db, current, key, CIL_SYM_CATS, CIL_CAT, call, &cat_node);
	if (rc != SEPOL_OK) {
		printf("Failed to resolve category name\n");
		goto senscat_insert_out;
	}
	/* TODO CDS This seems fragile - using the symtab abstraction sometimes but then dropping to the hashtab level when necessary (and it is necessary as using cil_symtab_insert() would reset the name field in the datum). */
	rc = hashtab_insert(hashtab, (hashtab_key_t)key, (hashtab_datum_t)cat_node->data);
	if (rc != SEPOL_OK) {
		printf("Failed to insert category into sensitivitycategory symtab\n");
		goto senscat_insert_out;
	}

	return SEPOL_OK;

senscat_insert_out:
	return rc;
}

int cil_resolve_senscat(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call)
{
	struct cil_tree_node *sens_node = NULL;
	struct cil_senscat *senscat = (struct cil_senscat*)current->data;
	struct cil_tree_node *cat_node = NULL;
	struct cil_list *sub_list = NULL;
	struct cil_list_item *curr = NULL;
	struct cil_list_item *curr_range_cat = NULL;
	int rc = SEPOL_ERR;
	char *key = NULL;
	
	rc = cil_resolve_name(db, current, (char*)senscat->sens_str, CIL_SYM_SENS, CIL_SENS, call, &sens_node);
	if (rc != SEPOL_OK) {
		printf("Failed to get sensitivity node\n");
		goto resolve_senscat_out;
	}

	if (senscat->catset_str != NULL) {
		rc = cil_resolve_name(db, current, (char*)senscat->catset_str, CIL_SYM_CATS, CIL_CATSET, call, &cat_node);
		if (rc != SEPOL_OK) {
			printf("Failed to resolve catset_str\n");
			goto resolve_senscat_out;
		}
		senscat->catset = (struct cil_catset*)cat_node->data;
		curr = senscat->catset->cat_list->head;

		while (curr != NULL) {
			key = cil_strdup(((struct cil_symtab_datum*)curr->data)->name);
			rc = __cil_senscat_insert(db, current, ((struct cil_sens*)sens_node->data)->cats.table, key, call);
			if (rc != SEPOL_OK) {
				printf("Failed to insert category from catset into sensitivity symtab\n");
				goto resolve_senscat_out;
			}
			curr = curr->next;
		}
	} else if (senscat->cat_list_str != NULL) {
		curr = senscat->cat_list_str->head;
		while (curr != NULL) {
			if (curr->flavor == CIL_LIST) {
				cil_list_init(&sub_list);
				rc = __cil_resolve_cat_range(db, (struct cil_list*)curr->data, sub_list);
				if (rc != SEPOL_OK) {
					printf("Failed to resolve category range\n");
					goto resolve_senscat_out;
				}
				curr_range_cat = sub_list->head;
				while (curr_range_cat != NULL) {
					key = cil_strdup(((struct cil_cat*)curr_range_cat->data)->datum.name);
					rc = __cil_senscat_insert(db, current, ((struct cil_sens*)sens_node->data)->cats.table, key, call);
					if (rc != SEPOL_OK) {
						printf("Failed to insert category into sensitivity symtab\n");
						goto resolve_senscat_out;
					}
					curr_range_cat = curr_range_cat->next;
				}
			} else {
				key = cil_strdup(curr->data);
				rc = __cil_senscat_insert(db, current, ((struct cil_sens*)sens_node->data)->cats.table, key, call);
				if (rc != SEPOL_OK) {
					printf("Failed to insert category into sensitivity symtab\n");
					goto resolve_senscat_out;
				}
			}
			curr = curr->next;
		}
	}

	return SEPOL_OK;

resolve_senscat_out:
	return rc;
}

int __cil_verify_sens_cats(struct cil_sens *sens, struct cil_list *cat_list)
{
	struct cil_tree_node *cat_node = NULL;
	struct cil_list_item *curr_cat = cat_list->head;
	symtab_t *symtab = &sens->cats;
	char *key = NULL;
	int rc = SEPOL_ERR;

	while (curr_cat != NULL) {
		if (curr_cat->flavor == CIL_LIST) {
			rc = __cil_verify_sens_cats(sens, curr_cat->data);
			if (rc != SEPOL_OK) {
				printf("Category sublist contains invalid category for sensitivity: %s\n", sens->datum.name);
				goto verify_sens_cats_out;
			}
		} else {
			key = ((struct cil_cat*)curr_cat->data)->datum.name;
			rc = cil_symtab_get_node(symtab, key, &cat_node);
			if (rc != SEPOL_OK) {
				printf("Category has not been associated with this sensitivity: %s\n", key);
				/*TOOD: should this return SEPOL_ERR, even if SEPOL_ENONENT is retunred? */
				goto verify_sens_cats_out;
			}
		}
		curr_cat = curr_cat->next;
	}
	
	return SEPOL_OK;

verify_sens_cats_out:
	return rc;
}

int cil_resolve_level(struct cil_db *db, struct cil_tree_node *current, struct cil_level *level, struct cil_call *call)
{
	struct cil_tree_node *sens_node = NULL;
	struct cil_tree_node *catset_node = NULL;
	struct cil_list *res_cat_list = NULL;
	int rc = SEPOL_ERR;
	
	rc = cil_resolve_name(db, current, (char*)level->sens_str, CIL_SYM_SENS, CIL_SENS, call, &sens_node);
	if (rc != SEPOL_OK) {
		printf("Failed to get sensitivity node\n");
		goto resolve_level_out;
	}
	level->sens = (struct cil_sens*)sens_node->data;

	if (level->catset_str != NULL) {
		rc = cil_resolve_name(db, current, level->catset_str, CIL_SYM_CATS, CIL_CATSET, call, &catset_node);
		if (rc != SEPOL_OK) {
			printf("Failed to resolve categoryset, rc: %d\n", rc);
			goto resolve_level_out;
		}
		rc = cil_resolve_catset(db, current, (struct cil_catset*)catset_node->data, call);
		if (rc != SEPOL_OK) {
			printf("Failed to resolve catset\n");
			goto resolve_level_out;
		}
		rc = __cil_verify_sens_cats(sens_node->data, ((struct cil_catset*)catset_node->data)->cat_list);
		if (rc != SEPOL_OK) {
			printf("Failed to verify sensitivitycategory relationship\n");
			goto resolve_level_out;
		}
		level->catset = catset_node->data;
	} else {
		cil_list_init(&res_cat_list);
		rc = cil_resolve_cat_list(db, current, level->cat_list_str, res_cat_list, call);
		if (rc != SEPOL_OK) {
			printf("Failed to resolve category list\n");
			/* TODO: Add cleanup for cil_list_init */
			goto resolve_level_out;
		}
	
		rc = __cil_verify_sens_cats(sens_node->data, res_cat_list);
		if (rc != SEPOL_OK) {
			printf("Failed to verify sensitivitycategory relationship\n");
			goto resolve_level_out;
		}

		if (level->cat_list) {
			/* clean up because of re-resolve */
			cil_list_destroy(&level->cat_list, 0);
		}
		level->cat_list = res_cat_list;
	}

	return SEPOL_OK;

resolve_level_out:
	return rc;
}

int __cil_resolve_constrain_expr(struct cil_db *db, struct cil_tree_node *current, struct cil_tree_node *expr_root, struct cil_call *call)
{
	struct cil_tree_node *curr = expr_root;
	struct cil_tree_node *attr_node = NULL;
	int rc = SEPOL_ERR;

	while (curr != NULL) {
		if (curr->cl_head == NULL) {
			if (strstr(CIL_CONSTRAIN_OPER, (char*)curr->data) == NULL && strstr(CIL_MLSCONSTRAIN_KEYS, (char*)curr->data) == NULL) {
				rc = cil_resolve_name(db, current, (char*)curr->data, CIL_SYM_TYPES, CIL_TYPE, call, &attr_node);
				if (rc != SEPOL_OK) {
					printf("Name resolution failed for: %s\n", (char*)curr->data);
					goto resolve_constrain_expr_out;
				}
				free(curr->data);
				curr->data = NULL;
				curr->flavor = attr_node->flavor;
				curr->data = attr_node->data;
			}
		} else {
			rc = __cil_resolve_constrain_expr(db, current, curr->cl_head, call);
			if (rc != SEPOL_OK) {
				printf("Failed resolving constrain expression\n");
				goto resolve_constrain_expr_out;
			}
		}
		curr = curr->next;
	}

	return SEPOL_OK;

resolve_constrain_expr_out:
	return rc;
}

int cil_resolve_constrain(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call)
{
	struct cil_constrain *cons = (struct cil_constrain*)current->data;
	struct cil_tree_node *class_node = NULL;
	struct cil_list_item *curr_class = cons->class_list_str->head;
	struct cil_list_item *new_item = NULL;
	struct cil_list *class_list = NULL;
	struct cil_list *perm_list = NULL;
	int rc = SEPOL_ERR;

	cil_list_init(&class_list);
	cil_list_init(&perm_list);
	while (curr_class != NULL) {
		rc = cil_resolve_name(db, current, (char*)curr_class->data, CIL_SYM_CLASSES, CIL_CLASS, call, &class_node);
		if (rc != SEPOL_OK) {
			printf("Name resolution failed for: %s\n", (char*)curr_class->data);
			goto resolve_constrain_out;
		}

		rc = __cil_resolve_perm_list((struct cil_class*)class_node->data, cons->perm_list_str, NULL);
		if (rc != SEPOL_OK) {
			printf("Failed to verify perm list\n");
			goto resolve_constrain_out;
		}

		cil_list_item_init(&new_item);
		new_item->flavor = CIL_CLASS;
		new_item->data = class_node->data;
		rc = cil_list_append_item(class_list, new_item);
		if (rc != SEPOL_OK) {
			printf("Failed to append to class list\n");
			goto resolve_constrain_out;
		}
		curr_class = curr_class->next;
	}

	rc = __cil_resolve_perm_list((struct cil_class*)class_node->data, cons->perm_list_str, perm_list);
	if (rc != SEPOL_OK) {
		printf("Failed to resolve perm list\n");
		goto resolve_constrain_out;
	}

	rc = cil_resolve_expr_stack(db, cons->expr, current, call);
	if (rc != SEPOL_OK) {
		printf("Failed to resolve constrain expression\n");
		goto resolve_constrain_out;
	}

	if (cons->class_list != NULL) {
		/* clean up because of re-resolve */
		cil_list_destroy(&cons->class_list, 0);
	}
	cons->class_list = class_list;

	if (cons->perm_list != NULL) {
		/* clean up because of re-resolve */
		cil_list_destroy(&cons->perm_list, 0);
	}
	cons->perm_list = perm_list;

	return SEPOL_OK;

resolve_constrain_out:
	return rc;
}

int cil_resolve_context(struct cil_db *db, struct cil_tree_node *current, struct cil_context *context, struct cil_call *call)
{
	struct cil_tree_node *user_node = NULL;
	struct cil_tree_node *role_node = NULL;
	struct cil_tree_node *type_node = NULL;
	struct cil_tree_node *low_node = NULL;
	struct cil_tree_node *high_node = NULL;

	int rc = SEPOL_ERR;
	char *error = NULL;

	rc = cil_resolve_name(db, current, context->user_str, CIL_SYM_USERS, CIL_USER, call, &user_node);
	if (rc != SEPOL_OK) {
		error = context->user_str;
		goto resolve_context_out;
	}
	context->user = (struct cil_user*)user_node->data;

	rc = cil_resolve_name(db, current, context->role_str, CIL_SYM_ROLES, CIL_ROLE, call, &role_node);
	if (rc != SEPOL_OK) {
		error = context->role_str;
		goto resolve_context_out;
	}
	context->role = (struct cil_role*)role_node->data;

	rc = cil_resolve_name(db, current, context->type_str, CIL_SYM_TYPES, CIL_TYPE, call, &type_node);
	if (rc != SEPOL_OK) {
		error = context->type_str;
		goto resolve_context_out;
	}
	context->type = (struct cil_type*)type_node->data;

	if (context->low_str != NULL) {
		rc = cil_resolve_name(db, current, context->low_str, CIL_SYM_LEVELS, CIL_LEVEL, call, &low_node);
		if (rc != SEPOL_OK) {
			error = context->low_str;
			goto resolve_context_out;
		}
		context->low = (struct cil_level*)low_node->data;

		if (context->low->datum.name == NULL) {
			rc = cil_resolve_level(db, current, context->low, call);
			if (rc != SEPOL_OK) {
				printf("Failed to resolve low level, rc: %d\n", rc);
				goto resolve_context_out;
			}
		}

	} else if (context->low != NULL) {
		rc = cil_resolve_level(db, current, context->low, call);
		if (rc != SEPOL_OK) {
			printf("Failed to resolve low level, rc: %d\n", rc);
			goto resolve_context_out;
		}
	} else {
		printf("Invalid context, low level not found\n");
		rc = SEPOL_ERR;
		goto resolve_context_out;
	}

	if (context->high_str != NULL) {
		rc = cil_resolve_name(db, current, context->high_str, CIL_SYM_LEVELS, CIL_LEVEL, call, &high_node);
		if (rc != SEPOL_OK) {
			error = context->high_str;
			goto resolve_context_out;
		}
		context->high = (struct cil_level*)high_node->data;

		if (context->high->datum.name == NULL) {
			rc = cil_resolve_level(db, current, context->high, call);
			if (rc != SEPOL_OK) {
				printf("Failed to resolve high level, rc: %d\n", rc);
				goto resolve_context_out;
			}
		}
	} else if (context->high != NULL) {
		rc = cil_resolve_level(db, current, context->high, call);
		if (rc != SEPOL_OK) {
			printf("Failed to resolve high level, rc: %d\n", rc);
			goto resolve_context_out;
		}
	} else {
		printf("Invalid context, high level not found\n");
		rc = SEPOL_ERR;
		goto resolve_context_out;
	}

	return SEPOL_OK;

resolve_context_out:
	printf("Name resolution failed for %s\n", error);
	return rc;
}

int cil_resolve_filecon(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call)
{
	struct cil_filecon *filecon = (struct cil_filecon*)current->data;
	struct cil_tree_node *context_node = NULL;
	int rc=  SEPOL_ERR;

	if (filecon->context_str != NULL) {
		rc = cil_resolve_name(db, current, filecon->context_str, CIL_SYM_CONTEXTS, CIL_CONTEXT, call, &context_node);
		if (rc != SEPOL_OK) {
			printf("Failed to resolve file context: %s, rc: %d\n", filecon->context_str, rc);
			return rc;
		}
		filecon->context = (struct cil_context*)context_node->data;
	} else {
		rc = cil_resolve_context(db, current, filecon->context, call);
		if (rc != SEPOL_OK) {
			printf("Failed to resolve file context\n");
			return rc;
		}
	}
	db->filecon->count++;

	return SEPOL_OK;
}

int cil_resolve_portcon(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call)
{
	struct cil_portcon *portcon = (struct cil_portcon*)current->data;
	struct cil_tree_node *context_node = NULL;
	int rc = SEPOL_ERR;

	if (portcon->context_str != NULL) {
		rc = cil_resolve_name(db, current, portcon->context_str, CIL_SYM_CONTEXTS, CIL_CONTEXT, call, &context_node);
		if (rc != SEPOL_OK) {
			printf("Failed to resolve port context: %s, rc: %d\n", portcon->context_str, rc);
			goto resolve_portcon_out;
		}
		portcon->context = (struct cil_context*)context_node->data;
	} else {
		rc = cil_resolve_context(db, current, portcon->context, call);
		if (rc != SEPOL_OK) {
			printf("Failed to resolve port context\n");
			goto resolve_portcon_out;
		}
	}
	db->portcon->count++;

	return SEPOL_OK;

resolve_portcon_out:
	return rc;
}

int cil_resolve_genfscon(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call)
{
	struct cil_genfscon *genfscon = (struct cil_genfscon*)current->data;
	struct cil_tree_node *context_node = NULL;
	int rc = SEPOL_ERR;

	if (genfscon->context_str != NULL) {
		rc = cil_resolve_name(db, current, genfscon->context_str, CIL_SYM_CONTEXTS, CIL_CONTEXT, call, &context_node);
		if (rc != SEPOL_OK) {
			printf("Failed to resolve genfs context: %s, rc: %d\n", genfscon->context_str, rc);
			goto resolve_genfscon_out;
		}
		genfscon->context = (struct cil_context*)context_node->data;
	} else {
		rc = cil_resolve_context(db, current, genfscon->context, call);
		if (rc != SEPOL_OK) {
			printf("Failed to resolve genfs context\n");
			goto resolve_genfscon_out;
		}
	}
	db->genfscon->count++;

	return SEPOL_OK;

resolve_genfscon_out:
	return rc;
}

int cil_resolve_nodecon(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call)
{
	struct cil_nodecon *nodecon = (struct cil_nodecon*)current->data;
	struct cil_tree_node *addr_node = NULL;
	struct cil_tree_node *mask_node = NULL;
	struct cil_tree_node *context_node = NULL;
	int rc = SEPOL_ERR;

	if (nodecon->addr_str != NULL) {
		rc = cil_resolve_name(db, current, nodecon->addr_str, CIL_SYM_IPADDRS, CIL_IPADDR, call, &addr_node);
		if (rc != SEPOL_OK) {
			printf("Failed to resolve node addr: %s, rc: %d\n", nodecon->addr_str, rc);
			goto resolve_nodecon_out;
		}
		nodecon->addr = (struct cil_ipaddr*)addr_node->data;
	}
	
	if (nodecon->mask_str != NULL) {
		rc = cil_resolve_name(db, current, nodecon->mask_str, CIL_SYM_IPADDRS, CIL_IPADDR, call, &mask_node);
		if (rc != SEPOL_OK) {
			printf("Failed to resolve node mask: %s, rc: %d\n", nodecon->mask_str, rc);
			goto resolve_nodecon_out;
		}
		nodecon->mask = (struct cil_ipaddr*)mask_node->data;
	}

	if (nodecon->context_str != NULL) {
		rc = cil_resolve_name(db, current, nodecon->context_str, CIL_SYM_CONTEXTS, CIL_CONTEXT, call, &context_node);
		if (rc != SEPOL_OK) {
			printf("Failed to resolve node context: %s, rc: %d\n", nodecon->context_str, rc);
			goto resolve_nodecon_out;
		}
		nodecon->context = (struct cil_context*)context_node->data;
	} else {
		rc = cil_resolve_context(db, current, nodecon->context, call);
		if (rc != SEPOL_OK) {
			printf("Failed to resolve node context\n");
			goto resolve_nodecon_out;
		}
	}

	if (nodecon->addr->family != nodecon->mask->family) {
		printf("Nodecon ip address not in the same family\n");
		rc = SEPOL_ERR;
		goto resolve_nodecon_out;
	}

	db->nodecon->count++;

	return SEPOL_OK;

resolve_nodecon_out:
	return rc;
}

int cil_resolve_netifcon(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call)
{
	struct cil_netifcon *netifcon = (struct cil_netifcon*)current->data;
	struct cil_tree_node *ifcon_node = NULL;
	struct cil_tree_node *packcon_node = NULL;

	int rc = SEPOL_ERR;

	if (netifcon->if_context_str != NULL) {
		rc = cil_resolve_name(db, current, netifcon->if_context_str, CIL_SYM_CONTEXTS, CIL_CONTEXT, call, &ifcon_node);
		if (rc != SEPOL_OK) {
			printf("Failed to resolve interface context: %s, rc: %d\n", netifcon->if_context_str, rc);
			goto resolve_netifcon_out;
		}
		netifcon->if_context = (struct cil_context*)ifcon_node->data;
	} else {
		rc = cil_resolve_context(db, current, netifcon->if_context, call);
		if (rc != SEPOL_OK) {
			printf("Failed to resolve OTF interface context\n");
			goto resolve_netifcon_out;
		}
	}

	if (netifcon->packet_context_str != NULL) {
		rc = cil_resolve_name(db, current, netifcon->packet_context_str, CIL_SYM_CONTEXTS, CIL_CONTEXT, call, &packcon_node);
		if (rc != SEPOL_OK) {
			printf("Failed to resolve packet context: %s, rc: %d\n", netifcon->packet_context_str, rc);
			goto resolve_netifcon_out;
		}
		netifcon->packet_context = (struct cil_context*)packcon_node->data;
	} else {
		rc = cil_resolve_context(db, current, netifcon->packet_context, call);
		if (rc != SEPOL_OK) {
			printf("Failed to resolve OTF packet context\n");
			goto resolve_netifcon_out;
		}
	}
	db->netifcon->count++;
	return SEPOL_OK;

resolve_netifcon_out:
	return rc;
}

int cil_resolve_fsuse(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call)
{
	struct cil_fsuse *fsuse = (struct cil_fsuse*)current->data;
	struct cil_tree_node *context_node = NULL;
	int rc = SEPOL_ERR;

	if (fsuse->context_str != NULL) {
		rc = cil_resolve_name(db, current, fsuse->context_str, CIL_SYM_CONTEXTS, CIL_CONTEXT, call, &context_node);
		if (rc != SEPOL_OK) {
			printf("Failed to resolve context, rc: %d\n", rc);
			goto resolve_fsuse_out;
		}
		fsuse->context = (struct cil_context*)context_node->data;
	} else {
		rc = cil_resolve_context(db, current, fsuse->context, call);
		if (rc != SEPOL_OK) {
			printf("Failed to resolve context, rc: %d\n", rc);
			goto resolve_fsuse_out;
		}
	}
	db->fsuse->count++;
	return SEPOL_OK;

resolve_fsuse_out:
	return rc;
}

int cil_resolve_sidcontext(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call)
{
	struct cil_sidcontext *sidcon = (struct cil_sidcontext*)current->data;
	struct cil_tree_node *sid_node = NULL;
	struct cil_tree_node *context_node = NULL;

	int rc = SEPOL_ERR;

	rc = cil_resolve_name(db, current, sidcon->sid_str, CIL_SYM_SIDS, CIL_SID, call, &sid_node);
	if (rc != SEPOL_OK) {
		printf("Failed to resolve sid, rc: %d : %s\n", rc, sidcon->sid_str);
		goto resolve_sidcontext_out;
	}
	sidcon->sid = (struct cil_sid*)sid_node->data;

	if (sidcon->context_str != NULL) {
		rc = cil_resolve_name(db, current, sidcon->context_str, CIL_SYM_CONTEXTS, CIL_CONTEXT, call, &context_node);
		if (rc != SEPOL_OK) {
			printf("Failed to resolve context, rc: %d\n", rc);
			goto resolve_sidcontext_out;
		}
		sidcon->context = (struct cil_context*)context_node->data;
	} else if (sidcon->context != NULL) {
		rc = cil_resolve_context(db, current, sidcon->context, call);
		if (rc != SEPOL_OK) {
			printf("Failed to resolve context, rc: %d\n", rc);
			goto resolve_sidcontext_out;
		}
	}

	return SEPOL_OK;

resolve_sidcontext_out:
	return rc;
}

int cil_resolve_call1(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call)
{
	struct cil_call *new_call = (struct cil_call*)current->data;
	struct cil_tree_node *macro_node = NULL;
	int rc = SEPOL_ERR;

	if (new_call->macro_str != NULL) {
		rc = cil_resolve_name(db, current, new_call->macro_str, CIL_SYM_MACROS, CIL_MACRO, call, &macro_node);
		if (rc != SEPOL_OK) {
			printf("Failed to resolve macro, rc: %d\n", rc);
			goto resolve_call1_out;
		}
		new_call->macro = (struct cil_macro*)macro_node->data;
	} else {
		printf("Macro string is null\n");
		rc = SEPOL_ERR;
		goto resolve_call1_out;
	}

	if (new_call->macro->params != NULL ) {
	
		struct cil_list_item *item = new_call->macro->params->head;
		struct cil_list_item *args_tail = NULL;
		struct cil_args *new_arg = NULL;
		struct cil_tree_node *pc = NULL;

		if (new_call->args_tree == NULL) {
			printf("Missing arguments (line: %d)\n", current->line);
			rc = SEPOL_ERR;
			goto resolve_call1_out;
		}

		pc = new_call->args_tree->root->cl_head;

		new_call->args = cil_malloc(sizeof(struct cil_list));

		while (item != NULL) {
			if (item != NULL && pc == NULL) {
				printf("Missing arguments (line: %d)\n", current->line);
				rc = SEPOL_ERR;
				goto resolve_call1_out;
			}
			if (item->flavor != CIL_PARAM) {
				rc = SEPOL_ERR;
				goto resolve_call1_out;
			}

			new_arg = cil_malloc(sizeof(struct cil_args));
			new_arg->arg_str = NULL;
			new_arg->arg = NULL;
			new_arg->param_str = NULL;

			switch (((struct cil_param*)item->data)->flavor) {
			case CIL_TYPE:
				new_arg->arg_str = cil_strdup(pc->data);
				break;
			case CIL_ROLE:
				new_arg->arg_str = cil_strdup(pc->data);
				break;
			case CIL_USER:
				new_arg->arg_str = cil_strdup(pc->data);
				break;
			case CIL_SENS:
				new_arg->arg_str = cil_strdup(pc->data);
				break;
			case CIL_CAT:
				new_arg->arg_str = cil_strdup(pc->data);
				break;
			case CIL_CATSET: {
				if (pc->cl_head != NULL) {
					struct cil_catset *catset = cil_malloc(sizeof(struct cil_catset));
					cil_list_init(&catset->cat_list_str);
					rc = cil_fill_cat_list(pc, catset->cat_list_str);
					if (rc != SEPOL_OK) {
						printf("Failed to create anonymous category set, rc: %d\n", rc);
						cil_destroy_catset(catset);
						goto resolve_call1_out;
					}
					struct cil_tree_node *cat_node;
					cil_tree_node_init(&cat_node);
					cat_node->flavor = CIL_CATSET;
					cat_node->data = catset;
					new_arg->arg = cat_node;
				} else {
					new_arg->arg_str = cil_strdup(pc->data);
				}

				break;
			}
			case CIL_LEVEL: {
				if (pc->cl_head != NULL) {
					struct cil_level *level = cil_malloc(sizeof(struct cil_level));
					struct cil_tree_node *lvl = NULL;

					rc = cil_fill_level(pc->cl_head, level);
					if (rc != SEPOL_OK) {
						printf("Failed to create anonymous level, rc: %d\n", rc);
						cil_destroy_level(level);
						goto resolve_call1_out;
					}
					cil_tree_node_init(&lvl);
					lvl->flavor = CIL_LEVEL;
					lvl->data = level;
					new_arg->arg = lvl;
				} else {
					new_arg->arg_str = cil_strdup(pc->data);
				}

				break;
			}
			case CIL_IPADDR: {
				if (pc->cl_head != NULL) {
					struct cil_ipaddr *ipaddr = NULL;
					struct cil_tree_node *addr_node = NULL;

					rc = cil_ipaddr_init(&ipaddr);
					if (rc != SEPOL_OK) {
						goto resolve_call1_out;
					}

					rc = cil_fill_ipaddr(pc->cl_head, ipaddr);
					if (rc != SEPOL_OK) {
						printf("Failed to create anonymous ip address, rc; %d\n", rc);
						cil_destroy_ipaddr(ipaddr);
						goto resolve_call1_out;
					}

					cil_tree_node_init(&addr_node);
					addr_node->flavor = CIL_IPADDR;
					addr_node->data = ipaddr;
					new_arg->arg = addr_node;
				} else {
					new_arg->arg_str = cil_strdup(pc->data);
				}

				break;
			}
			case CIL_CLASS:
				new_arg->arg_str = cil_strdup(pc->data);
				break;
			case CIL_PERMSET: {
				if (pc->cl_head != NULL) {
					struct cil_permset *permset = NULL;
					struct cil_tree_node *permset_node = NULL;
					rc = cil_permset_init(&permset);
					if (rc != SEPOL_OK) {
						goto resolve_call1_out;
					}
					cil_list_init(&permset->perms_list_str);
					rc = cil_parse_to_list(pc->cl_head, permset->perms_list_str, CIL_AST_STR);
					if (rc != SEPOL_OK) {
						printf("Failed to parse perms\n");
						goto resolve_call1_out;
					}
					cil_tree_node_init(&permset_node);
					permset_node->flavor = CIL_PERMSET;
					permset_node->data = permset;
					new_arg->arg = permset_node;
				} else {
				new_arg->arg_str = cil_strdup(pc->data);
				}
				break;

			}
			default:
				printf("Unexpected flavor: %d\n", item->flavor);
				rc = SEPOL_ERR;
				goto resolve_call1_out;
			}
			new_arg->param_str = ((struct cil_param*)item->data)->str;
			new_arg->flavor = ((struct cil_param*)item->data)->flavor;

			if (args_tail == NULL) {
				new_call->args->head = cil_malloc(sizeof(struct cil_list_item));
				new_call->args->head->flavor = CIL_ARGS;;
				new_call->args->head->data = new_arg;
				args_tail = new_call->args->head;
				args_tail->next = NULL;
			}
			else {
				args_tail->next = cil_malloc(sizeof(struct cil_list_item));
				args_tail->next->flavor = CIL_ARGS;
				args_tail->next->data = new_arg;
				args_tail = args_tail->next;
				args_tail->next = NULL;
			}
	
			pc = pc->next;
			item = item->next;
		}

		if (pc != NULL) {
			printf("Unexpected arguments (line: %d)\n", current->line);
			rc = SEPOL_ERR;
			goto resolve_call1_out;
		}
	} else if (new_call->args_tree != NULL) {
		printf("Rnexpected arguments (line: %d)\n", current->line);
		rc = SEPOL_ERR;
		goto resolve_call1_out;
	}

	rc = cil_copy_ast(db, macro_node, current);
	if (rc != SEPOL_OK) {
		printf("Failed to copy macro, rc: %d\n", rc);
		goto resolve_call1_out;
	}

	return SEPOL_OK;

resolve_call1_out:
	return rc;
}

int cil_resolve_call2(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call)
{
	struct cil_call *new_call = (struct cil_call*)current->data;
	int rc = SEPOL_ERR;
	uint32_t sym_index = CIL_SYM_UNKNOWN;
	struct cil_list_item *item = NULL;

	if (new_call->args == NULL) {
		rc = SEPOL_OK;
		goto resolve_call2_out;
	}
	
	for (item = new_call->args->head; item != NULL; item = item->next) {
		if (((struct cil_args*)item->data)->arg == NULL && ((struct cil_args*)item->data)->arg_str == NULL) {
			printf("Arguments not created correctly\n");
			rc = SEPOL_ERR;
			goto resolve_call2_out;
		}
		
		switch (((struct cil_args*)item->data)->flavor) {
		case CIL_LEVEL:
			if ((((struct cil_args*)item->data)->arg_str == NULL) && ((struct cil_args*)item->data)->arg != NULL) {
				continue; // anonymous, no need to resolve
			} else {
				sym_index = CIL_SYM_LEVELS;
			}
			break;
		case CIL_CATSET:
			if ((((struct cil_args*)item->data)->arg_str == NULL) && ((struct cil_args*)item->data)->arg != NULL) {
				continue; // anonymous, no need to resolve
			} else {
				sym_index = CIL_SYM_CATS;
			}
			break;
		case CIL_IPADDR:
			if ((((struct cil_args*)item->data)->arg_str == NULL) && ((struct cil_args*)item->data)->arg != NULL) {
				continue; // anonymous, no need to resolve
			} else {
				sym_index = CIL_SYM_IPADDRS;
			}
			break;
		case CIL_PERMSET:
			if ((((struct cil_args*)item->data)->arg_str == NULL) && ((struct cil_args*)item->data)->arg != NULL) {
				continue; // anonymous, no need to resolve
			} else {
				sym_index = CIL_SYM_PERMSETS;
			}
			break;
		case CIL_TYPE:
			sym_index = CIL_SYM_TYPES;
			break;
		case CIL_ROLE:
			sym_index = CIL_SYM_ROLES;
			break;
		case CIL_USER:
			sym_index = CIL_SYM_USERS;
			break;
		case CIL_SENS:
			sym_index = CIL_SYM_SENS;
			break;
		case CIL_CAT:
			sym_index = CIL_SYM_CATS;
			break;
		case CIL_CLASS:
			sym_index = CIL_SYM_CLASSES;
			break;
		default:
			rc = SEPOL_ERR;
			goto resolve_call2_out;
		}

		if (sym_index != CIL_SYM_UNKNOWN) {
			rc = cil_resolve_name(db, current, ((struct cil_args*)item->data)->arg_str, sym_index, ((struct cil_args*)item->data)->flavor, call, &(((struct cil_args*)item->data)->arg));
			if (rc != SEPOL_OK) {
				printf("Failed to resolve argument, rc: %d\n", rc);
				goto resolve_call2_out;
			}
		}
	}

	return SEPOL_OK;

resolve_call2_out:
	return rc;
}

int cil_resolve_name_call_args(struct cil_call *call, char *name, uint32_t flavor, struct cil_tree_node **node)
{
	struct cil_list_item *item = NULL;
	int rc = SEPOL_ERR;

	if (call == NULL || name == NULL) {
		goto resolve_name_call_args_out;
	}

	if (call->args == NULL) {
		goto resolve_name_call_args_out;
	}

	item = call->args->head;

	while(item != NULL) {
		if (((struct cil_args*)item->data)->flavor == flavor) {
			if (!strcmp(name, ((struct cil_args*)item->data)->param_str)) {
				*node = ((struct cil_args*)item->data)->arg;
				rc = SEPOL_OK;
				goto resolve_name_call_args_out;
			}
		}
		item = item->next;
	}

	return SEPOL_ERR;

resolve_name_call_args_out:
	return rc;
}

int cil_resolve_expr_stack(struct cil_db *db, struct cil_tree_node *expr_stack, struct cil_tree_node *parent, struct cil_call *call)
{
	int rc = SEPOL_ERR;
	struct cil_tree_node *curr_expr = expr_stack;
	struct cil_tree_node *res_node = NULL;
	

	while (curr_expr != NULL) {
		uint32_t flavor = ((struct cil_conditional*)curr_expr->data)->flavor;
		int sym_index =  CIL_SYM_UNKNOWN;

		if (flavor == CIL_BOOL) {
			sym_index = CIL_SYM_BOOLS;
		} else if (flavor == CIL_TUNABLE) {
			sym_index = CIL_SYM_TUNABLES;
		} else if (flavor == CIL_TYPE) {
			sym_index = CIL_SYM_TYPES;
		} else if (flavor == CIL_ROLE) {
			sym_index = CIL_SYM_ROLES;
		} else if (flavor == CIL_USER) {
			sym_index = CIL_SYM_USERS;
		} else {
			curr_expr = curr_expr->cl_head;
			continue;
		}
	
		if (((struct cil_conditional*)curr_expr->data)->str == NULL) {
			printf("Invalid expression\n");
			rc = SEPOL_ERR;
			goto resolve_expr_stack_out;
		}
		
		rc = cil_resolve_name(db, parent, ((struct cil_conditional*)curr_expr->data)->str, sym_index, flavor, call, &res_node);
		if (rc != SEPOL_OK) {
			printf("Name resolution failed for %s\n", ((struct cil_conditional*)curr_expr->data)->str);
			goto resolve_expr_stack_out;
		}
		((struct cil_conditional*)curr_expr->data)->data = res_node->data;

		curr_expr = curr_expr->cl_head;
	}
	return SEPOL_OK;

resolve_expr_stack_out:
	return rc;
}

int cil_resolve_boolif(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call)
{
	int rc = SEPOL_ERR;
	struct cil_booleanif *bif = (struct cil_booleanif*)current->data;
	
	rc = cil_resolve_expr_stack(db, bif->expr_stack, current, call);
	if (rc != SEPOL_OK) {
		printf("Failed to resolve booleanif (line %d)\n", current->line);
		goto resolve_boolif_out;
	}

	return SEPOL_OK;

resolve_boolif_out:
	return rc;
}

int cil_evaluate_expr_stack(struct cil_tree_node *stack, uint16_t *result)
{
	struct cil_conditional *cond = NULL;
	struct cil_tree_node *new = NULL;
	struct cil_tree_node *oper1 = NULL;
	struct cil_tree_node *oper2 = NULL;
	uint16_t value1 = CIL_FALSE;
	uint16_t value2 = CIL_FALSE;
	uint16_t new_value = CIL_FALSE;
	int rc = SEPOL_ERR;

	while (stack != NULL) {
		cond = (struct cil_conditional*)stack->data;
		if ((cond->flavor == CIL_AND) || (cond->flavor == CIL_OR) || (cond->flavor == CIL_XOR) || (cond->flavor == CIL_NOT) || (cond->flavor == CIL_EQ) || (cond->flavor == CIL_NEQ)) {

			cil_tree_node_init(&new);

			oper1 = stack->parent;
			if (cond->flavor != CIL_NOT) {
				oper2 = stack->parent->parent;
			}

			if (oper1->flavor == CIL_COND && ((struct cil_conditional*)oper1->data)->flavor == CIL_TUNABLE) {
				value1 = ((struct cil_bool *)((struct cil_conditional*)oper1->data)->data)->value;
			} else {
				value1 = *(uint16_t*)oper1->data;
			}

			if (cond->flavor != CIL_NOT) {
				if (oper2->flavor == CIL_COND && ((struct cil_conditional*)oper2->data)->flavor == CIL_TUNABLE) {
					value2 = ((struct cil_bool *)((struct cil_conditional*)oper2->data)->data)->value;
				} else {
					value2 = *(uint16_t*)oper2->data;
				}
			}

			if (cond->flavor == CIL_NOT) {
					new_value = !value1;
			} else if (cond->flavor == CIL_AND) {
				new_value = (value1 && value2);
			} else if (cond->flavor == CIL_OR) {
				new_value = (value1 || value2);
			} else if (cond->flavor == CIL_XOR) {
				new_value = (value1 ^ value2);
			} else if (cond->flavor == CIL_EQ) {
				new_value = (value1 == value2);
			} else if (cond->flavor == CIL_NEQ) {
				new_value = (value1 != value2);
			}

			new->data = &new_value;

			new->flavor = CIL_INT;
			new->cl_head = stack->cl_head;
			if (cond->flavor != CIL_NOT) {
				new->parent = stack->parent->parent->parent;
			} else {
				new->parent = stack->parent->parent;
			}

			if (cond->flavor != CIL_NOT) {
				if (stack->parent->parent->parent != NULL) {
					stack->parent->parent->parent->cl_head = new;
				}
			} else {
				if (stack->parent->parent != NULL) {
					stack->parent->parent->cl_head = new;
				}
			}

			if (stack->cl_head != NULL) {
				stack->cl_head->parent = new;
			}

			if (stack->parent->parent != NULL) {
				cil_tree_node_destroy(&stack->parent->parent);
			}

			cil_tree_node_destroy(&stack->parent);
			cil_tree_node_destroy(&stack);

			if (new->cl_head == NULL) {
				if (new->parent == NULL) {
					*result = *(uint16_t*)new->data;
				} else {
					rc = SEPOL_ERR;
					goto evaluate_expr_stack_out;
				}
			}

			stack = new;
		}
		stack = stack->cl_head;
	}

	return SEPOL_OK;

evaluate_expr_stack_out:
	return rc;
}

int cil_resolve_tunif(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call)
{
	int rc = SEPOL_ERR;
	struct cil_tunableif *tif = (struct cil_tunableif*)current->data;
	uint16_t result = CIL_FALSE;

	rc = cil_resolve_expr_stack(db, tif->expr_stack, current, call);
	if (rc != SEPOL_OK) {
		goto resolve_tunif_out;
	}

	rc = cil_evaluate_expr_stack(tif->expr_stack, &result);
	if (rc != SEPOL_OK) {
		printf("Failed to evaluate expr stack\n");
		goto resolve_tunif_out;
	}

	if (result == CIL_TRUE) {
		rc = cil_copy_ast(db, current, current->parent);
		if (rc != SEPOL_OK) {
			goto resolve_tunif_out;
		}
	}

	cil_tree_subtree_destroy(current->cl_head);
	current->cl_head = NULL;

	return SEPOL_OK;

resolve_tunif_out:
	return rc;
}


int __cil_resolve_ast_node(struct cil_tree_node *node, int pass, struct cil_db *db, struct cil_call *call)
{
	int rc = SEPOL_OK;

	if (node == NULL || db == NULL) {
		goto resolve_ast_node_out;
	}

	switch (pass) {
	case 1:
		if (node->flavor == CIL_TUNABLEIF) {
			rc = cil_resolve_tunif(db, node, call);
		}
		break;
	case 2:
		if (node->flavor == CIL_CALL) {
			rc = cil_resolve_call1(db, node, call);
		}
		break;
	case 3:
		if (node->flavor == CIL_CALL) {
			rc = cil_resolve_call2(db, node, call);
		}
		break;
	case 4:
		switch (node->flavor) {
		case CIL_CATORDER:
			rc = cil_resolve_catorder(db, node, call);
			break;
		case CIL_DOMINANCE:
			rc = cil_resolve_dominance(db, node, call);
			break;
		case CIL_CLASS:
			rc = cil_reset_class(db, node, call);
			break;
		case CIL_SENS:
			rc = cil_reset_sens(db, node, call);
			break;
		case CIL_BOOLEANIF:
			rc = cil_resolve_boolif(db, node, call);
			break;
		}
		break;
	case 5:
		switch (node->flavor) {
		case CIL_CATSET:
			rc = cil_resolve_catset(db, node, (struct cil_catset*)node->data, call);
			break;
		}
		break;
	case 6:
		switch (node->flavor) {
		case CIL_SENSCAT:
			rc = cil_resolve_senscat(db, node, call);
			break;
		case CIL_CLASSCOMMON:
			rc = cil_resolve_classcommon(db, node, call);
			break;
		}
		break;
	case 7:
		switch (node->flavor) {
		case CIL_TYPE_ATTR:
			rc = cil_resolve_typeattr(db, node, call);
			break;
		case CIL_TYPEALIAS:
			rc = cil_resolve_typealias(db, node, call);
			break;
		case CIL_TYPEBOUNDS:
			rc = cil_resolve_typebounds(db, node, call);
			break;
		case CIL_TYPEPERMISSIVE:
			rc = cil_resolve_typepermissive(db, node, call);
			break;
		case CIL_FILETRANSITION:
			rc = cil_resolve_filetransition(db, node, call);
			break;
		case CIL_AVRULE:
			rc = cil_resolve_avrule(db, node, call);
			break;
		case CIL_TYPE_RULE:
			rc = cil_resolve_type_rule(db, node, call);
			break;
		case CIL_USERROLE:
			rc = cil_resolve_userrole(db, node, call);
			break;
		case CIL_ROLETYPE:
			rc = cil_resolve_roletype(db, node, call);
			break;
		case CIL_ROLETRANS:
			rc = cil_resolve_roletrans(db, node, call);
			break;
		case CIL_ROLEALLOW:
			rc = cil_resolve_roleallow(db, node, call);
			break;
		case CIL_ROLEDOMINANCE:
			rc = cil_resolve_roleallow(db, node, call);
			break;
		case CIL_SENSALIAS:
			rc = cil_resolve_sensalias(db, node, call);
			break;
		case CIL_CATALIAS:
			rc = cil_resolve_catalias(db, node, call);
			break;
		case CIL_LEVEL:
			rc = cil_resolve_level(db, node, (struct cil_level*)node->data, call);
			break;
		case CIL_CONSTRAIN:
			rc = cil_resolve_constrain(db, node, call);
			break;
		case CIL_MLSCONSTRAIN:
			rc = cil_resolve_constrain(db, node, call);
			break;
		case CIL_CONTEXT:
			rc = cil_resolve_context(db, node, (struct cil_context*)node->data, call);
			break;
		case CIL_FILECON:
			rc = cil_resolve_filecon(db, node, call);
			break;
		case CIL_PORTCON:
			rc = cil_resolve_portcon(db, node, call);
			break;
		case CIL_NODECON:
			rc = cil_resolve_nodecon(db, node, call);
			break;
		case CIL_GENFSCON:
			rc = cil_resolve_genfscon(db, node, call);
			break;
		case CIL_NETIFCON:
			rc = cil_resolve_netifcon(db, node, call);
			break;
		case CIL_FSUSE:
			rc = cil_resolve_fsuse(db, node, call);
			break;
		case CIL_SIDCONTEXT:
			rc = cil_resolve_sidcontext(db, node, call);
			break;
		default:
			break;
		}
		break;
	case 8:
		switch (node->flavor) {
		case CIL_NETIFCON: {
			struct cil_sort *sort = db->netifcon;
			uint32_t count = sort->count;
			uint32_t i = sort->index;
			if (sort->array == NULL) {
				sort->array = cil_malloc(sizeof(struct cil_netifcon*)*count);
			}
			sort->array[i] = node->data;
			sort->index++;
			break;
		}
		case CIL_FSUSE: {
			struct cil_sort *sort = db->fsuse;
			uint32_t count = sort->count;
			uint32_t i = sort->index;
			if (sort->array == NULL) {
				sort->array = cil_malloc(sizeof(struct cil_fsuse*)*count);
			}
			sort->array[i] = node->data;
			sort->index++;
			break;
		}
		case CIL_GENFSCON: {
			struct cil_sort *sort = db->genfscon;
			uint32_t count = sort->count;
			uint32_t i = sort->index;
			if (sort->array == NULL) {
				sort->array = cil_malloc(sizeof(struct cil_genfscon*)*count);
			}
			sort->array[i] = node->data;
			sort->index++;
			break;
		}
		case CIL_FILECON: {
			struct cil_sort *sort = db->filecon;
			uint32_t count = sort->count;
			uint32_t i = sort->index;
			if (sort->array == NULL) {
				sort->array = cil_malloc(sizeof(struct cil_filecon*)*count);
			}
			sort->array[i] = node->data;
			sort->index++;
			break;
		}
		case CIL_NODECON: {
			struct cil_sort *sort = db->nodecon;
			uint32_t count = sort->count;
			uint32_t i = sort->index;
			if (sort->array == NULL) {
				sort->array = cil_malloc(sizeof(struct cil_nodecon*)*count);
			}
			sort->array[i] = node->data;
			sort->index++;
			break;
		}
		case CIL_PORTCON: {
			struct cil_sort *sort = db->portcon;
			uint32_t count = sort->count;
			uint32_t i = sort->index;
			if (sort->array == NULL) {
				sort->array = cil_malloc(sizeof(struct cil_portcon*)*count);
			}
			sort->array[i] = node->data;
			sort->index++;
			break;
		}
		default:
			break;
		}
	default:
		break;
	}

	return rc;

resolve_ast_node_out:
	return rc;
}

int __cil_resolve_ast_node_helper(struct cil_tree_node *node, __attribute__((unused)) uint32_t *finished, void **extra_args)
{
	int rc = SEPOL_ERR;
	int *pass = NULL;
	struct cil_db *db = NULL;
	struct cil_call *call = NULL;
	struct cil_tree_node *callstack = NULL;
	struct cil_tree_node *optstack = NULL;
	struct cil_macro *macro = NULL;
	int *changed = NULL;

	if (node == NULL || extra_args == NULL) {
		goto resolve_ast_node_helper_out;
	}

	db = extra_args[ARGS_RESOLVE_DB];
	pass = extra_args[ARGS_RESOLVE_PASS];
	changed = extra_args[ARGS_RESOLVE_CHANGED];
	callstack = extra_args[ARGS_RESOLVE_CALLS];
	optstack = extra_args[ARGS_RESOLVE_OPTIONALS];
	macro = extra_args[ARGS_RESOLVE_MACRO];

	if (callstack != NULL) {
		call = callstack->data;
	}
		
	if (optstack != NULL || macro != NULL) {
		if (node->flavor == CIL_TUNABLE || node->flavor == CIL_MACRO) {
			/* tuanbles and macros are not allowed in optionals or macros */
			printf("Node of flavor %i is not allowed in optionals or macros\n", node->flavor);
			goto resolve_ast_node_helper_out;
		}
	}

	/* don't resolve statements inside a macro, they're resolved when called */
	if (macro == NULL) {
		rc = __cil_resolve_ast_node(node, *pass, db, call);
		if (rc == SEPOL_ENOENT && optstack != NULL) {
			/* disable an optional if something failed to resolve */
			struct cil_optional *opt = (struct cil_optional *)optstack->data;
			opt->datum.state = CIL_STATE_DISABLING;
			/* let the resolve loop know something was changed */
			*changed = 1;
			rc = SEPOL_OK;
		} else {
			goto resolve_ast_node_helper_out;
		}
	} else {
		rc = SEPOL_OK;
	}

	if (node->flavor == CIL_CALL || node->flavor == CIL_OPTIONAL) {
		/* push this node onto a stack */
		struct cil_tree_node *new;
		rc = cil_tree_node_init(&new);
		if (rc != SEPOL_OK) {
			goto resolve_ast_node_helper_out;
		}

		new->data = node->data;
		new->flavor = node->flavor;

		if (node->flavor == CIL_CALL) {
			if (callstack != NULL) {
				callstack->parent = new;
				new->cl_head = callstack;
			}
			extra_args[ARGS_RESOLVE_CALLS] = new;
		} else if (node->flavor == CIL_OPTIONAL) {
			if (optstack != NULL) {
				optstack->parent = new;
				new->cl_head = optstack;
			}
			extra_args[ARGS_RESOLVE_OPTIONALS] = new;
		}
	} else if (node->flavor == CIL_MACRO) {
		/* set the macro parameter so future resolve know they're in a macro */
		extra_args[ARGS_RESOLVE_MACRO] = node;
	}
	
	return rc;

resolve_ast_node_helper_out:
	return rc;
}

int __cil_disable_children_helper(struct cil_tree_node *node, uint32_t *finished, __attribute__((unused)) void **extra_args)
{
	switch (node->flavor) {
	case CIL_OPTIONAL:
		if (((struct cil_optional *)node->data)->datum.state == CIL_STATE_DISABLED) {
			/* don't bother going into an optional that isn't enabled */
			*finished = CIL_TREE_SKIP_HEAD;
		} else {
			((struct cil_optional *)node->data)->datum.state = CIL_STATE_DISABLED;
		}
		break;
	case CIL_BLOCK:
		((struct cil_block *)node->data)->datum.state = CIL_STATE_DISABLED;
		break;
	case CIL_USER:
		((struct cil_user *)node->data)->datum.state = CIL_STATE_DISABLED;
		break;
	case CIL_ROLE:
		((struct cil_role *)node->data)->datum.state = CIL_STATE_DISABLED;
		break;
	case CIL_TYPE:
		((struct cil_type *)node->data)->datum.state = CIL_STATE_DISABLED;
		break;
	case CIL_TYPEALIAS:
		((struct cil_typealias *)node->data)->datum.state = CIL_STATE_DISABLED;
		break;
	case CIL_COMMON:
		((struct cil_common *)node->data)->datum.state = CIL_STATE_DISABLED;
		break;
	case CIL_CLASS:
		((struct cil_class *)node->data)->datum.state = CIL_STATE_DISABLED;
		break;
	case CIL_BOOL:
		((struct cil_bool *)node->data)->datum.state = CIL_STATE_DISABLED;
		break;
	case CIL_SENS:
		((struct cil_sens *)node->data)->datum.state = CIL_STATE_DISABLED;
		break;
	case CIL_CAT:
		((struct cil_cat *)node->data)->datum.state = CIL_STATE_DISABLED;
		break;
	case CIL_CATSET:
		((struct cil_catset *)node->data)->datum.state = CIL_STATE_DISABLED;
		break;
	case CIL_SID:
		((struct cil_sid *)node->data)->datum.state = CIL_STATE_DISABLED;
		break;
	case CIL_MACRO:
		/* TODO: how to handle macros that have already been copied??? */
		((struct cil_macro *)node->data)->datum.state = CIL_STATE_DISABLED;
		break;
	case CIL_CONTEXT:
		((struct cil_context *)node->data)->datum.state = CIL_STATE_DISABLED;
		break;
	case CIL_LEVEL:
		((struct cil_level *)node->data)->datum.state = CIL_STATE_DISABLED;
		break;
	case CIL_POLICYCAP:
		((struct cil_policycap *)node->data)->datum.state = CIL_STATE_DISABLED;
		break;
	case CIL_PERM:
		((struct cil_perm *)node->data)->datum.state = CIL_STATE_DISABLED;
		break;
	case CIL_CATALIAS:
		((struct cil_catalias *)node->data)->datum.state = CIL_STATE_DISABLED;
		break;
	case CIL_SENSALIAS:
		((struct cil_sensalias *)node->data)->datum.state = CIL_STATE_DISABLED;
		break;
	case CIL_TUNABLE: /*TODO not sure how to handle tunables??? */
		break;
	}

	return SEPOL_OK;
}

int __cil_resolve_ast_reverse_helper(struct cil_tree_node *current, void **extra_args)
{
	int rc = SEPOL_ERR;

	if (current == NULL ||  extra_args == NULL) {
		goto resolve_ast_reverse_helper_out;
	}

	if (current->flavor == CIL_CALL) {
		/* pop off the stack */
		struct cil_tree_node *callstack = extra_args[ARGS_RESOLVE_CALLS];
		extra_args[ARGS_RESOLVE_CALLS] = callstack->cl_head;
		if (callstack->cl_head) {
			callstack->cl_head->parent = NULL;
		}
		free(callstack);
	} else if (current->flavor == CIL_MACRO) {
		extra_args[ARGS_RESOLVE_MACRO] = NULL;
	} else if (current->flavor == CIL_OPTIONAL) {
		struct cil_tree_node *optstack;

		if (((struct cil_optional *)current->data)->datum.state == CIL_STATE_DISABLING) {
			/* go into the optional, removing everything that it added */
			rc = cil_tree_walk(current, __cil_disable_children_helper, NULL, NULL, NULL);
			if (rc != SEPOL_OK) {
				printf("Failed to disable optional children\n");
				goto resolve_ast_reverse_helper_out;
			}
			((struct cil_optional *)current->data)->datum.state = CIL_STATE_DISABLED;
		}
		
		/* pop off the stack */
		optstack = extra_args[ARGS_RESOLVE_OPTIONALS];
		extra_args[ARGS_RESOLVE_OPTIONALS] = optstack->cl_head;
		if (optstack->cl_head) {
			optstack->cl_head->parent = NULL;
		}
		free(optstack);
	}

	return SEPOL_OK;

resolve_ast_reverse_helper_out:
	return rc;
}

int cil_resolve_ast(struct cil_db *db, struct cil_tree_node *current)
{
	int rc = SEPOL_ERR;
	void **extra_args = NULL;
	int pass = 1;
	int changed = 0;

	if (db == NULL || current == NULL) {
		goto resolve_ast_out;
	}

	extra_args = cil_malloc(sizeof(*extra_args) * ARGS_RESOLVE_COUNT);
	extra_args[ARGS_RESOLVE_DB] = db;
	extra_args[ARGS_RESOLVE_PASS] = &pass;
	extra_args[ARGS_RESOLVE_CHANGED] = &changed;	
	extra_args[ARGS_RESOLVE_CALLS] = NULL;
	extra_args[ARGS_RESOLVE_OPTIONALS] = NULL;
	extra_args[ARGS_RESOLVE_MACRO] = NULL;
	
	for (pass = 1; pass <= 8; pass++) {
#ifdef DEBUG
		printf("---------- Pass %i ----------\n", pass);
#endif
		rc = cil_tree_walk(current, __cil_resolve_ast_node_helper, __cil_resolve_ast_reverse_helper, NULL, extra_args);
		if (rc != SEPOL_OK) {
			printf("Pass %i fo resolution failed\n", pass);
			goto resolve_ast_out;
		}

#ifdef DEBUG
		cil_tree_print(db->ast->root, 0);
#endif

		if (pass == 4) {
#ifdef DEBUG
			printf("----- Verify Catorder ------\n");
#endif
			rc = __cil_verify_order(db->catorder, current, CIL_CAT);
			if (rc != SEPOL_OK) {
				printf("Failed to verify categoryorder\n");
				goto resolve_ast_out;
			}
#ifdef DEBUG
			printf("----- Verify Dominance -----\n");
#endif
			rc = __cil_verify_order(db->dominance, current, CIL_SENS);
			if (rc != SEPOL_OK) {
				printf("Failed to verify dominance\n");
				goto resolve_ast_out;
			}
		}

		if (changed) {
#ifdef DEBUG
			printf("----- Redoing resolve passes -----\n");
#endif
			/* Need to re-resolve because an optional was disabled. We only
			 * need to reset to the thrid pass because things done in pass 1
			 * and 2 aren't allowed in optionals, and thus can't be disabled.
			 * Note: set pass to 2 because the pass++ will increment it to 3 */
			pass = 2;
			/* reset the global data */
			cil_list_destroy(&db->catorder, 0);
			cil_list_destroy(&db->dominance, 0);
		}

		/* reset the arguments */
		changed = 0;
		while (extra_args[ARGS_RESOLVE_CALLS] != NULL) {
			struct cil_list_item *curr = ((struct cil_list_item *)extra_args[ARGS_RESOLVE_CALLS]);
			struct cil_list_item *next = curr->next;
			free(curr);
			extra_args[ARGS_RESOLVE_CALLS] = next;
		}
		while (extra_args[ARGS_RESOLVE_OPTIONALS] != NULL) {
			struct cil_list_item *curr = ((struct cil_list_item *)extra_args[ARGS_RESOLVE_OPTIONALS]);
			struct cil_list_item *next = curr->next;
			free(curr);
			extra_args[ARGS_RESOLVE_OPTIONALS] = next;
		}
		extra_args[ARGS_RESOLVE_MACRO] = NULL;
	}

	return SEPOL_OK;

resolve_ast_out:
	return rc;
}

static int __cil_resolve_name_helper(struct cil_db *db, struct cil_tree_node *ast_node, char *name, uint32_t sym_index, struct cil_call *call, struct cil_tree_node **node)
{
	int rc = SEPOL_ERR;
	char* name_dup = cil_strdup(name);
	char *tok_current = strtok(name_dup, ".");
	char *tok_next = strtok(NULL, ".");
	symtab_t *symtab = NULL;
	struct cil_tree_node *tmp_node = NULL;

	if (ast_node->flavor == CIL_ROOT) {
		symtab = &(db->symtab[CIL_SYM_BLOCKS]);
	} else {
		if (call != NULL) {
			// check macro symtab
			symtab = &call->macro->symtab[CIL_SYM_BLOCKS];
			rc = cil_symtab_get_node(symtab, tok_current, node);
			if (rc == SEPOL_OK) {
				// if in macro, check call parent to verify successful copy to call
				rc = cil_get_parent_symtab(db, ast_node->parent, &symtab, CIL_SYM_BLOCKS);
				if (rc == SEPOL_OK) {
					rc = cil_symtab_get_node(symtab, tok_current, node);
					if (rc != SEPOL_OK) {
						printf("Failed to get node from parent symtab of call\n");
						goto resolve_name_helper_cleanup;
					}
				} else {
					printf("Failed to get symtab from call parent\n");
					goto resolve_name_helper_cleanup;
				}
			} else if (rc == SEPOL_ENOENT) {
				rc = cil_get_parent_symtab(db, call->macro->datum.node, &symtab, CIL_SYM_BLOCKS);
				if (rc != SEPOL_OK) {
					printf("Failed to get node from parent symtab of macro\n");
					goto resolve_name_helper_cleanup;
				} else {
					symtab = &(db->symtab[CIL_SYM_BLOCKS]);	
				}
			} else {
				goto resolve_name_helper_cleanup;
			}
				
		} else {
			rc = cil_get_parent_symtab(db, ast_node, &symtab, CIL_SYM_BLOCKS);
			if (rc != SEPOL_OK) {
				printf("Failed to get parent symtab, rc: %d\n", rc);
				goto resolve_name_helper_cleanup;
			}
		}
	}

	if (tok_next == NULL) {
		/*TODO: Should this set rc to SEPOL_ERR? */
		/* Cant this be done earlier */
		goto resolve_name_helper_cleanup;
	}

	while (tok_current != NULL) {
		if (tok_next != NULL) {
			rc = cil_symtab_get_node(symtab, tok_current, &tmp_node);
			if (rc != SEPOL_OK) {
				goto resolve_name_helper_cleanup;
			}
			symtab = &(((struct cil_block*)tmp_node->data)->symtab[CIL_SYM_BLOCKS]);
		} else {
			//printf("type key: %s\n", tok_current); 
			symtab = &(((struct cil_block*)tmp_node->data)->symtab[sym_index]);
			rc = cil_symtab_get_node(symtab, tok_current, &tmp_node);
			if (rc != SEPOL_OK) {
				printf("Failed to resolve name, current: %s\n", tok_current);
				goto resolve_name_helper_cleanup;
			}
		}
		tok_current = tok_next;
		tok_next = strtok(NULL, ".");
	}
	*node = tmp_node;
	free(name_dup);	

	return SEPOL_OK;

resolve_name_helper_cleanup:
	free(name_dup);
	return rc;
}

int cil_resolve_name(struct cil_db *db, struct cil_tree_node *ast_node, char *name, uint32_t sym_index, uint32_t flavor, struct cil_call *call, struct cil_tree_node **node)
{
	int rc = SEPOL_ERR;
	char *global_symtab_name = NULL;
	char first;

	if (db == NULL || ast_node == NULL || name == NULL) {
		printf("Invalid call to cil_resolve_name\n");
		goto resolve_name_out;
	}

	global_symtab_name = name;
	first = *name;

	if (first != '.') {
		if (strrchr(name, '.') == NULL) {
			symtab_t *symtab = NULL;
			if (call != NULL) {
				symtab = &call->macro->symtab[sym_index];
				rc = cil_symtab_get_node(symtab, name, node);
				if (rc == SEPOL_OK) {
					rc = cil_get_parent_symtab(db, ast_node->parent, &symtab, sym_index);
					if (rc == SEPOL_OK) {
						rc = cil_symtab_get_node(symtab, name, node);
						if (rc != SEPOL_OK) {
							printf("Failed to get node from parent symtab of call\n");
						}
						goto resolve_name_out;
					} else {
						printf("Failed to get parent symtab from call\n");
						goto resolve_name_out;
					}
						
				} else {
					rc = cil_resolve_name_call_args(call, name, flavor, node);
					if (rc == SEPOL_OK) {
						goto resolve_name_out;
					}

					rc = cil_get_parent_symtab(db, call->macro->datum.node, &symtab, sym_index);
					if (rc != SEPOL_OK) {
						goto resolve_name_out;
					}

					rc = cil_symtab_get_node(symtab, name, node);
					if (rc == SEPOL_OK) {
						goto resolve_name_out;
					}

					global_symtab_name = cil_malloc(strlen(name)+2);
					strcpy(global_symtab_name, ".");
					strncat(global_symtab_name, name, strlen(name));
				}
			} else {
				rc = cil_get_parent_symtab(db, ast_node, &symtab, sym_index);
				if (rc != SEPOL_OK) {
					printf("Failed to get parent symtab, rc: %d\n", rc);
					goto resolve_name_out;
				}
				rc = cil_symtab_get_node(symtab, name, node);
				if (rc != SEPOL_OK) {
					global_symtab_name = cil_malloc(strlen(name)+2);
					strcpy(global_symtab_name, ".");
					strncat(global_symtab_name, name, strlen(name));
				}
			}
		} else {
			rc = __cil_resolve_name_helper(db, ast_node, name, sym_index, call, node);
			if (rc != SEPOL_OK) {
				global_symtab_name = cil_malloc(strlen(name)+2);
				strcpy(global_symtab_name, ".");
				strncat(global_symtab_name, name, strlen(name));
			}
		}
	}
		
	first = *global_symtab_name;

	if (first == '.') {
		if (strrchr(global_symtab_name, '.') == global_symtab_name) { //Only one dot in name, check global symtabs
			rc = cil_symtab_get_node(&db->symtab[sym_index], global_symtab_name+1, node);
			if (rc != SEPOL_OK) {
				free(global_symtab_name);
				goto resolve_name_out;
			}
		} else {
			rc = __cil_resolve_name_helper(db, db->ast->root, global_symtab_name, sym_index, call, node);
			if (rc != SEPOL_OK) {
				free(global_symtab_name);
				goto resolve_name_out;
			}
		}
	}

	if (global_symtab_name != name) {
		free(global_symtab_name);
	}

	return SEPOL_OK;

resolve_name_out:
	return rc;
}
