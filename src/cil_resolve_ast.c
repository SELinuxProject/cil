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

#include <sepol/policydb/conditional.h>

#include "cil_internal.h"
#include "cil_log.h"
#include "cil_mem.h"
#include "cil_tree.h"
#include "cil_list.h"
#include "cil_build_ast.h"
#include "cil_resolve_ast.h"
#include "cil_copy_ast.h"
#include "cil_verify.h"

struct cil_args_resolve {
	struct cil_db *db;
	enum cil_pass pass;
	uint32_t *changed;
	struct cil_tree_node *callstack;
	struct cil_tree_node *optstack;
	struct cil_tree_node *macro;
};

static int __cil_resolve_perm_list(void *class, struct cil_list *perm_list_str, struct cil_list *res_list_perms)
{
	struct cil_tree_node *perm_node = NULL;
	struct cil_list_item *perm = perm_list_str->head;
	struct cil_list_item *list_item = NULL;
	struct cil_list_item *list_tail = NULL;
	struct cil_tree_node *class_node = NULL;
	symtab_t *perms_symtab = NULL;
	int rc = SEPOL_ERR;

	class_node = ((struct cil_symtab_datum*)class)->node;
	if (class_node->flavor == CIL_CLASS) {
		perms_symtab = &((struct cil_class*)class)->perms;
	} else {
		perms_symtab = &((struct cil_classmap*)class)->perms;
	}

	while (perm != NULL) {
		rc = cil_symtab_get_node(perms_symtab, (char*)perm->data, &perm_node);
		if (rc == SEPOL_ENOENT) {
			if (class_node->flavor == CIL_CLASS && ((struct cil_class*)class)->common != NULL) {
				symtab_t *com_perms_symtab = &((struct cil_class*)class)->common->perms;
				rc = cil_symtab_get_node(com_perms_symtab, (char*)perm->data, &perm_node);
				if (rc != SEPOL_OK) {
					cil_log(CIL_ERR, "Failed to find perm in class or common symtabs\n");
					goto exit;
				}
			} else {
				cil_log(CIL_ERR, "Failed to find perm '%s' in %s symtab\n", (char*)perm->data, cil_node_to_string(class_node));
				goto exit;
			}
		} else if (rc != SEPOL_OK) {
			goto exit;
		}

		cil_list_item_init(&list_item);
		list_item->flavor = CIL_PERM;
		list_item->data = perm_node->data;
		if (res_list_perms->head == NULL) {
			res_list_perms->head = list_item;
		} else {
			list_tail->next = list_item;
		}
		list_tail = list_item;

		perm = perm->next;
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_resolve_classpermset(struct cil_tree_node *current, struct cil_classpermset *cps, void *extra_args)
{
	struct cil_tree_node *class_node = NULL;
	struct cil_tree_node *permset_node = NULL;
	int rc = SEPOL_ERR;

	rc = cil_resolve_name(current, cps->class_str, CIL_SYM_CLASSES, extra_args, &class_node);
	if (rc != SEPOL_OK) {
		goto resolve_classpermset_out;
	}

	cps->class = class_node->data;
	cps->flavor = class_node->flavor;

	/* Reset for re-resolve */
	if (cps->perms != NULL) {
		cil_list_destroy(&cps->perms, 0);
	}

	if (cps->permset_str != NULL) {
		rc = cil_resolve_name(current, cps->permset_str, CIL_SYM_PERMSETS, extra_args, &permset_node);
		if (rc != SEPOL_OK) {
			goto resolve_classpermset_out;
		}
		cps->permset = (struct cil_permset*)permset_node->data;
	}

	cil_list_init(&cps->perms);

	rc = __cil_resolve_perm_list(cps->class, cps->permset->perms_list_str, cps->perms);
	if (rc != SEPOL_OK) {
		goto resolve_classpermset_out;
	}

	return SEPOL_OK;

resolve_classpermset_out:
	return rc;
}

int cil_resolve_avrule(struct cil_tree_node *current, void *extra_args)
{
	struct cil_args_resolve *args = extra_args;
	struct cil_db *db = NULL;

	struct cil_avrule *rule = (struct cil_avrule*)current->data;
	struct cil_tree_node *src_node = NULL;
	struct cil_tree_node *tgt_node = NULL;
	struct cil_tree_node *cps_node = NULL;
	int rc = SEPOL_ERR;

	if (args != NULL) {
		db = args->db;
	}

	rc = cil_resolve_name(current, rule->src_str, CIL_SYM_TYPES, args, &src_node);
	if (rc != SEPOL_OK) {
		goto exit;
	}
	rule->src = src_node->data;

	if (!strcmp(rule->tgt_str, CIL_KEY_SELF)) {
		rule->tgt = db->selftype;
	} else {
		rc = cil_resolve_name(current, rule->tgt_str, CIL_SYM_TYPES, args, &tgt_node);
		if (rc != SEPOL_OK) {
			goto exit;
		}
		rule->tgt = tgt_node->data;
	}

	if (rule->classpermset_str != NULL) {
		rc = cil_resolve_name(current, rule->classpermset_str, CIL_SYM_CLASSPERMSETS, args, &cps_node);
		if (rc != SEPOL_OK) {
			goto exit;
		}
		rule->classpermset = (struct cil_classpermset*)cps_node->data;

		/* This could still be an anonymous classpermset even if classpermset_str is set, if classpermset_str is a param_str*/
		if (rule->classpermset->datum.name == NULL) {
			rc = cil_resolve_classpermset(current, rule->classpermset, args);
			if (rc != SEPOL_OK) {
				goto exit;
			}
		}
	} else if (rule->classpermset != NULL) {
		rc = cil_resolve_classpermset(current, rule->classpermset, args);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_resolve_type_rule(struct cil_tree_node *current, void *extra_args)
{
	struct cil_type_rule *rule = (struct cil_type_rule*)current->data;
	struct cil_tree_node *src_node = NULL;
	struct cil_tree_node *tgt_node = NULL;
	struct cil_tree_node *obj_node = NULL;
	struct cil_tree_node *result_node = NULL;
	int rc = SEPOL_ERR;

	rc = cil_resolve_name(current, rule->src_str, CIL_SYM_TYPES, extra_args, &src_node);
	if (rc != SEPOL_OK) {
		goto exit;
	}
	rule->src = src_node->data;

	rc = cil_resolve_name(current, rule->tgt_str, CIL_SYM_TYPES, extra_args, &tgt_node);
	if (rc != SEPOL_OK) {
		goto exit;
	}
	rule->tgt = tgt_node->data;

	rc = cil_resolve_name(current, rule->obj_str, CIL_SYM_CLASSES, extra_args, &obj_node);
	if (rc != SEPOL_OK) {
		goto exit;
	}
	rule->obj = (struct cil_class*)(obj_node->data);

	rc = cil_resolve_name(current, rule->result_str, CIL_SYM_TYPES, extra_args, &result_node);
	if (rc != SEPOL_OK) {
		goto exit;
	}
	if (result_node->flavor != CIL_TYPE && result_node->flavor != CIL_TYPEALIAS) {
		cil_log(CIL_ERR, "Type rule result must be a type or type alias\n");
		rc = SEPOL_ERR;
		goto exit;
	}
	rule->result = result_node->data;

	return SEPOL_OK;

exit:
	return rc;
}

int cil_resolve_list(struct cil_list *str_list, struct cil_list *res_list, struct cil_tree_node *current, enum cil_sym_index sym_index, void *extra_args)
{
	int rc = SEPOL_ERR;
	struct cil_list_item *curr_str = NULL;
	struct cil_tree_node *res_node = NULL;
	struct cil_list_item *new_item = NULL;

	if (str_list == NULL || res_list == NULL || current == NULL) {
		cil_log(CIL_ERR, "Invalid call to cil_resolve_list\n");
		goto exit;
	}

	for (curr_str = str_list->head; curr_str != NULL; curr_str = curr_str->next) {
		rc = cil_resolve_name(current, (char*)curr_str->data, sym_index, extra_args, &res_node);
		if (rc != SEPOL_OK) {
			goto exit;
		}

		cil_list_item_init(&new_item);
		new_item->data = res_node->data;
		new_item->flavor = res_node->flavor;

		cil_list_append_item(res_list, new_item);
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_resolve_typeattributeset(struct cil_tree_node *current, void *extra_args)
{
	struct cil_typeattributeset *attrtypes = (struct cil_typeattributeset*)current->data;
	struct cil_tree_node *attr_node = NULL;
	struct cil_typeattribute *attr = NULL;
	struct cil_list_item *item = NULL;
	int rc = SEPOL_ERR;

	rc = cil_resolve_name(current, attrtypes->attr_str, CIL_SYM_TYPES, extra_args, &attr_node);
	if (rc != SEPOL_OK) {
		goto exit;
	}
	if (attr_node->flavor != CIL_TYPEATTRIBUTE) {
		rc = SEPOL_ERR;
		cil_log(CIL_ERR, "Attribute type not an attribute\n");
		goto exit;
	}
	attr = attr_node->data;

	rc = cil_resolve_expr_stack(attrtypes->expr_stack, current, extra_args);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	if (attr->expr_stack_list == NULL) {
		cil_list_init(&attr->expr_stack_list);
	}

	cil_list_item_init(&item);
	item->data = attrtypes->expr_stack;
	item->flavor = CIL_LIST;

	rc = cil_list_append_item(attr->expr_stack_list, item);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	rc = SEPOL_OK;
exit:
	return rc;
}

int cil_resolve_typealias(struct cil_tree_node *current, void *extra_args)
{
	struct cil_typealias *alias = (struct cil_typealias*)current->data;
	struct cil_tree_node *type_node = NULL;
	int rc = SEPOL_ERR;

	rc = cil_resolve_name(current, alias->type_str, CIL_SYM_TYPES, extra_args, &type_node);
	if (rc != SEPOL_OK) {
		goto exit;
	}
	if (type_node->flavor != CIL_TYPE && type_node->flavor != CIL_TYPEALIAS) {
		cil_log(CIL_ERR, "Typealias must resolve to a type or type alias\n");
		rc = SEPOL_ERR;
		goto exit;
	}
	alias->type = type_node->data;

	return SEPOL_OK;

exit:
	return rc;
}

int cil_resolve_typealias_to_type(struct cil_tree_node *current)
{
	int rc = SEPOL_ERR;
	int steps = 0;
	int limit = 2;
	struct cil_typealias *a1 = current->data;
	struct cil_typealias *a2 = current->data;
	struct cil_tree_node *a1_node = NULL;
	enum cil_flavor flavor;

	a1_node = a1->datum.node;
	flavor = a1_node->flavor;

	while (1) {
		if (flavor == CIL_TYPE) {
			break;
		}
		a1 = a1->type;
		a1_node = a1->datum.node;
		flavor = a1_node->flavor;

		steps += 1;

		if (a1 == a2) {
			cil_log(CIL_ERR, "Circular typealias found: %s\n", a1->datum.name);
			rc = SEPOL_ERR;
			goto exit;
		}

		if (steps == limit) {
			steps = 0;
			limit *= 2;
			a2 = a1;
		}
	}

	a2 = current->data;
	a2->type = (struct cil_type *)a1;

	rc = SEPOL_OK;
exit:
	return rc;
}

int cil_resolve_typebounds(struct cil_tree_node *current, void *extra_args)
{
	struct cil_typebounds *typebnds = (struct cil_typebounds*)current->data;
	struct cil_tree_node *type_node = NULL;
	struct cil_type *type = NULL;
	struct cil_tree_node *bounds_node = NULL;
	int rc = SEPOL_ERR;

	rc = cil_resolve_name(current, typebnds->type_str, CIL_SYM_TYPES, extra_args, &type_node);
	if (rc != SEPOL_OK) {
		goto exit;
	}
	if (type_node->flavor != CIL_TYPE && type_node->flavor != CIL_TYPEALIAS) {
		cil_log(CIL_ERR, "Typebounds must be a type or type alias\n");
		rc = SEPOL_ERR;
		goto exit;
	}
	
	rc = cil_resolve_name(current, typebnds->bounds_str, CIL_SYM_TYPES, extra_args, &bounds_node);
	if (rc != SEPOL_OK) {
		goto exit;
	}
	if (bounds_node->flavor != CIL_TYPE && bounds_node->flavor != CIL_TYPEALIAS) {
		cil_log(CIL_ERR, "Typebounds must be a type or type alias\n");
		rc = SEPOL_ERR;
		goto exit;
	}

	type = type_node->data;
	if (type->bounds != NULL) {
		cil_log(CIL_ERR, "Type cannot bind more than one type\n");
		rc = SEPOL_ERR;
		goto exit;
	}

	type->bounds = bounds_node->data;

	return SEPOL_OK;

exit:
	return rc;
}

int cil_resolve_typepermissive(struct cil_tree_node *current, void *extra_args)
{
	struct cil_typepermissive *typeperm = (struct cil_typepermissive*)current->data;
	struct cil_tree_node *type_node = NULL;
	int rc = SEPOL_ERR;

	rc = cil_resolve_name(current, typeperm->type_str, CIL_SYM_TYPES, extra_args, &type_node);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	if (type_node->flavor != CIL_TYPE && type_node->flavor != CIL_TYPEALIAS) {
		cil_log(CIL_ERR, "Typepermissive must be a type or type alias\n");
		rc = SEPOL_ERR;
		goto exit;
	}

	typeperm->type = type_node->data;

	return SEPOL_OK;

exit:
	return rc;
}

int cil_resolve_filetransition(struct cil_tree_node *current, void *extra_args)
{
	struct cil_filetransition *filetrans = (struct cil_filetransition*)current->data;
	struct cil_tree_node *src_node = NULL;
	struct cil_tree_node *exec_node = NULL;
	struct cil_tree_node *proc_node = NULL;
	struct cil_tree_node *dest_node = NULL;
	int rc = SEPOL_ERR;

	rc = cil_resolve_name(current, filetrans->src_str, CIL_SYM_TYPES, extra_args, &src_node);
	if (rc != SEPOL_OK) {
		goto exit;
	}
	filetrans->src = src_node->data;

	rc = cil_resolve_name(current, filetrans->exec_str, CIL_SYM_TYPES, extra_args, &exec_node);
	if (rc != SEPOL_OK) {
		goto exit;
	}
	filetrans->exec = exec_node->data;

	rc = cil_resolve_name(current, filetrans->proc_str, CIL_SYM_CLASSES, extra_args, &proc_node);
	if (rc != SEPOL_OK) {
		goto exit;
	}
	filetrans->proc = proc_node->data;

	rc = cil_resolve_name(current, filetrans->dest_str, CIL_SYM_TYPES, extra_args, &dest_node);
	if (rc != SEPOL_OK) {
		goto exit;
	}
	if (dest_node->flavor != CIL_TYPE && dest_node->flavor != CIL_TYPEALIAS) {
		cil_log(CIL_ERR, "File transition result is not a type or type alias\n");
		rc = SEPOL_ERR;
		goto exit;
	}
	filetrans->dest = dest_node->data;

	return SEPOL_OK;

exit:
	return rc;
}

int cil_resolve_rangetransition(struct cil_tree_node *current, void *extra_args)
{
	struct cil_rangetransition *rangetrans = (struct cil_rangetransition*)current->data;
	struct cil_tree_node *src_node = NULL;
	struct cil_tree_node *exec_node = NULL;
	struct cil_tree_node *obj_node = NULL;
	struct cil_tree_node *range_node = NULL;
	int rc = SEPOL_ERR;

	rc = cil_resolve_name(current, rangetrans->src_str, CIL_SYM_TYPES, extra_args, &src_node);
	if (rc != SEPOL_OK) {
		goto exit;
	}
	rangetrans->src = src_node->data;

	rc = cil_resolve_name(current, rangetrans->exec_str, CIL_SYM_TYPES, extra_args, &exec_node);
	if (rc != SEPOL_OK) {
		goto exit;
	}
	rangetrans->exec = exec_node->data;

	rc = cil_resolve_name(current, rangetrans->obj_str, CIL_SYM_CLASSES, extra_args, &obj_node);
	if (rc != SEPOL_OK) {
		goto exit;
	}
	rangetrans->obj = (struct cil_class*)obj_node->data;

	if (rangetrans->range_str != NULL) {
		rc = cil_resolve_name(current, rangetrans->range_str, CIL_SYM_LEVELRANGES, extra_args, &range_node);
		if (rc != SEPOL_OK) {
			goto exit;
		}
		rangetrans->range = (struct cil_levelrange*)range_node->data;

		/* This could still be an anonymous levelrange even if range_str is set, if range_str is a param_str*/
		if (rangetrans->range->datum.name == NULL) {
			rc = cil_resolve_levelrange(current, rangetrans->range, extra_args);
			if (rc != SEPOL_OK) {
				goto exit;
			}
		}
	} else {
		rc = cil_resolve_levelrange(current, rangetrans->range, extra_args);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_resolve_classcommon(struct cil_tree_node *current, void *extra_args)
{
	struct cil_classcommon *clscom = (struct cil_classcommon*)current->data;
	struct cil_tree_node *class_node = NULL;
	struct cil_tree_node *common_node = NULL;
	int rc = SEPOL_ERR;

	rc = cil_resolve_name(current, clscom->class_str, CIL_SYM_CLASSES, extra_args, &class_node);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	rc = cil_resolve_name(current, clscom->common_str, CIL_SYM_COMMONS, extra_args, &common_node);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	if (((struct cil_class*)class_node->data)->common != NULL) {
		cil_log(CIL_ERR, "class cannot be associeated with more than one common\n");
		rc = SEPOL_ERR;
		goto exit;
	}

	((struct cil_class*)class_node->data)->common = common_node->data;

	return SEPOL_OK;

exit:
	return rc;
}

int cil_resolve_classmapping(struct cil_tree_node *current, void *extra_args)
{
	struct cil_classmapping *mapping = (struct cil_classmapping*)current->data;
	struct cil_classmap *map = NULL;
	struct cil_classmap_perm *cmp = NULL;
	struct cil_tree_node *tmp = NULL;
	struct cil_list_item *curr_cps = NULL;
	struct cil_list_item *new_item = NULL;
	int rc = SEPOL_ERR;

	rc = cil_resolve_name(current, mapping->classmap_str, CIL_SYM_CLASSES, extra_args, &tmp);
	if (rc != SEPOL_OK) {
		goto resolve_classmapping_out;
	}
	map = tmp->data;

	rc = cil_symtab_get_node(&map->perms, mapping->classmap_perm_str, &tmp);
	if (rc != SEPOL_OK) {
		goto resolve_classmapping_out;
	}
	cmp = tmp->data;

	curr_cps = mapping->classpermsets_str->head;

	while (curr_cps != NULL) {
		if (cmp->classperms == NULL) {
			cil_list_init(&cmp->classperms);
		}

		cil_list_item_init(&new_item);
		new_item->flavor = CIL_CLASSPERMSET;

		if (curr_cps->flavor == CIL_AST_STR) {
			rc = cil_resolve_name(current, (char*)curr_cps->data, CIL_SYM_CLASSPERMSETS, extra_args, &tmp);
			if (rc != SEPOL_OK) {
				goto resolve_classmapping_out;
			}

			/* This could still be an anonymous classpermset even if the flavor is CIL_AST_STR, if it is a param_str*/
			if (((struct cil_classpermset*)tmp->data)->datum.name == NULL) {
				rc = cil_resolve_classpermset(current, (struct cil_classpermset*)tmp->data, extra_args);
				if (rc != SEPOL_OK) {
					goto resolve_classmapping_out;
				}
			}

			new_item->data = tmp->data;

		} else if (curr_cps->flavor == CIL_CLASSPERMSET) {
			rc = cil_resolve_classpermset(current, (struct cil_classpermset*)curr_cps->data, extra_args);
			if (rc != SEPOL_OK) {
				goto resolve_classmapping_out;
			}
			new_item->data = curr_cps->data;
		}

		cil_list_prepend_item(cmp->classperms, new_item);

		curr_cps = curr_cps->next;
	}

	return SEPOL_OK;

resolve_classmapping_out:
	return rc;
}

int cil_reset_class(struct cil_tree_node *current, __attribute__((unused)) void *extra_args)
{
	struct cil_class *class = (struct cil_class *)current->data;

	/* during a re-resolve, we need to reset the common, so a classcommon
	 * statement isn't seen as a duplicate */
	class->common = NULL;

	return SEPOL_OK;
}

int cil_reset_classmap_perm(struct cil_tree_node *current, __attribute__((unused)) void *extra_args)
{
	struct cil_classmap_perm *cmp = current->data;

	/* during a re-resolve the classperms list needs to be reset to avoid
	   duplicate entries
	*/

	cil_list_destroy(&cmp->classperms, 0);

	return SEPOL_OK;
}

int cil_reset_sens(struct cil_tree_node *current, __attribute__((unused)) void *extra_args)
{
	struct cil_sens *sens = (struct cil_sens *)current->data;
	/* during a re-resolve, we need to reset the categories associated with
	 * this sensitivity from a (sensitivitycategory) statement */
	cil_list_destroy(&sens->catsets, CIL_FALSE);
	cil_list_init(&sens->catsets);

	return SEPOL_OK;
}

int cil_reset_typeattr(struct cil_tree_node *current, __attribute__((unused)) void *extra_args)
{
	struct cil_typeattribute *attr = (struct cil_typeattribute*)current->data;

	/* during a re-resolve, we need to reset the lists of expression stacks  associated with this attribute from a attributetypes statement */
	if (attr->expr_stack_list != NULL) {
		/* we don't want to destroy the expression stacks (cil_list) inside
		 * this list cil_list_destroy destroys sublists, so we need to do it
		 * manually */
		struct cil_list_item *expr_stack = attr->expr_stack_list->head;
		while (expr_stack != NULL) {
			struct cil_list_item *next = expr_stack->next;
			cil_list_item_destroy(&expr_stack, CIL_FALSE);
			expr_stack = next;
		}
		free(attr->expr_stack_list);
		attr->expr_stack_list = NULL;
	}

	return SEPOL_OK;
}

int cil_reset_type(struct cil_tree_node *current, __attribute__((unused)) void *extra_args)
{
	struct cil_type *type = (struct cil_type*)current->data;

	/* reset the bounds to NULL during a re-resolve */
	type->bounds = NULL;

	return SEPOL_OK;
}

int cil_reset_user(struct cil_tree_node *current, __attribute__((unused)) void *extra_args)
{
	struct cil_user *user = (struct cil_user*)current->data;

	/* reset the bounds to NULL during a re-resolve */
	user->bounds = NULL;
	user->dftlevel = NULL;
	user->range = NULL;

	return SEPOL_OK;
}

int cil_reset_role(struct cil_tree_node *current, __attribute__((unused)) void *extra_args)
{
	struct cil_role *role = (struct cil_role*)current->data;

	/* reset the bounds to NULL during a re-resolve */
	role->bounds = NULL;

	return SEPOL_OK;
}

int cil_reset_sid(struct cil_tree_node *current, __attribute__((unused)) void *extra_args)
{
	struct cil_sid *sid = (struct cil_sid *)current->data;
	/* reset the context to NULL during a re-resolve */
	sid->context = NULL;

	return SEPOL_OK;
}

int cil_resolve_userrole(struct cil_tree_node *current, void *extra_args)
{
	struct cil_userrole *userrole = (struct cil_userrole*)current->data;
	struct cil_tree_node *user_node = NULL;
	struct cil_tree_node *role_node = NULL;
	struct cil_list_item *role = NULL;
	int rc = SEPOL_ERR;

	rc = cil_resolve_name(current, userrole->user_str, CIL_SYM_USERS, extra_args, &user_node);
	if (rc != SEPOL_OK) {
		goto exit;
	}
	userrole->user = user_node->data;

	rc = cil_resolve_name(current, userrole->role_str, CIL_SYM_ROLES, extra_args, &role_node);
	if (rc != SEPOL_OK) {
		goto exit;
	}
	userrole->role = role_node->data;

	cil_list_item_init(&role);
	role->flavor = CIL_ROLE;
	role->data = userrole->role;

	if (userrole->user->roles == NULL) {
		cil_list_init(&userrole->user->roles);
		userrole->user->roles->head = role;
	} else {
		cil_list_append_item(userrole->user->roles, role);
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_resolve_userlevel(struct cil_tree_node *current, void *extra_args)
{
	struct cil_userlevel *usrlvl = (struct cil_userlevel*)current->data;
	struct cil_tree_node *user_node = NULL;
	struct cil_tree_node *lvl_node = NULL;
	struct cil_user *user = NULL;
	int rc = SEPOL_ERR;

	rc = cil_resolve_name(current, usrlvl->user_str, CIL_SYM_USERS, extra_args, &user_node);
	if (rc != SEPOL_OK) {
		goto exit;
	}
	user = user_node->data;

	if (usrlvl->level_str != NULL) {
		rc = cil_resolve_name(current, usrlvl->level_str, CIL_SYM_LEVELS, extra_args, &lvl_node);
		if (rc != SEPOL_OK) {
			goto exit;
		}
		usrlvl->level = (struct cil_level*)lvl_node->data;
		user->dftlevel = usrlvl->level;

		/* This could still be an anonymous level even if level_str is set, if level_str is a param_str*/
		if (user->dftlevel->datum.name == NULL) {
			rc = cil_resolve_level(current, user->dftlevel, extra_args);
			if (rc != SEPOL_OK) {
				goto exit;
			}
		}
	} else if (usrlvl->level != NULL) {
		rc = cil_resolve_level(current, usrlvl->level, extra_args);
		if (rc != SEPOL_OK) {
			goto exit;
		}
		user->dftlevel = usrlvl->level;
	} else {
		cil_log(CIL_ERR, "Invalid userlevel, level not found\n");
		rc = SEPOL_ERR;
		goto exit;
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_resolve_userrange(struct cil_tree_node *current, void *extra_args)
{
	struct cil_userrange *userrange = (struct cil_userrange*)current->data;
	struct cil_tree_node *user_node = NULL;
	struct cil_tree_node *range_node = NULL;
	struct cil_user *user = NULL;
	int rc = SEPOL_ERR;

	rc = cil_resolve_name(current, userrange->user_str, CIL_SYM_USERS, extra_args, &user_node);
	if (rc != SEPOL_OK) {
		goto exit;
	}
	user = user_node->data;

	if (userrange->range_str != NULL) {
		rc = cil_resolve_name(current, userrange->range_str, CIL_SYM_LEVELRANGES, extra_args, &range_node);
		if (rc != SEPOL_OK) {
			goto exit;
		}
		userrange->range = (struct cil_levelrange*)range_node->data;
		user->range = userrange->range;

		/* This could still be an anonymous levelrange even if levelrange_str is set, if levelrange_str is a param_str*/
		if (user->range->datum.name == NULL) {
			rc = cil_resolve_levelrange(current, user->range, extra_args);
			if (rc != SEPOL_OK) {
				goto exit;
			}
		}
	} else if (userrange->range != NULL) {
		rc = cil_resolve_levelrange(current, userrange->range, extra_args);
		if (rc != SEPOL_OK) {
			goto exit;
		}
		user->range = userrange->range;
	} else {
		cil_log(CIL_ERR, "Invalid userrange, levelrange not found\n");
		rc = SEPOL_ERR;
		goto exit;
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_resolve_userbounds(struct cil_tree_node *current, void *extra_args)
{
	struct cil_userbounds *userbnds = (struct cil_userbounds*)current->data;
	struct cil_tree_node *user_node = NULL;
	struct cil_tree_node *bounds_node = NULL;
	int rc = SEPOL_ERR;

	rc = cil_resolve_name(current, userbnds->user_str, CIL_SYM_USERS, extra_args, &user_node);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	rc = cil_resolve_name(current, userbnds->bounds_str, CIL_SYM_USERS, extra_args, &bounds_node);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	if (((struct cil_user*)user_node->data)->bounds != NULL) {
		cil_log(CIL_ERR, "user cannot bind more than one user\n");
		rc = SEPOL_ERR;
		goto exit;
	}

	((struct cil_user*)user_node->data)->bounds = bounds_node->data;

	return SEPOL_OK;

exit:
	return rc;
}

int cil_resolve_userprefix(struct cil_tree_node *current, void *extra_args)
{
	struct cil_userprefix *userprefix = current->data;
	struct cil_tree_node *user_node = NULL;
	int rc = SEPOL_ERR;

	rc = cil_resolve_name(current, userprefix->user_str, CIL_SYM_USERS, extra_args, &user_node);
	if (rc != SEPOL_OK) {
		goto exit;
	}
	userprefix->user = user_node->data;

exit:
	return rc;
}

int cil_resolve_selinuxuser(struct cil_tree_node *current, void *extra_args)
{
	struct cil_selinuxuser *selinuxuser = current->data;
	struct cil_tree_node *user_node = NULL;
	struct cil_tree_node *lvlrange_node = NULL;
	int rc = SEPOL_ERR;

	rc = cil_resolve_name(current, selinuxuser->user_str, CIL_SYM_USERS, extra_args, &user_node);
	if (rc != SEPOL_OK) {
		goto exit;
	}
	selinuxuser->user = user_node->data;

	if (selinuxuser->range_str != NULL) {
		rc = cil_resolve_name(current, selinuxuser->range_str, CIL_SYM_LEVELRANGES, extra_args, &lvlrange_node);
		if (rc != SEPOL_OK) {
			cil_log(CIL_ERR, "Unable to resolve name: %s\n", selinuxuser->range_str);
			goto exit;
		}
		selinuxuser->range = (struct cil_levelrange*)lvlrange_node->data;

		/* This could still be an anonymous levelrange even if range_str is set, if range_str is a param_str*/
		if (selinuxuser->range->datum.name == NULL) {
			rc = cil_resolve_levelrange(current, selinuxuser->range, extra_args);
			if (rc != SEPOL_OK) {
				goto exit;
			}
		}
	} else if (selinuxuser->range != NULL) {
		rc = cil_resolve_levelrange(current, selinuxuser->range, extra_args);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	} else {
		cil_log(CIL_ERR, "Invalid selinuxuser, levelrange not found\n");
		rc = SEPOL_ERR;
		goto exit;
	}

	rc = SEPOL_OK;
exit:
	return rc;
}

int cil_resolve_roletype(struct cil_tree_node *current, void *extra_args)
{
	struct cil_roletype *roletype = (struct cil_roletype*)current->data;
	struct cil_tree_node *role_node = NULL;
	struct cil_tree_node *type_node = NULL;
	struct cil_list_item *type = NULL;
	int rc = SEPOL_ERR;

	rc = cil_resolve_name(current, roletype->role_str, CIL_SYM_ROLES, extra_args, &role_node);
	if (rc != SEPOL_OK) {
		goto exit;
	}
	roletype->role = role_node->data;

	rc = cil_resolve_name(current, roletype->type_str, CIL_SYM_TYPES, extra_args, &type_node);
	if (rc != SEPOL_OK) {
		goto exit;
	}
	roletype->type = type_node->data;

	cil_list_item_init(&type);
	type->flavor = CIL_TYPE;
	type->data = roletype->type;

	if (roletype->role->types == NULL) {
		cil_list_init(&roletype->role->types);
		roletype->role->types->head = type;
	} else {
		cil_list_append_item(roletype->role->types, type);
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_resolve_roletransition(struct cil_tree_node *current, void *extra_args)
{
	struct cil_roletransition *roletrans = (struct cil_roletransition*)current->data;
	struct cil_tree_node *src_node = NULL;
	struct cil_tree_node *tgt_node = NULL;
	struct cil_tree_node *obj_node = NULL;
	struct cil_tree_node *result_node = NULL;
	int rc = SEPOL_ERR;

	rc = cil_resolve_name(current, roletrans->src_str, CIL_SYM_ROLES, extra_args, &src_node);
	if (rc != SEPOL_OK) {
		goto exit;
	}
	roletrans->src = (struct cil_role*)(src_node->data);

	rc = cil_resolve_name(current, roletrans->tgt_str, CIL_SYM_TYPES, extra_args, &tgt_node);
	if (rc != SEPOL_OK) {
		goto exit;
	}
	roletrans->tgt = tgt_node->data;

	rc = cil_resolve_name(current, roletrans->obj_str, CIL_SYM_CLASSES, extra_args, &obj_node);
	if (rc != SEPOL_OK) {
		goto exit;
	}
	roletrans->obj = (struct cil_class*)(obj_node->data);

	rc = cil_resolve_name(current, roletrans->result_str, CIL_SYM_ROLES, extra_args, &result_node);
	if (rc != SEPOL_OK) {
		goto exit;
	}
	roletrans->result = (struct cil_role*)(result_node->data);

	return SEPOL_OK;

exit:
	return rc;
}

int cil_resolve_roleallow(struct cil_tree_node *current, void *extra_args)
{
	struct cil_roleallow *roleallow = (struct cil_roleallow*)current->data;
	struct cil_tree_node *src_node = NULL;
	struct cil_tree_node *tgt_node = NULL;
	int rc = SEPOL_ERR;

	rc = cil_resolve_name(current, roleallow->src_str, CIL_SYM_ROLES, extra_args, &src_node);
	if (rc != SEPOL_OK) {
		goto exit;
	}
	roleallow->src = (struct cil_role*)(src_node->data);

	rc = cil_resolve_name(current, roleallow->tgt_str, CIL_SYM_ROLES, extra_args, &tgt_node);
	if (rc != SEPOL_OK) {
		goto exit;
	}
	roleallow->tgt = (struct cil_role*)(tgt_node->data);

	return SEPOL_OK;

exit:
	return rc;
}

int cil_resolve_roledominance(struct cil_tree_node *current, void *extra_args)
{
	struct cil_roledominance *roledom = (struct cil_roledominance*)current->data;
	struct cil_tree_node *role_node = NULL;
	struct cil_tree_node *domed_node = NULL;
	int rc = SEPOL_ERR;

	rc = cil_resolve_name(current, roledom->role_str, CIL_SYM_ROLES, extra_args, &role_node);
	if (rc != SEPOL_OK) {
		goto exit;
	}
	roledom->role = (struct cil_role*)(role_node->data);

	rc = cil_resolve_name(current, roledom->domed_str, CIL_SYM_ROLES, extra_args, &domed_node);
	if (rc != SEPOL_OK) {
		goto exit;
	}
	roledom->domed = (struct cil_role*)(domed_node->data);

	return SEPOL_OK;

exit:
	return rc;
}

int cil_resolve_rolebounds(struct cil_tree_node *current, void *extra_args)
{
	struct cil_rolebounds *rolebnds = (struct cil_rolebounds*)current->data;
	struct cil_tree_node *role_node = NULL;
	struct cil_tree_node *bounds_node = NULL;
	int rc = SEPOL_ERR;

	rc = cil_resolve_name(current, rolebnds->role_str, CIL_SYM_ROLES, extra_args, &role_node);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	rc = cil_resolve_name(current, rolebnds->bounds_str, CIL_SYM_ROLES, extra_args, &bounds_node);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	if (((struct cil_role*)role_node->data)->bounds != NULL) {
		cil_log(CIL_ERR, "role cannot bind more than one role\n");
		rc = SEPOL_ERR;
		goto exit;
	}

	((struct cil_role*)role_node->data)->bounds = bounds_node->data;

	return SEPOL_OK;

exit:
	return rc;
}

int cil_resolve_sensalias(struct cil_tree_node *current, void *extra_args)
{
	struct cil_sensalias *alias = (struct cil_sensalias*)current->data;
	struct cil_tree_node *sens_node = NULL;
	int rc = SEPOL_ERR;

	rc = cil_resolve_name(current, alias->sens_str, CIL_SYM_SENS, extra_args, &sens_node);
	if (rc != SEPOL_OK) {
		goto exit;
	}
	alias->sens = (struct cil_sens*)(sens_node->data);

	return SEPOL_OK;

exit:
	return rc;
}

int cil_resolve_catalias(struct cil_tree_node *current, void *extra_args)
{
	struct cil_catalias *alias = (struct cil_catalias*)current->data;
	struct cil_tree_node *cat_node = NULL;
	int rc = SEPOL_ERR;

	rc = cil_resolve_name(current, alias->cat_str, CIL_SYM_CATS, extra_args, &cat_node);
	if (rc != SEPOL_OK) {
		goto exit;
	}
	alias->cat = (struct cil_cat*)(cat_node->data);

	return SEPOL_OK;

exit:
	return rc;
}

int __cil_set_append(struct cil_list_item *main_list_item, struct cil_list_item *new_list_item, int *success)
{
	int rc = SEPOL_ERR;

	if (main_list_item == NULL || new_list_item == NULL) {
		goto exit;
	}

	if (main_list_item->data == new_list_item->data && main_list_item->next == NULL) {
		main_list_item->next = new_list_item->next;
		*success = 1;
		rc = SEPOL_OK;
		goto exit;
	} else {
		while (main_list_item != NULL || new_list_item != NULL) {
			if (main_list_item->data != new_list_item->data) {
				cil_log(CIL_ERR, "Error: categoryorder adjacency mismatch\n");
				rc = SEPOL_ERR;
				goto exit;
			}
			main_list_item = main_list_item->next;
			new_list_item = new_list_item->next;
		}
		*success = 1;
		rc = SEPOL_OK;
		goto exit;
	}

	return SEPOL_OK;

exit:
	return rc;
}

int __cil_set_prepend(struct cil_list *main_list, struct cil_list *new_list, struct cil_list_item *main_list_item, struct cil_list_item *new_list_item, int *success)
{
	struct cil_list_item *new_list_iter = NULL;
	int rc = SEPOL_ERR;

	if (main_list_item == NULL || new_list_item == NULL) {
		goto exit;
	}

	if (new_list_item->next != NULL) {
		cil_log(CIL_ERR, "Invalid list item given to prepend to list: Has next item\n");
		goto exit;
	}

	if (main_list_item == main_list->head) {
		new_list_iter = new_list->head;
		while (new_list_iter != NULL) {
			if (new_list_iter->next == new_list_item) {
				new_list_iter->next = NULL;
				rc = cil_list_prepend_item(main_list, new_list_iter);
				if (rc != SEPOL_OK) {
					cil_log(CIL_ERR, "Failed to prepend item to list\n");
					goto exit;
				}
				*success = 1;
				goto exit;
			}
		}
		rc = SEPOL_ERR;
		goto exit;
	} else {
		cil_log(CIL_ERR, "Error: Attempting to prepend to not the head of the list\n");
		goto exit;
	}

	return SEPOL_OK;

exit:
	return rc;
}

int __cil_set_merge_lists(struct cil_list *primary, struct cil_list *new, int *success)
{
	struct cil_list_item *curr_main = primary->head;
	struct cil_list_item *curr_new = NULL;
	int rc = SEPOL_ERR;

	if (primary == NULL && new == NULL) {
		goto exit;
	}

	while (curr_main != NULL) {
		curr_new = new->head;
		while (curr_new != NULL) {
			if (curr_main->data == curr_new->data) {
				if (curr_new->next == NULL) {
					rc = __cil_set_prepend(primary, new, curr_main, curr_new, success);
					if (rc != SEPOL_OK) {
						cil_log(CIL_ERR, "Failed to prepend categoryorder sublist to primary list\n");
					}
					goto exit;
				} else {
					rc = __cil_set_append(curr_main, curr_new, success);
					if (rc != SEPOL_OK) {
						cil_log(CIL_ERR, "Failed to append categoryorder sublist to primary list\n");
					}
					goto exit;
				}
			}
			curr_new = curr_new->next;
		}
		curr_main = curr_main->next;
	}

	return SEPOL_OK;

exit:
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
			goto exit;
		}
		list_item = list_item->next;
	}

	return SEPOL_OK;

exit:
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
					cil_log(CIL_ERR, "Failed to merge categoryorder sublist with main list\n");
					goto exit;
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
							cil_log(CIL_ERR, "Failed combining categoryorder lists into one\n");
							goto exit;
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

exit:
	return rc;
}

int __cil_create_edge_list(struct cil_tree_node *current, struct cil_list *order, uint32_t sym_flavor, struct cil_list *edge_list, void *extra_args)
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
		goto exit;
	}

	curr = order->head;

	while (curr != NULL) {
		rc = cil_resolve_name(current, (char*)curr->data, sym_flavor, extra_args, &node);
		if (rc != SEPOL_OK) {
			goto exit;
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

exit:
	return rc;
}

int cil_resolve_catorder(struct cil_tree_node *current, void *extra_args)
{
	struct cil_args_resolve *args = extra_args;
	struct cil_db *db = NULL;
	struct cil_catorder *catorder = (struct cil_catorder*)current->data;
	struct cil_list_item *list_item = NULL;
	struct cil_list *edge_list = NULL;
	int rc = SEPOL_ERR;

	if (args != NULL) {
		db = args->db;
	}

	cil_list_init(&edge_list);

	rc = __cil_create_edge_list(current, catorder->cat_list_str, CIL_SYM_CATS, edge_list, extra_args);
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Failed to create category edge list\n");
		goto exit;
	}

	if (db->catorder->head == NULL) {
		cil_list_item_init(&list_item);
		db->catorder->head = list_item;
	}
	rc = __cil_set_order(db->catorder, edge_list);
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Failed to order categoryorder\n");
		goto exit;
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_resolve_dominance(struct cil_tree_node *current, void *extra_args)
{
	struct cil_args_resolve *args = extra_args;
	struct cil_db *db = NULL;
	struct cil_sens_dominates *dom = (struct cil_sens_dominates*)current->data;
	struct cil_list_item *list_item = NULL;
	struct cil_list *edge_list = NULL;
	int rc = SEPOL_ERR;

	if (args != NULL) {
		db = args->db;
	}

	cil_list_init(&edge_list);

	rc = __cil_create_edge_list(current, dom->sens_list_str, CIL_SYM_SENS, edge_list, args);
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Failed to create sensitivity edge list\n");
		goto exit;
	}

	if (db->dominance->head == NULL) {
		cil_list_item_init(&list_item);
		db->dominance->head = list_item;
	}

	rc = __cil_set_order(db->dominance, edge_list);
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Failed to order dominance\n");
		goto exit;
	}

	return SEPOL_OK;

exit:
	return rc;
}

int __cil_resolve_cat_range(struct cil_db *db, struct cil_list *cat_list, struct cil_list *res_list)
{
	struct cil_list_item *curr_cat = NULL;
	struct cil_list_item *catorder = NULL;
	struct cil_list_item *curr_catorder = NULL;
	struct cil_list_item *new_item = NULL;
	struct cil_list_item *list_tail = NULL;
	int rc = SEPOL_ERR;

	if (cat_list == NULL || res_list == NULL || db->catorder->head == NULL) {
		goto exit;
	}

	if (cat_list->head == NULL || cat_list->head->next == NULL || cat_list->head->next->next != NULL) {
		cil_log(CIL_ERR, "Invalid category list passed into category range resolution\n");
		goto exit;
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
					goto exit;
				}
				curr_catorder = curr_catorder->next;
			}
			cil_log(CIL_ERR, "Invalid category range\n");
			rc = SEPOL_ERR;
			goto exit;
		}
		curr_catorder = curr_catorder->next;
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_resolve_cat_list(struct cil_tree_node *current, struct cil_list *cat_list, struct cil_list *res_cat_list, void *extra_args)
{
	struct cil_args_resolve *args = extra_args;
	struct cil_db *db = NULL;
	struct cil_tree_node *cat_node = NULL;
	struct cil_list_item *new_item = NULL;
	struct cil_list_item *list_tail = NULL;
	struct cil_list_item *curr = NULL;
	int rc = SEPOL_ERR;

	if (cat_list == NULL || res_cat_list == NULL) {
		goto exit;
	}

	if (args != NULL) {
		db = args->db;
	}

	curr = cat_list->head;

	while (curr != NULL) {
		if (curr->flavor == CIL_LIST) {
			struct cil_list sub_list;
			sub_list.head = NULL;
			rc = __cil_resolve_cat_range(db, (struct cil_list*)curr->data, &sub_list);
			if (rc != SEPOL_OK) {
				goto exit;
			}
			new_item = sub_list.head;
		} else {
			rc = cil_resolve_name(current, (char*)curr->data, CIL_SYM_CATS, extra_args, &cat_node);
			if (rc != SEPOL_OK) {
				goto exit;
			}
			if (cat_node->flavor == CIL_CATSET) {
				cil_log(CIL_ERR, "categorysets are not allowed inside category lists\n");
				rc = SEPOL_ERR;
				goto exit;
			}
			cil_list_item_init(&new_item);
			new_item->flavor = cat_node->flavor;
			new_item->data = cat_node->data;
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

exit:
	return rc;
}

int cil_resolve_catset(struct cil_tree_node *current, struct cil_catset *catset, void *extra_args)
{
	struct cil_list *res_cat_list = NULL;
	struct cil_list_item *res_cat_item = NULL;
	struct cil_list_item *cat_item = NULL;
	struct cil_tree_node *cat_node = NULL;
	int rc = SEPOL_ERR;

	cil_list_init(&res_cat_list);

	for (cat_item = catset->cat_list_str->head; cat_item != NULL; cat_item = cat_item->next) {
		cil_list_item_init(&res_cat_item);

		switch (cat_item->flavor) {
		case CIL_AST_STR: {
			rc = cil_resolve_name(current, (char*)cat_item->data, CIL_SYM_CATS, extra_args, &cat_node);
			if (rc != SEPOL_OK) {
				goto exit;
			}
			res_cat_item->flavor = cat_node->flavor;
			res_cat_item->data = cat_node->data;
			break;
		}
		case CIL_CATRANGE: {
			rc = cil_resolve_catrange(current, cat_item->data, extra_args);
			if (rc != SEPOL_OK) {
				goto exit;
			}
			res_cat_item->flavor = CIL_CATRANGE;
			res_cat_item->data = cat_item->data;
			break;
		}
		default:
			rc = SEPOL_ERR;
			goto exit;
		}

		rc = cil_list_append_item(res_cat_list, res_cat_item);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	if (catset->cat_list != NULL) {
		/* clean up because of re-resolve */
		cil_list_destroy(&catset->cat_list, 0);
	}
	catset->cat_list = res_cat_list;

	return SEPOL_OK;

exit:
	cil_list_destroy(&res_cat_list, 0);
	return rc;
}

int cil_resolve_catrange(struct cil_tree_node *current, struct cil_catrange *catrange, void *extra_args)
{
	struct cil_args_resolve *args = extra_args;
	struct cil_db *db = NULL;
	struct cil_tree_node *cat_low_node = NULL;
	struct cil_tree_node *cat_high_node = NULL;
	struct cil_list_item *cat;
	int rc = SEPOL_ERR;

	if (args != NULL) {
		db = args->db;
	}

	rc = cil_resolve_name(current, catrange->cat_low_str, CIL_SYM_CATS, args, &cat_low_node);
	if (rc != SEPOL_OK) {
		goto exit;
	}
	catrange->cat_low = cat_low_node->data;

	for (cat = db->catorder->head; cat != NULL; cat = cat->next) {
		if (cat->data == cat_low_node->data) {
			break;
		}
	}

	if (cat == NULL) {
		cil_log(CIL_ERR, "Invalid category order\n");
		rc = SEPOL_ERR;
		goto exit;
	}

	rc = cil_resolve_name(current, catrange->cat_high_str, CIL_SYM_CATS, args, &cat_high_node);
	if (rc != SEPOL_OK) {
		goto exit;
	}
	catrange->cat_high = cat_high_node->data;

	for (cat = cat->next; cat != NULL; cat = cat->next) {
		if (cat->data == cat_high_node->data) {
			break;
		}
	}

	if (cat == NULL) {
		cil_log(CIL_ERR, "Invalid category order\n");
		rc = SEPOL_ERR;
		goto exit;
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_resolve_senscat(struct cil_tree_node *current, void *extra_args)
{
	struct cil_tree_node *sens_node = NULL;
	struct cil_senscat *senscat = (struct cil_senscat*)current->data;
	struct cil_sens *sens = NULL;
	struct cil_tree_node *cat_node = NULL;
	struct cil_list_item *catset_item = NULL;
	int rc = SEPOL_ERR;

	rc = cil_resolve_name(current, (char*)senscat->sens_str, CIL_SYM_SENS, extra_args, &sens_node);
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Failed to get sensitivity node\n");
		goto exit;
	}

	if (sens_node->flavor == CIL_SENSALIAS) {
		sens_node = ((struct cil_sensalias*)sens_node->data)->sens->datum.node;
	}
	sens = sens_node->data;

	if (senscat->catset_str != NULL) {
		rc = cil_resolve_name(current, (char*)senscat->catset_str, CIL_SYM_CATS, extra_args, &cat_node);
		if (rc != SEPOL_OK) {
			goto exit;
		}

		if (cat_node->flavor != CIL_CATSET) {
			cil_log(CIL_ERR, "Named object is not a category set\n");
			rc = SEPOL_ERR;
			goto exit;
		}

		senscat->catset = (struct cil_catset*)cat_node->data;

	} else {
		rc = cil_resolve_catset(current, senscat->catset, extra_args);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	cil_list_item_init(&catset_item);
	catset_item->flavor = CIL_CATSET;
	catset_item->data = senscat->catset;
	rc = cil_list_append_item(sens->catsets, catset_item);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	return SEPOL_OK;

exit:
	cil_list_item_destroy(&catset_item, CIL_FALSE);
	return rc;
}

int cil_resolve_level(struct cil_tree_node *current, struct cil_level *level, void *extra_args)
{
	struct cil_args_resolve *args = extra_args;
	struct cil_db *db = NULL;
	struct cil_tree_node *sens_node = NULL;
	struct cil_tree_node *catset_node = NULL;
	int rc = SEPOL_ERR;

	if (args != NULL) {
		db = args->db;
	}

	rc = cil_resolve_name(current, (char*)level->sens_str, CIL_SYM_SENS, extra_args, &sens_node);
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Failed to get sensitivity node\n");
		goto exit;
	}

	if (sens_node->flavor == CIL_SENSALIAS) {
		sens_node = ((struct cil_sensalias*)sens_node->data)->sens->datum.node;
	}

	level->sens = (struct cil_sens*)sens_node->data;

	if (level->catset_str != NULL || level->catset != NULL) {
		if (level->catset_str != NULL) {
			rc = cil_resolve_name(current, level->catset_str, CIL_SYM_CATS, extra_args, &catset_node);
			if (rc != SEPOL_OK) {
				goto exit;
			}
			level->catset = catset_node->data;
		} else {
			rc = cil_resolve_catset(current, level->catset, extra_args);
			if (rc != SEPOL_OK) {
				goto exit;
			}
		}

		rc = __cil_verify_senscatset(db, level->sens, level->catset);
		if (rc != SEPOL_OK) {
			cil_log(CIL_ERR, "Failed to verify sensitivitycategory relationship\n");
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_resolve_levelrange(struct cil_tree_node *current, struct cil_levelrange *lvlrange, void *extra_args)
{
	struct cil_tree_node *low_node = NULL;
	struct cil_tree_node *high_node = NULL;
	int rc = SEPOL_ERR;

	if (lvlrange->low_str != NULL) {
		rc = cil_resolve_name(current, lvlrange->low_str, CIL_SYM_LEVELS, extra_args, &low_node);
		if (rc != SEPOL_OK) {
			goto exit;
		}
		lvlrange->low = (struct cil_level*)low_node->data;

		/* This could still be an anonymous level even if low_str is set, if low_str is a param_str */
		if (lvlrange->low->datum.name == NULL) {
			rc = cil_resolve_level(current, lvlrange->low, extra_args);
			if (rc != SEPOL_OK) {
				goto exit;
			}
		}
	} else if (lvlrange->low != NULL) {
		rc = cil_resolve_level(current, lvlrange->low, extra_args);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	if (lvlrange->high_str != NULL) {
		rc = cil_resolve_name(current, lvlrange->high_str, CIL_SYM_LEVELS, extra_args, &high_node);
		if (rc != SEPOL_OK) {
			goto exit;
		}
		lvlrange->high = (struct cil_level*)high_node->data;

		/* This could still be an anonymous level even if high_str is set, if high_str is a param_str */
		if (lvlrange->high->datum.name == NULL) {
			rc = cil_resolve_level(current, lvlrange->high, extra_args);
			if (rc != SEPOL_OK) {
				goto exit;
			}
		}
	} else if (lvlrange->high != NULL) {
		rc = cil_resolve_level(current, lvlrange->high, extra_args);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_resolve_constrain(struct cil_tree_node *current, void *extra_args)
{
	struct cil_constrain *cons = (struct cil_constrain*)current->data;
	struct cil_args_resolve *args = extra_args;
	struct cil_tree_node *cps_node = NULL;
	int rc = SEPOL_ERR;

	if (cons->classpermset_str != NULL) {
		rc = cil_resolve_name(current, cons->classpermset_str, CIL_SYM_CLASSPERMSETS, args, &cps_node);
		if (rc != SEPOL_OK) {
			goto exit;
		}
		cons->classpermset = (struct cil_classpermset*)cps_node->data;

		/* This could still be an anonymous classpermset even if classpermset_str is set, if classpermset_str is a param_str*/
		if (cons->classpermset->datum.name == NULL) {

			rc = cil_resolve_classpermset(current, cons->classpermset, args);
			if (rc != SEPOL_OK) {
				goto exit;
			}
		}
	} else if (cons->classpermset != NULL) {
		rc = cil_resolve_classpermset(current, cons->classpermset, args);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	rc = cil_resolve_expr_stack(cons->expr, current, extra_args);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_resolve_validatetrans(struct cil_tree_node *current, void *extra_args)
{
	struct cil_validatetrans *validtrans = current->data;
	struct cil_args_resolve *args = extra_args;
	struct cil_tree_node *class_node = NULL;
	int rc = SEPOL_ERR;

	rc = cil_resolve_name(current, validtrans->class_str, CIL_SYM_CLASSES, args, &class_node);
	if (rc != SEPOL_OK) {
		goto exit;
	}
	validtrans->class = (struct cil_class*)class_node->data;

	rc = cil_resolve_expr_stack(validtrans->expr, current, extra_args);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_resolve_context(struct cil_tree_node *current, struct cil_context *context, void *extra_args)
{
	struct cil_tree_node *user_node = NULL;
	struct cil_tree_node *role_node = NULL;
	struct cil_tree_node *type_node = NULL;
	struct cil_tree_node *lvlrange_node = NULL;

	int rc = SEPOL_ERR;

	rc = cil_resolve_name(current, context->user_str, CIL_SYM_USERS, extra_args, &user_node);
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Unable to resolve name: %s\n", context->user_str);
		goto exit;
	}
	context->user = (struct cil_user*)user_node->data;

	rc = cil_resolve_name(current, context->role_str, CIL_SYM_ROLES, extra_args, &role_node);
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Unable to resolve name: %s\n", context->role_str);
		goto exit;
	}
	context->role = (struct cil_role*)role_node->data;

	rc = cil_resolve_name(current, context->type_str, CIL_SYM_TYPES, extra_args, &type_node);
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Unable to resolve name: %s\n", context->type_str);
		goto exit;
	}
	if (type_node->flavor != CIL_TYPE && type_node->flavor != CIL_TYPEALIAS) {
		rc = SEPOL_ERR;
		cil_log(CIL_ERR, "Type not a type or type alias\n");
		goto exit;
	}
	context->type = type_node->data;

	if (context->range_str != NULL) {
		rc = cil_resolve_name(current, context->range_str, CIL_SYM_LEVELRANGES, extra_args, &lvlrange_node);
		if (rc != SEPOL_OK) {
			cil_log(CIL_ERR, "Unable to resolve name: %s\n", context->range_str);
			goto exit;
		}
		context->range = (struct cil_levelrange*)lvlrange_node->data;

		/* This could still be an anonymous levelrange even if levelrange_str is set, if levelrange_str is a param_str*/
		if (context->range->datum.name == NULL) {
			rc = cil_resolve_levelrange(current, context->range, extra_args);
			if (rc != SEPOL_OK) {
				goto exit;
			}
		}
	} else if (context->range != NULL) {
		rc = cil_resolve_levelrange(current, context->range, extra_args);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	} else {
		cil_log(CIL_ERR, "Invalid context, levelrange not found\n");
		rc = SEPOL_ERR;
		goto exit;
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_resolve_filecon(struct cil_tree_node *current, void *extra_args)
{
	struct cil_filecon *filecon = (struct cil_filecon*)current->data;
	struct cil_tree_node *context_node = NULL;
	int rc = SEPOL_ERR;

	if (filecon->context_str != NULL) {
		rc = cil_resolve_name(current, filecon->context_str, CIL_SYM_CONTEXTS, extra_args, &context_node);
		if (rc != SEPOL_OK) {
			return rc;
		}
		filecon->context = (struct cil_context*)context_node->data;
	} else if (filecon->context != NULL) {
		rc = cil_resolve_context(current, filecon->context, extra_args);
		if (rc != SEPOL_OK) {
			return rc;
		}
	}

	return SEPOL_OK;
}

int cil_resolve_portcon(struct cil_tree_node *current, void *extra_args)
{
	struct cil_portcon *portcon = (struct cil_portcon*)current->data;
	struct cil_tree_node *context_node = NULL;
	int rc = SEPOL_ERR;

	if (portcon->context_str != NULL) {
		rc = cil_resolve_name(current, portcon->context_str, CIL_SYM_CONTEXTS, extra_args, &context_node);
		if (rc != SEPOL_OK) {
			goto exit;
		}
		portcon->context = (struct cil_context*)context_node->data;
	} else {
		rc = cil_resolve_context(current, portcon->context, extra_args);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_resolve_genfscon(struct cil_tree_node *current, void *extra_args)
{
	struct cil_genfscon *genfscon = (struct cil_genfscon*)current->data;
	struct cil_tree_node *context_node = NULL;
	int rc = SEPOL_ERR;

	if (genfscon->context_str != NULL) {
		rc = cil_resolve_name(current, genfscon->context_str, CIL_SYM_CONTEXTS, extra_args, &context_node);
		if (rc != SEPOL_OK) {
			goto exit;
		}
		genfscon->context = (struct cil_context*)context_node->data;
	} else {
		rc = cil_resolve_context(current, genfscon->context, extra_args);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_resolve_nodecon(struct cil_tree_node *current, void *extra_args)
{
	struct cil_nodecon *nodecon = (struct cil_nodecon*)current->data;
	struct cil_tree_node *addr_node = NULL;
	struct cil_tree_node *mask_node = NULL;
	struct cil_tree_node *context_node = NULL;
	int rc = SEPOL_ERR;

	if (nodecon->addr_str != NULL) {
		rc = cil_resolve_name(current, nodecon->addr_str, CIL_SYM_IPADDRS, extra_args, &addr_node);
		if (rc != SEPOL_OK) {
			goto exit;
		}
		nodecon->addr = (struct cil_ipaddr*)addr_node->data;
	}

	if (nodecon->mask_str != NULL) {
		rc = cil_resolve_name(current, nodecon->mask_str, CIL_SYM_IPADDRS, extra_args, &mask_node);
		if (rc != SEPOL_OK) {
			goto exit;
		}
		nodecon->mask = (struct cil_ipaddr*)mask_node->data;
	}

	if (nodecon->context_str != NULL) {
		rc = cil_resolve_name(current, nodecon->context_str, CIL_SYM_CONTEXTS, extra_args, &context_node);
		if (rc != SEPOL_OK) {
			goto exit;
		}
		nodecon->context = (struct cil_context*)context_node->data;
	} else {
		rc = cil_resolve_context(current, nodecon->context, extra_args);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	if (nodecon->addr->family != nodecon->mask->family) {
		cil_log(CIL_ERR, "Nodecon ip address not in the same family\n");
		rc = SEPOL_ERR;
		goto exit;
	}


	return SEPOL_OK;

exit:
	return rc;
}

int cil_resolve_netifcon(struct cil_tree_node *current, void *extra_args)
{
	struct cil_netifcon *netifcon = (struct cil_netifcon*)current->data;
	struct cil_tree_node *ifcon_node = NULL;
	struct cil_tree_node *packcon_node = NULL;

	int rc = SEPOL_ERR;

	if (netifcon->if_context_str != NULL) {
		rc = cil_resolve_name(current, netifcon->if_context_str, CIL_SYM_CONTEXTS, extra_args, &ifcon_node);
		if (rc != SEPOL_OK) {
			goto exit;
		}
		netifcon->if_context = (struct cil_context*)ifcon_node->data;
	} else {
		rc = cil_resolve_context(current, netifcon->if_context, extra_args);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	if (netifcon->packet_context_str != NULL) {
		rc = cil_resolve_name(current, netifcon->packet_context_str, CIL_SYM_CONTEXTS, extra_args, &packcon_node);
		if (rc != SEPOL_OK) {
			goto exit;
		}
		netifcon->packet_context = (struct cil_context*)packcon_node->data;
	} else {
		rc = cil_resolve_context(current, netifcon->packet_context, extra_args);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}
	return SEPOL_OK;

exit:
	return rc;
}

int cil_resolve_pirqcon(struct cil_tree_node *current, void *extra_args)
{
	struct cil_pirqcon *pirqcon = (struct cil_pirqcon*)current->data;
	struct cil_tree_node *context_node = NULL;
	int rc = SEPOL_ERR;

	if (pirqcon->context_str != NULL) {
		rc = cil_resolve_name(current, pirqcon->context_str, CIL_SYM_CONTEXTS, extra_args, &context_node);
		if (rc != SEPOL_OK) {
			goto exit;
		}
		pirqcon->context = (struct cil_context*)context_node->data;
	} else {
		rc = cil_resolve_context(current, pirqcon->context, extra_args);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_resolve_iomemcon(struct cil_tree_node *current, void *extra_args)
{
	struct cil_iomemcon *iomemcon = (struct cil_iomemcon*)current->data;
	struct cil_tree_node *context_node = NULL;
	int rc = SEPOL_ERR;

	if (iomemcon->context_str != NULL) {
		rc = cil_resolve_name(current, iomemcon->context_str, CIL_SYM_CONTEXTS, extra_args, &context_node);
		if (rc != SEPOL_OK) {
			goto exit;
		}
		iomemcon->context = (struct cil_context*)context_node->data;
	} else {
		rc = cil_resolve_context(current, iomemcon->context, extra_args);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_resolve_ioportcon(struct cil_tree_node *current, void *extra_args)
{
	struct cil_ioportcon *ioportcon = (struct cil_ioportcon*)current->data;
	struct cil_tree_node *context_node = NULL;
	int rc = SEPOL_ERR;

	if (ioportcon->context_str != NULL) {
		rc = cil_resolve_name(current, ioportcon->context_str, CIL_SYM_CONTEXTS, extra_args, &context_node);
		if (rc != SEPOL_OK) {
			goto exit;
		}
		ioportcon->context = (struct cil_context*)context_node->data;
	} else {
		rc = cil_resolve_context(current, ioportcon->context, extra_args);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_resolve_pcidevicecon(struct cil_tree_node *current, void *extra_args)
{
	struct cil_pcidevicecon *pcidevicecon = (struct cil_pcidevicecon*)current->data;
	struct cil_tree_node *context_node = NULL;
	int rc = SEPOL_ERR;

	if (pcidevicecon->context_str != NULL) {
		rc = cil_resolve_name(current, pcidevicecon->context_str, CIL_SYM_CONTEXTS, extra_args, &context_node);
		if (rc != SEPOL_OK) {
			goto exit;
		}
		pcidevicecon->context = (struct cil_context*)context_node->data;
	} else {
		rc = cil_resolve_context(current, pcidevicecon->context, extra_args);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_resolve_fsuse(struct cil_tree_node *current, void *extra_args)
{
	struct cil_fsuse *fsuse = (struct cil_fsuse*)current->data;
	struct cil_tree_node *context_node = NULL;
	int rc = SEPOL_ERR;

	if (fsuse->context_str != NULL) {
		rc = cil_resolve_name(current, fsuse->context_str, CIL_SYM_CONTEXTS, extra_args, &context_node);
		if (rc != SEPOL_OK) {
			goto exit;
		}
		fsuse->context = (struct cil_context*)context_node->data;
	} else {
		rc = cil_resolve_context(current, fsuse->context, extra_args);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_resolve_sidcontext(struct cil_tree_node *current, void *extra_args)
{
	struct cil_sidcontext *sidcon = (struct cil_sidcontext*)current->data;
	struct cil_sid *sid = NULL;
	struct cil_tree_node *sid_node = NULL;
	struct cil_tree_node *context_node = NULL;

	int rc = SEPOL_ERR;

	rc = cil_resolve_name(current, sidcon->sid_str, CIL_SYM_SIDS, extra_args, &sid_node);
	if (rc != SEPOL_OK) {
		goto exit;
	}
	sid = sid_node->data;


	if (sidcon->context_str != NULL) {
		rc = cil_resolve_name(current, sidcon->context_str, CIL_SYM_CONTEXTS, extra_args, &context_node);
		if (rc != SEPOL_OK) {
			goto exit;
		}
		sidcon->context = (struct cil_context*)context_node->data;
	} else if (sidcon->context != NULL) {
		rc = cil_resolve_context(current, sidcon->context, extra_args);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	if (sid->context != NULL) {
		cil_log(CIL_ERR, "sid's cannot be associated with more than one context\n");
		rc = SEPOL_ERR;
		goto exit;
	}

	sid->context = sidcon->context;

	return SEPOL_OK;

exit:
	return rc;
}

int cil_resolve_blockinherit(struct cil_tree_node *current, void *extra_args)
{
	struct cil_args_resolve *args = extra_args;
	struct cil_db *db = NULL;
	struct cil_blockinherit *inherit = (struct cil_blockinherit*)current->data;
	struct cil_tree_node *block_node = NULL;
	int rc = SEPOL_ERR;

	if (args != NULL) {
		db = args->db;
	}

	if (inherit->block_str != NULL) {
		rc = cil_resolve_name(current, inherit->block_str, CIL_SYM_BLOCKS, extra_args, &block_node);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	} else {
		cil_log(CIL_ERR, "block strings is null\n");
		rc = SEPOL_ERR;
		goto exit;
	}

	rc = cil_copy_ast(db, block_node, current);
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Failed to copy block, rc: %d\n", rc);
		goto exit;
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_resolve_blockabstract(struct cil_tree_node *current, void *extra_args)
{
	struct cil_blockabstract *abstract = (struct cil_blockabstract*)current->data;
	struct cil_tree_node *block_node = NULL;
	int rc = SEPOL_ERR;

	if (abstract->block_str != NULL) {
		rc = cil_resolve_name(current, abstract->block_str, CIL_SYM_BLOCKS, extra_args, &block_node);
		if (rc != SEPOL_OK || block_node->flavor != CIL_BLOCK) {
			cil_log(CIL_ERR, "Failed to resolve block, rc: %d\n", rc);
			goto exit;
		}
	} else {
		cil_log(CIL_ERR, "block string is null\n");
		goto exit;
	}

	((struct cil_block*)block_node->data)->is_abstract = CIL_TRUE;

	return SEPOL_OK;

exit:
	return rc;
}

int cil_resolve_in(struct cil_tree_node *current, void *extra_args)
{
	struct cil_args_resolve *args = extra_args;
	struct cil_db *db = NULL;
	struct cil_in *in = (struct cil_in*)current->data;
	struct cil_tree_node *block_node = NULL;
	int rc = SEPOL_ERR;

	if (args != NULL) {
		db = args->db;
	}

	if (in->block_str != NULL) {
		rc = cil_resolve_name(current, in->block_str, CIL_SYM_BLOCKS, extra_args, &block_node);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	rc = cil_copy_ast(db, current, block_node);
	if (rc != SEPOL_OK) {
		printf("Failed to copy in, rc: %d\n", rc);
		goto exit;
	}

	cil_tree_subtree_destroy(current->cl_head);
	current->cl_head = NULL;

	return SEPOL_OK;

exit:
	return rc;
}

int cil_resolve_call1(struct cil_tree_node *current, void *extra_args)
{
	struct cil_args_resolve *args = extra_args;
	struct cil_db *db = NULL;
	struct cil_call *new_call = (struct cil_call*)current->data;
	struct cil_tree_node *macro_node = NULL;
	int rc = SEPOL_ERR;

	if (args != NULL) {
		db = args->db;
	}

	if (new_call->macro_str != NULL) {
		rc = cil_resolve_name(current, new_call->macro_str, CIL_SYM_BLOCKS, extra_args, &macro_node);
		if (rc != SEPOL_OK) {
			goto exit;
		}
		if (macro_node->flavor != CIL_MACRO) {
			printf("Failed to resolve macro %s\n", new_call->macro_str);
			rc = SEPOL_ERR;
			goto exit;
		}
		new_call->macro = (struct cil_macro*)macro_node->data;
	} else {
		cil_log(CIL_ERR, "Macro string is null\n");
		rc = SEPOL_ERR;
		goto exit;
	}

	if (new_call->macro->params != NULL ) {

		struct cil_list_item *item = new_call->macro->params->head;
		struct cil_list_item *args_tail = NULL;
		struct cil_args *new_arg = NULL;
		struct cil_tree_node *pc = NULL;

		if (new_call->args_tree == NULL) {
			cil_log(CIL_ERR, "Missing arguments (%s, line: %d)\n", current->path, current->line);
			rc = SEPOL_ERR;
			goto exit;
		}

		pc = new_call->args_tree->root->cl_head;

		cil_list_init(&new_call->args);

		while (item != NULL) {
			if (item != NULL && pc == NULL) {
				cil_log(CIL_ERR, "Missing arguments (%s, line: %d)\n", current->path, current->line);
				rc = SEPOL_ERR;
				goto exit;
			}
			if (item->flavor != CIL_PARAM) {
				rc = SEPOL_ERR;
				goto exit;
			}

			cil_args_init(&new_arg);

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
			case CIL_BOOL:
				new_arg->arg_str = cil_strdup(pc->data);
				break;
			case CIL_CATSET: {
				if (pc->cl_head != NULL) {
					struct cil_catset *catset = NULL;
					cil_catset_init(&catset);
					rc = cil_fill_catset(pc->cl_head, catset);
					if (rc != SEPOL_OK) {
						cil_log(CIL_ERR, "Failed to create anonymous category set, rc: %d\n", rc);
						cil_destroy_catset(catset);
						goto exit;
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
					struct cil_level *level = NULL;
					struct cil_tree_node *lvl = NULL;
					cil_level_init(&level);

					rc = cil_fill_level(pc->cl_head, level);
					if (rc != SEPOL_OK) {
						cil_log(CIL_ERR, "Failed to create anonymous level, rc: %d\n", rc);
						cil_destroy_level(level);
						goto exit;
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
			case CIL_LEVELRANGE: {
				if (pc->cl_head != NULL) {
					struct cil_levelrange *range = NULL;
					struct cil_tree_node *range_node =NULL;
					cil_levelrange_init(&range);

					rc = cil_fill_levelrange(pc->cl_head, range);
					if (rc != SEPOL_OK) {
						cil_log(CIL_ERR, "Failed to create anonymous levelrange, rc: %d\n", rc);
						cil_destroy_levelrange(range);
						goto exit;
					}
					cil_tree_node_init(&range_node);
					range_node->flavor = CIL_LEVELRANGE;
					range_node->data = range;
					new_arg->arg = range_node;
				} else {
					new_arg->arg_str = cil_strdup(pc->data);
				}

				break;
			}
			case CIL_IPADDR: {
				if (pc->cl_head != NULL) {
					struct cil_ipaddr *ipaddr = NULL;
					struct cil_tree_node *addr_node = NULL;

					cil_ipaddr_init(&ipaddr);

					rc = cil_fill_ipaddr(pc->cl_head, ipaddr);
					if (rc != SEPOL_OK) {
						cil_log(CIL_ERR, "Failed to create anonymous ip address, rc; %d\n", rc);
						cil_destroy_ipaddr(ipaddr);
						goto exit;
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
			case CIL_CLASSMAP:
				new_arg->arg_str = cil_strdup(pc->data);
				break;
			case CIL_PERMSET: {
				if (pc->cl_head != NULL) {
					struct cil_permset *permset = NULL;
					struct cil_tree_node *permset_node = NULL;
					cil_permset_init(&permset);
					cil_list_init(&permset->perms_list_str);
					rc = cil_parse_to_list(pc->cl_head, permset->perms_list_str, CIL_AST_STR);
					if (rc != SEPOL_OK) {
						cil_log(CIL_ERR, "Failed to parse perms\n");
						goto exit;
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
			case CIL_CLASSPERMSET: {
				if (pc->cl_head != NULL) {
					struct cil_classpermset *cps = NULL;
					struct cil_tree_node *cps_node = NULL;

					cil_classpermset_init(&cps);
					rc = cil_fill_classpermset(pc->cl_head, cps);
					if (rc != SEPOL_OK) {
						cil_log(CIL_ERR, "Failed to create anonymous classpermset, rc: %d\n", rc);
						cil_destroy_classpermset(cps);
						goto exit;
					}
					cil_tree_node_init(&cps_node);
					cps_node->flavor = CIL_CLASSPERMSET;
					cps_node->data = cps;
					new_arg->arg = cps_node;
				} else {
					new_arg->arg_str = cil_strdup(pc->data);
				}
				break;
			}
			default:
				cil_log(CIL_ERR, "Unexpected flavor: %d\n", item->flavor);
				rc = SEPOL_ERR;
				goto exit;
			}
			new_arg->param_str = ((struct cil_param*)item->data)->str;
			new_arg->flavor = ((struct cil_param*)item->data)->flavor;

			if (args_tail == NULL) {
				cil_list_item_init(&new_call->args->head);
				new_call->args->head->flavor = CIL_ARGS;;
				new_call->args->head->data = new_arg;
				args_tail = new_call->args->head;
				args_tail->next = NULL;
			}
			else {
				cil_list_item_init(&args_tail->next);
				args_tail->next->flavor = CIL_ARGS;
				args_tail->next->data = new_arg;
				args_tail = args_tail->next;
				args_tail->next = NULL;
			}

			pc = pc->next;
			item = item->next;
		}

		if (pc != NULL) {
			cil_log(CIL_ERR, "Unexpected arguments (%s, line: %d)\n", current->path, current->line);
			rc = SEPOL_ERR;
			goto exit;
		}
	} else if (new_call->args_tree != NULL) {
		cil_log(CIL_ERR, "Rnexpected arguments (%s, line: %d)\n", current->path, current->line);
		rc = SEPOL_ERR;
		goto exit;
	}

	rc = cil_copy_ast(db, macro_node, current);
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Failed to copy macro, rc: %d\n", rc);
		goto exit;
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_resolve_call2(struct cil_tree_node *current, void *extra_args)
{
	struct cil_call *new_call = (struct cil_call*)current->data;
	int rc = SEPOL_ERR;
	enum cil_sym_index sym_index = CIL_SYM_UNKNOWN;
	struct cil_list_item *item = NULL;

	if (new_call->args == NULL) {
		rc = SEPOL_OK;
		goto exit;
	}

	for (item = new_call->args->head; item != NULL; item = item->next) {
		if (((struct cil_args*)item->data)->arg == NULL && ((struct cil_args*)item->data)->arg_str == NULL) {
			cil_log(CIL_ERR, "Arguments not created correctly\n");
			rc = SEPOL_ERR;
			goto exit;
		}

		switch (((struct cil_args*)item->data)->flavor) {
		case CIL_LEVEL:
			if ((((struct cil_args*)item->data)->arg_str == NULL) && ((struct cil_args*)item->data)->arg != NULL) {
				continue; // anonymous, no need to resolve
			} else {
				sym_index = CIL_SYM_LEVELS;
			}
			break;
		case CIL_LEVELRANGE:
			if ((((struct cil_args*)item->data)->arg_str == NULL) && ((struct cil_args*)item->data)->arg != NULL) {
				continue; // anonymous, no need to resolve
			} else {
				sym_index = CIL_SYM_LEVELRANGES;
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
		case CIL_CLASSPERMSET:
			if ((((struct cil_args*)item->data)->arg_str == NULL) && ((struct cil_args*)item->data)->arg != NULL) {
				continue;
			} else {
				sym_index = CIL_SYM_CLASSPERMSETS;
			}
			break;
		case CIL_TYPE:
			if ((((struct cil_args*)item->data)->arg_str == NULL) && ((struct cil_args*)item->data)->arg != NULL) {
				continue; // anonymous, no need to resolve
			} else {
				sym_index = CIL_SYM_TYPES;
			}
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
		case CIL_CLASSMAP:
			sym_index = CIL_SYM_CLASSES;
			break;
		case CIL_BOOL:
			sym_index = CIL_SYM_BOOLS;
			break;
		default:
			rc = SEPOL_ERR;
			goto exit;
		}

		if (sym_index != CIL_SYM_UNKNOWN) {
			rc = cil_resolve_name(current, ((struct cil_args*)item->data)->arg_str, sym_index, extra_args, &(((struct cil_args*)item->data)->arg));
			if (rc != SEPOL_OK) {
				goto exit;
			}
		}
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_resolve_name_call_args(struct cil_call *call, char *name, enum cil_sym_index sym_index, struct cil_tree_node **node)
{
	struct cil_list_item *item = NULL;
	enum cil_sym_index param_index = CIL_SYM_UNKNOWN;
	int rc = SEPOL_ERR;

	if (call == NULL || name == NULL) {
		goto exit;
	}

	if (call->args == NULL) {
		goto exit;
	}

	item = call->args->head;

	while(item != NULL) {
		rc = cil_flavor_to_symtab_index(((struct cil_args*)item->data)->flavor, &param_index);
		if (param_index == sym_index) {
			if (!strcmp(name, ((struct cil_args*)item->data)->param_str)) {
				*node = ((struct cil_args*)item->data)->arg;
				rc = SEPOL_OK;
				goto exit;
			}
		}
		item = item->next;
	}

	return SEPOL_ERR;

exit:
	return rc;
}

int cil_resolve_expr_stack(struct cil_list *expr_stack, struct cil_tree_node *parent, void *extra_args)
{
	int rc = SEPOL_ERR;
	struct cil_list_item *curr_expr = expr_stack->head;
	struct cil_tree_node *res_node = NULL;


	while (curr_expr != NULL) {
		struct cil_conditional *cond = curr_expr->data;
		enum cil_flavor flavor = cond->flavor;
		enum cil_sym_index sym_index =  CIL_SYM_UNKNOWN;

		switch (flavor) {
		case CIL_BOOL:
			sym_index = CIL_SYM_BOOLS;
			break;
		case CIL_TUNABLE:
			sym_index = CIL_SYM_TUNABLES;
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
		default:
			curr_expr = curr_expr->next;
			continue;
		}

		if (cond->str == NULL) {
			cil_log(CIL_ERR, "Invalid expression\n");
			rc = SEPOL_ERR;
			goto exit;
		}

		rc = cil_resolve_name(parent, cond->str, sym_index, extra_args, &res_node);
		if (rc != SEPOL_OK) {
			goto exit;
		}
		cond->data = res_node->data;

		curr_expr = curr_expr->next;
	}
	return SEPOL_OK;

exit:
	return rc;
}

int cil_resolve_boolif(struct cil_tree_node *current, void *extra_args)
{
	int rc = SEPOL_ERR;
	struct cil_booleanif *bif = (struct cil_booleanif*)current->data;

	rc = cil_resolve_expr_stack(bif->expr_stack, current, extra_args);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	return SEPOL_OK;

exit:
	return rc;
}

/* This modifies/destroys the original stack */
int cil_evaluate_expr_stack(struct cil_list *expr_stack, uint16_t *result)
{
	struct cil_conditional *cond = NULL;
	struct cil_list_item *curr = NULL;
	uint16_t eval_stack[COND_EXPR_MAXDEPTH];
	uint16_t value1 = CIL_FALSE;
	uint16_t value2 = CIL_FALSE;
	uint16_t pos = 0;
	int rc = SEPOL_ERR;

	if (expr_stack == NULL || result == NULL) {
		rc = SEPOL_ERR;
		goto exit;
	}

	curr = expr_stack->head;
	while (curr != NULL) {
		cond = curr->data;
		if ((cond->flavor == CIL_AND) || (cond->flavor == CIL_OR) 
		|| (cond->flavor == CIL_XOR) || (cond->flavor == CIL_NOT) 
		|| (cond->flavor == CIL_EQ) || (cond->flavor == CIL_NEQ)) {

			if (cond->flavor != CIL_NOT) {
				if (pos <= 1) {
					rc = SEPOL_ERR;
					goto exit;
				}
				value1 = eval_stack[pos - 1];
				value2 = eval_stack[pos - 2];
				if (cond->flavor == CIL_AND) {
					eval_stack[pos - 2] = (value1 && value2);
				} else if (cond->flavor == CIL_OR) {
					eval_stack[pos - 2] = (value1 || value2);
				} else if (cond->flavor == CIL_XOR) {
					eval_stack[pos - 2] = (value1 ^ value2);
				} else if (cond->flavor == CIL_EQ) {
					eval_stack[pos - 2] = (value1 == value2);
				} else if (cond->flavor == CIL_NEQ) {
					eval_stack[pos - 2] = (value1 != value2);
				}
				pos--;
			} else {
				if (pos == 0) {
					rc = SEPOL_ERR;
					goto exit;
				}
				eval_stack[pos - 1] = !eval_stack[pos - 1];
			}
		} else {
			struct cil_bool *bool = cond->data;
			if (pos >= COND_EXPR_MAXDEPTH) {
				rc = SEPOL_ERR;
				goto exit;
			}
			eval_stack[pos] = bool->value;
			pos++;
		}
		curr = curr->next;
	}

	*result = eval_stack[0];

	return SEPOL_OK;

exit:
	return rc;
}

int cil_resolve_tunif(struct cil_tree_node *current, void *extra_args)
{
	struct cil_args_resolve *args = extra_args;
	struct cil_db *db = NULL;
	int rc = SEPOL_ERR;
	struct cil_tunableif *tif = (struct cil_tunableif*)current->data;
	uint16_t result = CIL_FALSE;
	struct cil_tree_node *true_node = NULL;
	struct cil_tree_node *false_node = NULL;
	struct cil_condblock *cb = NULL;

	if (args != NULL) {
		db = args->db;
	}

	rc = cil_resolve_expr_stack(tif->expr_stack, current, extra_args);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	rc = cil_evaluate_expr_stack(tif->expr_stack, &result);
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Failed to evaluate expr stack\n");
		goto exit;
	}

	if (current->cl_head != NULL && current->cl_head->flavor == CIL_CONDBLOCK) {
		cb = current->cl_head->data;
		if (cb->flavor == CIL_CONDTRUE) {
			true_node = current->cl_head;
		} else if (cb->flavor == CIL_CONDFALSE) {
			false_node = current->cl_head;
		}
	}

	if (current->cl_head != NULL && current->cl_head->next != NULL && current->cl_head->next->flavor == CIL_CONDBLOCK) {
		cb = current->cl_head->next->data;
		if (cb->flavor == CIL_CONDTRUE) {
			true_node = current->cl_head->next;
		} else if (cb->flavor == CIL_CONDFALSE) {
			false_node = current->cl_head->next;
		}
	}

	if (result == CIL_TRUE) {
		if (true_node != NULL) {
			rc = cil_copy_ast(db, true_node, current->parent);
			if (rc != SEPOL_OK) {
				goto exit;
			}
		}
	} else {
		if (false_node != NULL) {
			rc = cil_copy_ast(db, false_node, current->parent);
			if (rc  != SEPOL_OK) {
				goto exit;
			}
		}
	}

	cil_tree_subtree_destroy(current->cl_head);
	current->cl_head = NULL;

	return SEPOL_OK;

exit:
	return rc;
}


int __cil_resolve_ast_node(struct cil_tree_node *node, void *extra_args)
{
	int rc = SEPOL_OK;
	struct cil_args_resolve *args = extra_args;
	enum cil_pass pass = 0;

	if (node == NULL || args == NULL) {
		goto exit;
	}

	pass = args->pass;

	switch (pass) {
	case CIL_PASS_TIF:
		if (node->flavor == CIL_TUNABLEIF) {
			rc = cil_resolve_tunif(node, args);
		}
		break;
	case CIL_PASS_IN:
		if (node->flavor == CIL_IN) {
			rc = cil_resolve_in(node, args);
		}
		break;
	case CIL_PASS_BLKIN:
		if (node->flavor == CIL_BLOCKINHERIT) {
			rc = cil_resolve_blockinherit(node, args);
		}
		break;
	case CIL_PASS_BLKABS:
		if (node->flavor == CIL_BLOCKABSTRACT) {
			rc = cil_resolve_blockabstract(node, args);
		}
		break;
	case CIL_PASS_CALL1:
		if (node->flavor == CIL_CALL) {
			rc = cil_resolve_call1(node, args);
		}
		break;
	case CIL_PASS_CALL2:
		if (node->flavor == CIL_CALL) {
			rc = cil_resolve_call2(node, args);
		}
		break;
	case CIL_PASS_MISC1:
		switch (node->flavor) {
		case CIL_CATORDER:
			rc = cil_resolve_catorder(node, args);
			break;
		case CIL_DOMINANCE:
			rc = cil_resolve_dominance(node, args);
			break;
		case CIL_CLASS:
			rc = cil_reset_class(node, args);
			break;
		case CIL_CLASSMAPPERM:
			rc = cil_reset_classmap_perm(node, args);
			break;
		case CIL_ROLE:
			rc = cil_reset_role(node, args);
			break;
		case CIL_TYPE:
			rc = cil_reset_type(node, args);
			break;
		case CIL_USER:
			rc = cil_reset_user(node, args);
			break;
		case CIL_TYPEATTRIBUTE:
			rc = cil_reset_typeattr(node, args);
			break;
		case CIL_SENS:
			rc = cil_reset_sens(node, args);
			break;
		case CIL_SID:
			rc = cil_reset_sid(node, args);
			break;
		case CIL_BOOLEANIF:
			rc = cil_resolve_boolif(node, args);
			break;
		}
		break;
	case CIL_PASS_MLS:
		switch (node->flavor) {
		case CIL_CATRANGE:
			rc = cil_resolve_catrange(node, (struct cil_catrange*)node->data, args);
			break;
		case CIL_CATSET:
			rc = cil_resolve_catset(node, (struct cil_catset*)node->data, args);
			break;
		case CIL_SENSALIAS:
			rc = cil_resolve_sensalias(node, args);
			break;
		}
		break;
	case CIL_PASS_MISC2:
		switch (node->flavor) {
		case CIL_SENSCAT:
			rc = cil_resolve_senscat(node, args);
			break;
		case CIL_CLASSCOMMON:
			rc = cil_resolve_classcommon(node, args);
			break;
		case CIL_TYPEALIAS:
			rc = cil_resolve_typealias(node, args);
			break;
		}
		break;
	case CIL_PASS_MISC3:
		switch (node->flavor) {
		case CIL_TYPEATTRIBUTESET:
			rc = cil_resolve_typeattributeset(node, args);
			break;
		case CIL_TYPEALIAS:
			rc = cil_resolve_typealias_to_type(node);
			break;
		case CIL_TYPEBOUNDS:
			rc = cil_resolve_typebounds(node, args);
			break;
		case CIL_TYPEPERMISSIVE:
			rc = cil_resolve_typepermissive(node, args);
			break;
		case CIL_FILETRANSITION:
			rc = cil_resolve_filetransition(node, args);
			break;
		case CIL_RANGETRANSITION:
			rc = cil_resolve_rangetransition(node, args);
			break;
		case CIL_CLASSPERMSET:
			rc = cil_resolve_classpermset(node, (struct cil_classpermset*)node->data, args);
			break;
		case CIL_CLASSMAPPING:
			rc = cil_resolve_classmapping(node, args);
			break;
		case CIL_AVRULE:
			rc = cil_resolve_avrule(node, args);
			break;
		case CIL_TYPE_RULE:
			rc = cil_resolve_type_rule(node, args);
			break;
		case CIL_USERROLE:
			rc = cil_resolve_userrole(node, args);
			break;
		case CIL_USERLEVEL:
			rc = cil_resolve_userlevel(node, args);
			break;
		case CIL_USERRANGE:
			rc = cil_resolve_userrange(node, args);
			break;
		case CIL_USERBOUNDS:
			rc = cil_resolve_userbounds(node, args);
			break;
		case CIL_USERPREFIX:
			rc = cil_resolve_userprefix(node, args);
			break;
		case CIL_SELINUXUSER:
		case CIL_SELINUXUSERDEFAULT:
			rc = cil_resolve_selinuxuser(node, args);
			break;
		case CIL_ROLETYPE:
			rc = cil_resolve_roletype(node, args);
			break;
		case CIL_ROLETRANSITION:
			rc = cil_resolve_roletransition(node, args);
			break;
		case CIL_ROLEALLOW:
			rc = cil_resolve_roleallow(node, args);
			break;
		case CIL_ROLEDOMINANCE:
			rc = cil_resolve_roledominance(node, args);
			break;
		case CIL_ROLEBOUNDS:
			rc = cil_resolve_rolebounds(node, args);
			break;
		case CIL_CATALIAS:
			rc = cil_resolve_catalias(node, args);
			break;
		case CIL_LEVEL:
			rc = cil_resolve_level(node, (struct cil_level*)node->data, args);
			break;
		case CIL_LEVELRANGE:
			rc = cil_resolve_levelrange(node, (struct cil_levelrange*)node->data, args);
			break;
		case CIL_CONSTRAIN:
			rc = cil_resolve_constrain(node, args);
			break;
		case CIL_MLSCONSTRAIN:
			rc = cil_resolve_constrain(node, args);
			break;
		case CIL_VALIDATETRANS:
		case CIL_MLSVALIDATETRANS:
			rc = cil_resolve_validatetrans(node, args);
			break;
		case CIL_CONTEXT:
			rc = cil_resolve_context(node, (struct cil_context*)node->data, args);
			break;
		case CIL_FILECON:
			rc = cil_resolve_filecon(node, args);
			break;
		case CIL_PORTCON:
			rc = cil_resolve_portcon(node, args);
			break;
		case CIL_NODECON:
			rc = cil_resolve_nodecon(node, args);
			break;
		case CIL_GENFSCON:
			rc = cil_resolve_genfscon(node, args);
			break;
		case CIL_NETIFCON:
			rc = cil_resolve_netifcon(node, args);
			break;
		case CIL_PIRQCON:
			rc = cil_resolve_pirqcon(node, args);
			break;
		case CIL_IOMEMCON:
			rc = cil_resolve_iomemcon(node, args);
			break;
		case CIL_IOPORTCON:
			rc = cil_resolve_ioportcon(node, args);
			break;
		case CIL_PCIDEVICECON:
			rc = cil_resolve_pcidevicecon(node, args);
			break;
		case CIL_FSUSE:
			rc = cil_resolve_fsuse(node, args);
			break;
		case CIL_SIDCONTEXT:
			rc = cil_resolve_sidcontext(node, args);
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}

	return rc;

exit:
	return rc;
}

int __cil_resolve_ast_node_helper(struct cil_tree_node *node, __attribute__((unused)) uint32_t *finished, void *extra_args)
{
	int rc = SEPOL_ERR;
	struct cil_args_resolve *args = extra_args;
	enum cil_pass pass = 0;
	struct cil_tree_node *optstack = NULL;
	uint32_t *changed = NULL;

	if (node == NULL || args == NULL) {
		goto exit;
	}

	if (args != NULL) {
		changed = args->changed;
		optstack = args->optstack;
		pass = args->pass;
	}

	if (optstack != NULL) {
		if (node->flavor == CIL_TUNABLE || node->flavor == CIL_MACRO) {
			/* tuanbles and macros are not allowed in optionals*/
			cil_log(CIL_ERR, "%s statment is not allowed in optionals (%s:%d)\n", cil_node_to_string(node), node->path, node->line);
			rc = SEPOL_ERR;
			goto exit;
		}
	}

	if (node->flavor == CIL_MACRO) {
		if (pass > CIL_PASS_TIF) {
			*finished = CIL_TREE_SKIP_HEAD;
			rc = SEPOL_OK;
			goto exit;
		}
	}

	if (node->flavor == CIL_OPTIONAL && ((struct cil_symtab_datum *)node->data)->state == CIL_STATE_DISABLED) {
		/* don't try to resolve children of a disabled optional */
		*finished = CIL_TREE_SKIP_HEAD;
		rc = SEPOL_OK;
		goto exit;
	}

	if (node->flavor == CIL_BLOCK && ((((struct cil_block*)node->data)->is_abstract == CIL_TRUE) && (pass > CIL_PASS_BLKABS))) {
		*finished = CIL_TREE_SKIP_HEAD;
		rc = SEPOL_OK;
		goto exit;
	}

	rc = __cil_resolve_ast_node(node, extra_args);
	if (rc == SEPOL_ENOENT && optstack != NULL) {
		struct cil_optional *opt = (struct cil_optional *)optstack->data;
		cil_log(CIL_WARN, "Disabling %s optional-statement (%s:%d)\n", opt->datum.name, node->parent->path, node->parent->line);
		/* disable an optional if something failed to resolve */
		opt->datum.state = CIL_STATE_DISABLING;
		/* let the resolve loop know something was changed */
		*changed = 1;
		rc = SEPOL_OK;
	} else if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Failed to resolve %s-statement (%s:%d)\n", cil_node_to_string(node), node->path, node->line);
		goto exit;
	}

	return rc;

exit:
	return rc;
}

int __cil_disable_children_helper(struct cil_tree_node *node, uint32_t *finished, __attribute__((unused)) void *extra_args)
{
	int rc = SEPOL_ERR;

	if (node == NULL || finished == NULL) {
		goto exit;
	}

	if (node->flavor < CIL_MIN_DECLARATIVE) {
		/* only declarative statements need to be disabled */
		rc = SEPOL_OK;
		goto exit;
	}

	if (node->flavor == CIL_OPTIONAL) {
		if (((struct cil_symtab_datum *)node->data)->state == CIL_STATE_DISABLED) {
			/* don't bother going into an optional that isn't enabled */
			*finished = CIL_TREE_SKIP_HEAD;
			rc = SEPOL_OK;
			goto exit;
		}
	}

	((struct cil_symtab_datum *)node->data)->state = CIL_STATE_DISABLED;

	return SEPOL_OK;

exit:
	return rc;
}

int __cil_resolve_ast_first_child_helper(struct cil_tree_node *current, void *extra_args)
{
	int rc = SEPOL_ERR;
	struct cil_args_resolve *args = extra_args;
	struct cil_tree_node *callstack = NULL;
	struct cil_tree_node *optstack = NULL;
	struct cil_tree_node *parent = NULL;

	if (current == NULL || extra_args == NULL) {
		goto exit;
	}

	callstack = args->callstack;
	optstack = args->optstack;
	parent = current->parent;

	if (parent->flavor == CIL_CALL || parent->flavor == CIL_OPTIONAL) {
		/* push this node onto a stack */
		struct cil_tree_node *new;
		cil_tree_node_init(&new);

		new->data = parent->data;
		new->flavor = parent->flavor;

		if (parent->flavor == CIL_CALL) {
			if (callstack != NULL) {
				struct cil_tree_node *curr = NULL;
				for (curr = callstack->cl_head; curr != NULL;
					curr = curr->cl_head) {
					struct cil_call *curr_call = curr->data;
					struct cil_call *new_call = new->data;
					if (curr_call->macro == new_call->macro) {
						cil_log(CIL_ERR, "Recursive macro call found\n");
						rc = SEPOL_ERR;
						goto exit;
					}
				}
				callstack->parent = new;
				new->cl_head = callstack;
			}
			args->callstack = new;
		} else if (parent->flavor == CIL_OPTIONAL) {
			if (optstack != NULL) {
				optstack->parent = new;
				new->cl_head = optstack;
			}
			args->optstack = new;
		}
	} else if (parent->flavor == CIL_MACRO) {
		args->macro = parent;
	}

	return SEPOL_OK;

exit:
	return rc;

}

int __cil_resolve_ast_last_child_helper(struct cil_tree_node *current, void *extra_args)
{
	int rc = SEPOL_ERR;
	struct cil_args_resolve *args = extra_args;
	struct cil_tree_node *parent = NULL;

	if (current == NULL ||  extra_args == NULL) {
		goto exit;
	}

	parent = current->parent;

	if (parent->flavor == CIL_CALL) {
		/* pop off the stack */
		struct cil_tree_node *callstack = args->callstack;
		args->callstack = callstack->cl_head;
		if (callstack->cl_head) {
			callstack->cl_head->parent = NULL;
		}
		free(callstack);
	} else if (parent->flavor == CIL_MACRO) {
		args->macro = NULL;
	} else if (parent->flavor == CIL_OPTIONAL) {
		struct cil_tree_node *optstack;

		if (((struct cil_optional *)parent->data)->datum.state == CIL_STATE_DISABLING) {
			/* go into the optional, removing everything that it added */
			rc = cil_tree_walk(parent, __cil_disable_children_helper, NULL, NULL, NULL);
			if (rc != SEPOL_OK) {
				cil_log(CIL_ERR, "Failed to disable optional children\n");
				goto exit;
			}
			((struct cil_optional *)parent->data)->datum.state = CIL_STATE_DISABLED;
		}

		/* pop off the stack */
		optstack = args->optstack;
		args->optstack = optstack->cl_head;
		if (optstack->cl_head) {
			optstack->cl_head->parent = NULL;
		}
		free(optstack);
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_resolve_ast(struct cil_db *db, struct cil_tree_node *current)
{
	int rc = SEPOL_ERR;
	struct cil_args_resolve extra_args;
	enum cil_pass pass = CIL_PASS_TIF;
	uint32_t changed = 0;

	if (db == NULL || current == NULL) {
		goto exit;
	}

	extra_args.db = db;
	extra_args.pass = pass;
	extra_args.changed = &changed;
	extra_args.callstack = NULL;
	extra_args.optstack = NULL;
	extra_args.macro = NULL;

	for (pass = CIL_PASS_TIF; pass < CIL_PASS_NUM; pass++) {
#ifdef DEBUG
		cil_log(CIL_INFO, "---------- Pass %i ----------\n", pass);
#endif
		extra_args.pass = pass;
		rc = cil_tree_walk(current, __cil_resolve_ast_node_helper, __cil_resolve_ast_first_child_helper, __cil_resolve_ast_last_child_helper, &extra_args);
		if (rc != SEPOL_OK) {
			cil_log(CIL_INFO, "Pass %i of resolution failed\n", pass);
			goto exit;
		}

#ifdef DEBUG
		cil_tree_print(db->ast->root, 0);
#endif

		if (pass == CIL_PASS_MISC1) {
#ifdef DEBUG
			cil_log(CIL_INFO, "----- Verify Catorder ------\n");
#endif
			rc = __cil_verify_order(db->catorder, current, CIL_CAT);
			if (rc != SEPOL_OK) {
				cil_log(CIL_ERR, "Failed to verify categoryorder\n");
				goto exit;
			}
#ifdef DEBUG
			cil_log(CIL_INFO, "----- Verify Dominance -----\n");
#endif
			rc = __cil_verify_order(db->dominance, current, CIL_SENS);
			if (rc != SEPOL_OK) {
				cil_log(CIL_ERR, "Failed to verify dominance\n");
				goto exit;
			}
		}

		if (changed) {
#ifdef DEBUG
			cil_log(CIL_INFO, "----- Redoing resolve passes -----\n");
#endif
			/* Need to re-resolve because an optional was disabled. We only
			 * need to reset to the call1 pass because things done in the preceeding
			 * passes aren't allowed in optionals, and thus can't be disabled.
			 * Note: set pass to CIL_PASS_CALL1 because the pass++ will increment it to BLK_CALL1 */
			pass = CIL_PASS_CALL1;
			/* reset the global data */
			cil_list_destroy(&db->catorder, 0);
			cil_list_destroy(&db->dominance, 0);
			cil_list_init(&db->catorder);
			cil_list_init(&db->dominance);
		}

		/* reset the arguments */
		changed = 0;
		while (extra_args.callstack != NULL) {
			struct cil_tree_node *curr = extra_args.callstack;
			struct cil_tree_node *next = curr->cl_head;
			free(curr);
			extra_args.callstack = next;
		}
		while (extra_args.optstack != NULL) {
			struct cil_tree_node *curr = extra_args.optstack;
			struct cil_tree_node *next = curr->cl_head;
			free(curr);
			extra_args.optstack = next;
		}
	}

	rc = SEPOL_OK;
exit:
	return rc;
}

static int __cil_resolve_name_helper(struct cil_tree_node *ast_node, char *name, enum cil_sym_index sym_index, void *extra_args, struct cil_tree_node **node)
{
	struct cil_args_resolve *args = extra_args;
	struct cil_db *db = NULL;
	struct cil_call *call = NULL;
	struct cil_tree_node *macro = NULL;
	enum cil_pass pass = CIL_PASS_INIT;

	int rc = SEPOL_ERR;
	char* name_dup = cil_strdup(name);
	char *tok_current = strtok(name_dup, ".");
	char *tok_next = strtok(NULL, ".");
	symtab_t *symtab = NULL;
	struct cil_tree_node *tmp_node = NULL;

	if (args != NULL) {
		db = args->db;
		if (args->callstack != NULL) {
			call = args->callstack->data;
		}
		pass = args->pass;
		macro = args->macro;
	}

	if (ast_node->flavor == CIL_ROOT) {
		symtab = &(db->symtab[CIL_SYM_BLOCKS]);
	} else {
		if (call != NULL) {
			// check macro symtab
			symtab = &call->macro->symtab[CIL_SYM_BLOCKS];
			rc = cil_symtab_get_node(symtab, tok_current, node);
			if (rc == SEPOL_OK) {
				if ((*node)->flavor != CIL_BLOCK) {
					printf("Failed to get block from symtab\n");
					rc = SEPOL_ERR;
					goto exit;
				}
				// if in macro, check call parent to verify successful copy to call
				rc = cil_get_symtab(db, ast_node->parent->parent, &symtab, CIL_SYM_BLOCKS);
				if (rc == SEPOL_OK) {
					rc = cil_symtab_get_node(symtab, tok_current, node);
					if (rc != SEPOL_OK) {
						cil_log(CIL_ERR, "Failed to get node from parent symtab of call\n");
						goto exit;
					} else if ((*node)->flavor != CIL_BLOCK) {
						printf("Failed to get block from symtab\n");
						rc = SEPOL_ERR;
						goto exit;
					}
				} else {
					cil_log(CIL_ERR, "Failed to get symtab from call parent\n");
					goto exit;
				}
			} else if (rc == SEPOL_ENOENT) {
				rc = cil_get_symtab(db, call->macro->datum.node->parent, &symtab, CIL_SYM_BLOCKS);
				if (rc != SEPOL_OK) {
					cil_log(CIL_ERR, "Failed to get node from parent symtab of macro\n");
					goto exit;
				} else {
					symtab = &(db->symtab[CIL_SYM_BLOCKS]);
				}
			} else {
				goto exit;
			}

		} else {
			if (ast_node->flavor == CIL_TUNABLEIF && macro != NULL) {
				rc = cil_get_symtab(db, macro->parent, &symtab, CIL_SYM_BLOCKS);
			} else {
				rc = cil_get_symtab(db, ast_node->parent, &symtab, CIL_SYM_BLOCKS);
			}
			if (rc != SEPOL_OK) {
				cil_log(CIL_ERR, "Failed to get parent symtab, rc: %d\n", rc);
				goto exit;
			}
		}
	}

	if (tok_next == NULL) {
		/*TODO: Should this set rc to SEPOL_ERR? */
		/* Cant this be done earlier */
		goto exit;
	}

	while (tok_current != NULL) {
		if (tok_next != NULL) {
			rc = cil_symtab_get_node(symtab, tok_current, &tmp_node);
			if (rc != SEPOL_OK) {
				goto exit;
			} else if ((tmp_node->flavor != CIL_BLOCK && ast_node->flavor != CIL_IN) ||
					(tmp_node->flavor == CIL_BLOCK && (((struct cil_block*)tmp_node->data)->is_abstract == CIL_TRUE && pass > CIL_PASS_BLKABS ))) {
				printf("Failed to resolve block: %s\n", tok_current);
				rc = SEPOL_ERR;
				goto exit;
			}
			symtab = &(((struct cil_block*)tmp_node->data)->symtab[CIL_SYM_BLOCKS]);
		} else {
			//cil_log(CIL_ERR, "type key: %s\n", tok_current);
			symtab = &(((struct cil_block*)tmp_node->data)->symtab[sym_index]);
			rc = cil_symtab_get_node(symtab, tok_current, &tmp_node);
			if (rc != SEPOL_OK) {
				cil_log(CIL_ERR, "Failed to resolve name, current: %s\n", tok_current);
				goto exit;
			}
		}
		tok_current = tok_next;
		tok_next = strtok(NULL, ".");
	}
	*node = tmp_node;
	free(name_dup);

	return SEPOL_OK;

exit:
	free(name_dup);
	return rc;
}

int cil_resolve_name(struct cil_tree_node *ast_node, char *name, enum cil_sym_index sym_index, void *extra_args, struct cil_tree_node **node)
{
	struct cil_args_resolve *args = extra_args;
	struct cil_db *db = NULL;
	struct cil_call *call = NULL;
	struct cil_tree_node *macro = NULL;
	int rc = SEPOL_ERR;
	char *global_symtab_name = NULL;
	char first;

	if (args != NULL) {
		db = args->db;
		if (args->callstack != NULL) {
			call = args->callstack->data;
		}
		macro = args->macro;
	}

	if (db == NULL || ast_node == NULL || name == NULL) {
		cil_log(CIL_ERR, "Invalid call to cil_resolve_name\n");
		goto exit;
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
					rc = cil_get_symtab(db, ast_node->parent->parent, &symtab, sym_index);
					if (rc == SEPOL_OK) {
						rc = cil_symtab_get_node(symtab, name, node);
						if (rc != SEPOL_OK) {
							cil_log(CIL_ERR, "Failed to get node from parent symtab of call\n");
						}
						goto exit;
					} else {
						cil_log(CIL_ERR, "Failed to get parent symtab from call\n");
						goto exit;
					}

				} else {
					rc = cil_resolve_name_call_args(call, name, sym_index, node);
					if (rc == SEPOL_OK) {
						goto exit;
					}

					rc = cil_get_symtab(db, call->macro->datum.node->parent, &symtab, sym_index);
					if (rc != SEPOL_OK) {
						goto exit;
					}

					rc = cil_symtab_get_node(symtab, name, node);
					if (rc == SEPOL_OK) {
						goto exit;
					}

					global_symtab_name = cil_malloc(strlen(name)+2);
					strcpy(global_symtab_name, ".");
					strncat(global_symtab_name, name, strlen(name));
				}
			} else {
				if (ast_node->flavor == CIL_TUNABLEIF && macro != NULL) {
					rc = cil_get_symtab(db, macro->parent, &symtab, sym_index);
				} else {
					rc = cil_get_symtab(db, ast_node->parent, &symtab, sym_index);
				}
				if (rc != SEPOL_OK) {
					cil_log(CIL_ERR, "Failed to get parent symtab, rc: %d\n", rc);
					goto exit;
				}
				rc = cil_symtab_get_node(symtab, name, node);
				if (rc != SEPOL_OK) {
					global_symtab_name = cil_malloc(strlen(name)+2);
					strcpy(global_symtab_name, ".");
					strncat(global_symtab_name, name, strlen(name));
				}
			}
		} else {
			rc = __cil_resolve_name_helper(ast_node, name, sym_index, args, node);
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
				goto exit;
			}
		} else {
			rc = __cil_resolve_name_helper(db->ast->root, global_symtab_name, sym_index, args, node);
			if (rc != SEPOL_OK) {
				free(global_symtab_name);
				goto exit;
			}
		}
	}

	if (global_symtab_name != name) {
		free(global_symtab_name);
	}

	return SEPOL_OK;

exit:
	if (rc != SEPOL_OK) {
		cil_log(CIL_WARN, "Failed to resolve %s in %s-statement (%s:%d)\n", name, cil_node_to_string(ast_node), ast_node->path, ast_node->line);
	}
	return rc;
}
