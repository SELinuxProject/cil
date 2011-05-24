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

int __cil_resolve_perm_list(struct cil_class *class, struct cil_list *perm_list_str, struct cil_list *res_list_perms)
{
	struct cil_tree_node *perm_node;
	struct cil_list_item *perm = perm_list_str->head;
	struct cil_list_item *list_item;
	struct cil_list_item *list_tail;
	int rc = SEPOL_ERR;
	while (perm != NULL) {
		rc = cil_symtab_get_node(&class->perms, (char*)perm->data, &perm_node);
		if (rc == SEPOL_ENOENT) {
			if (class->common != NULL) {
				rc = cil_symtab_get_node(&class->common->perms, (char*)perm->data, &perm_node);
				if (rc != SEPOL_OK) {
					printf("Failed to find perm in class or common symtabs\n");
					return rc;
				}
			}
			else {
				printf("Failed to find perm in class symtab\n");
				return rc;
			}
		} else if (rc != SEPOL_OK) {
			return rc;
		}
		if (res_list_perms != NULL) {
			cil_list_item_init(&list_item);
			list_item->flavor = CIL_PERM;
			list_item->data = perm_node->data;
			if (res_list_perms->head == NULL) 
				res_list_perms->head = list_item;
			else 
				list_tail->next = list_item;
			list_tail = list_item;
		}
		perm = perm->next;
	}

	return SEPOL_OK;
}

int cil_resolve_avrule(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call)
{
	struct cil_avrule *rule = (struct cil_avrule*)current->data;
	struct cil_tree_node *src_node = NULL;
	struct cil_tree_node *tgt_node = NULL;
	struct cil_tree_node *obj_node = NULL;

	int rc = SEPOL_ERR;
	
	rc = cil_resolve_name(db, current, rule->src_str, CIL_SYM_TYPES, CIL_TYPE, call, &src_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", rule->src_str);
		return rc;
	}
	rule->src = (struct cil_type*)(src_node->data);
					
	rc = cil_resolve_name(db, current, rule->tgt_str, CIL_SYM_TYPES, CIL_TYPE, call, &tgt_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", rule->tgt_str);
		return rc;
	}
	rule->tgt = (struct cil_type*)(tgt_node->data);

	rc = cil_resolve_name(db, current, rule->obj_str, CIL_SYM_CLASSES, CIL_CLASS, call, &obj_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", rule->obj_str);
		return rc;
	}
	else {
		rule->obj = (struct cil_class*)(obj_node->data);
	}
	struct cil_list *perms_list;
	cil_list_init(&perms_list);
	rc = __cil_resolve_perm_list(rule->obj, rule->perms_str, perms_list);
	if (rc != SEPOL_OK) {
		printf("Failed to resolve perm list\n");
		return rc;
	}
	rule->perms_list = perms_list;

	return SEPOL_OK;
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
		return rc;
	}
	rule->src = (struct cil_type*)(src_node->data);
					
	rc = cil_resolve_name(db, current, rule->tgt_str, CIL_SYM_TYPES, CIL_TYPE, call, &tgt_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", rule->tgt_str);
		return rc;
	}
	rule->tgt = (struct cil_type*)(tgt_node->data);

	rc = cil_resolve_name(db, current, rule->obj_str, CIL_SYM_CLASSES, CIL_CLASS, call, &obj_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", rule->obj_str);
		return rc;
	}
	rule->obj = (struct cil_class*)(obj_node->data);

	rc = cil_resolve_name(db, current, rule->result_str, CIL_SYM_TYPES, CIL_TYPE, call, &result_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", rule->result_str);
		return rc;
	}
	rule->result = (struct cil_type*)(result_node->data);

	return SEPOL_OK;
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
		return rc;
	}
	typeattr->type = (struct cil_type*)(type_node->data);

	rc = cil_resolve_name(db, current, typeattr->attr_str, CIL_SYM_TYPES, CIL_TYPE, call, &attr_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", typeattr->attr_str);
		return rc;
	}
	typeattr->attr = (struct cil_type*)(attr_node->data);

	return SEPOL_OK;
}

int cil_resolve_typealias(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call)
{
	struct cil_typealias *alias = (struct cil_typealias*)current->data;
	struct cil_tree_node *type_node = NULL;
	int rc = cil_resolve_name(db, current, alias->type_str, CIL_SYM_TYPES, CIL_TYPE, call, &type_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", alias->type_str);
		return rc;
	}
	alias->type = (struct cil_type*)(type_node->data);

	return SEPOL_OK;
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
		return rc;
	}
	typebnds->parent = (struct cil_type*)(parent_node->data);

	rc = cil_resolve_name(db, current, typebnds->child_str, CIL_SYM_TYPES, CIL_TYPE, call, &child_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", typebnds->child_str);
		return rc;
	}
	typebnds->child = (struct cil_type*)(child_node->data);

	return SEPOL_OK;
}

int cil_resolve_classcommon(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call)
{
	struct cil_classcommon *clscom = (struct cil_classcommon*)current->data;
	struct cil_tree_node *class_node = NULL;
	struct cil_tree_node *common_node = NULL;

	int rc = cil_resolve_name(db, current, clscom->class_str, CIL_SYM_CLASSES, CIL_CLASS, call, &class_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", clscom->class_str);
		return rc;
	}
	clscom->class = (struct cil_class*)(class_node->data);

	rc = cil_resolve_name(db, current, clscom->common_str, CIL_SYM_COMMONS, CIL_COMMON, call, &common_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", clscom->common_str);
		return rc;
	}
	clscom->common = (struct cil_common*)(common_node->data);

	clscom->class->common = clscom->common;

	return SEPOL_OK;
}

int cil_resolve_userrole(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call)
{
	struct cil_userrole *userrole = (struct cil_userrole*)current->data;
	struct cil_tree_node *user_node = NULL;
	struct cil_tree_node *role_node = NULL;

	int rc = cil_resolve_name(db, current, userrole->user_str, CIL_SYM_USERS, CIL_USER, call, &user_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", userrole->user_str);
		return rc;
	} 
	userrole->user = (struct cil_user*)(user_node->data);

	rc = cil_resolve_name(db, current, userrole->role_str, CIL_SYM_ROLES, CIL_ROLE, call, &role_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", userrole->role_str);
		return rc;
	} 
	userrole->role = (struct cil_role*)(role_node->data);

	return SEPOL_OK;	
}

int cil_resolve_roletype(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call)
{
	struct cil_roletype *roletype = (struct cil_roletype*)current->data;
	struct cil_tree_node *role_node = NULL;
	struct cil_tree_node *type_node = NULL;
	
	int rc = cil_resolve_name(db, current, roletype->role_str, CIL_SYM_ROLES, CIL_ROLE, call, &role_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", roletype->role_str);
		return rc;
	}
	roletype->role = (struct cil_role*)(role_node->data);
	
	rc = cil_resolve_name(db, current, roletype->type_str, CIL_SYM_TYPES, CIL_TYPE, call, &type_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", roletype->type_str);
		return rc;
	}
	roletype->type = (struct cil_type*)(type_node->data);

	return SEPOL_OK;
}

int cil_resolve_roletrans(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call)
{
	struct cil_role_trans *roletrans = (struct cil_role_trans*)current->data;
	struct cil_tree_node *src_node = NULL;
	struct cil_tree_node *tgt_node = NULL;
	struct cil_tree_node *result_node = NULL;
	int rc = SEPOL_ERR;

	rc = cil_resolve_name(db, current, roletrans->src_str, CIL_SYM_ROLES, CIL_ROLE, call, &src_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", roletrans->src_str);
		return rc;
	}
	roletrans->src = (struct cil_role*)(src_node->data);
					
	rc = cil_resolve_name(db, current, roletrans->tgt_str, CIL_SYM_TYPES, CIL_TYPE, call, &tgt_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", roletrans->tgt_str);
		return rc;
	}
	roletrans->tgt = (struct cil_type*)(tgt_node->data);

	rc = cil_resolve_name(db, current, roletrans->result_str, CIL_SYM_ROLES, CIL_ROLE, call, &result_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", roletrans->result_str);
		return rc;
	}
	roletrans->result = (struct cil_role*)(result_node->data);

	return SEPOL_OK;	
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
		return rc;
	}
	roleallow->src = (struct cil_role*)(src_node->data);

	rc = cil_resolve_name(db, current, roleallow->tgt_str, CIL_SYM_ROLES, CIL_ROLE, call, &tgt_node);	
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", roleallow->tgt_str);
		return rc;
	}
	roleallow->tgt = (struct cil_role*)(tgt_node->data);

	return SEPOL_OK;	
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
		return rc;
	}
	roledom->role = (struct cil_role*)(role_node->data);

	rc = cil_resolve_name(db, current, roledom->domed_str, CIL_SYM_ROLES, CIL_ROLE, call, &domed_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", roledom->domed_str);
		return rc;
	}
	roledom->domed = (struct cil_role*)(domed_node->data);

	return SEPOL_OK;
}

int cil_resolve_sensalias(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call)
{
	struct cil_sensalias *alias = (struct cil_sensalias*)current->data;
	struct cil_tree_node *sens_node = NULL;
	int rc = cil_resolve_name(db, current, alias->sens_str, CIL_SYM_SENS, CIL_SENS, call, &sens_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", alias->sens_str);
		return rc;
	}
	alias->sens = (struct cil_sens*)(sens_node->data);

	return SEPOL_OK;
}

int cil_resolve_catalias(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call)
{
	struct cil_catalias *alias = (struct cil_catalias*)current->data;
	struct cil_tree_node *cat_node = NULL;
	int rc = cil_resolve_name(db, current, alias->cat_str, CIL_SYM_CATS, CIL_CAT, call, &cat_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", alias->cat_str);
		return rc;
	}
	alias->cat = (struct cil_cat*)(cat_node->data);

	return SEPOL_OK;
}

int __cil_set_append(struct cil_list_item *main_list_item, struct cil_list_item *new_list_item, int *success)
{
	if (main_list_item == NULL || new_list_item == NULL)
		return SEPOL_ERR;

	if (main_list_item->data == new_list_item->data && main_list_item->next == NULL) { 
		main_list_item->next = new_list_item->next;
		*success = 1;
		return SEPOL_OK;
	}
	else {
		while (main_list_item != NULL || new_list_item != NULL) {
			if (main_list_item->data != new_list_item->data) {
				printf("Error: categoryorder adjacency mismatch\n");
				return SEPOL_ERR;
			}
			main_list_item = main_list_item->next;
			new_list_item = new_list_item->next;
		}
		*success = 1;
		return SEPOL_OK;
	}

	return SEPOL_OK;
}

int __cil_set_prepend(struct cil_list *main_list, struct cil_list *new_list, struct cil_list_item *main_list_item, struct cil_list_item *new_list_item, int *success)
{
	if (main_list_item == NULL || new_list_item == NULL)
		return SEPOL_ERR;

	if (new_list_item->next != NULL) {
		printf("Invalid list item given to prepend to list: Has next item\n");
		return SEPOL_ERR;
	}

	struct cil_list_item *new_list_iter;
	int rc = SEPOL_ERR;

	if (main_list_item == main_list->head) {
		new_list_iter = new_list->head;
		while (new_list_iter != NULL) {
			if (new_list_iter->next == new_list_item) {
				new_list_iter->next = NULL;
				rc = cil_list_prepend_item(main_list, new_list_iter);
				if (rc != SEPOL_OK) {
					printf("Failed to prepend item to list\n");
					return rc;
				}
				*success = 1;
				return SEPOL_OK;
			}
		}
		return SEPOL_ERR;
	}
	else {
		printf("Error: Attempting to prepend to not the head of the list\n");
		return SEPOL_ERR;
	}

	return SEPOL_OK;
}

int __cil_set_merge_lists(struct cil_list *primary, struct cil_list *new, int *success)
{
	if (primary == NULL && new == NULL)
		return SEPOL_ERR;

	struct cil_list_item *curr_main = primary->head;
	struct cil_list_item *curr_new;
	int rc = SEPOL_ERR;
	while (curr_main != NULL) {
		curr_new = new->head;
		while (curr_new != NULL) {
			if (curr_main->data == curr_new->data) {
				if (curr_new->next == NULL) {
					rc = __cil_set_prepend(primary, new, curr_main, curr_new, success);
					if (rc != SEPOL_OK) {
						printf("Failed to prepend categoryorder sublist to primary list\n");
						return rc;
					}
					return SEPOL_OK;
				}
				else {
					rc = __cil_set_append(curr_main, curr_new, success);
					if (rc != SEPOL_OK) {
						printf("Failed to append categoryorder sublist to primary list\n");
						return rc;
					}
					return SEPOL_OK;
				}
			}
			curr_new = curr_new->next;
		}
		curr_main = curr_main->next;
	}

	return SEPOL_OK;
}

int __cil_set_remove_list(struct cil_list *catorder, struct cil_list *remove_item)
{
	struct cil_list_item *list_item;

	list_item = catorder->head;
	while (list_item->next != NULL) {
		if (list_item->next->data == remove_item) {
			list_item->next = list_item->next->next;
			return SEPOL_OK;
		}
		list_item = list_item->next;
	}

	return SEPOL_OK;
}

int __cil_set_order(struct cil_list *order, struct cil_list *edges)
{
	struct cil_list_item *order_head;
	struct cil_list_item *order_sublist;
	struct cil_list_item *order_lists;
	struct cil_list_item *edge_node;
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
			}
			else {
				rc = __cil_set_merge_lists(order_sublist->data, edge_node->data, &success);
				if (rc != SEPOL_OK) {
					printf("Failed to merge categoryorder sublist with main list\n");
					return rc;
				}
			}
			if (success) 
				break;
			else if (order_sublist->next == NULL) {
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
							return rc;
						}
						if (success) 
							__cil_set_remove_list(order, order_lists->data);
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
}

/* other is a cil_list containing order, ordered, empty, and found */
int __cil_verify_order_node_helper(struct cil_tree_node *node, uint32_t *finished, struct cil_list *other)
{
	uint32_t *empty = NULL, *found = NULL, *flavor = NULL;
	struct cil_list_item *ordered = NULL;
	struct cil_list *order = NULL;	

	if (other == NULL || other->head == NULL || other->head->next == NULL
	|| other->head->next->next == NULL || other->head->next->next->next == NULL
	|| other->head->next->next->next->next == NULL)
		return SEPOL_ERR;

	if (other->head->flavor == CIL_LIST)
		order = (struct cil_list*)other->head->data;
	else
		return SEPOL_ERR;

	if (other->head->next->flavor == CIL_LIST_ITEM)
		ordered = (struct cil_list_item*)other->head->next->data;
	else
		return SEPOL_ERR;

	if (other->head->next->next->flavor == CIL_INT)
		empty = (uint32_t*)other->head->next->next->data;
	else
		return SEPOL_ERR;

	if (other->head->next->next->next->flavor == CIL_INT)
		found = (uint32_t*)other->head->next->next->next->data;
	else
		return SEPOL_ERR;

	if (other->head->next->next->next->next->flavor == CIL_INT)
		flavor = (uint32_t*)other->head->next->next->next->next->data;
	else
		return SEPOL_ERR;

	if (node->flavor == *flavor) {
		if (*empty) {
			printf("Error: ordering is empty\n");
			return SEPOL_ERR;
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
			return SEPOL_ERR;
		}
		*found = 0;
	}
	
	return SEPOL_OK;
}

int __cil_verify_order(struct cil_list *order, struct cil_tree_node *current, uint32_t flavor)
{
	if (order == NULL || current == NULL)
		return SEPOL_ERR;

	struct cil_list_item *ordered;
	int found = 0;
	int empty = 0;
	int rc = SEPOL_ERR;

	if (order->head == NULL)
		empty = 1;
	else {
		ordered = order->head;
		if (ordered->next != NULL) {
			printf("Disjoint category ordering exists\n");
			return SEPOL_ERR;
		}
		
		if (ordered->data != NULL) 
			order->head = ((struct cil_list*)ordered->data)->head;
	}

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->flavor = CIL_LIST;
	other->head->data = order;
	cil_list_item_init(&other->head->next);
	other->head->next->flavor = CIL_LIST_ITEM;
	other->head->next->data = ordered;
	cil_list_item_init(&other->head->next->next);
	other->head->next->next->flavor = CIL_INT;
	other->head->next->next->data = &found;
	cil_list_item_init(&other->head->next->next->next);
	other->head->next->next->next->flavor = CIL_INT;
	other->head->next->next->next->data = &empty;
	cil_list_item_init(&other->head->next->next->next->next);
	other->head->next->next->next->next->flavor = CIL_INT;
	other->head->next->next->next->next->data = &flavor;

	rc = cil_tree_walk(current, __cil_verify_order_node_helper, NULL, NULL, other); 
	if (rc != SEPOL_OK) {
		printf("Failed to verify category order\n");
		return rc;
	}
	
	return SEPOL_OK;
}

int __cil_create_edge_list(struct cil_db *db, struct cil_tree_node *current, struct cil_list *order, uint32_t sym_flavor, uint32_t flavor, struct cil_list *edge_list, struct cil_call *call)
{
	if (order == NULL || order->head == NULL || edge_list == NULL)
		return SEPOL_ERR;

	struct cil_tree_node *node = NULL;
	struct cil_list *edge_nodes = NULL;
	struct cil_list_item *edge = NULL;
	struct cil_list_item *edge_node = NULL;
	struct cil_list_item *copy_node = NULL;
	struct cil_list_item *edge_tail = NULL;
	struct cil_list_item *edge_list_tail = NULL;
	struct cil_list_item *curr = order->head;
	int rc = SEPOL_ERR;

	while (curr != NULL) {
		rc = cil_resolve_name(db, current, (char*)curr->data, sym_flavor, flavor, call, &node);
		if (rc != SEPOL_OK) {
			printf("Failed to resolve name: %s\n", (char*)curr->data);
			return rc;
		}
		cil_list_item_init(&edge_node);
		edge_node->flavor = node->flavor;
		edge_node->data = node->data;
		if (edge_nodes == NULL) {
			cil_list_init(&edge_nodes);
			cil_list_item_init(&edge);
			if (edge_list->head == NULL)
				edge_list->head = edge;
			else
				edge_list_tail->next = edge;
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
			}
			else
				edge_nodes->head = edge_node;
		}
		else {
			edge_nodes->head->next = edge_node;
			edge_tail = edge_node;
			edge_nodes = NULL;
		}
		curr = curr->next;
	}
	return SEPOL_OK;
}

int cil_resolve_catorder(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call)
{
	struct cil_catorder *catorder = (struct cil_catorder*)current->data;
	struct cil_list_item *list_item;
	struct cil_list *edge_list;
	int rc = SEPOL_ERR;

	cil_list_init(&edge_list);

	rc = __cil_create_edge_list(db, current, catorder->cat_list_str, CIL_SYM_CATS, CIL_CAT, edge_list, call);
	if (rc != SEPOL_OK) {
		printf("Failed to create category edge list\n");
		return rc;
	}

	if (db->catorder->head == NULL) {
		cil_list_item_init(&list_item);
		db->catorder->head = list_item;
	}
	rc = __cil_set_order(db->catorder, edge_list);
	if (rc != SEPOL_OK) {
		printf("Failed to order categoryorder\n");
		return rc;
	}

	return SEPOL_OK;
}

int cil_resolve_dominance(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call)
{
	struct cil_sens_dominates *dom = (struct cil_sens_dominates*)current->data;
	struct cil_list_item *list_item;
	struct cil_list *edge_list;
	int rc = SEPOL_ERR;
	
	cil_list_init(&edge_list);
	
	rc = __cil_create_edge_list(db, current, dom->sens_list_str, CIL_SYM_SENS, CIL_SENS, edge_list, call);
	if (rc != SEPOL_OK) {
		printf("Failed to create sensitivity edge list\n");
		return rc;
	}

	if (db->dominance->head == NULL) {
		cil_list_item_init(&list_item);
		db->dominance->head = list_item;
	}
	rc = __cil_set_order(db->dominance, edge_list);
	if (rc != SEPOL_OK) {
		printf("Failed to order dominance\n");
		return rc;
	}
	
	return SEPOL_OK;
}

int __cil_resolve_cat_range(struct cil_db *db, struct cil_list *cat_list, struct cil_list *res_list)
{
	if (cat_list == NULL || res_list == NULL)
		return SEPOL_ERR;

	if (cat_list->head == NULL || cat_list->head->next == NULL || cat_list->head->next->next != NULL) {
		printf("Invalid category list passed into category range resolution\n");
		return SEPOL_ERR;
	}

	struct cil_list_item *curr_cat = cat_list->head;
	struct cil_list_item *catorder = db->catorder->head;
	struct cil_list_item *curr_catorder = catorder;
	struct cil_list_item *new_item;
	struct cil_list_item *list_tail;

	while (curr_catorder != NULL) {
		if (!strcmp((char*)curr_cat->data, (char*)((struct cil_cat*)curr_catorder->data)->datum.name)) {
			while (curr_catorder != NULL) {
				cil_list_item_init(&new_item);
				new_item->flavor = curr_catorder->flavor;
				new_item->data = curr_catorder->data;
				if (res_list->head == NULL)
					res_list->head = new_item;
				else
					list_tail->next = new_item;
				list_tail = new_item;
				if (!strcmp((char*)curr_cat->next->data, (char*)((struct cil_cat*)curr_catorder->data)->datum.name))
					return SEPOL_OK;
				curr_catorder = curr_catorder->next;
			}
			printf("Invalid category range\n");
			return SEPOL_ERR;
		}
		curr_catorder = curr_catorder->next;
	}

	return SEPOL_OK;	
}

int cil_resolve_cat_list(struct cil_db *db, struct cil_tree_node *current, struct cil_list *cat_list, struct cil_list *res_cat_list, struct cil_call *call)
{
	if (cat_list == NULL || res_cat_list == NULL) 
		return SEPOL_ERR;

	struct cil_tree_node *cat_node = NULL;
	struct cil_list *sub_list;
	struct cil_list_item *new_item;
	struct cil_list_item *list_tail;
	struct cil_list_item *curr = cat_list->head;
	int rc = SEPOL_ERR;
	
	while (curr != NULL) {
		cil_list_item_init(&new_item);
		if (curr->flavor == CIL_LIST) {
			cil_list_init(&sub_list);
			new_item->flavor = CIL_LIST;
			new_item->data = sub_list;
			rc = __cil_resolve_cat_range(db, (struct cil_list*)curr->data, sub_list);
			if (rc != SEPOL_OK) {
				printf("Failed to resolve category range\n");
				return rc;
			}
		}
		else {
			rc = cil_resolve_name(db, current, (char*)curr->data, CIL_SYM_CATS, CIL_CAT, call, &cat_node);
			if (rc != SEPOL_OK) {
				printf("Failed to resolve category name: %s\n", (char*)curr->data);
				return rc;
			}
			new_item->flavor = cat_node->flavor;
			new_item->data = cat_node->data;
		}
		if (res_cat_list->head == NULL)
			res_cat_list->head = new_item;
		else
			list_tail->next = new_item;
		list_tail = new_item;
		curr = curr->next;
	}

	return SEPOL_OK;
}

int cil_resolve_catset(struct cil_db *db, struct cil_tree_node *current, struct cil_catset *catset, struct cil_call *call)
{
	//struct cil_catset *catset = (struct cil_catset*)current->data;
	struct cil_list *res_cat_list;
	int rc = SEPOL_ERR;

	cil_list_init(&res_cat_list);
	rc = cil_resolve_cat_list(db, current, catset->cat_list_str, res_cat_list, call);
	if (rc != SEPOL_OK) {
		printf("Failed to resolve category list\n");
		return rc;
	}
	
	catset->cat_list = res_cat_list;
	
	return SEPOL_OK;
}

int __cil_senscat_insert(struct cil_db *db, struct cil_tree_node *current, hashtab_t hashtab, char *key, struct cil_call *call)
{
	struct cil_tree_node *cat_node = NULL;
	int rc = SEPOL_ERR;

	rc = cil_resolve_name(db, current, key, CIL_SYM_CATS, CIL_CAT, call, &cat_node);
	if (rc != SEPOL_OK) {
		printf("Failed to resolve category name\n");
		return rc;
	}
	/* TODO CDS This seems fragile - using the symtab abstraction sometimes but then dropping to the hashtab level when necessary (and it is necessary as using cil_symtab_insert() would reset the name field in the datum). */
	rc = hashtab_insert(hashtab, (hashtab_key_t)key, (hashtab_datum_t)cat_node->data);
	if (rc != SEPOL_OK) {
		printf("Failed to insert category into sensitivitycategory symtab\n");
		return rc;
	}

	return SEPOL_OK;
}

int cil_resolve_senscat(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call)
{
	struct cil_tree_node *sens_node = NULL;
	struct cil_senscat *senscat = (struct cil_senscat*)current->data;
	struct cil_list *sub_list;
	struct cil_list_item *curr = senscat->cat_list_str->head;
	struct cil_list_item *curr_range_cat;
	int rc = SEPOL_ERR;
	char *key = NULL;
	
	rc = cil_resolve_name(db, current, (char*)senscat->sens_str, CIL_SYM_SENS, CIL_SENS, call, &sens_node);
	if (rc != SEPOL_OK) {
		printf("Failed to get sensitivity node\n");
		return rc;
	}
	
	while (curr != NULL) {
		if (curr->flavor == CIL_LIST) {
			cil_list_init(&sub_list);
			rc = __cil_resolve_cat_range(db, (struct cil_list*)curr->data, sub_list);
			if (rc != SEPOL_OK) {
				printf("Failed to resolve category range\n");
				return rc;
			}
			curr_range_cat = sub_list->head;
			while (curr_range_cat != NULL) {
				key = cil_strdup(((struct cil_cat*)curr_range_cat->data)->datum.name);
				rc = __cil_senscat_insert(db, current, ((struct cil_sens*)sens_node->data)->cats.table, key, call);
				if (rc != SEPOL_OK) {
					printf("Failed to insert category into sensitivity symtab\n");
					return rc;
				}
				curr_range_cat = curr_range_cat->next;
			}
		}
		else {
			key = cil_strdup(curr->data);
			rc = __cil_senscat_insert(db, current, ((struct cil_sens*)sens_node->data)->cats.table, key, call);
			if (rc != SEPOL_OK) {
				printf("Failed to insert category into sensitivity symtab\n");
				return rc;
			}
		}
		curr = curr->next;
	}

	return SEPOL_OK;
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
				return rc;
			}
		}
		else {
			key = ((struct cil_cat*)curr_cat->data)->datum.name;
			rc = cil_symtab_get_node(symtab, key, &cat_node);
			if (rc != SEPOL_OK) {
				printf("Category has not been associated with this sensitivity: %s\n", key);
				/*TOOD: should this return SEPOL_ERR, even if SEPOL_ENONENT is retunred? */
				return rc;
			}
		}
		curr_cat = curr_cat->next;
	}
	
	return SEPOL_OK;
}

int cil_resolve_level(struct cil_db *db, struct cil_tree_node *current, struct cil_level *level, struct cil_call *call)
{
	struct cil_tree_node *sens_node = NULL;
	struct cil_tree_node *catset_node = NULL;
	struct cil_list *res_cat_list;
	int rc = SEPOL_ERR;
	
	rc = cil_resolve_name(db, current, (char*)level->sens_str, CIL_SYM_SENS, CIL_SENS, call, &sens_node);
	if (rc != SEPOL_OK) {
		printf("Failed to get sensitivity node\n");
		return rc;
	}
	level->sens = (struct cil_sens*)sens_node->data;

	if (level->catset_str != NULL) {
		rc = cil_resolve_name(db, current, level->catset_str, CIL_SYM_CATS, CIL_CATSET, call, &catset_node);
		if (rc != SEPOL_OK) {
			printf("cil_resolve_level: Failed to resolve categoryset, rc: %d\n", rc);
			return rc;
		}
		level->catset = (struct cil_catset*)catset_node->data;
	}
	else {
		cil_list_init(&res_cat_list);
		rc = cil_resolve_cat_list(db, current, level->cat_list_str, res_cat_list, call);
		if (rc != SEPOL_OK) {
			printf("Failed to resolve category list\n");
			return rc;
		}
	
		rc = __cil_verify_sens_cats(sens_node->data, res_cat_list);
		if (rc != SEPOL_OK) {
			printf("Failed to verify sensitivitycategory relationship\n");
			return rc;
		}
	
		level->cat_list = res_cat_list;
	}

	return SEPOL_OK;
}

int __cil_resolve_constrain_expr(struct cil_db *db, struct cil_tree_node *current, struct cil_tree_node *expr_root, struct cil_call *call)
{
	struct cil_tree_node *curr = expr_root;
	struct cil_tree_node *attr_node;
	int rc = SEPOL_ERR;

	while (curr != NULL) {
		if (curr->cl_head == NULL) {
			if (strstr(CIL_CONSTRAIN_OPER, (char*)curr->data) == NULL && strstr(CIL_MLSCONSTRAIN_KEYS, (char*)curr->data) == NULL) {
				rc = cil_resolve_name(db, current, (char*)curr->data, CIL_SYM_TYPES, CIL_TYPE, call, &attr_node);
				if (rc != SEPOL_OK) {
					printf("Name resolution failed for: %s\n", (char*)curr->data);
					return rc;
				}
				free(curr->data);
				curr->data = NULL;
				curr->flavor = attr_node->flavor;
				curr->data = attr_node->data;
			}
		}
		else {
			rc = __cil_resolve_constrain_expr(db, current, curr->cl_head, call);
			if (rc != SEPOL_OK) {
				printf("Failed resolving constrain expression\n");
				return rc;
			}
		}
		curr = curr->next;
	}

	return SEPOL_OK;
}

int cil_resolve_constrain(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call)
{
	struct cil_constrain *cons = (struct cil_constrain*)current->data;
	struct cil_tree_node *class_node;
	struct cil_list_item *curr_class = cons->class_list_str->head;
	struct cil_list_item *new_item;
	struct cil_list *class_list;
	struct cil_list *perm_list;
	int rc = SEPOL_ERR;

	cil_list_init(&class_list);
	cil_list_init(&perm_list);
	while (curr_class != NULL) {
		rc = cil_resolve_name(db, current, (char*)curr_class->data, CIL_SYM_CLASSES, CIL_CLASS, call, &class_node);
		if (rc != SEPOL_OK) {
			printf("Name resolution failed for: %s\n", (char*)curr_class->data);
			return rc;
		}
		rc = __cil_resolve_perm_list((struct cil_class*)class_node->data, cons->perm_list_str, NULL);
		if (rc != SEPOL_OK) {
			printf("Failed to verify perm list\n");
			return rc;
		}
		cil_list_item_init(&new_item);
		new_item->flavor = CIL_CLASS;
		new_item->data = class_node->data;
		rc = cil_list_append_item(class_list, new_item);
		if (rc != SEPOL_OK) {
			printf("Failed to append to class list\n");
			return rc;
		}
		curr_class = curr_class->next;
	}

	rc = __cil_resolve_perm_list((struct cil_class*)class_node->data, cons->perm_list_str, perm_list);
	if (rc != SEPOL_OK) {
		printf("Failed to resolve perm list\n");
		return rc;
	}

	rc = __cil_resolve_constrain_expr(db, current, cons->expr->root, call);
	if (rc != SEPOL_OK) {
		printf("Failed to resolve constrain expression\n");
		return rc;
	}

	cons->class_list = class_list;
	cons->perm_list = perm_list;

	return SEPOL_OK;
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
		goto resolve_context_cleanup;
	}
	context->user = (struct cil_user*)user_node->data;

	rc = cil_resolve_name(db, current, context->role_str, CIL_SYM_ROLES, CIL_ROLE, call, &role_node);
	if (rc != SEPOL_OK) {
		error = context->role_str;
		goto resolve_context_cleanup;
	}
	context->role = (struct cil_role*)role_node->data;

	rc = cil_resolve_name(db, current, context->type_str, CIL_SYM_TYPES, CIL_TYPE, call, &type_node);
	if (rc != SEPOL_OK) {
		error = context->type_str;
		goto resolve_context_cleanup;
	}
	context->type = (struct cil_type*)type_node->data;

	if (context->low_str != NULL) {
		rc = cil_resolve_name(db, current, context->low_str, CIL_SYM_LEVELS, CIL_LEVEL, call, &low_node);
		if (rc != SEPOL_OK) {
			error = context->low_str;
			goto resolve_context_cleanup;
		}
		context->low = (struct cil_level*)low_node->data;
	}
	else if (context->low != NULL) {
		rc = cil_resolve_level(db, current, context->low, call);
		if (rc != SEPOL_OK) {
			printf("cil_resolve_context: Failed to resolve low level, rc: %d\n", rc);
			return rc;
		}
	}
	else {
		printf("cil_resolve_context: Invalid context, low level not found\n");
		return SEPOL_ERR;
	}

	if (context->high_str != NULL) {
		rc = cil_resolve_name(db, current, context->high_str, CIL_SYM_LEVELS, CIL_LEVEL, call, &high_node);
		if (rc != SEPOL_OK) {
			error = context->high_str;
			goto resolve_context_cleanup;
		}
		context->high = (struct cil_level*)high_node->data;
	}
	else if (context->high != NULL) {
		rc = cil_resolve_level(db, current, context->high, call);
		if (rc != SEPOL_OK) {
			printf("cil_resolve_context: Failed to resolve high level, rc: %d\n", rc);
			return rc;
		}
	}
	else {
		printf("cil_resolve_context: Invalid context, high level not found\n");
		return SEPOL_ERR;
	}

	return SEPOL_OK;

	resolve_context_cleanup:
		printf(" cil_resolve_context: Name resolution failed for %s\n", error);
		return rc;
}

int cil_resolve_filecon(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call)
{
	struct cil_filecon *filecon = (struct cil_filecon*)current->data;
	struct cil_tree_node *type_node = NULL;
	struct cil_tree_node *context_node = NULL;
	int rc=  SEPOL_ERR;

	rc = cil_resolve_name(db, current, filecon->type_str, CIL_SYM_TYPES, CIL_TYPE, call, &type_node);
	if (rc != SEPOL_OK) {
		printf("cil_resolve_portcon: Failed to resolve type: %s, rc: %d\n", filecon->type_str, rc);
		return rc;
	}
	filecon->type = (struct cil_type*)type_node->data;

	if (filecon->context_str != NULL) {
		rc = cil_resolve_name(db, current, filecon->context_str, CIL_SYM_CONTEXTS, CIL_CONTEXT, call, &context_node);
		if (rc != SEPOL_OK) {
			printf("cil_resolve_portcon: Failed to resolve file context: %s, rc: %d\n", filecon->context_str, rc);
			return rc;
		}
	}
	else {
		rc = cil_resolve_context(db, current, filecon->context, call);
		if (rc != SEPOL_OK) {
			printf("cil_resolve_portcon: Failed to resolve file context\n");
		}
	}

	return SEPOL_OK;
}

int cil_resolve_portcon(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call)
{
	struct cil_portcon *portcon = (struct cil_portcon*)current->data;
	struct cil_tree_node *type_node = NULL;
	struct cil_tree_node *context_node = NULL;
	int rc=  SEPOL_ERR;

	rc = cil_resolve_name(db, current, portcon->type_str, CIL_SYM_TYPES, CIL_TYPE, call, &type_node);
	if (rc != SEPOL_OK) {
		printf("cil_resolve_portcon: Failed to resolve type: %s, rc: %d\n", portcon->type_str, rc);
		return rc;
	}
	portcon->type = (struct cil_type*)type_node->data;

	if (portcon->context_str != NULL) {
		rc = cil_resolve_name(db, current, portcon->context_str, CIL_SYM_CONTEXTS, CIL_CONTEXT, call, &context_node);
		if (rc != SEPOL_OK) {
			printf("cil_resolve_portcon: Failed to resolve port context: %s, rc: %d\n", portcon->context_str, rc);
			return rc;
		}
	}
	else {
		rc = cil_resolve_context(db, current, portcon->context, call);
		if (rc != SEPOL_OK) {
			printf("cil_resolve_portcon: Failed to resolve port context\n");
		}
	}

	return SEPOL_OK;
}

int cil_resolve_genfscon(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call)
{
	struct cil_genfscon *genfscon = (struct cil_genfscon*)current->data;
	struct cil_tree_node *type_node = NULL;
	struct cil_tree_node *context_node = NULL;
	int rc=  SEPOL_ERR;

	rc = cil_resolve_name(db, current, genfscon->type_str, CIL_SYM_TYPES, CIL_TYPE, call, &type_node);
	if (rc != SEPOL_OK) {
		printf("cil_resolve_genfscon: Failed to resolve type: %s, rc: %d\n", genfscon->type_str, rc);
		return rc;
	}
	genfscon->type = (struct cil_type*)type_node->data;

	if (genfscon->context_str != NULL) {
		rc = cil_resolve_name(db, current, genfscon->context_str, CIL_SYM_CONTEXTS, CIL_CONTEXT, call, &context_node);
		if (rc != SEPOL_OK) {
			printf("cil_resolve_genfscon: Failed to resolve genfs context: %s, rc: %d\n", genfscon->context_str, rc);
			return rc;
		}
	}
	else {
		rc = cil_resolve_context(db, current, genfscon->context, call);
		if (rc != SEPOL_OK) {
			printf("cil_resolve_genfscon: Failed to resolve genfs context\n");
		}
	}

	return SEPOL_OK;
}

int cil_resolve_nodecon(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call)
{
	struct cil_nodecon *nodecon = (struct cil_nodecon*)current->data;
	struct cil_tree_node *context_node = NULL;
	int rc=  SEPOL_ERR;

	if (nodecon->context_str != NULL) {
		rc = cil_resolve_name(db, current, nodecon->context_str, CIL_SYM_CONTEXTS, CIL_CONTEXT, call, &context_node);
		if (rc != SEPOL_OK) {
			printf("cil_resolve_nodecon: Failed to resolve node context: %s, rc: %d\n", nodecon->context_str, rc);
			return rc;
		}
	}
	else {
		rc = cil_resolve_context(db, current, nodecon->context, call);
		if (rc != SEPOL_OK) {
			printf("cil_resolve_nodecon: Failed to resolve node context\n");
		}
	}

	return SEPOL_OK;
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
			printf("cil_resolve_netifcon: Failed to resolve interface context: %s, rc: %d\n", netifcon->if_context_str, rc);
			return rc;
		}
		netifcon->if_context = (struct cil_context*)ifcon_node->data;
	}
	else {
		rc = cil_resolve_context(db, current, netifcon->if_context, call);
		if (rc != SEPOL_OK) {
			printf("cil_resolve_netifcon: Failed to resolve OTF interface context\n");
			return rc;
		}
	}

	if (netifcon->packet_context_str != NULL) {
		rc = cil_resolve_name(db, current, netifcon->packet_context_str, CIL_SYM_CONTEXTS, CIL_CONTEXT, call, &packcon_node);
		if (rc != SEPOL_OK) {
			printf("cil_resolve_netifcon: Failed to resolve packet context: %s, rc: %d\n", netifcon->packet_context_str, rc);
			return rc;
		}
		netifcon->packet_context = (struct cil_context*)packcon_node->data;
	}
	else {
		rc = cil_resolve_context(db, current, netifcon->packet_context, call);
		if (rc != SEPOL_OK) {
			printf("cil_resolve_netifcon: Failed to resolve OTF packet context\n");
			return rc;
		}
	}

	return SEPOL_OK;
}

int cil_resolve_sidcontext(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call)
{
	struct cil_sidcontext *sidcon = (struct cil_sidcontext*)current->data;
	struct cil_tree_node *sid_node = NULL;
	struct cil_tree_node *context_node = NULL;

	int rc = SEPOL_ERR;

	rc = cil_resolve_name(db, current, sidcon->sid_str, CIL_SYM_SIDS, CIL_SID, call, &sid_node);
	if (rc != SEPOL_OK) {
		printf("cil_resolve_sidcontext: Failed to resolve sid, rc: %d : %s\n", rc, sidcon->sid_str);
		return rc;
	}
	sidcon->sid = (struct cil_sid*)sid_node->data;

	if (sidcon->context_str != NULL) {
		rc = cil_resolve_name(db, current, sidcon->context_str, CIL_SYM_CONTEXTS, CIL_CONTEXT, call, &context_node);
		if (rc != SEPOL_OK) {
			printf("cil_resolve_sidcontext: Failed to resolve context, rc: %d\n", rc);
			return rc;
		}
		sidcon->context = (struct cil_context*)context_node->data;
	}
	else if (sidcon->context != NULL) {
		rc = cil_resolve_context(db, current, sidcon->context, call);
		if (rc != SEPOL_OK) {
			printf("cil_resolve_sid: Failed to resolve context, rc: %d\n", rc);
			return rc;
		}
	}

	return SEPOL_OK;	
}

int cil_resolve_call1(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call)
{
	struct cil_call *new_call = (struct cil_call*)current->data;
	struct cil_tree_node *macro_node = NULL;
	int rc = SEPOL_ERR;

	if (new_call->macro_str != NULL) {
		rc = cil_resolve_name(db, current, new_call->macro_str, CIL_SYM_MACROS, CIL_MACRO, call, &macro_node);
		if (rc != SEPOL_OK) {
			printf("cil_resolve_call1: Failed to resolve macro, rc: %d\n", rc);
			return rc;
		}
		new_call->macro = (struct cil_macro*)macro_node->data;
	}

	if (new_call->macro->params != NULL ){
	
		struct cil_list_item *item = new_call->macro->params->head;
		struct cil_tree_node *pc = new_call->args_tree->root->cl_head;		

		new_call->args = cil_malloc(sizeof(struct cil_list));
		struct cil_list_item *args_tail = NULL;
		struct cil_args *new_arg = NULL;

		while (item != NULL) {
			if (item != NULL && pc == NULL) {
				printf("cil_resolve_call1 failed: missing arguments (line: %d)\n", current->line);
				return SEPOL_ERR;
			}

			new_arg = cil_malloc(sizeof(struct cil_args));
			new_arg->arg_str = NULL;
			new_arg->arg = NULL;
			new_arg->param_str = NULL;

			switch (item->flavor) {
				case CIL_TYPE : {
					new_arg->arg_str = cil_strdup(pc->data);
					break;
				}
				case CIL_ROLE : {
					new_arg->arg_str = cil_strdup(pc->data);
					break;
				}
				case CIL_USER : {
					new_arg->arg_str = cil_strdup(pc->data);
					break;
				}
				case CIL_SENS : {
					new_arg->arg_str = cil_strdup(pc->data);
					break;
				}
				case CIL_CAT : {
					new_arg->arg_str = cil_strdup(pc->data);
					break;
				}
				case CIL_CATSET : {
					if (pc->cl_head != NULL) {
						struct cil_catset *catset = cil_malloc(sizeof(struct cil_catset));
						rc = cil_fill_catset(pc, catset);
						if (rc != SEPOL_OK) {
							printf("cil_resolve_call1: cil_fill_catset failed, rc: %d\n", rc);
							cil_destroy_catset(catset);
							return rc;
						}
						new_arg->arg = catset;
					}
					else
						new_arg->arg_str = cil_strdup(pc->data);
					break;
				}
				case CIL_LEVEL : {
					if (pc->cl_head != NULL) {
						struct cil_level *level = cil_malloc(sizeof(struct cil_level));
						rc = cil_fill_level(pc, level);
						if (rc != SEPOL_OK) {
							printf("cil_resolve_call1: cil_fill_level failed, rc: %d\n", rc);
							cil_destroy_level(level);
							return rc;
						}
						new_arg->arg = level;
					}
					else
						new_arg->arg_str = cil_strdup(pc->data);
					break;
				}
				case CIL_CLASS : {
					new_arg->arg_str = cil_strdup(pc->data);
					break;
				}
				//permset and IP
				default : {
					printf("cil_resolve_call1: unexpected flavor: %d\n", item->flavor);
					return SEPOL_ERR;
				}
			}
			new_arg->param_str = item->data;
			new_arg->flavor = item->flavor;

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
			printf("cil_resolve_call1 failed: unexpected arguments (line: %d)\n", current->line);
			return SEPOL_ERR;
		}
	}

	rc = cil_copy_ast(db, macro_node, current);
	if (rc != SEPOL_OK) {
		printf("cil_resolve_call1: cil_copy_ast failed, rc: %d\n", rc);
		return rc;
	}

	return SEPOL_OK;
}

int cil_resolve_call2(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call)
{
	struct cil_call *new_call = (struct cil_call*)current->data;
	int rc = SEPOL_ERR;
	uint32_t sym_index = CIL_SYM_UNKNOWN;

	struct cil_list_item *item = new_call->args->head;
	while (item != NULL) {
		if (((struct cil_args*)item->data)->arg == NULL && ((struct cil_args*)item->data)->arg_str == NULL) {
			printf("cil_resolve_call2: arg and arg_str are both NULL\n");
			return SEPOL_ERR;
		}
		
		switch (((struct cil_args*)item->data)->flavor) {
		case CIL_LEVEL : 
			if (((struct cil_args*)item->data)->arg_str == NULL) {	
				rc = cil_resolve_level(db, current, (struct cil_level*)((struct cil_args*)item->data)->arg, call);
				if (rc != SEPOL_OK) {
					printf("cil_resolve_call2: cil_resolve_level failed: %d\n", rc);
					return rc;
				} 
			}
			else
				sym_index = CIL_SYM_LEVELS;
			break;
		case CIL_CATSET : 
			if (((struct cil_args*)item->data)->arg_str == NULL) {
				rc = cil_resolve_catset(db, current, (struct cil_catset*)((struct cil_args*)item->data)->arg, call);
				if (rc != SEPOL_OK) {
					printf("cil_resolve_call2: cil_resolve_catset failed, rc: %d\n", rc);
					return rc;
				}
			}
			else
				sym_index = CIL_SYM_CATS;
			break;
		case CIL_TYPE : 
			sym_index = CIL_SYM_TYPES;
			break;
		case CIL_ROLE :
			sym_index = CIL_SYM_ROLES;
			break;
		case CIL_USER :
			sym_index = CIL_SYM_USERS;
			break;
		case CIL_SENS :
			sym_index = CIL_SYM_SENS;
			break;
		case CIL_CAT :
			sym_index = CIL_SYM_CATS;
			break;
		case CIL_CLASS :
			sym_index = CIL_SYM_CLASSES;
			break;
		default : 
			sym_index = CIL_SYM_UNKNOWN;
			break;
		}
		if (sym_index != CIL_SYM_UNKNOWN) {
			rc = cil_resolve_name(db, current, ((struct cil_args*)item->data)->arg_str, sym_index, ((struct cil_args*)item->data)->flavor, call, (struct cil_tree_node**)&(((struct cil_args*)item->data)->arg));
			if (rc != SEPOL_OK) {
				printf("cil_resolve_call2: cil_resolve_name failed, rc: %d\n", rc);
				return rc;
			}
		}
		item = item->next;
	}

	return SEPOL_OK;
}

int cil_resolve_name_call_args(struct cil_call *call, char *name, uint32_t flavor, struct cil_tree_node **node)
{
	if (call == NULL || name == NULL)
		return SEPOL_ERR;

	if (call->args == NULL)
		return SEPOL_ERR;

	struct cil_list_item *item = call->args->head;

	while(item != NULL) {
		if (((struct cil_args*)item->data)->flavor == flavor) {
			if (!strcmp(name, ((struct cil_args*)item->data)->param_str)) {
				*node = ((struct cil_args*)item->data)->arg;
				return SEPOL_OK;
			}
		}
		item = item->next;
	}

	return SEPOL_ERR;
}

int cil_resolve_expr_stack(struct cil_db *db, struct cil_tree_node *current, struct cil_tree_node *bif, struct cil_call *call, uint32_t flavor)
{
	int rc = SEPOL_ERR;
	struct cil_tree_node *curr_expr = current;
	struct cil_tree_node *bool_node = NULL;
	int sym_index = 0;
	if (flavor == CIL_BOOL)
		sym_index = CIL_SYM_BOOLS;
	if (flavor == CIL_TUNABLE)
		sym_index = CIL_SYM_TUNABLES;

	while (curr_expr != NULL) {
		if (((struct cil_conditional*)curr_expr->data)->flavor == flavor) {
			if (((struct cil_conditional*)curr_expr->data)->str == NULL) {
				printf("Invalid expression\n");
				return SEPOL_ERR;
			}
			printf("resolving: %s\n", ((struct cil_conditional*)curr_expr->data)->str);
			rc = cil_resolve_name(db, bif, ((struct cil_conditional*)curr_expr->data)->str, sym_index, flavor, call, &bool_node);
			if (rc != SEPOL_OK) {
				printf("Name resolution failed for %s\n", ((struct cil_conditional*)curr_expr->data)->str);
				return rc;
			}
			((struct cil_conditional*)curr_expr->data)->boolean = (struct cil_bool*)bool_node->data;
		}

		curr_expr = curr_expr->cl_head;
	}
	return SEPOL_OK;	
}

int cil_resolve_boolif(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call)
{
	int rc = SEPOL_ERR;
	struct cil_booleanif *bif = (struct cil_booleanif*)current->data;
	
	rc = cil_resolve_expr_stack(db, bif->expr_stack, current, call, CIL_BOOL);
	if (rc != SEPOL_OK) {
		printf("Failed to resolve booleanif (line %d)\n", current->line);
		return rc;
	}

	return SEPOL_OK;
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

	while (stack != NULL) {
		cond = (struct cil_conditional*)stack->data;
		if ((cond->flavor == CIL_AND) || (cond->flavor == CIL_OR) || (cond->flavor == CIL_XOR) || (cond->flavor == CIL_NOT) || (cond->flavor == CIL_EQ) || (cond->flavor == CIL_NEQ)) {

			cil_tree_node_init(&new);

			oper1 = stack->parent;
			if (cond->flavor != CIL_NOT)
				oper2 = stack->parent->parent;

			if (oper1->flavor == CIL_COND && ((struct cil_conditional*)oper1->data)->flavor == CIL_TUNABLE)
				value1 = ((struct cil_conditional*)oper1->data)->boolean->value;
			else
				value1 = *(uint16_t*)oper1->data;

			if (cond->flavor != CIL_NOT) {
				if (oper2->flavor == CIL_COND && ((struct cil_conditional*)oper2->data)->flavor == CIL_TUNABLE)
					value2 = ((struct cil_conditional*)oper2->data)->boolean->value;
				else
					value2 = *(uint16_t*)oper2->data;
			}

			if (cond->flavor == CIL_NOT)
					new_value = !value1;
			else if (cond->flavor == CIL_AND)
				new_value = (value1 && value2);
			else if (cond->flavor == CIL_OR)
				new_value = (value1 || value2);
			else if (cond->flavor == CIL_XOR)
				new_value = (value1 ^ value2);
			else if (cond->flavor == CIL_EQ) 
				new_value = (value1 == value2);
			else if (cond->flavor == CIL_NEQ) 
				new_value = (value1 != value2);

			new->data = &new_value;

			new->flavor = CIL_INT;
			new->cl_head = stack->cl_head;
			if (cond->flavor != CIL_NOT)
				new->parent = stack->parent->parent->parent;
			else
				new->parent = stack->parent->parent;
			if (cond->flavor != CIL_NOT) {
				if (stack->parent->parent->parent != NULL)
					stack->parent->parent->parent->cl_head = new;
			}
			else {
				if (stack->parent->parent != NULL)
					stack->parent->parent->cl_head = new;
			}
			if (stack->cl_head != NULL)
				stack->cl_head->parent = new;
			if (stack->parent->parent != NULL)
				cil_tree_node_destroy(&stack->parent->parent);
			cil_tree_node_destroy(&stack->parent);
			cil_tree_node_destroy(&stack);

			if (new->cl_head == NULL) {
				if (new->parent == NULL)
					*result = *(uint16_t*)new->data;
				else
					return SEPOL_ERR;
			}

			stack = new;
		}
		stack = stack->cl_head;
	}

	printf("result: %d\n", *result);

	return SEPOL_OK;
}

int cil_resolve_tunif(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call)
{
	int rc = SEPOL_ERR;
	struct cil_tunableif *tif = (struct cil_tunableif*)current->data;
	uint16_t result = CIL_FALSE;

	rc = cil_resolve_expr_stack(db, tif->expr_stack, current, call, CIL_TUNABLE);
	if (rc != SEPOL_OK)
		return rc;
	rc = cil_evaluate_expr_stack(tif->expr_stack, &result);
	if (rc != SEPOL_OK) {
		printf("Failed to evaluate expr stack\n");
		return rc;
	}

	if (result) {
		rc = cil_copy_ast(db, current, current->parent);
		if (rc != SEPOL_OK)
			return rc;
	}
	cil_tree_subtree_destroy(current->cl_head);
	current->cl_head = NULL;

	return SEPOL_OK;
}

int __cil_resolve_ast_node_helper(struct cil_tree_node *node, __attribute__((unused)) uint32_t *finished, struct cil_list *other)
{
	int rc = SEPOL_OK;

	if (node == NULL || other == NULL || other->head == NULL)
		return SEPOL_ERR;

	int *pass = NULL;
	struct cil_db *db = NULL;
	struct cil_call *call = NULL;
	struct cil_tree_node *callstack = NULL;
	struct cil_tree_node *optstack = NULL;

	if (other->head->flavor == CIL_DB)
		db = (struct cil_db*)other->head->data;
	else
		return SEPOL_ERR;	
		
	if (other->head->next->flavor == CIL_INT)
		pass = (int*)other->head->next->data;
	else
		return SEPOL_ERR;

	if (other->head->next->next != NULL) {
		callstack = (struct cil_tree_node*)other->head->next->next->data;
		if (callstack != NULL) {
			call = (struct cil_call *)callstack->data;
		}
	} else {
		return SEPOL_ERR;
	}

	if (other->head->next->next->next != NULL) {
		optstack = (struct cil_tree_node *)other->head->next->next->next->data;
	} else {
		return SEPOL_ERR;
	}

	if (node->cl_head == NULL) {
		switch (*pass) {
			case 1 : {
				if (node->flavor == CIL_CALL) {
					rc = cil_resolve_call1(db, node, call);
				}
				break;
			}
			case 2 : {
				break;
			}
			case 3 : {
				switch (node->flavor) {
					case CIL_CATORDER : {
						printf("case categoryorder\n");
						rc = cil_resolve_catorder(db, node, call);
						break;
					}
					case CIL_DOMINANCE : {
						printf("case dominance\n");
						rc = cil_resolve_dominance(db, node, call);
						break;
					}
				}
				break;
			}
			case 4 : {
				switch (node->flavor) {
					case CIL_SENSCAT : {
						printf("case sensitivitycategory\n");
						rc = cil_resolve_senscat(db, node, call);
						break;
					}
					case CIL_CLASSCOMMON : {
						printf("case classcommon\n");
						rc = cil_resolve_classcommon(db, node, call);
						break;
					}
				}
				break;
			}
			case 5 : {
				switch (node->flavor) {
					case CIL_TYPE_ATTR : {
						printf("case typeattribute\n");
						rc = cil_resolve_typeattr(db, node, call);
						break;
					}
					case CIL_TYPEALIAS : {
						printf("case typealias\n");
						rc = cil_resolve_typealias(db, node, call);
						break;
					}
					case CIL_AVRULE : {
						printf("case avrule\n");
						rc = cil_resolve_avrule(db, node, call);
						break;
					}
					case CIL_TYPE_RULE : {
						printf("case type_rule\n");
						rc = cil_resolve_type_rule(db, node, call);
						break;
					}
					case CIL_USERROLE : {
						printf("case userrole\n");
						rc = cil_resolve_userrole(db, node, call);
						break;
					}
					case CIL_ROLETYPE : {
						printf("case roletype\n");
						rc = cil_resolve_roletype(db, node, call);
						break;
					}
					case CIL_ROLETRANS : {
						printf("case roletransition\n");
						rc = cil_resolve_roletrans(db, node, call);
						break;
					}
					case CIL_ROLEALLOW : {
						printf("case roleallow\n");
						rc = cil_resolve_roleallow(db, node, call);
						break;
					}
					case CIL_ROLEDOMINANCE : {
						printf("case roledominance\n");
						rc = cil_resolve_roleallow(db, node, call);
						break;
					}
					case CIL_SENSALIAS : {
						printf("case sensitivityalias\n");
						rc = cil_resolve_sensalias(db, node, call);
						break;
					}
					case CIL_CATALIAS : {
						printf("case categoryalias\n");
						rc = cil_resolve_catalias(db, node, call);
						break;
					}
					case CIL_CATSET : {
						printf("case categoryset\n");
						rc = cil_resolve_catset(db, node, (struct cil_catset*)node->data, call);
						break;
					}
					case CIL_LEVEL : {
						printf("case level\n");
						rc = cil_resolve_level(db, node, (struct cil_level*)node->data, call);
						break;
					}
					case CIL_CONSTRAIN : {
						printf("case constrain\n");
						rc = cil_resolve_constrain(db, node, call);
						break;
					}
					case CIL_MLSCONSTRAIN : {
						printf("case constrain\n");
						rc = cil_resolve_constrain(db, node, call);
						break;
					}
					case CIL_CONTEXT : {
						printf("case context\n");
						rc = cil_resolve_context(db, node, (struct cil_context*)node->data, call);
						break;
					}
					case CIL_FILECON : {
						printf("case filecon\n");
						rc = cil_resolve_filecon(db, node, call);
						break;
					}
					case CIL_PORTCON : {
						printf("case portcon\n");
						rc = cil_resolve_portcon(db, node, call);
						break;
					}
					case CIL_NODECON : {
						printf("case nodecon\n");
						rc = cil_resolve_nodecon(db, node, call);
						break;
					}
					case CIL_GENFSCON : {
						printf("case genfscon\n");
						rc = cil_resolve_genfscon(db, node, call);
						break;
					}
					case CIL_NETIFCON : {
						printf("case netifcon\n");
						rc = cil_resolve_netifcon(db, node, call);
						break;
					}
					case CIL_SIDCONTEXT : {
						printf("case sidcontext\n");
						rc = cil_resolve_sidcontext(db, node, call);
						break;
					}
					default : 
						break;
				}
				break;	
			}
			default : 
				break;
		}
	}
	else {
		if (node->flavor == CIL_MACRO) {
			printf("macros are not resolved\n");
			*finished = CIL_TREE_SKIP_HEAD;
			return SEPOL_OK;
		}
		switch (*pass) {
			case 1 : {
				switch (node->flavor) {
					default : 
						break;
				}
			
				break;	
			}
			case 2 : {
				if (node->flavor == CIL_CALL) {
					rc = cil_resolve_call2(db, node, call);
				}
				break;
			}
			case 3 : {
				if (node->flavor == CIL_BOOLEANIF)
					rc = cil_resolve_boolif(db, node, call);
				if (node->flavor == CIL_TUNABLEIF) 
					rc = cil_resolve_tunif(db, node, call);
				break;
			}
			default :
				break;
		}
	}	

	if (rc == SEPOL_ENOENT && optstack != NULL) {
		/* disable an optional if something failed to resolve */
		struct cil_optional *opt = (struct cil_optional *)optstack->data;
		opt->datum.state = CIL_STATE_DISABLED;
		rc = SEPOL_OK;
	}

	if (node->flavor == CIL_CALL || node->flavor == CIL_OPTIONAL) {
		/* push this node onto a stack */
		struct cil_tree_node *new;
		int rc2 = cil_tree_node_init(&new);
		if (rc2 != SEPOL_OK)
			return rc;

		new->data = node->data;
		new->flavor = node->flavor;

		if (node->flavor == CIL_CALL) {
			if (callstack != NULL) {
				callstack->parent = new;
				new->cl_head = callstack;
			}
			other->head->next->next->data = new;
		} else if (node->flavor == CIL_OPTIONAL) {
			if (optstack != NULL) {
				optstack->parent = new;
				new->cl_head = optstack;
			}
			other->head->next->next->next->data = new;
		}
	}
	
	return rc;
}

int __cil_resolve_ast_reverse_helper(struct cil_tree_node *current, struct cil_list *other)
{
	if (other == NULL || other->head == NULL || other->head->next == NULL || other->head->next->next == NULL || other->head->next->next->next == NULL)
		return SEPOL_ERR;

	if (current->flavor == CIL_CALL) {
		/* pop off the stack */
		struct cil_tree_node *callstack = other->head->next->next->data;
		other->head->next->next->data = callstack->cl_head;
		if (callstack->cl_head) {
			callstack->cl_head->parent = NULL;
		}
		free(callstack);
	} else if (current->flavor == CIL_OPTIONAL) {
		/* pop off the stack */
		struct cil_tree_node *optstack = other->head->next->next->next->data;
		other->head->next->next->next->data = optstack->cl_head;
		if (optstack->cl_head) {
			optstack->cl_head->parent = NULL;
		}
		free(optstack);
	}

	return SEPOL_OK;
}

int cil_resolve_ast(struct cil_db *db, struct cil_tree_node *current)
{
	if (db == NULL || current == NULL)
		return SEPOL_ERR;

	int rc = SEPOL_ERR;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = db;
	other->head->flavor = CIL_DB;
	cil_list_item_init(&other->head->next);
	other->head->next->flavor = CIL_INT;
	int pass = 1;
	other->head->next->data = &pass;
	cil_list_item_init(&other->head->next->next);
	other->head->next->next->data = NULL;
	other->head->next->next->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next->next->next);
	other->head->next->next->next->data = NULL;
	other->head->next->next->next->flavor = CIL_AST_NODE;

	for (pass = 1; pass <= 5; pass++) {

		printf("---------- Pass %i ----------\n", pass);
		rc = cil_tree_walk(current, __cil_resolve_ast_node_helper, __cil_resolve_ast_reverse_helper, NULL, other);	
		if (rc != SEPOL_OK) {
			printf("cil_resolve_ast: Pass %i failed\n", pass);
			return rc;
		}

		cil_tree_print(db->ast->root, 0);

		if (pass == 3) {
			printf("----- Verify Catorder ------\n");
			rc = __cil_verify_order(db->catorder, current, CIL_CAT);
			if (rc != SEPOL_OK) {
				printf("Failed to verify categoryorder\n");
				return rc;
			}
			printf("----- Verify Dominance -----\n");
			rc = __cil_verify_order(db->dominance, current, CIL_SENS);
			if (rc != SEPOL_OK) {
				printf("Failed to verify dominance\n");
				return rc;
			}
		}
	}

	return SEPOL_OK;
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
	}
	else {
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
						printf("__cil_resolve_name_helper: failed to get node from parent symtab of call\n");
						return rc;
					}
				} else {
					printf("__cil_resolve_name_helper: failed to get symtab from call parent\n");
					return rc;
				}
			} else if (rc == SEPOL_ENOENT) {
				rc = cil_get_parent_symtab(db, call->macro->datum.node, &symtab, CIL_SYM_BLOCKS);
				if (rc != SEPOL_OK) {
					printf("__cil_resolve_name_helper: failed to get node from parent symtab of macro\n");
					return rc;
				} else {
					symtab = &(db->symtab[CIL_SYM_BLOCKS]);	
				}
			} else {
				return rc;
			}
				
		} else {
			rc = cil_get_parent_symtab(db, ast_node, &symtab, CIL_SYM_BLOCKS);
			if (rc != SEPOL_OK) {
				printf("__cil_resolve_name_helper: cil_get_parent_symtab failed, rc: %d\n", rc);
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
				printf("__cil_resolve_name_helper: Failed to find table, block current: %s\n", tok_current);
				goto resolve_name_helper_cleanup;
			}
			symtab = &(((struct cil_block*)tmp_node->data)->symtab[CIL_SYM_BLOCKS]);
		}
		else {
			//printf("type key: %s\n", tok_current); 
			symtab = &(((struct cil_block*)tmp_node->data)->symtab[sym_index]);
			rc = cil_symtab_get_node(symtab, tok_current, &tmp_node);
			if (rc != SEPOL_OK) {
				printf("__cil_resolve_name_helper: Failed to resolve name, current: %s\n", tok_current);
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
		/*TODO: I think this is wrong */
		if (rc)
			return rc;
		else
			return SEPOL_ERR;
}

int cil_resolve_name(struct cil_db *db, struct cil_tree_node *ast_node, char *name, uint32_t sym_index, uint32_t flavor, struct cil_call *call, struct cil_tree_node **node)
{
	if (db == NULL || ast_node == NULL || name == NULL) {
		printf("Invalid call to cil_resolve_name\n");
		return SEPOL_ERR;
	}

	int rc = SEPOL_ERR;
	char *global_symtab_name = name;
	char first = *name;

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
							printf("cil_resolve_name: failed to get node from parent symtab of call\n");
						}
						return rc;
					}
					else {
						printf("failed to get parent symtab from call\n");
						return rc;
					}
						
				}
				else {
					rc = cil_resolve_name_call_args(call, name, flavor, node);
					if (rc == SEPOL_OK)
						return rc;

					rc = cil_get_parent_symtab(db, call->macro->datum.node, &symtab, sym_index);
					if (rc != SEPOL_OK)
						return rc;

					rc = cil_symtab_get_node(symtab, name, node);
					if (rc == SEPOL_OK)
						return rc;	

					global_symtab_name = cil_malloc(strlen(name)+2);
					strcpy(global_symtab_name, ".");
					strncat(global_symtab_name, name, strlen(name));
				}
			}
			else {
				rc = cil_get_parent_symtab(db, ast_node, &symtab, sym_index);
				if (rc != SEPOL_OK) {
					printf("cil_resolve_name: cil_get_parent_symtab failed, rc: %d\n", rc);
					return rc;
				}
				rc = cil_symtab_get_node(symtab, name, node);
				if (rc != SEPOL_OK) {
					global_symtab_name = cil_malloc(strlen(name)+2);
					strcpy(global_symtab_name, ".");
					strncat(global_symtab_name, name, strlen(name));
				}
			}
		}
		else {
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
				return rc;
			}
		}
		else {
			rc = __cil_resolve_name_helper(db, db->ast->root, global_symtab_name, sym_index, call, node);
			if (rc != SEPOL_OK) {
				free(global_symtab_name);
				return rc;
			}
		}
	}

	if (global_symtab_name != name)
		free(global_symtab_name);

	return SEPOL_OK;
}
