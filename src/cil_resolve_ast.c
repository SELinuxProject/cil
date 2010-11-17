#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "cil.h"
#include "cil_mem.h"
#include "cil_tree.h"
#include "cil_list.h"
#include "cil_resolve_ast.h"

int cil_resolve_avrule(struct cil_db *db, struct cil_tree_node *current)
{
	struct cil_avrule *rule = (struct cil_avrule*)current->data;
	struct cil_tree_node *src_node = NULL;
	struct cil_tree_node *tgt_node = NULL;
	struct cil_tree_node *obj_node = NULL;

	int rc = SEPOL_ERR;
	
	rc = cil_resolve_name(db, current, rule->src_str, CIL_SYM_TYPES, &src_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", rule->src_str);
		return SEPOL_ERR;
	}
	else {
		rule->src = (struct cil_type*)(src_node->data);
		free(rule->src_str);
		rule->src_str = NULL;
	}
					
	rc = cil_resolve_name(db, current, rule->tgt_str, CIL_SYM_TYPES, &tgt_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", rule->tgt_str);
		return SEPOL_ERR;
	}
	else {
		rule->tgt = (struct cil_type*)(tgt_node->data);
		free(rule->tgt_str);
		rule->tgt_str = NULL;	
	}

	rc = cil_resolve_name(db, current, rule->obj_str, CIL_SYM_CLASSES, &obj_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", rule->obj_str);
		return SEPOL_ERR;
	}
	else {
		rule->obj = (struct cil_class*)(obj_node->data);
		free(rule->obj_str);
		rule->obj_str = NULL;
	}
	struct cil_tree_node *perm_node;
	struct cil_list_item *perm = rule->perms_str->head;
	struct cil_list_item *list_item;
	struct cil_list_item *list_tail;
	struct cil_list *perms_list;
	cil_list_init(&perms_list);
	while (perm != NULL) {
		rc = cil_symtab_get_node(&rule->obj->perms, (char*)perm->data, &perm_node);
		if (rc != SEPOL_OK) {
			if (rule->obj->common != NULL) {
				rc = cil_symtab_get_node(&rule->obj->common->perms, (char*)perm->data, &perm_node);
				if (rc != SEPOL_OK) {
					printf("Failed to find perm in class or common symtabs\n");
					return rc;
				}
			}
			else {
				printf("Failed to find perm in class symtab\n");
				return rc;
			}
		}
		cil_list_item_init(&list_item);
		list_item->flavor = CIL_PERM;
		list_item->data = perm_node->data;
		if (perms_list->head == NULL) 
			perms_list->head = list_item;
		else 
			list_tail->next = list_item;
		list_tail = list_item;
		perm = perm->next;
	}
	rule->perms_list = perms_list;
	cil_list_destroy(&rule->perms_str, 1);

	return SEPOL_OK;
}

int cil_resolve_type_rule(struct cil_db *db, struct cil_tree_node *current)
{
	struct cil_type_rule *rule = (struct cil_type_rule*)current->data;
	struct cil_tree_node *src_node = NULL;
	struct cil_tree_node *tgt_node = NULL;
	struct cil_tree_node *obj_node = NULL;
	struct cil_tree_node *result_node = NULL;
	
	int rc = SEPOL_ERR;
	
	rc = cil_resolve_name(db, current, rule->src_str, CIL_SYM_TYPES, &src_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", rule->src_str);
		return SEPOL_ERR;
	}
	else {
		rule->src = (struct cil_type*)(src_node->data);
		free(rule->src_str);
		rule->src_str = NULL;
	}
					
	rc = cil_resolve_name(db, current, rule->tgt_str, CIL_SYM_TYPES, &tgt_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", rule->tgt_str);
		return SEPOL_ERR;
	}
	else {
		rule->tgt = (struct cil_type*)(tgt_node->data);
		free(rule->tgt_str);
		rule->tgt_str = NULL;	
	}

	rc = cil_resolve_name(db, current, rule->obj_str, CIL_SYM_CLASSES, &obj_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", rule->obj_str);
		return SEPOL_ERR;
	}
	else {
		rule->obj = (struct cil_class*)(obj_node->data);
		free(rule->obj_str);
		rule->obj_str = NULL;
	}

	rc = cil_resolve_name(db, current, rule->result_str, CIL_SYM_TYPES, &result_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", rule->result_str);
		return SEPOL_ERR;
	}
	else {
		rule->result = (struct cil_type*)(result_node->data);
		free(rule->result_str);
		rule->result_str = NULL;
	}
	return SEPOL_OK;
}

int cil_resolve_typeattr(struct cil_db *db, struct cil_tree_node *current)
{
	struct cil_typeattribute *typeattr = (struct  cil_typeattribute*)current->data;
	struct cil_tree_node *type_node = NULL;
	struct cil_tree_node *attr_node = NULL;
	int rc = SEPOL_ERR;
	rc = cil_resolve_name(db, current, typeattr->type_str, CIL_SYM_TYPES, &type_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", typeattr->type_str);
		return SEPOL_ERR;
	}
	typeattr->type = (struct cil_type*)(type_node->data);
	free(typeattr->type_str);
	typeattr->type_str = NULL;

	rc = cil_resolve_name(db, current, typeattr->attr_str, CIL_SYM_TYPES, &attr_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", typeattr->attr_str);
		return SEPOL_ERR;
	}
	typeattr->attr = (struct cil_type*)(attr_node->data);
	free(typeattr->attr_str);
	typeattr->attr_str = NULL;

	return SEPOL_OK;
}

int cil_resolve_typealias(struct cil_db *db, struct cil_tree_node *current)
{
	struct cil_typealias *alias = (struct cil_typealias*)current->data;
	struct cil_tree_node *type_node = NULL;
	int rc = cil_resolve_name(db, current, alias->type_str, CIL_SYM_TYPES, &type_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", alias->type_str);
		return SEPOL_ERR;
	}
	alias->type = (struct cil_type*)(type_node->data);
	free(alias->type_str);
	alias->type_str = NULL;

	return SEPOL_OK;
}

int cil_resolve_class(struct cil_db *db, struct cil_tree_node *current)
{
	struct cil_class *cls = (struct cil_class*)current->data;
	struct cil_tree_node *common_node = NULL;
	if (cls->common_str == NULL)
		return SEPOL_OK;

	if (cls->common_str != NULL) {
		int rc = cil_resolve_name(db, current, cls->common_str, CIL_SYM_COMMONS, &common_node);
		if (rc != SEPOL_OK) {
			printf("Name resolution failed for %s\n", cls->common_str);
			return SEPOL_ERR;
		}
		cls->common = (struct cil_common*)(common_node->data);
		free(cls->common_str);
		cls->common_str = NULL;
	}
	return SEPOL_OK;
}

int cil_resolve_userrole(struct cil_db *db, struct cil_tree_node *current)
{
	struct cil_userrole *userrole = (struct cil_userrole*)current->data;
	struct cil_tree_node *user_node = NULL;
	struct cil_tree_node *role_node = NULL;

	int rc = cil_resolve_name(db, current, userrole->user_str, CIL_SYM_USERS, &user_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", userrole->user_str);
		return SEPOL_ERR;
	} 
	userrole->user = (struct cil_user*)(user_node->data);
	free(userrole->user_str);
	userrole->user_str = NULL;

	rc = cil_resolve_name(db, current, userrole->role_str, CIL_SYM_ROLES, &role_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", userrole->role_str);
		return SEPOL_ERR;
	} 
	userrole->role = (struct cil_role*)(role_node->data);
	free(userrole->role_str);
	userrole->role_str = NULL;

	return SEPOL_OK;	
}

int cil_resolve_roletype(struct cil_db *db, struct cil_tree_node *current)
{
	struct cil_roletype *roletype = (struct cil_roletype*)current->data;
	struct cil_tree_node *role_node = NULL;
	struct cil_tree_node *type_node = NULL;
	
	int rc = cil_resolve_name(db, current, roletype->role_str, CIL_SYM_ROLES, &role_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", roletype->role_str);
		return SEPOL_ERR;
	}
	roletype->role = (struct cil_role*)(role_node->data);
	free(roletype->role_str);
	roletype->role_str = NULL;
	
	rc = cil_resolve_name(db, current, roletype->type_str, CIL_SYM_TYPES, &type_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", roletype->type_str);
		return SEPOL_ERR;
	}
	roletype->type = (struct cil_type*)(type_node->data);
	free(roletype->type_str);
	roletype->type_str = NULL;

	return SEPOL_OK;
}

int cil_resolve_roletrans(struct cil_db *db, struct cil_tree_node *current)
{
	struct cil_role_trans *roletrans = (struct cil_role_trans*)current->data;
	struct cil_tree_node *src_node = NULL;
	struct cil_tree_node *tgt_node = NULL;
	struct cil_tree_node *result_node = NULL;
	int rc = SEPOL_ERR;

	rc = cil_resolve_name(db, current, roletrans->src_str, CIL_SYM_ROLES, &src_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", roletrans->src_str);
		return SEPOL_ERR;
	}
	else {
		roletrans->src = (struct cil_role*)(src_node->data);
		free(roletrans->src_str);
		roletrans->src_str = NULL;
	}
					
	rc = cil_resolve_name(db, current, roletrans->tgt_str, CIL_SYM_TYPES, &tgt_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", roletrans->tgt_str);
		return SEPOL_ERR;
	}
	else {
		roletrans->tgt = (struct cil_type*)(tgt_node->data);
		free(roletrans->tgt_str);
		roletrans->tgt_str = NULL;	
	}

	rc = cil_resolve_name(db, current, roletrans->result_str, CIL_SYM_ROLES, &result_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", roletrans->result_str);
		return SEPOL_ERR;
	}
	else {
		roletrans->result = (struct cil_role*)(result_node->data);
		free(roletrans->result_str);
		roletrans->result_str = NULL;
	}

	return SEPOL_OK;	
}

int cil_resolve_roleallow(struct cil_db *db, struct cil_tree_node *current)
{
	struct cil_role_allow *roleallow = (struct cil_role_allow*)current->data;
	struct cil_tree_node *src_node = NULL;
	struct cil_tree_node *tgt_node = NULL;
	int rc = SEPOL_ERR;
	
	rc = cil_resolve_name(db, current, roleallow->src_str, CIL_SYM_ROLES, &src_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", roleallow->src_str);
		return SEPOL_ERR;
	}
	else {
		roleallow->src = (struct cil_role*)(src_node->data);
		free(roleallow->src_str);
		roleallow->src_str = NULL;
	}

	rc = cil_resolve_name(db, current, roleallow->tgt_str, CIL_SYM_ROLES, &tgt_node);	
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", roleallow->tgt_str);
		return SEPOL_ERR;
	}
	else {
		roleallow->tgt = (struct cil_role*)(tgt_node->data);
		free(roleallow->tgt_str);
		roleallow->tgt_str = NULL;
	}

	return SEPOL_OK;	
}

int cil_resolve_sensalias(struct cil_db *db, struct cil_tree_node *current)
{
	struct cil_sensalias *alias = (struct cil_sensalias*)current->data;
	struct cil_tree_node *sens_node = NULL;
	int rc = cil_resolve_name(db, current, alias->sens_str, CIL_SYM_SENS, &sens_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", alias->sens_str);
		return SEPOL_ERR;
	}
	alias->sens = (struct cil_sens*)(sens_node->data);
	free(alias->sens_str);
	alias->sens_str = NULL;

	return SEPOL_OK;
}

int cil_resolve_catalias(struct cil_db *db, struct cil_tree_node *current)
{
	struct cil_catalias *alias = (struct cil_catalias*)current->data;
	struct cil_tree_node *cat_node = NULL;
	int rc = cil_resolve_name(db, current, alias->cat_str, CIL_SYM_CATS, &cat_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", alias->cat_str);
		return SEPOL_ERR;
	}
	alias->cat = (struct cil_cat*)(cat_node->data);
	free(alias->cat_str);
	alias->cat_str = NULL;

	return SEPOL_OK;
}

int __cil_catorder_append(struct cil_list_item *main_list_item, struct cil_list_item *new_list_item, int *success)
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

int __cil_catorder_prepend(struct cil_list *main_list, struct cil_list *new_list, struct cil_list_item *main_list_item, struct cil_list_item *new_list_item, int *success)
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
				rc = cil_prepend_to_list(main_list, new_list_iter);
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

int __cil_catorder_merge_lists(struct cil_list *primary, struct cil_list *new, int *success)
{
	struct cil_list_item *curr_main = primary->head;
	struct cil_list_item *curr_new;
	int rc = SEPOL_ERR;
	while (curr_main != NULL) {
		curr_new = new->head;
		while (curr_new != NULL) {
			if (curr_main->data == curr_new->data) {
				if (curr_new->next == NULL) {
					rc = __cil_catorder_prepend(primary, new, curr_main, curr_new, success);
					if (rc != SEPOL_OK) {
						printf("Failed to prepend categoryorder sublist to primary list\n");
						return rc;
					}
					return SEPOL_OK;
				}
				else {
					rc = __cil_catorder_append(curr_main, curr_new, success);
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

int __cil_catorder_remove_list(struct cil_list *catorder, struct cil_list *remove_item)
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

int __cil_catorder_order(struct cil_db *db, struct cil_list *cat_edges)
{
	struct cil_list_item *catorder_head;
	struct cil_list_item *catorder_sublist;
	struct cil_list_item *catorder_lists;
	struct cil_list_item *edge_node;
	int success = 0;
	int rc = SEPOL_ERR;

	catorder_head = db->catorder->head;
	catorder_sublist = catorder_head;
	edge_node = cat_edges->head;
	while (edge_node != NULL) {
		while (catorder_sublist != NULL) {
			rc = __cil_catorder_merge_lists(((struct cil_list_item*)catorder_sublist)->data, edge_node->data, &success); 
			if (rc != SEPOL_OK) {
				printf("Failed to merge categoryorder sublist with main list\n");
				return rc;
			}
			if (success) 
				break;
			else if (catorder_sublist->next == NULL) { 
				catorder_sublist->next = edge_node;
				break;
			}
			catorder_sublist = catorder_sublist->next;
		}
		if (success) {
			success = 0;
			catorder_sublist = catorder_head;
			while (catorder_sublist != NULL) {
				catorder_lists = catorder_head;
				while (catorder_lists != NULL) {
					if (catorder_sublist != catorder_lists) {
						rc = __cil_catorder_merge_lists(((struct cil_list_item*)catorder_sublist)->data, ((struct cil_list_item*)catorder_lists)->data, &success);
						if (rc != SEPOL_OK) {
							printf("Failed combining categoryorder lists into one\n");
							return rc;
						}
						if (success) 
							__cil_catorder_remove_list(db->catorder, catorder_lists->data);
					}
					catorder_lists = catorder_lists->next;
				}
				catorder_sublist = catorder_sublist->next; 
			}
		}
		edge_node = edge_node->next;
	}
	return SEPOL_OK;
}

int cil_resolve_catorder(struct cil_db *db, struct cil_tree_node *current)
{
	struct cil_catorder *catorder = (struct cil_catorder*)current->data;
	struct cil_tree_node *cat_node = NULL;
	struct cil_list_item *curr_cat = catorder->cat_list_str->head;
	struct cil_list_item *list_item;
	struct cil_list_item *list_tail = NULL;
	struct cil_list_item *edge_node;
	struct cil_list_item *edges_list_tail = NULL;
	struct cil_list *cat_list;
	struct cil_list *edges_list;
	struct cil_list *edge = NULL;
	int rc = SEPOL_ERR;

	cil_list_init(&cat_list);
	cil_list_init(&edges_list);
	
	while (curr_cat != NULL) {
		cil_list_item_init(&list_item);
		rc = cil_resolve_name(db, current, (char*)curr_cat->data, CIL_SYM_CATS, &cat_node);
		if (rc != SEPOL_OK) {
			printf("Failed to resolve category name\n");
			return rc;
		}
		list_item->flavor = cat_node->flavor;
		list_item->data = cat_node->data;
		if (cat_list->head == NULL)
			cat_list->head = list_item;
		else
			list_tail->next = list_item;

		if (edge == NULL) {
			cil_list_init(&edge);
			if (list_tail == NULL) 
				edge->head = list_item;
			else
				edge->head = list_tail; 
		}
		else { 
			cil_list_item_init(&edge_node);
			edge->head->next = list_item;
			edge_node->data = edge;
			if (edges_list->head == NULL) 
				edges_list->head = edge_node;
			else 
				edges_list_tail->next = edge_node;
			edges_list_tail = edge_node;
			edge = NULL;
		}
		list_tail = list_item;
		curr_cat = curr_cat->next;
	}

	if (db->catorder->head == NULL) {
		cil_list_item_init(&list_item);
		list_item->data = cat_list; 
		db->catorder->head = list_item;
	}
	else {
		rc = __cil_catorder_order(db, edges_list);
		if (rc != SEPOL_OK) {
			printf("Failed to order categoryorder\n");
			return rc;
		}
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
	struct cil_list_item *catorder = ((struct cil_list*)db->catorder->head->data)->head;
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

int cil_resolve_cat_list(struct cil_db *db, struct cil_tree_node *current, struct cil_list *cat_list, struct cil_list *res_cat_list)
{
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
			__cil_resolve_cat_range(db, (struct cil_list*)curr->data, sub_list);
		}
		else {
			rc = cil_resolve_name(db, current, (char*)curr->data, CIL_SYM_CATS, &cat_node);
			if (rc != SEPOL_OK) {
				printf("Failed to resolve category name\n");
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

int cil_resolve_catset(struct cil_db *db, struct cil_tree_node *current)
{
	struct cil_catset *catset = (struct cil_catset*)current->data;
	struct cil_list *res_cat_list;
	int rc = SEPOL_ERR;

	cil_list_init(&res_cat_list);
	rc = cil_resolve_cat_list(db, current, catset->cat_list_str, res_cat_list);
	
	catset->cat_list = res_cat_list;
	cil_list_destroy(&catset->cat_list_str, 1);
	free(catset->cat_list_str);
	catset->cat_list_str = NULL;
	
	return SEPOL_OK;
}

int cil_resolve_senscat(struct cil_db *db, struct cil_tree_node *current)
{
	struct cil_tree_node *cat_node = NULL;
	struct cil_tree_node *sens_node = NULL;
	struct cil_senscat *senscat = (struct cil_senscat*)current->data;
	struct cil_list *sub_list;
	struct cil_list_item *curr = senscat->cat_list_str->head;
	struct cil_list_item *curr_range_cat;
	int rc = SEPOL_ERR;
	char *key = NULL;
	
	rc = cil_resolve_name(db, current, (char*)senscat->sens_str, CIL_SYM_SENS, &sens_node);
	if (rc != SEPOL_OK) {
		printf("Failed to get sensitivity node\n");
		return rc;
	}
	
	while (curr != NULL) {
		if (curr->flavor == CIL_LIST) {
			cil_list_init(&sub_list);
			__cil_resolve_cat_range(db, (struct cil_list*)curr->data, sub_list);
			curr_range_cat = sub_list->head;
			while (curr_range_cat != NULL) {
				key = cil_strdup(((struct cil_cat*)curr_range_cat->data)->datum.name);
				rc = cil_resolve_name(db, current, key, CIL_SYM_CATS, &cat_node);
				if (rc != SEPOL_OK) {
					printf("Failed to resolve category name\n");
					return rc;
				}
				rc = hashtab_insert(((struct cil_sens*)sens_node->data)->cats.table, (hashtab_key_t)key, (hashtab_datum_t)cat_node->data);
				if (rc != SEPOL_OK) {
					printf("Failed to insert category into sensitivitycategory symtab\n");
					return rc;
				}
				curr_range_cat = curr_range_cat->next;
			}
		}
		else {
			rc = cil_resolve_name(db, current, (char*)curr->data, CIL_SYM_CATS, &cat_node);
			if (rc != SEPOL_OK) {
				printf("Failed to resolve category name\n");
				return rc;
			}
			key = cil_strdup(curr->data);
			rc = hashtab_insert(((struct cil_sens*)sens_node->data)->cats.table, (hashtab_key_t)key, (hashtab_datum_t)cat_node->data);
			if (rc != SEPOL_OK) {
				printf("Failed to insert category into sensitivitycategory symtab\n");
				return rc;
			}
		}
		curr = curr->next;
	}

	cil_list_destroy(&senscat->cat_list_str, 1);
	free(senscat->cat_list_str);
	free(senscat->sens_str);
	senscat->cat_list_str = NULL;
	senscat->sens_str = NULL;

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
				return rc;
			}
		}
		curr_cat = curr_cat->next;
	}
	
	return SEPOL_OK;
}

int cil_resolve_level(struct cil_db *db, struct cil_tree_node *current)
{
	struct cil_level *level = (struct cil_level*)current->data;
	struct cil_tree_node *sens_node = NULL;
	struct cil_list *res_cat_list;
	int rc = SEPOL_ERR;
	symtab_t *symtab = NULL;

	rc = cil_get_parent_symtab(db, current, &symtab, CIL_SYM_SENS);
	if (rc != SEPOL_OK) {
		printf("Failed to get parent symtab\n");
		return rc;
	}
	
	rc = cil_symtab_get_node(symtab, (char*)level->sens_str, &sens_node);
	if (rc != SEPOL_OK) {
		printf("Failed to get sensitivity node\n");
		return rc;
	}

	level->sens = (struct cil_sens*)sens_node->data;

	cil_list_init(&res_cat_list);
	rc = cil_resolve_cat_list(db, current, level->cat_list_str, res_cat_list);
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
	cil_list_destroy(&level->cat_list_str, 1);
	free(level->cat_list_str);
	free(level->sens_str);
	level->cat_list_str = NULL;
	level->sens_str = NULL;
	
	return SEPOL_OK;
}

int cil_resolve_context(struct cil_db *db, struct cil_tree_node *current)
{
	struct cil_context *context = (struct cil_context*)current->data;
	struct cil_tree_node *user_node = NULL;
	struct cil_tree_node *role_node = NULL;
	struct cil_tree_node *type_node = NULL;
	struct cil_tree_node *low_node = NULL;
	struct cil_tree_node *high_node = NULL;

	int rc = SEPOL_ERR;
	char *error = NULL;

	rc = cil_resolve_name(db, current, context->user_str, CIL_SYM_USERS, &user_node);
	if (rc != SEPOL_OK) {
		error = context->user_str;
		goto resolve_context_cleanup;
	}
	context->user = (struct cil_user*)user_node->data;
	free(context->user_str);
	context->user_str = NULL;

	rc = cil_resolve_name(db, current, context->role_str, CIL_SYM_ROLES, &role_node);
	if (rc != SEPOL_OK) {
		error = context->role_str;
		goto resolve_context_cleanup;
	}
	context->role = (struct cil_role*)role_node->data;
	free(context->role_str);
	context->role_str = NULL;	

	rc = cil_resolve_name(db, current, context->type_str, CIL_SYM_TYPES, &type_node);
	if (rc != SEPOL_OK) {
		error = context->type_str;
		goto resolve_context_cleanup;
	}
	context->type = (struct cil_type*)type_node->data;
	free(context->type_str);
	context->type_str = NULL;

	if (context->low_str != NULL) {
		rc = cil_resolve_name(db, current, context->low_str, CIL_SYM_LEVELS, &low_node);
		if (rc != SEPOL_OK) {
			error = context->low_str;
			goto resolve_context_cleanup;
		}
		context->low = (struct cil_level*)low_node->data;
		free(context->low_str);
		context->low_str = NULL;
	}

	if (context->high_str != NULL) {
		rc = cil_resolve_name(db, current, context->high_str, CIL_SYM_LEVELS, &high_node);
		if (rc != SEPOL_OK) {
			error = context->high_str;
			goto resolve_context_cleanup;
		}
		context->high = (struct cil_level*)high_node->data;
		free(context->high_str);
		context->high_str = NULL;
	}

	return SEPOL_OK;

	resolve_context_cleanup:
		printf("Name resolution failed for %s\n", error);
		return SEPOL_ERR;
}

int __cil_resolve_ast_helper(struct cil_db *db, struct cil_tree_node *current, uint32_t pass)
{
	int rc = SEPOL_ERR;
	int reverse = 0;

	if (current == NULL) {
		printf("Error: Can't resolve NULL tree\n");
		return SEPOL_ERR;
	}

	do {
		if (current->cl_head == NULL) {
//			printf("FLAVOR: %d\n", current->flavor);
			switch (pass) {
				case 1 : {
					//dominance
					//catorder
					switch (current->flavor) {
						case CIL_CATORDER : {
							printf("case categoryorder\n");
							rc = cil_resolve_catorder(db, current);
							if (rc != SEPOL_OK)
								return rc;
							break;
						}
					}
					break;
				}
				case 2 : {
					//sensitivitycategory
					switch (current->flavor) {
						case CIL_SENSCAT : {
							printf("case sensitivitycategory\n");
							rc = cil_resolve_senscat(db, current);
							if (rc != SEPOL_OK)
								return rc;
							break;
						}
					}
					break;
				}
				case 3 : {
					switch (current->flavor) {
						case CIL_TYPE_ATTR : {
							printf("case typeattribute\n");
							rc = cil_resolve_typeattr(db, current);
							if (rc !=  SEPOL_OK)
								return rc;
							break;
						}
						case CIL_TYPEALIAS : {
							printf("case typealias\n");
							rc = cil_resolve_typealias(db, current);
							if (rc != SEPOL_OK)
								return rc;
							break;
						}
						case CIL_AVRULE : {
							printf("case avrule\n");
							rc = cil_resolve_avrule(db, current);
							if (rc != SEPOL_OK)
								return rc;
							break;
						}
						case CIL_TYPE_RULE : {
							printf("case type_rule\n");
							rc = cil_resolve_type_rule(db, current);
							if (rc != SEPOL_OK)
								return rc;
							break;
						}
						case CIL_USERROLE : {
							printf("case userrole\n");
							rc = cil_resolve_userrole(db, current);
							if (rc != SEPOL_OK)
								return rc;
							break;
						}
						case CIL_ROLETYPE : {
							printf("case roletype\n");
							rc = cil_resolve_roletype(db, current);
							if (rc != SEPOL_OK)
								return rc;
							break;
						}
						case CIL_ROLETRANS : {
							printf("case roletransition\n");
							rc = cil_resolve_roletrans(db, current);
							if (rc != SEPOL_OK)
								return rc;
							break;
						}
						case CIL_ROLEALLOW : {
							printf("case roleallow\n");
							rc = cil_resolve_roleallow(db, current);
							if (rc != SEPOL_OK)
								return rc;
							break;
						}
						case CIL_SENSALIAS : {
							printf("case sensitivityalias\n");
							rc = cil_resolve_sensalias(db, current);
							if (rc != SEPOL_OK)
								return rc;
							break;
						}
						case CIL_CATALIAS : {
							printf("case categoryalias\n");
							rc = cil_resolve_catalias(db, current);
							if (rc != SEPOL_OK)
								return rc;
							break;
						}
						case CIL_CATSET : {
							printf("case categoryset\n");
							rc = cil_resolve_catset(db, current);
							if (rc != SEPOL_OK)
								return rc;
							break;
						}
						case CIL_LEVEL : {
							printf("case level\n");
							rc = cil_resolve_level(db, current);
							if (rc != SEPOL_OK)
								return rc;
							break;
						}
						case CIL_CONTEXT : {
							printf("case context\n");
							rc = cil_resolve_context(db, current);
							if (rc != SEPOL_OK)
								return rc;
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
//			printf("FLAVOR: %d\n", current->flavor);
			switch (pass) {
				case 1 : {
					switch (current->flavor) {
						case CIL_CLASS : {
							printf("case class\n");
							rc = cil_resolve_class(db, current);
							if (rc != SEPOL_OK)
								return rc;
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

		if (current->cl_head != NULL && !reverse)
			current = current->cl_head;
		else if (current->next != NULL && reverse) {
			current = current->next;
			reverse = 0;
		}
		else if (current->next != NULL)
			current = current->next;
		else {
			current = current->parent;
			reverse = 1;
		}
	} while (current->flavor != CIL_ROOT);
	return SEPOL_OK;
}

static int __cil_resolve_name_helper(struct cil_db *db, struct cil_tree_node *ast_node, char *name, uint32_t sym_index, struct cil_tree_node **node)
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
		rc = cil_get_parent_symtab(db, ast_node, &symtab, CIL_SYM_BLOCKS);
		if (rc != SEPOL_OK) {
			printf("__cil_resolve_name_helper: cil_get_parent_symtab failed, rc: %d\n", rc);
			goto resolve_name_helper_cleanup;
		}
	}

	if (tok_next == NULL) {
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
		if (rc)
			return rc;
		else
			return SEPOL_ERR;
}

int cil_resolve_name(struct cil_db *db, struct cil_tree_node *ast_node, char *name, uint32_t sym_index, struct cil_tree_node **node)
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
		else {
			if (__cil_resolve_name_helper(db, ast_node, name, sym_index, node) != SEPOL_OK) {
				global_symtab_name = cil_malloc(strlen(name)+2);
				strcpy(global_symtab_name, ".");
				strncat(global_symtab_name, name, strlen(name));
			}
		}
	}
		
	first = *global_symtab_name;

	if (first == '.') {
		if (strrchr(global_symtab_name, '.') == global_symtab_name) { //Only one dot in name, check global symtabs
			if (cil_symtab_get_node(&db->symtab[sym_index], global_symtab_name+1, node)) {
				free(global_symtab_name);
				return SEPOL_ERR;
			}
		}
		else {
			if (__cil_resolve_name_helper(db, db->ast->root, global_symtab_name, sym_index, node)) {
				free(global_symtab_name);
				return SEPOL_ERR;
			}
		}
	}

	if (global_symtab_name != name)
		free(global_symtab_name);

	return SEPOL_OK;
}

