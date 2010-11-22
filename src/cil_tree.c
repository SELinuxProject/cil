#include <stdio.h>
#include "cil_tree.h"
#include "cil_list.h"
#include "cil.h"
#include "cil_parser.h"

int cil_tree_init(struct cil_tree **tree)
{
	struct cil_tree *new_tree;
	new_tree = cil_malloc(sizeof(struct cil_tree));
	cil_tree_node_init(&new_tree->root);
	
	*tree = new_tree;
	
	return SEPOL_OK;
}

void cil_tree_destroy(struct cil_tree **tree)
{
	struct cil_tree_node *node = (*tree)->root;
	struct cil_tree_node *next = NULL;

	while(node != NULL)
	{
		//printf("##### node: %d#####\n", (char*)node->flavor);
		if (node->cl_head != NULL){
			next = node->cl_head;
		}
		
		else {
			if (node->next == NULL) {
				next = node->parent;
				if (node->parent != NULL) {
					node->parent->cl_head = NULL;
				}
				//printf("Destroying node\n");
				cil_tree_node_destroy(&node);
			}
			else {
				next = node->next;
				//printf("Destroying node\n");
				cil_tree_node_destroy(&node);
			}
		}
		node = next;
	}

	*tree = NULL;
}

int cil_tree_node_init(struct cil_tree_node **node)
{
	struct cil_tree_node *new_node;
	new_node = cil_malloc(sizeof(struct cil_tree_node));
	new_node->cl_head = NULL;
	new_node->cl_tail = NULL;
	new_node->parent = NULL;
	new_node->data = NULL;
	new_node->next = NULL;
	new_node->flavor = CIL_ROOT;
	new_node->line = 0;	

	*node = new_node;

	return SEPOL_OK;
}

void cil_tree_node_destroy(struct cil_tree_node **node)
{
	cil_destroy_data(&(*node)->data, (*node)->flavor);
	free(*node);
	*node = NULL;
}

void cil_tree_print_perms_list(struct cil_tree_node *current_perm)
{
	while (current_perm != NULL) {
		if (current_perm->flavor == CIL_PERM) {
			printf(" %s", ((struct cil_perm *)current_perm->data)->datum.name);
		}
		else {
			printf("\n\n perms list contained unexpected data type: %d\n", current_perm->flavor);
			break;
		}
		current_perm = current_perm->next;	
	}
}

void cil_tree_print_level(struct cil_level *level)
{
	struct cil_list_item *cat;
	struct cil_list_item *parent;
	if (level->sens_str != NULL)
		printf(" %s", level->sens_str);
	else if (level->sens != NULL)
		printf(" %s", level->sens->datum.name);
	printf(" (");
	if (level->cat_list_str != NULL) {
		cat = level->cat_list_str->head;
		while (cat != NULL) {
			if (cat->flavor == CIL_LIST) {
				parent = cat;
				cat = ((struct cil_list *)cat->data)->head;
				printf(" (");
				while (cat != NULL) {
					printf(" %s", (char*)cat->data);
					cat = cat->next;
				}
				printf(" )");
				cat = parent;
			}
			else
				printf(" %s", (char*)cat->data);
				cat = cat->next;
			}
	}
	else if (level->cat_list != NULL) {
		cat = level->cat_list->head;
		while (cat != NULL) {
			if (cat->flavor == CIL_LIST) {
				parent = cat;
				cat = ((struct cil_list *)cat->data)->head;
				printf(" (");
				while (cat != NULL) {
					printf(" %s", ((struct cil_cat*)cat->data)->datum.name);
					cat = cat->next;
				}
				printf(" )");
				cat = parent;
			}
			else
				printf(" %s", ((struct cil_cat*)cat->data)->datum.name);
			cat = cat->next;
		}
	}
	printf(" )");
	return;
}

void cil_tree_print_context(struct cil_context *context)
{
	if (context->user_str != NULL)
		printf(" %s", context->user_str);
	else if (context->user != NULL)
		printf(" %s", context->user->datum.name);
	if (context->role_str != NULL)
		printf(" %s", context->role_str);
	else if (context->role != NULL)
		printf(" %s", context->role->datum.name);
	if (context->type_str != NULL)
		printf(" %s", context->type_str);
	else if (context->type != NULL)
		printf(" %s", context->type->datum.name);
	if (context->low_str != NULL)
		printf(" %s", context->low_str);
	else if (context->low != NULL) {
//		if (context->low->datum.name != NULL)
//			printf(" %s", context->low->datum.name);
//		else {
			printf(" (");
			cil_tree_print_level(context->low);
			printf(" )");
//		}
	}
	if (context->high_str != NULL)
		printf(" %s", context->high_str);
	else if (context->high != NULL) {
//		if (context->high->datum.name != NULL)
//			printf(" %s", context->high->datum.name);
//		else {
			printf(" (");
			cil_tree_print_level(context->high);
			printf(" )");
//		}
	}
	return;
}

void cil_tree_print_node(struct cil_tree_node *node)
{
	switch( node->flavor ) {
		case CIL_BLOCK	: {
			struct cil_block *block = node->data;
			printf("BLOCK: %s\n", block->datum.name);
			return;
		}
		case CIL_USER: {
			struct cil_user *user = node->data;
			printf("USER: %s\n", user->datum.name);
			return;
		}
		case CIL_TYPE : {
			struct cil_type *type = node->data;
			printf("TYPE: %s\n", type->datum.name);
			return;
		}
		case CIL_ATTR : {
			struct cil_type *attr = node->data;
			printf("ATTRIBUTE: %s\n", attr->datum.name);
			return;
		}
		case CIL_ROLE : {
			struct cil_role *role = node->data;
			printf("ROLE: %s\n", role->datum.name);
			return;
		}
		case CIL_USERROLE : {
			struct cil_userrole *userrole = node->data;
			printf("USERROLE:");
			if (userrole->user_str != NULL)
				printf(" %s", userrole->user_str);
			else if (userrole->user != NULL)
				printf(" %s", userrole->user->datum.name);
			if (userrole->role_str != NULL)
				printf(" %s", userrole->role_str);
			else if (userrole->role != NULL)
				printf(" %s", userrole->role->datum.name);
			printf("\n");
			return;
		}
		case CIL_ROLETYPE : {
			struct cil_roletype *roletype = node->data;
			printf("ROLETYPE:");
			if (roletype->role_str != NULL)
				printf(" %s", roletype->role_str);
			else if (roletype->role != NULL)
				printf(" %s", roletype->role->datum.name);
			if (roletype->type_str != NULL)
				printf(" %s", roletype->type_str);
			else if (roletype->type != NULL)
				printf(" %s", roletype->type->datum.name);
			printf("\n");
			return;
		}
		case CIL_ROLETRANS : {
			struct cil_role_trans *roletrans = node->data;
			printf("ROLETRANSITION:");
			if (roletrans->src_str != NULL)
				printf(" %s", roletrans->src_str);
			else
				printf(" %s", roletrans->src->datum.name);
			if (roletrans->tgt_str != NULL)
				printf(" %s", roletrans->tgt_str);
			else
				printf(" %s", roletrans->tgt->datum.name);
			if (roletrans->result_str != NULL)
				printf(" %s\n", roletrans->result_str);
			else
				printf(" %s\n", roletrans->result->datum.name);
			return;
		}
		case CIL_ROLEALLOW : {
			struct cil_role_allow *roleallow = node->data;
			printf("ROLEALLOW:");
			if (roleallow->src_str != NULL)
				printf(" %s", roleallow->src_str);
			else
				printf(" %s", roleallow->src->datum.name);
			if (roleallow->tgt_str != NULL)
				printf(" %s", roleallow->tgt_str);
			else
				printf(" %s", roleallow->tgt->datum.name);
			printf("\n");
			return;
		}
		case CIL_CLASS : {
			struct cil_class *cls = node->data;
			printf("CLASS: %s ", cls->datum.name);
			
			if (cls->common_str != NULL)
				printf("inherits: %s ", cls->common_str);
			else if (cls->common != NULL)
				printf("inherits: %s ", cls->common->datum.name);
			printf("(");

			cil_tree_print_perms_list(node->cl_head);

			printf(" )");
			return;
		}
		case CIL_COMMON : {
			struct cil_common *common = node->data;
			printf("COMMON: %s (", common->datum.name);
		
			cil_tree_print_perms_list(node->cl_head);
	
			printf(" )");
			return;
							
		}
		case CIL_BOOL : {
			struct cil_bool *boolean = node->data;
			printf("BOOL: %s, value: %d\n", boolean->datum.name, boolean->value);
			return;
		}
		case CIL_TYPE_ATTR : {
			struct cil_typeattribute *typeattr = node->data;
			if (typeattr->type_str != NULL && typeattr->attr_str != NULL)
				printf("TYPEATTR: type: %s, attribute: %s\n", typeattr->type_str, typeattr->attr_str);
			else
				printf("TYPEATTR: type: %s, attribute: %s\n", typeattr->type->datum.name, typeattr->attr->datum.name);
			return;
		}
		case CIL_TYPEALIAS : {
			struct cil_typealias *alias = node->data;
			if (alias->type_str != NULL) 
				printf("TYPEALIAS: %s, type: %s\n", alias->datum.name, alias->type_str);
			else
				printf("TYPEALIAS: %s, type: %s\n", alias->datum.name, alias->type->datum.name);
			return;
		}
		case CIL_AVRULE : {
			struct cil_avrule *rule = node->data;
			struct cil_list_item *item = NULL;
			switch (rule->rule_kind) {
				case CIL_AVRULE_ALLOWED:
					printf("ALLOW:");
					break;
				case CIL_AVRULE_AUDITALLOW:
					printf("AUDITALLOW:");
					break;
				case CIL_AVRULE_DONTAUDIT:
					printf("DONTAUDIT:");
					break;
				case CIL_AVRULE_NEVERALLOW:
					printf("NEVERALLOW:");
					break;
			}
			if (rule->src_str != NULL)
				printf(" %s", rule->src_str);
			else
				printf(" %s", rule->src->datum.name);
			if (rule->tgt_str != NULL)
				printf(" %s", rule->tgt_str);
			else
				printf(" %s", rule->tgt->datum.name);
			if (rule->obj_str != NULL)
				printf(" %s", rule->obj_str);
			else
				printf(" %s", rule->obj->datum.name);
			printf(" (");
			if (rule->perms_str != NULL) {
				item = rule->perms_str->head;
				while(item != NULL) {
					if (item->flavor == CIL_AST_STR)
						printf(" %s", (char*)item->data);
					else {
						printf("\n\n perms list contained unexpected data type\n");
						break;
					}
					item = item->next;
				}
			}
			else {
				item = rule->perms_list->head;
				while(item != NULL) {
					if (item->flavor == CIL_PERM)
						printf(" %s", ((struct cil_perm*)item->data)->datum.name);
					else {
						printf("\n\n perms list contained unexpected data type\n");
						break;
					}
					item = item->next;
				}
			}
			printf(" )\n");
			return;
		}
		case CIL_TYPE_RULE : {
			struct cil_type_rule *rule = node->data;
			switch (rule->rule_kind) {
				case CIL_TYPE_TRANSITION:
					printf("TYPETRANSITION:");
					break;
				case CIL_TYPE_MEMBER:
					printf("TYPEMEMBER:");
					break;
				case CIL_TYPE_CHANGE:
					printf("TYPECHANGE:");
					break;
			}
			if (rule->src_str != NULL)
				printf(" %s", rule->src_str);
			else
				printf(" %s", rule->src->datum.name);
			if (rule->tgt_str != NULL)
				printf(" %s", rule->tgt_str);
			else
				printf(" %s", rule->tgt->datum.name);
			if (rule->obj_str != NULL)
				printf(" %s", rule->obj_str);
			else
				printf(" %s", rule->obj->datum.name);
			if (rule->result_str != NULL)
				printf(" %s\n", rule->result_str);
			else
				printf(" %s\n", rule->result->datum.name);
			return;
		}
		case CIL_SENS : {
			struct cil_sens *sens = node->data;
			printf("SENSITIVITY: %s\n", sens->datum.name);
			return;
		}
		case CIL_SENSALIAS : {
			struct cil_sensalias *alias = node->data;
			if (alias->sens_str != NULL) 
				printf("SENSITIVITYALIAS: %s, sensitivity: %s\n", alias->datum.name, alias->sens_str);
			else
				printf("SENSITIVITYALIAS: %s, sensitivity: %s\n", alias->datum.name, alias->sens->datum.name);
			return;
		}
		case CIL_CAT : {
			struct cil_cat *cat = node->data;
			printf("CATEGORY: %s\n", cat->datum.name);
			return;
		}
		case CIL_CATALIAS : {
			struct cil_catalias *alias = node->data;
			if (alias->cat_str != NULL) 
				printf("CATEGORYALIAS: %s, category: %s\n", alias->datum.name, alias->cat_str);
			else
				printf("CATEGORYALIAS: %s, category: %s\n", alias->datum.name, alias->cat->datum.name);
			return;
		}
		case CIL_CATSET : {
			struct cil_catset *catset = node->data;
			struct cil_list_item *cat;
			struct cil_list_item *parent;
			if (catset->cat_list_str != NULL)
				cat = catset->cat_list_str->head;
			else
				cat = catset->cat_list->head;
			printf("CATSET: %s (",catset->datum.name);
			while (cat != NULL) {
				if (cat->flavor == CIL_LIST) {
					parent = cat;
					cat = ((struct cil_list*)cat->data)->head;
					printf(" (");
					while (cat != NULL) {
						printf(" %s", ((struct cil_cat*)cat->data)->datum.name);
						cat = cat->next;
					}
					printf(" )");
					cat = parent;
				}
				else
					printf(" %s", ((struct cil_cat*)cat->data)->datum.name);
				cat = cat->next;
			}
			printf(" )\n");
			return;
		}
		case CIL_CATORDER : {
			struct cil_catorder *catorder = node->data;
			struct cil_list_item *cat;
			if (catorder->cat_list_str != NULL)
				cat = catorder->cat_list_str->head;
			else
				return;
			printf("CATORDER: (");
			while (cat != NULL) {
				printf(" %s", (char*)cat->data);
				cat = cat->next;
			}
			printf(" )\n");
			return;
		}
		case CIL_SENSCAT : {
			struct cil_senscat *senscat = node->data;
			struct cil_list_item *cat;
			struct cil_list_item *parent;
			printf("SENSCAT:");
			if (senscat->sens_str != NULL)
				printf(" %s", senscat->sens_str);
			else
				printf(" [processed]");
			if (senscat->cat_list_str != NULL) {
				cat = senscat->cat_list_str->head;
				while (cat != NULL) {
					if (cat->flavor == CIL_LIST) {
						parent = cat;
						cat = ((struct cil_list*)cat->data)->head;
						printf(" (");
						while (cat != NULL) {
							printf(" %s", (char*)cat->data);
							cat = cat->next;
						}
						printf(" )");
						cat = parent;
					}
					else
						printf(" %s", (char*)cat->data);
					cat = cat->next;
				}
			}
			else
				printf("\n");
				return;
			printf(" )\n");
			return;
		}
		case CIL_LEVEL : {
			struct cil_level *level = node->data;
			printf("LEVEL %s:", level->datum.name); 
			cil_tree_print_level(level);
			printf("\n");
			return;
		}
		case CIL_CONTEXT : {
			struct cil_context *context = node->data;
			printf("CONTEXT %s:", context->datum.name);
			cil_tree_print_context(context);
			printf("\n");
			return;
		}
		case CIL_NETIFCON : {
			struct cil_netifcon *netifcon = node->data;
			printf("NETIFCON %s", netifcon->datum.name);
			if (netifcon->if_context_str != NULL)
				printf(" %s", netifcon->if_context_str);
			else if (netifcon->if_context != NULL) {
				printf(" (");
				cil_tree_print_context(netifcon->if_context);
				printf(" )");
			}
			if (netifcon->packet_context_str != NULL)
				printf(" %s", netifcon->packet_context_str);
			else if (netifcon->packet_context != NULL) {
				printf(" (");
				cil_tree_print_context(netifcon->packet_context);
				printf(" )");
			}
			printf("\n");
			return;
		}
					
		default : {
			printf("CIL FLAVOR: %d\n", node->flavor);
			return;
		}
	}
}

void cil_tree_print(struct cil_tree_node *tree, uint32_t depth)
{
	struct cil_tree_node * current;
	current = tree;
	uint32_t x = 0;

	if (current != NULL) {
//		printf("cil_tree_print: current not null\n");
		if (current->cl_head == NULL) {
//			printf("cil_tree_print: current->cl_head is null\n");
			if (current->flavor == CIL_PARSER) {
				if (current->parent->cl_head == current)
					printf("%s", (char*)current->data);
				else
					printf(" %s", (char*)current->data);
			}
			else if (current->flavor != CIL_PERM) {
				for (x = 0; x<depth; x++)
					printf("\t");
				cil_tree_print_node(current);
			}
		}
		else {
//			printf("cil_tree_print: current->cl_head is not null\n");
			if (current->parent != NULL) {
//				printf("cil_tree_print: current->parent not null\n");
				printf("\n");
				for (x = 0; x<depth; x++)
					printf("\t");
				printf("(");

				if (current->flavor != CIL_PARSER) 
					cil_tree_print_node(current);
			}
			cil_tree_print(current->cl_head, depth + 1);
		}
		if (current->next == NULL) {
//			printf("cil_tree_print: current->next is null\n");
			if ((current->parent != NULL) && (current->parent->cl_tail == current) && (current->parent->parent != NULL)) {
				if (current->flavor == CIL_PERM)
					printf(")\n");
				else if (current->flavor != CIL_PARSER) {
					for (x = 0; x<depth-1; x++)
						printf("\t");
					printf(")\n");
				}
				else
					printf(")");
			}
			if ((current->parent != NULL) && (current->parent->parent == NULL))
				printf("\n\n");
		}
		else {
//			printf("cil_tree_print: current->next is not null\n");
			cil_tree_print(current->next, depth);
		}
	}
	else
		printf("Tree is NULL\n");
}
