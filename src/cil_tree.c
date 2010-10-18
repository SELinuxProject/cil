#include <stdio.h>
#include "cil_tree.h"
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
	cil_data_destroy(&(*node)->data, (*node)->flavor);
	free(*node);
	*node = NULL;
}

void cil_tree_print_perms_list(struct cil_tree_node *current_perm)
{
	while (current_perm != NULL) {
		if (current_perm->flavor == CIL_PERM) {
			printf(" %d", ((struct cil_perm *)current_perm->data)->datum.value);
		}
		else {
			printf("\n\n perms list contained unexpected data type: %d\n", current_perm->flavor);
			break;
		}
		current_perm = current_perm->next;	
	}
}

void cil_tree_print_node(struct cil_tree_node *node)
{
	switch( node->flavor ) {
		case CIL_BLOCK	: {
			struct cil_block *block = node->data;
			printf("BLOCK: %d\n", block->datum.value);
			return;
		}
		case CIL_TYPE : {
			struct cil_type *type = node->data;
			printf("TYPE: %d\n", type->datum.value);
			return;
		}
		case CIL_ATTR : {
			struct cil_type *attr = node->data;
			printf("ATTRIBUTE: %d\n", attr->datum.value);
			return;
		}
		case CIL_ROLE : {
			struct cil_role *role = node->data;
			printf("ROLE: %d\n", role->datum.value);
			return;
		}
		case CIL_CLASS : {
			struct cil_class *cls = node->data;
			printf("CLASS: %d ", cls->datum.value);
			
			if (cls->common_str != NULL)
				printf("inherits: %s ", cls->common_str);
			else if (cls->common != NULL)
				printf("inherits: %d ", cls->common->datum.value);
			printf("(");

			cil_tree_print_perms_list(node->cl_head);

			printf(" )");
			return;
		}
		case CIL_COMMON : {
			struct cil_common *common = node->data;
			printf("COMMON: %d (", common->datum.value);
		
			cil_tree_print_perms_list(node->cl_head);
	
			printf(" )");
			return;
							
		}
		case CIL_BOOL : {
			struct cil_bool *boolean = node->data;
			printf("BOOL: %d, value: %d\n", boolean->datum.value, boolean->value);
			return;
		}
		case CIL_TYPEALIAS : {
			struct cil_typealias *alias = node->data;
			if (alias->type_str != NULL) 
				printf("TYPEALIAS: %d, type: %s\n", alias->datum.value, alias->type_str);
			else
				printf("TYPEALIAS: %d, type: %d\n", alias->datum.value, alias->type->datum.value);
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
				printf(" %d", rule->src->datum.value);
			if (rule->tgt_str != NULL)
				printf(" %s", rule->tgt_str);
			else
				printf(" %d", rule->tgt->datum.value);
			if (rule->obj_str != NULL)
				printf(" %s", rule->obj_str);
			else
				printf(" %d", rule->obj->datum.value);
			printf(" (");
			if (rule->perms_str != NULL) {
				item = rule->perms_str->list;
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
				item = rule->perms_list->list;
				while(item != NULL) {
					if (item->flavor == CIL_PERM)
						printf(" %s", ((struct cil_perm*)item->data)->datum.name);
					else {
						printf("\n\n perms list contained uexpected data type\n");
						break;
					}
					item = item->next;
				}
			}
			printf(" )\n");
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
