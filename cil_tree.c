#include <stdio.h>
#include "cil_tree.h"
#include "cil.h"

int cil_tree_init(struct cil_tree **tree)
{
	struct cil_tree *new_tree;
	new_tree = malloc(sizeof(struct cil_tree));
	cil_tree_node_init(&new_tree->root);
	
	*tree = new_tree;
	
	return SEPOL_OK;
}

int cil_tree_node_init(struct cil_tree_node **node)
{
	struct cil_tree_node *new_node;
	new_node = malloc(sizeof(struct cil_tree_node));
	new_node->cl_head = NULL;
	new_node->cl_tail = NULL;
	new_node->parent = NULL;
	new_node->data = NULL;
	new_node->next = NULL;
	new_node->flavor = 0;
	new_node->line = 0;	

	*node = new_node;

	return SEPOL_OK;
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
		case CIL_ROLE : {
			struct cil_role *role = node->data;
			printf("ROLE: %d\n", role->datum.value);
			return;
		}
		case CIL_PERM : {
			struct cil_perm *perm = node->data;
			printf("PERM: %d\n", perm->datum.value);
			return;
		}
		case CIL_CLASS : {
			int *id;
			struct cil_class *cls = node->data;
			struct cil_list_item *item;
			item = cls->av->list;
			printf("CLASS: %d (", cls->datum.value);
			while (item != NULL) {
				if (item->flavor == CIL_SEPOL_ID) {
					id = item->data;
					printf(" %d", *id);
				}
				else {
					printf(" %s", (char*)item->data);
				}
				item = item->next;
			}
			printf(" )\n");
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
				printf("TYPEALIAS: %d, type: %d\n", alias->datum.value, alias->type);
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
			else {
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
				if (current->flavor != CIL_PARSER) {
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
