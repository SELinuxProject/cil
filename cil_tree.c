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
				printf("CIL_TYPE: %d\n", current->flavor);	
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
					printf("CIL_TYPE: %d\n", current->flavor);
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
