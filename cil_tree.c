#include <stdio.h>
#include "cil_tree.h"
#include "cil.h"

void cil_print_tree(struct cil_tree_node *tree, uint32_t depth)
{
        struct cil_tree_node * current;
        current = tree;
        uint32_t x = 0;

        if (current != NULL)
        {
//		printf("cil_print_tree: current not null\n");
                if (current->cl_head == NULL)
                {
//			printf("cil_print_tree: current->cl_head is null\n");
			if (current->flavor == CIL_PARSER)
			{
                        	if (current->parent->cl_head == current)
                                	printf("%s", (char*)current->data);
	                        else
        	                        printf(" %s", (char*)current->data);
			}
			else
			{
				for (x = 0; x<depth; x++)
					printf("\t");
				printf("CIL_TYPE: %d\n", current->flavor);	
			}
                }
                else
                {
//			printf("cil_print_tree: current->cl_head is not null\n");
                        if (current->parent != NULL)
                        {
//				printf("cil_print_tree: current->parent not null\n");
                                printf("\n");
                                for (x = 0; x<depth; x++)
                                        printf("\t");
                                printf("(");

				if (current->flavor != CIL_PARSER)
					printf("CIL_TYPE: %d\n", current->flavor);
                        }
                        cil_print_tree(current->cl_head, depth + 1);
                }
                if (current->next == NULL)
                {
//			printf("cil_print_tree: current->next is null\n");
                        if ((current->parent != NULL) && (current->parent->cl_tail == current) && (current->parent->parent != NULL)){
				if (current->flavor != CIL_PARSER)
				{
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
                else
                {
//			printf("cil_print_tree: current->next is not null\n");
                        cil_print_tree(current->next, depth);
                }
        }
	else
		printf("Tree is NULL\n");
}
