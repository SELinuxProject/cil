#include <stdio.h>
#include "cil_tree.h"

void cil_print_tree(struct cil_tree_node *tree, uint32_t depth)
{
        struct cil_tree_node * current;
        current = tree;
        uint32_t x = 0;
        uint32_t tmp = depth;

        if (current != NULL)
        {
//		printf("cil_print_tree: current not null\n");
                if (current->cl_head == NULL)
                {
//			printf("cil_print_tree: current->cl_head is null\n");
			//TODO: If flavor == parser do these, else call functions to lookup data from symtab and print
                        if (current->parent->cl_head == current)
                                printf("%s", (char*)current->data);
                        else
                                printf(" %s", (char*)current->data);
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
                        }
                        cil_print_tree(current->cl_head, depth + 1);
                }
                if (current->next == NULL)
                {
//			printf("cil_print_tree: current->next is null\n");
                        if ((current->parent != NULL) && (current->parent->cl_tail == current) && (current->parent->parent != NULL))
                                printf(")");
                        if ((current->parent != NULL) && (current->parent->parent == NULL))
                                printf("\n\n");
                }
                else
                {
//			printf("cil_print_tree: current->next is not null\n");
                        cil_print_tree(current->next, depth);
                }
        }
}
