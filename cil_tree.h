#ifndef CIL_TREE_H_
#define CIL_TREE_H_

#include <stdint.h>

struct cil_tree
{
	struct cil_tree_node *root;
};

struct cil_tree_node
{
        struct cil_tree_node *parent;
        struct cil_tree_node *cl_head;        //Head of child_list
        struct cil_tree_node *cl_tail;        //Tail of child_list
        struct cil_tree_node *next;           //Each element in the list points to the next element
	uint32_t flavor;
	uint32_t line;
	void *data;
};

void cil_print_tree(struct cil_tree_node *, uint32_t);

#endif /* CIL_TREE_H_ */

