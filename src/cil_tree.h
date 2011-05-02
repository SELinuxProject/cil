#ifndef CIL_TREE_H_
#define CIL_TREE_H_

#include <stdint.h>

#include "cil_list.h"

struct cil_tree {
	struct cil_tree_node *root;
};

struct cil_tree_node {
	struct cil_tree_node *parent;
	struct cil_tree_node *cl_head;		//Head of child_list
	struct cil_tree_node *cl_tail;		//Tail of child_list
	struct cil_tree_node *next;		//Each element in the list points to the next element
	uint32_t flavor;
	uint32_t line;
	//TODO add file path here
	void *data;
};
int cil_tree_init(struct cil_tree **);
int cil_tree_node_init(struct cil_tree_node **);
void cil_tree_destroy(struct cil_tree **);
void cil_tree_node_destroy(struct cil_tree_node **);

//finished values
#define CIL_TREE_SKIP_NOTHING	0
#define CIL_TREE_SKIP_NEXT	1
#define CIL_TREE_SKIP_HEAD	2
#define CIL_TREE_SKIP_ALL	(CIL_TREE_SKIP_NOTHING | CIL_TREE_SKIP_NEXT | CIL_TREE_SKIP_HEAD)
int cil_tree_walk(struct cil_tree_node *, int (*process)(struct cil_tree_node *, uint32_t *, struct cil_list *), int (*finished_branch)(struct cil_tree_node *, struct cil_list *), struct cil_list *);
void cil_tree_print_node(struct cil_tree_node *);
void cil_tree_print(struct cil_tree_node *, uint32_t);
void cil_tree_print_perms_list(struct cil_tree_node *);
#endif /* CIL_TREE_H_ */

