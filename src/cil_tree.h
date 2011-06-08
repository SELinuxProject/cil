/* 
 * Copyright (C) 2011 Tresys Technology, LLC
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

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
void cil_tree_subtree_destroy(struct cil_tree_node *);
void cil_tree_node_destroy(struct cil_tree_node **);

//finished values
#define CIL_TREE_SKIP_NOTHING	0
#define CIL_TREE_SKIP_NEXT	1
#define CIL_TREE_SKIP_HEAD	2
#define CIL_TREE_SKIP_ALL	(CIL_TREE_SKIP_NOTHING | CIL_TREE_SKIP_NEXT | CIL_TREE_SKIP_HEAD)
int cil_tree_walk(struct cil_tree_node *, int (*process)(struct cil_tree_node *, uint32_t *, struct cil_list *), int (*reverse_node)(struct cil_tree_node *, struct cil_list *), int (*finished_branch)(struct cil_tree_node *, struct cil_list *), struct cil_list *);
void cil_tree_print_node(struct cil_tree_node *);
void cil_tree_print(struct cil_tree_node *, uint32_t);
void cil_tree_print_perms_list(struct cil_tree_node *);
#endif /* CIL_TREE_H_ */

