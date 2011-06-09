/*
 * Copyright 2011 Tresys Technology, LLC. All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 *    1. Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 * 
 *    2. Redistributions in binary form must reproduce the above copyright notice,
 *       this list of conditions and the following disclaimer in the documentation
 *       and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY TRESYS TECHNOLOGY, LLC ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
 * EVENT SHALL TRESYS TECHNOLOGY, LLC OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 * The views and conclusions contained in the software and documentation are those
 * of the authors and should not be interpreted as representing official policies,
 * either expressed or implied, of Tresys Technology, LLC.
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

