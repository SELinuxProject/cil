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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sepol/errcodes.h>
#include "cil_tree.h" 
#include "cil_lexer.h"
#include "cil.h"
#include "cil_mem.h"

int cil_parser(char *buffer, uint32_t size, struct cil_tree **parse_tree)
{
	cil_lexer_setup(buffer, size);

	int paren_count = 0;

	struct cil_tree *tree;
	struct cil_tree_node *node, *item, *current;

	struct token tok;

	if (*parse_tree == NULL) {
		cil_tree_init(&tree);
		tree->root->flavor = CIL_ROOT;
	}
	else {
		tree = *parse_tree;
	}
	current = tree->root;	

	do {
		cil_lexer_next(&tok);
		if (tok.type == OPAREN) {
			paren_count++;
			cil_tree_node_init(&node);
			node->parent = current;
			node->flavor = CIL_PARSE_NODE;
			node->line = tok.line;
			if (current->cl_head == NULL)
				current->cl_head = node;
			else
				current->cl_tail->next = node;
			current->cl_tail = node;
			current = node;
		}
		else if (tok.type == CPAREN) {
			paren_count--;
			if (paren_count < 0) {
				printf("Syntax error: Close parenthesis without matching open: line %d\n", tok.line);
				return SEPOL_ERR;
			}
			current = current->parent;
		}
		else if ((tok.type == SYMBOL) || (tok.type == QSTRING)) {
			cil_tree_node_init(&item);
			item->parent = current;
			item->data = cil_strdup(tok.value);
			item->flavor = CIL_PARSE_NODE;
			item->line = tok.line;
			if (current->cl_head == NULL)
				current->cl_head = item;
			else
				current->cl_tail->next = item;
			current->cl_tail = item;
		}
		else if ((tok.type == 0) && (paren_count > 0)) {
			printf("Syntax error: Open parenthesis without matching close\n");
			return SEPOL_ERR;
		}	
			
	}
	while (tok.type != 0);

	*parse_tree = tree;

	return SEPOL_OK;
}
