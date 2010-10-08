#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sepol/errcodes.h>
#include "cil_tree.h" 
#include "cil_lexer.h"
#include "cil.h"

int cil_parser(char *buffer, uint32_t size, struct cil_tree **parse_root)
{
	cil_lexer_setup(buffer, size);

	int paren_count = 0;

	struct cil_tree *tree;
	struct cil_tree_node *node, *item, *current;

	struct token *tok;

	cil_tree_init(&tree);
	tree->root->flavor = CIL_ROOT;
	current = tree->root;	

	do {
		cil_lexer_next(&tok);
		if (tok->type == OPAREN) {
			paren_count++;
			cil_tree_node_init(&node);
			node->parent = current;
			node->flavor = CIL_PARSER;
			node->line = tok->line;
			if (current->cl_head == NULL)
				current->cl_head = node;
			else
				current->cl_tail->next = node;
			current->cl_tail = node;
			current = node;
		}
		else if (tok->type == CPAREN) {
			paren_count--;
			if (paren_count < 0) {
				printf("Syntax error: Close parenthesis without matching open: line %d\n", tok->line);
				return SEPOL_ERR;
			}
			current = current->parent;
		}
		else if ((tok->type == SYMBOL) || (tok->type == QSTRING)) {
			cil_tree_node_init(&item);
			item->parent = current;
			item->data = strdup(tok->value);
			item->flavor = CIL_PARSER;
			item->line = tok->line;
			if (current->cl_head == NULL)
				current->cl_head = item;
			else
				current->cl_tail->next = item;
			current->cl_tail = item;
		}
		else if ((tok->type == 0) && (paren_count > 0)) {
			printf("Syntax error: Open parenthesis without matching close\n");
			return SEPOL_ERR;
		}	
			
	}
	while (tok->type != 0);

	*parse_root = tree;

	return SEPOL_OK;
}
