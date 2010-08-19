#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "cil_tree.h" 
#include "cil_lexer.h"
#include "cil.h"

struct cil_tree *cil_parser(char *buffer, uint32_t size)
{
	cil_lexer_setup(buffer, size);

	int paren_count = 0;

	struct cil_tree *tree;
	struct cil_tree_node *node, *item, *current;

	struct token *tok;

	tree = cil_tree_init(tree);
	tree->root->flavor = CIL_PARSER;
	current = tree->root;	

	do {
		tok = cil_lexer_next();
		if (tok->type == OPAREN) {
			paren_count++;
			/* TODO CDS switch to using an init()/destroy() for cil_tree_nodes to remove all this duplicate code */
			node = cil_tree_node_init(node);
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
				exit(1);
			}
			current = current->parent;
		}
		else if ((tok->type == SYMBOL) || (tok->type == QSTRING)) {
			item = cil_tree_node_init(item);
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
			exit(1);
		}	
			
	}
	while (tok->type != 0);

	return tree;
}
