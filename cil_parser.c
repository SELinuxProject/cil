#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "cil_tree.h" 
#include "cil_lexer.h"

struct cil_tree * cil_parser(char * buffer, uint32_t size)
{
	cil_lexer_setup(buffer, size);

	int paren_count = 0;

	struct cil_tree * tree;
	struct cil_tree_node * node, * item;
	struct cil_tree_node * current;

	struct token *tok;

	tree = (struct cil_tree*)malloc(sizeof(struct cil_tree));

	tree->root = (struct cil_tree_node*)malloc(sizeof(struct cil_tree_node));	
	tree->root->cl_head = NULL;
	tree->root->cl_tail = NULL;
	tree->root->parent = NULL;
	tree->root->data = "ROOT";
	tree->root->next = NULL;
	current = tree->root;	

	do
	{
		tok = cil_lexer_next();
		if (tok->type == OPAREN)
		{
			paren_count++;
			node = (struct cil_tree_node*)malloc(sizeof(struct cil_tree_node));
			node->parent = current;
			node->cl_head = NULL;
			node->cl_tail = NULL;
			node->next = NULL;
			node->line = tok->line;
			if (current->cl_head == NULL)
				current->cl_head = node;
			else
				current->cl_tail->next = node;
			current->cl_tail = node;
			current = node;
		}
		else if (tok->type == CPAREN)
		{
			paren_count--;
			if (paren_count < 0)
			{
				printf("Syntax error: Close parenthesis without matching open: line %d\n", tok->line);
				exit(1);
			}	
			current = current->parent;
		}
		else if ((tok->type == SYMBOL) || (tok->type == QSTRING))
		{
			item = (struct cil_tree_node*)malloc(sizeof(struct cil_tree_node));
			item->parent = current;
			item->cl_head = NULL;
			item->cl_tail = NULL;
			item->data = strdup(tok->value);
			item->line = tok->line;
			if (current->cl_head == NULL)
				current->cl_head = item;
			else
				current->cl_tail->next = item;
			current->cl_tail = item;
		}
		else if ((tok->type == 0) && (paren_count > 0))
		{
			printf("Syntax error: Open parenthesis without matching close\n");
			exit(1);
		}	
			
	}
	while (tok->type != 0);

	return tree;
}
