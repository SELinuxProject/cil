#include <stdlib.h>
#include <stdio.h>
#include "cil_parser.h"
#include "cil_lexer.h"
#include <string.h>

//void cil_parser(char * buffer, int size)
struct element * cil_parser(char * buffer, int size)
{
	cil_lexer_setup(buffer, size);

	int paren_count = 0;

	struct element * tree;//root of tree (does not change)
	struct element * node, * item;
	struct element * current;

	struct token *tok;

	tree = (struct element*)malloc(sizeof(struct element));	
	tree->cl_head = NULL;
	tree->cl_tail = NULL;
	tree->parent = NULL;
	tree->data = "ROOT";
	tree->next = NULL;
	current = tree;	

	do
	{
		tok = cil_lexer_next();
		if (tok->type == OPAREN)
		{
			paren_count++;
			node = (struct element*)malloc(sizeof(struct element));
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
				printf("Syntax error: Close parenthesis without matching open");
				exit(1);
			}	
			current = current->parent;
		}
		else if ((tok->type == SYMBOL) || (tok->type == QSTRING))
		{
			item = (struct element*)malloc(sizeof(struct element));
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
	}
	while (tok->type != 0);

	return (tree);
}

void cil_print_tree(struct element *tree, int depth)
{
	struct element * current;
	current = tree;
	int x = 0;
	int tmp = depth;
	
	if (current != NULL)
	{
		if (current->cl_head == NULL)
		{
			if (current->parent->cl_head == current)
				printf("%s", current->data);
			else
				printf(" %s", current->data);
		}		
		else
		{
			if (current->parent != NULL)
			{
				printf("\n");
				for (x = 0; x<depth; x++)
					printf("\t");
				printf("(");
			}
			cil_print_tree(current->cl_head, depth + 1);
		}
		if (current->next == NULL)
		{
			if ((current->parent != NULL) && (current->parent->cl_tail == current) && (current->parent->parent != NULL))
				printf(")");
			if ((current->parent != NULL) && (current->parent->parent == NULL))
				printf("\n\n");
		}
		else
		{
			cil_print_tree(current->next, depth);
		}
	}
}

