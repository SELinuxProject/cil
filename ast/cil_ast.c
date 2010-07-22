#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "cil_ast.h"
#include "cil.h"


void cil_build_ast(struct element *parse_tree, struct cil_tree_node *ast)
{
	struct element *parse_current;
	parse_current = parse_tree;

	struct cil_tree_node *ast_current;
	ast_current = ast;

	struct cil_tree_node *node;

	if ((parse_tree == NULL) || (ast == NULL))
	{
		printf("Error: NULL tree as parameter\n");
		exit(1);
	}

	if (parse_current->cl_head == NULL)
	{
		node = (struct cil_tree_node*)malloc(sizeof(struct cil_tree_node));

		if (!strcmp(parse_current->data, CIL_KEY_BLOCK))
		{
			struct cil_block *block;
			block = (struct cil_block*)malloc(sizeof(struct cil_block));
			node->data = block;
		}
	}
	else
	{
		cil_build_ast(parse_current->cl_head, ast_current);
	}
	if (parse_current->next != NULL)
	{
		cil_build_ast(parse_current->next, ast_current);
	}
}

