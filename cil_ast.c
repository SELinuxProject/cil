#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "cil_ast.h"
#include "cil_tree.h"
#include "cil_parser.h"
#include "cil.h"


struct cil_block * gen_block(struct cil_tree_node *node, uint16_t is_abstract, uint16_t is_optional, char *condition)
{
	struct cil_block *block;
	block = (struct cil_block*)malloc(sizeof(struct cil_block));
	//block->name --  insert name into table, and add sepol_id_t here
	block->is_abstract = is_abstract;
	block->is_optional = is_optional;
	block->condition = condition;
	block->self = node;

	return(block);	
}

struct cil_avrule * gen_avrule(struct cil_tree_node *parse_current, uint32_t rule_kind)
{
	struct cil_avrule *rule;
	rule = (struct cil_avrule*)malloc(sizeof(struct cil_avrule));
	rule->rule_kind = rule_kind;
	//rule->src -- confirm source domain exists and add sepol_id_t here
	//rule->tgt -- confirm target domain exists and add sepol_id_t here
	//rule->obj -- confirm objects exist and add sepol_id_t here
	//rule->perms -- lookup perms and OR together here


	if (parse_current->next->next->next->cl_head != NULL) //List of objects -- TODO: we're not going to support this
	{
		struct cil_tree_node *x;
		x = parse_current->next->next->next->cl_head;
		printf("obj: ");
		do
		{
			printf(" %s", (char*)x->data);
			x = x->next;
		} while (x != NULL);
		printf("\n");
	}
	else
		printf("obj: %s\n", (char*)parse_current->next->next->next->data);
							
	if (parse_current->next->next->next->next->cl_head != NULL) //List of permissions
	{
		struct cil_tree_node *x;
		x = parse_current->next->next->next->next->cl_head;
		printf("perms: ");
		do
		{
			printf(" %s", (char*)x->data);
			x = x->next;
		} while (x != NULL);
		printf("\n");
	}
	else
		printf("perms: %s\n", (char*)parse_current->next->next->next->next->data);

	return(rule);	
}

void cil_build_ast(struct cil_tree_node *parse_tree, struct cil_tree_node *ast)
{
	struct cil_tree_node *parse_current;
	parse_current = parse_tree;

	struct cil_tree_node *ast_current;
	ast_current = ast;

	struct cil_tree_node *node;

	if ((parse_current == NULL) || (ast_current == NULL))
	{
		printf("Error: NULL tree as parameter\n");
		exit(1);
	}

//	printf("before parse_current->cl_head check\n");
	if (parse_current->cl_head == NULL)	//This is a leaf node
	{
//		printf("parse_current cl_head is NULL\n");
		if (parse_current->parent->cl_head == parse_current) //This is the beginning of the line
		{
//			printf("cl_head = parse_current\n");
			//Node values set here
			node = (struct cil_tree_node*)malloc(sizeof(struct cil_tree_node));
			node->parent = ast_current;
			node->line = parse_current->line;

			if (ast_current->cl_head == NULL)
				ast_current->cl_head = node;
			else
				ast_current->cl_tail->next = node;
			ast_current->cl_tail = node;
			ast_current = node;
				
			// Determine data types and set those values here
			printf("parse_current->data: %s\n", (char*)parse_current->data);
			if (!strcmp(parse_current->data, CIL_KEY_BLOCK))
			{
				printf("new block: %s\n", (char*)parse_current->next->data); //This should be setting sepol_id_t	
				node->data = gen_block(node, 0, 0, NULL);
				node->flavor = CIL_BLOCK;
			}
			else if (!strcmp(parse_current->data, CIL_KEY_TYPE))
			{
				//Set values of type here
				printf("new type: %s\n", (char*)parse_current->next->data);
			}
			else if (!strcmp(parse_current->data, CIL_KEY_ALLOW))
			{
				printf("new allow: src:%s, tgt:%s\n", (char*)parse_current->next->data, (char*)parse_current->next->next->data);
				node->data = gen_avrule(parse_current, CIL_AVRULE_ALLOWED); 
				node->flavor = CIL_AVRULE;
				return;	//So that the object and perms lists don't get parsed again as potential keywords
			}
			else if (!strcmp(parse_current->data, CIL_KEY_INTERFACE))
			{
				printf("new interface: %s\n", (char*)parse_current->next->data);
			}
			
		}
		else //Rest of line 
		{
//			printf("Rest of line\n");
			//Not sure if this case is necessary (should be handled above when keyword is detected)			
		}
	}
	else
	{
//		printf("recurse with cl_head\n");
		cil_build_ast(parse_current->cl_head, ast_current);
	}
	if (parse_current->next != NULL)
	{
		//Process next in list
//		printf("recurse with next\n");
		cil_build_ast(parse_current->next, ast_current);
	}
	else
	{
		//Return to parent -- just return
//		printf("set ast_current to parent\n");
		ast_current = ast_current->parent;
		return;
	}
}

