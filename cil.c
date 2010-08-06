#include <stdlib.h>
#include <stdio.h>

#include "cil_tree.h"
#include "cil.h"

struct cil_block * gen_block(struct cil_tree_node *parse_current, struct cil_tree_node *node, uint16_t is_abstract, uint16_t is_optional, char *condition)
{
	//TODO: Check if this is actually a block, abort if not	

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
	//TODO: Check if this is actually an avrule, abort if not
	
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

struct cil_type * gen_type(struct cil_tree_node *parse_current, uint32_t flavor)
{
	struct cil_type *type;
	type = (struct cil_type*)malloc(sizeof(struct cil_type));
	
	if (flavor == CIL_TYPE)
	{
		printf("new type: %s\n", (char*)parse_current->next->data);
		//Add to type symtab and set type->type to point to new entry
	}
	else if (flavor == CIL_TYPE_ATTR)
	{
		printf("new attr: %s\n", (char*)parse_current->next->data);
		//ADD to attr symtab and set type->type to point to entry
	}
	else
	{
		printf("Error: gen_type called on invalid node\n");
		exit(1);
	}
	return(type);
}

struct cil_role * gen_role(struct cil_tree_node *parse_current)
{
	struct cil_role *role;
	role = (struct cil_role*)malloc(sizeof(struct cil_role));

	printf("new role: %s\n", (char*)parse_current->next->data);
	//Add to role symtab and set role->role to point to new entry
	return(role);
}

struct cil_bool * gen_bool(struct cil_tree_node *parse_current)
{
	struct cil_bool *boolean;
	boolean = (struct cil_bool*)malloc(sizeof(struct cil_bool));
	printf("new bool: %s", (char*)parse_current->next->data);
	//Add to bool symtab and set boolean->bool to point to new entry
	if (!strcmp(parse_current->next->next->data, "true"))
		boolean->value = 1;
	else if (!strcmp(parse_current->next->next->data, "false"))
		boolean->value = 0;
	else
	{
		printf("Error: boolean value must be \'true\' or \'false\'");
		exit(1);
	}
	printf(", value= %d\n", boolean->value);
	return(boolean);
}

struct cil_typealias * gen_typealias(struct cil_tree_node *parse_current)
{
	struct cil_typealias *alias;	
	alias = (struct cil_typealias*)malloc(sizeof(struct cil_typealias));
	printf("new alias: %s, type: %s\n", (char*)parse_current->next->data, (char*)parse_current->next->next->data);
	
	return(alias);
}
