#include <stdlib.h>
#include <stdio.h>

#include <sepol/policydb/policydb.h>
#include <sepol/policydb/symtab.h>

#include "cil_tree.h"
#include "cil.h"

struct cil_db * cil_db_init()
{
	int i, rc;	

	uint32_t symtab_size;
	symtab_size = 256;	//Need to determine what sizes are needed for each

	struct cil_db *db;
	db = (struct cil_db*)malloc(sizeof(struct cil_db));

	for (i = 0; i < CIL_SYM_NUM; i++)
	{
		rc = symtab_init(&db->symtab[i], symtab_size);
		if (rc)
		{
			printf("Symtab init failed\n");
			exit(1);
		}
	}
	
	db->ast_root = (struct cil_tree *)malloc(sizeof(struct cil_tree));

	return db;
}

char * cil_resolve_name(struct cil_tree_node *parse_parent, char* name)
{
	return name;
	strcat(parse_parent->next->data, name);
	if (parse_parent->parent != NULL)
		cil_resolve_name(parse_parent->parent, name);

	return name; 
}

struct cil_block * cil_gen_block(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *node, uint16_t is_abstract, uint16_t is_optional, char *condition)
{
	int rc;
	char *name, *key;
	struct cil_block *block;
	block = (struct cil_block*)malloc(sizeof(struct cil_block));

	name = (char *)parse_current->next->data;
		
	key = (hashtab_key_t)cil_resolve_name(parse_current->parent, name);
	printf("key: %s\n", (char*)key);
	
	rc = hashtab_insert(db->symtab[CIL_SYM_BLOCKS].table, (hashtab_key_t)parse_current->next->data, block);
	if (rc)
	{
		printf("Failed to insert block %s\n", (char*)parse_current->next->data);
		exit(1);
	}

	block->is_abstract = is_abstract;
	block->is_optional = is_optional;
	block->condition = condition;
	block->self = node;

	return block;	
}

struct cil_class * cil_gen_class(struct cil_db *db, struct cil_tree_node *parse_current)
{
	struct cil_class *cls;
	cls = (struct cil_class*)malloc(sizeof(struct cil_class));
	
	//Add class to symtab and add sepol_id_t
	//List of av rules here
	//Common to inherit from

	return cls;
}

struct cil_perm * cil_gen_perm(struct cil_db *db, struct cil_tree_node *parse_current)
{
	struct cil_perm *perm;
	perm = (struct cil_perm*)malloc(sizeof(struct cil_perm));

	//sepol_id_t?

	return perm;
}

struct cil_common * cil_gen_common(struct cil_db *db, struct cil_tree_node *parse_current)
{
	struct cil_common *common;
	common = (struct cil_common*)malloc(sizeof(struct cil_common));

	//sepol_id_t
	//list of av
	
	return common;
}

struct cil_sid * cil_gen_sid(struct cil_db *db, struct cil_tree_node *parse_current)
{
	struct cil_sid * sid;
	sid = (struct cil_sid*)malloc(sizeof(struct cil_sid));	

	//sepol_id_t

	return sid;
}

struct cil_user * cil_gen_user(struct cil_db *db, struct cil_tree_node *parse_current)
{
	struct cil_user *user;
	user = (struct cil_user*)malloc(sizeof(struct cil_user));

	printf("new user: %s", (char*)parse_current->next->data);
	//Add to user symtab and set user->user sepol_id_t of new entry

	return user;
}

struct cil_role * cil_gen_role(struct cil_db *db, struct cil_tree_node *parse_current)
{
	struct cil_role *role;
	role = (struct cil_role*)malloc(sizeof(struct cil_role));

	printf("new role: %s\n", (char*)parse_current->next->data);
	//Add to role symtab and set role->role to sepol_id_t of new entry

	return role;
}

struct cil_avrule * cil_gen_avrule(struct cil_db *db, struct cil_tree_node *parse_current, uint32_t rule_kind)
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

	return rule;	
}

struct cil_type * cil_gen_type(struct cil_db *db, struct cil_tree_node *parse_current, uint32_t flavor)
{
	struct cil_type *type;
	type = (struct cil_type*)malloc(sizeof(struct cil_type));
	
	if (flavor == CIL_TYPE)
	{
		printf("new type: %s\n", (char*)parse_current->next->data);
		//Add to type symtab and set type->type to sepol_id_t of new entry
	}
	else if (flavor == CIL_TYPE_ATTR)
	{
		printf("new attr: %s\n", (char*)parse_current->next->data);
		//ADD to attr symtab and set type->type to sepol_id_t of new entry
	}
	else
	{
		printf("Error: cil_gen_type called on invalid node\n");
		exit(1);
	}

	return type;
}


struct cil_bool * cil_gen_bool(struct cil_db *db, struct cil_tree_node *parse_current)
{
	struct cil_bool *boolean;
	boolean = (struct cil_bool*)malloc(sizeof(struct cil_bool));
	printf("new bool: %s", (char*)parse_current->next->data);
	//Add to bool symtab and set boolean->bool to sepol_id_t of new entry
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

	return boolean;
}

struct cil_typealias * cil_gen_typealias(struct cil_db *db, struct cil_tree_node *parse_current)
{
	struct cil_typealias *alias;	
	alias = (struct cil_typealias*)malloc(sizeof(struct cil_typealias));
	printf("new alias: %s, type: %s\n", (char*)parse_current->next->data, (char*)parse_current->next->next->data);
	
	return(alias);
}
