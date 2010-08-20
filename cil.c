#include <stdlib.h>
#include <stdio.h>

#include <sepol/policydb/policydb.h>
#include <sepol/policydb/symtab.h>

#include "cil_tree.h"
#include "cil.h"

/* TODO CDS Big change - need to change all functions in all files to return an int error code, e.g.:
int cil_db_init(struct cil_db **db) 
Use error codes provided by libsepol
*/
struct cil_db *cil_db_init()
{
	int i, rc;	

	uint32_t symtab_size = 256;	//Need to determine what sizes are needed for each

	struct cil_db *db;

	db = malloc(sizeof(struct cil_db));

	for (i = 0; i < CIL_SYM_NUM; i++) {
		rc = symtab_init(&db->symtab[i], symtab_size);
		if (rc) {
			printf("Symtab init failed\n");
			/* TODO CDS Do not ever abort or exit from within library code - return an error value of some sort */
			exit(1);
		}
	}
	
	db->ast_root = cil_tree_init(db->ast_root);

	return db;
}

/* TODO CDS add cil_db_destroy() */
struct cil_list *cil_list_init()
{
	struct cil_list *list = malloc(sizeof(struct cil_list));
	list->list = NULL;
	return list;
}


struct cil_list_item *cil_list_item_init()
{
	struct cil_list_item *item = malloc(sizeof(struct cil_list_item));
	item->next = NULL;
	item->flavor = 0;
	item->data = NULL;

	return item;
}

struct cil_stack *cil_stack_init()
{
	/* TODO CDS Big change - when you malloc, you need to check what you got back. malloc can fail */
	struct cil_stack *stack = malloc(sizeof(struct cil_stack));
	stack->top = NULL;
	return stack;
}

void cil_stack_push(struct cil_stack *stack, void *data)
{
	struct cil_stack_element *new_top;
	new_top = malloc(sizeof(struct cil_stack_element));
	new_top->data = data;
	new_top->next = stack->top;
	stack->top = new_top;
}

void *cil_stack_pop(struct cil_stack *stack)
{
	if (stack->top != NULL) {
		struct cil_stack_element *new_top;
		void *data;
		data = stack->top->data;
		new_top = stack->top->next;
		free(stack->top);
		stack->top = new_top;
		return data;
	}
	return NULL;
}

static void __namespace_helper(struct cil_stack_element *current, char *namespace)
{
	/* TODO add error handling */
	if (current->next != NULL) {
		__namespace_helper(current->next, namespace);
		strcat(namespace, ".");
	}
	strcat(namespace, current->data);
}

char *cil_get_namespace_str(struct cil_stack *stack)
{
	char *namespace;
	struct cil_stack_element *current = stack->top;
	/* TODO add error handling */
	if (current == NULL)
		return NULL;
	uint32_t length = strlen(current->data) + 2;
	while (current->next != NULL) {
		current = current->next;
		length += strlen(current->data) + 1;
	}
	namespace = malloc(length);
	namespace[0] = '\0';
	__namespace_helper(stack->top, namespace);
	return namespace;
}

struct cil_block *cil_gen_block(struct cil_db *db, struct cil_stack *namespace, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node, uint16_t is_abstract, uint16_t is_optional, char *condition)
{
	int rc;
	char *name, *key;
	struct cil_block *block = malloc(sizeof(struct cil_block));

	block->is_abstract = is_abstract;
	block->is_optional = is_optional;
	block->condition = condition;
	block->self = ast_node;

	name = (char *)parse_current->next->data;

	cil_stack_push(namespace, name);

	key = cil_get_namespace_str(namespace);
	
	/* TODO CDS look at hashtab_insert to see who owns the key, to see if they need to be freed */
	rc = hashtab_insert(db->symtab[CIL_SYM_BLOCKS].table, (hashtab_key_t)key, block);
	if (rc) {
		printf("Failed to insert block %s\n", key);
		exit(1);
	}

	return block;	
}

struct cil_class *cil_gen_class(struct cil_db *db, char *namespace_str, struct cil_tree_node *parse_current)
{
	int rc;
	char *key = parse_current->next->data;
	struct cil_tree_node *parse_current_av;
	struct cil_list_item *new_av, *last_av;
	struct cil_class *cls = malloc(sizeof(struct cil_class));
	cls->av = cil_list_init();
	parse_current_av = parse_current->next->next->cl_head;

	while(parse_current_av != NULL) {
		printf("parse_current_av: %s\n", (char*)parse_current_av->data);
		if (hashtab_search(db->symtab[CIL_SYM_PERMS].table, (hashtab_key_t)parse_current_av->data)) {
			new_av = cil_list_item_init();
			new_av->flavor = CIL_PERM;
			if (cls->av->list == NULL) {
				cls->av->list = new_av;
				last_av = cls->av->list;
			}
			else {
				last_av->next = new_av;
				last_av = last_av->next;
			}
		}
		else {
			printf("Error: unknown permission: %s\n", (char*)parse_current_av->data);
			exit(1);
		}
		parse_current_av = parse_current_av->next;		
	}
	
	//Syntax for inherit from common?
	//Lookup common in symtab and store in cls->common

	rc = hashtab_insert(db->symtab[CIL_SYM_CLASSES].table, (hashtab_key_t)key, cls);	
	
	return cls;
}

struct cil_perm *cil_gen_perm(struct cil_db *db, char *namespace_str, struct cil_tree_node *parse_current)
{
	int rc;
	struct cil_perm *perm = malloc(sizeof(struct cil_perm));
	char *key = parse_current->next->data;

	rc = hashtab_insert(db->symtab[CIL_SYM_PERMS].table, (hashtab_key_t)key, perm);
	if (rc) {
		printf("Failed to insert perm into symtab\n");
		exit(1);
	}

	return perm;
}

struct cil_common *cil_gen_common(struct cil_db *db, char *namespace_str, struct cil_tree_node *parse_current)
{
	struct cil_common *common;
	common = malloc(sizeof(struct cil_common));

	//sepol_id_t
	//list of av
	
	return common;
}

struct cil_sid *cil_gen_sid(struct cil_db *db, char *namespace_str, struct cil_tree_node *parse_current)
{
	struct cil_sid * sid;
	sid = malloc(sizeof(struct cil_sid));	

	//sepol_id_t

	return sid;
}

struct cil_user *cil_gen_user(struct cil_db *db, char *namespace_str, struct cil_tree_node *parse_current)
{
	struct cil_user *user;
	user = malloc(sizeof(struct cil_user));

	printf("new user: %s", (char*)parse_current->next->data);
	//Add to user symtab and set user->user sepol_id_t of new entry

	return user;
}

struct cil_role *cil_gen_role(struct cil_db *db, char *namespace_str, struct cil_tree_node *parse_current)
{
	struct cil_role *role;
	role = malloc(sizeof(struct cil_role));

	printf("new role: %s\n", (char*)parse_current->next->data);
	//Add to role symtab and set role->role to sepol_id_t of new entry

	return role;
}

struct cil_avrule *cil_gen_avrule(struct cil_db *db, char *namespace_str, struct cil_tree_node *parse_current, uint32_t rule_kind)
{
	//TODO: Check if this is actually an avrule, abort if not
	
	struct cil_avrule *rule;
	rule = malloc(sizeof(struct cil_avrule));
	rule->rule_kind = rule_kind;
	//rule->src -- confirm source domain exists and add sepol_id_t here
	//rule->tgt -- confirm target domain exists and add sepol_id_t here
	//rule->obj -- confirm objects exist and add sepol_id_t here
	//rule->perms -- lookup perms and OR together here


	if (parse_current->next->next->next->cl_head != NULL) { //List of objects -- TODO: we're not going to support this
		struct cil_tree_node *x;
		x = parse_current->next->next->next->cl_head;
		printf("obj: ");
		do {
			printf(" %s", (char*)x->data);
			x = x->next;
		} while (x != NULL);
		printf("\n");
	}
	else
		printf("obj: %s\n", (char*)parse_current->next->next->next->data);
							
	if (parse_current->next->next->next->next->cl_head != NULL) { //List of permissions
		struct cil_tree_node *x;
		x = parse_current->next->next->next->next->cl_head;
		printf("perms: ");
		do {
			printf(" %s", (char*)x->data);
			x = x->next;
		} while (x != NULL);
		printf("\n");
	}
	else
		printf("perms: %s\n", (char*)parse_current->next->next->next->next->data);

	return rule;	
}

struct cil_type *cil_gen_type(struct cil_db *db, char *namespace_str, struct cil_tree_node *parse_current, uint32_t flavor)
{
	int rc;
	char *name, *key; 
	struct cil_type *type = malloc(sizeof(struct cil_type));

	name = (char*)parse_current->next->data;

	/* TODO CDS see if you need to free this or if hashtab_insert takes ownership of key */
	if (namespace_str != NULL) {
		key = malloc(strlen(namespace_str) + strlen(name) + 2);
		strcpy(key, namespace_str);
		strcat(key, ".");
		strcat(key, name);
	}
	else
		key = strdup(name);

	if (flavor == CIL_TYPE) {
		rc = hashtab_insert(db->symtab[CIL_SYM_TYPES].table, (hashtab_key_t)key, type);
	}
	else if (flavor == CIL_TYPE_ATTR) {
		rc = hashtab_insert(db->symtab[CIL_SYM_ATTRS].table, (hashtab_key_t)key, type);	
	}
	else {
		printf("Error: cil_gen_type called on invalid node\n");
		exit(1);
	}

	if (rc) {
		printf("Failed to insert %s, rc:%d\n", key,rc);
		exit(1);
	}
	return type;
}


struct cil_bool *cil_gen_bool(struct cil_db *db, char *namespace_str, struct cil_tree_node *parse_current)
{
	struct cil_bool *boolean;
	boolean = malloc(sizeof(struct cil_bool));
	printf("new bool: %s", (char*)parse_current->next->data);
	//Add to bool symtab and set boolean->bool to sepol_id_t of new entry
	if (!strcmp(parse_current->next->next->data, "true"))
		boolean->value = 1;
	else if (!strcmp(parse_current->next->next->data, "false"))
		boolean->value = 0;
	else {
		printf("Error: boolean value must be \'true\' or \'false\'");
		exit(1);
	}
	printf(", value= %d\n", boolean->value);

	return boolean;
}

struct cil_typealias *cil_gen_typealias(struct cil_db *db, char *namespace_str, struct cil_tree_node *parse_current)
{
	struct cil_typealias *alias;	
	alias = malloc(sizeof(struct cil_typealias));
	printf("new alias: %s, type: %s\n", (char*)parse_current->next->data, (char*)parse_current->next->next->data);
	
	return(alias);
}
