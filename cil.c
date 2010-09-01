#include <stdlib.h>
#include <stdio.h>

#include <sepol/policydb/policydb.h>
//#include <sepol/policydb/symtab.h>

#include "cil_symtab.h"
#include "cil_tree.h"
#include "cil.h"

int cil_db_init(struct cil_db **db)
{
	int rc;	

	struct cil_db *new_db;
	new_db = malloc(sizeof(struct cil_db));

	rc = cil_symtab_array_init(new_db->global_symtab, CIL_SYM_GLOBAL_NUM);
	if (rc) {
		free(new_db);
		return rc;
	}

	rc = cil_symtab_array_init(new_db->local_symtab, CIL_SYM_LOCAL_NUM);
	if (rc) {
		free(new_db);
		return rc;
	}

	cil_tree_init(&new_db->ast_root);
	
	*db = new_db;

	return SEPOL_OK;
}

/* TODO CDS add cil_db_destroy() */
int cil_list_init(struct cil_list **list)
{
	struct cil_list *new_list = malloc(sizeof(struct cil_list));
	new_list->list = NULL;

	*list = new_list;
	
	return SEPOL_OK;
}


int cil_list_item_init(struct cil_list_item **item)
{
	struct cil_list_item *new_item = malloc(sizeof(struct cil_list_item));
	new_item->next = NULL;
	new_item->flavor = 0;
	new_item->data = NULL;

	*item = new_item;

	return SEPOL_OK;
}

int cil_parse_to_list(struct cil_tree_node *parse_cl_head, struct cil_list **ast_cl, uint32_t flavor)
{
	struct cil_list_item *new_item;
	struct cil_tree_node *parse_current = parse_cl_head;
	struct cil_list_item *list_tail;
	struct cil_list *ast_list = *ast_cl;
	
	if (ast_list == NULL) {
		if (cil_list_init(&ast_list)) {
			printf("Failed to init list\n");
			return SEPOL_ERR;
		}
	}
	while(parse_current != NULL) {
		cil_list_item_init(&new_item);
		new_item->flavor = flavor;
		new_item->data = parse_current->data;
		if (ast_list->list == NULL) {
			ast_list->list = new_item;
			list_tail = ast_list->list;
		}
		else {
			list_tail->next = new_item;
			list_tail = list_tail->next;
		}
		parse_current = parse_current->next;
	}

	*ast_cl = ast_list;

	return SEPOL_OK;
} 

int cil_stack_init(struct cil_stack **stack)
{
	/* TODO CDS Big change - when you malloc, you need to check what you got back. malloc can fail */
	struct cil_stack *new_stack = malloc(sizeof(struct cil_stack));
	new_stack->top = NULL;
	
	*stack = new_stack;

	return SEPOL_OK;
}

int cil_stack_push(struct cil_stack *stack, void *data)
{
	struct cil_stack_element *new_top;
	new_top = malloc(sizeof(struct cil_stack_element));
	new_top->data = data;
	new_top->next = stack->top;
	stack->top = new_top;

	return SEPOL_OK;
}

int cil_stack_pop(struct cil_stack *stack, void *popped)
{
	if (stack->top != NULL) {
		struct cil_stack_element *new_top;
		popped = stack->top->data;
		new_top = stack->top->next;
		free(stack->top);
		stack->top = new_top;
		return SEPOL_OK;
	}
	 return SEPOL_ERR;
}

static int __namespace_helper(struct cil_stack_element *current, char *namespace)
{
	/* TODO add error handling */
	if (current->next != NULL) {
		__namespace_helper(current->next, namespace);
		strcat(namespace, ".");
	}
	strcat(namespace, current->data);
	
	return SEPOL_OK;
}

int cil_get_namespace_str(struct cil_stack *stack, char **namespace)
{
	char *new_namespace;
	struct cil_stack_element *current = stack->top;
	/* TODO add error handling */
	if (current == NULL) {
		new_namespace = NULL;
		return SEPOL_OK;
	}	
	uint32_t length = strlen(current->data) + 2;
	while (current->next != NULL) {
		current = current->next;
		length += strlen(current->data) + 1;
	}
	new_namespace = malloc(length);
	new_namespace[0] = '\0';
	__namespace_helper(stack->top, new_namespace);
	*namespace = new_namespace;
	return SEPOL_OK;
}

int cil_symtab_array_init(symtab_t symtab[], uint32_t symtab_num)
{
	uint32_t i = 0, rc = 0;
	for (i=0; i<symtab_num; i++) {
		rc = symtab_init(&symtab[i], CIL_SYM_SIZE);
		if (rc) {
			printf("Symtab init failed\n");
			return SEPOL_ERR;
		}
	}

	return SEPOL_OK;
}

int cil_get_parent_symtab(struct cil_db *db, struct cil_tree_node *ast_node, symtab_t **symtab, uint32_t cil_sym_index)
{
	if (ast_node->parent->flavor == CIL_BLOCK)
		*symtab = &((struct cil_block*)ast_node->parent->data)->symtab[cil_sym_index];
	else if (ast_node->parent->flavor == CIL_ROOT)
		*symtab = &db->local_symtab[cil_sym_index];
	else {
		printf("Failed to get symtab from parent node\n");
		return SEPOL_ERR;
	}
	return SEPOL_OK;
}

int cil_gen_block(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node, uint16_t is_abstract, uint16_t is_optional, char *condition)
{
	int rc;
	char *name;
	struct cil_block *block = malloc(sizeof(struct cil_block));
	symtab_t *symtab = NULL;

	cil_symtab_array_init(block->symtab, CIL_SYM_LOCAL_NUM);

	block->is_abstract = is_abstract;
	block->is_optional = is_optional;
	block->condition = condition;
	block->self = ast_node;

	name = (char *)parse_current->next->data;

	rc = cil_get_parent_symtab(db, ast_node, &symtab, CIL_SYM_LOCAL_BLOCKS);
	if (rc) {
		free(block);
		return rc;
	}	
	
	/* TODO CDS look at hashtab_insert to see who owns the key (name in this case), to see if they need to be freed */
	rc = cil_symtab_insert(symtab, (hashtab_key_t)name, (symtab_datum_t*)block);
	if (rc) {
		printf("Failed to insert block %s\n into symtab", name);
		return rc;
	}

	ast_node->data = block;
	ast_node->flavor = CIL_BLOCK;

	return SEPOL_OK;	
}

int cil_insert_perm(struct cil_db *db, char *name, uint32_t *value)
{
	int rc;
	struct cil_perm *perm = malloc(sizeof(struct cil_perm));
	symtab_datum_t *datum;

	rc = cil_symtab_insert(&db->global_symtab[CIL_SYM_GLOBAL_PERMS], (hashtab_key_t)name, (symtab_datum_t*)perm);
	if (rc) {
		if (rc == SEPOL_EEXIST) {
			datum = (symtab_datum_t*)hashtab_search(db->global_symtab[CIL_SYM_GLOBAL_PERMS].table, (hashtab_key_t)name);
			if (datum != NULL)
				*value = datum->value;
			else
				return SEPOL_ERR;
		}
		else
			printf("Failed to insert perm into symtab\n");
		return rc;
	}
	else
		*value = perm->datum.value;

	return SEPOL_OK;
}

int cil_gen_class(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	int rc;
	char *key = parse_current->next->data;
	struct cil_list_item *item = NULL;

	struct cil_class *cls = malloc(sizeof(struct cil_class));
	
	rc = cil_parse_to_list(parse_current->next->next->cl_head, &cls->av, CIL_PERM);
	if (rc) {
		printf("Failed to parse permissions list from parse tree\n");
		return rc;
 	}

	item = cls->av->list;
	while(item != NULL) {
		rc = cil_insert_perm(db, (char*)item->data, &item->data);
		if (rc == SEPOL_EEXIST || rc == SEPOL_OK) 
			item->flavor = CIL_SEPOL_ID;
		else {
			printf("Failed to insert perm list\n");
			return rc;
		}
		item = item->next;
	}

	//Syntax for inherit from common?

	rc = cil_symtab_insert(&db->global_symtab[CIL_SYM_GLOBAL_CLASSES], (hashtab_key_t)key, (symtab_datum_t*)cls);	
	if (rc) {
		printf("Failed to insert class into symtab\n");
		return rc;
	}

	ast_node->data = cls;
	ast_node->flavor = CIL_CLASS;

	return SEPOL_OK;
}

int cil_gen_common(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	int rc;
	char *key = parse_current->next->data;
	struct cil_common *common = malloc(sizeof(struct cil_common));

	rc = cil_parse_to_list(parse_current->next->next->cl_head, &common->av, CIL_PERM);
	if (rc) {
		printf("Failed to parse permissions list from parse tree\n");
		return rc;
	}

	rc = cil_symtab_insert(&db->global_symtab[CIL_SYM_GLOBAL_COMMONS], (hashtab_key_t)key, (symtab_datum_t*)common);
	if (rc) {
		printf("Failed to insert common into symtab\n");
		return rc;
	}

	ast_node->data = common;
	ast_node->flavor = CIL_COMMON;
	
	return SEPOL_OK;
}

int cil_gen_sid(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	int rc;
	struct cil_sid * sid = malloc(sizeof(struct cil_sid));	
	char *key = parse_current->next->data;

	rc = cil_symtab_insert(&db->global_symtab[CIL_SYM_GLOBAL_SIDS], (hashtab_key_t)key, (symtab_datum_t*)sid);
	if (rc) {
		printf("Failed to insert sid into symtab\n");
		return rc;	
	}

	ast_node->data = sid;
	ast_node->flavor = CIL_SID;

	return SEPOL_OK;
}

int cil_gen_user(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	int rc;
	struct cil_user *user = malloc(sizeof(struct cil_user));
	char *key = parse_current->next->data;

	rc = cil_symtab_insert(&db->global_symtab[CIL_SYM_GLOBAL_USERS], (hashtab_key_t)key, (symtab_datum_t*)user);
	if (rc) {
		printf("Failed to insert user into symtab\n");
		return rc;
	}

	ast_node->data = user;
	ast_node->flavor = CIL_USER;

	return SEPOL_OK;
}

int cil_gen_role(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	int rc;
	struct cil_role *role = malloc(sizeof(struct cil_role));
	char *key = parse_current->next->data;

	rc = cil_symtab_insert(&db->global_symtab[CIL_SYM_GLOBAL_ROLES], (hashtab_key_t)key, (symtab_datum_t*)role);
	if (rc) {
		printf("Failed to insert role into symtab\n");
		return rc;
	}

	ast_node->data = role;
	ast_node->flavor = CIL_ROLE;

	return SEPOL_OK;
}

int cil_gen_avrule(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node, uint32_t rule_kind)
{
	//TODO: Check if this is actually an avrule, abort if not
	
	struct cil_avrule *rule;
	rule = malloc(sizeof(struct cil_avrule));
	rule->rule_kind = rule_kind;
	rule->src_str = parse_current->next->data;
	rule->tgt_str = parse_current->next->next->data;
	rule->obj_str = parse_current->next->next->next->data;	

	if(cil_list_init(&rule->perms)) {
		printf("failed to init perm list\n");
		return SEPOL_ERR;
	}
	

	if (parse_current->next->next->next->next->cl_head != NULL)
		cil_parse_to_list(parse_current->next->next->next->next->cl_head, &rule->perms, CIL_PERM);
	else if ((parse_current->next->next->next->next->data != NULL) && (parse_current->next->next->next->next->next == NULL)) {
		rule->perms->list->flavor = CIL_AST_STR;
		rule->perms->list->data = (char*)parse_current->next->next->next->next->data;		
		
	}

	ast_node->data = rule;
	ast_node->flavor = CIL_AVRULE;

	return SEPOL_OK;	
}

int cil_gen_type(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node, uint32_t flavor)
{
	int rc;
	char *key = (char*)parse_current->next->data; 
	struct cil_type *type = malloc(sizeof(struct cil_type));
	symtab_t *symtab = NULL;

	/* TODO CDS see if you need to free this or if hashtab_insert takes ownership of key */

	if (flavor == CIL_TYPE) {
		rc = cil_get_parent_symtab(db, ast_node, &symtab, CIL_SYM_LOCAL_TYPES);
		rc = cil_symtab_insert(symtab, (hashtab_key_t)key, (symtab_datum_t*)type);
	}
	else if (flavor == CIL_TYPE_ATTR) {
		rc = cil_get_parent_symtab(db, ast_node, &symtab, CIL_SYM_LOCAL_ATTRS);
		rc = cil_symtab_insert(symtab, (hashtab_key_t)key, (symtab_datum_t*)type);	
	}
	else {
		printf("Error: cil_gen_type called on invalid node\n");
		return SEPOL_ERR;
	}

	if (rc) {
		printf("Failed to insert %s, rc:%d\n", key,rc);
		return rc;
	}

	ast_node->data = type;
	ast_node->flavor = flavor;	

	return SEPOL_OK;
}

int cil_gen_bool(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	int rc;
	struct cil_bool *boolean;
	char *key = parse_current->next->data;
	boolean = malloc(sizeof(struct cil_bool));

	if (!strcmp(parse_current->next->next->data, "true"))
		boolean->value = 1;
	else if (!strcmp(parse_current->next->next->data, "false"))
		boolean->value = 0;
	else {
		printf("Error: boolean value must be \'true\' or \'false\'");
		return SEPOL_ERR;
	}

	rc = cil_symtab_insert(&db->global_symtab[CIL_SYM_GLOBAL_BOOLS], (hashtab_key_t)key, (symtab_datum_t*)boolean);
	if (rc) {
		printf("Failed to insert bool into symtab\n");
		return rc;	
	}

	ast_node->data = boolean;
	ast_node->flavor = CIL_BOOL;

	return SEPOL_OK;
}

int cil_gen_typealias(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	int rc;
	struct cil_typealias *alias = malloc(sizeof(struct cil_typealias));
	char *key = parse_current->next->next->data;
	symtab_t *symtab;

	rc = cil_get_parent_symtab(db, ast_node, &symtab, CIL_SYM_LOCAL_ALIASES);
	if (rc) {
		free(alias);
		return rc;
	}
	
	alias->type_str = strdup(parse_current->next->data);

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, (symtab_datum_t*)alias);
	if (rc) {
		printf("Failed to insert alias into symtab\n");
		return rc;
	}

	ast_node->data = alias;
	ast_node->flavor = CIL_TYPEALIAS;

	return SEPOL_OK;
}
