#include <stdlib.h>
#include <stdio.h>

#include <sepol/policydb/policydb.h>
#include <sepol/policydb/symtab.h>

#include "cil_symtab.h"
#include "cil_tree.h"
#include "cil.h"

int cil_db_init(struct cil_db **db)
{
	int rc;	

	struct cil_db *new_db;
	new_db = malloc(sizeof(struct cil_db));

	rc = cil_symtab_array_init(new_db->global_symtab, CIL_SYM_GLOBAL_NUM);
	if (rc != SEPOL_OK) {
		free(new_db);
		return rc;
	}

	rc = cil_symtab_array_init(new_db->local_symtab, CIL_SYM_LOCAL_NUM);
	if (rc != SEPOL_OK) {
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
	
	if (parse_current == NULL || ast_list == NULL)
		return SEPOL_ERR;
	
	while(parse_current != NULL) {
		cil_list_item_init(&new_item);
		new_item->flavor = flavor;
		new_item->data = strdup(parse_current->data);
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

int cil_gen_perm_nodes(struct cil_db *db, struct cil_tree_node *current_perm, struct cil_tree_node *ast_node)
{
	int rc = 0;
	struct cil_tree_node *new_ast = NULL;

	while(current_perm != NULL) {
		cil_tree_node_init(&new_ast);
		new_ast->parent = ast_node;
		new_ast->line = current_perm->line;
		rc = cil_gen_perm(db, current_perm, new_ast);
		if (rc != SEPOL_OK) {
			printf("CLASS: Failed to gen perm\n");
			return SEPOL_ERR;
		}
		//printf("perm id: %d\n", ((struct cil_perm*)new_ast->data)->datum.value);

		if (ast_node->cl_head == NULL) 
			ast_node->cl_head = new_ast;
		else {
			ast_node->cl_tail->next = new_ast;
		}
		ast_node->cl_tail = new_ast;

		current_perm = current_perm->next;
	}
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
	if (stack == NULL || data == NULL)
		return SEPOL_ERR;

	struct cil_stack_element *new_top;
	new_top = malloc(sizeof(struct cil_stack_element));
	new_top->data = data;
	new_top->next = stack->top;
	stack->top = new_top;

	return SEPOL_OK;
}

int cil_stack_pop(struct cil_stack *stack, void *popped)
{
	if (stack == NULL)
		return SEPOL_ERR;
	
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
	if (current == NULL || namespace == NULL)
		return SEPOL_ERR;
	
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
	if (stack == NULL)
		return SEPOL_ERR;

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
		if (rc != SEPOL_OK) {
			printf("Symtab init failed\n");
			return SEPOL_ERR;
		}
	}

	return SEPOL_OK;
}

int cil_get_parent_symtab(struct cil_db *db, struct cil_tree_node *ast_node, symtab_t **symtab, uint32_t cil_sym_index)
{
	if (db == NULL || ast_node == NULL)
		return SEPOL_ERR;

	if (ast_node->parent != NULL) {
		if (ast_node->parent->flavor == CIL_BLOCK) 
			*symtab = &((struct cil_block*)ast_node->parent->data)->symtab[cil_sym_index];
		else if (ast_node->parent->flavor == CIL_CLASS) 
			*symtab = &((struct cil_class*)ast_node->parent->data)->perms;
		else if (ast_node->parent->flavor == CIL_COMMON)
			*symtab = &((struct cil_common*)ast_node->parent->data)->perms;
		else if (ast_node->parent->flavor == CIL_ROOT)
			*symtab = &db->local_symtab[cil_sym_index];
		else {
			printf("Failed to get symtab from parent node\n");
			return SEPOL_ERR;
		}
	}
	else {
		printf("Failed to get symtab: no parent node\n");
		return SEPOL_ERR;
	}

	return SEPOL_OK;
}

int cil_gen_block(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node, uint16_t is_abstract, uint16_t is_optional, char *condition)
{
	if (db == NULL || parse_current == NULL || ast_node == NULL)
		return SEPOL_ERR;

	if (parse_current->next == NULL || parse_current->next->cl_head != NULL) {
		printf("Invalid block declaration (line: %d)\n", parse_current->line);
		return SEPOL_ERR;
	}

	int rc;
	char *name;
	struct cil_block *block = malloc(sizeof(struct cil_block));
	symtab_t *symtab = NULL;

	rc = cil_symtab_array_init(block->symtab, CIL_SYM_LOCAL_NUM);
	if (rc != SEPOL_OK) {
		printf("Failed to initialize symtab array\n");
		free(block);
		return rc;
	}

	block->is_abstract = is_abstract;
	block->is_optional = is_optional;
	block->condition = condition;

	name = (char *)parse_current->next->data;

	rc = cil_get_parent_symtab(db, ast_node, &symtab, CIL_SYM_LOCAL_BLOCKS);
	if (rc != SEPOL_OK) {
		// TODO CDS create cleanup for this, since you need it after insert failure too
		free(block);
		return rc;
	}	
	
	/* TODO CDS look at hashtab_insert to see who owns the key (name in this case), to see if they need to be freed */
	rc = cil_symtab_insert(symtab, (hashtab_key_t)name, (cil_symtab_datum_t*)block, ast_node);
	if (rc != SEPOL_OK) {
		printf("Failed to insert block %s into symtab, rc: %d\n", name, rc);
		return rc;
	}

	ast_node->data = block;
	ast_node->flavor = CIL_BLOCK;

	return SEPOL_OK;	
}

void cil_destroy_block(struct cil_block *block)
{
	int i=0;
	for (i=0;i<CIL_SYM_LOCAL_NUM; i++) {
		hashtab_destroy(block->symtab[i].table);
	}

	free(block);
}

int cil_gen_class(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	if (db == NULL || parse_current == NULL || ast_node == NULL)
		return SEPOL_ERR;

	// TODO Update this check to work with common inherits
	if (parse_current->next == NULL || parse_current->next->next == NULL || parse_current->next->next->cl_head == NULL || parse_current->next->next->next != NULL) {
		printf("Invalid class declaration (line: %d)\n", parse_current->line);
		return SEPOL_ERR;
	}

	int rc;
	char *key = parse_current->next->data;
	struct cil_class *cls = malloc(sizeof(struct cil_class));

	rc = symtab_init(&cls->perms, CIL_SYM_SIZE);
	if (rc != SEPOL_OK) {
		printf("Perms symtab init failed\n");
		return SEPOL_ERR;
	}

	//TODO Syntax for inherit from common?

	rc = cil_symtab_insert(&db->global_symtab[CIL_SYM_GLOBAL_CLASSES], (hashtab_key_t)key, (cil_symtab_datum_t*)cls, ast_node);	
	if (rc != SEPOL_OK) {
		printf("Failed to insert class into symtab\n");
		return rc;
	}

	ast_node->data = cls;
	ast_node->flavor = CIL_CLASS;

	rc = cil_gen_perm_nodes(db, parse_current->next->next->cl_head, ast_node);
	if (rc != SEPOL_OK) {
		printf("Class: failed to parse perms\n");
		return SEPOL_ERR;
	}

	return SEPOL_OK;
}

void cil_destroy_class(struct cil_class *cls)
{
	hashtab_destroy(cls->perms.table);
	
	free(cls);
}

int cil_gen_perm(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	if (db == NULL || parse_current == NULL || ast_node == NULL)
		return SEPOL_ERR;

	int rc = 0;
	struct cil_perm *perm = malloc(sizeof(struct cil_perm));
	// TODO CDS the rest of this function is done over and over again. Look at pulling it out into a helper function that can be called from cil_gen_*.
	symtab_t *symtab = NULL;
	char *key = (char*)parse_current->data;

	rc = cil_get_parent_symtab(db, ast_node, &symtab, CIL_SYM_LOCAL_PERMS);
	if (rc != SEPOL_OK) {
		return rc;
	}
	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, (cil_symtab_datum_t*)perm, ast_node);
	if (rc != SEPOL_OK) {
		if (rc == SEPOL_EEXIST) {
			printf("Error: perm already exists in symtab\n");
			return rc;
		}
		else {
			printf("Error: Failed to insert perm into symtab\n");
			return rc;
		}
	}
	
	ast_node->data = perm;
	ast_node->flavor = CIL_PERM;

	return SEPOL_OK;
}

void cil_destroy_perm(struct cil_perm *perm)
{
	free(perm);
}

// TODO try to merge some of this with cil_gen_class (helper function for both)
int cil_gen_common(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	if (db == NULL || parse_current == NULL || ast_node == NULL)
		return SEPOL_ERR;

	if (parse_current->next == NULL || parse_current->next->next == NULL || parse_current->next->next->cl_head == NULL || parse_current->next->next->next != NULL) {
		printf("Invalid common declaration (line: %d)\n", parse_current->line);
		return SEPOL_ERR;
	}

	int rc;
	char *key = parse_current->next->data;
	struct cil_common *common = malloc(sizeof(struct cil_common));

	rc = symtab_init(&common->perms, CIL_SYM_SIZE);
	if (rc != SEPOL_OK) {
		printf("Common perms symtab init failed\n");
		return SEPOL_ERR;
	}

	rc = cil_symtab_insert(&db->global_symtab[CIL_SYM_GLOBAL_COMMONS], (hashtab_key_t)key, (cil_symtab_datum_t*)common, ast_node);
	if (rc != SEPOL_OK) {
		printf("Failed to insert common into symtab\n");
		return rc;
	}

	ast_node->data = common;
	ast_node->flavor = CIL_COMMON;

	rc = cil_gen_perm_nodes(db, parse_current->next->next->cl_head, ast_node);
	if (rc != SEPOL_OK) {
		printf("Class: failed to parse perms\n");
		return SEPOL_ERR;
	}
		
	return SEPOL_OK;
}

void cil_destroy_common(struct cil_common *common)
{
	hashtab_destroy(common->perms.table);
	free(common);
}

int cil_gen_sid(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	if (db == NULL || parse_current == NULL || ast_node == NULL)
		return SEPOL_ERR;

	int rc;
	struct cil_sid * sid = malloc(sizeof(struct cil_sid));	
	char *key = parse_current->next->data;

	rc = cil_symtab_insert(&db->global_symtab[CIL_SYM_GLOBAL_SIDS], (hashtab_key_t)key, (cil_symtab_datum_t*)sid, ast_node);
	if (rc != SEPOL_OK) {
		printf("Failed to insert sid into symtab\n");
		return rc;	
	}

	ast_node->data = sid;
	ast_node->flavor = CIL_SID;

	return SEPOL_OK;
}

void cil_destroy_sid(struct cil_sid *sid)
{
	free(sid);
}

int cil_gen_user(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	if (db == NULL || parse_current == NULL || ast_node == NULL)
		return SEPOL_ERR;

	if (parse_current->next == NULL || parse_current->next->next != NULL) {
		printf("Invalid user declaration (line: %d)\n", parse_current->line);
		return SEPOL_ERR;
	}

	int rc;
	struct cil_user *user = malloc(sizeof(struct cil_user));
	char *key = parse_current->next->data;

	rc = cil_symtab_insert(&db->global_symtab[CIL_SYM_GLOBAL_USERS], (hashtab_key_t)key, (cil_symtab_datum_t*)user, ast_node);
	if (rc != SEPOL_OK) {
		printf("Failed to insert user into symtab\n");
		return rc;
	}

	ast_node->data = user;
	ast_node->flavor = CIL_USER;

	return SEPOL_OK;
}

void cil_destroy_user(struct cil_user *user)
{
	free(user);
}

int cil_gen_role(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	if (db == NULL || parse_current == NULL || ast_node == NULL)
		return SEPOL_ERR;

	if (parse_current->next == NULL || parse_current->next->next != NULL) {
		printf("Invalid role declaration (line: %d)\n", parse_current->line);
		return SEPOL_ERR;
	}

	int rc;
	struct cil_role *role = malloc(sizeof(struct cil_role));
	char *key = parse_current->next->data;

	rc = cil_symtab_insert(&db->global_symtab[CIL_SYM_GLOBAL_ROLES], (hashtab_key_t)key, (cil_symtab_datum_t*)role, ast_node);
	if (rc != SEPOL_OK) {
		printf("Failed to insert role into symtab\n");
		return rc;
	}

	ast_node->data = role;
	ast_node->flavor = CIL_ROLE;

	return SEPOL_OK;
}

void cil_destroy_role(struct cil_role *role)
{
	free(role);
}

int cil_gen_avrule(struct cil_tree_node *parse_current, struct cil_tree_node *ast_node, uint32_t rule_kind)
{
	if (parse_current == NULL || ast_node == NULL)
		return SEPOL_ERR;
	
	if (parse_current->next == NULL || parse_current->next->next == NULL || parse_current->next->next->next == NULL || parse_current->next->next->next->next == NULL || parse_current->next->next->next->next->cl_head == NULL || parse_current->next->next->next->next->next != NULL) {
		printf("Invalid allow rule (line: %d)\n", parse_current->line);
		return SEPOL_ERR;
	}
	
	struct cil_avrule *rule = malloc(sizeof(struct cil_avrule));
	rule->rule_kind = rule_kind;
	rule->src_str = strdup(parse_current->next->data);
	rule->tgt_str = strdup(parse_current->next->next->data);
	rule->obj_str = strdup(parse_current->next->next->next->data);	

	if(cil_list_init(&rule->perms_str)) {
		printf("failed to init perm list\n");
		return SEPOL_ERR;
	}
	

	cil_parse_to_list(parse_current->next->next->next->next->cl_head, &rule->perms_str, CIL_AST_STR);

	ast_node->data = rule;
	ast_node->flavor = CIL_AVRULE;

	return SEPOL_OK;	
}

void cil_destroy_avrule(struct cil_avrule *rule)
{
	if (rule->src_str != NULL)
		free(rule->src_str);
	if (rule->tgt_str != NULL)
		free(rule->tgt_str);
	if (rule->obj_str != NULL)
		free(rule->obj_str);
	//If perms_str is not null, destroy list
	free(rule);
}

int cil_gen_type(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node, uint32_t flavor)
{
	if (db == NULL || parse_current == NULL || ast_node == NULL)
		return SEPOL_ERR;

	if (parse_current->next == NULL || parse_current->next->next != NULL) {
		if (flavor == CIL_TYPE) {
			printf("Invalid type declaration (line: %d)\n", parse_current->line);
			return SEPOL_ERR;
		}
		if (flavor == CIL_ATTR) {
			printf("Invalid attribute declaration (line %d)\n", parse_current->line);
			return SEPOL_ERR;
		}
	}

	int rc;
	char *key = (char*)parse_current->next->data; 
	struct cil_type *type = malloc(sizeof(struct cil_type));
	symtab_t *symtab = NULL;

	if (flavor == CIL_TYPE) {
		rc = cil_get_parent_symtab(db, ast_node, &symtab, CIL_SYM_LOCAL_TYPES);
		rc = cil_symtab_insert(symtab, (hashtab_key_t)key, (cil_symtab_datum_t*)type, ast_node);
	}
	else if (flavor == CIL_ATTR) {
		rc = cil_get_parent_symtab(db, ast_node, &symtab, CIL_SYM_LOCAL_ATTRS);
		rc = cil_symtab_insert(symtab, (hashtab_key_t)key, (cil_symtab_datum_t*)type, ast_node);	
	}
	else {
		printf("Error: cil_gen_type called on invalid node\n");
		return SEPOL_ERR;
	}

	if (rc != SEPOL_OK) {
		printf("Failed to insert %s, rc:%d\n", key,rc);
		return rc;
	}
	
	ast_node->data = type;
	ast_node->flavor = flavor;	

	return SEPOL_OK;
}

void cil_destroy_type(struct cil_type *type)
{
	free(type);
}

int cil_gen_bool(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	if (db == NULL || parse_current == NULL || ast_node == NULL)
		return SEPOL_ERR;

	if (parse_current->next == NULL || parse_current->next->next == NULL || parse_current->next->next->next != NULL) {
		printf("Invalid boolean declaration (line: %d)\n", parse_current->line);
		return SEPOL_ERR;
	}

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

	rc = cil_symtab_insert(&db->global_symtab[CIL_SYM_GLOBAL_BOOLS], (hashtab_key_t)key, (cil_symtab_datum_t*)boolean, ast_node);
	if (rc != SEPOL_OK) {
		printf("Failed to insert bool into symtab\n");
		return rc;	
	}

	ast_node->data = boolean;
	ast_node->flavor = CIL_BOOL;

	return SEPOL_OK;
}

void cil_destroy_bool(struct cil_bool *boolean)
{
	free(boolean);
}

int cil_gen_typealias(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	if (db == NULL || parse_current == NULL || ast_node == NULL)
		return SEPOL_ERR;

	int rc;
	struct cil_typealias *alias = malloc(sizeof(struct cil_typealias));
	char *key = parse_current->next->next->data;
	symtab_t *symtab;

	rc = cil_get_parent_symtab(db, ast_node, &symtab, CIL_SYM_LOCAL_ALIASES);
	if (rc != SEPOL_OK) {
		free(alias);
		return rc;
	}
	
	alias->type_str = strdup(parse_current->next->data);

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, (cil_symtab_datum_t*)alias, ast_node);
	if (rc != SEPOL_OK) {
		printf("Failed to insert alias into symtab\n");
		return rc;
	}

	ast_node->data = alias;
	ast_node->flavor = CIL_TYPEALIAS;

	return SEPOL_OK;
}

void cil_destroy_typealias(struct cil_typealias *alias)
{
	if (alias->type_str != NULL)
		free(alias->type_str);
	free(alias);
}
