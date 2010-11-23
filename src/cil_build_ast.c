#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "cil.h"
#include "cil_mem.h"
#include "cil_tree.h"
#include "cil_list.h"
#include "cil_parser.h"
#include "cil_build_ast.h"

int cil_parse_to_list(struct cil_tree_node *parse_cl_head, struct cil_list *ast_cl, uint32_t flavor)
{
	struct cil_list_item *new_item;
	struct cil_tree_node *parse_current = parse_cl_head;
	struct cil_list_item *list_tail;
	
	if (parse_current == NULL || ast_cl == NULL)
		return SEPOL_ERR;
	
	while(parse_current != NULL) {
		cil_list_item_init(&new_item);
		new_item->flavor = flavor;
		new_item->data = cil_strdup(parse_current->data);
		if (ast_cl->head == NULL)
			ast_cl->head = new_item;
		else
			list_tail->next = new_item;
		list_tail = new_item;
		parse_current = parse_current->next;
	}

	return SEPOL_OK;
} 

int cil_gen_perm_nodes(struct cil_db *db, struct cil_tree_node *current_perm, struct cil_tree_node *ast_node)
{
	int rc = SEPOL_ERR;
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

int cil_gen_block(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node, uint16_t is_abstract, uint16_t is_optional, char *condition)
{
	if (db == NULL || parse_current == NULL || ast_node == NULL)
		return SEPOL_ERR;

	if (parse_current->next == NULL || parse_current->next->cl_head != NULL) {
		printf("Invalid block declaration (line: %d)\n", parse_current->line);
		return SEPOL_ERR;
	}

	int rc = SEPOL_ERR;
	char *name;
	struct cil_block *block = cil_malloc(sizeof(struct cil_block));
	symtab_t *symtab = NULL;

	rc = cil_symtab_array_init(block->symtab, CIL_SYM_NUM);
	if (rc != SEPOL_OK) {
		printf("Failed to initialize symtab array\n");
		goto gen_block_cleanup;
	}

	block->is_abstract = is_abstract;
	block->is_optional = is_optional;
	block->condition = condition;

	name = (char *)parse_current->next->data;

	rc = cil_get_parent_symtab(db, ast_node, &symtab, CIL_SYM_BLOCKS);
	if (rc != SEPOL_OK) {
		goto gen_block_cleanup;
	}	
	
	rc = cil_symtab_insert(symtab, (hashtab_key_t)name, (struct cil_symtab_datum*)block, ast_node);
	if (rc != SEPOL_OK) {
		printf("Failed to insert block %s into symtab, rc: %d\n", name, rc);
		goto gen_block_cleanup;
	}

	ast_node->data = block;
	ast_node->flavor = CIL_BLOCK;

	return SEPOL_OK;

	gen_block_cleanup:	
		cil_destroy_block(block);
		return rc;
}

void cil_destroy_block(struct cil_block *block)
{
	cil_symtab_datum_destroy(block->datum);
	cil_symtab_array_destroy(block->symtab);
	free(block);
}

int cil_gen_class(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	int inherits = 0;

	if (db == NULL || parse_current == NULL || ast_node == NULL)
		return SEPOL_ERR;

	if (parse_current->next == NULL || parse_current->next->next == NULL) {
		goto failed_decl;	
	}

	if (parse_current->next->next->cl_head == NULL) {
		if (strcmp(parse_current->next->next->data, "inherits") != 0) {
			goto failed_decl;	
		}
		else if (parse_current->next->next->next == NULL || parse_current->next->next->next->cl_head != NULL || parse_current->next->next->next->next == NULL || parse_current->next->next->next->next->cl_head == NULL || parse_current->next->next->next->next->next != NULL) {
			goto failed_decl;	
		}
		else
			inherits = 1;
	}
	else if (parse_current->next->next->next != NULL) {	
		goto failed_decl;	
	}

	int rc = SEPOL_ERR;
	char *key = parse_current->next->data;
	struct cil_class *cls = cil_malloc(sizeof(struct cil_class));
	struct cil_tree_node *perms;
	symtab_t *symtab = NULL;

	rc = symtab_init(&cls->perms, CIL_SYM_SIZE);
	if (rc != SEPOL_OK) {
		printf("Perms symtab init failed\n");
		goto gen_class_cleanup;
	}

	if (inherits) 
		cls->common_str = cil_strdup(parse_current->next->next->next->data);

	rc = cil_get_parent_symtab(db, ast_node, &symtab, CIL_SYM_CLASSES);
	if (rc != SEPOL_OK) {
		goto gen_class_cleanup;
	}

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, (struct cil_symtab_datum*)cls, ast_node);	
	if (rc != SEPOL_OK) {
		printf("Failed to insert class into symtab\n");
		goto gen_class_cleanup;
	}

	ast_node->data = cls;
	ast_node->flavor = CIL_CLASS;

	if (inherits)
		perms = parse_current->next->next->next->next->cl_head;
	else
		perms = parse_current->next->next->cl_head;

	rc = cil_gen_perm_nodes(db, perms, ast_node);
	if (rc != SEPOL_OK) {
		printf("Class: failed to parse perms\n");
		goto gen_class_cleanup;
	}

	return SEPOL_OK;

	failed_decl:
		printf("Invalid class declaration (line: %d)\n", parse_current->line);
		return SEPOL_ERR;
			
	gen_class_cleanup:
		cil_destroy_class(cls);
		return rc;	

}

void cil_destroy_class(struct cil_class *cls)
{
	cil_symtab_datum_destroy(cls->datum);
	cil_symtab_destroy(&cls->perms);
	
	free(cls);
}

int cil_gen_perm(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	if (db == NULL || parse_current == NULL || ast_node == NULL)
		return SEPOL_ERR;

	int rc = SEPOL_ERR;
	struct cil_perm *perm = cil_malloc(sizeof(struct cil_perm));
	// TODO CDS the rest of this function is done over and over again. Look at pulling it out into a helper function that can be called from cil_gen_*.
	symtab_t *symtab = NULL;
	char *key = (char*)parse_current->data;

	rc = cil_get_parent_symtab(db, ast_node, &symtab, CIL_SYM_UNKNOWN);
	if (rc != SEPOL_OK) {
		goto gen_perm_cleanup;
	}
	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, (struct cil_symtab_datum*)perm, ast_node);
	if (rc != SEPOL_OK) {
		if (rc == SEPOL_EEXIST) {
			printf("Error: perm already exists in symtab\n");
			goto gen_perm_cleanup;
		}
		else {
			printf("Error: Failed to insert perm into symtab\n");
			goto gen_perm_cleanup;
		}
	}
	
	ast_node->data = perm;
	ast_node->flavor = CIL_PERM;

	return SEPOL_OK;

	gen_perm_cleanup:
		cil_destroy_perm(perm);
		return rc;
}

void cil_destroy_perm(struct cil_perm *perm)
{
	cil_symtab_datum_destroy(perm->datum);
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

	int rc = SEPOL_ERR;
	char *key = parse_current->next->data;
	struct cil_common *common = cil_malloc(sizeof(struct cil_common));
	symtab_t *symtab = NULL;

	rc = symtab_init(&common->perms, CIL_SYM_SIZE);
	if (rc != SEPOL_OK) {
		printf("Common perms symtab init failed\n");
		return SEPOL_ERR;
	}
	
	rc = cil_get_parent_symtab(db, ast_node, &symtab, CIL_SYM_COMMONS);
	if (rc != SEPOL_OK) {
		goto gen_common_cleanup;
	}

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, (struct cil_symtab_datum*)common, ast_node);
	if (rc != SEPOL_OK) {
		printf("Failed to insert common into symtab\n");
		return rc;
	}

	ast_node->data = common;
	ast_node->flavor = CIL_COMMON;

	rc = cil_gen_perm_nodes(db, parse_current->next->next->cl_head, ast_node);
	if (rc != SEPOL_OK) {
		printf("Common: failed to parse perms\n");
		goto gen_common_cleanup;
	}
	
	return SEPOL_OK;

	gen_common_cleanup:
		cil_destroy_common(common);
		return rc;
	
}

void cil_destroy_common(struct cil_common *common)
{
	cil_symtab_datum_destroy(common->datum);
	cil_symtab_destroy(&common->perms);
	free(common);
}

int cil_gen_sid(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	if (db == NULL || parse_current == NULL || ast_node == NULL)
		return SEPOL_ERR;

	if (parse_current->next == NULL || parse_current->next->next == NULL
	|| parse_current->next->next->next != NULL) {
		printf("Invalid sid declaration (line: %d)\n", parse_current->line);
		return SEPOL_ERR;
	}

	int rc = SEPOL_ERR;
	struct cil_sid * sid = cil_malloc(sizeof(struct cil_sid));	
	char *key = parse_current->next->data;
	symtab_t *symtab = NULL;

	rc = cil_get_parent_symtab(db, ast_node, &symtab, CIL_SYM_SIDS);
	if (rc != SEPOL_OK) {
		goto gen_sid_cleanup;
	}

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, (struct cil_symtab_datum*)sid, ast_node);
	if (rc != SEPOL_OK) {
		printf("Failed to insert sid into symtab\n");
		goto gen_sid_cleanup;	
	}

	if (parse_current->next->next->cl_head == NULL) 
		sid->context_str = cil_strdup(parse_current->next->next->data);
	else {
		sid->context = cil_malloc(sizeof(struct cil_context));
		rc = cil_fill_context(parse_current->next->next->cl_head, sid->context);
		if (rc != SEPOL_OK) {
			printf("Failed to fill sid context\n");
			goto gen_sid_cleanup;
		}
	}

	ast_node->data = sid;
	ast_node->flavor = CIL_SID;

	return SEPOL_OK;
	
	gen_sid_cleanup:
		cil_destroy_sid(sid);
		return rc;
}

void cil_destroy_sid(struct cil_sid *sid)
{
	cil_symtab_datum_destroy(sid->datum);
	if (sid->context_str != NULL)
		free(sid->context_str);
	else if (sid->context != NULL && sid->context->datum.name == NULL)
		cil_destroy_context(sid->context);
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

	int rc = SEPOL_ERR;
	struct cil_user *user = cil_malloc(sizeof(struct cil_user));
	char *key = parse_current->next->data;
	symtab_t *symtab = NULL;
	
	rc = cil_get_parent_symtab(db, ast_node, &symtab, CIL_SYM_USERS);
	if (rc != SEPOL_OK) {
		goto gen_user_cleanup;
	}

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, (struct cil_symtab_datum*)user, ast_node);
	if (rc != SEPOL_OK) {
		printf("Failed to insert user into symtab\n");
		goto gen_user_cleanup;
	}

	ast_node->data = user;
	ast_node->flavor = CIL_USER;

	return SEPOL_OK;

	gen_user_cleanup:
		cil_destroy_user(user);
		return rc;
}

void cil_destroy_user(struct cil_user *user)
{
	cil_symtab_datum_destroy(user->datum);
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

	int rc = SEPOL_ERR;
	struct cil_role *role = cil_malloc(sizeof(struct cil_role));
	char *key = parse_current->next->data;
	symtab_t *symtab = NULL;

	rc = cil_get_parent_symtab(db, ast_node, &symtab, CIL_SYM_ROLES);
	if (rc != SEPOL_OK) {
		goto gen_role_cleanup;
	}

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, (struct cil_symtab_datum*)role, ast_node);
	if (rc != SEPOL_OK) {
		printf("Failed to insert role into symtab\n");
		goto gen_role_cleanup;
	}

	ast_node->data = role;
	ast_node->flavor = CIL_ROLE;

	return SEPOL_OK;

	gen_role_cleanup:
		cil_destroy_role(role);
		return rc;
}

void cil_destroy_role(struct cil_role *role)
{
	cil_symtab_datum_destroy(role->datum);
	free(role);
}

int cil_gen_roletype(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	if (db == NULL || parse_current == NULL || ast_node == NULL)
		return SEPOL_ERR;

	if (parse_current->next == NULL || parse_current->next->cl_head != NULL || parse_current->next->next == NULL || parse_current->next->next->cl_head != NULL) {
		printf("Invalid roletype declaration (line: %d)\n", parse_current->line);
		return SEPOL_ERR;
	}
	
	struct cil_roletype *roletype = cil_malloc(sizeof(struct cil_roletype));

	roletype->role_str = cil_strdup(parse_current->next->data);
	roletype->type_str = cil_strdup(parse_current->next->next->data);

	ast_node->data = roletype;
	ast_node->flavor = CIL_ROLETYPE;
	
	return SEPOL_OK;
}

void cil_destroy_roletype(struct cil_roletype *roletype)
{
	if (roletype->role_str != NULL)
		free(roletype->role_str);
	if (roletype->type_str != NULL)
		free(roletype->type_str);
	free(roletype);
}

int cil_gen_userrole(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	if (db == NULL || parse_current == NULL || ast_node == NULL)
		return SEPOL_ERR;

	if (parse_current->next == NULL || parse_current->next->cl_head != NULL || parse_current->next->next == NULL || parse_current->next->next->cl_head != NULL) {
		printf("Invalid userrole declaration (line: %d)\n", parse_current->line);
		return SEPOL_ERR;
	}

	struct cil_userrole *userrole = cil_malloc(sizeof(struct cil_userrole));

	userrole->user_str = cil_strdup(parse_current->next->data);
	userrole->role_str = cil_strdup(parse_current->next->next->data);

	ast_node->data = userrole;
	ast_node->flavor = CIL_USERROLE;
	
	return SEPOL_OK;
}

void cil_destroy_userrole(struct cil_userrole *userrole)
{
	if (userrole->user_str != NULL)
		free(userrole->user_str);
	if (userrole->role_str != NULL)
		free(userrole->role_str);
	free(userrole);
}

int cil_gen_roletrans(struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	if (parse_current == NULL || ast_node == NULL)
		return SEPOL_ERR;
	
	if (parse_current->next == NULL || \
		parse_current->next->next == NULL || \
		parse_current->next->next->next == NULL || \
		parse_current->next->next->next->next != NULL) 
	{
		printf("Invalid roletransition declaration (line: %d)\n", parse_current->line);
		return SEPOL_ERR;
	}

	struct cil_role_trans *roletrans = cil_malloc(sizeof(struct cil_role_trans));

	roletrans->src_str = cil_strdup(parse_current->next->data);
	roletrans->tgt_str = cil_strdup(parse_current->next->next->data);
	roletrans->result_str = cil_strdup(parse_current->next->next->next->data);

	ast_node->data = roletrans;
	ast_node->flavor = CIL_ROLETRANS;

	return SEPOL_OK;
}

void cil_destroy_roletrans(struct cil_role_trans *roletrans)
{
	if (roletrans->src_str != NULL)
		free(roletrans->src_str);
	if (roletrans->tgt_str != NULL)
		free(roletrans->tgt_str);
	if (roletrans->result_str != NULL)
		free(roletrans->result_str);
	free(roletrans);
}

int cil_gen_roleallow(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	if (db == NULL || parse_current == NULL || ast_node == NULL)
		return SEPOL_ERR;
	
	if (parse_current->next == NULL || \
		parse_current->next->next == NULL || \
		parse_current->next->next->next != NULL)
	{
		printf("Invalid roleallow declaration (line: %d)\n", parse_current->line);
		return SEPOL_ERR;
	}

	struct cil_role_allow *roleallow = cil_malloc(sizeof(struct cil_role_allow));

	roleallow->src_str = cil_strdup(parse_current->next->data);
	roleallow->tgt_str = cil_strdup(parse_current->next->next->data);

	ast_node->data = roleallow;
	ast_node->flavor = CIL_ROLEALLOW;

	return SEPOL_OK;
}

void cil_destroy_roleallow(struct cil_role_allow *roleallow)
{
	if (roleallow->src_str != NULL)
		free(roleallow->src_str);
	if (roleallow->tgt_str != NULL)
		free(roleallow->tgt_str);
	free(roleallow);
}


int cil_gen_avrule(struct cil_tree_node *parse_current, struct cil_tree_node *ast_node, uint32_t rule_kind)
{
	if (parse_current == NULL || ast_node == NULL)
		return SEPOL_ERR;
	
	if (parse_current->next == NULL || parse_current->next->next == NULL || parse_current->next->next->next == NULL || parse_current->next->next->next->next == NULL || parse_current->next->next->next->next->cl_head == NULL || parse_current->next->next->next->next->next != NULL) {
		printf("Invalid allow rule (line: %d)\n", parse_current->line);
		return SEPOL_ERR;
	}
	
	struct cil_avrule *rule = cil_malloc(sizeof(struct cil_avrule));
	rule->rule_kind = rule_kind;
	rule->src_str = cil_strdup(parse_current->next->data);
	rule->tgt_str = cil_strdup(parse_current->next->next->data);
	rule->obj_str = cil_strdup(parse_current->next->next->next->data);	

	cil_list_init(&rule->perms_str);
	cil_parse_to_list(parse_current->next->next->next->next->cl_head, rule->perms_str, CIL_AST_STR);

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
	if (rule->perms_str != NULL)
		cil_list_destroy(&rule->perms_str, 1);
	if (rule->perms_list != NULL)
		cil_list_destroy(&rule->perms_list, 0);
	free(rule);
}

int cil_gen_type_rule(struct cil_tree_node *parse_current, struct cil_tree_node *ast_node, uint32_t rule_kind)
{
	if (parse_current == NULL || ast_node == NULL)
		return SEPOL_ERR;
	
	if (parse_current->next == NULL || \
		parse_current->next->next == NULL || \
		parse_current->next->next->next == NULL || \
		parse_current->next->next->next->next == NULL || \
		parse_current->next->next->next->next->next != NULL) 
	{
		printf("Invalid type rule (line: %d)\n", parse_current->line);
		return SEPOL_ERR;
	}
	
	struct cil_type_rule *rule = cil_malloc(sizeof(struct cil_type_rule));
	rule->rule_kind = rule_kind;
	rule->src_str = cil_strdup(parse_current->next->data);
	rule->tgt_str = cil_strdup(parse_current->next->next->data);
	rule->obj_str = cil_strdup(parse_current->next->next->next->data);	
	rule->result_str = cil_strdup(parse_current->next->next->next->next->data);

	ast_node->data = rule;
	ast_node->flavor = CIL_TYPE_RULE;

	return SEPOL_OK;	
}

void cil_destroy_type_rule(struct cil_type_rule *rule)
{
	if (rule->src_str != NULL)
		free(rule->src_str);
	if (rule->tgt_str != NULL)
		free(rule->tgt_str);
	if (rule->obj_str != NULL)
		free(rule->obj_str);
	if (rule->result_str != NULL)
		free(rule->result_str);
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

	int rc = SEPOL_ERR;
	char *key = (char*)parse_current->next->data; 
	struct cil_type *type = cil_malloc(sizeof(struct cil_type));
	symtab_t *symtab = NULL;

	if (flavor == CIL_TYPE || flavor == CIL_ATTR) {
		rc = cil_get_parent_symtab(db, ast_node, &symtab, CIL_SYM_TYPES);
		rc = cil_symtab_insert(symtab, (hashtab_key_t)key, (struct cil_symtab_datum*)type, ast_node);
	}
	else {
		printf("Error: cil_gen_type called on invalid node\n");
		goto gen_type_cleanup;
	}

	if (rc != SEPOL_OK) {
		printf("Failed to insert %s, rc:%d\n", key,rc);
		goto gen_type_cleanup;
	}
	
	ast_node->data = type;
	ast_node->flavor = flavor;	

	return SEPOL_OK;

	gen_type_cleanup:
		cil_destroy_type(type);
		return rc;
}

void cil_destroy_type(struct cil_type *type)
{
	cil_symtab_datum_destroy(type->datum);
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

	int rc = SEPOL_ERR;
	struct cil_bool *boolean;
	char *key = parse_current->next->data;
	boolean = cil_malloc(sizeof(struct cil_bool));
	symtab_t *symtab = NULL;

	if (!strcmp(parse_current->next->next->data, "true"))
		boolean->value = 1;
	else if (!strcmp(parse_current->next->next->data, "false"))
		boolean->value = 0;
	else {
		printf("Error: boolean value must be \'true\' or \'false\'");
		goto gen_bool_cleanup;
	}
	
	rc = cil_get_parent_symtab(db, ast_node, &symtab, CIL_SYM_BOOLS);
	if (rc != SEPOL_OK) 
		goto gen_bool_cleanup;

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, (struct cil_symtab_datum*)boolean, ast_node);
	if (rc != SEPOL_OK) {
		printf("Failed to insert bool into symtab\n");
		goto gen_bool_cleanup;	
	}

	ast_node->data = boolean;
	ast_node->flavor = CIL_BOOL;

	return SEPOL_OK;

	gen_bool_cleanup:
		cil_destroy_bool(boolean);
		return rc;
}

void cil_destroy_bool(struct cil_bool *boolean)
{
	cil_symtab_datum_destroy(boolean->datum);
	free(boolean);
}

int cil_gen_typealias(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	if (db == NULL || parse_current == NULL || ast_node == NULL)
		return SEPOL_ERR;

	if (parse_current->next == NULL || parse_current->next->next == NULL || parse_current->next->next->next != NULL) {
		printf("Invalid typealias declaration (line: %d)\n", parse_current->line);
		return SEPOL_ERR;
	}

	int rc = SEPOL_ERR;
	struct cil_typealias *alias = cil_malloc(sizeof(struct cil_typealias));
	char *key = parse_current->next->next->data;
	symtab_t *symtab;

	rc = cil_get_parent_symtab(db, ast_node, &symtab, CIL_SYM_TYPES);
	if (rc != SEPOL_OK) {
		goto gen_typealias_cleanup;
	}
	
	alias->type_str = cil_strdup(parse_current->next->data);

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, (struct cil_symtab_datum*)alias, ast_node);
	if (rc != SEPOL_OK) {
		printf("Failed to insert alias into symtab\n");
		goto gen_typealias_cleanup;
	}

	ast_node->data = alias;
	ast_node->flavor = CIL_TYPEALIAS;

	return SEPOL_OK;
	
	gen_typealias_cleanup:
		cil_destroy_typealias(alias);
		return rc;
}

void cil_destroy_typealias(struct cil_typealias *alias)
{
	cil_symtab_datum_destroy(alias->datum);
	if (alias->type_str != NULL)
		free(alias->type_str);
	free(alias);
}

int cil_gen_typeattr(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	if (db == NULL || parse_current == NULL || ast_node == NULL)
		return SEPOL_ERR;

	if (parse_current->next == NULL || parse_current->next->next == NULL || \
		parse_current->next->next->cl_head != NULL || parse_current->next->next->next != NULL ) {
		printf("Invalid typeattribute declaration (line: %d)\n", parse_current->line);
		return SEPOL_ERR;
	}

	struct cil_typeattribute *typeattr = cil_malloc(sizeof(struct cil_typeattribute));
	typeattr->type_str = cil_strdup(parse_current->next->data);
	typeattr->attr_str = cil_strdup(parse_current->next->next->data);

	ast_node->data = typeattr;
	ast_node->flavor = CIL_TYPE_ATTR;

	return SEPOL_OK;
}

void cil_destroy_typeattr(struct cil_typeattribute *typeattr)
{
	free(typeattr);
}

int cil_gen_sensitivity(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	if (db == NULL || parse_current == NULL || ast_node == NULL)
		return SEPOL_ERR;

	if (parse_current->next == NULL || parse_current->next->next != NULL || parse_current->next->cl_head != NULL) {
		printf("Invalid sensitivity declaration (line: %d)\n", parse_current->line);
		return SEPOL_ERR;
	}

	int rc = SEPOL_ERR;
	struct cil_sens *sens = cil_malloc(sizeof(struct cil_sens));
	char *key = parse_current->next->data;
	symtab_t *symtab = NULL;
	
	rc = symtab_init(&sens->cats, CIL_SYM_SIZE);
	if (rc != SEPOL_OK) {
		printf("Categories symtab init failed\n");
		goto gen_sens_cleanup;
	}

	rc = cil_get_parent_symtab(db, ast_node, &symtab, CIL_SYM_SENS);
	if (rc != SEPOL_OK) {
		goto gen_sens_cleanup;
	}

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, (struct cil_symtab_datum*)sens, ast_node);
	if (rc != SEPOL_OK) {
		printf("Failed to insert sensitivity into symtab\n");
		goto gen_sens_cleanup;
	}

	ast_node->data = sens;
	ast_node->flavor = CIL_SENS;

	return SEPOL_OK;

	gen_sens_cleanup:
		cil_destroy_sensitivity(sens);
		return rc;
}

void cil_destroy_sensitivity(struct cil_sens *sens)
{
	cil_symtab_datum_destroy(sens->datum);
	free(sens);
}

int cil_gen_sensalias(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	if (db == NULL || parse_current == NULL || ast_node == NULL)
		return SEPOL_ERR;

	if (parse_current->next == NULL || parse_current->next->next == NULL || parse_current->next->next->next != NULL) {
		printf("Invalid sensitivityalias declaration (line: %d)\n", parse_current->line);
		return SEPOL_ERR;
	}

	int rc = SEPOL_ERR;
	struct cil_sensalias *alias = cil_malloc(sizeof(struct cil_sensalias));
	char *key = parse_current->next->next->data;
	symtab_t *symtab;

	rc = cil_get_parent_symtab(db, ast_node, &symtab, CIL_SYM_SENS);
	if (rc != SEPOL_OK) {
		goto gen_sensalias_cleanup;
	}
	
	alias->sens_str = cil_strdup(parse_current->next->data);

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, (struct cil_symtab_datum*)alias, ast_node);
	if (rc != SEPOL_OK) {
		printf("Failed to insert alias into symtab\n");
		goto gen_sensalias_cleanup;
	}

	ast_node->data = alias;
	ast_node->flavor = CIL_SENSALIAS;

	return SEPOL_OK;
	
	gen_sensalias_cleanup:
		cil_destroy_sensalias(alias);
		return rc;
}

void cil_destroy_sensalias(struct cil_sensalias *alias)
{
	cil_symtab_datum_destroy(alias->datum);
	if (alias->sens_str != NULL)
		free(alias->sens_str);
	free(alias);
}

int cil_gen_category(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	if (db == NULL || parse_current == NULL || ast_node == NULL)
		return SEPOL_ERR;

	if (parse_current->next == NULL || parse_current->next->next != NULL || parse_current->next->cl_head != NULL) {
		printf("Invalid category declaration (line: %d)\n", parse_current->line);
		return SEPOL_ERR;
	}

	int rc = SEPOL_ERR;
	struct cil_cat *cat = cil_malloc(sizeof(struct cil_cat));
	char *key = parse_current->next->data;
	symtab_t *symtab = NULL;
	
	rc = cil_get_parent_symtab(db, ast_node, &symtab, CIL_SYM_CATS);
	if (rc != SEPOL_OK) {
		goto gen_cat_cleanup;
	}

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, (struct cil_symtab_datum*)cat, ast_node);
	if (rc != SEPOL_OK) {
		printf("Failed to insert sensitivity into symtab\n");
		goto gen_cat_cleanup;
	}

	ast_node->data = cat;
	ast_node->flavor = CIL_CAT;

	return SEPOL_OK;

	gen_cat_cleanup:
		cil_destroy_category(cat);
		return rc;
}

void cil_destroy_category(struct cil_cat *cat)
{
	cil_symtab_datum_destroy(cat->datum);
	free(cat);
}

int cil_gen_catalias(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	if (db == NULL || parse_current == NULL || ast_node == NULL)
		return SEPOL_ERR;

	if (parse_current->next == NULL || parse_current->next->next == NULL || parse_current->next->next->next != NULL) {
		printf("Invalid sensitivityalias declaration (line: %d)\n", parse_current->line);
		return SEPOL_ERR;
	}

	int rc = SEPOL_ERR;
	
	struct cil_catalias *alias = cil_malloc(sizeof(struct cil_catalias));
	char *key = parse_current->next->next->data;
	symtab_t *symtab;

	rc = cil_get_parent_symtab(db, ast_node, &symtab, CIL_SYM_CATS);
	if (rc != SEPOL_OK) {
		goto gen_catalias_cleanup;
	}
	
	alias->cat_str = cil_strdup(parse_current->next->data);

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, (struct cil_symtab_datum*)alias, ast_node);
	if (rc != SEPOL_OK) {
		printf("Failed to insert alias into symtab\n");
		goto gen_catalias_cleanup;
	}

	ast_node->data = alias;
	ast_node->flavor = CIL_CATALIAS;

	return SEPOL_OK;
	
	gen_catalias_cleanup:
		cil_destroy_catalias(alias);
		return rc;
}

void cil_destroy_catalias(struct cil_catalias *alias)
{
	cil_symtab_datum_destroy(alias->datum);
	if (alias->cat_str != NULL)
		free(alias->cat_str);
	free(alias);
}

int cil_catset_to_list(struct cil_tree_node *parse_current, struct cil_list *ast_cl)
{
	if (parse_current == NULL || ast_cl == NULL)
		return SEPOL_ERR;

	struct cil_list *sub_list;
	struct cil_list_item *new_item;
	struct cil_list_item *list_tail;
	struct cil_tree_node *curr = parse_current;
	
	if (parse_current->cl_head == NULL) {
		printf("Error: Invalid list\n");
		return SEPOL_ERR;
	}

	curr = curr->cl_head;
	while (curr != NULL) {
		cil_list_item_init(&new_item);
		if (curr->cl_head == NULL) {
			new_item->flavor = CIL_AST_STR;
			new_item->data = cil_strdup(curr->data);
		}
		else {
			cil_list_init(&sub_list);
			new_item->flavor = CIL_LIST;
			new_item->data = sub_list;
			cil_catset_to_list(curr, sub_list);
		}
		if (ast_cl->head == NULL)
			ast_cl->head = new_item;
		else
			list_tail->next = new_item;
		list_tail = new_item;
		curr = curr->next;
	}
	
	return SEPOL_OK;
}

int cil_gen_catset(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	if (db == NULL || parse_current == NULL || ast_node == NULL)
		return SEPOL_ERR;

	if (parse_current->next == NULL || parse_current->next->next == NULL) {
		printf("Invalid categoryset declaration (line: %d)\n", parse_current->line);
		return SEPOL_ERR;
	}

	int rc = SEPOL_ERR;
	char *key = parse_current->next->data;
	struct cil_catset *catset = cil_malloc(sizeof(struct cil_catset));
	symtab_t *symtab;

	rc = cil_get_parent_symtab(db, ast_node, &symtab, CIL_SYM_CATS);
	if (rc != SEPOL_OK) {
		goto gen_catset_cleanup;
	}

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, (struct cil_symtab_datum*)catset, ast_node);
	if (rc != SEPOL_OK) {
		printf("Failed to insert categoryset into symtab\n");
		goto gen_catset_cleanup;
	}

	cil_list_init(&catset->cat_list_str);

	rc = cil_catset_to_list(parse_current->next->next, catset->cat_list_str);
	if (rc != SEPOL_OK) {
		printf("Failed to create categoryset list\n");
		goto gen_catset_cleanup;
	}

	ast_node->data = catset;
	ast_node->flavor = CIL_CATSET;

	return SEPOL_OK;

	gen_catset_cleanup:
		cil_destroy_catset(catset);
		return rc;	
}

void cil_destroy_catset(struct cil_catset *catset)
{
	cil_symtab_datum_destroy(catset->datum);
	if (catset->cat_list_str != NULL)
		cil_list_destroy(&catset->cat_list_str, 1);
	if (catset->cat_list != NULL) 
		cil_list_destroy(&catset->cat_list, 0);
	free(catset);
}

int cil_gen_catorder(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	if (db == NULL || parse_current == NULL || ast_node == NULL)
		return SEPOL_ERR;
	
	if (parse_current->next == NULL || parse_current->next->cl_head == NULL) {
		printf("Invalid categoryorder declaration (line %d)\n", parse_current->line);
		return SEPOL_ERR;
	}

	int rc = SEPOL_ERR;
	struct cil_catorder *catorder = cil_malloc(sizeof(struct cil_catorder));
	cil_list_init(&catorder->cat_list_str);
	
	rc = cil_catset_to_list(parse_current->next, catorder->cat_list_str);
	if (rc != SEPOL_OK) {
		printf("Failed to create category list\n");
		goto gen_catorder_cleanup;
	}
	ast_node->data = catorder;
	ast_node->flavor = CIL_CATORDER;

	return SEPOL_OK;

	gen_catorder_cleanup:
		cil_destroy_catorder(catorder);
		return rc;
}

void cil_destroy_catorder(struct cil_catorder *catorder)
{
	if (catorder->cat_list_str != NULL)
		cil_list_destroy(&catorder->cat_list_str, 1);
	free(catorder);
}

int cil_gen_senscat(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	if (db == NULL || parse_current == NULL || ast_node == NULL)
		return SEPOL_ERR;

	if (parse_current->next == NULL || parse_current->next->next->cl_head == NULL) {
		printf("Invalid sensitivitycategory declaration (line %d)\n", parse_current->line);
		return SEPOL_ERR;
	}

	int rc = SEPOL_ERR;
	struct cil_senscat *senscat = cil_malloc(sizeof(struct cil_senscat));

	senscat->sens_str = cil_strdup(parse_current->next->data);

	cil_list_init(&senscat->cat_list_str);
	
	rc = cil_catset_to_list(parse_current->next->next, senscat->cat_list_str);
	if (rc != SEPOL_OK) {
		printf("Failed to create category list\n");
		goto gen_senscat_cleanup;
	}
	ast_node->data = senscat;
	ast_node->flavor = CIL_SENSCAT;

	return SEPOL_OK;

	gen_senscat_cleanup:
		cil_destroy_senscat(senscat);
		return rc;
}

void cil_destroy_senscat(struct cil_senscat *senscat)
{
	if (senscat->sens_str != NULL)
		free(senscat->sens_str);
	if (senscat->cat_list_str != NULL)
		cil_list_destroy(&senscat->cat_list_str, 1);
	free(senscat);
}

int cil_fill_level(struct cil_tree_node *sens, struct cil_level *level)
{
	int rc = SEPOL_ERR;

	if (sens == NULL || level == NULL)
		return SEPOL_ERR;

	level->sens_str = cil_strdup(sens->data);

	if (sens->next == NULL)
		return SEPOL_OK;

	cil_list_init(&level->cat_list_str);

	rc = cil_catset_to_list(sens->next, level->cat_list_str);
	if (rc != SEPOL_OK) {
		printf("Failed to create level category list\n");
		goto cil_fill_level_cleanup;
	}

	return SEPOL_OK;

	cil_fill_level_cleanup:
		if (level->sens_str != NULL) {
			free(level->sens_str);
			level->sens_str = NULL;
		}
		if (level->cat_list_str != NULL) {
			cil_list_destroy(&level->cat_list_str, 1);
			level->cat_list_str = NULL;
		}
		return rc;

}

int cil_gen_level(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	if (db == NULL || parse_current == NULL || ast_node == NULL)
		return SEPOL_ERR;

	if (parse_current->next == NULL || parse_current->next->next == NULL) {
		printf("Invalid level declaration (line: %d)\n", parse_current->line);
		return SEPOL_ERR;
	}

	int rc = SEPOL_ERR;
	char *key = parse_current->next->data;
	struct cil_level *level = cil_malloc(sizeof(struct cil_level));
	symtab_t *symtab;

	rc = cil_get_parent_symtab(db, ast_node, &symtab, CIL_SYM_LEVELS);
	if (rc != SEPOL_OK) {
		goto gen_level_cleanup;
	}

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, (struct cil_symtab_datum*)level, ast_node);
	if (rc != SEPOL_OK) {
		printf("Failed to insert level into symtab\n");
		goto gen_level_cleanup;
	}

	rc = cil_fill_level(parse_current->next->next, level);
	if (rc != SEPOL_OK) {
		printf("Failed to populate level\n");
		goto gen_level_cleanup;
	}

	ast_node->data = level;
	ast_node->flavor = CIL_LEVEL;

	return SEPOL_OK;

	gen_level_cleanup:
		cil_destroy_level(level);
		return rc;	
}

void cil_destroy_level(struct cil_level *level)
{
	cil_symtab_datum_destroy(level->datum);
	if (level->sens_str != NULL)
		free(level->sens_str);
	if (level->cat_list_str != NULL)
		cil_list_destroy(&level->cat_list_str, 1);
	if (level->cat_list != NULL) 
		cil_list_destroy(&level->cat_list, 0);
	free(level);
}

int __cil_build_constrain_tree(struct cil_tree_node *parse_current, struct cil_tree_node *expr_root)
{
	struct cil_tree_node *curr = parse_current;
	struct cil_tree_node *expr_curr = expr_root;
	struct cil_tree_node *new_node = NULL;
	int rc = SEPOL_ERR;

	while (curr != NULL) {
		if (curr->cl_head == NULL) {
			cil_tree_node_init(&new_node);
			new_node->parent = expr_curr;
			new_node->line = expr_curr->line;
			new_node->data = cil_strdup(curr->data);
			new_node->flavor = CIL_AST_STR;
			if (expr_curr->cl_head == NULL)
				expr_curr->cl_head = new_node;
			else
				expr_curr->cl_tail->next = new_node;
			expr_curr->cl_tail = new_node;
			if (strstr(CIL_CONSTRAIN_OPER, curr->data) != NULL) 
				expr_curr = new_node;
		}
		else {
			rc = __cil_build_constrain_tree(curr->cl_head, expr_curr);
			if (rc != SEPOL_OK) {
				printf("Error building constrain expression tree\n");
				return rc;
			}
		}
		curr = curr->next;
	}
	expr_curr = expr_curr->parent;
	
	return SEPOL_OK;
}

int cil_gen_mlsconstrain(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	if (db == NULL || parse_current == NULL || ast_node == NULL)
		return SEPOL_ERR;
	
	if (parse_current->next == NULL || 
		parse_current->next->cl_head == NULL || 
		parse_current->next->next == NULL || 
		parse_current->next->next->cl_head == NULL || 
		parse_current->next->next->next == NULL || 
		parse_current->next->next->next->cl_head == NULL) {
		printf("Invalid mlsconstrain declaration (line: %d)\n", parse_current->line);
		return SEPOL_ERR;
	}

	struct cil_mlsconstrain *mlscon = cil_malloc(sizeof(struct cil_mlsconstrain));
	int rc = SEPOL_ERR;

	cil_list_init(&mlscon->class_list_str);
	cil_parse_to_list(parse_current->next->cl_head, mlscon->class_list_str, CIL_AST_STR);
	cil_list_init(&mlscon->perm_list_str);
	cil_parse_to_list(parse_current->next->next->cl_head, mlscon->perm_list_str, CIL_AST_STR);

	cil_tree_init(&mlscon->expr);
	rc = __cil_build_constrain_tree(parse_current->next->next->next->cl_head, mlscon->expr->root);
	if (rc != SEPOL_OK) {
		printf("Failed to build constrain expression tree\n");
		goto gen_mlsconstrain_cleanup;
	}

	ast_node->data = mlscon;
	ast_node->flavor = CIL_MLSCONSTRAIN;

	return SEPOL_OK;

	gen_mlsconstrain_cleanup:
		cil_destroy_mlsconstrain(mlscon);
		return rc;
		
}

void cil_destroy_mlsconstrain(struct cil_mlsconstrain *mlscon)
{
	if (mlscon->class_list_str != NULL)
		cil_list_destroy(&mlscon->class_list_str, 1);
	if (mlscon->class_list != NULL)
		cil_list_destroy(&mlscon->class_list, 0);
	if (mlscon->perm_list_str != NULL)
		cil_list_destroy(&mlscon->perm_list_str, 1);
	if (mlscon->perm_list != NULL)
		cil_list_destroy(&mlscon->perm_list, 0);
	if (mlscon->expr != NULL)
		cil_tree_destroy(&mlscon->expr);
	free(mlscon);
}

/* Fills in context starting from user */
int cil_fill_context(struct cil_tree_node *user_node, struct cil_context *context) 
{	
	if (user_node == NULL || context == NULL) 
		return SEPOL_ERR;

	if (user_node->next == NULL || user_node->next->next == NULL
	|| user_node->next->next->next == NULL || user_node->next->next->next->next == NULL) {
		printf("Invalid context (line: %d)\n", user_node->line);
		return SEPOL_ERR;
	}

	int rc = SEPOL_ERR;

	context->user_str = cil_strdup(user_node->data);
	context->role_str = cil_strdup(user_node->next->data);
	context->type_str = cil_strdup(user_node->next->next->data);
	
	context->low_str = NULL;
	context->high_str = NULL;

	if (user_node->next->next->next->cl_head == NULL)
		context->low_str = cil_strdup(user_node->next->next->next->data);
	else {
		context->low = cil_malloc(sizeof(struct cil_level));
		rc = cil_fill_level(user_node->next->next->next->cl_head, context->low);
		if (rc != SEPOL_OK) {
			printf("cil_fill_context: Failed to fill low level, rc: %d\n", rc); 
			goto cil_fill_context_cleanup;
		}
	}

	if (user_node->next->next->next->next->cl_head == NULL)
		context->high_str = cil_strdup(user_node->next->next->next->next->data);
	else {
		context->high = cil_malloc(sizeof(struct cil_level));
		rc = cil_fill_level(user_node->next->next->next->next->cl_head, context->high);
		if (rc != SEPOL_OK) {
			printf("cil_fill_context: Failed to fill high level, rc %d\n", rc);
			goto cil_fill_context_cleanup;
		}
	}

	return SEPOL_OK;
	
	cil_fill_context_cleanup:
		if (context->user_str != NULL) {
			free(context->user_str);
			context->user_str = NULL;
		}
		if (context->role_str != NULL) {
			free(context->role_str);
			context->role_str = NULL;
		}
		if (context->type_str != NULL) {
			free(context->type_str);
			context->type_str = NULL;
		}
		if (context->low_str != NULL) {
			free(context->low_str);
			context->low_str = NULL;
		}
		if (context->low != NULL) {
			cil_destroy_level(context->low);
			context->low = NULL;
		}
		if (context->high_str != NULL) {
			free(context->high_str);
			context->high_str = NULL;
		}
		if (context->high != NULL) {
			cil_destroy_level(context->high);
			context->high = NULL;
		}
		return rc;
} 

int cil_gen_context(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	if (db == NULL || parse_current == NULL || ast_node == NULL)
		return SEPOL_ERR;

	int rc = SEPOL_ERR;

	if (parse_current->next == NULL || parse_current->next->next == NULL) {
		printf("Invalid context declaration (line: %d)\n", parse_current->line);
		return SEPOL_ERR;
	}

	struct cil_context *context = cil_malloc(sizeof(struct cil_context));
	// Syntax for 'context' statements (named)
	if (parse_current->next->next->cl_head != NULL) {
		if (parse_current->next->next->next != NULL
		|| parse_current->next->next->cl_head == NULL
		|| parse_current->next->next->cl_head->cl_head != NULL
		|| parse_current->next->next->cl_head->next == NULL
 		|| parse_current->next->next->cl_head->next->cl_head != NULL
		|| parse_current->next->next->cl_head->next->next == NULL
		|| parse_current->next->next->cl_head->next->next->cl_head != NULL
		|| parse_current->next->next->cl_head->next->next->next == NULL
		|| parse_current->next->next->cl_head->next->next->next->next == NULL) {
			printf("Invalid context declaration (line: %d)\n", parse_current->line);
			goto gen_context_cleanup;
		}

		char *key = (char*)parse_current->next->data;
		symtab_t *symtab = NULL;

		rc = cil_get_parent_symtab(db, ast_node, &symtab, CIL_SYM_CONTEXTS);
		rc = cil_symtab_insert(symtab, (hashtab_key_t)key, (struct cil_symtab_datum*)context, ast_node);
		if (rc != SEPOL_OK) {
			printf("Failed to insert context: %s, rc: %d\n", key, rc);
			goto gen_context_cleanup;
		}
	
		rc = cil_fill_context(parse_current->next->next->cl_head, context);
		if (rc != SEPOL_OK) {
			printf("Failed to fill context, rc: %d\n", rc);
			goto gen_context_cleanup;
		}
	}
	else {
		rc = cil_fill_context(parse_current, context);
		if (rc != SEPOL_OK) {
			printf("Failed to fill context, rc: %d\n", rc);
			goto gen_context_cleanup;
		}
	}

	ast_node->data = context;
	ast_node->flavor = CIL_CONTEXT;

	return SEPOL_OK;
	
	gen_context_cleanup:
		cil_destroy_context(context);
		return SEPOL_ERR;
}

void cil_destroy_context(struct cil_context *context)
{
	if (context->user_str != NULL)
		free(context->user_str);
	if (context->role_str != NULL)
		free(context->role_str);
	if (context->type_str != NULL)
		free(context->type_str);
	if (context->low_str != NULL)
		free(context->low_str);
	if (context->high_str != NULL)
		free(context->high_str);
//	if (context->low != NULL)
//		cil_destroy_level(low);
//	if (context->high != NULL)
//		cil_destroy_level(high);	
}

int cil_gen_netifcon(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node) {
	if (db == NULL || parse_current == NULL || ast_node == NULL)
		return SEPOL_ERR;

	int rc = SEPOL_ERR;

	if (parse_current->next == NULL
	|| parse_current->next->cl_head != NULL
	|| parse_current->next->next == NULL
	|| parse_current->next->next->next == NULL
	|| (parse_current->next->next->cl_head != NULL && parse_current->next->next->next->cl_head == NULL)
	|| (parse_current->next->next->cl_head == NULL && parse_current->next->next->next->cl_head != NULL)) {
		printf("Invalid netifcon declaration (line: %d)\n", parse_current->line);
		return SEPOL_ERR;
	}
	
	struct cil_netifcon *netifcon = cil_malloc(sizeof(struct cil_netifcon));
	char *netif = (char*)parse_current->next->data;
	
	rc = cil_symtab_insert(&db->netif, (hashtab_key_t)netif, (struct cil_symtab_datum*)netifcon, ast_node);
	if (rc != SEPOL_OK) {
		printf("failed to insert network interface %s into symtab, rc: %d\n", netif, rc);
		return SEPOL_ERR;
	}

	if (parse_current->next->next->cl_head == NULL) {
		netifcon->if_context_str = cil_strdup(parse_current->next->next->data);
	}
	else {
		netifcon->if_context = cil_malloc(sizeof(struct cil_context));
		rc = cil_fill_context(parse_current->next->next->cl_head, netifcon->if_context);
		if (rc != SEPOL_OK) {
			printf("Failed to fill interface context\n");
			goto gen_netifcon_cleanup;
		}
	}

	if (parse_current->next->next->next->cl_head == NULL ) {
		netifcon->packet_context_str = cil_strdup(parse_current->next->next->next->data);
	}
	else {
		netifcon->packet_context = cil_malloc(sizeof(struct cil_context));
		rc = cil_fill_context(parse_current->next->next->next->cl_head, netifcon->packet_context);
		if (rc != SEPOL_OK) {
			printf("Failed to fill packet context\n");
			goto gen_netifcon_cleanup;
		}
	}

	ast_node->data = netifcon;
	ast_node->flavor = CIL_NETIFCON; 

	return SEPOL_OK;

	gen_netifcon_cleanup:
		cil_destroy_netifcon(netifcon);
		return SEPOL_ERR;
}

void cil_destroy_netifcon(struct cil_netifcon *netifcon)
{
	cil_symtab_datum_destroy(netifcon->datum);
	if (netifcon->if_context_str != NULL)
		free(netifcon->if_context_str);
	else if (netifcon->if_context != NULL)
		cil_destroy_context(netifcon->if_context);
	if (netifcon->packet_context_str != NULL)
		free(netifcon->packet_context_str);
	else if (netifcon->packet_context != NULL)
		cil_destroy_context(netifcon->packet_context);
}

int cil_build_ast(struct cil_db *db, struct cil_tree_node *parse_tree, struct cil_tree_node *ast)
{
	if (db == NULL || parse_tree == NULL || ast == NULL)
		return SEPOL_ERR;

	int rc = SEPOL_ERR;
	int reverse = 0;
	int forced = 0;
	struct cil_tree_node *parse_current = parse_tree;
	struct cil_tree_node *ast_current = ast;
	struct cil_tree_node *ast_node;

	do {
		if (parse_current->cl_head == NULL) {
			if (!reverse) {
				if (parse_current->parent->cl_head == parse_current) {
					rc = cil_tree_node_init(&ast_node);
					if (rc != SEPOL_OK) {
						printf("Failed to init tree node, rc: %d\n", rc);
						return rc;
					}
					ast_node->parent = ast_current;
					ast_node->line = parse_current->line;
	
					if (ast_current->cl_head == NULL)
						ast_current->cl_head = ast_node;
					else
						ast_current->cl_tail->next = ast_node;
					ast_current->cl_tail = ast_node;
					ast_current = ast_node;
					
					// Determine data types and set those values here
					// printf("parse_current->data: %s\n", (char*)parse_current->data);
					if (!strcmp(parse_current->data, CIL_KEY_BLOCK)) {
						rc = cil_gen_block(db, parse_current, ast_node, 0, 0, NULL);
						if (rc != SEPOL_OK) {
							printf("cil_gen_block failed, rc: %d\n", rc);
							return rc;
						}
					}
					else if (!strcmp(parse_current->data, CIL_KEY_CLASS)) {
						rc = cil_gen_class(db, parse_current, ast_node);
						if (rc != SEPOL_OK) {
							printf("cil_gen_class failed, rc: %d\n", rc);
							return rc;
						}
						// To avoid parsing list of perms again
						forced = 1;
					}
					else if (!strcmp(parse_current->data, CIL_KEY_COMMON)) {
						rc = cil_gen_common(db, parse_current, ast_node);
						if (rc != SEPOL_OK) {
							printf("cil_gen_common failed, rc: %d\n", rc);
							return rc;
						}
						forced = 1;
					}
					else if (!strcmp(parse_current->data, CIL_KEY_SID)) {
						rc = cil_gen_sid(db, parse_current, ast_node);
						if (rc != SEPOL_OK) {
							printf("cil_gen_sid failed, rc: %d\n", rc);
							return rc;
						}
						forced = 1;
					}
					else if (!strcmp(parse_current->data, CIL_KEY_USER)) {
						rc = cil_gen_user(db, parse_current, ast_node);
						if (rc != SEPOL_OK) {
							printf("cil_gen_user failed, rc: %d\n", rc);
							return rc;
						}
					}
					else if (!strcmp(parse_current->data, CIL_KEY_TYPE)) {
						rc = cil_gen_type(db, parse_current, ast_node, CIL_TYPE);
						if (rc != SEPOL_OK) {
							printf("cil_gen_type failed, rc: %d\n", rc);
							return rc;
						}
					}
					else if (!strcmp(parse_current->data, CIL_KEY_ATTR)) {
						rc = cil_gen_type(db, parse_current, ast_node, CIL_ATTR);
						if (rc != SEPOL_OK) {
							printf("cil_gen_type (attr) failed, rc: %d\n", rc);
							return rc;
						}
					}
					else if (!strcmp(parse_current->data, CIL_KEY_TYPEATTR)) {
						rc = cil_gen_typeattr(db, parse_current, ast_node);
						if (rc != SEPOL_OK) {
							printf("cil_gen_typeattr failed, rc: %d\n", rc);
							return rc;
						}
					}
					else if (!strcmp(parse_current->data, CIL_KEY_TYPEALIAS)) {
						rc = cil_gen_typealias(db, parse_current, ast_node);
						if (rc != SEPOL_OK) {
							printf("cil_gen_typealias failed, rc: %d\n", rc);
								return rc;
						}
					}
					else if (!strcmp(parse_current->data, CIL_KEY_ROLE)) {
						rc = cil_gen_role(db, parse_current, ast_node);
						if (rc != SEPOL_OK) {
							printf("cil_gen_role failed, rc: %d\n", rc);
							return rc;
						}
					}
					else if (!strcmp(parse_current->data, CIL_KEY_USERROLE)) {
						rc = cil_gen_userrole(db, parse_current, ast_node);
						if (rc != SEPOL_OK) {
							printf("cil_gen_userrole failed, rc: %d\n", rc);
							return rc;
						}
					}
					else if (!strcmp(parse_current->data, CIL_KEY_ROLETYPE)) {
						rc = cil_gen_roletype(db, parse_current, ast_node);
						if (rc != SEPOL_OK) {
							printf("cil_gen_roletype failed, rc: %d\n", rc);
							return rc;
						}
					}
					else if (!strcmp(parse_current->data, CIL_KEY_ROLETRANS)) {
						rc = cil_gen_roletrans(parse_current, ast_node);
						if (rc != SEPOL_OK) {
							printf("cil_gen_roletrans failed, rc: %d\n", rc);
							return rc;
						}
					}
					else if (!strcmp(parse_current->data, CIL_KEY_ROLEALLOW)) {
						rc = cil_gen_roleallow(db, parse_current, ast_node);
						if (rc != SEPOL_OK) {
							printf("cil_gen_roleallow failed, rc: %d\n", rc);
							return rc;
						}
					}
					else if (!strcmp(parse_current->data, CIL_KEY_BOOL)) {
						rc = cil_gen_bool(db, parse_current, ast_node);
						if (rc != SEPOL_OK) {
							printf("cil_gen_bool failed, rc: %d\n", rc);
							return rc;
						}
					}
					else if (!strcmp(parse_current->data, CIL_KEY_ALLOW)) {
						rc = cil_gen_avrule(parse_current, ast_node, CIL_AVRULE_ALLOWED); 
						if (rc != SEPOL_OK) {
							printf("cil_gen_avrule (allow) failed, rc: %d\n", rc);
							return rc;
						}
						// So that the object and perms lists do not get parsed again
						forced = 1;
					}
					else if (!strcmp(parse_current->data, CIL_KEY_AUDITALLOW)) {
						rc = cil_gen_avrule(parse_current, ast_node, CIL_AVRULE_AUDITALLOW);
						if (rc != SEPOL_OK) {
							printf("cil_gen_avrule (auditallow) failed, rc: %d\n", rc);
						}
						forced = 1;
					}
					else if (!strcmp(parse_current->data, CIL_KEY_DONTAUDIT)) {
						rc = cil_gen_avrule(parse_current, ast_node, CIL_AVRULE_DONTAUDIT);
						if (rc != SEPOL_OK) {
							printf("cil_gen_avrule (dontaudit) failed, rc: %d\n", rc);
						}
						forced = 1;
					}
					else if (!strcmp(parse_current->data, CIL_KEY_NEVERALLOW)) {
						rc = cil_gen_avrule(parse_current, ast_node, CIL_AVRULE_NEVERALLOW);
						if (rc != SEPOL_OK) {
							printf("cil_gen_avrule (neverallow) failed, rc: %d\n", rc);
							return rc;
						}
						forced = 1;
					}
					else if (!strcmp(parse_current->data, CIL_KEY_TYPETRANS)) {
						rc = cil_gen_type_rule(parse_current, ast_node, CIL_TYPE_TRANSITION);
						if (rc != SEPOL_OK) {
							printf("cil_gen_type_rule (typetransition) failed, rc: %d\n", rc);
							return rc;
						}
					}
					else if (!strcmp(parse_current->data, CIL_KEY_TYPECHANGE)) {
						rc = cil_gen_type_rule(parse_current, ast_node, CIL_TYPE_CHANGE);
						if (rc != SEPOL_OK) {
							printf("cil_gen_type_rule (typechange) failed, rc: %d\n", rc);
							return rc;
						}
					}
					else if (!strcmp(parse_current->data, CIL_KEY_TYPEMEMBER)) {
						rc = cil_gen_type_rule(parse_current, ast_node, CIL_TYPE_MEMBER);
						if (rc != SEPOL_OK) {
							printf("cil_gen_type_rule (typemember) failed, rc: %d\n", rc);
							return rc;
						}
					}
					else if (!strcmp(parse_current->data, CIL_KEY_INTERFACE)) {
						printf("new interface: %s\n", (char*)parse_current->next->data);
						ast_node->flavor = CIL_TRANS_IF;
					}
					else if (!strcmp(parse_current->data, CIL_KEY_SENSITIVITY)) {
						rc = cil_gen_sensitivity(db, parse_current, ast_node);
						if (rc != SEPOL_OK) {
							printf("cil_gen_sensitivity (sensitivity) failed, rc: %d\n", rc);
							return rc;
						}
					}
					else if (!strcmp(parse_current->data, CIL_KEY_SENSALIAS)) {
						rc = cil_gen_sensalias(db, parse_current, ast_node);
						if (rc != SEPOL_OK) {
							printf("cil_gen_sensalias (sensitivityalias) failed, rc: %d\n", rc);
							return rc;
						}
					}
					else if (!strcmp(parse_current->data, CIL_KEY_CATEGORY)) {
						rc = cil_gen_category(db, parse_current, ast_node);
						if (rc != SEPOL_OK) {
							printf("cil_gen_category (category) failed, rc: %d\n", rc);
							return rc;
						}
					}
					else if (!strcmp(parse_current->data, CIL_KEY_CATALIAS)) {
						rc = cil_gen_catalias(db, parse_current, ast_node);
						if (rc != SEPOL_OK) {
							printf("cil_gen_catalias (categoryalias) failed, rc: %d\n", rc);
							return rc;
						}
					}
					else if (!strcmp(parse_current->data, CIL_KEY_CATSET)) {
						rc = cil_gen_catset(db, parse_current, ast_node);
						if (rc != SEPOL_OK) {
							printf("cil_gen_catset (categoryset) failed, rc: %d\n", rc);
							return rc;
						}
						forced = 1;
					}
					else if (!strcmp(parse_current->data, CIL_KEY_CATORDER)) {
						rc = cil_gen_catorder(db, parse_current, ast_node);
						if (rc != SEPOL_OK) {
							printf("cil_gen_catorder failed, rc: %d\n", rc);
							return rc;
						}
						forced = 1;
					}
					else if (!strcmp(parse_current->data, CIL_KEY_SENSCAT)) {
						rc = cil_gen_senscat(db, parse_current, ast_node);
						if (rc != SEPOL_OK) {
							printf("cil_gen_senscat failed, rc: %d\n", rc);
							return rc;
						}
						forced = 1;
					}
					else if (!strcmp(parse_current->data, CIL_KEY_LEVEL)) {
						rc = cil_gen_level(db, parse_current, ast_node);
						if (rc != SEPOL_OK) {
							printf("cil_gen_level failed, rc: %d\n", rc);
							return rc;
						}
						forced = 1;
					}
					else if (!strcmp(parse_current->data, CIL_KEY_MLSCONSTRAIN)) {
						rc = cil_gen_mlsconstrain(db, parse_current, ast_node);
						if (rc != SEPOL_OK) {
							printf("cil_gen_mlsconstrain failed, rc: %d\n", rc);
							return rc;
						}
						forced = 1;
					}

					else if (!strcmp(parse_current->data, CIL_KEY_CONTEXT)) {
						rc = cil_gen_context(db, parse_current, ast_node);
						if (rc != SEPOL_OK) {
							printf("cil_gen_context failed, rc: %d\n", rc);
							return rc;
						}
						forced = 1;
					}
					else if (!strcmp(parse_current->data, CIL_KEY_NETIFCON)) {
						rc = cil_gen_netifcon(db, parse_current, ast_node);
						if (rc != SEPOL_OK) {
							printf("cil_gen_netifcon failed, rc: %d\n", rc);
							return rc;
						}
						forced = 1;
					}
				}
			}
		}

		if (parse_current->cl_head != NULL && !reverse) {
			parse_current = parse_current->cl_head;
		}
		else if (parse_current->next != NULL && reverse) {
			parse_current = parse_current->next;
			reverse = 0;
		}
		else if (parse_current->next != NULL && !forced) {
			parse_current = parse_current->next;
		}
		else {
			ast_current = ast_current->parent;
			parse_current = parse_current->parent;
			reverse = 1;
			forced = 0;
		}
	} while (parse_current->flavor != CIL_ROOT);

	return SEPOL_OK;
}


