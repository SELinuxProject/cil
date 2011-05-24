#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "cil.h"
#include "cil_mem.h"
#include "cil_tree.h"
#include "cil_list.h"
#include "cil_parser.h"
#include "cil_build_ast.h"
#include "cil_copy_ast.h"

int cil_gen_node(struct cil_db *db, struct cil_tree_node *ast_node, struct cil_symtab_datum *datum, hashtab_key_t key, uint32_t sflavor, uint32_t nflavor)
{
	symtab_t *symtab = NULL;
	int rc = SEPOL_ERR;

	rc = cil_get_parent_symtab(db, ast_node, &symtab, sflavor);
	if (rc != SEPOL_OK) 
		return rc;

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, datum, ast_node);
	if (rc != SEPOL_OK) {
		printf("Failed to insert %s into symtab, rc: %d\n", key, rc);
		return rc;
	}

	ast_node->data = datum;
	ast_node->flavor = nflavor;

	return SEPOL_OK;
}

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
		if (current_perm->cl_head != NULL) {
			printf("Invalid permission declaration\n");
			return SEPOL_ERR;
		}
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

int cil_gen_block(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node, uint16_t is_abstract, char *condition)
{
	if (db == NULL || parse_current == NULL || ast_node == NULL)
		return SEPOL_ERR;

	if (parse_current->next == NULL || parse_current->next->cl_head != NULL) {
		printf("Invalid block declaration (line: %d)\n", parse_current->line);
		return SEPOL_ERR;
	}

	char *name;
	struct cil_block *block;
	int rc = cil_block_init(&block);
	if (rc != SEPOL_OK) {
		return rc;
	}

	block->is_abstract = is_abstract;
	block->condition = condition;

	name = (char *)parse_current->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)block, (hashtab_key_t)name, CIL_SYM_BLOCKS, CIL_BLOCK);
	if (rc != SEPOL_OK) 
		goto gen_block_cleanup;

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
	if (db == NULL || parse_current == NULL || ast_node == NULL)
		return SEPOL_ERR;

	if (parse_current->next == NULL || parse_current->next->cl_head != NULL
	|| parse_current->next->next == NULL || parse_current->next->next->cl_head == NULL
	|| parse_current->next->next->next != NULL) {
		goto failed_decl;	
	}

	char *key = parse_current->next->data;
	struct cil_class *cls;
	int rc = cil_class_init(&cls);
	if (rc != SEPOL_OK) {
		return rc;
	}

	struct cil_tree_node *perms;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)cls, (hashtab_key_t)key, CIL_SYM_CLASSES, CIL_CLASS);
	if (rc != SEPOL_OK) 
		goto gen_class_cleanup;

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

	struct cil_perm *perm;
	int rc = cil_perm_init(&perm);
	if (rc != SEPOL_OK) {
		return rc;
	}

	char *key = (char*)parse_current->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)perm, (hashtab_key_t)key, CIL_SYM_UNKNOWN, CIL_PERM);
	if (rc != SEPOL_OK) 
		goto gen_perm_cleanup;

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

	char *key = parse_current->next->data;
	struct cil_common *common;
	int rc = cil_common_init(&common);
	if (rc != SEPOL_OK) {
		return rc;
	}

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)common, (hashtab_key_t)key, CIL_SYM_COMMONS, CIL_COMMON);
	if (rc != SEPOL_OK) 
		goto gen_common_cleanup;

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

int cil_gen_classcommon(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	if (db == NULL || parse_current == NULL || ast_node == NULL)
		return SEPOL_ERR;

	if (parse_current->next == NULL || parse_current->next->next == NULL
	|| parse_current->next->next->next != NULL) {
		printf("Invalid classcommon declaration (line: %d)\n", parse_current->line);
		return SEPOL_ERR;
	}

	struct cil_classcommon *clscom;
	int rc = cil_classcommon_init(&clscom);
	if (rc != SEPOL_OK) {
		return rc;
	}

	clscom->class_str = cil_strdup(parse_current->next->data);
	clscom->common_str = cil_strdup(parse_current->next->next->data);

	ast_node->data = clscom;
	ast_node->flavor = CIL_CLASSCOMMON;
	
	return SEPOL_OK;

}

void cil_destroy_classcommon(struct cil_classcommon *clscom)
{
	if (clscom->class_str != NULL)
		free(clscom->class_str);
	if (clscom->common_str != NULL)
		free(clscom->common_str);		
	free(clscom);
}

int cil_gen_sid(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		return SEPOL_ERR;
	}

	if (parse_current->next == NULL  || parse_current->next->cl_head != NULL
	|| parse_current->next->next != NULL) {
		printf("Invalid sid declaration (line: %d)\n", parse_current->line);
		return SEPOL_ERR;
	}

	struct cil_sid *sid;
	int rc = cil_sid_init(&sid);
	if (rc != SEPOL_OK) {
		return rc;
	}

	char *key = parse_current->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)sid, (hashtab_key_t)key, CIL_SYM_SIDS, CIL_SID);
	if (rc != SEPOL_OK) 
		goto gen_sid_cleanup;

	return SEPOL_OK;

	gen_sid_cleanup:
		cil_destroy_sid(sid);
		return rc;
}

void cil_destroy_sid(struct cil_sid *sid)
{
	cil_symtab_datum_destroy(sid->datum);
	free(sid);
}

int cil_gen_sidcontext(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		return SEPOL_ERR;
	}

	struct cil_sidcontext *sidcon;
	int rc = cil_sidcontext_init(&sidcon);
	if (rc != SEPOL_OK) {
		return rc;
	}

	if (parse_current->next == NULL || parse_current->next->next == NULL
	|| parse_current->next->next->next != NULL) {
		printf("Invalid sidcontext declaration (line: %d)\n", parse_current->line);
		return SEPOL_ERR;
	}

	sidcon->sid_str = cil_strdup(parse_current->next->data);

	if (parse_current->next->next->cl_head == NULL) 
		sidcon->context_str = cil_strdup(parse_current->next->next->data);
	else {
		rc = cil_context_init(&sidcon->context);
		if (rc != SEPOL_OK) {
			printf("Failed to init context\n");	
			goto gen_sidcontext_cleanup;
		}

		rc = cil_fill_context(parse_current->next->next->cl_head, sidcon->context);
		if (rc != SEPOL_OK) {
			printf("Failed to fill sid context\n");
			goto gen_sidcontext_cleanup;
		}
	}

	ast_node->data = sidcon;
	ast_node->flavor = CIL_SIDCONTEXT;

	return SEPOL_OK;

	gen_sidcontext_cleanup:
		cil_destroy_sidcontext(sidcon);
		return rc;
	
}

void cil_destroy_sidcontext(struct cil_sidcontext *sidcon)
{
	if (sidcon->sid_str != NULL)
		free(sidcon->sid_str);
	if (sidcon->context_str != NULL)
		free(sidcon->context_str);
	else if (sidcon->context != NULL && sidcon->context->datum.name == NULL)
		cil_destroy_context(sidcon->context);
	free(sidcon);
}

int cil_gen_user(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	if (db == NULL || parse_current == NULL || ast_node == NULL)
		return SEPOL_ERR;

	if (parse_current->next == NULL || parse_current->next->next != NULL) {
		printf("Invalid user declaration (line: %d)\n", parse_current->line);
		return SEPOL_ERR;
	}

	struct cil_user *user;
	int rc = cil_user_init(&user);
	if (rc != SEPOL_OK) {
		return rc;
	}

	char *key = parse_current->next->data;
	
	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)user, (hashtab_key_t)key, CIL_SYM_USERS, CIL_USER);
	if (rc != SEPOL_OK) 
		goto gen_user_cleanup;
	
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

	struct cil_role *role;
	int rc = cil_role_init(&role);	
	if (rc != SEPOL_OK) {
		return rc;
	}

	char *key = parse_current->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)role, (hashtab_key_t)key, CIL_SYM_ROLES, CIL_ROLE);
	if (rc != SEPOL_OK) 
		goto gen_role_cleanup;
	
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
	
	struct cil_roletype *roletype;
	int rc = cil_roletype_init(&roletype);
	if (rc != SEPOL_OK) {
		return rc;
	}

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

	struct cil_userrole *userrole;
	int rc = cil_userrole_init(&userrole);
	if (rc != SEPOL_OK) {
		return rc;
	}

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

	struct cil_role_trans *roletrans;
	int rc = cil_role_trans_init(&roletrans);
	if (rc != SEPOL_OK) {
		return rc;
	}

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

	struct cil_role_allow *roleallow;
	int rc = cil_role_allow_init(&roleallow);
	if (rc != SEPOL_OK) {
		return rc;
	}

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

int cil_gen_roledominance(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		return SEPOL_ERR;
	}

	if (parse_current->next == NULL || parse_current->next->next == NULL) {
		printf("Invalid roledominance declaration (line: %d)\n", parse_current->line);
		return SEPOL_ERR;
	}

	struct cil_roledominance *roledom;
	int rc = cil_roledominance_init(&roledom);
	if (rc != SEPOL_OK) {
		return rc;
	}

	roledom->role_str = cil_strdup(parse_current->next->data);
	roledom->domed_str = cil_strdup(parse_current->next->next->data);

	ast_node->data = roledom;
	ast_node->flavor = CIL_ROLEDOMINANCE;

	return SEPOL_OK;
}

void cil_destroy_roledominance(struct cil_roledominance *roledom)
{
	if (roledom->role_str != NULL)
		free(roledom->role_str);
	if (roledom->domed_str != NULL)
		free(roledom->domed_str);
	free(roledom);
}

int cil_gen_avrule(struct cil_tree_node *parse_current, struct cil_tree_node *ast_node, uint32_t rule_kind)
{
	if (parse_current == NULL || ast_node == NULL)
		return SEPOL_ERR;
	
	if (parse_current->next == NULL || 
	parse_current->next->cl_head != NULL ||
	parse_current->next->next == NULL || 
	parse_current->next->next->cl_head != NULL || 
	parse_current->next->next->next == NULL || 
	parse_current->next->next->next->cl_head != NULL || 
	parse_current->next->next->next->next == NULL || 
	parse_current->next->next->next->next->cl_head == NULL || 
	parse_current->next->next->next->next->next != NULL) {
		printf("Invalid allow rule (line: %d)\n", parse_current->line);
		return SEPOL_ERR;
	}
	
	struct cil_avrule *rule;
	int rc = cil_avrule_init(&rule);
	if (rc != SEPOL_OK) {
		return rc;
	}

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
	
	struct cil_type_rule *rule;
	int rc = cil_type_rule_init(&rule);
	if (rc != SEPOL_OK) {
		return rc;
	}

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
		else {
			printf("Error while handling unknown declaration (line %d)\n", parse_current->line);
			return SEPOL_ERR;
		}
	}

	char *key = (char*)parse_current->next->data; 
	struct cil_type *type;
	int rc = cil_type_init(&type);
	if (rc != SEPOL_OK) {
		return rc;
	}

	if (flavor == CIL_TYPE || flavor == CIL_ATTR) 
		rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)type, (hashtab_key_t)key, CIL_SYM_TYPES, CIL_TYPE);
	else {
		printf("Error: cil_gen_type called on invalid node\n");
		rc = SEPOL_ERR;
		goto gen_type_cleanup;
	}

	if (rc != SEPOL_OK) {
		printf("Failed to insert %s (line: %d), rc:%d\n", key, parse_current->line, rc);
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

int cil_gen_bool(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node, uint32_t flavor)
{
	if (db == NULL || parse_current == NULL || ast_node == NULL)
		return SEPOL_ERR;

	if (parse_current->next == NULL || parse_current->next->next == NULL || parse_current->next->next->next != NULL) {
		printf("Invalid boolean declaration (line: %d)\n", parse_current->line);
		return SEPOL_ERR;
	}

	struct cil_bool *boolean;
	int rc = cil_bool_init(&boolean);
	if (rc != SEPOL_OK) {
		return rc;
	}

	char *key = parse_current->next->data;

	if (!strcmp(parse_current->next->next->data, "true"))
		boolean->value = CIL_TRUE;
	else if (!strcmp(parse_current->next->next->data, "false"))
		boolean->value = CIL_FALSE;
	else {
		printf("Error: value must be \'true\' or \'false\'");
		rc = SEPOL_ERR;	
		goto gen_bool_cleanup;
	}

	if (flavor == CIL_BOOL)	
		rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)boolean, (hashtab_key_t)key, CIL_SYM_BOOLS, CIL_BOOL);
	else
		rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)boolean, (hashtab_key_t)key, CIL_SYM_TUNABLES, CIL_TUNABLE);
	if (rc != SEPOL_OK) 
		goto gen_bool_cleanup;
	
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

int cil_gen_expr_stack(struct cil_tree_node *current, uint32_t flavor, struct cil_tree_node **stack)
{
	if (current == NULL || stack == NULL) 
		return SEPOL_ERR;

	uint32_t rc = SEPOL_ERR;

	if (current->cl_head == NULL) {
		struct cil_tree_node *new = NULL;
		cil_tree_node_init(&new);
		struct cil_conditional *cond;
		rc = cil_conditional_init(&cond);
		if (rc != SEPOL_OK)
			return rc;

		if (current == current->parent->cl_head) {	
			if (!strcmp((char*)current->data, CIL_KEY_AND))
				cond->flavor = CIL_AND;
			else if (!strcmp((char*)current->data, CIL_KEY_OR))
				cond->flavor = CIL_OR;
			else if (!strcmp((char*)current->data, CIL_KEY_XOR))
				cond->flavor = CIL_XOR;
			else if (!strcmp((char*)current->data, CIL_KEY_NOT))
				cond->flavor = CIL_NOT;
			else if (!strcmp((char*)current->data, CIL_KEY_EQ))
				cond->flavor = CIL_EQ;
			else if (!strcmp((char*)current->data, CIL_KEY_NEQ))
				cond->flavor = CIL_NEQ;
			else
				return SEPOL_ERR;

			if (cond->flavor == CIL_NOT) {
				if (current->next->next != NULL)
					return SEPOL_ERR;
			}
			else if (current->next == NULL || current->next->next == NULL || current->next->next->next != NULL)
				return SEPOL_ERR;
		}
		else {
			cond->flavor = flavor;
		}
		
		cond->str = cil_strdup(current->data);

		new->data = cond;
		new->flavor = CIL_COND;

		if (*stack != NULL) {
			(*stack)->parent = new;
			new->cl_head = *stack;
		}
		*stack = new;
	}

	if (current->cl_head != NULL) {
		if (current == current->parent->cl_head) {
			printf("Invalid booleanif expression\n");
			return SEPOL_ERR;
		}
		rc = cil_gen_expr_stack(current->cl_head, flavor, stack);
		if (rc != SEPOL_OK) 
			return SEPOL_ERR;
	}
	if (current->next != NULL) {
		rc = cil_gen_expr_stack(current->next, flavor, stack);
		if (rc != SEPOL_OK)
			return SEPOL_ERR;
	}

	return SEPOL_OK;
}

int cil_gen_boolif(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	if (db == NULL || parse_current == NULL || ast_node == NULL)
		return SEPOL_ERR;

	if (parse_current->next == NULL || parse_current->next->next == NULL) {
		printf("Invalid booleanif declaration (line:%d)\n", parse_current->line);
		return SEPOL_ERR;
	}

	int rc = SEPOL_ERR;
	struct cil_booleanif *bif;
	rc = cil_boolif_init(&bif);
	if (rc != SEPOL_OK)
		return rc;
	
	if (parse_current->next->cl_head == NULL) {
		if (parse_current->next->data == NULL) {
			printf("Invalid booleanif expression (line: %d)\n", parse_current->line);
			return SEPOL_ERR;
		}
		struct cil_conditional *cond;
		cil_conditional_init(&cond);
		cil_tree_node_init(&bif->expr_stack);
		bif->expr_stack->flavor = CIL_COND;
		cond->str = cil_strdup(parse_current->next->data);
		cond->flavor = CIL_BOOL;
		bif->expr_stack->data = cond;
	}
	else {
		rc = cil_gen_expr_stack(parse_current->next->cl_head, CIL_BOOL, &bif->expr_stack);
		if (rc != SEPOL_OK) {
			printf("cil_gen_boolif (line %d): failed to create expr tree, rc: %d\n", parse_current->line, rc);
			return rc;
		}
	}

	struct cil_tree_node *next = parse_current->next->next;
	cil_tree_subtree_destroy(parse_current->next);
	parse_current->next = next;

	ast_node->flavor = CIL_BOOLEANIF;
	ast_node->data = bif;
	
	return SEPOL_OK;
}

void cil_destroy_boolif(struct cil_booleanif *bif) 
{
	struct cil_tree_node *curr = NULL;
	struct cil_tree_node *next = NULL;
	if (bif->expr_stack != NULL) {
		curr = bif->expr_stack;
		while (curr != NULL) {
			if (curr->flavor == CIL_COND && curr->data != NULL) {
				if (((struct cil_conditional*)curr->data)->str != NULL) {
					free(((struct cil_conditional*)curr->data)->str);
					((struct cil_conditional*)curr->data)->str = NULL;
				}
			}
			next = curr->next;
			free(curr->data);
			free(curr);
			curr = next;
		}
	}
	free(bif);
}

void cil_destroy_conditional(struct cil_conditional *cond)
{
	if (cond->str != NULL)
		free(cond->str);
	free(cond);
}

int cil_gen_else(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	if (db == NULL || parse_current == NULL || ast_node == NULL)
		return SEPOL_ERR;

	if (ast_node->parent->flavor != CIL_BOOLEANIF) {
		printf("Invalid else statement: Not within booleanif\n");
		return SEPOL_ERR;
	}

	ast_node->flavor = CIL_ELSE;
	ast_node->data = "else";
	return SEPOL_OK;
}

int cil_gen_tunif(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	if (db == NULL || parse_current == NULL || ast_node == NULL)
		return SEPOL_ERR;

	if (parse_current->next == NULL || parse_current->next->next == NULL) {
		printf("Invalid tunableif declaration (line: %d)\n", parse_current->line);
		return SEPOL_ERR;
	}

	int rc = SEPOL_ERR;
	struct cil_tunableif *tif;
	rc = cil_tunif_init(&tif);
	if (rc != SEPOL_OK)
		return rc;

	if (parse_current->next->cl_head == NULL) {
		struct cil_conditional *cond;
		cil_conditional_init(&cond);
		cil_tree_node_init(&tif->expr_stack);
		tif->expr_stack->flavor = CIL_COND;
		cond->str = cil_strdup(parse_current->next->data);
		cond->flavor = CIL_TUNABLE;
		tif->expr_stack->data = cond;
	}
	else {
		rc = cil_gen_expr_stack(parse_current->next->cl_head, CIL_TUNABLE, &tif->expr_stack);
		if (rc != SEPOL_OK) {
			printf("cil_gen_tunif (line %d): failed to create expr tree, rc: %d\n", parse_current->line, rc);
			return rc;
		}
	}

	struct cil_tree_node *next = parse_current->next->next;
	cil_tree_subtree_destroy(parse_current->next);
	parse_current->next = next;

	ast_node->flavor = CIL_TUNABLEIF;
	ast_node->data = tif;
	
	return SEPOL_OK;
}

void cil_destroy_tunif(struct cil_tunableif *tif) 
{
	struct cil_tree_node *curr = NULL;
	struct cil_tree_node *next = NULL;
	if (tif->expr_stack != NULL) {
		curr = tif->expr_stack;
		while (curr != NULL) {
			if (curr->flavor == CIL_COND && curr->data != NULL) {
				if (((struct cil_conditional*)curr->data)->str != NULL) {
					free(((struct cil_conditional*)curr->data)->str);
					((struct cil_conditional*)curr->data)->str = NULL;
				}
			}
			next = curr->next;
			free(curr->data);
			free(curr);
			curr = next;
		}
	}

	cil_symtab_array_destroy(tif->symtab);

	free(tif);
}

int cil_gen_typealias(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	if (db == NULL || parse_current == NULL || ast_node == NULL)
		return SEPOL_ERR;

	if (parse_current->next == NULL || parse_current->next->next == NULL || parse_current->next->next->next != NULL) {
		printf("Invalid typealias declaration (line: %d)\n", parse_current->line);
		return SEPOL_ERR;
	}

	struct cil_typealias *alias;
	int rc = cil_typealias_init(&alias);
	if (rc != SEPOL_OK) {
		return rc;
	}

	char *key = parse_current->next->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)alias, (hashtab_key_t)key, CIL_SYM_TYPES, CIL_TYPEALIAS);
	if (rc != SEPOL_OK) 
		goto gen_typealias_cleanup;
	
	alias->type_str = cil_strdup(parse_current->next->data);
	
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

	struct cil_typeattribute *typeattr;
	int rc = cil_typeattribute_init(&typeattr);
	if (rc != SEPOL_OK) {
		return rc;
	}

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

int cil_gen_typebounds(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		return SEPOL_ERR;
	}

	if (parse_current->next == NULL || parse_current->next->next == NULL) {
		printf("Invalid typebounds declaration (line: %d)\n", parse_current->line);
		return SEPOL_ERR;
	}

	struct cil_typebounds *typebnds;
	int rc = cil_typebounds_init(&typebnds);
	if (rc != SEPOL_OK) {
		return rc;
	}

	typebnds->parent_str = cil_strdup(parse_current->next->data);
	typebnds->child_str = cil_strdup(parse_current->next->next->data);

	ast_node->data = typebnds;
	ast_node->flavor = CIL_TYPEBOUNDS;

	return SEPOL_OK;
}

void cil_destroy_typebounds(struct cil_typebounds *typebnds)
{
	if (typebnds->parent_str != NULL)
		free(typebnds->parent_str);
	if (typebnds->child_str != NULL)
		free(typebnds->child_str);
	free(typebnds);
}

int cil_gen_sensitivity(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	if (db == NULL || parse_current == NULL || ast_node == NULL)
		return SEPOL_ERR;

	if (parse_current->next == NULL || parse_current->next->next != NULL || parse_current->next->cl_head != NULL) {
		printf("Invalid sensitivity declaration (line: %d)\n", parse_current->line);
		return SEPOL_ERR;
	}

	struct cil_sens *sens;
	int rc = cil_sens_init(&sens);
	if (rc != SEPOL_OK) {
		return rc;
	}

	char *key = parse_current->next->data;
	
	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)sens, (hashtab_key_t)key, CIL_SYM_SENS, CIL_SENS);
	if (rc != SEPOL_OK)
		goto gen_sens_cleanup;
	
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

	if (parse_current->next == NULL || parse_current->next->next == NULL || parse_current->next->next->next != NULL \
	 || parse_current->next->cl_head != NULL || parse_current->next->next->cl_head != NULL ) {
		printf("Invalid sensitivityalias declaration (line: %d)\n", parse_current->line);
		return SEPOL_ERR;
	}

	struct cil_sensalias *alias;
	int rc = cil_sensalias_init(&alias);
	if (rc != SEPOL_OK) {
		return rc;
	}
	
	char *key = parse_current->next->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)alias, (hashtab_key_t)key, CIL_SYM_SENS, CIL_SENSALIAS);
	if (rc != SEPOL_OK)
		goto gen_sensalias_cleanup;
	
	alias->sens_str = cil_strdup(parse_current->next->data);

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

	struct cil_cat *cat;
	int rc = cil_cat_init(&cat);
	if (rc != SEPOL_OK) {
		return rc;
	}

	char *key = parse_current->next->data;
	
	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)cat, (hashtab_key_t)key, CIL_SYM_CATS, CIL_CAT);
	if (rc != SEPOL_OK)
		goto gen_cat_cleanup;
	
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

	struct cil_catalias *alias;
	int rc = cil_catalias_init(&alias);
	if (rc != SEPOL_OK) {
		return rc;
	}

	char *key = parse_current->next->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)alias, (hashtab_key_t)key, CIL_SYM_CATS, CIL_CATALIAS);
	if (rc != SEPOL_OK) 
		goto gen_catalias_cleanup;
	
	alias->cat_str = cil_strdup(parse_current->next->data);
	
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

int cil_set_to_list(struct cil_tree_node *parse_current, struct cil_list *ast_cl, uint8_t sublists)
{
	if (parse_current == NULL || ast_cl == NULL)
		return SEPOL_ERR;

	struct cil_list *sub_list;
	struct cil_list_item *new_item;
	struct cil_list_item *list_tail;
	struct cil_tree_node *curr = parse_current;
	int rc = SEPOL_ERR;
	
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
		else if (sublists) {
			cil_list_init(&sub_list);
			new_item->flavor = CIL_LIST;
			new_item->data = sub_list;
			rc = cil_set_to_list(curr, sub_list, sublists);
			if (rc != SEPOL_OK) {
				printf("Error while building sublist\n");
				return rc;
			}
		}
		else {
			printf("cil_set_to_list: invalid sublist\n");
			return SEPOL_ERR;
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

	if (parse_current->next == NULL || parse_current->next->next == NULL || 
	parse_current->next->cl_head != NULL || parse_current->next->next->next != NULL ||
	parse_current->next->next->cl_head == NULL) {
		printf("Invalid categoryset declaration (line: %d)\n", parse_current->line);
		return SEPOL_ERR;
	}

	char *key = parse_current->next->data;
	struct cil_catset *catset;
	int rc = cil_catset_init(&catset);
	if (rc != SEPOL_OK) {
		return rc;
	}

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)catset, (hashtab_key_t)key, CIL_SYM_CATS, CIL_CATSET);
	if (rc != SEPOL_OK) 
		goto gen_catset_cleanup;

	rc = cil_fill_catset(parse_current->next->next, catset);
	if (rc != SEPOL_OK) {
		printf("Failed to fill categoryset\n");
		goto gen_catset_cleanup;
	}

	return SEPOL_OK;

	gen_catset_cleanup:
		cil_destroy_catset(catset);
		return rc;	
}

int cil_fill_catset(struct cil_tree_node *start, struct cil_catset *catset)
{
	int rc = SEPOL_ERR;

	if (start == NULL || catset == NULL)
		return SEPOL_ERR;
	
	cil_list_init(&catset->cat_list_str);

	rc = cil_set_to_list(start, catset->cat_list_str, 1);
	if (rc != SEPOL_OK) {
		printf("Failed to create categoryset list\n");
		goto fill_catset_cleanup;
	}
	
	return SEPOL_OK;

	fill_catset_cleanup:
		if (catset->cat_list_str != NULL) {
			cil_list_destroy(&catset->cat_list_str, 1);
			catset->cat_list_str = NULL;
		}
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

	struct cil_catorder *catorder;
	int rc = cil_catorder_init(&catorder);
	if (rc != SEPOL_OK) {
		return rc;
	}
	cil_list_init(&catorder->cat_list_str);
	
	rc = cil_set_to_list(parse_current->next, catorder->cat_list_str, 0);
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

int cil_gen_dominance(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	if (db == NULL || parse_current == NULL || ast_node == NULL)
		return SEPOL_ERR;
	
	if (parse_current->next == NULL || parse_current->next->cl_head == NULL) {
		printf("Invalid dominance declaration (line %d)\n", parse_current->line);
		return SEPOL_ERR;
	}

	struct cil_sens_dominates *dom;
	int rc = cil_sens_dominates_init(&dom);
	if (rc != SEPOL_OK) {
		return rc;
	}
	cil_list_init(&dom->sens_list_str);
	
	rc = cil_set_to_list(parse_current->next, dom->sens_list_str, 0);
	if (rc != SEPOL_OK) {
		printf("Failed to create sensitivity list\n");
		goto gen_dominance_cleanup;
	}
	ast_node->data = dom;
	ast_node->flavor = CIL_DOMINANCE;

	return SEPOL_OK;

	gen_dominance_cleanup:
		cil_destroy_dominance(dom);
		return rc;
}

void cil_destroy_dominance(struct cil_sens_dominates *dom)
{
	if (dom->sens_list_str != NULL)
		cil_list_destroy(&dom->sens_list_str, 1);
	free(dom);
}

int cil_gen_senscat(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	if (db == NULL || parse_current == NULL || ast_node == NULL)
		return SEPOL_ERR;

	if (parse_current->next == NULL || parse_current->next->next->cl_head == NULL) {
		printf("Invalid sensitivitycategory declaration (line %d)\n", parse_current->line);
		return SEPOL_ERR;
	}

	struct cil_senscat *senscat;
	int rc = cil_senscat_init(&senscat);
	if (rc != SEPOL_OK) {
		return rc;
	}

	senscat->sens_str = cil_strdup(parse_current->next->data);

	cil_list_init(&senscat->cat_list_str);
	
	rc = cil_set_to_list(parse_current->next->next, senscat->cat_list_str, 1);
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

	if (sens->next->cl_head == NULL) {
		if (sens->next->data != NULL) {
			level->catset_str = cil_strdup(sens->next->data);
			return SEPOL_OK;
		}
		else
			return SEPOL_ERR;
	}

	cil_list_init(&level->cat_list_str);

	rc = cil_set_to_list(sens->next, level->cat_list_str, 1);
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

	if (parse_current->next == NULL || 
	parse_current->next->cl_head != NULL ||
	parse_current->next->next == NULL) {
		printf("Invalid level declaration (line: %d)\n", parse_current->line);
		return SEPOL_ERR;
	}

	char *key = parse_current->next->data;
	struct cil_level *level;
	int rc = cil_level_init(&level);
	if (rc != SEPOL_OK) {
		return rc;
	}

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)level, (hashtab_key_t)key, CIL_SYM_LEVELS, CIL_LEVEL);
	if (rc != SEPOL_OK) 
		goto gen_level_cleanup;
	
	rc = cil_fill_level(parse_current->next->next, level);
	if (rc != SEPOL_OK) {
		printf("Failed to populate level\n");
		goto gen_level_cleanup;
	}
	
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

int __cil_build_constrain_tree(struct cil_tree_node *parse_current, struct cil_tree_node *expr_root, uint32_t flavor)
{
	if (expr_root == NULL || parse_current == NULL)
		return SEPOL_ERR;

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
			new_node->flavor = CIL_CONSTRAIN_NODE;
			if (expr_curr->cl_head == NULL)
				expr_curr->cl_head = new_node;
			else
				expr_curr->cl_tail->next = new_node;
			expr_curr->cl_tail = new_node;
			if (curr->data != NULL) {
				if (strstr(CIL_CONSTRAIN_OPER, curr->data) != NULL)
					expr_curr = new_node;
				else if (flavor == CIL_CONSTRAIN && strstr(CIL_MLS_LEVELS, curr->data) != NULL)
					return SEPOL_ERR;
			}
			else 
				return SEPOL_ERR;
		}
		else {
			rc = __cil_build_constrain_tree(curr->cl_head, expr_curr, flavor);
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

void cil_destroy_constrain_node(struct cil_tree_node *cons_node)
{
	if (cons_node->data != NULL)
		free(cons_node->data);
	cons_node->data = NULL;
	cons_node->parent = NULL;
	free(cons_node);
}

int cil_gen_constrain(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node, uint32_t flavor)
{
	if (db == NULL || parse_current == NULL || ast_node == NULL)
		return SEPOL_ERR;
	
	if (parse_current->next == NULL || 
		parse_current->next->cl_head == NULL || 
		parse_current->next->next == NULL || 
		parse_current->next->next->cl_head == NULL || 
		parse_current->next->next->next == NULL || 
		parse_current->next->next->next->cl_head == NULL) {
		printf("Invalid constrain declaration (line: %d)\n", parse_current->line);
		return SEPOL_ERR;
	}

	struct cil_constrain *cons;
	int rc = cil_constrain_init(&cons);
	if (rc != SEPOL_OK) {
		return rc;
	}

	cil_list_init(&cons->class_list_str);
	cil_parse_to_list(parse_current->next->cl_head, cons->class_list_str, CIL_AST_STR);
	cil_list_init(&cons->perm_list_str);
	cil_parse_to_list(parse_current->next->next->cl_head, cons->perm_list_str, CIL_AST_STR);

	cil_tree_init(&cons->expr);
	rc = __cil_build_constrain_tree(parse_current->next->next->next->cl_head, cons->expr->root, flavor);
	if (rc != SEPOL_OK) {
		printf("Failed to build constrain expression tree\n");
		goto gen_constrain_cleanup;
	}

	ast_node->data = cons;
	ast_node->flavor = flavor;

	return SEPOL_OK;

	gen_constrain_cleanup:
		cil_destroy_constrain(cons);
		return rc;
		
}

void cil_destroy_constrain(struct cil_constrain *cons)
{
	if (cons->class_list_str != NULL)
		cil_list_destroy(&cons->class_list_str, 1);
	if (cons->class_list != NULL)
		cil_list_destroy(&cons->class_list, 0);
	if (cons->perm_list_str != NULL)
		cil_list_destroy(&cons->perm_list_str, 1);
	if (cons->perm_list != NULL)
		cil_list_destroy(&cons->perm_list, 0);
	if (cons->expr != NULL)
		cil_tree_destroy(&cons->expr);
	free(cons);
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
		rc = cil_level_init(&context->low);
		if (rc != SEPOL_OK) {
			printf("Couldn't initialize low level\n");
			goto cil_fill_context_cleanup;
		}

		rc = cil_fill_level(user_node->next->next->next->cl_head, context->low);
		if (rc != SEPOL_OK) {
			printf("cil_fill_context: Failed to fill low level, rc: %d\n", rc); 
			goto cil_fill_context_cleanup;
		}
	}

	if (user_node->next->next->next->next->cl_head == NULL)
		context->high_str = cil_strdup(user_node->next->next->next->next->data);
	else {
		rc = cil_level_init(&context->high);
		if (rc != SEPOL_OK) {
			printf("Couldn't initialize high level\n");
			goto cil_fill_context_cleanup;
		}

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

	if (parse_current->next == NULL || parse_current->next->next == NULL) {
		printf("Invalid context declaration (line: %d)\n", parse_current->line);
		return SEPOL_ERR;
	}

	struct cil_context *context;
	int rc = cil_context_init(&context);
	if (rc != SEPOL_OK) {
		return rc;
	}
	
	// Syntax for 'context' statements (named)
	if (parse_current->next->next->cl_head != NULL) {
		if (parse_current->next->next->next != NULL
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

		rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)context, (hashtab_key_t)key, CIL_SYM_CONTEXTS, CIL_CONTEXT);
		if (rc != SEPOL_OK) 
			goto gen_context_cleanup;
	
		rc = cil_fill_context(parse_current->next->next->cl_head, context);
		if (rc != SEPOL_OK) {
			printf("Failed to fill context, rc: %d\n", rc);
			goto gen_context_cleanup;
		}
	}
	else {
		printf("Invalid context declaration (line: %d)\n", parse_current->line);
		goto gen_context_cleanup;
	}
	
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

int cil_gen_filecon(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		return SEPOL_ERR;
	}

	if (parse_current->next == NULL
	|| parse_current->next->cl_head != NULL
	|| parse_current->next->next == NULL
	|| parse_current->next->next->cl_head != NULL
	|| parse_current->next->next->next == NULL
	|| parse_current->next->next->next->cl_head != NULL
	|| parse_current->next->next->next->next == NULL
	|| parse_current->next->next->next->next->next != NULL) {
		printf("Invalid filecon declaration (line: %d)\n", parse_current->line);
		return SEPOL_ERR;
	}

	struct cil_filecon *filecon;
	char *type = (char*)parse_current->next->next->next->data;
	int rc = cil_filecon_init(&filecon);
	if (rc != SEPOL_OK) {
		return rc;
	}

	filecon->root_str = cil_strdup(parse_current->next->data);
	filecon->path_str = cil_strdup(parse_current->next->next->data);

	if (!strcmp(type, "file")) {
		filecon->type = CIL_FILECON_FILE;
	}
	else if (!strcmp(type, "dir")) {
		filecon->type = CIL_FILECON_DIR;
	}
	else if (!strcmp(type, "char")) {
		filecon->type = CIL_FILECON_CHAR;
	}
	else if (!strcmp(type, "block")) {
		filecon->type = CIL_FILECON_BLOCK;
	}
	else if (!strcmp(type, "socket")) {
		filecon->type = CIL_FILECON_SOCKET;
	}
	else if (!strcmp(type, "pipe")) {
		filecon->type = CIL_FILECON_PIPE;
	}
	else if (!strcmp(type, "symlink")) {
		filecon->type = CIL_FILECON_SYMLINK;
	}
	else if (!strcmp(type, "any")) {
		filecon->type = CIL_FILECON_ANY;
	}
	else {
		printf("cil_gen_filecon: Invalid file type\n");
		return SEPOL_ERR;
	}
		
	if (parse_current->next->next->next->next->cl_head == NULL) {
		filecon->context_str = cil_strdup(parse_current->next->next->next->next->data);
	}
	else {
		rc = cil_context_init(&filecon->context);
		if (rc != SEPOL_OK) {
			printf("Failed to init file context\n");
			goto gen_filecon_cleanup;
		}

		rc = cil_fill_context(parse_current->next->next->next->next->cl_head, filecon->context);
		if (rc != SEPOL_OK) {
			printf("Failed to fill file context\n");
			goto gen_filecon_cleanup;
		}
	}

	ast_node->data = filecon;
	ast_node->flavor = CIL_FILECON; 

	return SEPOL_OK;

	gen_filecon_cleanup:
		cil_destroy_filecon(filecon);
		return SEPOL_ERR;
}

void cil_destroy_filecon(struct cil_filecon *filecon)
{
	if (filecon->root_str != NULL)
		free(filecon->root_str);
	if (filecon->path_str != NULL)
		free(filecon->path_str);
	if (filecon->context_str != NULL)
		free(filecon->context_str);
	else
		cil_destroy_context(filecon->context);
	free(filecon);
}

int cil_gen_portcon(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		return SEPOL_ERR;
	}

	if (parse_current->next == NULL
	|| parse_current->next->cl_head != NULL
	|| parse_current->next->next == NULL
	|| parse_current->next->next->next == NULL) {
		printf("Invalid portcon declaration (line: %d)\n", parse_current->line);
		return SEPOL_ERR;
	}

	struct cil_portcon *portcon;
	int rc = cil_portcon_init(&portcon);
	if (rc != SEPOL_OK) {
		return rc;
	}

	portcon->type_str = cil_strdup(parse_current->next->data);

	if (parse_current->next->next->cl_head != NULL) {
		if (parse_current->next->next->cl_head->next != NULL) {
			portcon->port_low = (uint32_t)atoi(parse_current->next->next->cl_head->data);
			portcon->port_high = (uint32_t)atoi(parse_current->next->next->cl_head->next->data);
		}
		else {
			printf("Error: Improper port range specified\n");
			return SEPOL_ERR;
		}
	}
	else {
		portcon->port_low = (uint32_t)atoi(parse_current->next->next->data);
		portcon->port_high = (uint32_t)atoi(parse_current->next->next->data);
	}

	if (parse_current->next->next->next->cl_head == NULL ) {
		portcon->context_str = cil_strdup(parse_current->next->next->next->data);
	}
	else {
		rc = cil_context_init(&portcon->context);
		if (rc != SEPOL_OK) {
			printf("Failed to init port context\n");
			goto gen_portcon_cleanup;
		}

		rc = cil_fill_context(parse_current->next->next->next->cl_head, portcon->context);
		if (rc != SEPOL_OK) {
			printf("Failed to fill port context\n");
			goto gen_portcon_cleanup;
		}
	}

	ast_node->data = portcon;
	ast_node->flavor = CIL_PORTCON; 

	return SEPOL_OK;

	gen_portcon_cleanup:
		cil_destroy_portcon(portcon);
		return SEPOL_ERR;
}

void cil_destroy_portcon(struct cil_portcon *portcon)
{
	if (portcon->type_str != NULL)
		free(portcon->type_str);
	if (portcon->context_str != NULL)
		free(portcon->context_str);
	else if (portcon->context != NULL)
		cil_destroy_context(portcon->context);
	free(portcon);
}

int cil_gen_nodecon(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		return SEPOL_ERR;
	}

	if (parse_current->next == NULL
	|| parse_current->next->cl_head != NULL
	|| parse_current->next->next == NULL
	|| parse_current->next->next->cl_head != NULL
	|| parse_current->next->next->next == NULL) {
		printf("Invalid nodecon declaration (line: %d)\n", parse_current->line);
		return SEPOL_ERR;
	}

	struct cil_nodecon *nodecon;
	int rc = cil_nodecon_init(&nodecon);
	if (rc != SEPOL_OK) {
		return rc;
	}

	nodecon->node_str = cil_strdup(parse_current->next->data);
	nodecon->netmask_str = cil_strdup(parse_current->next->next->data);


	if (parse_current->next->next->next->cl_head == NULL ) {
		nodecon->context_str = cil_strdup(parse_current->next->next->next->data);
	}
	else {
		rc = cil_context_init(&nodecon->context);
		if (rc != SEPOL_OK) {
			printf("Failed to init node context\n");
			goto gen_nodecon_cleanup;
		}

		rc = cil_fill_context(parse_current->next->next->next->cl_head, nodecon->context);
		if (rc != SEPOL_OK) {
			printf("Failed to fill node context\n");
			goto gen_nodecon_cleanup;
		}
	}

	ast_node->data = nodecon;
	ast_node->flavor = CIL_NODECON; 

	return SEPOL_OK;

	gen_nodecon_cleanup:
		cil_destroy_nodecon(nodecon);
		return SEPOL_ERR;
}

void cil_destroy_nodecon(struct cil_nodecon *nodecon)
{
	if (nodecon->node_str != NULL)
		free(nodecon->node_str);
	if (nodecon->netmask_str != NULL)
		free(nodecon->netmask_str);
	if (nodecon->context_str != NULL)
		free(nodecon->context_str);
	else if (nodecon->context != NULL)
		cil_destroy_context(nodecon->context);
	free(nodecon);
}

int cil_gen_genfscon(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		return SEPOL_ERR;
	}

	if (parse_current->next == NULL
	|| parse_current->next->cl_head != NULL
	|| parse_current->next->next == NULL
	|| parse_current->next->next->cl_head != NULL
	|| parse_current->next->next->next == NULL) {
		printf("Invalid genfscon declaration (line: %d)\n", parse_current->line);
		return SEPOL_ERR;
	}

	struct cil_genfscon *genfscon;
	int rc = cil_genfscon_init(&genfscon);
	if (rc != SEPOL_OK) {
		return rc;
	}

	genfscon->type_str = cil_strdup(parse_current->next->data);
	genfscon->path_str = cil_strdup(parse_current->next->next->data);

	if (parse_current->next->next->next->cl_head == NULL ) {
		genfscon->context_str = cil_strdup(parse_current->next->next->next->data);
	}
	else {
		rc = cil_context_init(&genfscon->context);
		if (rc != SEPOL_OK) {
			printf("Failed to init genfs context\n");
			goto gen_genfscon_cleanup;
		}

		rc = cil_fill_context(parse_current->next->next->next->cl_head, genfscon->context);
		if (rc != SEPOL_OK) {
			printf("Failed to fill genfs context\n");
			goto gen_genfscon_cleanup;
		}
	}

	ast_node->data = genfscon;
	ast_node->flavor = CIL_GENFSCON; 

	return SEPOL_OK;

	gen_genfscon_cleanup:
		cil_destroy_genfscon(genfscon);
		return SEPOL_ERR;
}

void cil_destroy_genfscon(struct cil_genfscon *genfscon)
{
	if (genfscon->type_str != NULL)
		free(genfscon->type_str);
	if (genfscon->path_str != NULL)
		free(genfscon->path_str);
	if (genfscon->context_str != NULL)
		free(genfscon->context_str);
	else if (genfscon->context != NULL)
		cil_destroy_context(genfscon->context);
	free(genfscon);
}


int cil_gen_netifcon(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	if (db == NULL || parse_current == NULL || ast_node == NULL)
		return SEPOL_ERR;

	if (parse_current->next == NULL
	|| parse_current->next->cl_head != NULL
	|| parse_current->next->next == NULL
	|| parse_current->next->next->next == NULL
	|| (parse_current->next->next->cl_head != NULL && parse_current->next->next->next->cl_head == NULL)
	|| (parse_current->next->next->cl_head == NULL && parse_current->next->next->next->cl_head != NULL)) {
		printf("Invalid netifcon declaration (line: %d)\n", parse_current->line);
		return SEPOL_ERR;
	}
	
	struct cil_netifcon *netifcon;
	int rc = cil_netifcon_init(&netifcon);
	if (rc != SEPOL_OK) {
		return rc;
	}
	
	char *name = (char*)parse_current->next->data;
	
	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)netifcon, (hashtab_key_t)name, CIL_SYM_NETIFCONS, CIL_NETIFCON);
	if (rc != SEPOL_OK)
		goto gen_netifcon_cleanup;

	if (parse_current->next->next->cl_head == NULL) {
		netifcon->if_context_str = cil_strdup(parse_current->next->next->data);
	}
	else {
		rc = cil_context_init(&netifcon->if_context);
		if (rc != SEPOL_OK) {
			printf("Failed to init if_context\n");	
			goto gen_netifcon_cleanup;	
		}

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
		rc = cil_context_init(&netifcon->packet_context);
		if (rc != SEPOL_OK) {
			printf("Failed to init packet_context\n");
			goto gen_netifcon_cleanup;
		}

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
	free(netifcon);
}

int cil_gen_macro(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	if (db == NULL || parse_current == NULL || ast_node == NULL)
		return SEPOL_ERR;

	if (parse_current->next == NULL || parse_current->next->next == NULL || parse_current->next->next->next == NULL){
		printf("Invalid macro declaration (line: %d)\n", parse_current->line);
		return SEPOL_ERR;
	}

	uint32_t flavor = 0;
	char *name = (char*)parse_current->next->data;
	struct cil_macro *macro;
	int rc = cil_macro_init(&macro);	
	if (rc != SEPOL_OK) {
		return rc;
	}

	if (parse_current->next->next->cl_head != NULL) {
		cil_list_init(&macro->params);
		struct cil_tree_node *current_item = parse_current->next->next->cl_head;
		struct cil_list_item *params_tail = NULL;
		while (current_item != NULL) {
			if (current_item->cl_head == NULL) {
				printf("Invalid macro declaration (line: %d)\n", parse_current->line);
				goto gen_macro_cleanup;
			}
			char *kind = current_item->cl_head->data;
			if (!strcmp(kind, CIL_KEY_TYPE)) {
				flavor = CIL_TYPE;
			}
			else if (!strcmp(kind, CIL_KEY_ROLE)) {
				flavor = CIL_ROLE;
			}
			else if (!strcmp(kind, CIL_KEY_USER)) {
				flavor = CIL_USER;
			}
			else if (!strcmp(kind, CIL_KEY_SENSITIVITY)) {
				flavor = CIL_SENS;
			}
			else if (!strcmp(kind, CIL_KEY_CATEGORY)) {
				flavor = CIL_CAT;
			}
			else if (!strcmp(kind, CIL_KEY_CATSET)) {
				flavor = CIL_CATSET;
			}
			else if (!strcmp(kind, CIL_KEY_LEVEL)) {
				flavor = CIL_LEVEL;
			}
			else if (!strcmp(kind, CIL_KEY_CLASS)) {
				flavor = CIL_CLASS;
			}
			//TODO permissionset and IP addresses
			else {
				printf("Invalid macro declaration (line: %d)\n", parse_current->line);
				goto gen_macro_cleanup;
			}

			char *param =  cil_strdup(current_item->cl_head->next->data);

			if (strchr(param, '.')) {
				printf("Invalid macro declaration: parameter names cannot contain a '.' (line: %d)\n", parse_current->line);
				goto gen_macro_cleanup;
			}

			if (params_tail == NULL) {
				cil_list_item_init(&macro->params->head);
				macro->params->head->data = param;
				macro->params->head->flavor = flavor;

				params_tail = macro->params->head;
			}			
			else {
				//walk current list and check for duplicate parameters
				struct cil_list_item *curr_param = macro->params->head;
				while (curr_param != NULL) {
					if (!strcmp(param, (char*)curr_param->data)) {
						if (flavor == curr_param->flavor) {
							printf("Invalid macro declaration (line: %d): Duplicate parameter\n", parse_current->line);
							goto gen_macro_cleanup;
						}
					}
					curr_param = curr_param->next;
				}

				cil_list_item_init(&params_tail->next);
				params_tail->next->data = param;
				params_tail->next->flavor = flavor;
				
				params_tail = params_tail->next;
				params_tail->next = NULL;
			}

			current_item = current_item->next;
		}
	}

	struct cil_tree_node *next = parse_current->next->next->next;
	cil_tree_subtree_destroy(parse_current->next->next);
	parse_current->next->next = next;
	
	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)macro, (hashtab_key_t)name, CIL_SYM_MACROS, CIL_MACRO);
	if (rc != SEPOL_OK)
		goto gen_macro_cleanup;


	ast_node->data = macro;
	ast_node->flavor = CIL_MACRO; 

	return SEPOL_OK;

	gen_macro_cleanup:
		cil_destroy_macro(macro);
		return SEPOL_ERR;
}

void cil_destroy_macro(struct cil_macro *macro)
{
	cil_symtab_datum_destroy(macro->datum);
	cil_symtab_array_destroy(macro->symtab);
	cil_list_destroy(&macro->params, 1);
	free(macro);
}

int cil_gen_call(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	if (db == NULL || parse_current == NULL || ast_node == NULL)
		return SEPOL_ERR;

	if (parse_current->next == NULL || (parse_current->next->next != NULL && parse_current->next->next->cl_head == NULL)) {
		printf("Invalid call declaration (line: %d)\n", parse_current->line);
		return SEPOL_ERR;
	}

	struct cil_call *call;
	int rc = cil_call_init(&call);
	if (rc != SEPOL_OK) {
		return rc;
	}

	call->macro_str = cil_strdup(parse_current->next->data);

	cil_tree_init(&call->args_tree);
	cil_tree_node_init(&call->args_tree->root);
	
	cil_copy_ast(db, parse_current->next->next, call->args_tree->root); 

	ast_node->data = call;
	ast_node->flavor = CIL_CALL;

	return SEPOL_OK;
}

void cil_destroy_call(struct cil_call *call)
{
	if (call->macro_str != NULL)
		free(call->macro_str);
	call->macro = NULL;
	if (call->args_tree != NULL)
		cil_tree_destroy(&call->args_tree);
	if (call->args != NULL)
		cil_list_destroy(&call->args, 1);
}

int cil_gen_optional(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	if (db == NULL || parse_current == NULL || ast_node == NULL)
		return SEPOL_ERR;

	if (parse_current->next == NULL || parse_current->next->cl_head != NULL) {
		printf("Invalid optional declaration (line: %d)\n", parse_current->line);
		return SEPOL_ERR;
	}

	char *name;
	struct cil_optional *optional;
	int rc = cil_optional_init(&optional);
	if (rc != SEPOL_OK) {
		return rc;
	}
	
	name = (char *)parse_current->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)optional, (hashtab_key_t)name, CIL_SYM_OPTIONALS, CIL_OPTIONAL);
	if (rc != SEPOL_OK) 
		goto gen_optional_cleanup;

	return SEPOL_OK;

	gen_optional_cleanup:	
		cil_destroy_optional(optional);
		return rc;

}

void cil_destroy_optional(struct cil_optional *optional)
{
	cil_symtab_datum_destroy(optional->datum);
	free(optional);
}

void cil_destroy_args(struct cil_args *args)
{
	if (args->arg_str != NULL)
		free(args->arg_str);
	args->param_str = NULL;
	if (((struct cil_symtab_datum*)args->arg)->name == NULL)
		switch (((struct cil_symtab_datum*)args->arg)->node->flavor) {
		case CIL_LEVEL : 
			cil_destroy_level((struct cil_level*)args->arg);
			args->arg = NULL;
			break;
		case CIL_CATSET : 
			cil_destroy_catset((struct cil_catset*)args->arg);
			args->arg = NULL;
			break;
		} 
}

int cil_gen_policycap(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	if (db == NULL || parse_current == NULL || ast_node == NULL)
		return SEPOL_ERR;

	if (parse_current->next == NULL || parse_current->next->next != NULL || parse_current->next->cl_head != NULL) {
		printf("Invalid policycap declaration (line: %d)\n", parse_current->line);
		return SEPOL_ERR;
	}

	struct cil_policycap *polcap;
	int rc = cil_policycap_init(&polcap);
	if (rc != SEPOL_OK) {
		return rc;
	}
	char *key = parse_current->next->data;
	
	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)polcap, (hashtab_key_t)key, CIL_SYM_POLICYCAPS, CIL_POLICYCAP);
	if (rc != SEPOL_OK)
		goto gen_polcap_cleanup;
	
	return SEPOL_OK;

	gen_polcap_cleanup:
		cil_destroy_policycap(polcap);
		return rc;
}

void cil_destroy_policycap(struct cil_policycap *polcap)
{
	cil_symtab_datum_destroy(polcap->datum);
	free(polcap);
}

/* other is a list of 2 items. head should be ast_current, head->next should be db */
int __cil_build_ast_node_helper(struct cil_tree_node *parse_current, uint32_t *finished, struct cil_list *other)
{
	if (other == NULL || other->head == NULL || other->head->next == NULL)
		return SEPOL_ERR;

	struct cil_tree_node *ast_current = NULL;
	struct cil_db *db = NULL;
	struct cil_tree_node *ast_node;
	uint32_t rc = SEPOL_ERR;

	if (other->head->flavor == CIL_AST_NODE)
		ast_current = (struct cil_tree_node*)other->head->data;
	else
		return SEPOL_ERR;
	
	if (other->head->next->flavor == CIL_DB)
		db = (struct cil_db*)other->head->next->data;
	else
		return SEPOL_ERR;

	if (parse_current->cl_head == NULL) {
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
			other->head->data = ast_current;

			if (!strcmp(parse_current->data, CIL_KEY_BLOCK)) {
				rc = cil_gen_block(db, parse_current, ast_node, 0, NULL);
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
				*finished = CIL_TREE_SKIP_NEXT;
			}
			else if (!strcmp(parse_current->data, CIL_KEY_COMMON)) {
				rc = cil_gen_common(db, parse_current, ast_node);
				if (rc != SEPOL_OK) {
					printf("cil_gen_common failed, rc: %d\n", rc);
					return rc;
				}
				*finished = CIL_TREE_SKIP_NEXT;
			}
			else if (!strcmp(parse_current->data, CIL_KEY_CLASSCOMMON)) {
				rc = cil_gen_classcommon(db, parse_current, ast_node);
				if (rc != SEPOL_OK) {
					printf("cil_gen_classcommon failed, rc: %d\n", rc);
					return rc;
				}
			}
			else if (!strcmp(parse_current->data, CIL_KEY_SID)) {
				rc = cil_gen_sid(db, parse_current, ast_node);
				if (rc != SEPOL_OK) {
					printf("cil_gen_sid failed, rc: %d\n", rc);
					return rc;
				}
				*finished = CIL_TREE_SKIP_NEXT;
			}
			else if (!strcmp(parse_current->data, CIL_KEY_SIDCONTEXT)) {
				rc = cil_gen_sidcontext(db, parse_current, ast_node);
				if (rc != SEPOL_OK) {
					printf("cil_gen_sidcontext failed, rc: %d\n", rc);
					return rc;
				}
				*finished = CIL_TREE_SKIP_NEXT;
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
			else if (!strcmp(parse_current->data, CIL_KEY_TYPEBOUNDS)) {
				rc = cil_gen_typebounds(db, parse_current, ast_node);
				if (rc != SEPOL_OK) {
					printf("cil_gen_typebounds failed, rc: %d\n", rc);
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
			else if (!strcmp(parse_current->data, CIL_KEY_ROLEDOMINANCE)) {
				rc = cil_gen_roledominance(db, parse_current, ast_node);
				if (rc != SEPOL_OK) {
					printf("cil_gen_roledominance failed, rc: %d\n", rc);
					return rc;
				}
			}
			else if (!strcmp(parse_current->data, CIL_KEY_BOOL)) {
				rc = cil_gen_bool(db, parse_current, ast_node, CIL_BOOL);
				if (rc != SEPOL_OK) {
					printf("cil_gen_bool failed, rc: %d\n", rc);
					return rc;
				}
			}
			else if (!strcmp(parse_current->data, CIL_KEY_BOOLEANIF)) {
				rc = cil_gen_boolif(db, parse_current, ast_node);
				if (rc != SEPOL_OK) {
					printf("cil_gen_boolif failed, rc: %d\n", rc);
					return rc;
				}
			}
			else if(!strcmp(parse_current->data, CIL_KEY_TUNABLE)) {
				rc = cil_gen_bool(db, parse_current, ast_node, CIL_TUNABLE);
				if (rc != SEPOL_OK) {
					printf("cil_gen_bool failed, rc: %d\n", rc);
					return rc;
				}
			}
			else if (!strcmp(parse_current->data, CIL_KEY_TUNABLEIF)) {
				rc = cil_gen_tunif(db, parse_current, ast_node);
				if (rc != SEPOL_OK) {
					printf("cil_gen_tunif failed, rc: %d\n", rc);
					return rc;
				}
			}
			else if (!strcmp(parse_current->data, CIL_KEY_ELSE)) {
				rc = cil_gen_else(db, parse_current, ast_node);
				if (rc != SEPOL_OK) {
					printf("cil_gen_else failed, rc: %d\n", rc);
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
				*finished = CIL_TREE_SKIP_NEXT;
			}
			else if (!strcmp(parse_current->data, CIL_KEY_AUDITALLOW)) {
				rc = cil_gen_avrule(parse_current, ast_node, CIL_AVRULE_AUDITALLOW);
				if (rc != SEPOL_OK) {
					printf("cil_gen_avrule (auditallow) failed, rc: %d\n", rc);
					return rc;
				}
				*finished = CIL_TREE_SKIP_NEXT;
			}
			else if (!strcmp(parse_current->data, CIL_KEY_DONTAUDIT)) {
				rc = cil_gen_avrule(parse_current, ast_node, CIL_AVRULE_DONTAUDIT);
				if (rc != SEPOL_OK) {
					printf("cil_gen_avrule (dontaudit) failed, rc: %d\n", rc);
					return rc;
				}
				*finished = CIL_TREE_SKIP_NEXT;
			}
			else if (!strcmp(parse_current->data, CIL_KEY_NEVERALLOW)) {
				rc = cil_gen_avrule(parse_current, ast_node, CIL_AVRULE_NEVERALLOW);
				if (rc != SEPOL_OK) {
					printf("cil_gen_avrule (neverallow) failed, rc: %d\n", rc);
					return rc;
				}
				*finished = CIL_TREE_SKIP_NEXT;
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
				*finished = CIL_TREE_SKIP_NEXT;
			}
			else if (!strcmp(parse_current->data, CIL_KEY_CATORDER)) {
				rc = cil_gen_catorder(db, parse_current, ast_node);
				if (rc != SEPOL_OK) {
					printf("cil_gen_catorder failed, rc: %d\n", rc);
					return rc;
				}
				*finished = CIL_TREE_SKIP_NEXT;
			}
			else if (!strcmp(parse_current->data, CIL_KEY_DOMINANCE)) {
				rc = cil_gen_dominance(db, parse_current, ast_node);
				if (rc != SEPOL_OK) {
					printf("cil_gen_dominance failed, rc: %d\n", rc);
					return rc;
				}
				*finished = CIL_TREE_SKIP_NEXT;
			}
			else if (!strcmp(parse_current->data, CIL_KEY_SENSCAT)) {
				rc = cil_gen_senscat(db, parse_current, ast_node);
				if (rc != SEPOL_OK) {
					printf("cil_gen_senscat failed, rc: %d\n", rc);
					return rc;
				}
				*finished = CIL_TREE_SKIP_NEXT;
			}
			else if (!strcmp(parse_current->data, CIL_KEY_LEVEL)) {
				rc = cil_gen_level(db, parse_current, ast_node);
				if (rc != SEPOL_OK) {
					printf("cil_gen_level failed, rc: %d\n", rc);
					return rc;
				}
				*finished = CIL_TREE_SKIP_NEXT;
			}
			else if (!strcmp(parse_current->data, CIL_KEY_CONSTRAIN)) {
				rc = cil_gen_constrain(db, parse_current, ast_node, CIL_CONSTRAIN);
				if (rc != SEPOL_OK) {
					printf("cil_gen_constrain failed, rc: %d\n", rc);
					return rc;
				}
				*finished = CIL_TREE_SKIP_NEXT;
			}
			else if (!strcmp(parse_current->data, CIL_KEY_MLSCONSTRAIN)) {
				rc = cil_gen_constrain(db, parse_current, ast_node, CIL_MLSCONSTRAIN);
				if (rc != SEPOL_OK) {
					printf("cil_gen_constrain failed, rc: %d\n", rc);
					return rc;
				}
				*finished = CIL_TREE_SKIP_NEXT;
			}

			else if (!strcmp(parse_current->data, CIL_KEY_CONTEXT)) {
				rc = cil_gen_context(db, parse_current, ast_node);
				if (rc != SEPOL_OK) {
					printf("cil_gen_context failed, rc: %d\n", rc);
					return rc;
				}
				*finished = CIL_TREE_SKIP_NEXT;
			}
			else if (!strcmp(parse_current->data, CIL_KEY_FILECON)) {
				rc = cil_gen_filecon(db, parse_current, ast_node);
				if (rc != SEPOL_OK) {
					printf("cil_gen_filecon failed, rc: %d\n", rc);
					return rc;
				}
				*finished = CIL_TREE_SKIP_NEXT;
			}
			else if (!strcmp(parse_current->data, CIL_KEY_PORTCON)) {
				rc = cil_gen_portcon(db, parse_current, ast_node);
				if (rc != SEPOL_OK) {
					printf("cil_gen_portcon failed, rc: %d\n", rc);
					return rc;
				}
				*finished = CIL_TREE_SKIP_NEXT;
			}
			else if (!strcmp(parse_current->data, CIL_KEY_NODECON)) {
				rc = cil_gen_nodecon(db, parse_current, ast_node);
				if (rc != SEPOL_OK) {
					printf("cil_gen_nodecon failed, rc: %d\n", rc);
					return rc;
				}
				*finished = CIL_TREE_SKIP_NEXT;
			}
			else if (!strcmp(parse_current->data, CIL_KEY_GENFSCON)) {
				rc = cil_gen_genfscon(db, parse_current, ast_node);
				if (rc != SEPOL_OK) {
					printf("cil_gen_genfscon failed, rc: %d\n", rc);
					return rc;
				}
				*finished = CIL_TREE_SKIP_NEXT;
			}
			else if (!strcmp(parse_current->data, CIL_KEY_NETIFCON)) {
				rc = cil_gen_netifcon(db, parse_current, ast_node);
				if (rc != SEPOL_OK) {
					printf("cil_gen_netifcon failed, rc: %d\n", rc);
					return rc;
				}
				*finished = CIL_TREE_SKIP_NEXT;
			}
			else if (!strcmp(parse_current->data, CIL_KEY_MACRO)) {
				rc = cil_gen_macro(db, parse_current, ast_node);
				if (rc != SEPOL_OK) {
					printf("cil_gen_macro failed, rc: %d\n", rc);
					return rc;
				}
			}
			else if (!strcmp(parse_current->data, CIL_KEY_CALL)) {
				rc = cil_gen_call(db, parse_current, ast_node);
				if (rc != SEPOL_OK) {
					printf("cil_gen_call failed, rc: %d\n", rc);
					return rc;
				}
				*finished = 1;
			}
			else if (!strcmp(parse_current->data, CIL_KEY_POLICYCAP)) {
				rc = cil_gen_policycap(db, parse_current, ast_node);
				if (rc != SEPOL_OK) {
					printf("cil_gen_policycap failed, rc: %d\n", rc);
					return rc;
				}
				*finished = 1;
			}
			else if (!strcmp(parse_current->data, CIL_KEY_OPTIONAL)) {
				rc = cil_gen_optional(db, parse_current, ast_node);
				if (rc != SEPOL_OK) {
					printf("cil_gen_optional failed, rc: %d\n", rc);
					return rc;
				}
			}
			else {
				printf("Error: Unknown keyword %s\n", (char*)parse_current->data);
				return SEPOL_ERR;
			}
		}
	}

	return SEPOL_OK;
}

int __cil_build_ast_branch_helper(__attribute__((unused)) struct cil_tree_node *parse_current, struct cil_list *other)
{
	if (other == NULL || other->head == NULL)
		return SEPOL_ERR;

	if (other->head->flavor == CIL_AST_NODE) 
		other->head->data = ((struct cil_tree_node*)other->head->data)->parent;
	else
		return SEPOL_ERR;

	return SEPOL_OK;
}

int cil_build_ast(struct cil_db *db, struct cil_tree_node *parse_tree, struct cil_tree_node *ast)
{
	if (db == NULL || parse_tree == NULL || ast == NULL)
		return SEPOL_ERR;

	int rc = SEPOL_ERR;

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->data = ast;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = db;
	other->head->next->flavor = CIL_DB;	

	rc = cil_tree_walk(parse_tree, __cil_build_ast_node_helper, NULL, __cil_build_ast_branch_helper, other); 
	if (rc != SEPOL_OK) {
		printf("cil_tree_walk failed, rc: %d\n", rc);
		return rc;
	}
	
	return SEPOL_OK;
}


