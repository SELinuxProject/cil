#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "cil_ast.h"
#include "cil_tree.h"
#include "cil_parser.h"
#include "cil.h"

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
					}
					else if (!strcmp(parse_current->data, CIL_KEY_USER)) {
						rc = cil_gen_user(db, parse_current, ast_node);
						if (rc != SEPOL_OK) {
							printf("cil_gen_sid failed, rc: %d\n", rc);
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
						rc = cil_gen_typeattr(db, parse_current, ast_node, CIL_TYPE_ATTR);
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
					else if (!strcmp(parse_current->data, CIL_KEY_INTERFACE)) {
						printf("new interface: %s\n", (char*)parse_current->next->data);
						ast_node->flavor = CIL_TRANS_IF;
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

int cil_resolve_avrule(struct cil_db *db, struct cil_tree_node *current)
{
	struct cil_avrule *rule = (struct cil_avrule*)current->data;
	struct cil_tree_node *src_node = NULL;
	struct cil_tree_node *tgt_node = NULL;
	struct cil_tree_node *obj_node = NULL;

	int rc = SEPOL_ERR;
	
	rc = cil_resolve_name(db, current, rule->src_str, CIL_SYM_LOCAL_TYPES, &src_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", rule->src_str);
		return SEPOL_ERR;
	}
	else {
		rule->src = (struct cil_type*)(src_node->data);
		free(rule->src_str);
		rule->src_str = NULL;
	}
					
	rc = cil_resolve_name(db, current, rule->tgt_str, CIL_SYM_LOCAL_TYPES, &tgt_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", rule->tgt_str);
		return SEPOL_ERR;
	}
	else {
		rule->tgt = (struct cil_type*)(tgt_node->data);
		free(rule->tgt_str);
		rule->tgt_str = NULL;	
	}

	rc = cil_symtab_get_node(&db->global_symtab[CIL_SYM_GLOBAL_CLASSES], rule->obj_str, &obj_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", rule->obj_str);
		return SEPOL_ERR;
	}
	else {
		rule->obj = (struct cil_class*)(obj_node->data);
		free(rule->obj_str);
		rule->obj_str = NULL;
	}
	struct cil_tree_node *perm_node;
	struct cil_list_item *perm = rule->perms_str->list;
	struct cil_list_item *list_item;
	struct cil_list_item *list_tail;
	struct cil_list *perms_list;
	rc = cil_list_init(&perms_list);
	if (rc != SEPOL_OK) {
		printf("Failed to init perm node list\n");
		return rc;
	}
	while (perm != NULL) {	
		rc = cil_symtab_get_node(&rule->obj->perms, (char*)perm->data, &perm_node);
		if (rc != SEPOL_OK) {
			printf("Failed to get node from symtab\n");
			return rc;
		}
		rc = cil_list_item_init(&list_item);
		if (rc != SEPOL_OK) {
			printf("Failed to init perm node list item\n");
			return rc;
		}
		list_item->flavor = CIL_PERM;
		list_item->data = perm_node->data;
		if (perms_list->list == NULL) 
			perms_list->list = list_item;
		else 
			list_tail->next = list_item;
		list_tail = list_item;
		perm = perm->next;
	}
	rule->perms_list = perms_list;
	cil_list_destroy(&rule->perms_str);

	return SEPOL_OK;
}

int cil_resolve_typeattr(struct cil_db *db, struct cil_tree_node *current)
{
	struct cil_typeattribute *typeattr = (struct  cil_typeattribute*)current->data;
	struct cil_tree_node *type_node = NULL;
	struct cil_tree_node *attr_node = NULL;
	int rc = SEPOL_ERR;
	rc = cil_resolve_name(db, current, typeattr->type_str, CIL_SYM_LOCAL_TYPES, &type_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", typeattr->type_str);
		return SEPOL_ERR;
	}
	typeattr->type = (struct cil_type*)(type_node->data);
	free(typeattr->type_str);
	typeattr->type_str = NULL;

	rc = cil_resolve_name(db, current, typeattr->attrib_str, CIL_SYM_LOCAL_ATTRS, &attr_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", typeattr->attrib_str);
		return SEPOL_ERR;
	}
	typeattr->attrib = (struct cil_type*)(attr_node->data);
	free(typeattr->attrib_str);
	typeattr->attrib_str = NULL;

	return SEPOL_OK;
}

int cil_resolve_typealias(struct cil_db *db, struct cil_tree_node *current)
{
	struct cil_typealias *alias = (struct cil_typealias*)current->data;
	struct cil_tree_node *type_node = NULL;
	int rc = cil_resolve_name(db, current, alias->type_str, CIL_SYM_LOCAL_TYPES, &type_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", alias->type_str);
		return SEPOL_ERR;
	}
	alias->type = (struct cil_type*)(type_node->data);
	free(alias->type_str);
	alias->type_str = NULL;

	return SEPOL_OK;
}

int cil_resolve_class(struct cil_db *db, struct cil_tree_node *current)
{
	struct cil_class *cls = (struct cil_class*)current->data;
	struct cil_tree_node *common_node = NULL;
	if (cls->common_str == NULL)
		return SEPOL_OK;

	if (cls->common_str != NULL) {
		int rc = cil_symtab_get_node(&db->global_symtab[CIL_SYM_GLOBAL_COMMONS], cls->common_str, &common_node);
		if (rc != SEPOL_OK) {
			printf("Name resolution failed for %s\n", cls->common_str);
			return SEPOL_ERR;
		}
		cls->common = (struct cil_common*)(common_node->data);
		free(cls->common_str);
		cls->common_str = NULL;
	}
	return SEPOL_OK;
}

int cil_resolve_userrole(struct cil_db *db, struct cil_tree_node *current)
{
	struct cil_userrole *userrole = (struct cil_userrole*)current->data;
	struct cil_tree_node *user_node = NULL;
	struct cil_tree_node *role_node = NULL;
	int rc = cil_symtab_get_node(&db->global_symtab[CIL_SYM_GLOBAL_USERS], userrole->user_str, &user_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", userrole->user_str);
		return SEPOL_ERR;
	}
	userrole->user = (struct cil_user*)(user_node->data);
	free(userrole->user_str);
	userrole->user_str = NULL;

	rc = cil_symtab_get_node(&db->global_symtab[CIL_SYM_GLOBAL_ROLES], userrole->role_str, &role_node);
	if (rc != SEPOL_OK) {
		printf("Name resolution failed for %s\n", userrole->role_str);
		return SEPOL_ERR;
	}
	userrole->role = (struct cil_role*)(role_node->data);
	free(userrole->role_str);
	userrole->role_str = NULL;

	return SEPOL_OK;	
}

int cil_resolve_ast(struct cil_db *db, struct cil_tree_node *current)
{
	int rc = SEPOL_ERR;
	int reverse = 0;

	if (current == NULL) {
		printf("Error: Can't resolve NULL tree\n");
		return SEPOL_ERR;
	}

	do {
		if (current->cl_head == NULL) {
//			printf("FLAVOR: %d\n", current->flavor);
			switch( current->flavor ) {
				case CIL_TYPE_ATTR : {
					printf("case typeattribute\n");
					rc = cil_resolve_typeattr(db, current);
					if (rc !=  SEPOL_OK)
						return rc;
					break;
				}
				case CIL_TYPEALIAS : {
					printf("case typealias\n");
					rc = cil_resolve_typealias(db, current);
					if (rc != SEPOL_OK)
						return rc;
					break;
				}
				case CIL_AVRULE : {
					printf("case avrule\n");
					rc = cil_resolve_avrule(db, current);
					if (rc != SEPOL_OK)
						return rc;
					break;
				}
				case CIL_USERROLE : {
					printf("case userrole\n");
					rc = cil_resolve_userrole(db, current);
					if (rc != SEPOL_OK)
						return rc;
					break;
				}
				default : {
					break;
				}
				
			}
		}
		else {
//			printf("FLAVOR: %d\n", current->flavor);
			switch (current->flavor) {
				case CIL_CLASS : {
					printf("case class\n");
					rc = cil_resolve_class(db, current);
					if (rc != SEPOL_OK)
						return rc;
					break;
				}
				default : {
					break;
				}
			}
		}	

		if (current->cl_head != NULL && !reverse)
			current = current->cl_head;
		else if (current->next != NULL && reverse) {
			current = current->next;
			reverse = 0;
		}
		else if (current->next != NULL)
			current = current->next;
		else {
			current = current->parent;
			reverse = 1;
		}
	} while (current->flavor != CIL_ROOT);
	return SEPOL_OK;
}

static int __cil_resolve_name_helper(struct cil_db *db, struct cil_tree_node *ast_node, char *name, uint32_t sym_index, struct cil_tree_node **node)
{
	int rc = SEPOL_ERR;
	char* name_dup = strdup(name);
	char *tok_current = strtok(name_dup, ".");
	char *tok_next = strtok(NULL, ".");
	symtab_t *symtab = NULL;
	struct cil_tree_node *tmp_node = NULL;

	if (ast_node->flavor == CIL_ROOT) {
		symtab = &(db->local_symtab[CIL_SYM_LOCAL_BLOCKS]);
	}
	else {
		rc = cil_get_parent_symtab(db, ast_node, &symtab, CIL_SYM_LOCAL_BLOCKS);
		if (rc != SEPOL_OK) {
			printf("__cil_resolve_name_helper: cil_get_parent_symtab failed, rc: %d\n", rc);
			goto resolve_name_helper_cleanup;
		}
	}

	if (tok_next == NULL) {
		goto resolve_name_helper_cleanup;
	}

	while (tok_current != NULL) {
		if (tok_next != NULL) {
			rc = cil_symtab_get_node(symtab, tok_current, &tmp_node);
			if (rc != SEPOL_OK) {
				printf("__cil_resolve_name_helper: Failed to find table, block current: %s\n", tok_current);
				goto resolve_name_helper_cleanup;
			}
			symtab = &(((struct cil_block*)tmp_node->data)->symtab[CIL_SYM_LOCAL_BLOCKS]);
		}
		else {
			//printf("type key: %s\n", tok_current); 
			symtab = &(((struct cil_block*)tmp_node->data)->symtab[sym_index]);
			rc = cil_symtab_get_node(symtab, tok_current, &tmp_node);
			if (rc != SEPOL_OK) {
				printf("__cil_resolve_name_helper: Failed to resolve name, current: %s\n", tok_current);
				goto resolve_name_helper_cleanup;
			}
		}
		tok_current = tok_next;
		tok_next = strtok(NULL, ".");
	}
	*node = tmp_node;
	free(name_dup);	

	return SEPOL_OK;

	resolve_name_helper_cleanup:
		free(name_dup);
		if (rc)
			return rc;
		else
			return SEPOL_ERR;
}

int cil_resolve_name(struct cil_db *db, struct cil_tree_node *ast_node, char *name, uint32_t sym_index, struct cil_tree_node **node)
{
	if (db == NULL || ast_node == NULL || name == NULL) {
		printf("Invalid call to cil_resolve_name\n");
		return SEPOL_ERR;
	}

	int rc = SEPOL_ERR;
	char *global_symtab_name = name;
	char first = *name;

	if (first != '.') {
		if (strrchr(name, '.') == NULL) {
			symtab_t *symtab = NULL;
			rc = cil_get_parent_symtab(db, ast_node, &symtab, sym_index);
			if (rc != SEPOL_OK) {
				printf("cil_resolve_name: cil_get_parent_symtab failed, rc: %d\n", rc);
				return rc;
			}
			rc = cil_symtab_get_node(symtab, name, node);
			if (rc != SEPOL_OK) {
				global_symtab_name = cil_malloc(strlen(name)+2);
				strcpy(global_symtab_name, ".");
				strncat(global_symtab_name, name, strlen(name));
			}
		}
		else {
			if (__cil_resolve_name_helper(db, ast_node, name, sym_index, node) != SEPOL_OK) {
				global_symtab_name = cil_malloc(strlen(name)+2);
				strcpy(global_symtab_name, ".");
				strncat(global_symtab_name, name, strlen(name));
			}
		}
	}
		
	first = *global_symtab_name;

	if (first == '.') {
		if (strrchr(global_symtab_name, '.') == global_symtab_name) { //Only one dot in name, check global symtabs
			if (cil_symtab_get_node(&db->local_symtab[sym_index], global_symtab_name+1, node)) {
				free(global_symtab_name);
				return SEPOL_ERR;
			}
		}
		else {
			if (__cil_resolve_name_helper(db, db->ast->root, global_symtab_name, sym_index, node)) {
				free(global_symtab_name);
				return SEPOL_ERR;
			}
		}
	}

	if (global_symtab_name != name)
		free(global_symtab_name);

	return SEPOL_OK;
}

#define MAX_CIL_NAME_LENGTH 2048
int cil_qualify_name(struct cil_tree_node *root)
{
	struct cil_tree_node *curr = root;
	uint16_t reverse = 0;
	uint32_t length;
	char fqp[MAX_CIL_NAME_LENGTH];
	*fqp = '\0';
	char *fqn, *uqn;

	do {
		if (curr->cl_head != NULL) {
			if (!reverse) {
				if (curr->flavor >= CIL_MIN_DECLARATIVE) { // append name
					strcat(fqp, ((struct cil_symtab_datum*)curr->data)->name);
					strcat(fqp, ".");
				}
			}
			else {
				length = strlen(fqp) - (strlen(((struct cil_symtab_datum*)curr->data)->name) + 1);
				fqp[length] = '\0';
			}
		}
		else if (curr->flavor >= CIL_MIN_DECLARATIVE){
			uqn = ((struct cil_symtab_datum*)curr->data)->name; 
			length = strlen(fqp) + strlen(uqn) + 1;
			fqn = cil_malloc(length + 1);

			strcpy(fqn, fqp);
			strcat(fqn, uqn);

			((struct cil_symtab_datum*)curr->data)->name = fqn;	// Replace with new, fully qualified string
		}

		if (curr->cl_head != NULL && !reverse) 
			curr = curr->cl_head;
		else if (curr->next != NULL) {
			curr = curr->next;
			reverse = 0;
		}
		else {
			curr = curr->parent;
			reverse = 1;
		}
	} while (curr->flavor != CIL_ROOT);

	return SEPOL_OK;
}
