#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "cil_ast.h"
#include "cil_tree.h"
#include "cil_parser.h"
#include "cil.h"

// TODO CDS think about switching to a loop instead of recursion
int cil_build_ast(struct cil_db *db, struct cil_tree_node *parse_tree, struct cil_tree_node *ast)
{
	if (db == NULL || parse_tree == NULL || ast == NULL)
		return SEPOL_ERR;

	int rc = SEPOL_ERR;
	struct cil_tree_node *parse_current = parse_tree;
	struct cil_tree_node *ast_current = ast;
	struct cil_tree_node *ast_node;

//	printf("before parse_current->cl_head check\n");
	if (parse_current->cl_head == NULL) {	//This is a leaf node
//		printf("parse_current cl_head is NULL\n");
		if (parse_current->parent->cl_head == parse_current) { //This is the beginning of the line
			// TODO CDS pull this out into a function of its own, as this is pretty nested
//			printf("cl_head = parse_current\n");
			//Node values set here
			// TODO CDS move this code to cil_tree_add_child() with or without the initializer
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
//			printf("parse_current->data: %s\n", (char*)parse_current->data);
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
						
				ast_current = ast_current->parent; //To avoid parsing list of perms again
				return SEPOL_OK;
			}
			else if (!strcmp(parse_current->data, CIL_KEY_COMMON)) {
				rc = cil_gen_common(db, parse_current, ast_node);
				if (rc != SEPOL_OK) {
					printf("cil_gen_common failed, rc: %d\n", rc);
					return rc;
				}
				ast_current = ast_current->parent;
				return SEPOL_OK;
			}
			else if (!strcmp(parse_current->data, CIL_KEY_SID)) {
				rc = cil_gen_sid(db, parse_current, ast_node);
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
				ast_current = ast_current->parent;
				return SEPOL_OK;	//So that the object and perms lists don't get parsed again as potential keywords
			}
			else if (!strcmp(parse_current->data, CIL_KEY_INTERFACE)) {
				printf("new interface: %s\n", (char*)parse_current->next->data);
				ast_node->flavor = CIL_TRANS_IF;
			}
		}
		else { //Rest of line 
//			printf("Rest of line\n");
			//Not sure if this case is necessary (should be handled above when keyword is detected)			
		}
	}
	else {
//		printf("recurse with cl_head\n");
		rc = cil_build_ast(db, parse_current->cl_head, ast_current);
		if (rc != SEPOL_OK) 
			return rc;
	}
	if (parse_current->next != NULL) {
		//Process next in list
//		printf("recurse with next\n");
		rc = cil_build_ast(db, parse_current->next, ast_current);
		if (rc != SEPOL_OK) 
			return rc;	
	}
	else {
		//Return to parent
//		printf("set ast_current to parent\n");

		ast_current = ast_current->parent;

		return SEPOL_OK;
	}
	
	return SEPOL_OK;
}

// TODO CDS un-recurse
int cil_resolve_ast(struct cil_db *db, struct cil_tree_node *current)
{
	int rc = 0;

	if (current == NULL) {
		printf("Error: Can't resolve NULL tree\n");
		return SEPOL_ERR;
	}

	if (current->cl_head == NULL) {
		// TODO CDS factor out each case into its own resolve function
		switch( current->flavor ) {
			case CIL_TYPEALIAS : {
				printf("case typealias\n");
				struct cil_typealias *alias = (struct cil_typealias*)current->data;
				struct cil_tree_node *type_node = NULL;
				rc = cil_resolve_name(db, current, alias->type_str, CIL_SYM_LOCAL_TYPES, &type_node);
				if (rc != SEPOL_OK) {
					printf("Name resolution failed for %s\n", alias->type_str);
					return SEPOL_ERR;
				}
				alias->type = (struct cil_type*)(type_node->data);
				free(alias->type_str);
				alias->type_str = NULL;
				break;
			}
			case CIL_AVRULE : {
				printf("case avrule\n");
				struct cil_avrule *rule = (struct cil_avrule*)current->data;
				struct cil_tree_node *src_node = NULL;
				struct cil_tree_node *tgt_node = NULL;
				struct cil_tree_node *obj_node = NULL;
					
				if (rule->rule_kind == CIL_AVRULE_ALLOWED) {
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
					struct cil_list_item *perm = rule->perms_str->list;
					uint32_t value;
					while (	perm != NULL) {
						rc = cil_symtab_get_value(&rule->obj->perms, (char*)perm->data, &value);
						if (rc != SEPOL_OK) {
							printf("Failed to get value from symtab\n");
							return rc;
						}

						rule->perms |= 1U << (value - 1);
						perm = perm->next;
					}
					cil_list_destroy(&rule->perms_str);
				}
				break;
			}	
			default : {
				printf("Default\n");
			}
			
		}
	}
	else {
		rc = cil_resolve_ast(db, current->cl_head);
		if (rc != SEPOL_OK) 
			return rc;
	}

	if (current->next != NULL) {
		rc = cil_resolve_ast(db, current->next);
		if (rc != SEPOL_OK)
			return rc;
	}
	else {
		current = current->parent;		
	}
	
	return SEPOL_OK;
}

static int __cil_resolve_name_helper(struct cil_db *db, struct cil_tree_node *ast_node, char *name, uint32_t sym_index, struct cil_tree_node **node)
{
	int rc = 0;
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
			// TODO add cleanup label
			free(name_dup);
			return rc;
		}
	}

	if (tok_next == NULL) {
		free(name_dup);
		return SEPOL_ERR;
	}

	while (tok_current != NULL) {
		if (tok_next != NULL) {
			rc = cil_symtab_get_node(symtab, tok_current, &tmp_node);
			if (rc != SEPOL_OK) {
				printf("__cil_resolve_name_helper: Failed to find table, block current: %s\n", tok_current);
				free(name_dup);
				return SEPOL_ERR;
			}
			symtab = &(((struct cil_block*)tmp_node->data)->symtab[CIL_SYM_LOCAL_BLOCKS]);
		}
		else {
			//printf("type key: %s\n", tok_current); 
			symtab = &(((struct cil_block*)tmp_node->data)->symtab[sym_index]);
			rc = cil_symtab_get_node(symtab, tok_current, &tmp_node);
			if (rc != SEPOL_OK) {
				printf("__cil_resolve_name_helper: Failed to resolve name, current: %s\n", tok_current);
				free(name_dup);
				return SEPOL_ERR;
			}
		}
		tok_current = tok_next;
		tok_next = strtok(NULL, ".");
	}
	*node = tmp_node;
	free(name_dup);	

	return SEPOL_OK;
}

int cil_resolve_name(struct cil_db *db, struct cil_tree_node *ast_node, char *name, uint32_t sym_index, struct cil_tree_node **node)
{
	if (db == NULL || ast_node == NULL || name == NULL) {
		printf("Invalid call to cil_resolve_name\n");
		return SEPOL_ERR;
	}

	int rc = 0;
	// TODO CDS change to something more descriptive
	char *global_name = strdup(name);
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
				free(global_name);
				global_name = malloc(strlen(name)+2);
				strcpy(global_name, ".");
				strncat(global_name, name, strlen(name));
			}
		}
		else {
			if (__cil_resolve_name_helper(db, ast_node, name, sym_index, node) != SEPOL_OK) {
				free(global_name);
				global_name = malloc(strlen(name)+2);
				strcpy(global_name, ".");
				strncat(global_name, name, strlen(name));
			}
		}
	}
		
	first = *global_name;

	if (first == '.') {
		if (strrchr(global_name, '.') == global_name) { //Only one dot in name, check global symtabs
			if (cil_symtab_get_node(&db->local_symtab[sym_index], global_name+1, node)) {
				free(global_name);
				return SEPOL_ERR;
			}
		}
		else {
			if (__cil_resolve_name_helper(db, db->ast_root->root, global_name, sym_index, node)) {
				free(global_name);
				return SEPOL_ERR;
			}
		}
	}

	free(global_name);

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
					strcat(fqp, ((cil_symtab_datum_t*)curr->data)->name);
					strcat(fqp, ".");
				}
			}
			else {
				length = strlen(fqp) - (strlen(((cil_symtab_datum_t*)curr->data)->name) + 1);
				fqp[length] = '\0';
			}
		}
		else if (curr->flavor >= CIL_MIN_DECLARATIVE){
			uqn = ((cil_symtab_datum_t*)curr->data)->name; 
			length = strlen(fqp) + strlen(uqn) + 1;
			fqn = malloc(length + 1);

			strcpy(fqn, fqp);
			strcat(fqn, uqn);

			((cil_symtab_datum_t*)curr->data)->name = fqn;	// Replace with new, fully qualified string
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
