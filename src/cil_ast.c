#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "cil_ast.h"
#include "cil_tree.h"
#include "cil_parser.h"
#include "cil.h"

// TODO CDS think about switching to a loop instead of recursion
static int __cil_build_ast(struct cil_db *db, struct cil_stack *namespace, char *namespace_str, struct cil_tree_node *parse_tree, struct cil_tree_node *ast)
{
	if (db == NULL || parse_tree == NULL || ast == NULL)
		return SEPOL_ERR;

	int rc = SEPOL_ERR;
	struct cil_tree_node *parse_current = parse_tree;
	struct cil_tree_node *ast_current = ast;
	struct cil_tree_node *ast_node;

	printf("before parse_current->cl_head check\n");
	if (parse_current->cl_head == NULL) {	//This is a leaf node
		printf("parse_current cl_head is NULL\n");
		if (parse_current->parent->cl_head == parse_current) { //This is the beginning of the line
			// TODO CDS pull this out into a function of its own, as this is pretty nested
			printf("cl_head = parse_current\n");
			//Node values set here
			// TODO CDS move this code to cil_tree_add_child() with or without the initializer
			rc = cil_tree_node_init(&ast_node);
			if (rc) {
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
			printf("parse_current->data: %s\n", (char*)parse_current->data);
			if (!strcmp(parse_current->data, CIL_KEY_BLOCK)) {
				rc = cil_gen_block(db, parse_current, ast_node, 0, 0, NULL);
				if (rc) {
					printf("cil_gen_block failed, rc: %d\n", rc);
					return rc;
				}
				// TODO CDS this can go away
				rc = cil_get_namespace_str(namespace, &namespace_str);
				if (rc) {
					printf("cil_get_namespace_str failed, rc: %d\n", rc);
					return rc;
				}
			}
			else if (!strcmp(parse_current->data, CIL_KEY_CLASS)) {
				rc = cil_gen_class(db, parse_current, ast_node);
				if (rc) {
					printf("cil_gen_class failed, rc: %d\n", rc);
					return rc;
				}
						
				ast_current = ast_current->parent; //To avoid parsing list of perms again
				return SEPOL_OK;
			}
			else if (!strcmp(parse_current->data, CIL_KEY_COMMON)) {
				rc = cil_gen_common(db, parse_current, ast_node);
				if (rc) {
					printf("cil_gen_common failed, rc: %d\n", rc);
					return rc;
				}
				ast_current = ast_current->parent;
				return SEPOL_OK;
			}
			else if (!strcmp(parse_current->data, CIL_KEY_SID)) {
				rc = cil_gen_sid(db, parse_current, ast_node);
				if (rc) {
					printf("cil_gen_sid failed, rc: %d\n", rc);
					return rc;
				}
			}
			else if (!strcmp(parse_current->data, CIL_KEY_TYPE)) {
				rc = cil_gen_type(db, parse_current, ast_node, CIL_TYPE);
				if (rc) {
					printf("cil_gen_type failed, rc: %d\n", rc);
					return rc;
				}
			}
			else if (!strcmp(parse_current->data, CIL_KEY_ATTR)) {
				rc = cil_gen_type(db, parse_current, ast_node, CIL_ATTR);
				if (rc) {
					printf("cil_gen_type (attr) failed, rc: %d\n", rc);
					return rc;
				}
			}
			else if (!strcmp(parse_current->data, CIL_KEY_TYPEALIAS)) {
				rc = cil_gen_typealias(db, parse_current, ast_node);
				if (rc) {
					printf("cil_gen_typealias failed, rc: %d\n", rc);
					return rc;
				}
			}
			else if (!strcmp(parse_current->data, CIL_KEY_ROLE)) {
				rc = cil_gen_role(db, parse_current, ast_node);
				if (rc) {
					printf("cil_gen_role failed, rc: %d\n", rc);
					return rc;
				}
			}
			else if (!strcmp(parse_current->data, CIL_KEY_BOOL)) {
				rc = cil_gen_bool(db, parse_current, ast_node);
				if (rc) {
					printf("cil_gen_bool failed, rc: %d\n", rc);
					return rc;
				}
			}
			else if (!strcmp(parse_current->data, CIL_KEY_ALLOW)) {
				rc = cil_gen_avrule(db, parse_current, ast_node, CIL_AVRULE_ALLOWED); 
				if (rc) {
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
			printf("Rest of line\n");
			//Not sure if this case is necessary (should be handled above when keyword is detected)			
		}
	}
	else {
		printf("recurse with cl_head\n");
		rc = __cil_build_ast(db, namespace, namespace_str, parse_current->cl_head, ast_current);
		if (rc) 
			return rc;
	}
	if (parse_current->next != NULL) {
		//Process next in list
		printf("recurse with next\n");
		rc = __cil_build_ast(db, namespace, namespace_str, parse_current->next, ast_current);
		if (rc) 
			return rc;	
	}
	else {
		//Return to parent
		printf("set ast_current to parent\n");

		ast_current = ast_current->parent;

		return SEPOL_OK;
	}
	
	return SEPOL_OK;
}

// TODO CDS Seems like this can go away, as all it does is call the helper function
int cil_build_ast(struct cil_db *db, struct cil_tree *parse_root)
{
	if (db == NULL || parse_root == NULL)
		return SEPOL_ERR;

	// TODO CDS namespace stuff should go away here
	struct cil_stack *namespace;
	char *namespace_str = NULL;
	cil_stack_init(&namespace);
	if(__cil_build_ast(db, namespace, namespace_str, parse_root->root, db->ast_root->root)) {
		free(namespace);
		return SEPOL_ERR;
	}
	free(namespace);
	
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
				if (rc) {
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
					if (rc) {
						printf("Name resolution failed for %s\n", rule->src_str);
						return SEPOL_ERR;
					}
					else {
						rule->src = (struct cil_type*)(src_node->data);
						free(rule->src_str);
						rule->src_str = NULL;
					}
					
					rc = cil_resolve_name(db, current, rule->tgt_str, CIL_SYM_LOCAL_TYPES, &tgt_node);
					if (rc) {
						printf("Name resolution failed for %s\n", rule->tgt_str);
						return SEPOL_ERR;
					}
					else {
						rule->tgt = (struct cil_type*)(tgt_node->data);
						free(rule->tgt_str);
						rule->tgt_str = NULL;	
					}

					rc = cil_resolve_name_global(db->global_symtab[CIL_SYM_GLOBAL_CLASSES], rule->obj_str, &obj_node);
					if (rc) {
						printf("Name resolution failed for %s\n", rule->obj_str);
						return SEPOL_ERR;
					}
					else {
						rule->obj = (struct cil_class*)(obj_node->data);
						free(rule->obj_str);
						rule->obj_str = NULL;
					}
					cil_symtab_datum_t *datum = NULL;
					struct cil_list_item *perm = rule->perms_str->list;
					while (	perm != NULL) {
						datum = (cil_symtab_datum_t*)hashtab_search(rule->obj->perms.table, (hashtab_key_t)perm->data);
						if (datum != NULL) 
							rule->perms |= 1U << (datum->value - 1);
						else {
							printf("Failed to resolve perm: %s\n", (char*)perm->data);
							return SEPOL_ERR;
						}
						perm = perm->next;
					}
					rule->perms_str = NULL; //TODO Need to destroy list here
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
		if (rc) 
			return rc;
	}

	if (current->next != NULL) {
		rc = cil_resolve_ast(db, current->next);
		if (rc)
			return rc;
	}
	else {
		current = current->parent;		
	}
	
	return SEPOL_OK;
}

// TODO rename, as this is generic and just resolves in a symtab, global or not
int cil_resolve_name_global(symtab_t symtab, char *name, void **data)
{
	cil_symtab_datum_t *datum = NULL;
	datum = (cil_symtab_datum_t*)hashtab_search(symtab.table, (hashtab_key_t)(name));
	if (datum == NULL) 
		return SEPOL_ERR;

	*data = (struct cil_tree_node*)datum->self;
	
	return SEPOL_OK;
} 

static int __cil_resolve_name_helper(struct cil_db *db, struct cil_tree_node *ast_node, char *name, uint32_t sym_index, cil_symtab_datum_t **datum)
{
	int rc = 0;
	char* name_dup = strdup(name);
	char *tok_current = strtok(name_dup, ".");
	char *tok_next = strtok(NULL, ".");
	symtab_t *symtab = NULL;
	cil_symtab_datum_t *new_datum = NULL;

	if (ast_node->flavor == CIL_ROOT) {
		symtab = &(db->local_symtab[CIL_SYM_LOCAL_BLOCKS]);
	}
	else {
		rc = cil_get_parent_symtab(db, ast_node, &symtab, CIL_SYM_LOCAL_BLOCKS);
		if (rc) {
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
			new_datum = (cil_symtab_datum_t*)hashtab_search(symtab->table, (hashtab_key_t)tok_current);
			if (new_datum == NULL) {
				printf("__cil_resolve_name_helper: Failed to find table, block current: %s\n", tok_current);
				free(name_dup);
				return SEPOL_ERR;
			}
			symtab = &(((struct cil_block*)new_datum->self->data)->symtab[CIL_SYM_LOCAL_BLOCKS]);
		}
		else {
			//printf("type key: %s\n", tok_current); 
			symtab = &(((struct cil_block*)new_datum->self->data)->symtab[sym_index]);
			new_datum = (cil_symtab_datum_t*)hashtab_search(symtab->table, (hashtab_key_t)tok_current);
			if (new_datum == NULL) {
				printf("__cil_resolve_name_helper: Failed to resolve name, current: %s\n", tok_current);
				free(name_dup);
				return SEPOL_ERR;
			}
		}
		tok_current = tok_next;
		tok_next = strtok(NULL, ".");
	}
	*datum = new_datum;
	free(name_dup);	

	return SEPOL_OK;
}

int cil_resolve_name(struct cil_db *db, struct cil_tree_node *ast_node, char *name, uint32_t sym_index, void **data)
{
	int rc = 0;
	// TODO CDS change to something more descriptive
	char *global_name = strdup(name);
	char first = *name;
	cil_symtab_datum_t *datum = NULL;	

	// TODO Need to actually error out if you no name
	if (name != NULL) {
		if (first != '.') {
			if (strrchr(name, '.') == NULL) {
				symtab_t *symtab = NULL;
				rc = cil_get_parent_symtab(db, ast_node, &symtab, sym_index);
				// TODO CDS should really check against constants, since we're using them
				if (rc) {
					printf("cil_resolve_name: cil_get_parent_symtab failed, rc: %d\n", rc);
					return rc;
				}
				datum = (cil_symtab_datum_t*)hashtab_search(symtab->table, (hashtab_key_t)name);
				if (datum == NULL) {
				//	printf("Not found in local symtab, checking global\n");
					free(global_name);
					global_name = malloc(strlen(name)+2);
					strcpy(global_name, ".");
					strncat(global_name, name, strlen(name));
				}
			}
			else {
				if (__cil_resolve_name_helper(db, ast_node, global_name, sym_index, &datum) != SEPOL_OK) {
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
				if (cil_resolve_name_global(db->local_symtab[sym_index], global_name+1, data)) {
					free(global_name);
					return SEPOL_ERR;
				}
			}
			else {
				if (__cil_resolve_name_helper(db, db->ast_root->root, global_name, sym_index, &datum)) {
					free(global_name);
					return SEPOL_ERR;
				}
			}
		}

		if (datum != NULL) {
			*data = (struct cil_tree_node*)datum->self;
		}
	}
	
	free(global_name);

	return SEPOL_OK;
}


