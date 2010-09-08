#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "cil_ast.h"
#include "cil_tree.h"
#include "cil_parser.h"
#include "cil.h"

static int __cil_build_ast(struct cil_db **db, struct cil_stack *namespace, char *namespace_str, struct cil_tree_node *parse_tree, struct cil_tree_node *ast)
{
	struct cil_tree_node *parse_current = parse_tree;
	struct cil_tree_node *ast_current = ast;
	struct cil_tree_node *ast_node;

	if ((parse_current == NULL) || (ast_current == NULL)) {
		printf("Error: NULL tree as parameter\n");
		return SEPOL_ERR;
	}

//	printf("before parse_current->cl_head check\n");
	if (parse_current->cl_head == NULL) {	//This is a leaf node
//		printf("parse_current cl_head is NULL\n");
		if (parse_current->parent->cl_head == parse_current) { //This is the beginning of the line
//			printf("cl_head = parse_current\n");
			//Node values set here
			cil_tree_node_init(&ast_node);
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
				cil_gen_block(*db, parse_current, ast_node, 0, 0, NULL);
				cil_get_namespace_str(namespace, &namespace_str);
			}
			else if (!strcmp(parse_current->data, CIL_KEY_CLASS)) {
				cil_gen_class(*db, parse_current, ast_node);
				ast_current = ast_current->parent; //To avoid parsing list of perms again
				return SEPOL_OK;
			}
//			else if (!strcmp(parse_current->data, CIL_KEY_PERM)) {
//				cil_gen_perm(*db, parse_current, ast_node);
//			}
			else if (!strcmp(parse_current->data, CIL_KEY_COMMON)) {
				cil_gen_common(*db, parse_current, ast_node);
			}
			else if (!strcmp(parse_current->data, CIL_KEY_SID)) {
				cil_gen_sid(*db, parse_current, ast_node);
			}
			else if (!strcmp(parse_current->data, CIL_KEY_TYPE)) {
				cil_gen_type(*db, parse_current, ast_node, CIL_TYPE);
			}
			else if (!strcmp(parse_current->data, CIL_KEY_ATTR)) {
				cil_gen_type(*db, parse_current, ast_node, CIL_TYPE_ATTR);
			}
			else if (!strcmp(parse_current->data, CIL_KEY_TYPEALIAS)) {
				cil_gen_typealias(*db, parse_current, ast_node);
			}
			else if (!strcmp(parse_current->data, CIL_KEY_ROLE)) {
				cil_gen_role(*db, parse_current, ast_node);
			}
			else if (!strcmp(parse_current->data, CIL_KEY_BOOL)) {
				cil_gen_bool(*db, parse_current, ast_node);
			}
			else if (!strcmp(parse_current->data, CIL_KEY_ALLOW)) {
				cil_gen_avrule(*db, parse_current, ast_node, CIL_AVRULE_ALLOWED); 
				ast_current = ast_current->parent;
				return SEPOL_OK;	//So that the object and perms lists don't get parsed again as potential keywords
			}
			else if (!strcmp(parse_current->data, CIL_KEY_INTERFACE)) {
				printf("new interface: %s\n", (char*)parse_current->next->data);
				ast_node->flavor = CIL_TRANS_IF;
			}
		}
		else { //Rest of line 
			//printf("Rest of line\n");
			//Not sure if this case is necessary (should be handled above when keyword is detected)			
		}
	}
	else {
//		printf("recurse with cl_head\n");
		__cil_build_ast(db, namespace, namespace_str, parse_current->cl_head, ast_current);
	}
	if (parse_current->next != NULL) {
		//Process next in list
//		printf("recurse with next\n");
		__cil_build_ast(db, namespace, namespace_str, parse_current->next, ast_current);
	}
	else {
		//Return to parent
//		printf("set ast_current to parent\n");
		if (ast_current->flavor == CIL_BLOCK) {
			cil_stack_pop(namespace, NULL);
			cil_get_namespace_str(namespace, &namespace_str);
		}

		ast_current = ast_current->parent;

		return SEPOL_OK;
	}
	
	return SEPOL_OK;
}

int cil_build_ast(struct cil_db **db, struct cil_tree *parse_root)
{
	struct cil_stack *namespace;
	char *namespace_str = NULL;
	cil_stack_init(&namespace);
	__cil_build_ast(db, namespace, namespace_str, parse_root->root, (*db)->ast_root->root);
	free(namespace);
	
	return SEPOL_OK;
}

int cil_resolve_ast(struct cil_db **db, struct cil_tree_node *current)
{
	symtab_datum_t *datum = NULL;

	if (current == NULL) {
		printf("Error: Can't resolve NULL tree\n");
		return SEPOL_ERR;
	}

	if (current->cl_head == NULL) {
		switch( current->flavor ) {
			case CIL_TYPEALIAS : {
				printf("case typealias\n");
				struct cil_typealias *alias = (struct cil_typealias*)current->data;
				char first = *alias->type_str;
				struct cil_tree_node *node;
				cil_resolve_name(*db, current, alias->type_str, &node);
				alias->type = node;	
			}
			break;
			case CIL_AVRULE : {
				printf("case avrule\n");
				struct cil_avrule *rule = (struct cil_avrule*)current->data;
				//if (rule->rule_kind == CIL_AVRULE_ALLOWED) {
				//}
			}	
			default : {
				printf("Default\n");
			}
			
		}
	}
	else {
		cil_resolve_ast(db, current->cl_head);
	}

	if (current->next != NULL) {
		cil_resolve_ast(db, current->next);
	}
	else {
		current = current->parent;		
	}
	
	return SEPOL_OK;
}

int cil_resolve_name(struct cil_db *db, struct cil_tree_node *ast_node, char *name, void **data)
{
	char first = *name;
	symtab_datum_t *datum = NULL;	

	if (name != NULL) {
		if (first == '.') {
			printf("start lookup in global namespace\n");
			if (strrchr(name, '.') == name) {
				printf("Look in Global types\n");
				datum = (symtab_datum_t*)hashtab_search(db->local_symtab[CIL_SYM_LOCAL_TYPES].table, (hashtab_key_t)name);
				if (datum != NULL) {
					printf("found\n");
					
				}
			}
		}
		else {
			printf("do lookup in local namespace first\n");
		}
	}

	return SEPOL_OK;
}


