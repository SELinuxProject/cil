#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "cil_ast.h"
#include "cil_tree.h"
#include "cil_parser.h"
#include "cil.h"

void cil_build_ast(struct cil_db **db, struct cil_tree *parse_root)
{
	struct cil_stack *namespace;
	char *namespace_str = NULL;
	cil_stack_init(&namespace);
	__cil_build_ast(db, namespace, namespace_str, parse_root->root, (*db)->ast_root->root);
	free(namespace);
}

void __cil_build_ast(struct cil_db **db, struct cil_stack *namespace, char *namespace_str, struct cil_tree_node *parse_tree, struct cil_tree_node *ast)
{
	struct cil_tree_node *parse_current = parse_tree;
	struct cil_tree_node *ast_current = ast;
	struct cil_tree_node *ast_node;

	if ((parse_current == NULL) || (ast_current == NULL)) {
		printf("Error: NULL tree as parameter\n");
		exit(1);
	}

//	printf("before parse_current->cl_head check\n");
	if (parse_current->cl_head == NULL) {	//This is a leaf node
//		printf("parse_current cl_head is NULL\n");
		if (parse_current->parent->cl_head == parse_current) { //This is the beginning of the line
//			printf("cl_head = parse_current\n");
			//Node values set here
			ast_node = cil_tree_node_init(ast_node);
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
				cil_gen_block(*db, namespace, parse_current, ast_node, 0, 0, NULL);
				cil_get_namespace_str(namespace, &namespace_str);
			}
			else if (!strcmp(parse_current->data, CIL_KEY_CLASS)) {
				cil_gen_class(*db, namespace_str, parse_current, ast_node);
				ast_current = ast_current->parent; //To avoid parsing list of perms again
				return;
			}
			else if (!strcmp(parse_current->data, CIL_KEY_PERM)) {
				ast_node->data = cil_gen_perm(*db, namespace_str, parse_current);
				ast_node->flavor = CIL_PERM;
			}
			else if (!strcmp(parse_current->data, CIL_KEY_COMMON)) {
				ast_node->data = cil_gen_common(*db, namespace_str, parse_current);
				ast_node->flavor = CIL_COMMON;
			}
			else if (!strcmp(parse_current->data, CIL_KEY_SID)) {
				ast_node->data = cil_gen_sid(*db, namespace_str, parse_current);
				ast_node->flavor = CIL_SID;
			}
			else if (!strcmp(parse_current->data, CIL_KEY_TYPE)) {
				ast_node->data = cil_gen_type(*db, namespace_str, parse_current, CIL_TYPE);
				ast_node->flavor = CIL_TYPE; //This is the data structure type (same for both type and attr)
			}
			else if (!strcmp(parse_current->data, CIL_KEY_ATTR)) {
				ast_node->data = cil_gen_type(*db, namespace_str, parse_current, CIL_TYPE_ATTR);
				ast_node->flavor = CIL_TYPE_ATTR;
			}
			else if (!strcmp(parse_current->data, CIL_KEY_TYPEALIAS)) {
				ast_node->data = cil_gen_typealias(*db, namespace_str, parse_current);
				ast_node->flavor = CIL_TYPEALIAS;
			}
			else if (!strcmp(parse_current->data, CIL_KEY_ROLE)) {
				ast_node->data = cil_gen_role(*db, namespace_str, parse_current);
				ast_node->flavor = CIL_ROLE;
			}
			else if (!strcmp(parse_current->data, CIL_KEY_BOOL)) {
				ast_node->data = cil_gen_bool(*db, namespace_str, parse_current);
				ast_node->flavor = CIL_BOOL;
			}
			else if (!strcmp(parse_current->data, CIL_KEY_ALLOW)) {
				printf("new allow: src:%s, tgt:%s\n", (char*)parse_current->next->data, (char*)parse_current->next->next->data);
				ast_node->data = cil_gen_avrule(*db, namespace_str, parse_current, CIL_AVRULE_ALLOWED); 
				ast_node->flavor = CIL_AVRULE;
				ast_current = ast_current->parent;
				return;	//So that the object and perms lists don't get parsed again as potential keywords
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

		return;
	}
}

