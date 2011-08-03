/*
 * Copyright 2011 Tresys Technology, LLC. All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 *    1. Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 * 
 *    2. Redistributions in binary form must reproduce the above copyright notice,
 *       this list of conditions and the following disclaimer in the documentation
 *       and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY TRESYS TECHNOLOGY, LLC ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
 * EVENT SHALL TRESYS TECHNOLOGY, LLC OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 * The views and conclusions contained in the software and documentation are those
 * of the authors and should not be interpreted as representing official policies,
 * either expressed or implied, of Tresys Technology, LLC.
 */

#include <stdio.h>

#include "cil_tree.h"
#include "cil_list.h"
#include "cil.h"
#include "cil_parser.h"

int cil_tree_init(struct cil_tree **tree)
{
	struct cil_tree *new_tree = cil_malloc(sizeof(*new_tree));
	cil_tree_node_init(&new_tree->root);
	
	*tree = new_tree;
	
	return SEPOL_OK;
}

void cil_tree_destroy(struct cil_tree **tree)
{
	cil_tree_subtree_destroy((*tree)->root);
	free(*tree);
	*tree = NULL;
}

void cil_tree_subtree_destroy(struct cil_tree_node *node)
{
	struct cil_tree_node *start_node = node;
	struct cil_tree_node *next = NULL;

	if (node == NULL) {
		return;
	}

	if (node->cl_head != NULL) {
		node = node->cl_head;
	}

	while (node != start_node) {
		//printf("##### node: %d#####\n", (char*)node->flavor);
		if (node->cl_head != NULL){
			next = node->cl_head;
		} else {
			if (node->next == NULL) {
				next = node->parent;
				if (node->parent != NULL) {
					node->parent->cl_head = NULL;
				}
				//printf("Destroying node\n");
				cil_tree_node_destroy(&node);
			} else {
				next = node->next;
				//printf("Destroying node\n");
				cil_tree_node_destroy(&node);
			}
		}
		node = next;
	}

	//Destroy start node
	cil_tree_node_destroy(&node);
}

int cil_tree_node_init(struct cil_tree_node **node)
{
	struct cil_tree_node *new_node = cil_malloc(sizeof(*new_node));
	new_node->cl_head = NULL;
	new_node->cl_tail = NULL;
	new_node->parent = NULL;
	new_node->data = NULL;
	new_node->next = NULL;
	new_node->flavor = CIL_ROOT;
	new_node->line = 0;	

	*node = new_node;

	return SEPOL_OK;
}

void cil_tree_node_destroy(struct cil_tree_node **node)
{
	cil_destroy_data(&(*node)->data, (*node)->flavor);
	free(*node);
	*node = NULL;
}

/* Perform depth-first walk of the tree
   Parameters:
   start_node:          root node to start walking from
   process_node:        function to call when visiting a node
                        Takes parameters:
                            node:     node being visited
                            finished: boolean indicating to the tree walker that it should move on from this branch
                            extra_args:    additional data
   first_child:		Function to call before entering list of children
                        Takes parameters:
                            node:     node of first child
                            extra args:     additional data
   last_child:		Function to call when finished with the last child of a node's children
   extra_args:               any additional data to be passed to the helper functions
*/
int cil_tree_walk(struct cil_tree_node *start_node, int (*process_node)(struct cil_tree_node *node, uint32_t *finished, void *extra_args), int (*first_child)(struct cil_tree_node *node, void *extra_args), int (*last_child)(struct cil_tree_node *node, void *extra_args), void *extra_args)
{
	struct cil_tree_node *node = NULL;
	uint32_t reverse = 0;
	uint32_t finished = 0;
	int rc = SEPOL_ERR;

	if (start_node == NULL) {
		return SEPOL_ERR;
	}

	if (start_node->cl_head == NULL) {
		return SEPOL_OK;
	}

	node = start_node->cl_head;


	if (first_child != NULL) {
		rc = (*first_child)(node, extra_args);
		if (rc != SEPOL_OK) {
			printf("Failed to process first child\n");
			return rc;
		}
	}

	do {
		if (!reverse) {
			if (process_node != NULL) {
				rc = (*process_node)(node, &finished, extra_args);
				if (rc != SEPOL_OK) {
					printf("Failed to process node\n");
					return rc;
				}
			}
		}

		if (node->cl_head != NULL && !reverse && !(finished & CIL_TREE_SKIP_HEAD)) {
			node = node->cl_head;
			if (first_child != NULL) {
				rc = (*first_child)(node, extra_args);
				if (rc != SEPOL_OK) {
					printf("Failed to process first child\n");
					return rc;
				}
			}
			finished = CIL_TREE_SKIP_NOTHING;
		} else if (node->next != NULL && reverse && !(finished & CIL_TREE_SKIP_NEXT)) {
			node = node->next;
			reverse = 0;
			finished = CIL_TREE_SKIP_NOTHING;
		} else if (node->next != NULL && !(finished & CIL_TREE_SKIP_NEXT)) {
			node = node->next;
			finished = CIL_TREE_SKIP_NOTHING;
		} else {
			if (last_child != NULL) {
				rc = (*last_child)(node, extra_args);
				if (rc != SEPOL_OK) {
					printf("Failed to process last child\n");
					return rc;
				}
			}
			node = node->parent;
			reverse = 1;
			finished = CIL_TREE_SKIP_NOTHING;
		}
	} while (node != start_node);
	
	return SEPOL_OK;
}

void cil_tree_print_perms_list(struct cil_tree_node *current_perm)
{
	while (current_perm != NULL) {
		if (current_perm->flavor == CIL_PERM) {
			printf(" %s", ((struct cil_perm *)current_perm->data)->datum.name);
		} else {
			printf("\n\n perms list contained unexpected data type: %d\n", current_perm->flavor);
			break;
		}
		current_perm = current_perm->next;	
	}
}

void cil_tree_print_catrange(struct cil_catrange *catrange)
{
	printf(" (");

	if (catrange->cat_low != NULL) {
		printf(" %s", catrange->cat_low->datum.name);
	} else {
		printf(" %s", catrange->cat_low_str);
	}
	
	if (catrange->cat_high != NULL) {
		printf(" %s", catrange->cat_high->datum.name);
	} else {
		printf(" %s", catrange->cat_high_str);
	}

	printf(" )");

}

void cil_tree_print_catset(struct cil_catset *catset)
{
	struct cil_list_item *cat_item;

	printf(" (");
	if (catset->cat_list != NULL) {
		for (cat_item = catset->cat_list->head; cat_item != NULL; cat_item = cat_item->next) {
			switch (cat_item->flavor) {
			case CIL_CATRANGE:
				cil_tree_print_catrange(cat_item->data);
				break;
			case CIL_CAT: {
				struct cil_cat *cat = cat_item->data;
				printf(" %s", cat->datum.name);
				break;
			}
			default:
				break;
			}
		}
	} else {
		for (cat_item = catset->cat_list_str->head; cat_item != NULL; cat_item = cat_item->next) {
			switch (cat_item->flavor) {
			case CIL_CATRANGE:
				cil_tree_print_catrange(cat_item->data);
				break;
			case CIL_AST_STR: {
				printf(" %s", (char *)cat_item->data);
				break;
			}
			default:
				break;
			}
		}
	}
	printf(" )");
}

void cil_tree_print_level(struct cil_level *level)
{
	if (level->sens != NULL) {
		printf(" %s", level->sens->datum.name);
	} else if (level->sens_str != NULL) {
		printf(" %s", level->sens_str);
	}

	if (level->catset != NULL) {
		cil_tree_print_catset(level->catset);
	} else {
		printf(" %s", level->catset_str);
	}

	return;
}

void cil_tree_print_levelrange(struct cil_levelrange *lvlrange)
{
	printf(" (");
	if (lvlrange->low != NULL) {
		printf(" (");
		cil_tree_print_level(lvlrange->low);
		printf(" )");
	} else if (lvlrange->low_str != NULL) {
		printf(" %s", lvlrange->low_str);
	}

	if (lvlrange->high != NULL) {
		printf(" (");
		cil_tree_print_level(lvlrange->high);
		printf(" )");
	} else if (lvlrange->high_str != NULL) {
		printf(" %s", lvlrange->high_str);
	}
	printf(" )");
}

void cil_tree_print_context(struct cil_context *context)
{
	printf(" (");
	if (context->user != NULL) {
		printf(" %s", context->user->datum.name);
	} else if (context->user_str != NULL) {
		printf(" %s", context->user_str);
	}

	if (context->role != NULL) {
		printf(" %s", context->role->datum.name);
	} else if (context->role_str != NULL) {
		printf(" %s", context->role_str);
	}

	if (context->type != NULL) {
		printf(" %s", context->type->datum.name);
	} else if (context->type_str != NULL) {
		printf(" %s", context->type_str);
	}

	if (context->range != NULL) {
		cil_tree_print_levelrange(context->range);
	} else if (context->range_str != NULL) {
		printf(" %s", context->range_str);
	}

	printf(" )");

	return;
}

void cil_tree_print_constrain(struct cil_constrain *cons)
{
	struct cil_list_item *class_curr = NULL;
	struct cil_list_item *perm_curr = NULL;
	struct cil_list_item *expr_curr = NULL;

	if (cons->class_list != NULL) {
		class_curr = cons->class_list->head;
	} else {
		class_curr = cons->class_list_str->head;
	}

	if (cons->perm_list != NULL) {
		perm_curr = cons->perm_list->head;
	} else {
		perm_curr = cons->perm_list_str->head;
	}

	while (class_curr != NULL) {
		if (cons->class_list != NULL) {
			printf("%s ", ((struct cil_class*)class_curr->data)->datum.name);
		} else {
			printf("%s ", (char*)class_curr->data);
		}
		class_curr = class_curr->next;
	}
	printf(") \n\t\t( ");

	while (perm_curr != NULL) {
		if (cons->perm_list != NULL) {
			printf("%s ", ((struct cil_class*)perm_curr->data)->datum.name);
		} else {
			printf("%s ", (char*)perm_curr->data);
		}
		perm_curr = perm_curr->next;
	}
	printf(") \n\t\t");
	expr_curr = cons->expr->head;
	while (expr_curr != NULL) {
		struct cil_conditional *cond = expr_curr->data;
		if (cond->data != NULL) {
			printf("%s:%i ", ((struct cil_symtab_datum *)cond->data)->name, cond->flavor);
		} else {
			printf("-%s:%i ", cond->str, cond->flavor);
		}
		expr_curr = expr_curr->next;
	}
	printf(")\n");
	printf("\n");
}

void cil_tree_print_node(struct cil_tree_node *node)
{
	if (node->data == NULL) {
		if (node->flavor ==  CIL_CONDTRUE) {
			printf("true\n");
		} else if (node->flavor == CIL_CONDFALSE) {
			printf("false\n");
		} else {
			printf("FLAVOR: %d", node->flavor);
		}

		return;
	} else {
		switch( node->flavor ) {
			case CIL_BLOCK: {
				struct cil_block *block = node->data;
				printf("BLOCK: %s\n", block->datum.name);
				return;
			}
			case CIL_USER: {
				struct cil_user *user = node->data;
				printf("USER: %s\n", user->datum.name);
				return;
			}
			case CIL_TYPE: {
				struct cil_type *type = node->data;
				struct cil_list_item *curr = NULL;
				printf("TYPE: %s", type->datum.name);
				if (type->attrs_list != NULL) {
					curr = type->attrs_list->head;
					printf(" attrs: (");
					while (curr != NULL) {
						printf(" %s ", ((struct cil_attribute*)curr->data)->datum.name);
						curr = curr->next;
					}
					printf(")");
				}
				printf("\n");
				return;
			}
			case CIL_ATTRTYPES: {
				struct cil_attrtypes *attrtypes = node->data;
				struct cil_list_item *curr = NULL;
				printf("ATTRTYPES: attr: %s", attrtypes->attr_str);
				if (attrtypes->types_list_str != NULL) {
					printf(" types list: (");
					curr = attrtypes->types_list_str->head;
					while (curr != NULL) {
						printf(" %s", (char*)curr->data);
						curr = curr->next;
					}
					printf(" )");
				}

				if (attrtypes->neg_list_str != NULL) {
					printf(" neg list: (");
					curr = attrtypes->neg_list_str->head;
					while (curr != NULL) {
						printf(" %s", (char*)curr->data);
						curr = curr->next;
					}
					printf(" )");
				}

				printf("\n");
				return;
			}
			case CIL_ATTR: {
				struct cil_attribute *attr = node->data;
				struct cil_list_item *curr = NULL;
				printf("ATTRIBUTE: %s", attr->datum.name);
				if (attr->types_list != NULL) {
					curr = attr->types_list->head;
					printf(" types: ( ");
					while (curr != NULL) {
						printf("%s ", ((struct cil_type*)curr->data)->datum.name);
						curr = curr->next;
					}
					printf(")");
				}
				if (attr->neg_list != NULL) {
					curr = attr->neg_list->head;
					printf(" neg types: (");
					while (curr != NULL) {
						printf(" %s ", ((struct cil_type*)curr->data)->datum.name);
						curr = curr->next;
					}
					printf(")");
				}
				printf("\n");
				return;
			}
			case CIL_ROLE: {
				struct cil_role *role = node->data;
				printf("ROLE: %s\n", role->datum.name);
				return;
			}
			case CIL_USERROLE: {
				struct cil_userrole *userrole = node->data;
				printf("USERROLE:");

				if (userrole->user != NULL) {
					printf(" %s", userrole->user->datum.name);
				} else if (userrole->user_str != NULL) {
					printf(" %s", userrole->user_str);
				}

				if (userrole->role != NULL) {
					printf(" %s", userrole->role->datum.name);
				} else if (userrole->role_str != NULL) {
					printf(" %s", userrole->role_str);
				}

				printf("\n");
				return;
			}
			case CIL_USERLEVEL: {
				struct cil_userlevel *usrlvl = node->data;
				printf("USERLEVEL:");

				if (usrlvl->user_str != NULL) {
					printf(" %s", usrlvl->user_str);
				}

				if (usrlvl->level != NULL) {
					printf(" (");
					cil_tree_print_level(usrlvl->level);
					printf(" )");
				} else if (usrlvl->level_str != NULL) {
					printf(" %s", usrlvl->level_str);
				}

				printf("\n");
				return;
			}
			case CIL_USERRANGE: {
				struct cil_userrange *userrange = node->data;
				printf("USERRANGE:");

				if (userrange->user_str != NULL) {
					printf(" %s", userrange->user_str);
				}

				if (userrange->range != NULL) {
					printf(" (");
					cil_tree_print_levelrange(userrange->range);
					printf(" )");
				} else if (userrange->range_str != NULL) {
					printf(" %s", userrange->range_str);
				}

				printf("\n");
				return;
			}
			case CIL_USERBOUNDS: {
				struct cil_userbounds *userbnds = node->data;
				printf("USERBOUNDS: user: %s, bounds: %s\n", userbnds->user_str, userbnds->bounds_str);
				return;
			}

			case CIL_ROLETYPE: {
				struct cil_roletype *roletype = node->data;
				printf("ROLETYPE:");

				if (roletype->role != NULL) {
					printf(" %s", roletype->role->datum.name);
				} else if (roletype->role_str != NULL) {
					printf(" %s", roletype->role_str);
				}

				if (roletype->type != NULL) {
					printf(" %s", roletype->type->datum.name);
				} else if (roletype->type_str != NULL) {
					printf(" %s", roletype->type_str);
				}

				printf("\n");
				return;
			}
			case CIL_ROLETRANS: {
				struct cil_role_trans *roletrans = node->data;
				printf("ROLETRANSITION:");

				if (roletrans->src != NULL) {
					printf(" %s", roletrans->src->datum.name);
				} else {
					printf(" %s", roletrans->src_str);
				}

				if (roletrans->tgt != NULL) {
					printf(" %s", roletrans->tgt->datum.name);
				} else {
					printf(" %s", roletrans->tgt_str);
				}
				
				if (roletrans->obj != NULL) {
					printf(" %s", roletrans->obj->datum.name);
				} else {
					printf(" %s", roletrans->obj_str);
				}

				if (roletrans->result != NULL) {
					printf(" %s\n", roletrans->result->datum.name);
				} else {
					printf(" %s\n", roletrans->result_str);
				}

				return;
			}
			case CIL_ROLEALLOW: {
				struct cil_role_allow *roleallow = node->data;
				printf("ROLEALLOW:");

				if (roleallow->src != NULL) {
					printf(" %s", roleallow->src->datum.name);
				} else {
					printf(" %s", roleallow->src_str);
				}

				if (roleallow->tgt != NULL) {
					printf(" %s", roleallow->tgt->datum.name);
				} else {
					printf(" %s", roleallow->tgt_str);
				}

				printf("\n");
				return;
			}
			case CIL_ROLEDOMINANCE: {
				struct cil_roledominance *roledom = node->data;
				printf("ROLEDOMINANCE:");

				if (roledom->role != NULL) {
					printf(" %s", roledom->role->datum.name);
				} else {
					printf(" %s", roledom->role_str);
				}

				if (roledom->domed != NULL) {
					printf(" %s", roledom->domed->datum.name);
				} else {
					printf(" %s", roledom->domed_str);
				}

				printf("\n");
				return;
			}
			case CIL_ROLEBOUNDS: {
				struct cil_rolebounds *rolebnds = node->data;
				printf("ROLEBOUNDS: role: %s, bounds: %s\n", rolebnds->role_str, rolebnds->bounds_str);
				return;
			}
			case CIL_CLASS: {
				struct cil_class *cls = node->data;
				printf("CLASS: %s ", cls->datum.name);
				
				if (cls->common != NULL) {
					printf("inherits: %s ", cls->common->datum.name);
				}
				printf("(");
	
				cil_tree_print_perms_list(node->cl_head);
	
				printf(" )");
				return;
			}
			case CIL_COMMON: {
				struct cil_common *common = node->data;
				printf("COMMON: %s (", common->datum.name);
		
				cil_tree_print_perms_list(node->cl_head);
	
				printf(" )");
				return;
			}
			case CIL_CLASSCOMMON: {
				struct cil_classcommon *clscom = node->data;

				printf("CLASSCOMMON: class: %s, common: %s\n", clscom->class_str, clscom->common_str);

				return;
			}
			case CIL_PERMSET: {
				struct cil_permset *permset = node->data;
				printf("PERMSET: %s", permset->datum.name);

				if (permset->perms_list_str != NULL) {
					printf(" (");
					struct cil_list_item *item = permset->perms_list_str->head;
					while(item != NULL) {
						printf(" %s", (char*)item->data);
						item = item->next;
					}
					printf(" )\n");
				}

				return;
			}
			case CIL_BOOL: {
				struct cil_bool *boolean = node->data;
				printf("BOOL: %s, value: %d\n", boolean->datum.name, boolean->value);
				return;
			}
			case CIL_TUNABLE: {
				struct cil_bool *boolean = node->data;
				printf("TUNABLE: %s, value: %d\n", boolean->datum.name, boolean->value);
				return;
			}
			case CIL_BOOLEANIF: {
				struct cil_booleanif *bif = node->data;
				struct cil_list_item *current = bif->expr_stack->head;
				printf("BOOLEANIF: expression stack: ( ");

				while (current != NULL) {
					struct cil_conditional *cond = current->data;
					if (cond->data != NULL) {
						struct cil_bool *bool = cond->data;
						printf("(bool %s, value: %d) ", bool->datum.name, bool->value);
					} else if (cond->str != NULL) {
						printf("%s ", cond->str);
					}
					current = current->next;
				}

				printf(")\n");
				return;
			}
			case CIL_TUNABLEIF: {
				struct cil_tunableif *tif = node->data;
				struct cil_list_item *current = tif->expr_stack->head;
				printf("TUNABLEIF: expression stack: ( ");

				if (current->flavor != CIL_INT) {
					while (current != NULL && current->data != NULL) {
						struct cil_conditional *cond = current->data;
						if (cond->data != NULL) {
							struct cil_bool *bool = cond->data;
							printf("(tunable %s, value: %d) ", bool->datum.name, bool->value);
						} else if (cond->str != NULL) {
							printf("%s ", cond->str);
						}
						current = current->next;
					}
				} else {
					printf("%d", *(uint16_t*)current->data);
				}

				printf(")\n");
				return;
			}
			case CIL_AND:
				printf("&&");
				return;
			case CIL_OR:
				printf("|| ");
				return;
			case CIL_NOT:
				printf("!");
				return;
			case CIL_EQ:
				printf("==");
				return;
			case CIL_NEQ:
				printf("!=");
				return;
			case CIL_TYPEALIAS: {
				struct cil_typealias *alias = node->data;

				if (alias->type != NULL) {
					printf("TYPEALIAS: %s, type: %s\n", alias->datum.name, alias->type->datum.name);
				} else {
					printf("TYPEALIAS: %s, type: %s\n", alias->datum.name, alias->type_str);
				}

				return;
			}
			case CIL_TYPEBOUNDS: {
				struct cil_typebounds *typebnds = node->data;
				printf("TYPEBOUNDS: type: %s, bounds: %s\n", typebnds->type_str, typebnds->bounds_str);
				return;
			}
			case CIL_TYPEPERMISSIVE: {
				struct cil_typepermissive *typeperm = node->data;

				if (typeperm->type != NULL) {
					printf("TYPEPERMISSIVE: %s\n", typeperm->type->datum.name);
				} else {
					printf("TYPEPERMISSIVE: %s\n", typeperm->type_str);
				}

				return;
			}
			case CIL_FILETRANSITION: {
				struct cil_filetransition *filetrans = node->data;
				printf("FILETRANSITION:");

				if (filetrans->src != NULL) {
					printf(" %s", filetrans->src->datum.name);
				} else {
					printf(" %s", filetrans->src_str);
				}

				if (filetrans->exec != NULL) {
					printf(" %s", filetrans->exec->datum.name);
				} else {
					printf(" %s", filetrans->exec_str);
				}

				if (filetrans->proc != NULL) {
					printf(" %s", filetrans->proc->datum.name);
				} else {
					printf(" %s", filetrans->proc_str);
				}

				printf(" %s\n", filetrans->path_str);
				return;
			}
			case CIL_RANGETRANSITION: {
				struct cil_rangetransition *rangetrans = node->data;
				printf("RANGETRANSITION:");

				if (rangetrans->src != NULL) {
					printf(" %s", rangetrans->src->datum.name);
				} else {
					printf(" %s", rangetrans->src_str);
				}

				if (rangetrans->exec != NULL) {
					printf(" %s", rangetrans->exec->datum.name);
				} else {
					printf(" %s", rangetrans->exec_str);
				}

				if (rangetrans->obj != NULL) {
					printf(" %s", rangetrans->obj->datum.name);
				} else {
					printf(" %s", rangetrans->obj_str);
				}

				if (rangetrans->range != NULL) {
					printf(" (");
					cil_tree_print_levelrange(rangetrans->range);
					printf(" )");
				} else {
					printf(" %s", rangetrans->range_str);
				}

				printf("\n");
				return;
			}
			case CIL_AVRULE: {
				struct cil_avrule *rule = node->data;
				struct cil_list_item *item = NULL;
				switch (rule->rule_kind) {
					case CIL_AVRULE_ALLOWED:
						printf("ALLOW:");
						break;
					case CIL_AVRULE_AUDITALLOW:
						printf("AUDITALLOW:");
						break;
					case CIL_AVRULE_DONTAUDIT:
						printf("DONTAUDIT:");
						break;
					case CIL_AVRULE_NEVERALLOW:
						printf("NEVERALLOW:");
						break;
				}

				if (rule->src != NULL) {
					printf(" %s", ((struct cil_symtab_datum*)rule->src)->name);
				} else {
					printf(" %s", rule->src_str);
				}

				if (rule->tgt != NULL) {
					printf(" %s", ((struct cil_symtab_datum*)rule->tgt)->name);
				} else {
					printf(" %s", rule->tgt_str);
				}

				if (rule->obj != NULL) {
					printf(" %s", rule->obj->datum.name);
				} else {
					printf(" %s", rule->obj_str);
				}

				if (rule->perms_list != NULL) {
					printf(" (");
					item = rule->perms_list->head;
					while(item != NULL) {
						if (item->flavor == CIL_PERM) {
							printf(" %s", ((struct cil_perm*)item->data)->datum.name);
						} else {
							printf("\n\n perms list contained unexpected data type\n");
							break;
						}
						item = item->next;
					}
					printf(" )\n");
				} else if (rule->perms_list_str != NULL) {
					printf(" (");
					item = rule->perms_list_str->head;
					while(item != NULL) {
						if (item->flavor == CIL_AST_STR) {
							printf(" %s", (char*)item->data);
						} else {
							printf("\n\n perms list contained unexpected data type\n");
							break;
						}
						item = item->next;
					}
					printf(" )\n");
				} else if (rule->permset_str != NULL) {
					printf(" permset: %s", rule->permset_str);
				}

				return;
			}
			case CIL_TYPE_RULE: {
				struct cil_type_rule *rule = node->data;
				switch (rule->rule_kind) {
					case CIL_TYPE_TRANSITION:
						printf("TYPETRANSITION:");
						break;
					case CIL_TYPE_MEMBER:
						printf("TYPEMEMBER:");
						break;
					case CIL_TYPE_CHANGE:
						printf("TYPECHANGE:");
						break;
				}

				if (rule->src != NULL) {
					printf(" %s", rule->src->datum.name);
				} else {
					printf(" %s", rule->src_str);
				}

				if (rule->tgt != NULL) {
					printf(" %s", rule->tgt->datum.name);
				} else {
					printf(" %s", rule->tgt_str);
				}

				if (rule->obj != NULL) {
					printf(" %s", rule->obj->datum.name);
				} else {
					printf(" %s", rule->obj_str);
				}

				if (rule->result != NULL) {
					printf(" %s\n", rule->result->datum.name);
				} else {
					printf(" %s\n", rule->result_str);
				}

				return;
			}
			case CIL_SENS: {
				struct cil_sens *sens = node->data;
				printf("SENSITIVITY: %s\n", sens->datum.name);
				return;
			}
			case CIL_SENSALIAS: {
				struct cil_sensalias *alias = node->data;
				if (alias->sens != NULL) {
					printf("SENSITIVITYALIAS: %s, sensitivity: %s\n", alias->datum.name, alias->sens->datum.name);
				} else {
					printf("SENSITIVITYALIAS: %s, sensitivity: %s\n", alias->datum.name, alias->sens_str);
				}

				return;
			}
			case CIL_CAT: {
				struct cil_cat *cat = node->data;
				printf("CATEGORY: %s\n", cat->datum.name);
				return;
			}
			case CIL_CATALIAS: {
				struct cil_catalias *alias = node->data;

				if (alias->cat != NULL) {
					printf("CATEGORYALIAS: %s, category: %s\n", alias->datum.name, alias->cat->datum.name);
				} else {
					printf("CATEGORYALIAS: %s, category: %s\n", alias->datum.name, alias->cat_str);
				}

				return;
			}
			case CIL_CATSET: {
				struct cil_catset *catset = node->data;
				struct cil_list_item *cat = NULL;
				struct cil_list_item *parent = NULL;

				printf("CATSET: %s (",catset->datum.name);

				if (catset->cat_list != NULL) {
					cat = catset->cat_list->head;
				} else {
					cat = catset->cat_list_str->head;
				}

				while (cat != NULL) {
					if (cat->flavor == CIL_LIST) {
						parent = cat;
						cat = ((struct cil_list*)cat->data)->head;
						printf(" (");
						while (cat != NULL) {
							printf(" %s", ((struct cil_cat*)cat->data)->datum.name);
							cat = cat->next;
						}
						printf(" )");
						cat = parent;
					} else {
						printf(" %s", ((struct cil_cat*)cat->data)->datum.name);
					}
					cat = cat->next;
				}

				printf(" )\n");
				return;
			}
			case CIL_CATORDER: {
				struct cil_catorder *catorder = node->data;
				struct cil_list_item *cat = NULL;

				printf("CATORDER: (");

				if (catorder->cat_list_str != NULL) {
					cat = catorder->cat_list_str->head;
				} else {
					return;
				}

				while (cat != NULL) {
					printf(" %s", (char*)cat->data);
					cat = cat->next;
				}

				printf(" )\n");
				return;
			}
			case CIL_SENSCAT: {
				struct cil_senscat *senscat = node->data;

				printf("SENSCAT: sens:");

				if (senscat->sens_str != NULL) {
					printf(" %s ", senscat->sens_str);
				} else {
					printf(" [processed]");
				}

				if (senscat->catset != NULL) {
					cil_tree_print_catset(senscat->catset);
				} else {
					printf(" %s", senscat->catset_str);
				}

				printf(" )\n");
				return;
			}
			case CIL_DOMINANCE: {
				struct cil_sens_dominates *dom = node->data;
				struct cil_list_item *sens = NULL;
				struct cil_list_item *parent = NULL;

				printf("DOMINANCE: (");

				if (dom->sens_list_str != NULL) {
					sens = dom->sens_list_str->head;
					while(sens != NULL) {
						if (sens->flavor == CIL_LIST) {
							parent = sens;
							sens = ((struct cil_list*)sens->data)->head;
							printf(" (");
							while (sens != NULL) {
								printf(" %s", (char*)sens->data);
								sens = sens->next;
							}
							printf(" )");
							sens = parent;
						} else {
							printf(" %s", (char*)sens->data);
						}
						sens = sens->next;
					}
				} else {
					printf("\n");
					return;
				}

				printf(" )\n");
				return;
			}
			case CIL_LEVEL: {
				struct cil_level *level = node->data;
				printf("LEVEL %s:", level->datum.name); 
				cil_tree_print_level(level);
				printf("\n");
				return;
			}
			case CIL_LEVELRANGE: {
				struct cil_levelrange *lvlrange = node->data;
				printf("LEVELRANGE %s:", lvlrange->datum.name);
				cil_tree_print_levelrange(lvlrange);
				printf("\n");
				return;
			}
			case CIL_CONSTRAIN: {
				struct cil_constrain *cons = node->data;
				printf("CONSTRAIN: \n\t(");
				cil_tree_print_constrain(cons);
				return;
			}
			case CIL_MLSCONSTRAIN: {
				struct cil_constrain *cons = node->data;
				printf("MLSCONSTRAIN: \n\t(");
				cil_tree_print_constrain(cons);
				return;
			}
			case CIL_CONTEXT: {
				struct cil_context *context = node->data;
				printf("CONTEXT %s:", context->datum.name);
				cil_tree_print_context(context);
				printf("\n");
				return;
			}
			case CIL_FILECON: {
				struct cil_filecon *filecon = node->data;
				printf("FILECON:");
				printf(" %s %s %d", filecon->root_str, filecon->path_str, filecon->type);

				if (filecon->context_str != NULL) {
					printf(" %s", filecon->context_str);
				} else if (filecon->context != NULL) {
					cil_tree_print_context(filecon->context);
				} else if (filecon->context_str != NULL) {
					printf(" %s", filecon->context_str);
				}

				printf("\n");
				return;

			}
			case CIL_PORTCON: {
				struct cil_portcon *portcon = node->data;
				printf("PORTCON:");
				printf(" %s (%d %d)", portcon->type_str, portcon->port_low, portcon->port_high);

				if (portcon->context != NULL) {
					cil_tree_print_context(portcon->context);
				} else if (portcon->context_str != NULL) {
					printf(" %s", portcon->context_str);
				}

				printf("\n");
				return;
			}
			case CIL_NODECON: {
				struct cil_nodecon *nodecon = node->data;
				char buf[256];
				
				printf("NODECON:");
				
				if (nodecon->addr) {
					inet_ntop(nodecon->addr->family, &nodecon->addr->ip, buf, 256);
					printf(" %s", buf);
				}  else {
					printf(" %s", nodecon->addr_str);
				}

				if (nodecon->mask) {
					inet_ntop(nodecon->mask->family, &nodecon->mask->ip, buf, 256);
					printf(" %s", buf);
				} else {
					printf(" %s", nodecon->mask_str);
				}
				
				if (nodecon->context != NULL) {
					cil_tree_print_context(nodecon->context);
				} else if (nodecon->context_str != NULL) {
					printf(" %s", nodecon->context_str);
				}

				printf("\n");
				return;
			}
			case CIL_GENFSCON: {
				struct cil_genfscon *genfscon = node->data;
				printf("GENFSCON:");
				printf(" %s %s", genfscon->type_str, genfscon->path_str);

				if (genfscon->context != NULL) {
					cil_tree_print_context(genfscon->context);
				} else if (genfscon->context_str != NULL) {
					printf(" %s", genfscon->context_str);
				}

				printf("\n");
				return;
			}
			case CIL_NETIFCON: {
				struct cil_netifcon *netifcon = node->data;
				printf("NETIFCON %s", netifcon->interface_str);

				if (netifcon->if_context != NULL) {
					cil_tree_print_context(netifcon->if_context);
				} else if (netifcon->if_context_str != NULL) {
					printf(" %s", netifcon->if_context_str);
				}

				if (netifcon->packet_context != NULL) {
					cil_tree_print_context(netifcon->packet_context);
				} else if (netifcon->packet_context_str != NULL) {
					printf(" %s", netifcon->packet_context_str);
				}

				printf("\n");
				return;
			}
			case CIL_PIRQCON: {
				struct cil_pirqcon *pirqcon = node->data;

				printf("PIRQCON %d", pirqcon->pirq);
				if (pirqcon->context != NULL) {
					cil_tree_print_context(pirqcon->context);
				} else {
					printf(" %s", pirqcon->context_str);
				}

				printf("\n");
				return;
			}
			case CIL_IOMEMCON: {
				struct cil_iomemcon *iomemcon = node->data;

				printf("IOMEMCON ( %d %d )", iomemcon->iomem_low, iomemcon->iomem_high);
				if (iomemcon->context != NULL) {
					cil_tree_print_context(iomemcon->context);
				} else {
					printf(" %s", iomemcon->context_str);
				}

				printf("\n");
				return;
			}
			case CIL_IOPORTCON: {
				struct cil_ioportcon *ioportcon = node->data;

				printf("IOPORTCON ( %d %d )", ioportcon->ioport_low, ioportcon->ioport_high);
				if (ioportcon->context != NULL) {
					cil_tree_print_context(ioportcon->context);
				} else {
					printf(" %s", ioportcon->context_str);
				}

				printf("\n");
				return;
			}
			case CIL_PCIDEVICECON: {
				struct cil_pcidevicecon *pcidevicecon = node->data;

				printf("PCIDEVICECON %d", pcidevicecon->dev);
				if (pcidevicecon->context != NULL) {
					cil_tree_print_context(pcidevicecon->context);
				} else {
					printf(" %s", pcidevicecon->context_str);
				}

				printf("\n");
				return;
			}
			case CIL_FSUSE: {
				struct cil_fsuse *fsuse = node->data;
				printf("FSUSE: ");

				if (fsuse->type == CIL_FSUSE_XATTR) {
					printf("xattr ");
				} else if (fsuse->type == CIL_FSUSE_TASK) {
					printf("task ");
				} else if (fsuse->type == CIL_FSUSE_TRANS) {
					printf("trans ");
				} else {
					printf("unknown ");
				}

				printf("%s ", fsuse->fs_str);

				if (fsuse->context != NULL) {
					cil_tree_print_context(fsuse->context);
				} else {
					printf(" %s", fsuse->context_str);
				}

				printf("\n");
				return;
			}
			case CIL_SID: {
				struct cil_sid *sid = node->data;
				printf("SID: %s\n", sid->datum.name);
				return;
			}
			case CIL_SIDCONTEXT: {
				struct cil_sidcontext *sidcon = node->data;
				printf("SIDCONTEXT:");

				if (sidcon->sid != NULL) {
					printf(" %s", (((struct cil_sid*)sidcon->sid)->datum.name));
				} else {
					printf(" %s", sidcon->sid_str);
				}

				if (sidcon->context != NULL) {
					cil_tree_print_context(sidcon->context);
				} else {
					printf(" %s", sidcon->context_str);
				}

				printf("\n");
				return;
			}
			case CIL_POLICYCAP: {
				struct cil_policycap *polcap = node->data;
				printf("POLICYCAP: %s\n", polcap->datum.name);
				return;
			}
			case CIL_MACRO: {
				struct cil_macro *macro = node->data;
				printf("MACRO %s:", macro->datum.name);

				if (macro->params != NULL && macro->params->head != NULL) {
					struct cil_list_item *curr_param = macro->params->head;
					printf(" parameters: (");
					while (curr_param != NULL) {
						printf(" flavor: %d, string: %s;", ((struct cil_param*)curr_param->data)->flavor, ((struct cil_param*)curr_param->data)->str);

						curr_param = curr_param->next;
					}
					printf(" )");
				}
				printf("\n");

				return;
			}
			case CIL_CALL: {
				struct cil_call *call = node->data;
				printf("CALL: macro name:");

				if (call->macro != NULL) {
					printf(" %s", call->macro->datum.name);
				} else {
					printf(" %s", call->macro_str);
				}

				if (call->args != NULL) {
					printf(", args: ( ");
					struct cil_list_item *item = call->args->head;
					while(item != NULL) {
						if (((struct cil_args*)item->data)->arg != NULL) {
							cil_tree_print_node(((struct cil_args*)item->data)->arg);
						} else if (((struct cil_args*)item->data)->arg_str != NULL) {
							switch (item->flavor) {
							case CIL_TYPE: printf("type:"); break;
							case CIL_USER: printf("user:"); break;
							case CIL_ROLE: printf("role:"); break;
							case CIL_SENS: printf("sensitivity:"); break;
							case CIL_CAT: printf("category:"); break;
							case CIL_CATSET: printf("categoryset:"); break;
							case CIL_LEVEL: printf("level:"); break;
							case CIL_CLASS: printf("class:"); break;
							}
							printf("%s ", ((struct cil_args*)item->data)->arg_str);
						}
						item = item->next;
					}
					printf(")");
				}

				printf("\n");
				return;
			}	
			case CIL_OPTIONAL: {
				struct cil_optional *optional = node->data;
				printf("OPTIONAL: %s", optional->datum.name);
				return;
			}
			case CIL_IPADDR: {
				struct cil_ipaddr *ipaddr = node->data;
				char buf[256];

				inet_ntop(ipaddr->family, &ipaddr->ip, buf, 256);
				printf("IPADDR %s: %s\n", ipaddr->datum.name, buf);

				break;
			}
			default : {
				printf("CIL FLAVOR: %d\n", node->flavor);
				return;
			}
		}
	}
}

void cil_tree_print(struct cil_tree_node *tree, uint32_t depth)
{
	struct cil_tree_node *current = NULL;
	current = tree;
	uint32_t x = 0;

	if (current != NULL) {
		if (current->cl_head == NULL) {
			if (current->flavor == CIL_PARSE_NODE) {
				if (current->parent->cl_head == current) {
					printf("%s", (char*)current->data);
				} else {
					printf(" %s", (char*)current->data);
				}
			} else if (current->flavor != CIL_PERM) {
				for (x = 0; x<depth; x++) {
					printf("\t");
				}
				cil_tree_print_node(current);
			}
		} else {
			if (current->parent != NULL) {
				printf("\n");
				for (x = 0; x<depth; x++) {
					printf("\t");
				}
				printf("(");

				if (current->flavor != CIL_PARSE_NODE) {
					cil_tree_print_node(current);
				}
			}
			cil_tree_print(current->cl_head, depth + 1);
		}

		if (current->next == NULL) {
			if ((current->parent != NULL) && (current->parent->cl_tail == current) && (current->parent->parent != NULL)) {
				if (current->flavor == CIL_PERM) {
					printf(")\n");
				} else if (current->flavor != CIL_PARSE_NODE) {
					for (x = 0; x<depth-1; x++) {
						printf("\t");
					}
					printf(")\n");
				} else {
					printf(")");
				}
			}

			if ((current->parent != NULL) && (current->parent->parent == NULL))
				printf("\n\n");
		} else {
//			printf("cil_tree_print: current->next is not null\n");
			cil_tree_print(current->next, depth);
		}
	} else {
		printf("Tree is NULL\n");
	}
}
