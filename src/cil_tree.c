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

#include "cil.h"
#include "cil_log.h"
#include "cil_tree.h"
#include "cil_list.h"
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
		if (node->cl_head != NULL){
			next = node->cl_head;
		} else {
			if (node->next == NULL) {
				next = node->parent;
				if (node->parent != NULL) {
					node->parent->cl_head = NULL;
				}
				cil_tree_node_destroy(&node);
			} else {
				next = node->next;
				cil_tree_node_destroy(&node);
			}
		}
		node = next;
	}

	// Destroy start node
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
	new_node->path = NULL;

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
			cil_log(CIL_INFO, "Failed to process first child\n");
			return rc;
		}
	}

	do {
		if (!reverse) {
			if (process_node != NULL) {
				rc = (*process_node)(node, &finished, extra_args);
				if (rc != SEPOL_OK) {
					cil_log(CIL_INFO, "Failed to process node\n");
					return rc;
				}
			}
		}

		if (node->cl_head != NULL && !reverse && !(finished & CIL_TREE_SKIP_HEAD)) {
			node = node->cl_head;
			if (first_child != NULL) {
				rc = (*first_child)(node, extra_args);
				if (rc != SEPOL_OK) {
					cil_log(CIL_INFO, "Failed to process first child\n");
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
					cil_log(CIL_INFO, "Failed to process last child\n");
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
			cil_log(CIL_INFO, " %s", ((struct cil_perm *)current_perm->data)->datum.name);
		} else if (current_perm->flavor == CIL_CLASSMAPPERM) {
			cil_log(CIL_INFO, " %s", ((struct cil_classmap_perm*)current_perm->data)->datum.name);
		} else {
			cil_log(CIL_INFO, "\n\n perms list contained unexpected data type: %d\n", current_perm->flavor);
			break;
		}
		current_perm = current_perm->next;	
	}
}

void cil_tree_print_catrange(struct cil_catrange *catrange)
{
	cil_log(CIL_INFO, " (");

	if (catrange->cat_low != NULL) {
		cil_log(CIL_INFO, " %s", catrange->cat_low->datum.name);
	} else {
		cil_log(CIL_INFO, " %s", catrange->cat_low_str);
	}
	
	if (catrange->cat_high != NULL) {
		cil_log(CIL_INFO, " %s", catrange->cat_high->datum.name);
	} else {
		cil_log(CIL_INFO, " %s", catrange->cat_high_str);
	}

	cil_log(CIL_INFO, " )");

}

void cil_tree_print_catset(struct cil_catset *catset)
{
	struct cil_list_item *cat_item;

	cil_log(CIL_INFO, " (");
	if (catset->cat_list != NULL) {
		for (cat_item = catset->cat_list->head; cat_item != NULL; cat_item = cat_item->next) {
			switch (cat_item->flavor) {
			case CIL_CATRANGE:
				cil_tree_print_catrange(cat_item->data);
				break;
			case CIL_CAT: {
				struct cil_cat *cat = cat_item->data;
				cil_log(CIL_INFO, " %s", cat->datum.name);
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
				cil_log(CIL_INFO, " %s", (char *)cat_item->data);
				break;
			}
			default:
				break;
			}
		}
	}
	cil_log(CIL_INFO, " )");
}

void cil_tree_print_permset(struct cil_permset *permset)
{
	struct cil_list_item *curr = NULL;

	if (permset == NULL) {
		return;
	}

	if (permset->perms_list_str != NULL) {
		curr = permset->perms_list_str->head;

		cil_log(CIL_INFO, " (");

		while (curr != NULL) {
			cil_log(CIL_INFO, " %s", (char*)curr->data);
			curr = curr->next;
		}

		cil_log(CIL_INFO, " )");
	}
}

void cil_tree_print_classpermset(struct cil_classpermset *cps)
{
	if (cps == NULL) {
		return;
	}

	if (cps->class == NULL) {
		cil_log(CIL_INFO, " class: %s", cps->class_str);
	} else {
		if (cps->flavor == CIL_CLASS) {
			cil_log(CIL_INFO, " class: %s", ((struct cil_class*)cps->class)->datum.name);
		} else {
			cil_log(CIL_INFO, " classmap: %s", ((struct cil_classmap*)cps->class)->datum.name);
		}
	}

	cil_log(CIL_INFO, ", permset:");
	if (cps->permset != NULL) {
		cil_tree_print_permset(cps->permset);
	} else {
		cil_log(CIL_INFO, " %s", cps->permset_str);
	}
}

void cil_tree_print_level(struct cil_level *level)
{
	if (level->sens != NULL) {
		cil_log(CIL_INFO, " %s", level->sens->datum.name);
	} else if (level->sens_str != NULL) {
		cil_log(CIL_INFO, " %s", level->sens_str);
	}

	if (level->catset != NULL) {
		cil_tree_print_catset(level->catset);
	} else {
		cil_log(CIL_INFO, " %s", level->catset_str);
	}

	return;
}

void cil_tree_print_levelrange(struct cil_levelrange *lvlrange)
{
	cil_log(CIL_INFO, " (");
	if (lvlrange->low != NULL) {
		cil_log(CIL_INFO, " (");
		cil_tree_print_level(lvlrange->low);
		cil_log(CIL_INFO, " )");
	} else if (lvlrange->low_str != NULL) {
		cil_log(CIL_INFO, " %s", lvlrange->low_str);
	}

	if (lvlrange->high != NULL) {
		cil_log(CIL_INFO, " (");
		cil_tree_print_level(lvlrange->high);
		cil_log(CIL_INFO, " )");
	} else if (lvlrange->high_str != NULL) {
		cil_log(CIL_INFO, " %s", lvlrange->high_str);
	}
	cil_log(CIL_INFO, " )");
}

void cil_tree_print_context(struct cil_context *context)
{
	cil_log(CIL_INFO, " (");
	if (context->user != NULL) {
		cil_log(CIL_INFO, " %s", context->user->datum.name);
	} else if (context->user_str != NULL) {
		cil_log(CIL_INFO, " %s", context->user_str);
	}

	if (context->role != NULL) {
		cil_log(CIL_INFO, " %s", context->role->datum.name);
	} else if (context->role_str != NULL) {
		cil_log(CIL_INFO, " %s", context->role_str);
	}

	if (context->type != NULL) {
		cil_log(CIL_INFO, " %s", ((struct cil_symtab_datum *)context->type)->name);
	} else if (context->type_str != NULL) {
		cil_log(CIL_INFO, " %s", context->type_str);
	}

	if (context->range != NULL) {
		cil_tree_print_levelrange(context->range);
	} else if (context->range_str != NULL) {
		cil_log(CIL_INFO, " %s", context->range_str);
	}

	cil_log(CIL_INFO, " )");

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
			cil_log(CIL_INFO, "%s ", ((struct cil_class*)class_curr->data)->datum.name);
		} else {
			cil_log(CIL_INFO, "%s ", (char*)class_curr->data);
		}
		class_curr = class_curr->next;
	}
	cil_log(CIL_INFO, ") \n\t\t( ");

	while (perm_curr != NULL) {
		if (cons->perm_list != NULL) {
			cil_log(CIL_INFO, "%s ", ((struct cil_class*)perm_curr->data)->datum.name);
		} else {
			cil_log(CIL_INFO, "%s ", (char*)perm_curr->data);
		}
		perm_curr = perm_curr->next;
	}
	cil_log(CIL_INFO, ") \n\t\t");
	expr_curr = cons->expr->head;
	while (expr_curr != NULL) {
		struct cil_conditional *cond = expr_curr->data;
		if (cond->data != NULL) {
			cil_log(CIL_INFO, "%s:%i ", ((struct cil_symtab_datum *)cond->data)->name, cond->flavor);
		} else {
			cil_log(CIL_INFO, "-%s:%i ", cond->str, cond->flavor);
		}
		expr_curr = expr_curr->next;
	}
	cil_log(CIL_INFO, ")\n");
	cil_log(CIL_INFO, "\n");
}

void cil_tree_print_node(struct cil_tree_node *node)
{
	if (node->data == NULL) {
		if (node->flavor ==  CIL_CONDTRUE) {
			cil_log(CIL_INFO, "true\n");
		} else if (node->flavor == CIL_CONDFALSE) {
			cil_log(CIL_INFO, "false\n");
		} else {
			cil_log(CIL_INFO, "FLAVOR: %d", node->flavor);
		}

		return;
	} else {
		switch( node->flavor ) {
			case CIL_BLOCK: {
				struct cil_block *block = node->data;
				cil_log(CIL_INFO, "BLOCK: %s\n", block->datum.name);
				return;
			}
			case CIL_BLOCKINHERIT: {
				struct cil_blockinherit *inherit = node->data;
				cil_log(CIL_INFO, "BLOCKINHERIT: %s\n", inherit->block_str);
				return;
			}
			case CIL_USER: {
				struct cil_user *user = node->data;
				cil_log(CIL_INFO, "USER: %s\n", user->datum.name);
				return;
			}
			case CIL_TYPE: {
				struct cil_type *type = node->data;
				cil_log(CIL_INFO, "TYPE: %s\n", type->datum.name);
				return;
			}
			case CIL_TYPEATTRIBUTETYPES: {
				struct cil_typeattributetypes *attrtypes = node->data;
				struct cil_list_item *curr = NULL;
				cil_log(CIL_INFO, "TYPEATTRIBUTETYPES: attr: %s", attrtypes->attr_str);
				if (attrtypes->types_list_str != NULL) {
					cil_log(CIL_INFO, " types list: (");
					curr = attrtypes->types_list_str->head;
					while (curr != NULL) {
						cil_log(CIL_INFO, " %s", (char*)curr->data);
						curr = curr->next;
					}
					cil_log(CIL_INFO, " )");
				}

				if (attrtypes->neg_list_str != NULL) {
					cil_log(CIL_INFO, " neg list: (");
					curr = attrtypes->neg_list_str->head;
					while (curr != NULL) {
						cil_log(CIL_INFO, " %s", (char*)curr->data);
						curr = curr->next;
					}
					cil_log(CIL_INFO, " )");
				}

				cil_log(CIL_INFO, "\n");
				return;
			}
			case CIL_TYPEATTRIBUTE: {
				struct cil_typeattribute *attr = node->data;
				struct cil_list_item *curr = NULL;
				cil_log(CIL_INFO, "TYPEATTRIBUTE: %s", attr->datum.name);
				if (attr->types_list != NULL) {
					curr = attr->types_list->head;
					cil_log(CIL_INFO, " types: ( ");
					while (curr != NULL) {
						cil_log(CIL_INFO, "%s ", ((struct cil_symtab_datum *)curr->data)->name);
						curr = curr->next;
					}
					cil_log(CIL_INFO, ")");
				}
				if (attr->neg_list != NULL) {
					curr = attr->neg_list->head;
					cil_log(CIL_INFO, " neg types: (");
					while (curr != NULL) {
						cil_log(CIL_INFO, " %s ", ((struct cil_symtab_datum *)curr->data)->name);
						curr = curr->next;
					}
					cil_log(CIL_INFO, ")");
				}
				cil_log(CIL_INFO, "\n");
				return;
			}
			case CIL_ROLE: {
				struct cil_role *role = node->data;
				cil_log(CIL_INFO, "ROLE: %s\n", role->datum.name);
				return;
			}
			case CIL_USERROLE: {
				struct cil_userrole *userrole = node->data;
				cil_log(CIL_INFO, "USERROLE:");

				if (userrole->user != NULL) {
					cil_log(CIL_INFO, " %s", userrole->user->datum.name);
				} else if (userrole->user_str != NULL) {
					cil_log(CIL_INFO, " %s", userrole->user_str);
				}

				if (userrole->role != NULL) {
					cil_log(CIL_INFO, " %s", userrole->role->datum.name);
				} else if (userrole->role_str != NULL) {
					cil_log(CIL_INFO, " %s", userrole->role_str);
				}

				cil_log(CIL_INFO, "\n");
				return;
			}
			case CIL_USERLEVEL: {
				struct cil_userlevel *usrlvl = node->data;
				cil_log(CIL_INFO, "USERLEVEL:");

				if (usrlvl->user_str != NULL) {
					cil_log(CIL_INFO, " %s", usrlvl->user_str);
				}

				if (usrlvl->level != NULL) {
					cil_log(CIL_INFO, " (");
					cil_tree_print_level(usrlvl->level);
					cil_log(CIL_INFO, " )");
				} else if (usrlvl->level_str != NULL) {
					cil_log(CIL_INFO, " %s", usrlvl->level_str);
				}

				cil_log(CIL_INFO, "\n");
				return;
			}
			case CIL_USERRANGE: {
				struct cil_userrange *userrange = node->data;
				cil_log(CIL_INFO, "USERRANGE:");

				if (userrange->user_str != NULL) {
					cil_log(CIL_INFO, " %s", userrange->user_str);
				}

				if (userrange->range != NULL) {
					cil_log(CIL_INFO, " (");
					cil_tree_print_levelrange(userrange->range);
					cil_log(CIL_INFO, " )");
				} else if (userrange->range_str != NULL) {
					cil_log(CIL_INFO, " %s", userrange->range_str);
				}

				cil_log(CIL_INFO, "\n");
				return;
			}
			case CIL_USERBOUNDS: {
				struct cil_userbounds *userbnds = node->data;
				cil_log(CIL_INFO, "USERBOUNDS: user: %s, bounds: %s\n", userbnds->user_str, userbnds->bounds_str);
				return;
			}

			case CIL_ROLETYPE: {
				struct cil_roletype *roletype = node->data;
				cil_log(CIL_INFO, "ROLETYPE:");

				if (roletype->role != NULL) {
					cil_log(CIL_INFO, " %s", roletype->role->datum.name);
				} else if (roletype->role_str != NULL) {
					cil_log(CIL_INFO, " %s", roletype->role_str);
				}

				if (roletype->type != NULL) {
					cil_log(CIL_INFO, " %s", ((struct cil_symtab_datum *)roletype->type)->name);
				} else if (roletype->type_str != NULL) {
					cil_log(CIL_INFO, " %s", roletype->type_str);
				}

				cil_log(CIL_INFO, "\n");
				return;
			}
			case CIL_ROLETRANSITION: {
				struct cil_roletransition *roletrans = node->data;
				cil_log(CIL_INFO, "ROLETRANSITION:");

				if (roletrans->src != NULL) {
					cil_log(CIL_INFO, " %s", roletrans->src->datum.name);
				} else {
					cil_log(CIL_INFO, " %s", roletrans->src_str);
				}

				if (roletrans->tgt != NULL) {
					cil_log(CIL_INFO, " %s", ((struct cil_symtab_datum *)roletrans->tgt)->name);
				} else {
					cil_log(CIL_INFO, " %s", roletrans->tgt_str);
				}
				
				if (roletrans->obj != NULL) {
					cil_log(CIL_INFO, " %s", roletrans->obj->datum.name);
				} else {
					cil_log(CIL_INFO, " %s", roletrans->obj_str);
				}

				if (roletrans->result != NULL) {
					cil_log(CIL_INFO, " %s\n", roletrans->result->datum.name);
				} else {
					cil_log(CIL_INFO, " %s\n", roletrans->result_str);
				}

				return;
			}
			case CIL_ROLEALLOW: {
				struct cil_roleallow *roleallow = node->data;
				cil_log(CIL_INFO, "ROLEALLOW:");

				if (roleallow->src != NULL) {
					cil_log(CIL_INFO, " %s", roleallow->src->datum.name);
				} else {
					cil_log(CIL_INFO, " %s", roleallow->src_str);
				}

				if (roleallow->tgt != NULL) {
					cil_log(CIL_INFO, " %s", roleallow->tgt->datum.name);
				} else {
					cil_log(CIL_INFO, " %s", roleallow->tgt_str);
				}

				cil_log(CIL_INFO, "\n");
				return;
			}
			case CIL_ROLEDOMINANCE: {
				struct cil_roledominance *roledom = node->data;
				cil_log(CIL_INFO, "ROLEDOMINANCE:");

				if (roledom->role != NULL) {
					cil_log(CIL_INFO, " %s", roledom->role->datum.name);
				} else {
					cil_log(CIL_INFO, " %s", roledom->role_str);
				}

				if (roledom->domed != NULL) {
					cil_log(CIL_INFO, " %s", roledom->domed->datum.name);
				} else {
					cil_log(CIL_INFO, " %s", roledom->domed_str);
				}

				cil_log(CIL_INFO, "\n");
				return;
			}
			case CIL_ROLEBOUNDS: {
				struct cil_rolebounds *rolebnds = node->data;
				cil_log(CIL_INFO, "ROLEBOUNDS: role: %s, bounds: %s\n", rolebnds->role_str, rolebnds->bounds_str);
				return;
			}
			case CIL_CLASS: {
				struct cil_class *cls = node->data;
				cil_log(CIL_INFO, "CLASS: %s ", cls->datum.name);
				
				if (cls->common != NULL) {
					cil_log(CIL_INFO, "inherits: %s ", cls->common->datum.name);
				}
				cil_log(CIL_INFO, "(");
	
				cil_tree_print_perms_list(node->cl_head);
	
				cil_log(CIL_INFO, " )");
				return;
			}
			case CIL_COMMON: {
				struct cil_common *common = node->data;
				cil_log(CIL_INFO, "COMMON: %s (", common->datum.name);
		
				cil_tree_print_perms_list(node->cl_head);
	
				cil_log(CIL_INFO, " )");
				return;
			}
			case CIL_CLASSCOMMON: {
				struct cil_classcommon *clscom = node->data;

				cil_log(CIL_INFO, "CLASSCOMMON: class: %s, common: %s\n", clscom->class_str, clscom->common_str);

				return;
			}
			case CIL_PERMSET: {
				struct cil_permset *permset = node->data;
				cil_log(CIL_INFO, "PERMSET: %s", permset->datum.name);

				cil_tree_print_permset(permset);

				cil_log(CIL_INFO, "\n");

				return;
			}
			case CIL_CLASSPERMSET: {
				struct cil_classpermset *csp = node->data;
				cil_log(CIL_INFO, "CLASSPERMSET: %s", csp->datum.name);

				cil_tree_print_classpermset(csp);

				cil_log(CIL_INFO, "\n");

				return;
			}
			case CIL_CLASSMAP: {
				struct cil_classmap *cm = node->data;
				cil_log(CIL_INFO, "CLASSMAP: %s", cm->datum.name);

				cil_log(CIL_INFO, " (");
				cil_tree_print_perms_list(node->cl_head);
				cil_log(CIL_INFO, " )\n");

				return;
			}
			case CIL_CLASSMAPPERM: {
				struct cil_classmap_perm *cmp = node->data;
				struct cil_list_item *curr = NULL;

				cil_log(CIL_INFO, "CLASSMAPPERM: %s", cmp->datum.name);

				if (cmp->classperms != NULL) {
					curr = cmp->classperms->head;
				}

				cil_log(CIL_INFO, " perms: (");

				while (curr != NULL) {
					cil_tree_print_classpermset(curr->data);
					curr = curr->next;
				}

				cil_log(CIL_INFO, " )\n");

				return;
			}
			case CIL_CLASSMAPPING: {
				struct cil_classmapping *mapping = node->data;
				struct cil_list_item *curr = mapping->classpermsets_str->head;

				cil_log(CIL_INFO, "CLASSMAPPING: classmap: %s, classmap_perm: %s,", mapping->classmap_str, mapping->classmap_perm_str);

				cil_log(CIL_INFO, " (");
				while (curr != NULL) {
					if (curr->flavor == CIL_AST_STR) {
						cil_log(CIL_INFO, " %s", (char*)curr->data);
					} else if (curr->flavor == CIL_CLASSPERMSET) {
						cil_log(CIL_INFO, " (");
						cil_tree_print_classpermset((struct cil_classpermset*)curr->data);
						cil_log(CIL_INFO, " )");
					}
					curr = curr->next;
				}

				cil_log(CIL_INFO, " )\n");
				return;
			}
			case CIL_BOOL: {
				struct cil_bool *boolean = node->data;
				cil_log(CIL_INFO, "BOOL: %s, value: %d\n", boolean->datum.name, boolean->value);
				return;
			}
			case CIL_TUNABLE: {
				struct cil_bool *boolean = node->data;
				cil_log(CIL_INFO, "TUNABLE: %s, value: %d\n", boolean->datum.name, boolean->value);
				return;
			}
			case CIL_BOOLEANIF: {
				struct cil_booleanif *bif = node->data;
				struct cil_list_item *current = bif->expr_stack->head;
				cil_log(CIL_INFO, "BOOLEANIF: expression stack: ( ");

				while (current != NULL) {
					struct cil_conditional *cond = current->data;
					if (cond->data != NULL) {
						struct cil_bool *bool = cond->data;
						cil_log(CIL_INFO, "(bool %s, value: %d) ", bool->datum.name, bool->value);
					} else if (cond->str != NULL) {
						cil_log(CIL_INFO, "%s ", cond->str);
					}
					current = current->next;
				}

				cil_log(CIL_INFO, ")\n");
				return;
			}
			case CIL_TUNABLEIF: {
				struct cil_tunableif *tif = node->data;
				struct cil_list_item *current = tif->expr_stack->head;
				cil_log(CIL_INFO, "TUNABLEIF: expression stack: ( ");

				if (current->flavor != CIL_INT) {
					while (current != NULL && current->data != NULL) {
						struct cil_conditional *cond = current->data;
						if (cond->data != NULL) {
							struct cil_bool *bool = cond->data;
							cil_log(CIL_INFO, "(tunable %s, value: %d) ", bool->datum.name, bool->value);
						} else if (cond->str != NULL) {
							cil_log(CIL_INFO, "%s ", cond->str);
						}
						current = current->next;
					}
				} else {
					cil_log(CIL_INFO, "%d", *(uint16_t*)current->data);
				}

				cil_log(CIL_INFO, ")\n");
				return;
			}
			case CIL_AND:
				cil_log(CIL_INFO, "&&");
				return;
			case CIL_OR:
				cil_log(CIL_INFO, "|| ");
				return;
			case CIL_NOT:
				cil_log(CIL_INFO, "!");
				return;
			case CIL_EQ:
				cil_log(CIL_INFO, "==");
				return;
			case CIL_NEQ:
				cil_log(CIL_INFO, "!=");
				return;
			case CIL_TYPEALIAS: {
				struct cil_typealias *alias = node->data;

				if (alias->type != NULL) {
					cil_log(CIL_INFO, "TYPEALIAS: %s, type: %s\n", alias->datum.name, ((struct cil_symtab_datum *)alias->type)->name);
				} else {
					cil_log(CIL_INFO, "TYPEALIAS: %s, type: %s\n", alias->datum.name, alias->type_str);
				}

				return;
			}
			case CIL_TYPEBOUNDS: {
				struct cil_typebounds *typebnds = node->data;
				cil_log(CIL_INFO, "TYPEBOUNDS: type: %s, bounds: %s\n", typebnds->type_str, typebnds->bounds_str);
				return;
			}
			case CIL_TYPEPERMISSIVE: {
				struct cil_typepermissive *typeperm = node->data;

				if (typeperm->type != NULL) {
					cil_log(CIL_INFO, "TYPEPERMISSIVE: %s\n", ((struct cil_symtab_datum *)typeperm->type)->name);
				} else {
					cil_log(CIL_INFO, "TYPEPERMISSIVE: %s\n", typeperm->type_str);
				}

				return;
			}
			case CIL_FILETRANSITION: {
				struct cil_filetransition *filetrans = node->data;
				cil_log(CIL_INFO, "FILETRANSITION:");

				if (filetrans->src != NULL) {
					cil_log(CIL_INFO, " %s", ((struct cil_symtab_datum *)filetrans->src)->name);
				} else {
					cil_log(CIL_INFO, " %s", filetrans->src_str);
				}

				if (filetrans->exec != NULL) {
					cil_log(CIL_INFO, " %s", ((struct cil_symtab_datum *)filetrans->exec)->name);
				} else {
					cil_log(CIL_INFO, " %s", filetrans->exec_str);
				}

				if (filetrans->proc != NULL) {
					cil_log(CIL_INFO, " %s", filetrans->proc->datum.name);
				} else {
					cil_log(CIL_INFO, " %s", filetrans->proc_str);
				}

				cil_log(CIL_INFO, " %s\n", filetrans->path_str);
				return;
			}
			case CIL_RANGETRANSITION: {
				struct cil_rangetransition *rangetrans = node->data;
				cil_log(CIL_INFO, "RANGETRANSITION:");

				if (rangetrans->src != NULL) {
					cil_log(CIL_INFO, " %s", ((struct cil_symtab_datum *)rangetrans->src)->name);
				} else {
					cil_log(CIL_INFO, " %s", rangetrans->src_str);
				}

				if (rangetrans->exec != NULL) {
					cil_log(CIL_INFO, " %s", ((struct cil_symtab_datum *)rangetrans->exec)->name);
				} else {
					cil_log(CIL_INFO, " %s", rangetrans->exec_str);
				}

				if (rangetrans->obj != NULL) {
					cil_log(CIL_INFO, " %s", rangetrans->obj->datum.name);
				} else {
					cil_log(CIL_INFO, " %s", rangetrans->obj_str);
				}

				if (rangetrans->range != NULL) {
					cil_log(CIL_INFO, " (");
					cil_tree_print_levelrange(rangetrans->range);
					cil_log(CIL_INFO, " )");
				} else {
					cil_log(CIL_INFO, " %s", rangetrans->range_str);
				}

				cil_log(CIL_INFO, "\n");
				return;
			}
			case CIL_AVRULE: {
				struct cil_avrule *rule = node->data;
				switch (rule->rule_kind) {
					case CIL_AVRULE_ALLOWED:
						cil_log(CIL_INFO, "ALLOW:");
						break;
					case CIL_AVRULE_AUDITALLOW:
						cil_log(CIL_INFO, "AUDITALLOW:");
						break;
					case CIL_AVRULE_DONTAUDIT:
						cil_log(CIL_INFO, "DONTAUDIT:");
						break;
					case CIL_AVRULE_NEVERALLOW:
						cil_log(CIL_INFO, "NEVERALLOW:");
						break;
				}

				if (rule->src != NULL) {
					cil_log(CIL_INFO, " %s", ((struct cil_symtab_datum*)rule->src)->name);
				} else {
					cil_log(CIL_INFO, " %s", rule->src_str);
				}

				if (rule->tgt != NULL) {
					cil_log(CIL_INFO, " %s", ((struct cil_symtab_datum*)rule->tgt)->name);
				} else {
					cil_log(CIL_INFO, " %s", rule->tgt_str);
				}

				if (rule->classpermset != NULL) {
					cil_tree_print_classpermset(rule->classpermset);
				} else {
					cil_log(CIL_INFO, " %s", rule->classpermset_str);
				}

				cil_log(CIL_INFO, "\n");

				return;
			}
			case CIL_TYPE_RULE: {
				struct cil_type_rule *rule = node->data;
				switch (rule->rule_kind) {
					case CIL_TYPE_TRANSITION:
						cil_log(CIL_INFO, "TYPETRANSITION:");
						break;
					case CIL_TYPE_MEMBER:
						cil_log(CIL_INFO, "TYPEMEMBER:");
						break;
					case CIL_TYPE_CHANGE:
						cil_log(CIL_INFO, "TYPECHANGE:");
						break;
				}

				if (rule->src != NULL) {
					cil_log(CIL_INFO, " %s", ((struct cil_symtab_datum *)rule->src)->name);
				} else {
					cil_log(CIL_INFO, " %s", rule->src_str);
				}

				if (rule->tgt != NULL) {
					cil_log(CIL_INFO, " %s", ((struct cil_symtab_datum *)rule->tgt)->name);
				} else {
					cil_log(CIL_INFO, " %s", rule->tgt_str);
				}

				if (rule->obj != NULL) {
					cil_log(CIL_INFO, " %s", rule->obj->datum.name);
				} else {
					cil_log(CIL_INFO, " %s", rule->obj_str);
				}

				if (rule->result != NULL) {
					cil_log(CIL_INFO, " %s\n", ((struct cil_symtab_datum *)rule->result)->name);
				} else {
					cil_log(CIL_INFO, " %s\n", rule->result_str);
				}

				return;
			}
			case CIL_SENS: {
				struct cil_sens *sens = node->data;
				cil_log(CIL_INFO, "SENSITIVITY: %s\n", sens->datum.name);
				return;
			}
			case CIL_SENSALIAS: {
				struct cil_sensalias *alias = node->data;
				if (alias->sens != NULL) {
					cil_log(CIL_INFO, "SENSITIVITYALIAS: %s, sensitivity: %s\n", alias->datum.name, alias->sens->datum.name);
				} else {
					cil_log(CIL_INFO, "SENSITIVITYALIAS: %s, sensitivity: %s\n", alias->datum.name, alias->sens_str);
				}

				return;
			}
			case CIL_CAT: {
				struct cil_cat *cat = node->data;
				cil_log(CIL_INFO, "CATEGORY: %s\n", cat->datum.name);
				return;
			}
			case CIL_CATALIAS: {
				struct cil_catalias *alias = node->data;

				if (alias->cat != NULL) {
					cil_log(CIL_INFO, "CATEGORYALIAS: %s, category: %s\n", alias->datum.name, alias->cat->datum.name);
				} else {
					cil_log(CIL_INFO, "CATEGORYALIAS: %s, category: %s\n", alias->datum.name, alias->cat_str);
				}

				return;
			}
			case CIL_CATSET: {
				struct cil_catset *catset = node->data;
				struct cil_list_item *cat = NULL;
				struct cil_list_item *parent = NULL;

				cil_log(CIL_INFO, "CATSET: %s (",catset->datum.name);

				if (catset->cat_list != NULL) {
					cat = catset->cat_list->head;
				} else {
					cat = catset->cat_list_str->head;
				}

				while (cat != NULL) {
					if (cat->flavor == CIL_LIST) {
						parent = cat;
						cat = ((struct cil_list*)cat->data)->head;
						cil_log(CIL_INFO, " (");
						while (cat != NULL) {
							cil_log(CIL_INFO, " %s", ((struct cil_cat*)cat->data)->datum.name);
							cat = cat->next;
						}
						cil_log(CIL_INFO, " )");
						cat = parent;
					} else {
						if (cat->flavor == CIL_CAT) {
							cil_log(CIL_INFO, " %s", ((struct cil_cat*)cat->data)->datum.name);
						} else {
							cil_log(CIL_INFO, " %s", (char*)cat->data);
						}
					}
					cat = cat->next;
				}

				cil_log(CIL_INFO, " )\n");
				return;
			}
			case CIL_CATORDER: {
				struct cil_catorder *catorder = node->data;
				struct cil_list_item *cat = NULL;

				cil_log(CIL_INFO, "CATORDER: (");

				if (catorder->cat_list_str != NULL) {
					cat = catorder->cat_list_str->head;
				} else {
					return;
				}

				while (cat != NULL) {
					cil_log(CIL_INFO, " %s", (char*)cat->data);
					cat = cat->next;
				}

				cil_log(CIL_INFO, " )\n");
				return;
			}
			case CIL_SENSCAT: {
				struct cil_senscat *senscat = node->data;

				cil_log(CIL_INFO, "SENSCAT: sens:");

				if (senscat->sens_str != NULL) {
					cil_log(CIL_INFO, " %s ", senscat->sens_str);
				} else {
					cil_log(CIL_INFO, " [processed]");
				}

				if (senscat->catset != NULL) {
					cil_tree_print_catset(senscat->catset);
				} else {
					cil_log(CIL_INFO, " %s", senscat->catset_str);
				}

				cil_log(CIL_INFO, " )\n");
				return;
			}
			case CIL_DOMINANCE: {
				struct cil_sens_dominates *dom = node->data;
				struct cil_list_item *sens = NULL;
				struct cil_list_item *parent = NULL;

				cil_log(CIL_INFO, "DOMINANCE: (");

				if (dom->sens_list_str != NULL) {
					sens = dom->sens_list_str->head;
					while(sens != NULL) {
						if (sens->flavor == CIL_LIST) {
							parent = sens;
							sens = ((struct cil_list*)sens->data)->head;
							cil_log(CIL_INFO, " (");
							while (sens != NULL) {
								cil_log(CIL_INFO, " %s", (char*)sens->data);
								sens = sens->next;
							}
							cil_log(CIL_INFO, " )");
							sens = parent;
						} else {
							cil_log(CIL_INFO, " %s", (char*)sens->data);
						}
						sens = sens->next;
					}
				} else {
					cil_log(CIL_INFO, "\n");
					return;
				}

				cil_log(CIL_INFO, " )\n");
				return;
			}
			case CIL_LEVEL: {
				struct cil_level *level = node->data;
				cil_log(CIL_INFO, "LEVEL %s:", level->datum.name); 
				cil_tree_print_level(level);
				cil_log(CIL_INFO, "\n");
				return;
			}
			case CIL_LEVELRANGE: {
				struct cil_levelrange *lvlrange = node->data;
				cil_log(CIL_INFO, "LEVELRANGE %s:", lvlrange->datum.name);
				cil_tree_print_levelrange(lvlrange);
				cil_log(CIL_INFO, "\n");
				return;
			}
			case CIL_CONSTRAIN: {
				struct cil_constrain *cons = node->data;
				cil_log(CIL_INFO, "CONSTRAIN: \n\t(");
				cil_tree_print_constrain(cons);
				return;
			}
			case CIL_MLSCONSTRAIN: {
				struct cil_constrain *cons = node->data;
				cil_log(CIL_INFO, "MLSCONSTRAIN: \n\t(");
				cil_tree_print_constrain(cons);
				return;
			}
			case CIL_CONTEXT: {
				struct cil_context *context = node->data;
				cil_log(CIL_INFO, "CONTEXT %s:", context->datum.name);
				cil_tree_print_context(context);
				cil_log(CIL_INFO, "\n");
				return;
			}
			case CIL_FILECON: {
				struct cil_filecon *filecon = node->data;
				cil_log(CIL_INFO, "FILECON:");
				cil_log(CIL_INFO, " %s %s %d", filecon->root_str, filecon->path_str, filecon->type);

				if (filecon->context_str != NULL) {
					cil_log(CIL_INFO, " %s", filecon->context_str);
				} else if (filecon->context != NULL) {
					cil_tree_print_context(filecon->context);
				} else if (filecon->context_str != NULL) {
					cil_log(CIL_INFO, " %s", filecon->context_str);
				}

				cil_log(CIL_INFO, "\n");
				return;

			}
			case CIL_PORTCON: {
				struct cil_portcon *portcon = node->data;
				cil_log(CIL_INFO, "PORTCON:");
				if (portcon->proto == CIL_PROTOCOL_UDP) {
					cil_log(CIL_INFO, " udp");
				} else if (portcon->proto == CIL_PROTOCOL_TCP) {
					cil_log(CIL_INFO, " tcp");
				}
				cil_log(CIL_INFO, " (%d %d)", portcon->port_low, portcon->port_high);

				if (portcon->context != NULL) {
					cil_tree_print_context(portcon->context);
				} else if (portcon->context_str != NULL) {
					cil_log(CIL_INFO, " %s", portcon->context_str);
				}

				cil_log(CIL_INFO, "\n");
				return;
			}
			case CIL_NODECON: {
				struct cil_nodecon *nodecon = node->data;
				char buf[256];
				
				cil_log(CIL_INFO, "NODECON:");
				
				if (nodecon->addr) {
					inet_ntop(nodecon->addr->family, &nodecon->addr->ip, buf, 256);
					cil_log(CIL_INFO, " %s", buf);
				}  else {
					cil_log(CIL_INFO, " %s", nodecon->addr_str);
				}

				if (nodecon->mask) {
					inet_ntop(nodecon->mask->family, &nodecon->mask->ip, buf, 256);
					cil_log(CIL_INFO, " %s", buf);
				} else {
					cil_log(CIL_INFO, " %s", nodecon->mask_str);
				}
				
				if (nodecon->context != NULL) {
					cil_tree_print_context(nodecon->context);
				} else if (nodecon->context_str != NULL) {
					cil_log(CIL_INFO, " %s", nodecon->context_str);
				}

				cil_log(CIL_INFO, "\n");
				return;
			}
			case CIL_GENFSCON: {
				struct cil_genfscon *genfscon = node->data;
				cil_log(CIL_INFO, "GENFSCON:");
				cil_log(CIL_INFO, " %s %s", genfscon->fs_str, genfscon->path_str);

				if (genfscon->context != NULL) {
					cil_tree_print_context(genfscon->context);
				} else if (genfscon->context_str != NULL) {
					cil_log(CIL_INFO, " %s", genfscon->context_str);
				}

				cil_log(CIL_INFO, "\n");
				return;
			}
			case CIL_NETIFCON: {
				struct cil_netifcon *netifcon = node->data;
				cil_log(CIL_INFO, "NETIFCON %s", netifcon->interface_str);

				if (netifcon->if_context != NULL) {
					cil_tree_print_context(netifcon->if_context);
				} else if (netifcon->if_context_str != NULL) {
					cil_log(CIL_INFO, " %s", netifcon->if_context_str);
				}

				if (netifcon->packet_context != NULL) {
					cil_tree_print_context(netifcon->packet_context);
				} else if (netifcon->packet_context_str != NULL) {
					cil_log(CIL_INFO, " %s", netifcon->packet_context_str);
				}

				cil_log(CIL_INFO, "\n");
				return;
			}
			case CIL_PIRQCON: {
				struct cil_pirqcon *pirqcon = node->data;

				cil_log(CIL_INFO, "PIRQCON %d", pirqcon->pirq);
				if (pirqcon->context != NULL) {
					cil_tree_print_context(pirqcon->context);
				} else {
					cil_log(CIL_INFO, " %s", pirqcon->context_str);
				}

				cil_log(CIL_INFO, "\n");
				return;
			}
			case CIL_IOMEMCON: {
				struct cil_iomemcon *iomemcon = node->data;

				cil_log(CIL_INFO, "IOMEMCON ( %d %d )", iomemcon->iomem_low, iomemcon->iomem_high);
				if (iomemcon->context != NULL) {
					cil_tree_print_context(iomemcon->context);
				} else {
					cil_log(CIL_INFO, " %s", iomemcon->context_str);
				}

				cil_log(CIL_INFO, "\n");
				return;
			}
			case CIL_IOPORTCON: {
				struct cil_ioportcon *ioportcon = node->data;

				cil_log(CIL_INFO, "IOPORTCON ( %d %d )", ioportcon->ioport_low, ioportcon->ioport_high);
				if (ioportcon->context != NULL) {
					cil_tree_print_context(ioportcon->context);
				} else {
					cil_log(CIL_INFO, " %s", ioportcon->context_str);
				}

				cil_log(CIL_INFO, "\n");
				return;
			}
			case CIL_PCIDEVICECON: {
				struct cil_pcidevicecon *pcidevicecon = node->data;

				cil_log(CIL_INFO, "PCIDEVICECON %d", pcidevicecon->dev);
				if (pcidevicecon->context != NULL) {
					cil_tree_print_context(pcidevicecon->context);
				} else {
					cil_log(CIL_INFO, " %s", pcidevicecon->context_str);
				}

				cil_log(CIL_INFO, "\n");
				return;
			}
			case CIL_FSUSE: {
				struct cil_fsuse *fsuse = node->data;
				cil_log(CIL_INFO, "FSUSE: ");

				if (fsuse->type == CIL_FSUSE_XATTR) {
					cil_log(CIL_INFO, "xattr ");
				} else if (fsuse->type == CIL_FSUSE_TASK) {
					cil_log(CIL_INFO, "task ");
				} else if (fsuse->type == CIL_FSUSE_TRANS) {
					cil_log(CIL_INFO, "trans ");
				} else {
					cil_log(CIL_INFO, "unknown ");
				}

				cil_log(CIL_INFO, "%s ", fsuse->fs_str);

				if (fsuse->context != NULL) {
					cil_tree_print_context(fsuse->context);
				} else {
					cil_log(CIL_INFO, " %s", fsuse->context_str);
				}

				cil_log(CIL_INFO, "\n");
				return;
			}
			case CIL_SID: {
				struct cil_sid *sid = node->data;
				cil_log(CIL_INFO, "SID: %s\n", sid->datum.name);
				return;
			}
			case CIL_SIDCONTEXT: {
				struct cil_sidcontext *sidcon = node->data;
				cil_log(CIL_INFO, "SIDCONTEXT: %s", sidcon->sid_str);

				if (sidcon->context != NULL) {
					cil_tree_print_context(sidcon->context);
				} else {
					cil_log(CIL_INFO, " %s", sidcon->context_str);
				}

				cil_log(CIL_INFO, "\n");
				return;
			}
			case CIL_POLICYCAP: {
				struct cil_policycap *polcap = node->data;
				cil_log(CIL_INFO, "POLICYCAP: %s\n", polcap->datum.name);
				return;
			}
			case CIL_MACRO: {
				struct cil_macro *macro = node->data;
				cil_log(CIL_INFO, "MACRO %s:", macro->datum.name);

				if (macro->params != NULL && macro->params->head != NULL) {
					struct cil_list_item *curr_param = macro->params->head;
					cil_log(CIL_INFO, " parameters: (");
					while (curr_param != NULL) {
						cil_log(CIL_INFO, " flavor: %d, string: %s;", ((struct cil_param*)curr_param->data)->flavor, ((struct cil_param*)curr_param->data)->str);

						curr_param = curr_param->next;
					}
					cil_log(CIL_INFO, " )");
				}
				cil_log(CIL_INFO, "\n");

				return;
			}
			case CIL_CALL: {
				struct cil_call *call = node->data;
				cil_log(CIL_INFO, "CALL: macro name:");

				if (call->macro != NULL) {
					cil_log(CIL_INFO, " %s", call->macro->datum.name);
				} else {
					cil_log(CIL_INFO, " %s", call->macro_str);
				}

				if (call->args != NULL) {
					cil_log(CIL_INFO, ", args: ( ");
					struct cil_list_item *item = call->args->head;
					while(item != NULL) {
						if (((struct cil_args*)item->data)->arg != NULL) {
							cil_tree_print_node(((struct cil_args*)item->data)->arg);
						} else if (((struct cil_args*)item->data)->arg_str != NULL) {
							switch (item->flavor) {
							case CIL_TYPE: cil_log(CIL_INFO, "type:"); break;
							case CIL_USER: cil_log(CIL_INFO, "user:"); break;
							case CIL_ROLE: cil_log(CIL_INFO, "role:"); break;
							case CIL_SENS: cil_log(CIL_INFO, "sensitivity:"); break;
							case CIL_CAT: cil_log(CIL_INFO, "category:"); break;
							case CIL_CATSET: cil_log(CIL_INFO, "categoryset:"); break;
							case CIL_LEVEL: cil_log(CIL_INFO, "level:"); break;
							case CIL_CLASS: cil_log(CIL_INFO, "class:"); break;
							}
							cil_log(CIL_INFO, "%s ", ((struct cil_args*)item->data)->arg_str);
						}
						item = item->next;
					}
					cil_log(CIL_INFO, ")");
				}

				cil_log(CIL_INFO, "\n");
				return;
			}	
			case CIL_OPTIONAL: {
				struct cil_optional *optional = node->data;
				cil_log(CIL_INFO, "OPTIONAL: %s\n", optional->datum.name);
				return;
			}
			case CIL_IPADDR: {
				struct cil_ipaddr *ipaddr = node->data;
				char buf[256];

				inet_ntop(ipaddr->family, &ipaddr->ip, buf, 256);
				cil_log(CIL_INFO, "IPADDR %s: %s\n", ipaddr->datum.name, buf);

				break;
			}
			default : {
				cil_log(CIL_INFO, "CIL FLAVOR: %d\n", node->flavor);
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
					cil_log(CIL_INFO, "%s", (char*)current->data);
				} else {
					cil_log(CIL_INFO, " %s", (char*)current->data);
				}
			} else if (current->flavor != CIL_PERM) {
				for (x = 0; x<depth; x++) {
					cil_log(CIL_INFO, "\t");
				}
				cil_tree_print_node(current);
			}
		} else {
			if (current->parent != NULL) {
				cil_log(CIL_INFO, "\n");
				for (x = 0; x<depth; x++) {
					cil_log(CIL_INFO, "\t");
				}
				cil_log(CIL_INFO, "(");

				if (current->flavor != CIL_PARSE_NODE) {
					cil_tree_print_node(current);
				}
			}
			cil_tree_print(current->cl_head, depth + 1);
		}

		if (current->next == NULL) {
			if ((current->parent != NULL) && (current->parent->cl_tail == current) && (current->parent->parent != NULL)) {
				if (current->flavor == CIL_PERM) {
					cil_log(CIL_INFO, ")\n");
				} else if (current->flavor != CIL_PARSE_NODE) {
					for (x = 0; x<depth-1; x++) {
						cil_log(CIL_INFO, "\t");
					}
					cil_log(CIL_INFO, ")\n");
				} else {
					cil_log(CIL_INFO, ")");
				}
			}

			if ((current->parent != NULL) && (current->parent->parent == NULL))
				cil_log(CIL_INFO, "\n\n");
		} else {
//			cil_log(CIL_INFO, "cil_tree_print: current->next is not null\n");
			cil_tree_print(current->next, depth);
		}
	} else {
		cil_log(CIL_INFO, "Tree is NULL\n");
	}
}
