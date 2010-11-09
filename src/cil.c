#include <stdlib.h>
#include <stdio.h>

#include <sepol/policydb/policydb.h>
#include <sepol/policydb/symtab.h>

#include "cil.h"
#include "cil_mem.h"
#include "cil_tree.h"
#include "cil_symtab.h"
#include "cil_build_ast.h"

int cil_db_init(struct cil_db **db)
{
	int rc = SEPOL_ERR;	

	struct cil_db *new_db;
	new_db = cil_malloc(sizeof(struct cil_db));

	rc = cil_symtab_array_init(new_db->symtab, CIL_SYM_NUM);
	if (rc != SEPOL_OK) {
		free(new_db);
		return rc;
	}

	cil_tree_init(&new_db->ast);
	
	*db = new_db;

	return SEPOL_OK;
}

void cil_db_destroy(struct cil_db **db)
{
	cil_tree_destroy(&(*db)->ast);
	cil_symtab_array_destroy((*db)->symtab);
	
	*db = NULL;	

}

int cil_list_init(struct cil_list **list)
{
	struct cil_list *new_list = cil_malloc(sizeof(struct cil_list));
	new_list->head = NULL;

	*list = new_list;
	
	return SEPOL_OK;
}

void cil_list_destroy(struct cil_list **list, uint8_t destroy_data)
{
	struct cil_list_item *item = (*list)->head;
	struct cil_list_item *next = NULL;
	struct cil_list_item *parent = NULL;
	while (item != NULL)
	{
		if (item->flavor == CIL_LIST) {
			parent = item;
			item = ((struct cil_list*)item->data)->head;
			while (item != NULL) {
				next = item->next;
				cil_list_item_destroy(&item, destroy_data);
				item = next;
			}
			item = parent;
		}
		next = item->next;
		cil_list_item_destroy(&item, destroy_data);
		item = next;
	}
	*list = NULL;	
}

int cil_list_item_init(struct cil_list_item **item)
{
	struct cil_list_item *new_item = cil_malloc(sizeof(struct cil_list_item));
	new_item->next = NULL;
	new_item->flavor = 0;
	new_item->data = NULL;

	*item = new_item;

	return SEPOL_OK;
}

void cil_list_item_destroy(struct cil_list_item **item, uint8_t destroy_data)
{
	if (destroy_data) 
		cil_destroy_data(&(*item)->data, (*item)->flavor);
	free(*item);
	*item = NULL;
}

void cil_destroy_data(void **data, uint32_t flavor)
{
	switch(flavor) {
		case (CIL_ROOT) : {
			free(*data);
			break;
		}
		case (CIL_PARSER) : {
			free(*data);
			break;
		}
		case (CIL_AST_STR) : {
			free(*data);
			break;
		}
		case (CIL_BLOCK) : {
			cil_destroy_block(*data);
			break;
		}
		case (CIL_CLASS) : {
			cil_destroy_class(*data);
			break;
		}
		case (CIL_PERM) : {
			cil_destroy_perm(*data);
			break;
		}
		case (CIL_COMMON) : {
			cil_destroy_common(*data);
			break;
		}
		case (CIL_SID) : {
			cil_destroy_sid(*data);
			break;
		}
		case (CIL_AVRULE) : {
			cil_destroy_avrule(*data);
			break;
		}
		case (CIL_TYPE_RULE) : {
			cil_destroy_type_rule(*data);
			break;
		}
		case (CIL_TYPE) : {
			cil_destroy_type(*data);
			break;
		}
		case (CIL_ATTR) : {
			cil_destroy_type(*data);
			break;
		}
		case (CIL_USER) : {
			cil_destroy_user(*data);
			break;
		}
		case (CIL_ROLE) : {
			cil_destroy_role(*data);
			break;
		}
		case (CIL_ROLETRANS) : {
			cil_destroy_roletrans(*data);
			break;
		}
		case (CIL_ROLEALLOW) : {
			cil_destroy_roleallow(*data);
			break;
		}
		case (CIL_BOOL) : {
			cil_destroy_bool(*data);
			break;
		}
		case (CIL_TYPEALIAS) : {
			cil_destroy_typealias(*data);
			break;
		}
		case (CIL_TYPE_ATTR) : {
			cil_destroy_typeattr(*data);
			break;
		}
		case (CIL_SENS) : {
			cil_destroy_sensitivity(*data);
			break;
		}
		case (CIL_SENSALIAS) : {
			cil_destroy_sensalias(*data);
			break;
		}
		case (CIL_CAT) : {
			cil_destroy_category(*data);
			break;
		}
		case (CIL_CATALIAS) : {
			cil_destroy_catalias(*data);
			break;
		}
		case (CIL_CATSET) : {
			cil_destroy_catset(*data);
			break;
		}
		case (CIL_ROLETYPE) : {
			cil_destroy_roletype(*data);
			break;
		}
		case (CIL_USERROLE) : { 
			cil_destroy_userrole(*data);
			break;
		}
		default : {
			printf("Unknown data flavor: %d\n", flavor);
			break;
		}
	}
	
	*data = NULL;		
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

void cil_symtab_array_destroy(symtab_t symtab[])
{
	int i=0;
	for (i=0;i<CIL_SYM_NUM; i++) {
		cil_symtab_destroy(&symtab[i]);
	}
}

int cil_destroy_ast_symtabs(struct cil_tree_node *root)
{
	struct cil_tree_node *current = root;
	uint16_t reverse = 0;
	
	do {
		if (current->cl_head != NULL && !reverse) {
			switch (current->flavor) {
				case (CIL_ROOT) :
					break;
				case (CIL_BLOCK) : {
					cil_symtab_array_destroy(((struct cil_block*)current->data)->symtab);
					break;
				}
				case (CIL_CLASS) : {
					cil_symtab_destroy(&((struct cil_class*)current->data)->perms);
					break;
				}
				case (CIL_COMMON) : {
					cil_symtab_destroy(&((struct cil_common*)current->data)->perms);
					break;
				}
				default : 
					printf("destroy symtab error, wrong flavor node\n");
			}
			current = current->cl_head;
		}
		else if (current->next != NULL) {
			current = current->next;
			reverse = 0;
		}
		else {
			current = current->parent;
			reverse = 1;
		}
	}
	while (current->flavor != CIL_ROOT);

	return SEPOL_OK;
}

int cil_get_parent_symtab(struct cil_db *db, struct cil_tree_node *ast_node, symtab_t **symtab, uint32_t cil_sym_index)
{
	if (db == NULL || ast_node == NULL)
		return SEPOL_ERR;

	if (ast_node->parent != NULL) {
		if (ast_node->parent->flavor == CIL_BLOCK && cil_sym_index < CIL_SYM_NUM) 
			*symtab = &((struct cil_block*)ast_node->parent->data)->symtab[cil_sym_index];
		else if (ast_node->parent->flavor == CIL_CLASS) 
			*symtab = &((struct cil_class*)ast_node->parent->data)->perms;
		else if (ast_node->parent->flavor == CIL_COMMON)
			*symtab = &((struct cil_common*)ast_node->parent->data)->perms;
		else if (ast_node->parent->flavor == CIL_ROOT && cil_sym_index < CIL_SYM_NUM)
			*symtab = &db->symtab[cil_sym_index];
		else if (cil_sym_index >= CIL_SYM_NUM) {
			printf("Invalid index passed to cil_get_parent_symtab\n");
			return SEPOL_ERR;
		}
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
