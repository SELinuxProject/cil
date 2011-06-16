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

#include <stdlib.h>
#include <stdio.h>

#include <sepol/policydb/policydb.h>
#include <sepol/policydb/symtab.h>

#include "cil.h"
#include "cil_mem.h"
#include "cil_tree.h"
#include "cil_list.h"
#include "cil_symtab.h"
#include "cil_build_ast.h"

int cil_db_init(struct cil_db **db)
{
	int rc = SEPOL_ERR;	

	struct cil_db *new_db = NULL;
	new_db = cil_malloc(sizeof(struct cil_db));

	rc = cil_symtab_array_init(new_db->symtab, CIL_SYM_NUM);
	if (rc != SEPOL_OK) {
		free(new_db);
		return rc;
	}

	cil_tree_init(&new_db->ast);
	cil_list_init(&new_db->catorder);
	cil_list_init(&new_db->dominance);
	symtab_init(&new_db->netif, CIL_SYM_SIZE);
	cil_sort_init(&new_db->netifcon);
	cil_sort_init(&new_db->genfscon);
	cil_sort_init(&new_db->filecon);
	cil_sort_init(&new_db->nodecon);
	cil_sort_init(&new_db->portcon);
	cil_sort_init(&new_db->fsuse);

	*db = new_db;

	return SEPOL_OK;
}

void cil_db_destroy(struct cil_db **db)
{
	cil_tree_destroy(&(*db)->ast);
	cil_symtab_array_destroy((*db)->symtab);
	cil_sort_destroy(&(*db)->netifcon);
	cil_sort_destroy(&(*db)->genfscon);
	cil_sort_destroy(&(*db)->filecon);
	cil_sort_destroy(&(*db)->nodecon);
	cil_sort_destroy(&(*db)->portcon);

	*db = NULL;	

}

void cil_destroy_data(void **data, uint32_t flavor)
{
	switch(flavor) {
	case CIL_ROOT:
		free(*data);
		break;
	case CIL_PARSE_NODE:
		free(*data);
		break;
	case CIL_AST_STR:
		free(*data);
		break;
	case CIL_LIST:
		free(*data);
		break;
	case CIL_BLOCK:
		cil_destroy_block(*data);
		break;
	case CIL_CLASS:
		cil_destroy_class(*data);
		break;
	case CIL_PERM:
		cil_destroy_perm(*data);
		break;
	case CIL_PERMSET:
		cil_destroy_permset(*data);
		break;
	case CIL_COMMON:
		cil_destroy_common(*data);
		break;
	case CIL_CLASSCOMMON:
		cil_destroy_classcommon(*data);
		break;
	case CIL_SID:
		cil_destroy_sid(*data);
		break;
	case CIL_SIDCONTEXT:
		cil_destroy_sidcontext(*data);
		break;
	case CIL_POLICYCAP:
		cil_destroy_policycap(*data);
		break;
	case CIL_AVRULE:
		cil_destroy_avrule(*data);
		break;
	case CIL_TYPE_RULE:
		cil_destroy_type_rule(*data);
		break;
	case CIL_TYPE:
		cil_destroy_type(*data);
		break;
	case CIL_ATTR:
		cil_destroy_type(*data);
		break;
	case CIL_USER:
		cil_destroy_user(*data);
		break;
	case CIL_ROLE:
		cil_destroy_role(*data);
		break;
	case CIL_ROLETRANS:
		cil_destroy_roletrans(*data);
		break;
	case CIL_ROLEALLOW:
		cil_destroy_roleallow(*data);
		break;
	case CIL_ROLEDOMINANCE:
		cil_destroy_roledominance(*data);
		break;
	case CIL_BOOL:
		cil_destroy_bool(*data);
		break;
	case CIL_TUNABLE:
		cil_destroy_bool(*data);
		break;
	case CIL_BOOLEANIF:
		cil_destroy_boolif(*data);
		break;
	case CIL_ELSE : break;
	case CIL_COND:
		cil_destroy_conditional(*data);
		break;
	case CIL_TUNABLEIF:
		cil_destroy_tunif(*data);
		break;
	case CIL_TYPEALIAS:
		cil_destroy_typealias(*data);
		break;
	case CIL_TYPE_ATTR:
		cil_destroy_typeattr(*data);
		break;
	case CIL_TYPEBOUNDS:
		cil_destroy_typebounds(*data);
		break;
	case CIL_TYPEPERMISSIVE:
		cil_destroy_typepermissive(*data);
		break;
	case CIL_FILETRANSITION:
		cil_destroy_filetransition(*data);
		break;
	case CIL_SENS:
		cil_destroy_sensitivity(*data);
		break;
	case CIL_SENSALIAS:
		cil_destroy_sensalias(*data);
		break;
	case CIL_CAT:
		cil_destroy_category(*data);
		break;
	case CIL_CATALIAS:
		cil_destroy_catalias(*data);
		break;
	case CIL_CATSET:
		cil_destroy_catset(*data);
		break;
	case CIL_CATORDER:
		cil_destroy_catorder(*data);
		break;
	case CIL_DOMINANCE:
		cil_destroy_dominance(*data);
		break;
	case CIL_SENSCAT:
		cil_destroy_senscat(*data);
		break;
	case CIL_LEVEL:
		cil_destroy_level(*data);
		break;
	case CIL_CONSTRAIN:
		cil_destroy_constrain(*data);
		break;
	case CIL_MLSCONSTRAIN:
		cil_destroy_constrain(*data);
		break;
	case CIL_CONSTRAIN_NODE:
		cil_destroy_constrain_node(*data);
		break;
	case CIL_ROLETYPE:
		cil_destroy_roletype(*data);
		break;
	case CIL_USERROLE:
		cil_destroy_userrole(*data);
		break;
	case CIL_CONTEXT:
		cil_destroy_context(*data);
		break;
	case CIL_FILECON:
		cil_destroy_filecon(*data);
		break;
	case CIL_PORTCON:
		cil_destroy_portcon(*data);
		break;
	case CIL_NODECON:
		cil_destroy_nodecon(*data);
		break;
	case CIL_GENFSCON:
		cil_destroy_genfscon(*data);
		break;
	case CIL_NETIFCON:
		cil_destroy_netifcon(*data);
		break;
	case CIL_FSUSE:
		cil_destroy_fsuse(*data);
		break;
	case CIL_PARAM:
		cil_destroy_param(*data);
		break;
	case CIL_MACRO:
		cil_destroy_macro(*data);
		break;
	case CIL_CALL:
		cil_destroy_call(*data);
		break;
	case CIL_ARGS:
		cil_destroy_args(*data);
		break;
	case CIL_OPTIONAL:
		cil_destroy_optional(*data);
		break;
	case CIL_IPADDR:
		cil_destroy_ipaddr(*data);
		break;
	case CIL_INT: break;
	default:
		printf("Unknown data flavor: %d\n", flavor);
		break;
	}
	
	*data = NULL;		
}

int cil_symtab_array_init(symtab_t symtab[], uint32_t symtab_num)
{
	uint32_t i = 0, rc = 0;
	for (i = 0; i < symtab_num; i++) {
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
	int i = 0;
	for (i = 0; i < CIL_SYM_NUM; i++) {
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
			case CIL_ROOT:
				break;
			case CIL_BLOCK:
				cil_symtab_array_destroy(((struct cil_block*)current->data)->symtab);
				break;
			case CIL_CLASS:
				cil_symtab_destroy(&((struct cil_class*)current->data)->perms);
				break;
			case CIL_COMMON:
				cil_symtab_destroy(&((struct cil_common*)current->data)->perms);
				break;
			case CIL_MACRO:
				cil_symtab_array_destroy(((struct cil_macro*)current->data)->symtab);
				break;
			case CIL_CALL:
				/* do nothing */
				break;
			case CIL_OPTIONAL:
				/* do nothing */
				break;
			default:
				printf("destroy symtab error, wrong flavor node\n");
			}
			current = current->cl_head;
		} else if (current->next != NULL) {
			current = current->next;
			reverse = 0;
		} else {
			current = current->parent;
			reverse = 1;
		}
	}
	while (current->flavor != CIL_ROOT);

	return SEPOL_OK;
}

int cil_get_parent_symtab(struct cil_db *db, struct cil_tree_node *ast_node, symtab_t **symtab, uint32_t cil_sym_index)
{
	int rc = SEPOL_ERR;

	if (db == NULL || ast_node == NULL) {
		return SEPOL_ERR;
	}

	if (ast_node->parent != NULL) {
		if (ast_node->parent->flavor == CIL_BLOCK && cil_sym_index < CIL_SYM_NUM) {
			*symtab = &((struct cil_block*)ast_node->parent->data)->symtab[cil_sym_index];
		} else if (ast_node->parent->flavor == CIL_MACRO  && cil_sym_index < CIL_SYM_NUM) {
			*symtab = &((struct cil_macro*)ast_node->parent->data)->symtab[cil_sym_index];
		} else if (ast_node->parent->flavor == CIL_CALL  && cil_sym_index < CIL_SYM_NUM) {
			rc = cil_get_parent_symtab(db, ast_node->parent, symtab, cil_sym_index);
			if (rc != SEPOL_OK) {
				printf("cil_get_parent_symtab: cil_call failed, rc: %d\n", rc);
				return rc;
			}
		} else if (ast_node->parent->flavor == CIL_CLASS) {
			*symtab = &((struct cil_class*)ast_node->parent->data)->perms;
		} else if (ast_node->parent->flavor == CIL_COMMON) {
			*symtab = &((struct cil_common*)ast_node->parent->data)->perms;
		} else if (ast_node->parent->flavor == CIL_TUNABLEIF) {
			*symtab = &((struct cil_tunableif*)ast_node->parent->data)->symtab[cil_sym_index];
		} else if ((ast_node->parent->flavor == CIL_BOOLEANIF || ast_node->parent->flavor == CIL_ELSE) && cil_sym_index < CIL_SYM_NUM) {
			rc = cil_get_parent_symtab(db, ast_node->parent, symtab, cil_sym_index);
			if (rc != SEPOL_OK) {
				printf("cil_get_parent_symtab: cil_booleanif failed, rc: %d\n", rc);
				return rc;
			}
		} else if (ast_node->parent->flavor == CIL_OPTIONAL && cil_sym_index < CIL_SYM_NUM) {
			rc = cil_get_parent_symtab(db, ast_node->parent, symtab, cil_sym_index);
			if (rc != SEPOL_OK) {
				printf("cil_get_parent_symtab: cil_optional failed, rc: %d\n", rc);
				return rc;
			}
		} else if (ast_node->parent->flavor == CIL_ROOT && cil_sym_index < CIL_SYM_NUM) {
			*symtab = &db->symtab[cil_sym_index];
		} else if (cil_sym_index >= CIL_SYM_NUM) {
			printf("Invalid index passed to cil_get_parent_symtab\n");
			return SEPOL_ERR;
		} else {
			printf("Failed to get symtab from parent node\n");
			return SEPOL_ERR;
		}
	} else {
		printf("Failed to get symtab: no parent node\n");
		return SEPOL_ERR;
	}

	return SEPOL_OK;
}

int cil_sort_init(struct cil_sort **sort)
{
	struct cil_sort *new_sort = NULL;

	if (sort == NULL) {
		return SEPOL_ERR;
	}

	new_sort = cil_malloc(sizeof(struct cil_sort));

	new_sort->flavor = 0;
	new_sort->count = 0;
	new_sort->index = 0;
	new_sort->array = NULL;

	*sort = new_sort;

	return SEPOL_OK;
}

void cil_sort_destroy(struct cil_sort **sort)
{
	(*sort)->flavor = 0;
	(*sort)->count = 0;
	(*sort)->index = 0;
	if ((*sort)->array != NULL) {
		free((*sort)->array);
	}
	(*sort)->array = NULL;

	*sort = NULL;
}

int cil_netifcon_init(struct cil_netifcon **netifcon)
{
	struct cil_netifcon *new_netifcon = NULL;

	if (netifcon == NULL) {
		return SEPOL_ERR;
	}

	new_netifcon = cil_malloc(sizeof(struct cil_netifcon));

	new_netifcon->interface_str = NULL;
	new_netifcon->if_context_str = NULL;
	new_netifcon->if_context = NULL;
	new_netifcon->packet_context_str = NULL;
	new_netifcon->packet_context = NULL;

	*netifcon = new_netifcon;

	return SEPOL_OK;	
}

int cil_context_init(struct cil_context **context)
{
	struct cil_context *new_context = NULL;

	if (context == NULL) {
		return SEPOL_ERR;
	}

	new_context = cil_malloc(sizeof(struct cil_context));

	cil_symtab_datum_init(&new_context->datum);
	new_context->user_str = NULL;
	new_context->user = NULL;
	new_context->role_str = NULL;
	new_context->role = NULL;
	new_context->type_str = NULL;
	new_context->type = NULL;
	new_context->low_str = NULL;
	new_context->low = NULL;
	new_context->high_str = NULL;
	new_context->high = NULL;

	*context = new_context;	

	return SEPOL_OK;	
}

int cil_level_init(struct cil_level **level)
{
	struct cil_level *new_level = NULL;

	if (level == NULL) {
		return SEPOL_ERR;
	}

	new_level = cil_malloc(sizeof(struct cil_level));

	cil_symtab_datum_init(&new_level->datum);
	new_level->sens_str = NULL;
	new_level->sens = NULL;
	new_level->cat_list_str = NULL;
	new_level->cat_list = NULL;
	
	*level = new_level;

	return SEPOL_OK;
}

int cil_sens_init(struct cil_sens **sens)
{
	struct cil_sens *new_sens = NULL;
	int rc = SEPOL_ERR;

	if (sens == NULL) {
		return SEPOL_ERR;
	}

	new_sens = cil_malloc(sizeof(struct cil_sens));

	cil_symtab_datum_init(&new_sens->datum);

	rc = symtab_init(&new_sens->cats, CIL_SYM_SIZE);
	if (rc != SEPOL_OK) {
		free(new_sens);
		return rc;
	}

	*sens = new_sens;

	return SEPOL_OK;
}

int cil_block_init(struct cil_block **block)
{
	struct cil_block *new_block = NULL;
	int rc = SEPOL_ERR;

	if (block == NULL) {
		return SEPOL_ERR;
	}

	new_block = cil_malloc(sizeof(struct cil_block));

	cil_symtab_datum_init(&new_block->datum);

	rc = cil_symtab_array_init(new_block->symtab, CIL_SYM_NUM);
	if (rc == SEPOL_ERR) {
		cil_destroy_block(new_block);
		return SEPOL_ERR;
	}

	new_block->is_abstract = 0;
	new_block->condition = NULL;

	*block = new_block;

	return SEPOL_OK;
}

int cil_class_init(struct cil_class **class)
{
	struct cil_class *new_class = NULL;
	int rc = SEPOL_ERR;

	if (class == NULL) {
		return SEPOL_ERR;
	}

	new_class = cil_malloc(sizeof(struct cil_class));

	cil_symtab_datum_init(&new_class->datum);

	rc = symtab_init(&new_class->perms, CIL_SYM_SIZE);
	if (rc != SEPOL_OK) {
		free(new_class);
		return rc;
	}

	new_class->common = NULL;

	*class = new_class;

	return SEPOL_OK;
}

int cil_common_init(struct cil_common **common)
{
	struct cil_common *new_common = NULL;
	int rc = SEPOL_ERR;

	if (common == NULL) {
		return SEPOL_ERR;
	}

	new_common = cil_malloc(sizeof(struct cil_common));

	cil_symtab_datum_init(&new_common->datum);
	rc = symtab_init(&new_common->perms, CIL_SYM_SIZE);
	if (rc != SEPOL_OK) {
		free(new_common);
		return rc;
	}

	*common = new_common;

	return SEPOL_OK;
}

int cil_classcommon_init(struct cil_classcommon **classcommon)
{
	struct cil_classcommon *new_classcommon = NULL;

	if (classcommon == NULL) {
		return SEPOL_ERR;
	}

	new_classcommon = cil_malloc(sizeof(struct cil_classcommon));

	new_classcommon->class_str = NULL;
	new_classcommon->class = NULL;
	new_classcommon->common_str = NULL;
	new_classcommon->common = NULL;

	*classcommon = new_classcommon;

	return SEPOL_OK;
}

int cil_sid_init(struct cil_sid **sid)
{
	struct cil_sid *new_sid = NULL;

	if (sid == NULL) {
		return SEPOL_ERR;
	}

	new_sid = cil_malloc(sizeof(struct cil_sid));

	cil_symtab_datum_init(&new_sid->datum);

	*sid = new_sid;

	return SEPOL_OK;
}

int cil_sidcontext_init(struct cil_sidcontext **sidcontext)
{
	struct cil_sidcontext *new_sidcontext = NULL;

	if (sidcontext == NULL) {
		return SEPOL_ERR;
	}

	new_sidcontext = cil_malloc(sizeof(struct cil_sidcontext));

	new_sidcontext->sid_str = NULL;
	new_sidcontext->sid = NULL;
	new_sidcontext->context_str = NULL;
	new_sidcontext->context = NULL;

	*sidcontext = new_sidcontext;

	return SEPOL_OK;
}

int cil_userrole_init(struct cil_userrole **userrole)
{
	struct cil_userrole *new_userrole = NULL;

	if (userrole == NULL) {
		return SEPOL_ERR;
	}

	new_userrole = cil_malloc(sizeof(struct cil_userrole));

	new_userrole->user_str = NULL;
	new_userrole->user = NULL;
	new_userrole->role_str = NULL;
	new_userrole->role = NULL;

	*userrole = new_userrole;

	return SEPOL_OK;
}

int cil_roledominance_init(struct cil_roledominance **roledominance)
{
	struct cil_roledominance *new_roledominance = NULL;

	if (roledominance == NULL) {
		return SEPOL_ERR;
	}

	new_roledominance = cil_malloc(sizeof(struct cil_roledominance));

	new_roledominance->role_str = NULL;
	new_roledominance->role = NULL;
	new_roledominance->domed_str = NULL;
	new_roledominance->domed = NULL;

	*roledominance = new_roledominance;

	return SEPOL_OK;
}

int cil_roletype_init(struct cil_roletype **roletype)
{
	struct cil_roletype *new_roletype = NULL;

	if (roletype == NULL) {
		return SEPOL_ERR;
	}

	new_roletype = cil_malloc(sizeof(struct cil_roletype));

	new_roletype->role_str = NULL;
	new_roletype->role = NULL;
	new_roletype->type_str = NULL;
	new_roletype->type = NULL;
	
	*roletype = new_roletype;

	return SEPOL_OK;
}

int cil_typeattribute_init(struct cil_typeattribute **typeattribute)
{
	struct cil_typeattribute *new_typeattribute = NULL;

	if (typeattribute == NULL) {
		return SEPOL_ERR;
	}

	new_typeattribute = cil_malloc(sizeof(struct cil_typeattribute));

	new_typeattribute->type_str = NULL;
	new_typeattribute->type = NULL;
	new_typeattribute->attr_str = NULL;
	new_typeattribute->attr = NULL;

	*typeattribute = new_typeattribute;

	return SEPOL_OK;
}

int cil_typealias_init(struct cil_typealias **typealias)
{
	struct cil_typealias *new_typealias = NULL;

	if (typealias == NULL) {
		return SEPOL_ERR;
	}

	new_typealias = cil_malloc(sizeof(struct cil_typealias));

	cil_symtab_datum_init(&new_typealias->datum);
	new_typealias->type_str = NULL;
	new_typealias->type = NULL;

	*typealias = new_typealias;

	return SEPOL_OK;
}

int cil_typebounds_init(struct cil_typebounds **typebnds)
{
	struct cil_typebounds *new_typebnds = NULL;

	if (typebnds == NULL) {
		return SEPOL_ERR;
	}

	new_typebnds = cil_malloc(sizeof(struct cil_typebounds));

	new_typebnds->parent_str = NULL;
	new_typebnds->child_str = NULL;

	*typebnds = new_typebnds;

	return SEPOL_OK;
}

int cil_typepermissive_init(struct cil_typepermissive **typeperm)
{
	struct cil_typepermissive *new_typeperm = NULL;

	if (typeperm == NULL) {
		return SEPOL_ERR;
	}

	new_typeperm = cil_malloc(sizeof(struct cil_typepermissive));

	new_typeperm->type_str = NULL;

	*typeperm = new_typeperm;

	return SEPOL_OK;
}

int cil_filetransition_init(struct cil_filetransition **filetrans)
{
	struct cil_filetransition *new_filetrans = NULL;

	if (filetrans == NULL) {
		return SEPOL_ERR;
	}

	new_filetrans = cil_malloc(sizeof(struct cil_filetransition));

	new_filetrans->src_str = NULL;
	new_filetrans->src = NULL;
	new_filetrans->exec_str = NULL;
	new_filetrans->exec = NULL;
	new_filetrans->proc_str = NULL;
	new_filetrans->proc = NULL;
	new_filetrans->dest_str = NULL;
	new_filetrans->dest = NULL;
	new_filetrans->path_str = NULL;

	*filetrans = new_filetrans;

	return SEPOL_OK;
}

int cil_bool_init(struct cil_bool **cilbool)
{
	struct cil_bool *new_cilbool = NULL;

	if (cilbool == NULL) {
		return SEPOL_ERR;
	}

	new_cilbool = cil_malloc(sizeof(struct cil_bool));

	cil_symtab_datum_init(&new_cilbool->datum);
	new_cilbool->value = 0;

	*cilbool = new_cilbool;
	
	return SEPOL_OK;
}

int cil_boolif_init(struct cil_booleanif **bif)
{
	struct cil_booleanif *new_bif = NULL;

	if (bif == NULL) {
		return SEPOL_ERR;
	}

	new_bif = cil_malloc(sizeof(struct cil_booleanif));

	new_bif->expr_stack = NULL;

	*bif = new_bif;

	return SEPOL_OK;
}

int cil_conditional_init(struct cil_conditional **cond)
{
	struct cil_conditional *new_cond = NULL;

	if (cond == NULL) {
		return SEPOL_ERR;
	}

	new_cond = cil_malloc(sizeof(struct cil_conditional));

	new_cond->str = NULL;
	new_cond->data = NULL;
	new_cond->flavor = CIL_AST_NODE;

	*cond = new_cond;

	return SEPOL_OK;
}

int cil_tunif_init(struct cil_tunableif **tif)
{
	int rc = SEPOL_ERR;
	struct cil_tunableif *new_tif = NULL;

	if (tif == NULL) {
		return SEPOL_ERR;
	}

	new_tif = cil_malloc(sizeof(struct cil_tunableif));

	new_tif->expr_stack = NULL;
	rc = cil_symtab_array_init(new_tif->symtab, CIL_SYM_NUM);
	if (rc != SEPOL_OK)
		return SEPOL_ERR;

	*tif = new_tif;

	return SEPOL_OK;
}

int cil_avrule_init(struct cil_avrule **avrule)
{
	struct cil_avrule *new_avrule = NULL;

	if (avrule == NULL) {
		return SEPOL_ERR;
	}

	new_avrule = cil_malloc(sizeof(struct cil_avrule));

	new_avrule->rule_kind = 0;
	new_avrule->src_str = NULL;
	new_avrule->src = NULL;
	new_avrule->tgt_str = NULL;
	new_avrule->tgt = NULL;
	new_avrule->obj_str = NULL;
	new_avrule->obj = NULL;
	new_avrule->perms_list_str = NULL;
	new_avrule->perms_list = NULL;
	new_avrule->permset_str = NULL;

	*avrule = new_avrule;

	return SEPOL_OK;
}

int cil_type_rule_init(struct cil_type_rule **type_rule)
{
	struct cil_type_rule *new_type_rule = NULL;

	if (type_rule == NULL) {
		return SEPOL_ERR;
	}

	new_type_rule = cil_malloc(sizeof(struct cil_type_rule));

	new_type_rule->rule_kind = 0;
	new_type_rule->src_str = NULL;
	new_type_rule->src = NULL;
	new_type_rule->tgt_str = NULL;
	new_type_rule->tgt = NULL;
	new_type_rule->obj_str = NULL;
	new_type_rule->obj = NULL;
	new_type_rule->result_str = NULL;
	new_type_rule->result = NULL;

	*type_rule = new_type_rule;

	return SEPOL_OK;
}

int cil_role_trans_init(struct cil_role_trans **role_trans)
{
	struct cil_role_trans *new_role_trans = NULL;

	if (role_trans == NULL) {
		return SEPOL_ERR;
	}

	new_role_trans = cil_malloc(sizeof(struct cil_role_trans));

	new_role_trans->src_str = NULL;
	new_role_trans->src = NULL;
	new_role_trans->tgt_str = NULL;
	new_role_trans->tgt = NULL;
	new_role_trans->obj_str = NULL;
	new_role_trans->obj = NULL;
	new_role_trans->result_str = NULL;
	new_role_trans->result = NULL;

	*role_trans = new_role_trans;

	return SEPOL_OK;
}

int cil_role_allow_init(struct cil_role_allow **role_allow)
{
	struct cil_role_allow *new_role_allow = NULL;

	if (role_allow == NULL) {
		return SEPOL_ERR;
	}

	new_role_allow = cil_malloc(sizeof(struct cil_role_allow));

	new_role_allow->src_str = NULL;
	new_role_allow->src = NULL;
	new_role_allow->tgt_str = NULL;
	new_role_allow->tgt = NULL;

	*role_allow = new_role_allow;

	return SEPOL_OK;
}

int cil_sensalias_init(struct cil_sensalias **sensalias)
{
	struct cil_sensalias *new_sensalias = NULL;

	if (sensalias == NULL) {
		return SEPOL_ERR;
	}

	new_sensalias = cil_malloc(sizeof(struct cil_sensalias));

	cil_symtab_datum_init(&new_sensalias->datum);
	new_sensalias->sens_str = NULL;
	new_sensalias->sens = NULL;

	*sensalias = new_sensalias;

	return SEPOL_OK;
}

int cil_catalias_init(struct cil_catalias **catalias)
{
	struct cil_catalias *new_catalias = NULL;

	if (catalias == NULL) {
		return SEPOL_ERR;
	}

	new_catalias = cil_malloc(sizeof(struct cil_catalias));

	cil_symtab_datum_init(&new_catalias->datum);
	new_catalias->cat_str = NULL;
	new_catalias->cat = NULL;

	*catalias = new_catalias;

	return SEPOL_OK;
}

int cil_catset_init(struct cil_catset **catset)
{
	struct cil_catset *new_catset = NULL;

	if (catset == NULL) {
		return SEPOL_ERR;
	}

	new_catset = cil_malloc(sizeof(struct cil_catset));

	cil_symtab_datum_init(&new_catset->datum);
	new_catset->cat_list_str = NULL;
	new_catset->cat_list = NULL;

	*catset = new_catset;

	return SEPOL_OK;
}

int cil_senscat_init(struct cil_senscat **senscat)
{
	struct cil_senscat *new_senscat = NULL;

	if (senscat == NULL) {
		return SEPOL_ERR;
	}

	new_senscat = cil_malloc(sizeof(struct cil_senscat));

	new_senscat->sens_str = NULL;
	new_senscat->cat_list_str = NULL;

	*senscat = new_senscat;

	return SEPOL_OK;
}


int cil_filecon_init(struct cil_filecon **filecon)
{
	struct cil_filecon *new_filecon = NULL;

	if (filecon == NULL) {
		return SEPOL_ERR;
	}

	new_filecon = cil_malloc(sizeof(struct cil_filecon));

	new_filecon->root_str = NULL;
	new_filecon->path_str = NULL;
	new_filecon->context_str =NULL;
	new_filecon->context = NULL;

	*filecon = new_filecon;

	return SEPOL_OK;
}

int cil_portcon_init(struct cil_portcon **portcon)
{
	struct cil_portcon *new_portcon = NULL;

	if (portcon == NULL) {
		return SEPOL_ERR;
	}

	new_portcon = cil_malloc(sizeof(struct cil_portcon));

	new_portcon->type_str = NULL;
	new_portcon->context_str = NULL;
	new_portcon->context = NULL;

	*portcon = new_portcon;

	return SEPOL_OK;
}

int cil_nodecon_init(struct cil_nodecon **nodecon)
{
	struct cil_nodecon *new_nodecon = NULL;

	if (nodecon == NULL) {
		return SEPOL_ERR;
	}

	new_nodecon = cil_malloc(sizeof(struct cil_nodecon));

	new_nodecon->addr_str = NULL;
	new_nodecon->addr = NULL;
	new_nodecon->mask_str = NULL;
	new_nodecon->mask = NULL;
	new_nodecon->context_str = NULL;
	new_nodecon->context = NULL;

	*nodecon = new_nodecon;

	return SEPOL_OK;
}

int cil_genfscon_init(struct cil_genfscon **genfscon)
{
	struct cil_genfscon *new_genfscon = NULL;

	if (genfscon == NULL) {
		return SEPOL_ERR;
	}

	new_genfscon = cil_malloc(sizeof(struct cil_genfscon));

	new_genfscon->type_str = NULL;
	new_genfscon->context_str = NULL;
	new_genfscon->context = NULL;

	*genfscon = new_genfscon;

	return SEPOL_OK;
}

int cil_fsuse_init(struct cil_fsuse **fsuse)
{
	struct cil_fsuse *new_fsuse = NULL;

	if (fsuse == NULL) {
		return SEPOL_ERR;
	}

	new_fsuse = cil_malloc(sizeof(struct cil_fsuse));

	new_fsuse->type = 0;
	new_fsuse->fs_str = NULL;
	new_fsuse->context_str = NULL;
	new_fsuse->context = NULL;

	*fsuse = new_fsuse;

	return SEPOL_OK;
}

int cil_constrain_init(struct cil_constrain **constrain)
{
	struct cil_constrain *new_constrain = NULL;

	if (constrain == NULL) {
		return SEPOL_ERR;
	}

	new_constrain = cil_malloc(sizeof(struct cil_constrain));

	new_constrain->class_list_str = NULL;
	new_constrain->class_list = NULL;
	new_constrain->perm_list_str = NULL;
	new_constrain->perm_list = NULL;
	new_constrain->expr = NULL;

	*constrain = new_constrain;

	return SEPOL_OK;
}

int cil_ipaddr_init(struct cil_ipaddr **ipaddr)
{
	struct cil_ipaddr *new_ipaddr = NULL;

	if (ipaddr == NULL) {
		return SEPOL_ERR;
	}

	new_ipaddr = cil_malloc(sizeof(struct cil_ipaddr));

	cil_symtab_datum_init(&new_ipaddr->datum);
	memset(&new_ipaddr->ip, 0, sizeof(new_ipaddr->ip));

	*ipaddr = new_ipaddr;

	return SEPOL_OK;
}

int cil_perm_init(struct cil_perm **perm)
{
	struct cil_perm *new_perm = NULL;

	if (perm == NULL) {
		return SEPOL_ERR;
	}

	new_perm = cil_malloc(sizeof(struct cil_perm));

	cil_symtab_datum_init(&new_perm->datum);

	*perm = new_perm;

	return SEPOL_OK;
}

int cil_permset_init(struct cil_permset **permset)
{
	struct cil_permset *new_permset = NULL;

	if (permset == NULL) {
		return SEPOL_ERR;
	}

	new_permset = cil_malloc(sizeof(struct cil_permset));

	cil_symtab_datum_init(&new_permset->datum);
	new_permset->perms_list_str = NULL;

	*permset = new_permset;

	return SEPOL_OK;
}

int cil_user_init(struct cil_user **user)
{
	struct cil_user *new_user = NULL;

	if (user == NULL) {
		return SEPOL_ERR;
	}

	new_user = cil_malloc(sizeof(struct cil_user));

	cil_symtab_datum_init(&new_user->datum);

	*user = new_user;

	return SEPOL_OK;
}

int cil_role_init(struct cil_role **role)
{
	struct cil_role *new_role = NULL;

	if (role == NULL) {
		return SEPOL_ERR;
	}

	new_role = cil_malloc(sizeof(struct cil_role));

	cil_symtab_datum_init(&new_role->datum);

	*role = new_role;

	return SEPOL_OK;
}

int cil_type_init(struct cil_type **type)
{
	struct cil_type *new_type = NULL;

	if (type == NULL) {
		return SEPOL_ERR;
	}

	new_type = cil_malloc(sizeof(struct cil_type));

	cil_symtab_datum_init(&new_type->datum);

	*type = new_type;

	return SEPOL_OK;
}

int cil_cat_init(struct cil_cat **cat)
{
	struct cil_cat *new_cat = NULL;

	if (cat == NULL) {
		return SEPOL_ERR;
	}

	new_cat = cil_malloc(sizeof(struct cil_cat));

	cil_symtab_datum_init(&new_cat->datum);

	*cat = new_cat;

	return SEPOL_OK;
}

int cil_catorder_init(struct cil_catorder **catorder)
{
	struct cil_catorder *new_catorder = NULL;

	if (catorder == NULL) {
		return SEPOL_ERR;
	}

	new_catorder = cil_malloc(sizeof(struct cil_catorder));

	new_catorder->cat_list_str = NULL;

	*catorder = new_catorder;

	return SEPOL_OK;
}

int cil_sens_dominates_init(struct cil_sens_dominates **sens_dominates)
{
	struct cil_sens_dominates *new_sens_dominates = NULL;

	if (sens_dominates == NULL) {
		return SEPOL_ERR;
	}

	new_sens_dominates = cil_malloc(sizeof(struct cil_sens_dominates));

	new_sens_dominates->sens_list_str = NULL;

	*sens_dominates = new_sens_dominates;

	return SEPOL_OK;
}

int cil_call_init(struct cil_call **call)
{
	struct cil_call *new_call = NULL;

	if (call == NULL) {
		return SEPOL_ERR;
	}

	new_call = cil_malloc(sizeof(struct cil_call));

	new_call->macro_str = NULL;
	new_call->macro = NULL;
	new_call->args_tree = NULL;
	new_call->args = NULL;

	*call = new_call;

	return SEPOL_OK;
}

int cil_optional_init(struct cil_optional **optional)
{
	struct cil_optional *new_optional = NULL;

	if (optional == NULL) {
		return SEPOL_ERR;
	}

	new_optional = cil_malloc(sizeof(struct cil_optional));
	cil_symtab_datum_init(&new_optional->datum);

	*optional = new_optional;

	return SEPOL_OK;
}

int cil_param_init(struct cil_param **param)
{
	struct cil_param *new_param = NULL;

	if (param == NULL) {
		return SEPOL_ERR;
	}

	new_param = cil_malloc(sizeof(struct cil_param));

	new_param->str = NULL;
	new_param->flavor = CIL_AST_STR;

	*param = new_param;

	return SEPOL_OK;
}

int cil_macro_init(struct cil_macro **macro)
{
	struct cil_macro *new_macro = NULL;
	int rc = SEPOL_ERR;

	if (macro == NULL) {
		return SEPOL_ERR;
	}

	new_macro = cil_malloc(sizeof(struct cil_macro));

	cil_symtab_datum_init(&new_macro->datum);
	rc = cil_symtab_array_init(new_macro->symtab, CIL_SYM_NUM);
	if (rc != SEPOL_OK) {
		printf("Failed to initialize symtab array\n");
		free(new_macro);
		return rc;
	}
	new_macro->params = NULL;

	*macro = new_macro;

	return SEPOL_OK;
}

int cil_policycap_init(struct cil_policycap **policycap)
{
	struct cil_policycap *new_policycap = NULL;

	if (policycap == NULL) {
		return SEPOL_ERR;
	}

	new_policycap = cil_malloc(sizeof(struct cil_policycap));

	cil_symtab_datum_init(&new_policycap->datum);

	*policycap = new_policycap;

	return SEPOL_OK;
}
