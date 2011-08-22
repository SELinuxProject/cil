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

void cil_db_init(struct cil_db **db)
{
	*db = cil_malloc(sizeof(**db));

	cil_symtab_array_init((*db)->symtab, CIL_SYM_NUM);

	cil_tree_init(&(*db)->ast);
	cil_list_init(&(*db)->catorder);
	cil_list_init(&(*db)->dominance);
	cil_sort_init(&(*db)->netifcon);
	cil_sort_init(&(*db)->genfscon);
	cil_sort_init(&(*db)->filecon);
	cil_sort_init(&(*db)->nodecon);
	cil_sort_init(&(*db)->portcon);
	cil_sort_init(&(*db)->pirqcon);
	cil_sort_init(&(*db)->iomemcon);
	cil_sort_init(&(*db)->ioportcon);
	cil_sort_init(&(*db)->pcidevicecon);
	cil_sort_init(&(*db)->fsuse);

	cil_type_init(&(*db)->selftype);
	(*db)->selftype->datum.name = cil_strdup(CIL_KEY_SELF);
}

void cil_db_destroy(struct cil_db **db)
{
	cil_tree_destroy(&(*db)->ast);
	cil_symtab_array_destroy((*db)->symtab);
	cil_list_destroy(&(*db)->catorder, CIL_FALSE);
	cil_list_destroy(&(*db)->dominance, CIL_FALSE);
	cil_sort_destroy(&(*db)->netifcon);
	cil_sort_destroy(&(*db)->genfscon);
	cil_sort_destroy(&(*db)->filecon);
	cil_sort_destroy(&(*db)->nodecon);
	cil_sort_destroy(&(*db)->portcon);
	cil_sort_destroy(&(*db)->pirqcon);
	cil_sort_destroy(&(*db)->iomemcon);
	cil_sort_destroy(&(*db)->ioportcon);
	cil_sort_destroy(&(*db)->pcidevicecon);
	cil_sort_destroy(&(*db)->fsuse);
	
	cil_destroy_type((*db)->selftype);

	free(*db);
	*db = NULL;	

}

void cil_destroy_data(void **data, enum cil_flavor flavor)
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
	case CIL_TYPEATTRIBUTE:
		cil_destroy_typeattribute(*data);
		break;
	case CIL_USER:
		cil_destroy_user(*data);
		break;
	case CIL_ROLE:
		cil_destroy_role(*data);
		break;
	case CIL_ROLETRANSITION:
		cil_destroy_roletransition(*data);
		break;
	case CIL_ROLEALLOW:
		cil_destroy_roleallow(*data);
		break;
	case CIL_ROLEDOMINANCE:
		cil_destroy_roledominance(*data);
		break;
	case CIL_ROLEBOUNDS:
		cil_destroy_rolebounds(*data);
		break;
	case CIL_BOOL:
		cil_destroy_bool(*data);
		break;
	case CIL_TUNABLE:
		cil_destroy_bool(*data);
		break;
	case CIL_CONDTRUE: break;
	case CIL_CONDFALSE: break;
	case CIL_BOOLEANIF:
		cil_destroy_boolif(*data);
		break;
	case CIL_COND:
		cil_destroy_conditional(*data);
		break;
	case CIL_TUNABLEIF:
		cil_destroy_tunif(*data);
		break;
	case CIL_TYPEALIAS:
		cil_destroy_typealias(*data);
		break;
	case CIL_TYPEATTRIBUTETYPES:
		cil_destroy_typeattributetypes(*data);
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
	case CIL_RANGETRANSITION:
		cil_destroy_rangetransition(*data);
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
	case CIL_CATRANGE:
		cil_destroy_catrange(*data);
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
	case CIL_LEVELRANGE:
		cil_destroy_levelrange(*data);
		break;
	case CIL_CONSTRAIN:
		cil_destroy_constrain(*data);
		break;
	case CIL_MLSCONSTRAIN:
		cil_destroy_constrain(*data);
		break;
	case CIL_ROLETYPE:
		cil_destroy_roletype(*data);
		break;
	case CIL_USERROLE:
		cil_destroy_userrole(*data);
		break;
	case CIL_USERLEVEL:
		cil_destroy_userlevel(*data);
		break;
	case CIL_USERRANGE:
		cil_destroy_userrange(*data);
		break;
	case CIL_USERBOUNDS:
		cil_destroy_userbounds(*data);
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
	case CIL_PIRQCON:
		cil_destroy_pirqcon(*data);
		break;
	case CIL_IOMEMCON:
		cil_destroy_iomemcon(*data);
		break;
	case CIL_IOPORTCON:
		cil_destroy_ioportcon(*data);
		break;
	case CIL_PCIDEVICECON:
		cil_destroy_pcidevicecon(*data);
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

int cil_flavor_to_symtab_index(enum cil_flavor flavor, enum cil_sym_index *sym_index)
{
	if (flavor < CIL_MIN_DECLARATIVE) {
		return SEPOL_ERR;
	}

	switch(flavor) {
	case CIL_BLOCK:
		*sym_index = CIL_SYM_BLOCKS;
		break;
	case CIL_CLASS:
		*sym_index = CIL_SYM_CLASSES;
		break;
	case CIL_COMMON:
		*sym_index = CIL_SYM_COMMONS;
		break;
	case CIL_SID:
		*sym_index = CIL_SYM_SIDS;
		break;
	case CIL_USER:
		*sym_index = CIL_SYM_USERS;
		break;
	case CIL_ROLE:
		*sym_index = CIL_SYM_ROLES;
		break;
	case CIL_TYPE:
	case CIL_TYPEALIAS:
	case CIL_TYPEATTRIBUTE:
		*sym_index = CIL_SYM_TYPES;
		break;
	case CIL_BOOL:
		*sym_index = CIL_SYM_BOOLS;
		break;
	case CIL_TUNABLE:
		*sym_index = CIL_SYM_TUNABLES;
		break;
	case CIL_CONTEXT:
		*sym_index = CIL_SYM_CONTEXTS;
		break;
	case CIL_LEVEL:
		*sym_index = CIL_SYM_LEVELS;
		break;
	case CIL_LEVELRANGE:
		*sym_index = CIL_SYM_LEVELRANGES;
		break;
	case CIL_SENS:
	case CIL_SENSALIAS:
		*sym_index = CIL_SYM_SENS;
		break;
	case CIL_CAT:
	case CIL_CATSET:
	case CIL_CATALIAS:
		*sym_index = CIL_SYM_CATS;
		break;
	case CIL_MACRO:
		*sym_index = CIL_SYM_MACROS;
		break;
	case CIL_OPTIONAL:
		*sym_index = CIL_SYM_OPTIONALS;
		break;
	case CIL_POLICYCAP:
		*sym_index = CIL_SYM_POLICYCAPS;
		break;
	case CIL_IPADDR:
		*sym_index = CIL_SYM_IPADDRS;
		break;
	default:
		*sym_index = CIL_SYM_UNKNOWN;
		printf("cil_flavor_to_symtab_index: Failed to find flavor: %d\n", flavor);
		return SEPOL_ERR;
	}

	return SEPOL_OK;
}

void cil_symtab_array_init(symtab_t symtab[], uint32_t symtab_num)
{
	uint32_t i = 0;
	for (i = 0; i < symtab_num; i++) {
		cil_symtab_init(&symtab[i], CIL_SYM_SIZE);
	}
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
			case CIL_TUNABLEIF:
				cil_symtab_array_destroy(((struct cil_tunableif*)current->data)->symtab);
				break;
			case CIL_BOOLEANIF:
				/* do nothing */
				break;
			case CIL_CALL:
				/* do nothing */
				break;
			case CIL_OPTIONAL:
				/* do nothing */
				break;
			case CIL_CONDTRUE:
				/* do nothing */
				break;
			case CIL_CONDFALSE:
				/* do nothing */
				break;
			default:
				printf("destroy symtab error, wrong flavor node: %d\n", current->flavor);
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

int cil_get_parent_symtab(struct cil_db *db, struct cil_tree_node *ast_node, symtab_t **symtab, enum cil_sym_index sym_index)
{
	int rc = SEPOL_ERR;

	if (db == NULL || ast_node == NULL) {
		goto exit;
	}

	if (ast_node->parent != NULL) {
		if (ast_node->parent->flavor == CIL_BLOCK && sym_index < CIL_SYM_NUM) {
			*symtab = &((struct cil_block*)ast_node->parent->data)->symtab[sym_index];
		} else if (ast_node->parent->flavor == CIL_MACRO  && sym_index < CIL_SYM_NUM) {
			*symtab = &((struct cil_macro*)ast_node->parent->data)->symtab[sym_index];
		} else if (ast_node->parent->flavor == CIL_CALL  && sym_index < CIL_SYM_NUM) {
			rc = cil_get_parent_symtab(db, ast_node->parent, symtab, sym_index);
			if (rc != SEPOL_OK) {
				printf("cil_get_parent_symtab: cil_call failed, rc: %d\n", rc);
				goto exit;
			}
		} else if (ast_node->parent->flavor == CIL_CLASS) {
			*symtab = &((struct cil_class*)ast_node->parent->data)->perms;
		} else if (ast_node->parent->flavor == CIL_COMMON) {
			*symtab = &((struct cil_common*)ast_node->parent->data)->perms;
		} else if (ast_node->parent->flavor == CIL_TUNABLEIF) {
			*symtab = &((struct cil_tunableif*)ast_node->parent->data)->symtab[sym_index];
		} else if ((ast_node->parent->flavor == CIL_BOOLEANIF || ast_node->parent->flavor == CIL_CONDTRUE || ast_node->parent->flavor == CIL_CONDFALSE) && sym_index < CIL_SYM_NUM) {
			rc = cil_get_parent_symtab(db, ast_node->parent, symtab, sym_index);
			if (rc != SEPOL_OK) {
				printf("cil_get_parent_symtab: cil_booleanif failed, rc: %d\n", rc);
				goto exit;
			}
		} else if (ast_node->parent->flavor == CIL_OPTIONAL && sym_index < CIL_SYM_NUM) {
			rc = cil_get_parent_symtab(db, ast_node->parent, symtab, sym_index);
			if (rc != SEPOL_OK) {
				printf("cil_get_parent_symtab: cil_optional failed, rc: %d\n", rc);
				goto exit;
			}
		} else if (ast_node->parent->flavor == CIL_ROOT && sym_index < CIL_SYM_NUM) {
			*symtab = &db->symtab[sym_index];
		} else if (sym_index >= CIL_SYM_NUM) {
			printf("Invalid index passed to cil_get_parent_symtab\n");
			rc = SEPOL_ERR;
			goto exit;
		} else {
			printf("Failed to get symtab from parent node\n");
			rc = SEPOL_ERR;
			goto exit;
		}
	} else {
		printf("Failed to get symtab: no parent node\n");
		rc = SEPOL_ERR;
		goto exit;
	}

	return SEPOL_OK;

exit:
	return rc;
}

void cil_sort_init(struct cil_sort **sort)
{
	*sort = cil_malloc(sizeof(**sort));

	(*sort)->flavor = 0;
	(*sort)->count = 0;
	(*sort)->index = 0;
	(*sort)->array = NULL;
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

	free(*sort);
	*sort = NULL;
}

void cil_netifcon_init(struct cil_netifcon **netifcon)
{
	*netifcon = cil_malloc(sizeof(**netifcon));

	(*netifcon)->interface_str = NULL;
	(*netifcon)->if_context_str = NULL;
	(*netifcon)->if_context = NULL;
	(*netifcon)->packet_context_str = NULL;
	(*netifcon)->packet_context = NULL;
}

void cil_context_init(struct cil_context **context)
{
	*context = cil_malloc(sizeof(**context));

	cil_symtab_datum_init(&(*context)->datum);
	(*context)->user_str = NULL;
	(*context)->user = NULL;
	(*context)->role_str = NULL;
	(*context)->role = NULL;
	(*context)->type_str = NULL;
	(*context)->type = NULL;
	(*context)->range_str = NULL;
	(*context)->range = NULL;
}

void cil_level_init(struct cil_level **level)
{
	*level = cil_malloc(sizeof(**level));

	cil_symtab_datum_init(&(*level)->datum);
	(*level)->sens_str = NULL;
	(*level)->sens = NULL;
	(*level)->catset_str = NULL;
	(*level)->catset = NULL;
}

void cil_levelrange_init(struct cil_levelrange **range)
{
	*range = cil_malloc(sizeof(**range));

	cil_symtab_datum_init(&(*range)->datum);
	(*range)->low = NULL;
	(*range)->high = NULL;
}

void cil_sens_init(struct cil_sens **sens)
{
	*sens = cil_malloc(sizeof(**sens));

	cil_symtab_datum_init(&(*sens)->datum);
	cil_list_init(&(*sens)->catsets);
}

void cil_block_init(struct cil_block **block)
{
	*block = cil_malloc(sizeof(**block));

	cil_symtab_datum_init(&(*block)->datum);

	cil_symtab_array_init((*block)->symtab, CIL_SYM_NUM);

	(*block)->is_abstract = 0;
	(*block)->condition = NULL;
}

void cil_class_init(struct cil_class **class)
{
	*class = cil_malloc(sizeof(**class));

	cil_symtab_datum_init(&(*class)->datum);

	cil_symtab_init(&(*class)->perms, CIL_SYM_SIZE);

	(*class)->common = NULL;
}

void cil_common_init(struct cil_common **common)
{
	*common = cil_malloc(sizeof(**common));

	cil_symtab_datum_init(&(*common)->datum);
	cil_symtab_init(&(*common)->perms, CIL_SYM_SIZE);
}

void cil_classcommon_init(struct cil_classcommon **classcommon)
{
	*classcommon = cil_malloc(sizeof(**classcommon));

	(*classcommon)->class_str = NULL;
	(*classcommon)->common_str = NULL;
}

void cil_sid_init(struct cil_sid **sid)
{
	*sid = cil_malloc(sizeof(**sid));

	cil_symtab_datum_init(&(*sid)->datum);
	
	(*sid)->context = NULL;
}

void cil_sidcontext_init(struct cil_sidcontext **sidcontext)
{
	*sidcontext = cil_malloc(sizeof(**sidcontext));

	(*sidcontext)->sid_str = NULL;
	(*sidcontext)->context_str = NULL;
	(*sidcontext)->context = NULL;
}

void cil_userrole_init(struct cil_userrole **userrole)
{
	*userrole = cil_malloc(sizeof(**userrole));

	(*userrole)->user_str = NULL;
	(*userrole)->user = NULL;
	(*userrole)->role_str = NULL;
	(*userrole)->role = NULL;
}

void cil_userbounds_init(struct cil_userbounds **userbounds)
{
	*userbounds = cil_malloc(sizeof(**userbounds));

	(*userbounds)->user_str = NULL;
	(*userbounds)->bounds_str = NULL;
}

void cil_roledominance_init(struct cil_roledominance **roledominance)
{
	*roledominance = cil_malloc(sizeof(**roledominance));

	(*roledominance)->role_str = NULL;
	(*roledominance)->role = NULL;
	(*roledominance)->domed_str = NULL;
	(*roledominance)->domed = NULL;
}

void cil_roletype_init(struct cil_roletype **roletype)
{
	*roletype = cil_malloc(sizeof(**roletype));

	(*roletype)->role_str = NULL;
	(*roletype)->role = NULL;
	(*roletype)->type_str = NULL;
	(*roletype)->type = NULL;
}

void cil_rolebounds_init(struct cil_rolebounds **rolebounds)
{
	*rolebounds = cil_malloc(sizeof(**rolebounds));

	(*rolebounds)->role_str = NULL;
	(*rolebounds)->bounds_str = NULL;
}

void cil_typeattribute_init(struct cil_typeattribute **attr)
{
	*attr = cil_malloc(sizeof(**attr));

	cil_symtab_datum_init(&(*attr)->datum);

	(*attr)->types_list = NULL;
	(*attr)->neg_list = NULL;
}

void cil_typeattributetypes_init(struct cil_typeattributetypes **attrtypes)
{
	*attrtypes = cil_malloc(sizeof(**attrtypes));

	(*attrtypes)->attr_str = NULL;
	(*attrtypes)->types_list_str = NULL;
	(*attrtypes)->neg_list_str = NULL;
}

void cil_typealias_init(struct cil_typealias **typealias)
{
	*typealias = cil_malloc(sizeof(**typealias));

	cil_symtab_datum_init(&(*typealias)->datum);
	(*typealias)->type_str = NULL;
	(*typealias)->type = NULL;
}

void cil_typebounds_init(struct cil_typebounds **typebnds)
{
	*typebnds = cil_malloc(sizeof(**typebnds));

	(*typebnds)->type_str = NULL;
	(*typebnds)->bounds_str = NULL;
}

void cil_typepermissive_init(struct cil_typepermissive **typeperm)
{
	*typeperm = cil_malloc(sizeof(**typeperm));

	(*typeperm)->type_str = NULL;
}

void cil_filetransition_init(struct cil_filetransition **filetrans)
{
	*filetrans = cil_malloc(sizeof(**filetrans));

	(*filetrans)->src_str = NULL;
	(*filetrans)->src = NULL;
	(*filetrans)->exec_str = NULL;
	(*filetrans)->exec = NULL;
	(*filetrans)->proc_str = NULL;
	(*filetrans)->proc = NULL;
	(*filetrans)->dest_str = NULL;
	(*filetrans)->dest = NULL;
	(*filetrans)->path_str = NULL;
}

void cil_rangetransition_init(struct cil_rangetransition **rangetrans)
{
        *rangetrans = cil_malloc(sizeof(**rangetrans));

	(*rangetrans)->src_str = NULL;
	(*rangetrans)->src = NULL;
	(*rangetrans)->exec_str = NULL;
	(*rangetrans)->exec = NULL;
	(*rangetrans)->obj_str = NULL;
	(*rangetrans)->obj = NULL;
	(*rangetrans)->range_str = NULL;
	(*rangetrans)->range = NULL;
}

void cil_bool_init(struct cil_bool **cilbool)
{
	*cilbool = cil_malloc(sizeof(**cilbool));

	cil_symtab_datum_init(&(*cilbool)->datum);
	(*cilbool)->value = 0;
}

void cil_boolif_init(struct cil_booleanif **bif)
{
	*bif = cil_malloc(sizeof(**bif));

	(*bif)->expr_stack = NULL;
	(*bif)->condtrue = NULL;
	(*bif)->condfalse = NULL;
}

void cil_conditional_init(struct cil_conditional **cond)
{
	*cond = cil_malloc(sizeof(**cond));

	(*cond)->str = NULL;
	(*cond)->data = NULL;
	(*cond)->flavor = CIL_AST_NODE;
}

void cil_tunif_init(struct cil_tunableif **tif)
{
	*tif = cil_malloc(sizeof(**tif));

	(*tif)->expr_stack = NULL;
	cil_symtab_array_init((*tif)->symtab, CIL_SYM_NUM);

	(*tif)->condtrue = NULL;
	(*tif)->condfalse = NULL;
}

void cil_avrule_init(struct cil_avrule **avrule)
{
	*avrule = cil_malloc(sizeof(**avrule));

	(*avrule)->rule_kind = 0;
	(*avrule)->src_str = NULL;
	(*avrule)->src = NULL;
	(*avrule)->tgt_str = NULL;
	(*avrule)->tgt = NULL;
	(*avrule)->obj_str = NULL;
	(*avrule)->obj = NULL;
	(*avrule)->perms_list_str = NULL;
	(*avrule)->perms_list = NULL;
	(*avrule)->permset_str = NULL;
}

void cil_type_rule_init(struct cil_type_rule **type_rule)
{
	*type_rule = cil_malloc(sizeof(**type_rule));

	(*type_rule)->rule_kind = 0;
	(*type_rule)->src_str = NULL;
	(*type_rule)->src = NULL;
	(*type_rule)->tgt_str = NULL;
	(*type_rule)->tgt = NULL;
	(*type_rule)->obj_str = NULL;
	(*type_rule)->obj = NULL;
	(*type_rule)->result_str = NULL;
	(*type_rule)->result = NULL;
}

void cil_roletransition_init(struct cil_roletransition **role_trans)
{
	*role_trans = cil_malloc(sizeof(**role_trans));

	(*role_trans)->src_str = NULL;
	(*role_trans)->src = NULL;
	(*role_trans)->tgt_str = NULL;
	(*role_trans)->tgt = NULL;
	(*role_trans)->obj_str = NULL;
	(*role_trans)->obj = NULL;
	(*role_trans)->result_str = NULL;
	(*role_trans)->result = NULL;
}

void cil_roleallow_init(struct cil_roleallow **roleallow)
{
	*roleallow = cil_malloc(sizeof(**roleallow));

	(*roleallow)->src_str = NULL;
	(*roleallow)->src = NULL;
	(*roleallow)->tgt_str = NULL;
	(*roleallow)->tgt = NULL;
}

void cil_sensalias_init(struct cil_sensalias **sensalias)
{
	*sensalias = cil_malloc(sizeof(**sensalias));

	cil_symtab_datum_init(&(*sensalias)->datum);
	(*sensalias)->sens_str = NULL;
	(*sensalias)->sens = NULL;
}

void cil_catalias_init(struct cil_catalias **catalias)
{
	*catalias = cil_malloc(sizeof(**catalias));

	cil_symtab_datum_init(&(*catalias)->datum);
	(*catalias)->cat_str = NULL;
	(*catalias)->cat = NULL;
}

void cil_catrange_init(struct cil_catrange **catrange)
{
	*catrange = cil_malloc(sizeof(**catrange));

	cil_symtab_datum_init(&(*catrange)->datum);
	(*catrange)->cat_low_str = NULL;
	(*catrange)->cat_low = NULL;
	(*catrange)->cat_high_str = NULL;
	(*catrange)->cat_high = NULL;
}

void cil_catset_init(struct cil_catset **catset)
{
	*catset = cil_malloc(sizeof(**catset));

	cil_symtab_datum_init(&(*catset)->datum);
	(*catset)->cat_list_str = NULL;
	(*catset)->cat_list = NULL;
}

void cil_senscat_init(struct cil_senscat **senscat)
{
	*senscat = cil_malloc(sizeof(**senscat));

	(*senscat)->sens_str = NULL;
	(*senscat)->catset_str = NULL;
	(*senscat)->catset = NULL;
}


void cil_filecon_init(struct cil_filecon **filecon)
{
	*filecon = cil_malloc(sizeof(**filecon));

	(*filecon)->root_str = NULL;
	(*filecon)->path_str = NULL;
	(*filecon)->context_str =NULL;
	(*filecon)->context = NULL;
}

void cil_portcon_init(struct cil_portcon **portcon)
{
	*portcon = cil_malloc(sizeof(**portcon));

	(*portcon)->context_str = NULL;
	(*portcon)->context = NULL;
}

void cil_nodecon_init(struct cil_nodecon **nodecon)
{
	*nodecon = cil_malloc(sizeof(**nodecon));

	(*nodecon)->addr_str = NULL;
	(*nodecon)->addr = NULL;
	(*nodecon)->mask_str = NULL;
	(*nodecon)->mask = NULL;
	(*nodecon)->context_str = NULL;
	(*nodecon)->context = NULL;
}

void cil_genfscon_init(struct cil_genfscon **genfscon)
{
	*genfscon = cil_malloc(sizeof(**genfscon));

	(*genfscon)->type_str = NULL;
	(*genfscon)->context_str = NULL;
	(*genfscon)->context = NULL;
}

void cil_pirqcon_init(struct cil_pirqcon **pirqcon)
{
	*pirqcon = cil_malloc(sizeof(**pirqcon));

	(*pirqcon)->context_str = NULL;
	(*pirqcon)->context = NULL;
}

void cil_iomemcon_init(struct cil_iomemcon **iomemcon)
{
	*iomemcon = cil_malloc(sizeof(**iomemcon));

	(*iomemcon)->context_str = NULL;
	(*iomemcon)->context = NULL;
}

void cil_ioportcon_init(struct cil_ioportcon **ioportcon)
{
	*ioportcon = cil_malloc(sizeof(**ioportcon));

	(*ioportcon)->context_str = NULL;
	(*ioportcon)->context = NULL;
}

void cil_pcidevicecon_init(struct cil_pcidevicecon **pcidevicecon)
{
	*pcidevicecon = cil_malloc(sizeof(**pcidevicecon));

	(*pcidevicecon)->context_str = NULL;
	(*pcidevicecon)->context = NULL;
}

void cil_fsuse_init(struct cil_fsuse **fsuse)
{
	*fsuse = cil_malloc(sizeof(**fsuse));

	(*fsuse)->type = 0;
	(*fsuse)->fs_str = NULL;
	(*fsuse)->context_str = NULL;
	(*fsuse)->context = NULL;
}

void cil_constrain_init(struct cil_constrain **constrain)
{
	*constrain = cil_malloc(sizeof(**constrain));

	(*constrain)->class_list_str = NULL;
	(*constrain)->class_list = NULL;
	(*constrain)->perm_list_str = NULL;
	(*constrain)->perm_list = NULL;
	(*constrain)->expr = NULL;
}

void cil_ipaddr_init(struct cil_ipaddr **ipaddr)
{
	*ipaddr = cil_malloc(sizeof(**ipaddr));

	cil_symtab_datum_init(&(*ipaddr)->datum);
	memset(&(*ipaddr)->ip, 0, sizeof((*ipaddr)->ip));
}

void cil_perm_init(struct cil_perm **perm)
{
	*perm = cil_malloc(sizeof(**perm));

	cil_symtab_datum_init(&(*perm)->datum);
}

void cil_permset_init(struct cil_permset **permset)
{
	*permset = cil_malloc(sizeof(**permset));

	cil_symtab_datum_init(&(*permset)->datum);
	(*permset)->perms_list_str = NULL;
}

void cil_user_init(struct cil_user **user)
{
	*user = cil_malloc(sizeof(**user));

	cil_symtab_datum_init(&(*user)->datum);
	(*user)->bounds = NULL;
	(*user)->dftlevel = NULL;
	(*user)->range = NULL;
}

void cil_userlevel_init(struct cil_userlevel **usrlvl)
{
	*usrlvl = cil_malloc(sizeof(**usrlvl));

	(*usrlvl)->user_str = NULL;
	(*usrlvl)->level_str = NULL;
	(*usrlvl)->level = NULL;
}

void cil_userrange_init(struct cil_userrange **userrange)
{
	*userrange = cil_malloc(sizeof(**userrange));

	(*userrange)->user_str = NULL;
	(*userrange)->range_str = NULL;
	(*userrange)->range = NULL;
}

void cil_role_init(struct cil_role **role)
{
	*role = cil_malloc(sizeof(**role));

	cil_symtab_datum_init(&(*role)->datum);
}

void cil_type_init(struct cil_type **type)
{
	*type = cil_malloc(sizeof(**type));

	cil_symtab_datum_init(&(*type)->datum);
}

void cil_cat_init(struct cil_cat **cat)
{
	*cat = cil_malloc(sizeof(**cat));

	cil_symtab_datum_init(&(*cat)->datum);
}

void cil_catorder_init(struct cil_catorder **catorder)
{
	*catorder = cil_malloc(sizeof(**catorder));

	(*catorder)->cat_list_str = NULL;
}

void cil_sens_dominates_init(struct cil_sens_dominates **sens_dominates)
{
	*sens_dominates = cil_malloc(sizeof(**sens_dominates));

	(*sens_dominates)->sens_list_str = NULL;
}

void cil_args_init(struct cil_args **args)
{
	*args = cil_malloc(sizeof(**args));
	(*args)->arg_str = NULL;
	(*args)->arg = NULL;
	(*args)->param_str = NULL;
	(*args)->flavor = CIL_AST_STR;
}

void cil_call_init(struct cil_call **call)
{
	*call = cil_malloc(sizeof(**call));

	(*call)->macro_str = NULL;
	(*call)->macro = NULL;
	(*call)->args_tree = NULL;
	(*call)->args = NULL;
}

void cil_optional_init(struct cil_optional **optional)
{
	*optional = cil_malloc(sizeof(**optional));
	cil_symtab_datum_init(&(*optional)->datum);
}

void cil_param_init(struct cil_param **param)
{
	*param = cil_malloc(sizeof(**param));

	(*param)->str = NULL;
	(*param)->flavor = CIL_AST_STR;
}

void cil_macro_init(struct cil_macro **macro)
{
	*macro = cil_malloc(sizeof(**macro));

	cil_symtab_datum_init(&(*macro)->datum);
	cil_symtab_array_init((*macro)->symtab, CIL_SYM_NUM);
	(*macro)->params = NULL;
}

void cil_policycap_init(struct cil_policycap **policycap)
{
	*policycap = cil_malloc(sizeof(**policycap));

	cil_symtab_datum_init(&(*policycap)->datum);
}
