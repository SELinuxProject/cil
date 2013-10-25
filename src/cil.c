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

#include "cil_internal.h"
#include "cil_log.h"
#include "cil_mem.h"
#include "cil_tree.h"
#include "cil_list.h"
#include "cil_symtab.h"
#include "cil_build_ast.h"

#include "cil_parser.h"
#include "cil_build_ast.h"
#include "cil_resolve_ast.h"
#include "cil_fqn.h"
#include "cil_post.h"
#include "cil_binary.h"
#include "cil_policy.h"

int cil_sym_sizes[CIL_SYM_ARRAY_NUM][CIL_SYM_NUM] = {
	{64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64},
	{64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64},
	{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
	{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
	{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
};

void cil_db_init(struct cil_db **db)
{
	*db = cil_malloc(sizeof(**db));

	cil_symtab_array_init((*db)->symtab, cil_sym_sizes[CIL_SYM_ARRAY_ROOT]);

	cil_tree_init(&(*db)->parse);
	cil_tree_init(&(*db)->ast);
	(*db)->catorder = NULL;
	(*db)->dominance = NULL;
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
	cil_list_init(&(*db)->userprefixes, CIL_LIST_ITEM);
	cil_list_init(&(*db)->selinuxusers, CIL_LIST_ITEM);

	cil_type_init(&(*db)->selftype);
	(*db)->selftype->datum.name = cil_strdup(CIL_KEY_SELF);

	(*db)->num_types = 0;
	(*db)->num_roles = 0;
	(*db)->val_to_type = NULL;
	(*db)->val_to_role = NULL;

	(*db)->disable_dontaudit = CIL_FALSE;
}

void cil_db_destroy(struct cil_db **db)
{
	if (db == NULL || *db == NULL) {
		return;
	}

	cil_tree_destroy(&(*db)->parse);
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
	cil_list_destroy(&(*db)->userprefixes, CIL_FALSE);
	cil_list_destroy(&(*db)->selinuxusers, CIL_FALSE);
	
	cil_destroy_type((*db)->selftype);

	free((*db)->val_to_type);
	free((*db)->val_to_role);

	free(*db);
	*db = NULL;	
}

int cil_add_file(cil_db_t *db, char *name, char *data, size_t size)
{
	char *buffer = NULL;
	int rc;

	cil_log(CIL_INFO, "Parsing %s\n", name);

	buffer = cil_malloc(size + 2);
	memcpy(buffer, data, size);
	memset(buffer + size, 0, 2);

	rc = cil_parser(name, buffer, size + 2, &db->parse);
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Failed to parse %s\n", name);
		goto exit;
	}

	free(buffer);
	buffer = NULL;

	rc = SEPOL_OK;

exit:
	free(buffer);

	return rc;
}

int cil_compile(struct cil_db *db, sepol_policydb_t *sepol_db)
{
	int rc = SEPOL_ERR;

	if (db == NULL || sepol_db == NULL) {
		goto exit;
	}

	cil_log(CIL_INFO, "Building AST from Parse Tree\n");
	rc = cil_build_ast(db, db->parse->root, db->ast->root);
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Failed to build ast\n");
		goto exit;
	}

	cil_log(CIL_INFO, "Destroying Parse Tree\n");
	cil_tree_destroy(&db->parse);

	cil_log(CIL_INFO, "Resolving AST\n");
	rc = cil_resolve_ast(db, db->ast->root);
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Failed to resolve ast\n");
		goto exit;
	}

	cil_log(CIL_INFO, "Qualifying Names\n");
	rc = cil_fqn_qualify(db->ast->root);
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Failed to qualify names\n");
		goto exit;
	}

	cil_log(CIL_INFO, "Compile post process\n");
	rc = cil_post_process(db);
	if (rc != SEPOL_OK ) {
		cil_log(CIL_ERR, "Post process failed\n");
		goto exit;
	}

	cil_log(CIL_INFO, "Destroying AST Symtabs\n");
	rc = cil_destroy_ast_symtabs(db->ast->root);
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Failed to destroy ast symtabs\n");
		goto exit;
	}

exit:

	return rc;
}

int cil_build_policydb(cil_db_t *db, sepol_policydb_t *sepol_db)
{
	int rc;

	cil_log(CIL_INFO, "Building policy binary\n");
	rc = cil_binary_create(db, sepol_db);
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Failed to generate binary\n");
		goto exit;
	}

exit:
	return rc;
}

void cil_destroy_data(void **data, enum cil_flavor flavor)
{
	if (*data == NULL) {
		return;
	}

	switch(flavor) {
		case CIL_NONE:
		break;
	case CIL_ROOT:
		free(*data);
		break;
	case CIL_PARSE_NODE:
		free(*data);
		break;
	case CIL_STRING:
		free(*data);
		break;
	case CIL_LIST:
		free(*data);
		break;
	case CIL_BLOCK:
		cil_destroy_block(*data);
		break;
	case CIL_BLOCKINHERIT:
		cil_destroy_blockinherit(*data);
		break;
	case CIL_BLOCKABSTRACT:
		cil_destroy_blockabstract(*data);
		break;
	case CIL_IN:
		cil_destroy_in(*data);
		break;
	case CIL_CLASS:
		cil_destroy_class(*data);
		break;
	case CIL_MAP_PERM:
		cil_destroy_map_perm(*data);
		break;
	case CIL_MAP_CLASS:
		cil_destroy_map_class(*data);
		break;
	case CIL_CLASSMAPPING:
		cil_destroy_classmapping(*data);
		break;
	case CIL_PERM:
		cil_destroy_perm(*data);
		break;
	case CIL_CLASSPERMSET:
		cil_destroy_classpermset(*data);
		break;
	case CIL_CLASSPERMS:
		cil_destroy_classperms(*data);
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
	case CIL_ROLEATTRIBUTE:
		cil_destroy_roleattribute(*data);
		break;
	case CIL_ROLEATTRIBUTESET:
		cil_destroy_roleattributeset(*data);
		break;
	case CIL_ROLEBOUNDS:
		cil_destroy_rolebounds(*data);
		break;
	case CIL_BOOL:
		cil_destroy_bool(*data);
		break;
	case CIL_TUNABLE:
		cil_destroy_tunable(*data);
		break;
	case CIL_CONDBLOCK:
		cil_destroy_condblock(*data);
		break;
	case CIL_BOOLEANIF:
		cil_destroy_boolif(*data);
		break;
	case CIL_TUNABLEIF:
		cil_destroy_tunif(*data);
		break;
	case CIL_TYPEALIAS:
		cil_destroy_typealias(*data);
		break;
	case CIL_TYPEATTRIBUTESET:
		cil_destroy_typeattributeset(*data);
		break;
	case CIL_TYPEBOUNDS:
		cil_destroy_typebounds(*data);
		break;
	case CIL_TYPEPERMISSIVE:
		cil_destroy_typepermissive(*data);
		break;
	case CIL_NAME:
		cil_destroy_name(*data);
		break;
	case CIL_NAMETYPETRANSITION:
		cil_destroy_typetransition(*data);
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
	case CIL_VALIDATETRANS:
	case CIL_MLSVALIDATETRANS:
		cil_destroy_validatetrans(*data);
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
	case CIL_USERPREFIX:
		cil_destroy_userprefix(*data);
		break;
	case CIL_SELINUXUSER:
	case CIL_SELINUXUSERDEFAULT:
		cil_destroy_selinuxuser(*data);
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
	case CIL_INT:
		break;
	case CIL_OP:
		free(*data);
		break;
	case CIL_CONS_OPERAND:
		free(*data);
		break;
	default:
		cil_log(CIL_INFO, "Unknown data flavor: %d\n", flavor);
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
	case CIL_PERM:
	case CIL_MAP_PERM:
		*sym_index = CIL_SYM_PERMS;
		break;
	case CIL_CLASSPERMSET:
		*sym_index = CIL_SYM_CLASSPERMSETS;
		break;
	case CIL_MAP_CLASS:
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
		*sym_index = CIL_SYM_BLOCKS;
		break;
	case CIL_OPTIONAL:
		*sym_index = CIL_SYM_BLOCKS;
		break;
	case CIL_POLICYCAP:
		*sym_index = CIL_SYM_POLICYCAPS;
		break;
	case CIL_IPADDR:
		*sym_index = CIL_SYM_IPADDRS;
		break;
	case CIL_NAME:
		*sym_index = CIL_SYM_NAMES;
		break;
	default:
		*sym_index = CIL_SYM_UNKNOWN;
		cil_log(CIL_INFO, "Failed to find flavor: %d\n", flavor);
		return SEPOL_ERR;
	}

	return SEPOL_OK;
}

const char * cil_node_to_string(struct cil_tree_node *node)
{
	switch (node->flavor) {
	case CIL_ROOT:
		return CIL_KEY_ROOT;
	case CIL_AST_NODE:
		return CIL_KEY_AST_NODE;
	case CIL_PARSE_NODE:
		return CIL_KEY_PARSE_NODE;
	case CIL_AVRULE:
		switch (((struct cil_avrule *)node->data)->rule_kind) {
		case CIL_AVRULE_ALLOWED:
			return CIL_KEY_ALLOW;
		case CIL_AVRULE_AUDITALLOW:
			return CIL_KEY_AUDITALLOW;
		case CIL_AVRULE_DONTAUDIT:
			return CIL_KEY_DONTAUDIT;
		case CIL_AVRULE_NEVERALLOW:
			return CIL_KEY_NEVERALLOW;
		}
		break;
	case CIL_BLOCKINHERIT:
		return CIL_KEY_BLOCKINHERIT;
	case CIL_IN:
		return CIL_KEY_IN;
	case CIL_FILECON:
		return CIL_KEY_FILECON;
	case CIL_PORTCON:
		return CIL_KEY_PORTCON;
	case CIL_NODECON:
		return CIL_KEY_NODECON;
	case CIL_GENFSCON:
		return CIL_KEY_GENFSCON;
	case CIL_NETIFCON:
		return CIL_KEY_NETIFCON;
	case CIL_PIRQCON:
		return CIL_KEY_PIRQCON;
	case CIL_IOMEMCON:
		return CIL_KEY_IOMEMCON;
	case CIL_IOPORTCON:
		return CIL_KEY_IOPORTCON;
	case CIL_PCIDEVICECON:
		return CIL_KEY_PCIDEVICECON;
	case CIL_FSUSE:
		return CIL_KEY_FSUSE;
	case CIL_CONSTRAIN:
		return CIL_KEY_CONSTRAIN;
	case CIL_MLSCONSTRAIN:
		return CIL_KEY_MLSCONSTRAIN;
	case CIL_PERM:
		return CIL_KEY_PERM;
	case CIL_CLASSMAPPING:
		return CIL_KEY_CLASSMAPPING;
	case CIL_USERROLE:
		return CIL_KEY_USERROLE;
	case CIL_USERLEVEL:
		return CIL_KEY_USERLEVEL;
	case CIL_USERRANGE:
		return CIL_KEY_USERRANGE;
	case CIL_USERBOUNDS:
		return CIL_KEY_USERBOUNDS;
	case CIL_TYPEATTRIBUTESET:
		return CIL_KEY_TYPEATTRIBUTESET;
	case CIL_TYPE_RULE:
		switch (((struct cil_type_rule *)node->data)->rule_kind) {
		case CIL_TYPE_TRANSITION:
			return CIL_KEY_TYPETRANSITION;
		case CIL_TYPE_MEMBER:
			return CIL_KEY_TYPEMEMBER;
		case CIL_TYPE_CHANGE:
			return CIL_KEY_TYPECHANGE;
		}
		break;
	case CIL_TYPEBOUNDS:
		return CIL_KEY_TYPEBOUNDS;
	case CIL_NAMETYPETRANSITION:
		return CIL_KEY_TYPETRANSITION;
	case CIL_RANGETRANSITION:
		return CIL_KEY_RANGETRANSITION;
	case CIL_TYPEPERMISSIVE:
		return CIL_KEY_TYPEPERMISSIVE;
	case CIL_ROLETRANSITION:
		return CIL_KEY_ROLETRANSITION;
	case CIL_ROLEALLOW:
		return CIL_KEY_ROLEALLOW;
	case CIL_ROLETYPE:
		return CIL_KEY_ROLETYPE;
	case CIL_ROLEBOUNDS:
		return CIL_KEY_ROLEBOUNDS;
	case CIL_CATORDER:
		return CIL_KEY_CATORDER;
	case CIL_DOMINANCE:
		return CIL_KEY_DOMINANCE;
	case CIL_SENSCAT:
		return CIL_KEY_SENSCAT;
	case CIL_CLASSCOMMON:
		return CIL_KEY_CLASSCOMMON;
	case CIL_SIDCONTEXT:
		return CIL_KEY_SIDCONTEXT;
	case CIL_CALL:
		return CIL_KEY_CALL;
	case CIL_BOOLEANIF:
		return CIL_KEY_BOOLEANIF;
	case CIL_TUNABLEIF:
		return CIL_KEY_TUNABLEIF;
	case CIL_CONDBLOCK:
		switch (((struct cil_condblock*)node->data)->flavor) {
		case CIL_CONDTRUE:
			return CIL_KEY_CONDTRUE;
		case CIL_CONDFALSE:
			return CIL_KEY_CONDFALSE;
		default:
			break;
		}
		break;
	case CIL_TUNABLEIFDEF:
		return CIL_KEY_TUNABLEIFDEF;
	case CIL_TUNABLEIFNDEF:
		return CIL_KEY_TUNABLEIFNDEF;
	case CIL_AND:
		return CIL_KEY_AND;
	case CIL_OR:
		return CIL_KEY_OR;
	case CIL_XOR:
		return CIL_KEY_XOR;
	case CIL_NOT:
		return CIL_KEY_NOT;
	case CIL_EQ:
		return CIL_KEY_EQ;
	case CIL_NEQ:
		return CIL_KEY_NEQ;
	case CIL_CONS_DOM:
		return CIL_KEY_CONS_DOM;
	case CIL_CONS_DOMBY:
		return CIL_KEY_CONS_DOMBY;
	case CIL_CONS_INCOMP:
		return CIL_KEY_CONS_INCOMP;
	case CIL_CONS_U1:
		return CIL_KEY_CONS_U1;
	case CIL_CONS_U2:
		return CIL_KEY_CONS_U2;
	case CIL_CONS_T1:
		return CIL_KEY_CONS_T1;
	case CIL_CONS_T2:
		return CIL_KEY_CONS_T2;
	case CIL_CONS_R1:
		return CIL_KEY_CONS_R1;
	case CIL_CONS_R2:
		return CIL_KEY_CONS_R2;
	case CIL_CONS_L1:
		return CIL_KEY_CONS_L1;
	case CIL_CONS_L2:
		return CIL_KEY_CONS_L2;
	case CIL_CONS_H1:
		return CIL_KEY_CONS_H1;
	case CIL_CONS_H2:
		return CIL_KEY_CONS_H2;
	case CIL_BLOCK:
		return CIL_KEY_BLOCK;
	case CIL_CLASS:
		return CIL_KEY_CLASS;
	case CIL_MAP_CLASS:
		return CIL_KEY_MAP_CLASS;
	case CIL_COMMON:
		return CIL_KEY_COMMON;
	case CIL_SID:
		return CIL_KEY_SID;
	case CIL_USER:
		return CIL_KEY_USER;
	case CIL_ROLE:
		return CIL_KEY_ROLE;
	case CIL_TYPE:
		return CIL_KEY_TYPE;
	case CIL_TYPEATTRIBUTE:
		return CIL_KEY_TYPEATTRIBUTE;
	case CIL_BOOL:
		return CIL_KEY_BOOL;
	case CIL_CLASSPERMSET:
		return CIL_KEY_CLASSPERMSET;
	case CIL_CLASSPERMS:
		return CIL_KEY_CLASSPERMS;
	case CIL_TUNABLE:
		return CIL_KEY_TUNABLE;
	case CIL_TYPEALIAS:
		return CIL_KEY_TYPEALIAS;
	case CIL_CONTEXT:
		return CIL_KEY_CONTEXT;
	case CIL_LEVEL:
		return CIL_KEY_LEVEL;
	case CIL_LEVELRANGE:
		return CIL_KEY_LEVELRANGE;
	case CIL_SENS:
		return CIL_KEY_SENSITIVITY;
	case CIL_CAT:
		return CIL_KEY_CATEGORY;
	case CIL_SENSALIAS:
		return CIL_KEY_SENSALIAS;
	case CIL_CATALIAS:
		return CIL_KEY_CATALIAS;
	case CIL_CATRANGE:
		return CIL_KEY_CATRANGE;
	case CIL_CATSET:
		return CIL_KEY_CATSET;
	case CIL_MACRO:
		return CIL_KEY_MACRO;
	case CIL_OPTIONAL:
		return CIL_KEY_OPTIONAL;
	case CIL_POLICYCAP:
		return CIL_KEY_POLICYCAP;
	case CIL_IPADDR:
		return CIL_KEY_IPADDR;
	}

	return "<unknown>";
}

int cil_userprefixes_to_string(struct cil_db *db, __attribute__((unused)) sepol_policydb_t *sepol_db, char **out, size_t *size)
{
	int rc = SEPOL_ERR;
	size_t str_len = 0;
	int buf_pos = 0;
	char *str_tmp = NULL;
	struct cil_list_item *curr;
	struct cil_userprefix *userprefix = NULL;
	struct cil_user *user = NULL;

	*out = NULL;

	if (db->userprefixes->head == NULL) {
		rc = SEPOL_OK;
		*size = 0;
		goto exit;
	}

	cil_list_for_each(curr, db->userprefixes) {
		userprefix = curr->data;
		user = userprefix->user;
		str_len += strlen("user ") + strlen(user->datum.name) + strlen(" prefix ") + strlen(userprefix->prefix_str) + 2;
	}

	*size = str_len * sizeof(char);
	str_len++;
	str_tmp = cil_malloc(str_len * sizeof(char));
	*out = str_tmp;

	cil_list_for_each(curr, db->userprefixes) {
		userprefix = curr->data;
		user = userprefix->user;

		buf_pos = snprintf(str_tmp, str_len, "user %s prefix %s;\n", user->datum.name,
									userprefix->prefix_str);
		str_len -= buf_pos;
		str_tmp += buf_pos;
	}

	rc = SEPOL_OK;
exit:
	return rc;

}

int __cil_level_to_string(struct cil_level *lvl, char **out)
{
	struct cil_list_item *curr_cat;
	struct cil_catset *catset = lvl->catset;
	int str_len = 0;
	int buf_pos = 0;
	char *str_tmp = NULL;

	str_len += strlen(lvl->sens->datum.name) + 1;

	if (catset != NULL) {
		cil_list_for_each(curr_cat, catset->cat_list) {
			switch (curr_cat->flavor) {
			case CIL_CATRANGE: {
				struct cil_catrange *catrange = curr_cat->data;
				str_len += (strlen(catrange->cat_low->datum.name)
					+ strlen(catrange->cat_high->datum.name)) + 1;
				break;
			}
			case CIL_CAT: {
				struct cil_cat *cat = curr_cat->data;
				str_len += strlen(cat->datum.name);
			}
			default:
				break;
			}

			if (curr_cat->next != NULL) {
				str_len += 1;
			}
		}
	}
	str_len += 1;
	str_tmp = cil_malloc(sizeof(char) * (str_len));
	*out = str_tmp;

	buf_pos = snprintf(str_tmp, str_len, "%s", lvl->sens->datum.name);
	str_len -= buf_pos;
	str_tmp += buf_pos;

	if (catset != NULL) {
		strncat(str_tmp, ":", str_len);
		str_len -= 1;
		str_tmp += 1;

		for (curr_cat = catset->cat_list->head; curr_cat != NULL;
						curr_cat = curr_cat->next) {
			switch (curr_cat->flavor) {
			case CIL_CATRANGE: {
				struct cil_catrange *catrange = curr_cat->data;
				buf_pos = snprintf(str_tmp, str_len, "%s.%s",
						catrange->cat_low->datum.name,
						catrange->cat_high->datum.name);
				str_len -= buf_pos;
				str_tmp += buf_pos;
				break;
			}
			case CIL_CAT: {
				struct cil_cat *cat = curr_cat->data;
				buf_pos = snprintf(str_tmp, str_len, "%s", cat->datum.name);
				str_len -= buf_pos;
				str_tmp += buf_pos;
			}
			default:
				break;
			}

			if (curr_cat->next != NULL) {
				strncat(str_tmp, ",", str_len);
				str_len -= 1;
				str_tmp += 1;
			}
		}
	}

	return SEPOL_OK;
}

int cil_selinuxusers_to_string(struct cil_db *db, sepol_policydb_t *sepol_db, char **out, size_t *size)
{
	int rc = SEPOL_ERR;
	size_t str_len = 0;
	int buf_pos = 0;
	char *str_tmp = NULL;
	struct cil_list_item *curr;
	struct cil_selinuxuser *selinuxuser = NULL;
	struct cil_user *user = NULL;

	*out = NULL;

	if (db->selinuxusers->head == NULL) {
		*size = 0;
		rc = SEPOL_OK;
		goto exit;
	}

	cil_list_for_each(curr, db->selinuxusers) {
		selinuxuser = curr->data;
		user = selinuxuser->user;
		str_len += strlen(selinuxuser->name_str) + strlen(user->datum.name) + 1;

		if (sepol_db->p.mls == CIL_TRUE) {
			struct cil_levelrange *range = selinuxuser->range;
			struct cil_level *low = range->low;
			struct cil_level *high = range->high;
			char *str_low = NULL;
			char *str_high = NULL;

			rc = __cil_level_to_string(low, &str_low);
			if (rc != SEPOL_OK) {
				goto exit;
			}

			rc = __cil_level_to_string(high, &str_high);
			if (rc != SEPOL_OK) {
				goto exit;
			}

			str_len += (strlen(str_low) + strlen(str_high) + 2);
			free(str_low);
			free(str_high);
		}

		str_len++;
	}

	*size = str_len * sizeof(char);
	str_len++;
	str_tmp = cil_malloc(str_len * sizeof(char));
	*out = str_tmp;

	for(curr = db->selinuxusers->head; curr != NULL; curr = curr->next) {
		selinuxuser = curr->data;
		user = selinuxuser->user;

		buf_pos = snprintf(str_tmp, str_len, "%s:%s", selinuxuser->name_str,
									user->datum.name);
		str_len -= buf_pos;
		str_tmp += buf_pos;

		if (sepol_db->p.mls == CIL_TRUE) {
			struct cil_levelrange *range = selinuxuser->range;
			struct cil_level *low = range->low;
			struct cil_level *high = range->high;
			char *str_low = NULL;
			char *str_high = NULL;

			rc = __cil_level_to_string(low, &str_low);
			if (rc != SEPOL_OK) {
				goto exit;
			}

			rc = __cil_level_to_string(high, &str_high);
			if (rc != SEPOL_OK) {
				goto exit;
			}

			buf_pos = snprintf(str_tmp, str_len, ":%s-%s", str_low, str_high);
			str_len -= buf_pos;
			str_tmp += buf_pos;

			free(str_low);
			free(str_high);
		}

		buf_pos = snprintf(str_tmp, str_len, "\n");
		str_len -= 1;
		str_tmp += 1;
	}

	rc = SEPOL_OK;
exit:
	return rc;
}

int cil_filecons_to_string(struct cil_db *db, sepol_policydb_t *sepol_db, char **out, size_t *size)
{
	int rc = SEPOL_ERR;
	uint32_t i = 0;
	int buf_pos = 0;
	size_t str_len = 0;
	char *str_tmp = NULL;
	struct cil_sort *filecons = db->filecon;
	struct cil_filecon *filecon = NULL;
	struct cil_context *ctx = NULL;

	for (i = 0; i < filecons->count; i++) {
		filecon = filecons->array[i];
		ctx = filecon->context;

		str_len += (strlen(filecon->root_str) + strlen(filecon->path_str));

		if (filecon->type != CIL_FILECON_ANY) {
			/* If a type is specified,
			   +2 for type string, +1 for tab */
			str_len += 3;
		}

		if (ctx != NULL) {
			struct cil_user *user = ctx->user;
			struct cil_role *role = ctx->role;
			struct cil_type *type = ctx->type;

			str_len += (strlen(user->datum.name) + strlen(role->datum.name) + strlen(type->datum.name) + 3);

			if (sepol_db->p.mls == CIL_TRUE) {
				struct cil_levelrange *range = ctx->range;
				struct cil_level *low = range->low;
				struct cil_level *high = range->high;
				char *str_low = NULL;
				char *str_high = NULL;

				rc = __cil_level_to_string(low, &str_low);
				if (rc != SEPOL_OK) {
					goto exit;
				}

				rc = __cil_level_to_string(high, &str_high);
				if (rc != SEPOL_OK) {
					goto exit;
				}

				str_len += (strlen(str_low) + strlen(str_high) + 2);
				free(str_low);
				free(str_high);
			}
		} else {
			str_len += strlen("\t<<none>>");
		}

		str_len++;
	}

	*size = str_len * sizeof(char);
	str_len++;
	str_tmp = cil_malloc(str_len * sizeof(char));
	*out = str_tmp;

	for (i = 0; i < filecons->count; i++) {
		char *str_type = NULL;
		filecon = filecons->array[i];
		ctx = filecon->context;

		buf_pos = snprintf(str_tmp, str_len, "%s%s", filecon->root_str,
									filecon->path_str);

		str_len += buf_pos;
		str_tmp += buf_pos;

		switch(filecon->type) {
		case CIL_FILECON_FILE:
			str_type = "\t--";
			break;
		case CIL_FILECON_DIR:
			str_type = "\t-d";
			break;
		case CIL_FILECON_CHAR:
			str_type = "\t-c";
			break;
		case CIL_FILECON_BLOCK:
			str_type = "\t-b";
			break;
		case CIL_FILECON_SOCKET:
			str_type = "\t-s";
			break;
		case CIL_FILECON_PIPE:
			str_type = "\t-p";
			break;
		case CIL_FILECON_SYMLINK:
			str_type = "\t-l";
			break;
		default:
			str_type = "";
			break;
		}
		strncat(str_tmp, str_type, str_len);

		str_len -= strlen(str_type);
		str_tmp += strlen(str_type);

		if (ctx != NULL) {
			struct cil_user *user = ctx->user;
			struct cil_role *role = ctx->role;
			struct cil_type *type = ctx->type;

			buf_pos = snprintf(str_tmp, str_len, "\t%s:%s:%s", user->datum.name,
									role->datum.name,
									type->datum.name);

			str_len -= buf_pos;
			str_tmp += buf_pos;

			if (sepol_db->p.mls == CIL_TRUE) {
				struct cil_levelrange *range = ctx->range;
				struct cil_level *low = range->low;
				struct cil_level *high = range->high;
				char *str_low = NULL;
				char *str_high = NULL;

				rc = __cil_level_to_string(low, &str_low);
				if (rc != SEPOL_OK) {
					goto exit;
				}

				rc = __cil_level_to_string(high, &str_high);
				if (rc != SEPOL_OK) {
					goto exit;
				}

				buf_pos = snprintf(str_tmp, str_len, ":%s-%s", str_low, str_high);
				str_len -= buf_pos;
				str_tmp += buf_pos;

				free(str_low);
				free(str_high);
			}
		} else {
			buf_pos = snprintf(str_tmp, str_len, "\t<<none>>");
			str_len -= buf_pos;
			str_tmp += buf_pos;
		}

		buf_pos = snprintf(str_tmp, str_len, "\n");
		str_len -= 1;
		str_tmp += 1;
	}

	rc = SEPOL_OK;
exit:
	return rc;
}

void cil_set_disable_dontaudit(struct cil_db *db, int disable_dontaudit)
{
	db->disable_dontaudit = disable_dontaudit;
}

void cil_symtab_array_init(symtab_t symtab[], int symtab_sizes[CIL_SYM_NUM])
{
	uint32_t i = 0;
	for (i = 0; i < CIL_SYM_NUM; i++) {
		cil_symtab_init(&symtab[i], symtab_sizes[i]);
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
	int rc = SEPOL_ERR;

	if (current == NULL) {
		rc = SEPOL_OK;
		goto exit;
	}

	do {
		if (current->cl_head != NULL && !reverse) {
			switch (current->flavor) {
			case CIL_ROOT:
				break;
			case CIL_BLOCK:
				cil_symtab_array_destroy(((struct cil_block*)current->data)->symtab);
				break;
			case CIL_IN:
				cil_symtab_array_destroy(((struct cil_in*)current->data)->symtab);
				break;
			case CIL_CLASS:
				cil_symtab_destroy(&((struct cil_class*)current->data)->perms);
				break;
			case CIL_MAP_CLASS:
				cil_symtab_destroy(&((struct cil_map_class*)current->data)->perms);
				break;
			case CIL_COMMON:
				cil_symtab_destroy(&((struct cil_common*)current->data)->perms);
				break;
			case CIL_MACRO:
				cil_symtab_array_destroy(((struct cil_macro*)current->data)->symtab);
				break;
			case CIL_TUNABLEIF:
				break;
			case CIL_BOOLEANIF:
				/* do nothing */
				break;
			case CIL_CALL:
				/* do nothing */
				break;
			case CIL_BLOCKINHERIT:
				break;
			case CIL_OPTIONAL:
				/* do nothing */
				break;
			case CIL_CONDBLOCK:
				cil_symtab_array_destroy(((struct cil_condblock*)current->data)->symtab);
				break;
			default:
				cil_log(CIL_INFO, "destroy symtab error, wrong flavor node: %d\n", current->flavor);
				rc = SEPOL_ERR;
				goto exit;
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
	while (current != NULL && current->flavor != CIL_ROOT);

	return SEPOL_OK;

exit:
	return rc;
}

int cil_get_symtab(struct cil_db *db, struct cil_tree_node *ast_node, symtab_t **symtab, enum cil_sym_index sym_index)
{
	int rc = SEPOL_ERR;

	if (db == NULL || ast_node == NULL) {
		goto exit;
	}

	*symtab = NULL;

	while (ast_node != NULL && *symtab == NULL) {
		if (ast_node->flavor == CIL_BLOCK && sym_index < CIL_SYM_NUM) {
			*symtab = &((struct cil_block*)ast_node->data)->symtab[sym_index];
		} else if (ast_node->flavor == CIL_MACRO  && sym_index < CIL_SYM_NUM) {
			*symtab = &((struct cil_macro*)ast_node->data)->symtab[sym_index];
		} else if (ast_node->flavor == CIL_IN && sym_index < CIL_SYM_NUM) {
			*symtab = &((struct cil_in*)ast_node->data)->symtab[sym_index];
		} else if (ast_node->flavor == CIL_CALL  && sym_index < CIL_SYM_NUM) {
			ast_node = ast_node->parent;
		} else if (ast_node->flavor == CIL_BLOCKINHERIT && sym_index < CIL_SYM_NUM) {
			ast_node = ast_node->parent;
		} else if (ast_node->flavor == CIL_CLASS || ast_node->flavor == CIL_MAP_CLASS) {
			*symtab = &((struct cil_class*)ast_node->data)->perms;
		} else if (ast_node->flavor == CIL_COMMON) {
			*symtab = &((struct cil_common*)ast_node->data)->perms;
		} else if (ast_node->flavor == CIL_CONDBLOCK && sym_index < CIL_SYM_NUM) {
			if (ast_node->parent->flavor == CIL_TUNABLEIF) {
				*symtab = &((struct cil_condblock*)ast_node->data)->symtab[sym_index];
			} else if (ast_node->parent->flavor == CIL_BOOLEANIF) {
				ast_node = ast_node->parent->parent;
			}
		} else if (ast_node->flavor == CIL_OPTIONAL && sym_index < CIL_SYM_NUM) {
			ast_node = ast_node->parent;
		} else if (ast_node->flavor == CIL_ROOT && sym_index < CIL_SYM_NUM) {
			*symtab = &db->symtab[sym_index];
		} else if (sym_index >= CIL_SYM_NUM) {
			cil_log(CIL_INFO, "Invalid symtab index at line %d of %s\n",
				ast_node->line, ast_node->path);
			rc = SEPOL_ERR;
			goto exit;
		} else {
			cil_log(CIL_INFO, "Failed to get symtab from node at line %d of %s\n",
				ast_node->line, ast_node->path);
			rc = SEPOL_ERR;
			goto exit;
		}
	}

	if (ast_node == NULL || *symtab == NULL) {
		cil_log(CIL_INFO, "Failed to get symtab at line %d of %s\n",
			ast_node->line, ast_node->path);
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

	(*sort)->flavor = CIL_NONE;
	(*sort)->count = 0;
	(*sort)->index = 0;
	(*sort)->array = NULL;
}

void cil_sort_destroy(struct cil_sort **sort)
{
	(*sort)->flavor = CIL_NONE;
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
	(*netifcon)->context_str = NULL;
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
	(*range)->low_str = NULL;
	(*range)->low = NULL;
	(*range)->high_str = NULL;
	(*range)->high = NULL;
}

void cil_sens_init(struct cil_sens **sens)
{
	*sens = cil_malloc(sizeof(**sens));

	cil_symtab_datum_init(&(*sens)->datum);
	cil_list_init(&(*sens)->catsets, CIL_LIST_ITEM);
	(*sens)->ordered = CIL_FALSE;
}

void cil_block_init(struct cil_block **block)
{
	*block = cil_malloc(sizeof(**block));

	cil_symtab_datum_init(&(*block)->datum);

	cil_symtab_array_init((*block)->symtab, cil_sym_sizes[CIL_SYM_ARRAY_BLOCK]);

	(*block)->is_abstract = CIL_FALSE;
}

void cil_blockinherit_init(struct cil_blockinherit **inherit)
{
	*inherit = cil_malloc(sizeof(**inherit));
	(*inherit)->block_str = NULL;
}

void cil_blockabstract_init(struct cil_blockabstract **abstract)
{
	*abstract = cil_malloc(sizeof(**abstract));
	(*abstract)->block_str = NULL;
}

void cil_in_init(struct cil_in **in)
{
	*in = cil_malloc(sizeof(**in));

	cil_symtab_array_init((*in)->symtab, cil_sym_sizes[CIL_SYM_ARRAY_IN]);
	(*in)->block_str = NULL;
}

void cil_class_init(struct cil_class **class)
{
	*class = cil_malloc(sizeof(**class));

	cil_symtab_datum_init(&(*class)->datum);

	cil_symtab_init(&(*class)->perms, CIL_CLASS_SYM_SIZE);

	(*class)->common = NULL;
	(*class)->num_perms = 0;
}

void cil_common_init(struct cil_common **common)
{
	*common = cil_malloc(sizeof(**common));

	cil_symtab_datum_init(&(*common)->datum);
	cil_symtab_init(&(*common)->perms, CIL_CLASS_SYM_SIZE);
	(*common)->num_perms = 0;
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

void cil_userprefix_init(struct cil_userprefix **userprefix)
{
	*userprefix = cil_malloc(sizeof(**userprefix));

	(*userprefix)->user_str = NULL;
	(*userprefix)->user = NULL;
	(*userprefix)->prefix_str = NULL;
}

void cil_selinuxuser_init(struct cil_selinuxuser **selinuxuser)
{
	*selinuxuser = cil_malloc(sizeof(**selinuxuser));

	(*selinuxuser)->name_str = NULL;
	(*selinuxuser)->user_str = NULL;
	(*selinuxuser)->user = NULL;
	(*selinuxuser)->range_str = NULL;
	(*selinuxuser)->range = NULL;
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

void cil_roleattribute_init(struct cil_roleattribute **attr)
{
	*attr = cil_malloc(sizeof(**attr));

	cil_symtab_datum_init(&(*attr)->datum);

	(*attr)->expr_list = NULL;
	(*attr)->roles = NULL;
}

void cil_roleattributeset_init(struct cil_roleattributeset **attrset)
{
	*attrset = cil_malloc(sizeof(**attrset));

	(*attrset)->attr_str = NULL;
	(*attrset)->str_expr = NULL;
	(*attrset)->datum_expr = NULL;
}

void cil_typeattribute_init(struct cil_typeattribute **attr)
{
	*attr = cil_malloc(sizeof(**attr));

	cil_symtab_datum_init(&(*attr)->datum);

	(*attr)->expr_list = NULL;
	(*attr)->types = NULL;
}

void cil_typeattributeset_init(struct cil_typeattributeset **attrset)
{
	*attrset = cil_malloc(sizeof(**attrset));

	(*attrset)->attr_str = NULL;
	(*attrset)->str_expr = NULL;
	(*attrset)->datum_expr = NULL;
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
	(*typeperm)->type = NULL;
}

void cil_name_init(struct cil_name **name)
{
	*name = cil_malloc(sizeof(**name));

	cil_symtab_datum_init(&(*name)->datum);
	(*name)->name_str = NULL;
}

void cil_nametypetransition_init(struct cil_nametypetransition **nametypetrans)
{
	*nametypetrans = cil_malloc(sizeof(**nametypetrans));

	(*nametypetrans)->src_str = NULL;
	(*nametypetrans)->src = NULL;
	(*nametypetrans)->tgt_str = NULL;
	(*nametypetrans)->tgt = NULL;
	(*nametypetrans)->obj_str = NULL;
	(*nametypetrans)->obj = NULL;
	(*nametypetrans)->name_str = NULL;
	(*nametypetrans)->name = NULL;
	(*nametypetrans)->result_str = NULL;
	(*nametypetrans)->result = NULL;
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

void cil_tunable_init(struct cil_tunable **ciltun)
{
	*ciltun = cil_malloc(sizeof(**ciltun));

	cil_symtab_datum_init(&(*ciltun)->datum);
	(*ciltun)->value = 0;
}

void cil_condblock_init(struct cil_condblock **cb)
{
	*cb = cil_malloc(sizeof(**cb));

	(*cb)->flavor = CIL_NONE;
	cil_symtab_array_init((*cb)->symtab, cil_sym_sizes[CIL_SYM_ARRAY_CONDBLOCK]);
}

void cil_boolif_init(struct cil_booleanif **bif)
{
	*bif = cil_malloc(sizeof(**bif));

	(*bif)->str_expr = NULL;
	(*bif)->datum_expr = NULL;
}

void cil_tunif_init(struct cil_tunableif **tif)
{
	*tif = cil_malloc(sizeof(**tif));

	(*tif)->str_expr = NULL;
	(*tif)->datum_expr = NULL;
}

void cil_avrule_init(struct cil_avrule **avrule)
{
	*avrule = cil_malloc(sizeof(**avrule));

	(*avrule)->rule_kind = CIL_NONE;
	(*avrule)->src_str = NULL;
	(*avrule)->src = NULL;
	(*avrule)->tgt_str = NULL;
	(*avrule)->tgt = NULL;
	(*avrule)->classperms = NULL;
}

void cil_type_rule_init(struct cil_type_rule **type_rule)
{
	*type_rule = cil_malloc(sizeof(**type_rule));

	(*type_rule)->rule_kind = CIL_NONE;
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
	(*filecon)->type = 0;
	(*filecon)->context_str = NULL;
	(*filecon)->context = NULL;
}

void cil_portcon_init(struct cil_portcon **portcon)
{
	*portcon = cil_malloc(sizeof(**portcon));
	(*portcon)->proto = 0;
	(*portcon)->port_low = 0;
	(*portcon)->port_high = 0;
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

	(*genfscon)->fs_str = NULL;
	(*genfscon)->path_str = NULL;
	(*genfscon)->context_str = NULL;
	(*genfscon)->context = NULL;
}

void cil_pirqcon_init(struct cil_pirqcon **pirqcon)
{
	*pirqcon = cil_malloc(sizeof(**pirqcon));
	
	(*pirqcon)->pirq = 0;
	(*pirqcon)->context_str = NULL;
	(*pirqcon)->context = NULL;
}

void cil_iomemcon_init(struct cil_iomemcon **iomemcon)
{
	*iomemcon = cil_malloc(sizeof(**iomemcon));

	(*iomemcon)->iomem_low = 0;
	(*iomemcon)->iomem_high = 0;
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

	(*pcidevicecon)->dev = 0;
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

	(*constrain)->classperms = NULL;
	(*constrain)->str_expr = NULL;
	(*constrain)->datum_expr = NULL;
}

void cil_validatetrans_init(struct cil_validatetrans **validtrans)
{
	*validtrans = cil_malloc(sizeof(**validtrans));

	(*validtrans)->class_str = NULL;
	(*validtrans)->class = NULL;
	(*validtrans)->str_expr = NULL;
	(*validtrans)->datum_expr = NULL;
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
	(*perm)->value = 0;
}

void cil_classpermset_init(struct cil_classpermset **cps)
{
	*cps = cil_malloc(sizeof(**cps));

	cil_symtab_datum_init(&(*cps)->datum);
	(*cps)->classperms = NULL;
}

void cil_classperms_init(struct cil_classperms **cp)
{
	*cp = cil_malloc(sizeof(**cp));
	memset(*cp, 0, sizeof(struct cil_classperms));
	(*cp)->flavor = CIL_NONE;
}

void cil_map_perm_init(struct cil_map_perm **cmp)
{
	*cmp = cil_malloc(sizeof(**cmp));

	cil_symtab_datum_init(&(*cmp)->datum);
	(*cmp)->classperms = NULL;
	(*cmp)->value = 0;
}

void cil_map_class_init(struct cil_map_class **map)
{
	*map = cil_malloc(sizeof(**map));

	cil_symtab_datum_init(&(*map)->datum);
	cil_symtab_init(&(*map)->perms, CIL_CLASS_SYM_SIZE);
	(*map)->num_perms = 0;
}

void cil_classmapping_init(struct cil_classmapping **mapping)
{
	*mapping = cil_malloc(sizeof(**mapping));

	(*mapping)->map_class_str = NULL;
	(*mapping)->map_perm_str = NULL;
	(*mapping)->classperms = NULL;
}

void cil_user_init(struct cil_user **user)
{
	*user = cil_malloc(sizeof(**user));

	cil_symtab_datum_init(&(*user)->datum);
	(*user)->bounds = NULL;
	(*user)->roles = NULL;
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
	(*role)->bounds = NULL;
	(*role)->types = NULL;
	(*role)->value = 0;
}

void cil_type_init(struct cil_type **type)
{
	*type = cil_malloc(sizeof(**type));

	cil_symtab_datum_init(&(*type)->datum);
	(*type)->bounds = NULL;
	(*type)->value = 0;
}

void cil_cat_init(struct cil_cat **cat)
{
	*cat = cil_malloc(sizeof(**cat));

	cil_symtab_datum_init(&(*cat)->datum);
	(*cat)->ordered = CIL_FALSE;
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
	(*args)->flavor = CIL_NONE;
}

void cil_call_init(struct cil_call **call)
{
	*call = cil_malloc(sizeof(**call));

	(*call)->macro_str = NULL;
	(*call)->macro = NULL;
	(*call)->args_tree = NULL;
	(*call)->args = NULL;
	(*call)->copied = 0;
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
	(*param)->flavor = CIL_NONE;
}

void cil_macro_init(struct cil_macro **macro)
{
	*macro = cil_malloc(sizeof(**macro));

	cil_symtab_datum_init(&(*macro)->datum);
	cil_symtab_array_init((*macro)->symtab, cil_sym_sizes[CIL_SYM_ARRAY_MACRO]);
	(*macro)->params = NULL;
}

void cil_policycap_init(struct cil_policycap **policycap)
{
	*policycap = cil_malloc(sizeof(**policycap));

	cil_symtab_datum_init(&(*policycap)->datum);
}
