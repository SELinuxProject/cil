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

	struct cil_db *new_db;
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

	*db = new_db;

	return SEPOL_OK;
}

void cil_db_destroy(struct cil_db **db)
{
	cil_tree_destroy(&(*db)->ast);
	cil_symtab_array_destroy((*db)->symtab);
	
	*db = NULL;	

}

void cil_destroy_data(void **data, uint32_t flavor)
{
	switch(flavor) {
		case (CIL_ROOT) : {
			free(*data);
			break;
		}
		case (CIL_PARSE_NODE) : {
			free(*data);
			break;
		}
		case (CIL_AST_STR) : {
			free(*data);
			break;
		}
		case (CIL_LIST) : {
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
		case (CIL_CLASSCOMMON) : {
			cil_destroy_classcommon(*data);
			break;
		}
		case (CIL_SID) : {
			cil_destroy_sid(*data);
			break;
		}
		case (CIL_SIDCONTEXT) : {
			cil_destroy_sidcontext(*data);
			break;
		}
		case (CIL_POLICYCAP) : {
			cil_destroy_policycap(*data);
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
		case (CIL_ROLEDOMINANCE) : {
			cil_destroy_roledominance(*data);
			break;
		}
		case (CIL_BOOL) : {
			cil_destroy_bool(*data);
			break;
		}
		case (CIL_TUNABLE) : {
			cil_destroy_bool(*data);
			break;
		}
		case (CIL_BOOLEANIF) : {
			cil_destroy_boolif(*data);
			break;
		}
		case (CIL_ELSE) : break;
		case (CIL_COND) : {
			cil_destroy_conditional(*data);
			break;
		}
		case (CIL_TUNABLEIF) : {
			cil_destroy_tunif(*data);
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
		case (CIL_TYPEBOUNDS) : {
			cil_destroy_typebounds(*data);
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
		case (CIL_CATORDER) : {
			cil_destroy_catorder(*data);
			break;
		}
		case (CIL_DOMINANCE) : {
			cil_destroy_dominance(*data);
			break;
		}
		case (CIL_SENSCAT) : {
			cil_destroy_senscat(*data);
			break;
		}
		case (CIL_LEVEL) : {
			cil_destroy_level(*data);
			break;
		}
		case (CIL_CONSTRAIN) : {
			cil_destroy_constrain(*data);
			break;
		}
		case (CIL_MLSCONSTRAIN) : {
			cil_destroy_constrain(*data);
			break;
		}
		case (CIL_CONSTRAIN_NODE) : {
			cil_destroy_constrain_node(*data);
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
		case (CIL_CONTEXT) : {
			cil_destroy_context(*data);
			break;
		}
		case (CIL_FILECON) : {
			cil_destroy_filecon(*data);
			break;
		}
		case (CIL_PORTCON) : {
			cil_destroy_portcon(*data);
			break;
		}
		case (CIL_GENFSCON) : {
			cil_destroy_genfscon(*data);
			break;
		}
		case (CIL_NETIFCON) : {
			cil_destroy_netifcon(*data);
			break;
		}
		case (CIL_MACRO) : {
			cil_destroy_macro(*data);
			break;
		}
		case (CIL_CALL) : {
			cil_destroy_call(*data);
			break;
		}
		case (CIL_ARGS) : {
			cil_destroy_args(*data);
			break;
		}
		case (CIL_OPTIONAL) : {
			cil_destroy_optional(*data);
			break;
		}
		case (CIL_INT) : break;
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
				case (CIL_MACRO) : {
					cil_symtab_array_destroy(((struct cil_macro*)current->data)->symtab);
					break;
				}
				case (CIL_CALL) : {
					/* do nothing */
					break;
				}
				case (CIL_OPTIONAL) : {
					/* do nothing */
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

	int rc = SEPOL_ERR;

	if (ast_node->parent != NULL) {
		if (ast_node->parent->flavor == CIL_BLOCK && cil_sym_index < CIL_SYM_NUM) 
			*symtab = &((struct cil_block*)ast_node->parent->data)->symtab[cil_sym_index];
		else if (ast_node->parent->flavor == CIL_MACRO  && cil_sym_index < CIL_SYM_NUM) 
			*symtab = &((struct cil_macro*)ast_node->parent->data)->symtab[cil_sym_index];
		else if (ast_node->parent->flavor == CIL_CALL  && cil_sym_index < CIL_SYM_NUM) {
			rc = cil_get_parent_symtab(db, ast_node->parent, symtab, cil_sym_index);
			if (rc != SEPOL_OK) {
				printf("cil_get_parent_symtab: cil_call failed, rc: %d\n", rc);
				return rc;
			}
		}
		else if (ast_node->parent->flavor == CIL_CLASS) 
			*symtab = &((struct cil_class*)ast_node->parent->data)->perms;
		else if (ast_node->parent->flavor == CIL_COMMON)
			*symtab = &((struct cil_common*)ast_node->parent->data)->perms;
		else if (ast_node->parent->flavor == CIL_TUNABLEIF)
			*symtab = &((struct cil_tunableif*)ast_node->parent->data)->symtab[cil_sym_index];
		else if ((ast_node->parent->flavor == CIL_BOOLEANIF || ast_node->parent->flavor == CIL_ELSE) && cil_sym_index < CIL_SYM_NUM) {
			rc = cil_get_parent_symtab(db, ast_node->parent, symtab, cil_sym_index);
			if (rc != SEPOL_OK) {
				printf("cil_get_parent_symtab: cil_booleanif failed, rc: %d\n", rc);
				return rc;
			}
		}
		else if (ast_node->parent->flavor == CIL_OPTIONAL && cil_sym_index < CIL_SYM_NUM) {
			rc = cil_get_parent_symtab(db, ast_node->parent, symtab, cil_sym_index);
			if (rc != SEPOL_OK) {
				printf("cil_get_parent_symtab: cil_optional failed, rc: %d\n", rc);
				return rc;
			}
		}
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

int cil_netifcon_init(struct cil_netifcon **netifcon)
{
	if (netifcon == NULL) {
		return SEPOL_ERR;
	}

	struct cil_netifcon *new_netifcon = cil_malloc(sizeof(struct cil_netifcon));	

	cil_symtab_datum_init(&new_netifcon->datum);
	new_netifcon->if_context_str = NULL;
	new_netifcon->if_context = NULL;
	new_netifcon->packet_context_str = NULL;
	new_netifcon->packet_context = NULL;

	*netifcon = new_netifcon;

	return SEPOL_OK;	
}

int cil_context_init(struct cil_context **context)
{
	if(context == NULL) {
		return SEPOL_ERR;
	}

	struct cil_context *new_context = cil_malloc(sizeof(struct cil_context));

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
	if (level == NULL) {
		return SEPOL_ERR;
	}

	struct cil_level *new_level = cil_malloc(sizeof(struct cil_level));

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
	if (sens == NULL) {
		return SEPOL_ERR;
	}

	struct cil_sens *new_sens = cil_malloc(sizeof(struct cil_sens));

	cil_symtab_datum_init(&new_sens->datum);
	int rc = symtab_init(&new_sens->cats, CIL_SYM_SIZE);
	if (rc != SEPOL_OK) {
		free(new_sens);
		return rc;
	}

	*sens = new_sens;

	return SEPOL_OK;
}

int cil_block_init(struct cil_block **block)
{
	if (block == NULL) {
		return SEPOL_ERR;
	}

	struct cil_block *new_block = cil_malloc(sizeof(struct cil_block));

	cil_symtab_datum_init(&new_block->datum);
	int rc = cil_symtab_array_init(new_block->symtab, CIL_SYM_NUM);

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
	if (class == NULL) {
		return SEPOL_ERR;
	}

	struct cil_class *new_class = cil_malloc(sizeof(struct cil_class));

	cil_symtab_datum_init(&new_class->datum);
	int rc = symtab_init(&new_class->perms, CIL_SYM_SIZE);
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
	if (common == NULL) {
		return SEPOL_ERR;
	}

	struct cil_common *new_common = cil_malloc(sizeof(struct cil_common));

	cil_symtab_datum_init(&new_common->datum);
	int rc = symtab_init(&new_common->perms, CIL_SYM_SIZE);
	if (rc != SEPOL_OK) {
		free(new_common);
		return rc;
	}


	*common = new_common;

	return SEPOL_OK;
}

int cil_classcommon_init(struct cil_classcommon **classcommon)
{
	if (classcommon == NULL) {
		return SEPOL_ERR;
	}


	struct cil_classcommon *new_classcommon = cil_malloc(sizeof(struct cil_classcommon));

	new_classcommon->class_str = NULL;
	new_classcommon->class = NULL;
	new_classcommon->common_str = NULL;
	new_classcommon->common = NULL;

	*classcommon = new_classcommon;

	return SEPOL_OK;
}

int cil_sid_init(struct cil_sid **sid)
{
	if (sid == NULL) {
		return SEPOL_ERR;
	}


	struct cil_sid *new_sid = cil_malloc(sizeof(struct cil_sid));

	cil_symtab_datum_init(&new_sid->datum);

	*sid = new_sid;

	return SEPOL_OK;
}

int cil_sidcontext_init(struct cil_sidcontext **sidcontext)
{
	if (sidcontext == NULL) {
		return SEPOL_ERR;
	}

	struct cil_sidcontext *new_sidcontext = cil_malloc(sizeof(struct cil_sidcontext));

	new_sidcontext->sid_str = NULL;
	new_sidcontext->sid = NULL;
	new_sidcontext->context_str = NULL;
	new_sidcontext->context = NULL;

	*sidcontext = new_sidcontext;

	return SEPOL_OK;
}

int cil_userrole_init(struct cil_userrole **userrole)
{
	if (userrole == NULL) {
		return SEPOL_ERR;
	}

	struct cil_userrole *new_userrole = cil_malloc(sizeof(struct cil_userrole));

	new_userrole->user_str = NULL;
	new_userrole->user = NULL;
	new_userrole->role_str = NULL;
	new_userrole->role = NULL;

	*userrole = new_userrole;

	return SEPOL_OK;
}

int cil_roledominance_init(struct cil_roledominance **roledominance)
{
	if (roledominance == NULL) {
		return SEPOL_ERR;
	}

	struct cil_roledominance *new_roledominance = cil_malloc(sizeof(struct cil_roledominance));

	new_roledominance->role_str = NULL;
	new_roledominance->role = NULL;
	new_roledominance->domed_str = NULL;
	new_roledominance->domed = NULL;

	*roledominance = new_roledominance;

	return SEPOL_OK;
}

int cil_roletype_init(struct cil_roletype **roletype)
{
	if (roletype == NULL) {
		return SEPOL_ERR;
	}

	struct cil_roletype *new_roletype = cil_malloc(sizeof(struct cil_roletype));

	new_roletype->role_str = NULL;
	new_roletype->role = NULL;
	new_roletype->type_str = NULL;
	new_roletype->type = NULL;
	
	*roletype = new_roletype;

	return SEPOL_OK;
}

int cil_typeattribute_init(struct cil_typeattribute **typeattribute)
{
	if (typeattribute == NULL) {
		return SEPOL_ERR;
	}

	struct cil_typeattribute *new_typeattribute = cil_malloc(sizeof(struct cil_typeattribute));

	new_typeattribute->type_str = NULL;
	new_typeattribute->type = NULL;
	new_typeattribute->attr_str = NULL;
	new_typeattribute->attr = NULL;

	*typeattribute = new_typeattribute;

	return SEPOL_OK;
}

int cil_typealias_init(struct cil_typealias **typealias)
{
	if (typealias == NULL) {
		return SEPOL_ERR;
	}

	struct cil_typealias *new_typealias = cil_malloc(sizeof(struct cil_typealias));

	cil_symtab_datum_init(&new_typealias->datum);
	new_typealias->type_str = NULL;
	new_typealias->type = NULL;

	*typealias = new_typealias;

	return SEPOL_OK;
}

int cil_typebounds_init(struct cil_typebounds **typebnds)
{
	if (typebnds == NULL) {
		return SEPOL_ERR;
	}

	struct cil_typebounds *new_typebnds = cil_malloc(sizeof(struct cil_typebounds));

	cil_symtab_datum_init(&new_typebnds->datum);
	new_typebnds->parent_str = NULL;
	new_typebnds->child_str = NULL;

	*typebnds = new_typebnds;

	return SEPOL_OK;
}

int cil_bool_init(struct cil_bool **cilbool)
{
	if (cilbool == NULL) {
		return SEPOL_ERR;
	}

	struct cil_bool *new_cilbool = cil_malloc(sizeof(struct cil_bool));

	cil_symtab_datum_init(&new_cilbool->datum);
	new_cilbool->value = 0;

	*cilbool = new_cilbool;
	
	return SEPOL_OK;
}

int cil_boolif_init(struct cil_booleanif **bif)
{
	if (bif == NULL)
		return SEPOL_ERR;

	struct cil_booleanif *new_bif = cil_malloc(sizeof(struct cil_booleanif));

	new_bif->expr_stack = NULL;

	*bif = new_bif;

	return SEPOL_OK;
}

int cil_conditional_init(struct cil_conditional **cond)
{
	if (cond == NULL)
		return SEPOL_ERR;

	struct cil_conditional *new_cond = cil_malloc(sizeof(struct cil_conditional));

	new_cond->str = NULL;
	new_cond->boolean = NULL;
	new_cond->flavor = CIL_AST_NODE;

	*cond = new_cond;

	return SEPOL_OK;
}

int cil_tunif_init(struct cil_tunableif **tif)
{
	if (tif == NULL)
		return SEPOL_ERR;

	int rc = SEPOL_ERR;
	struct cil_tunableif *new_tif = cil_malloc(sizeof(struct cil_tunableif));

	new_tif->expr_stack = NULL;
	rc = cil_symtab_array_init(new_tif->symtab, CIL_SYM_NUM);
	if (rc != SEPOL_OK)
		return SEPOL_ERR;

	*tif = new_tif;

	return SEPOL_OK;
}

int cil_avrule_init(struct cil_avrule **avrule)
{
	if (avrule == NULL) {
		return SEPOL_ERR;
	}

	struct cil_avrule *new_avrule = cil_malloc(sizeof(struct cil_avrule));

	new_avrule->rule_kind = 0;
	new_avrule->src_str = NULL;
	new_avrule->src = NULL;
	new_avrule->tgt_str = NULL;
	new_avrule->tgt = NULL;
	new_avrule->obj_str = NULL;
	new_avrule->obj = NULL;
	new_avrule->perms_str = NULL;
	new_avrule->perms_list = NULL;

	*avrule = new_avrule;

	return SEPOL_OK;
}

int cil_type_rule_init(struct cil_type_rule **type_rule)
{
	if (type_rule == NULL) {
		return SEPOL_ERR;
	}

	struct cil_type_rule *new_type_rule = cil_malloc(sizeof(struct cil_type_rule));

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
	if (role_trans == NULL) {
		return SEPOL_ERR;
	}

	struct cil_role_trans *new_role_trans = cil_malloc(sizeof(struct cil_role_trans));

	new_role_trans->src_str = NULL;
	new_role_trans->src = NULL;
	new_role_trans->tgt_str = NULL;
	new_role_trans->tgt = NULL;
	new_role_trans->result_str = NULL;
	new_role_trans->result = NULL;

	*role_trans = new_role_trans;

	return SEPOL_OK;
}

int cil_role_allow_init(struct cil_role_allow **role_allow)
{
	if (role_allow == NULL) {
		return SEPOL_ERR;
	}

	struct cil_role_allow *new_role_allow = cil_malloc(sizeof(struct cil_role_allow));

	new_role_allow->src_str = NULL;
	new_role_allow->src = NULL;
	new_role_allow->tgt_str = NULL;
	new_role_allow->tgt = NULL;

	*role_allow = new_role_allow;

	return SEPOL_OK;
}

int cil_sensalias_init(struct cil_sensalias **sensalias)
{
	if (sensalias == NULL) {
		return SEPOL_ERR;
	}

	struct cil_sensalias *new_sensalias = cil_malloc(sizeof(struct cil_sensalias));

	cil_symtab_datum_init(&new_sensalias->datum);
	new_sensalias->sens_str = NULL;
	new_sensalias->sens = NULL;

	*sensalias = new_sensalias;

	return SEPOL_OK;
}

int cil_catalias_init(struct cil_catalias **catalias)
{
	if (catalias == NULL) {
		return SEPOL_ERR;
	}

	struct cil_catalias *new_catalias = cil_malloc(sizeof(struct cil_catalias));

	cil_symtab_datum_init(&new_catalias->datum);
	new_catalias->cat_str = NULL;
	new_catalias->cat = NULL;

	*catalias = new_catalias;

	return SEPOL_OK;
}

int cil_catset_init(struct cil_catset **catset)
{
	if (catset == NULL) {
		return SEPOL_ERR;
	}

	struct cil_catset *new_catset = cil_malloc(sizeof(struct cil_catset));

	cil_symtab_datum_init(&new_catset->datum);
	new_catset->cat_list_str = NULL;
	new_catset->cat_list = NULL;

	*catset = new_catset;

	return SEPOL_OK;
}

int cil_senscat_init(struct cil_senscat **senscat)
{
	if (senscat == NULL) {
		return SEPOL_ERR;
	}

	struct cil_senscat *new_senscat = cil_malloc(sizeof(struct cil_senscat));

	new_senscat->sens_str = NULL;
	new_senscat->cat_list_str = NULL;

	*senscat = new_senscat;

	return SEPOL_OK;
}


int cil_filecon_init(struct cil_filecon **filecon)
{
	if (filecon == NULL) {
		return SEPOL_ERR;
	}

	struct cil_filecon *new_filecon = cil_malloc(sizeof(struct cil_filecon));

	cil_symtab_datum_init(&new_filecon->datum);
	new_filecon->root_str = NULL;
	new_filecon->path_str = NULL;
	new_filecon->context_str =NULL;
	new_filecon->context = NULL;

	*filecon = new_filecon;

	return SEPOL_OK;
}

int cil_portcon_init(struct cil_portcon **portcon)
{
	if (portcon == NULL) {
		return SEPOL_ERR;
	}

	struct cil_portcon *new_portcon = cil_malloc(sizeof(struct cil_portcon));

	new_portcon->type_str = NULL;
	new_portcon->context_str = NULL;
	new_portcon->context = NULL;

	*portcon = new_portcon;

	return SEPOL_OK;
}

int cil_nodecon_init(struct cil_nodecon **nodecon)
{
	if (nodecon == NULL) {
		return SEPOL_ERR;
	}

	struct cil_nodecon *new_nodecon = cil_malloc(sizeof(struct cil_nodecon));

	cil_symtab_datum_init(&new_nodecon->datum);
	new_nodecon->node_str = NULL;
	new_nodecon->netmask_str = NULL;
	new_nodecon->context_str = NULL;
	new_nodecon->context = NULL;

	*nodecon = new_nodecon;

	return SEPOL_OK;
}

int cil_genfscon_init(struct cil_genfscon **genfscon)
{
	if (genfscon == NULL) {
		return SEPOL_ERR;
	}

	struct cil_genfscon *new_genfscon = cil_malloc(sizeof(struct cil_genfscon));

	new_genfscon->type_str = NULL;
	new_genfscon->context_str = NULL;
	new_genfscon->context = NULL;

	*genfscon = new_genfscon;

	return SEPOL_OK;
}

int cil_fscon_init(struct cil_fscon **fscon)
{
	if (fscon == NULL) {
		return SEPOL_ERR;
	}

	struct cil_fscon *new_fscon = cil_malloc(sizeof(struct cil_fscon));

	new_fscon->fs_str = NULL;
	new_fscon->fs = NULL;
	new_fscon->path = NULL;
	new_fscon->context = NULL;

	*fscon = new_fscon;

	return SEPOL_OK;
}

int cil_fs_use_init(struct cil_fs_use **fs_use)
{
	if (fs_use == NULL) {
		return SEPOL_ERR;
	}

	struct cil_fs_use *new_fs_use = cil_malloc(sizeof(struct cil_fs_use));

	new_fs_use->flavor = 0;
	new_fs_use->fs_str = NULL;
	new_fs_use->fs = NULL;
	new_fs_use->context = NULL;

	*fs_use = new_fs_use;

	return SEPOL_OK;
}

int cil_constrain_init(struct cil_constrain **constrain)
{
	if (constrain == NULL) {
		return SEPOL_ERR;
	}

	struct cil_constrain *new_constrain = cil_malloc(sizeof(struct cil_constrain));

	new_constrain->class_list_str = NULL;
	new_constrain->class_list = NULL;
	new_constrain->perm_list_str = NULL;
	new_constrain->perm_list = NULL;
	new_constrain->expr = NULL;

	*constrain = new_constrain;

	return SEPOL_OK;
}

int cil_perm_init(struct cil_perm **perm)
{
	if (perm == NULL) {
		return SEPOL_ERR;
	}

	struct cil_perm *new_perm = cil_malloc(sizeof(struct cil_perm));

	cil_symtab_datum_init(&new_perm->datum);

	*perm = new_perm;

	return SEPOL_OK;
}

int cil_user_init(struct cil_user **user)
{
	if (user == NULL) {
		return SEPOL_ERR;
	}

	struct cil_user *new_user = cil_malloc(sizeof(struct cil_user));

	cil_symtab_datum_init(&new_user->datum);

	*user = new_user;

	return SEPOL_OK;
}

int cil_role_init(struct cil_role **role)
{
	if (role == NULL) {
		return SEPOL_ERR;
	}

	struct cil_role *new_role = cil_malloc(sizeof(struct cil_role));

	cil_symtab_datum_init(&new_role->datum);

	*role = new_role;

	return SEPOL_OK;
}

int cil_type_init(struct cil_type **type)
{
	if (type == NULL) {
		return SEPOL_ERR;
	}

	struct cil_type *new_type = cil_malloc(sizeof(struct cil_type));

	cil_symtab_datum_init(&new_type->datum);

	*type = new_type;

	return SEPOL_OK;
}

int cil_cat_init(struct cil_cat **cat)
{
	if (cat == NULL) {
		return SEPOL_ERR;
	}

	struct cil_cat *new_cat = cil_malloc(sizeof(struct cil_cat));

	cil_symtab_datum_init(&new_cat->datum);

	*cat = new_cat;

	return SEPOL_OK;
}

int cil_catorder_init(struct cil_catorder **catorder)
{
	if (catorder == NULL) {
		return SEPOL_ERR;
	}

	struct cil_catorder *new_catorder = cil_malloc(sizeof(struct cil_catorder));

	new_catorder->cat_list_str = NULL;

	*catorder = new_catorder;

	return SEPOL_OK;
}

int cil_sens_dominates_init(struct cil_sens_dominates **sens_dominates)
{
	if (sens_dominates == NULL) {
		return SEPOL_ERR;
	}

	struct cil_sens_dominates *new_sens_dominates = cil_malloc(sizeof(struct cil_sens_dominates));

	new_sens_dominates->sens_list_str = NULL;

	*sens_dominates = new_sens_dominates;

	return SEPOL_OK;
}

int cil_call_init(struct cil_call **call)
{
	if (call == NULL) {
		return SEPOL_ERR;
	}

	struct cil_call *new_call = cil_malloc(sizeof(struct cil_call));

	new_call->macro_str = NULL;
	new_call->macro = NULL;
	new_call->args_tree = NULL;
	new_call->args = NULL;

	*call = new_call;

	return SEPOL_OK;
}

int cil_optional_init(struct cil_optional **optional)
{
	if (optional == NULL) {
		return SEPOL_ERR;
	}

	struct cil_optional *new_optional = cil_malloc(sizeof(struct cil_optional));
	cil_symtab_datum_init(&new_optional->datum);

	*optional = new_optional;

	return SEPOL_OK;
}

int cil_macro_init(struct cil_macro **macro)
{
	if (macro == NULL) {
		return SEPOL_ERR;
	}

	struct cil_macro *new_macro = cil_malloc(sizeof(struct cil_macro));

	cil_symtab_datum_init(&new_macro->datum);
	int rc = cil_symtab_array_init(new_macro->symtab, CIL_SYM_NUM);
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
	if (policycap == NULL) {
		return SEPOL_ERR;
	}

	struct cil_policycap *new_policycap = cil_malloc(sizeof(struct cil_policycap));

	cil_symtab_datum_init(&new_policycap->datum);

	*policycap = new_policycap;

	return SEPOL_OK;
}
