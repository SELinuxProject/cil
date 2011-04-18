#include <stdlib.h>
#include <stdio.h>

#include "cil.h"
#include "cil_mem.h"
#include "cil_tree.h"
#include "cil_list.h"
#include "cil_symtab.h"
#include "cil_copy_ast.h"

void cil_copy_list(struct cil_list *orig, struct cil_list **copy)
{
	if (orig == NULL)
		return;
	struct cil_list *new;
	struct cil_list_item *orig_item = orig->head;
	cil_list_init(&new);
	cil_list_item_init(&new->head);
	struct cil_list_item *new_item = new->head;
	while(orig_item != NULL) {
		if (orig_item->flavor == CIL_AST_STR) {
			new_item->data = cil_strdup(orig_item->data);
			new_item->flavor = orig_item->flavor;
			if (orig_item->next != NULL) {
				cil_list_item_init(&new_item->next);
				new_item = new_item->next;
			}	
		}
		else if (orig_item->flavor == CIL_LIST) {
			struct cil_list *new_sub;
			cil_list_init(&new_sub);
			cil_copy_list((struct cil_list*)orig_item->data, &new_sub);
		}
	
		orig_item = orig_item->next;
	}

	*copy = new;
}

int cil_copy_block(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_block *new = cil_malloc(sizeof(struct cil_block));
	char *key = ((struct cil_symtab_datum *)orig->data)->name;
	int rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_block: cil_symtab_insert failed, rc: %d\n", rc);
		free(new);
		return rc;
	}
	rc = cil_symtab_array_init(new->symtab, CIL_SYM_NUM);
	if (rc != SEPOL_OK) {
		printf("cil_copy_block: cil_symtab_array_init failed, rc: %d\n", rc);
		free(new);
		return rc;
	}

	copy->data = new;

	return SEPOL_OK;
}

int cil_copy_perm(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_perm *new = cil_malloc(sizeof(struct cil_perm));
	char *key = ((struct cil_symtab_datum *)orig->data)->name;
	int rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_perm: cil_symtab_insert failed, rc: %d\n", rc);
		free(new);
		return rc;
	}
	copy->data = new;

	return SEPOL_OK;
}

int cil_copy_class(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_class *new = cil_malloc(sizeof(struct cil_class));
	char *key = ((struct cil_symtab_datum *)orig->data)->name;
	int rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_class: cil_symtab_insert failed, rc: %d\n", rc);
		free(new);
		return rc;
	}
	rc = symtab_init(&new->perms, CIL_SYM_SIZE);
	if (rc != SEPOL_OK) {
		printf("cil_copy_class: symtab_init failed, rc: %d\n", rc);
		free(new);
		return rc;
	}
	new->common = NULL;
	copy->data = new;
		
	return SEPOL_OK;
}

int cil_copy_common(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_common *new = cil_malloc(sizeof(struct cil_common));
	char *key = ((struct cil_symtab_datum *)orig->data)->name;
	int rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_common: cil_symtab_insert failed, rc: %d\n", rc);
		free(new);
		return rc;
	}
	rc = symtab_init(&new->perms, CIL_SYM_SIZE);
	if (rc != SEPOL_OK) {
		printf("cil_copy_common: symtab_init failed, rc: %d\n", rc);
		free(new);
		return rc;
	}
	copy->data = new;

	return SEPOL_OK;
}

void cil_copy_classcommon(struct cil_classcommon *orig, struct cil_classcommon **copy)
{
	struct cil_classcommon *new = cil_malloc(sizeof(struct cil_classcommon));
	new->class_str = cil_strdup(orig->class_str);
	new->common_str = cil_strdup(orig->common_str);
	*copy = new;
}

int cil_copy_sid(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_sid *new = cil_malloc(sizeof(struct cil_sid));
	char *key = ((struct cil_symtab_datum *)orig->data)->name;
	int rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_sid: cil_symtab_insert failed, rc: %d\n", rc);
		free(new);
		return rc;
	}
	new->context_str = cil_strdup(((struct cil_sid *)orig->data)->context_str);
	
	if (((struct cil_sid*)orig->data)->context != NULL) {
		new->context = cil_malloc(sizeof(struct cil_context));
		cil_copy_fill_context(((struct cil_sid*)orig->data)->context, new->context);
	}

	copy->data = new;
	
	return SEPOL_OK;
}

int cil_copy_user(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_user *new = cil_malloc(sizeof(struct cil_user));
	char *key = ((struct cil_symtab_datum *)orig->data)->name;
	int rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_user: cil_symtab_insert failed, rc: %d\n", rc);
		free(new);
		return rc;
	}
	copy->data = new;

	return SEPOL_OK;
}

int cil_copy_role(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_role *new = cil_malloc(sizeof(struct cil_role));
	char *key = ((struct cil_symtab_datum *)orig->data)->name;
	int rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_role: cil_symtab_insert failed, rc: %d\n", rc);
		free(new);
		return rc;
	}
	copy->data = new;

	return SEPOL_OK;
}

void cil_copy_userrole(struct cil_userrole *orig, struct cil_userrole **copy)
{
	struct cil_userrole *new = cil_malloc(sizeof(struct cil_userrole));
	new->user_str = cil_strdup(orig->user_str);
	new->role_str = cil_strdup(orig->role_str);
	*copy = new;
}

int cil_copy_type(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_type *new = cil_malloc(sizeof(struct cil_type));
	char *key = ((struct cil_symtab_datum *)orig->data)->name;
	int rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_type: cil_symtab_insert failed, rc: %d\n", rc);
		free(new);
		return rc;
	}
	copy->data = new;

	return SEPOL_OK;
}

void cil_copy_typeattr(struct cil_typeattribute *orig, struct cil_typeattribute **copy)
{
	struct cil_typeattribute *new = cil_malloc(sizeof(struct cil_typeattribute));
	new->type_str = cil_strdup(orig->type_str);
	new->attr_str = cil_strdup(orig->attr_str);
	*copy = new;
}

int cil_copy_typealias(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_typealias *new = cil_malloc(sizeof(struct cil_typealias));
	char *key = ((struct cil_symtab_datum*)orig->data)->name;
	int rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_typealias: cil_symtab_insert failed, rc: %d\n", rc);
		free(new);
		return rc;
	}
	new->type_str = cil_strdup(((struct cil_typealias*)orig->data)->type_str);
	copy->data = new;
	
	return SEPOL_OK;
}

int cil_copy_bool(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_bool *new = cil_malloc(sizeof(struct cil_bool));
	char *key = ((struct cil_symtab_datum *)orig->data)->name;
	int rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_bool: cil_symtab_insert failed, rc: %d\n", rc);
		free(new);
		return rc;
	}
	new->value = ((struct cil_bool *)orig->data)->value;
	copy->data = new;

	return SEPOL_OK;
}

void cil_copy_avrule(struct cil_avrule *orig, struct cil_avrule **copy)
{
	struct cil_avrule *new = cil_malloc(sizeof(struct cil_avrule));
	new->rule_kind = orig->rule_kind;
	new->src_str = cil_strdup(orig->src_str);
	new->tgt_str = cil_strdup(orig->tgt_str);
	new->obj_str = cil_strdup(orig->obj_str);
	cil_copy_list(orig->perms_str, &new->perms_str);
	
	*copy = new;
}

void cil_copy_type_rule(struct cil_type_rule *orig, struct cil_type_rule **copy)
{
	struct cil_type_rule *new = cil_malloc(sizeof(struct cil_type_rule));
	new->rule_kind = orig->rule_kind;
	new->src_str = cil_strdup(orig->src_str);
	new->tgt_str = cil_strdup(orig->tgt_str);
	new->obj_str = cil_strdup(orig->obj_str);
	new->result_str = cil_strdup(orig->result_str);

	*copy = new;
}

int cil_copy_sens(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_sens *new = cil_malloc(sizeof(struct cil_sens));
	char *key = ((struct cil_symtab_datum*)orig->data)->name;
	int rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_sens: cil_symtab_insert failed, rc: %d\n", rc);
		free(new);
		return rc;
	}
	copy->data = new;

	return SEPOL_OK;
}

int cil_copy_sensalias(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_sensalias *new = cil_malloc(sizeof(struct cil_sens));
	char *key = ((struct cil_symtab_datum*)orig->data)->name;
	int rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_sensalias: cil_symtab_insert failed, rc: %d\n", rc);
		free(new);
		return rc;
	}
	new->sens_str = cil_strdup(((struct cil_sensalias*)orig->data)->sens_str);
	copy->data = new;

	return SEPOL_OK;
}

int cil_copy_cat(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_cat *new = cil_malloc(sizeof(struct cil_cat));
	char *key = ((struct cil_symtab_datum*)orig->data)->name;
	int rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_cat: cil_symtab_insert failed, rc: %d\n", rc);
		free(new);
		return rc;
	}
	copy->data = new;

	return SEPOL_OK;
}

int cil_copy_catalias(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_catalias *new = cil_malloc(sizeof(struct cil_cat));
	char *key = ((struct cil_symtab_datum*)orig->data)->name;
	int rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_catalias: cil_symtab_insert failed, rc: %d\n", rc);
		free(new);
		return rc;
	}
	new->cat_str = cil_strdup(((struct cil_catalias*)orig->data)->cat_str);
	copy->data = new;

	return SEPOL_OK;
}

void cil_copy_senscat(struct cil_senscat *orig, struct cil_senscat **copy)
{
	struct cil_senscat *new = cil_malloc(sizeof(struct cil_senscat));
	new->sens_str = cil_strdup(orig->sens_str);
	cil_copy_list(orig->cat_list_str, &new->cat_list_str);
	*copy = new;
}

void cil_copy_catorder(struct cil_catorder *orig, struct cil_catorder **copy)
{
	struct cil_catorder *new = cil_malloc(sizeof(struct cil_catorder));
	cil_copy_list(orig->cat_list_str, &new->cat_list_str);
	*copy = new;
}

void cil_copy_dominance(struct cil_sens_dominates *orig, struct cil_sens_dominates **copy)
{
	struct cil_sens_dominates *new = cil_malloc(sizeof(struct cil_sens_dominates));
	cil_copy_list(orig->sens_list_str, &new->sens_list_str);
	*copy = new;
}

void cil_copy_fill_level(struct cil_level *orig, struct cil_level *new)
{
	new->sens_str = cil_strdup(orig->sens_str);
	cil_copy_list(orig->cat_list_str, &new->cat_list_str);
}

int cil_copy_level(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_level *new = cil_malloc(sizeof(struct cil_level));

	if (((struct cil_level*)orig->data)->datum.name != NULL) {
		char *key = ((struct cil_symtab_datum*)orig->data)->name;
		int rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
		if (rc != SEPOL_OK) {
			printf("cil_copy_level: cil_symtab_insert failed, rc: %d\n", rc);
			free(new);
			return rc;
		}
	}
	cil_copy_fill_level((struct cil_level*)orig->data, new);
	copy->data = new;

	return SEPOL_OK;
}

void cil_copy_fill_context(struct cil_context *orig, struct cil_context *new)
{
	new->user_str = cil_strdup(orig->user_str);
	new->role_str = cil_strdup(orig->role_str);
	new->type_str = cil_strdup(orig->type_str);
	new->low_str = cil_strdup(orig->low_str);
	new->high_str = cil_strdup(orig->high_str);

	if (orig->low != NULL) {
		new->low = cil_malloc(sizeof(struct cil_level));
		cil_copy_fill_level(orig->low, new->low);
	}

	if (orig->high != NULL) {
		new->high = cil_malloc(sizeof(struct cil_level));
		cil_copy_fill_level(orig->high, new->high);
	}
}

int cil_copy_context(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_context *new = cil_malloc(sizeof(struct cil_context));

	if (((struct cil_context*)orig->data)->datum.name != NULL) {
		char *key = ((struct cil_symtab_datum*)orig->data)->name;
		int rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
		if (rc != SEPOL_OK) {
			printf("cil_copy_context: cil_symtab_insert failed, rc: %d\n", rc);
			free(new);
			return rc;
		}
	}

	cil_copy_fill_context(((struct cil_context*)orig->data), new);

	copy->data = new;

	return SEPOL_OK;
}

int cil_copy_netifcon(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_netifcon *new = cil_malloc(sizeof(struct cil_netifcon));
	char *key = ((struct cil_symtab_datum*)orig->data)->name;
	int rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_netifcon: cil_symtab_insert failed, rc: %d\n", rc);
		free(new);
		return rc;
	}

	new->if_context_str = cil_strdup(((struct cil_netifcon*)orig->data)->if_context_str);
	new->packet_context_str = cil_strdup(((struct cil_netifcon*)orig->data)->packet_context_str);

	if (((struct cil_netifcon*)orig->data)->if_context != NULL) {
		new->if_context = cil_malloc(sizeof(struct cil_context));
		cil_copy_fill_context(((struct cil_netifcon*)orig->data)->if_context, new->if_context);
	}
	
	if (((struct cil_netifcon*)orig->data)->packet_context != NULL) {
		new->packet_context = cil_malloc(sizeof(struct cil_context));
		cil_copy_fill_context(((struct cil_netifcon*)orig->data)->packet_context, new->packet_context);
	}

	copy->data = new;

	return SEPOL_OK;	
}

void cil_copy_mlsconstrain(struct cil_db *db, struct cil_mlsconstrain *orig, struct cil_mlsconstrain **copy)
{
	struct cil_mlsconstrain *new = cil_malloc(sizeof(struct cil_mlsconstrain));
	cil_copy_list(orig->class_list_str, &new->class_list_str);
	cil_copy_list(orig->perm_list_str, &new->perm_list_str);

	cil_tree_init(&new->expr);
	cil_tree_node_init(&new->expr->root);
	cil_copy_ast(db, orig->expr->root, new->expr->root);

	*copy = new;
}

int __cil_copy_data_helper(struct cil_db *db, struct cil_tree_node *orig, struct cil_tree_node *new, symtab_t *symtab, uint32_t index, int (*copy_data)(struct cil_tree_node *orig_node, struct cil_tree_node *new_node, symtab_t *sym))
{
	int rc = SEPOL_ERR;

	rc = cil_get_parent_symtab(db, new, &symtab, index);
	if (rc != SEPOL_OK) {
		return rc;
	}
	rc = (*copy_data)(orig, new, symtab);
	if (rc != SEPOL_OK) {
		return rc;
	}
	return SEPOL_OK;
}

int __cil_copy_node_helper(struct cil_tree_node *orig, uint32_t *finished, struct cil_list *other)
{
	printf("__cil_copy_node_helper, node: %d\n", orig->flavor);
	int rc = SEPOL_ERR;
	struct cil_tree_node *parent = NULL;
	struct cil_tree_node *new = NULL;
	struct cil_db *db = NULL;
	
	if (orig == NULL || other == NULL || other->head == NULL || other->head->next == NULL)
		return SEPOL_ERR;

	if (other->head->flavor == CIL_AST_NODE)
		parent = (struct cil_tree_node*)other->head->data;	
	else
		return SEPOL_ERR;
	
	if (other->head->next->flavor == CIL_DB)
		db = (struct cil_db *)other->head->next->data;
	else
		return SEPOL_ERR;

	rc = cil_tree_node_init(&new);
	if (rc != SEPOL_OK) {
		printf("Failed to init tree node, rc: %d\n", rc);
		cil_tree_node_destroy(&new);
		return rc;
	}

	new->parent = parent;
	new->line = orig->line;
	new->flavor = orig->flavor;

	if (parent->cl_head == NULL) {
		parent->cl_head = new;
		parent->cl_tail = new;
	}
	else {
		parent->cl_tail->next = new;
		parent->cl_tail = new;
	}

	symtab_t *symtab = NULL;
	switch (orig->flavor) {
		case CIL_BLOCK : {
			rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_BLOCKS, &cil_copy_block);
			if (rc != SEPOL_OK) {
				free(new);
				return rc;
			}
			break;
		}
		case CIL_PERM : {
			rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_UNKNOWN, &cil_copy_perm);
			if (rc != SEPOL_OK) {
				free(new);
				return rc;
			}
			break;
		}
		case CIL_CLASS : {
			rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_CLASSES, &cil_copy_class);
			if (rc != SEPOL_OK) {
				free(new);
				return rc;
			}
			break;
		}
		case CIL_COMMON : {
			rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_COMMONS, &cil_copy_common);
			if (rc != SEPOL_OK) {
				free(new);
				return rc;
			}
			break;
		}
		case CIL_CLASSCOMMON : {
			cil_copy_classcommon((struct cil_classcommon*)orig->data, (struct cil_classcommon**)&new->data); 
			break;
		}
		case CIL_SID : {
			rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_SIDS, &cil_copy_sid);
			if (rc != SEPOL_OK) {
				free(new);
				return rc;
			}
			break;
		}
		case CIL_USER : {
			rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_USERS, &cil_copy_user);
			if (rc != SEPOL_OK) {
				free(new);
				return rc;
			}
			break;
		}
		case CIL_ROLE : {
			rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_ROLES, &cil_copy_role);
			if (rc != SEPOL_OK) {
				free(new);
				return rc;
			}
			break;
		}
		case CIL_USERROLE : {
			cil_copy_userrole((struct cil_userrole*)orig->data, (struct cil_userrole**)&new->data);
			break;
		}
		case CIL_TYPE : { 
			rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_TYPES, &cil_copy_type);
			if (rc != SEPOL_OK) {
				free(new);
				return rc;
			}
			break;
		}
		case CIL_ATTR : {
			rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_TYPES, &cil_copy_type);
			if (rc != SEPOL_OK) {
				free(new);
				return rc;
			}
			break;
		}
		case CIL_TYPE_ATTR : {
			cil_copy_typeattr((struct cil_typeattribute*)orig->data, (struct cil_typeattribute**)&new->data);
			break;
		}
		case CIL_TYPEALIAS : {
			rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_TYPES, &cil_copy_typealias);
			if (rc != SEPOL_OK) {
				free(new);
				return rc;
			}
			break;
		}
		case CIL_BOOL : {
			rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_BOOLS, &cil_copy_bool);
			if (rc != SEPOL_OK) {
				free(new);
				return rc;
			}
			break;
		}
		case CIL_AVRULE : {
			cil_copy_avrule((struct cil_avrule*)orig->data, (struct cil_avrule**)&new->data);
			break;
		}
		case CIL_TYPE_RULE : {
			cil_copy_type_rule((struct cil_type_rule*)orig->data, (struct cil_type_rule**)&new->data);
			break;
		}
		case CIL_SENS : {
			rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_SENS, &cil_copy_sens);
			if (rc != SEPOL_OK) {
				free(new);
				return rc;
			}
			break;
		}
		case CIL_SENSALIAS : {
			rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_SENS, &cil_copy_sensalias);
			if (rc != SEPOL_OK) {
				free(new);
				return rc;
			}
			break;
		}
		case CIL_CAT : {
			rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_CATS, &cil_copy_cat);
			if (rc != SEPOL_OK) {
				free(new);
				return rc;
			}
			break;
		}
		case CIL_CATALIAS : {
			rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_CATS, &cil_copy_catalias);
			if (rc != SEPOL_OK) {
				free(new);
				return rc;
			}
			break;
		}
		case CIL_SENSCAT : {
			cil_copy_senscat((struct cil_senscat*)orig->data, (struct cil_senscat**)&new->data);
			break;
		}
		case CIL_CATORDER : {
			cil_copy_catorder((struct cil_catorder*)orig->data, (struct cil_catorder**)&new->data);
			break;
		}
		case CIL_DOMINANCE : {
			cil_copy_dominance((struct cil_sens_dominates*)orig->data, (struct cil_sens_dominates**)&new->data);
			break;
		}
		case CIL_LEVEL : {
			rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_LEVELS, &cil_copy_level);
			if (rc != SEPOL_OK) {
				free(new);
				return rc;
			}
			break;
		}
		case CIL_CONTEXT : {
			rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_CONTEXTS, &cil_copy_context);
			if (rc != SEPOL_OK) {
				free(new);
				return rc;
			}
			break;
		}
		case CIL_NETIFCON : {
			rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_NETIFCONS, &cil_copy_netifcon);
			if (rc != SEPOL_OK) {
				free(new);
				return rc;
			}
			break;
		}
		case CIL_MLSCONSTRAIN : {
			cil_copy_mlsconstrain(db, (struct cil_mlsconstrain*)orig->data, (struct cil_mlsconstrain**)&new->data);
			break;
		}
		case CIL_MLSCONSTRAIN_NODE : {
			new->data = cil_strdup(((char*)orig->data));
			break;	
		}	
		default : return SEPOL_OK;
	}

	if (orig->cl_head != NULL) {
		printf("orig->cl_head not null\n");
		other->head->data = new;
	}

	printf("return __cil_copy_node_helper\n");
	return SEPOL_OK;

	

}

int __cil_copy_branch_helper(__attribute__((unused)) struct cil_tree_node *orig, struct cil_list *other)
{
	printf("__cil_copy_branch_helper\n");
	if (other == NULL || other->head == NULL) 
		return SEPOL_ERR;

	if (other->head->flavor != CIL_AST_NODE)
		return SEPOL_ERR;

	if (((struct cil_tree_node *)other->head->data)->flavor != CIL_ROOT) {
		other->head->data = ((struct cil_tree_node*)other->head->data)->parent;
	}

	printf("return __cil_copy_branch_helper\n");
	return SEPOL_OK;
}

// dest is the parent node to copy into
// if the copy is for a call to a macro, dest should be a pointer to the call
int cil_copy_ast(struct cil_db *db, struct cil_tree_node *orig, struct cil_tree_node *dest)
{
	int rc = SEPOL_ERR;
	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);	
	other->head->data = dest;
	other->head->flavor = CIL_AST_NODE;
	cil_list_item_init(&other->head->next);
	other->head->next->data = db;
	other->head->next->flavor = CIL_DB;

	rc = cil_tree_walk(orig, __cil_copy_node_helper, __cil_copy_branch_helper, other);
	if (rc != SEPOL_OK) {
		printf("cil_tree_walk failed, rc: %d\n", rc);
		return rc;
	}

	return SEPOL_OK;
}

