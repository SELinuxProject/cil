#include <stdlib.h>
#include <stdio.h>

#include "cil.h"
#include "cil_mem.h"
#include "cil_tree.h"
#include "cil_list.h"
#include "cil_symtab.h"
#include "cil_copy_ast.h"
#include "cil_build_ast.h"

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
		}
		else if (orig_item->flavor == CIL_LIST) {
			struct cil_list *new_sub;
			cil_list_init(&new_sub);
			cil_copy_list((struct cil_list*)orig_item->data, &new_sub);
			new_item->data = new_sub;
		}
	
		new_item->flavor = orig_item->flavor;
		if (orig_item->next != NULL) {
			cil_list_item_init(&new_item->next);
			new_item = new_item->next;
		}	
		orig_item = orig_item->next;
	}

	*copy = new;
}

int cil_copy_block(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_block *new;
	int rc = cil_block_init(&new);
	if (rc != SEPOL_OK) {
		return rc;
	}

	char *key = ((struct cil_symtab_datum *)orig->data)->name;
	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_block: cil_symtab_insert failed, rc: %d\n", rc);
		cil_destroy_block(new);
		return rc;
	}
	rc = cil_symtab_array_init(new->symtab, CIL_SYM_NUM);
	if (rc != SEPOL_OK) {
		printf("cil_copy_block: cil_symtab_array_init failed, rc: %d\n", rc);
		cil_destroy_block(new);
		return rc;
	}

	copy->data = new;

	return SEPOL_OK;
}

int cil_copy_perm(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_perm *new;
	int rc = cil_perm_init(&new);
	if (rc != SEPOL_OK) {
		return rc;
	}
	char *key = ((struct cil_symtab_datum *)orig->data)->name;
	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
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
	struct cil_class *new;
	int rc = cil_class_init(&new);
	if (rc != SEPOL_OK) {
		return rc;
	}

	char *key = ((struct cil_symtab_datum *)orig->data)->name;
	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_class: cil_symtab_insert failed, rc: %d\n", rc);
		cil_destroy_class(new);
		return rc;
	}
	rc = symtab_init(&new->perms, CIL_SYM_SIZE);
	if (rc != SEPOL_OK) {
		printf("cil_copy_class: symtab_init failed, rc: %d\n", rc);
		cil_destroy_class(new);
		return rc;
	}
	new->common = NULL;
	copy->data = new;
		
	return SEPOL_OK;
}

int cil_copy_common(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_common *new;
	int rc = cil_common_init(&new);
	if (rc != SEPOL_OK) {
		return rc;
	}

	char *key = ((struct cil_symtab_datum *)orig->data)->name;
	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_common: cil_symtab_insert failed, rc: %d\n", rc);
		cil_destroy_common(new);
		return rc;
	}
	rc = symtab_init(&new->perms, CIL_SYM_SIZE);
	if (rc != SEPOL_OK) {
		printf("cil_copy_common: symtab_init failed, rc: %d\n", rc);
		cil_destroy_common(new);
		return rc;
	}
	copy->data = new;

	return SEPOL_OK;
}

void cil_copy_classcommon(struct cil_classcommon *orig, struct cil_classcommon **copy)
{
	struct cil_classcommon *new;
	int rc = cil_classcommon_init(&new);
	if (rc != SEPOL_OK) {
		return;
	}

	new->class_str = cil_strdup(orig->class_str);
	new->common_str = cil_strdup(orig->common_str);
	*copy = new;
}

int cil_copy_sid(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_sid *new;
	int rc = cil_sid_init(&new);
	if (rc != SEPOL_OK) {
		return rc;
	}
	char *key = ((struct cil_symtab_datum*)orig->data)->name;
	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_sid: cil_symtab_insert failed, rc: %d\n", rc);
		free(new);
		return rc;
	}
	copy->data = new;

	return SEPOL_OK;
}

int cil_copy_sidcontext(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_sidcontext *new;
	int rc = cil_sidcontext_init(&new);
	if (rc != SEPOL_OK) {
		return rc;
	}

	new->context_str = cil_strdup(((struct cil_sidcontext*)orig->data)->context_str);
	
	if (((struct cil_sidcontext*)orig->data)->context != NULL) {
		rc = cil_context_init(&new->context);

		if (rc != SEPOL_OK) {
			cil_destroy_sidcontext(new);
			return rc;
		}

		cil_copy_fill_context(((struct cil_sidcontext*)orig->data)->context, new->context);
	}

	copy->data = new;
	
	return SEPOL_OK;
}

int cil_copy_user(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_user *new;
	int rc = cil_user_init(&new);
	if (rc != SEPOL_OK) {
		return rc;
	}
	char *key = ((struct cil_symtab_datum *)orig->data)->name;
	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
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
	struct cil_role *new;
	int rc = cil_role_init(&new);
	if (rc != SEPOL_OK) {
		return rc;
	}
	char *key = ((struct cil_symtab_datum *)orig->data)->name;
	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
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
	struct cil_userrole *new;
	int rc = cil_userrole_init(&new);
	if (rc != SEPOL_OK) {
		return;
	}

	new->user_str = cil_strdup(orig->user_str);
	new->role_str = cil_strdup(orig->role_str);
	*copy = new;
}

int cil_copy_type(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_type *new;
	int rc = cil_type_init(&new);
	if (rc != SEPOL_OK) {
		return rc;
	}
	char *key = ((struct cil_symtab_datum *)orig->data)->name;
	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
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
	struct cil_typeattribute *new;
	int rc = cil_typeattribute_init(&new);
	if (rc != SEPOL_OK) {
		return;
	}

	new->type_str = cil_strdup(orig->type_str);
	new->attr_str = cil_strdup(orig->attr_str);
	*copy = new;
}

int cil_copy_typealias(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_typealias *new;
	int rc = cil_typealias_init(&new);
	if (rc != SEPOL_OK) {
		return rc;
	}

	char *key = ((struct cil_symtab_datum*)orig->data)->name;
	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_typealias: cil_symtab_insert failed, rc: %d\n", rc);
		cil_destroy_typealias(new);
		return rc;
	}
	new->type_str = cil_strdup(((struct cil_typealias*)orig->data)->type_str);
	copy->data = new;
	
	return SEPOL_OK;
}

int cil_copy_bool(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_bool *new;
	int rc = cil_bool_init(&new);
	if (rc != SEPOL_OK) {
		return rc;
	}

	char *key = ((struct cil_symtab_datum *)orig->data)->name;
	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_bool: cil_symtab_insert failed, rc: %d\n", rc);
		cil_destroy_bool(new);
		return rc;
	}
	new->value = ((struct cil_bool *)orig->data)->value;
	copy->data = new;

	return SEPOL_OK;
}

void cil_copy_avrule(struct cil_avrule *orig, struct cil_avrule **copy)
{
	struct cil_avrule *new;
	int rc = cil_avrule_init(&new);
	if (rc != SEPOL_OK) {
		return;
	}

	new->rule_kind = orig->rule_kind;
	new->src_str = cil_strdup(orig->src_str);
	new->tgt_str = cil_strdup(orig->tgt_str);
	new->obj_str = cil_strdup(orig->obj_str);
	cil_copy_list(orig->perms_str, &new->perms_str);
	
	*copy = new;
}

void cil_copy_type_rule(struct cil_type_rule *orig, struct cil_type_rule **copy)
{
	struct cil_type_rule *new;
	int rc = cil_type_rule_init(&new);
	if (rc != SEPOL_OK) {
		return;
	}

	new->rule_kind = orig->rule_kind;
	new->src_str = cil_strdup(orig->src_str);
	new->tgt_str = cil_strdup(orig->tgt_str);
	new->obj_str = cil_strdup(orig->obj_str);
	new->result_str = cil_strdup(orig->result_str);

	*copy = new;
}

int cil_copy_sens(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_sens *new;
	int rc = cil_sens_init(&new);
	if (rc != SEPOL_OK) {
		return rc;
	}

	char *key = ((struct cil_symtab_datum*)orig->data)->name;
	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_sens: cil_symtab_insert failed, rc: %d\n", rc);
		cil_destroy_sensitivity(new);
		return rc;
	}
	copy->data = new;

	return SEPOL_OK;
}

int cil_copy_sensalias(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_sensalias *new;
	int rc = cil_sensalias_init(&new);
	if (rc != SEPOL_OK) {
		return rc;
	}

	char *key = ((struct cil_symtab_datum*)orig->data)->name;
	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_sensalias: cil_symtab_insert failed, rc: %d\n", rc);
		cil_destroy_sensalias(new);
		return rc;
	}
	new->sens_str = cil_strdup(((struct cil_sensalias*)orig->data)->sens_str);
	copy->data = new;

	return SEPOL_OK;
}

int cil_copy_cat(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_cat *new;
	int rc = cil_cat_init(&new);
	if (rc != SEPOL_OK) {
		return rc;
	}
	char *key = ((struct cil_symtab_datum*)orig->data)->name;
	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
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
	struct cil_catalias *new;
	int rc = cil_catalias_init(&new);
	if (rc != SEPOL_OK) {
		return rc;
	}

	char *key = ((struct cil_symtab_datum*)orig->data)->name;
	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_catalias: cil_symtab_insert failed, rc: %d\n", rc);
		cil_destroy_catalias(new);
		return rc;
	}
	new->cat_str = cil_strdup(((struct cil_catalias*)orig->data)->cat_str);
	copy->data = new;

	return SEPOL_OK;
}

void cil_copy_senscat(struct cil_senscat *orig, struct cil_senscat **copy)
{
	struct cil_senscat *new;
	int rc = cil_senscat_init(&new);
	if (rc != SEPOL_OK) {
		return;
	}

	new->sens_str = cil_strdup(orig->sens_str);
	cil_copy_list(orig->cat_list_str, &new->cat_list_str);
	*copy = new;
}

void cil_copy_catorder(struct cil_catorder *orig, struct cil_catorder **copy)
{
	struct cil_catorder *new;
	int rc = cil_catorder_init(&new);
	if (rc != SEPOL_OK) {
		return;
	}
	cil_copy_list(orig->cat_list_str, &new->cat_list_str);
	*copy = new;
}

void cil_copy_dominance(struct cil_sens_dominates *orig, struct cil_sens_dominates **copy)
{
	struct cil_sens_dominates *new;
	int rc = cil_sens_dominates_init(&new);
	if (rc != SEPOL_OK) {
		return;
	}
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
	struct cil_level *new;
	int rc = cil_level_init(&new);
	if (rc != SEPOL_OK) {
		return rc;
	}

	if (((struct cil_level*)orig->data)->datum.name != NULL) {
		char *key = ((struct cil_symtab_datum*)orig->data)->name;
		rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
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
	int rc = SEPOL_ERR;	
	new->user_str = cil_strdup(orig->user_str);
	new->role_str = cil_strdup(orig->role_str);
	new->type_str = cil_strdup(orig->type_str);
	new->low_str = cil_strdup(orig->low_str);
	new->high_str = cil_strdup(orig->high_str);

	if (orig->low != NULL) {
		rc = cil_level_init(&new->low);
		if (rc != SEPOL_OK) {
			return;
		}
		
		cil_copy_fill_level(orig->low, new->low);
	}

	if (orig->high != NULL) {
		rc = cil_level_init(&new->high);
		if (rc != SEPOL_OK) {
			return;
		}
	
		cil_copy_fill_level(orig->high, new->high);
	}
}

int cil_copy_context(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_context *new;
	int rc = cil_context_init(&new);
	if (rc != SEPOL_OK) {
		return rc;
	}

	if (((struct cil_context*)orig->data)->datum.name != NULL) {
		char *key = ((struct cil_symtab_datum*)orig->data)->name;
		rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
		if (rc != SEPOL_OK) {
			printf("cil_copy_context: cil_symtab_insert failed, rc: %d\n", rc);
			cil_destroy_context(new);
			return rc;
		}
	}

	cil_copy_fill_context(((struct cil_context*)orig->data), new);

	copy->data = new;

	return SEPOL_OK;
}

int cil_copy_netifcon(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_netifcon *new;
	int rc = cil_netifcon_init(&new);
	if (rc != SEPOL_OK) {
		return rc;
	}

	new->interface_str = cil_strdup(((struct cil_netifcon*)orig->data)->interface_str);
	new->if_context_str = cil_strdup(((struct cil_netifcon*)orig->data)->if_context_str);
	new->packet_context_str = cil_strdup(((struct cil_netifcon*)orig->data)->packet_context_str);

	if (((struct cil_netifcon*)orig->data)->if_context != NULL) {
		rc = cil_context_init(&new->if_context);
		if (rc != SEPOL_OK) {
			cil_destroy_netifcon(new);
			return rc;
		}
		
		cil_copy_fill_context(((struct cil_netifcon*)orig->data)->if_context, new->if_context);
	}
	
	if (((struct cil_netifcon*)orig->data)->packet_context != NULL) {
		rc = cil_context_init(&new->packet_context);
		if (rc != SEPOL_OK) {
			cil_destroy_netifcon(new);
			return rc;
		}

		cil_copy_fill_context(((struct cil_netifcon*)orig->data)->packet_context, new->packet_context);
	}

	copy->data = new;

	return SEPOL_OK;	
}

void cil_copy_constrain(struct cil_db *db, struct cil_constrain *orig, struct cil_constrain **copy)
{
	struct cil_constrain *new;
	int rc = cil_constrain_init(&new);
	if (rc != SEPOL_OK) {
		return;
	}

	cil_copy_list(orig->class_list_str, &new->class_list_str);
	cil_copy_list(orig->perm_list_str, &new->perm_list_str);

	cil_tree_node_init(&new->expr);
	cil_copy_ast(db, orig->expr, new->expr);

	*copy = new;
}

void cil_copy_call(struct cil_db *db, struct cil_call *orig, struct cil_call **copy)
{
	struct cil_call *new = cil_malloc(sizeof(struct cil_call));
	new->macro_str = cil_strdup(orig->macro_str);

	cil_tree_init(&new->args_tree);
	cil_tree_node_init(&new->args_tree->root);
	cil_copy_ast(db, orig->args_tree->root, new->args_tree->root);

	*copy = new;

}

int cil_copy_optional(struct cil_tree_node *orig, struct cil_tree_node *copy, symtab_t *symtab)
{
	struct cil_optional *new;
	int rc = cil_optional_init(&new);
	if (rc != SEPOL_OK) {
		return rc;
	}

	char *key = ((struct cil_symtab_datum *)orig->data)->name;
	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, &new->datum, copy);
	if (rc != SEPOL_OK) {
		printf("cil_copy_optional: cil_symtab_insert failed, rc: %d\n", rc);
		cil_destroy_optional(new);
		return rc;
	}

	copy->data = new;

	return SEPOL_OK;
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
		case CIL_SIDCONTEXT : {
			rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_SIDS, &cil_copy_sidcontext);
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
			cil_copy_constrain(db, (struct cil_constrain*)orig->data, (struct cil_constrain**)&new->data);
			break;
		}
		case CIL_CONSTRAIN_NODE : {
			new->data = cil_strdup(((char*)orig->data));
			break;	
		}
		case CIL_CALL : {
			cil_copy_call(db, (struct cil_call*)orig->data, (struct cil_call**)&new->data);
			break;
		}
		case CIL_PARSE_NODE : {
			new->data = cil_strdup(((char*)orig->data));
			break;
		}
		case CIL_OPTIONAL : {
			rc = __cil_copy_data_helper(db, orig, new, symtab, CIL_SYM_OPTIONALS, &cil_copy_optional);
			if (rc != SEPOL_OK) {
				free(new);
				return rc;
			}
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

	rc = cil_tree_walk(orig, __cil_copy_node_helper, NULL,  __cil_copy_branch_helper, other);
	if (rc != SEPOL_OK) {
		printf("cil_tree_walk failed, rc: %d\n", rc);
		return rc;
	}

	return SEPOL_OK;
}

