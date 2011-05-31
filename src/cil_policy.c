#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sepol/errcodes.h>
#include "cil_tree.h"
#include "cil_list.h"
#include "cil.h"
#include "cil_mem.h"
#include "cil_policy.h"

#define SEPOL_DONE			555

#define CLASS_DECL			0
#define ISIDS				1
#define COMMONS				2
#define CLASSES				3
#define INTERFACES			4
#define SENS				5
#define CATS				6
#define LEVELS				7
#define CONSTRAINS			8
#define ATTRTYPES			9
#define ALIASES				10
#define ALLOWS				11
#define CONDS				12
#define USERROLES			13
//fs_use, genfscon, portcon
#define SIDS				14
#define NETIFCONS			15 

#define BUFFER				1024
#define NUM_POLICY_FILES		16

int cil_expr_stack_to_policy(FILE **file_arr, uint32_t file_index, struct cil_tree_node *stack);

int cil_combine_policy(FILE **file_arr, FILE *policy_file)
{
	char temp[BUFFER];
	int i, rc, rc_read, rc_write;

	for(i=0; i<NUM_POLICY_FILES; i++) {
		fseek(file_arr[i], 0, SEEK_SET);
		while (!feof(file_arr[i])) {
			rc_read = fread(temp, 1, BUFFER, file_arr[i]);
			if (rc_read == 0 && ferror(file_arr[i])) {
				printf("Error reading temp policy file\n");
				return SEPOL_ERR;
			}
			rc_write = 0;
			while (rc_read > rc_write) {
				rc = fwrite(temp+rc_write, 1, rc_read-rc_write, policy_file);
				rc_write += rc;
				if (rc == 0 && ferror(file_arr[i])) {
					printf("Error writing to policy.conf\n");
					return SEPOL_ERR;
				}
			}
		}
	}

	return SEPOL_OK;
}

static int __cil_multimap_insert_key(struct cil_list_item **curr_key, struct cil_symtab_datum *key, struct cil_symtab_datum *value, uint32_t key_flavor, uint32_t val_flavor)
{
	struct cil_list_item *new_key = NULL;
	cil_list_item_init(&new_key);
	struct cil_multimap_item *new_data = cil_malloc(sizeof(struct cil_multimap_item));
	new_data->key = key;
	cil_list_init(&new_data->values);
	if (value != NULL) {
		cil_list_item_init(&new_data->values->head);
		new_data->values->head->data = value;
		new_data->values->head->flavor = val_flavor;
	}
	new_key->flavor = key_flavor;
	new_key->data = new_data;
	if (*curr_key == NULL)
		*curr_key = new_key;
	else
		(*curr_key)->next = new_key;

	return SEPOL_OK;
}

int cil_multimap_insert(struct cil_list *list, struct cil_symtab_datum *key, struct cil_symtab_datum *value, uint32_t key_flavor, uint32_t val_flavor)
{
	if (list == NULL || key == NULL) 
		return SEPOL_ERR;

	struct cil_list_item *curr_key = list->head;
	struct cil_list_item *curr_value = NULL;

	if (curr_key == NULL) 
		__cil_multimap_insert_key(&list->head, key, value, key_flavor, val_flavor);
	while(curr_key != NULL) {
		if ((struct cil_multimap_item*)curr_key->data != NULL) {
			if (((struct cil_multimap_item*)curr_key->data)->key != NULL && ((struct cil_multimap_item*)curr_key->data)->key == key) {
				curr_value = ((struct cil_multimap_item*)curr_key->data)->values->head;

				struct cil_list_item *new_value = NULL;
				cil_list_item_init(&new_value);
				new_value->data = value;
				new_value->flavor = val_flavor;

				if (curr_value == NULL) {
					((struct cil_multimap_item*)curr_key->data)->values->head = new_value;
					return SEPOL_OK;
				}
				while (curr_value != NULL) {
					if (curr_value == (struct cil_list_item*)value) {
						free(new_value);
						break;
					}
					if (curr_value->next == NULL) {
						curr_value->next = new_value;
						return SEPOL_OK;
					}
					curr_value = curr_value->next;
				}
			}	
			else if (curr_key->next == NULL) {
				__cil_multimap_insert_key(&curr_key, key, value, key_flavor, val_flavor);
				return SEPOL_OK;
			}
		}
		else {
			printf("No data in list item\n");
			return SEPOL_ERR;
		}
		curr_key = curr_key->next;
	}
	return SEPOL_OK;
}

int cil_userrole_to_policy(FILE **file_arr, struct cil_list *userroles)
{
	if (userroles == NULL) 
		return SEPOL_OK;
	
	struct cil_list_item *current_user = userroles->head;
	while (current_user != NULL) {
		if (((struct cil_multimap_item*)current_user->data)->values->head == NULL) {
			printf("No roles associated with user %s (line %d)\n",  ((struct cil_multimap_item*)current_user->data)->key->name,  ((struct cil_multimap_item*)current_user->data)->key->node->line);
			return SEPOL_ERR;
		}
		fprintf(file_arr[USERROLES], "user %s roles {", ((struct cil_multimap_item*)current_user->data)->key->name);
		struct cil_list_item *current_role = ((struct cil_multimap_item*)current_user->data)->values->head;
		while (current_role != NULL) {
			fprintf(file_arr[USERROLES], " %s",  ((struct cil_role*)current_role->data)->datum.name);
			current_role = current_role->next;
		}
		fprintf(file_arr[USERROLES], " };\n"); 
		current_user = current_user->next;
	}
	return SEPOL_OK;
}

int cil_cat_to_policy(FILE **file_arr, struct cil_list *cats)
{
	if (cats == NULL) 
		return SEPOL_OK;
	
	struct cil_list_item *curr_cat = cats->head;
	while (curr_cat != NULL) {
		if (((struct cil_multimap_item*)curr_cat->data)->values->head == NULL) 
			fprintf(file_arr[CATS], "category %s;\n", ((struct cil_multimap_item*)curr_cat->data)->key->name);
		else {
			fprintf(file_arr[CATS], "category %s alias", ((struct cil_multimap_item*)curr_cat->data)->key->name);
			struct cil_list_item *curr_catalias = ((struct cil_multimap_item*)curr_cat->data)->values->head;
			while (curr_catalias != NULL) {
				fprintf(file_arr[CATS], " %s",  ((struct cil_cat*)curr_catalias->data)->datum.name);
				curr_catalias = curr_catalias->next;
			}
			fprintf(file_arr[CATS], ";\n"); 
		}
		curr_cat = curr_cat->next;
	}
	return SEPOL_OK;
}

int cil_sens_to_policy(FILE **file_arr, struct cil_list *sens)
{
	if (sens == NULL) 
		return SEPOL_OK;
	
	struct cil_list_item *curr_sens = sens->head;
	while (curr_sens != NULL) {
		if (((struct cil_multimap_item*)curr_sens->data)->values->head == NULL) 
			fprintf(file_arr[SENS], "sensitivity %s;\n", ((struct cil_multimap_item*)curr_sens->data)->key->name);
		else {
			fprintf(file_arr[SENS], "sensitivity %s alias", ((struct cil_multimap_item*)curr_sens->data)->key->name);
			struct cil_list_item *curr_sensalias = ((struct cil_multimap_item*)curr_sens->data)->values->head;
			while (curr_sensalias != NULL) {
				fprintf(file_arr[SENS], " %s",  ((struct cil_sens*)curr_sensalias->data)->datum.name);
				curr_sensalias = curr_sensalias->next;
			}
			fprintf(file_arr[SENS], ";\n"); 
		}
		curr_sens = curr_sens->next;
	}

	return SEPOL_OK;
}

int cil_print_constrain_expr(FILE **file_arr, struct cil_tree_node *root)
{
	struct cil_tree_node *curr = root;
	int rc = SEPOL_ERR;

	if (curr->flavor == CIL_ROOT)
		curr = curr->cl_head;

	while (curr != NULL) {
		if (curr->cl_head != NULL) {
			fprintf(file_arr[CONSTRAINS], "( ");
			rc = cil_print_constrain_expr(file_arr, curr->cl_head);
			if (rc != SEPOL_OK) {
				printf("Failed to print constrain expression\n");
				return rc;
			}
		}
		else {
			if (curr->flavor == CIL_CONSTRAIN_NODE)
				fprintf(file_arr[CONSTRAINS], "%s", (char*)curr->data);
			else
				fprintf(file_arr[CONSTRAINS], "%s", ((struct cil_type*)curr->data)->datum.name);
		}
		if (curr->next != NULL) 
			fprintf(file_arr[CONSTRAINS], " %s ", (char*)curr->parent->data);
		else if (curr->parent->flavor != CIL_ROOT) 
			fprintf(file_arr[CONSTRAINS], " )");

		curr = curr->next;
	}

	return SEPOL_OK;
}

void cil_level_to_policy(FILE **file_arr, uint32_t file_index, struct cil_level *level)
{
	struct cil_list_item *cat;
	struct cil_list_item *curr;
	struct cil_list_item *start_range;
	struct cil_list_item *end_range;
	char *sens_str = level->sens->datum.name;

	if (level->catset != NULL)
		cat = ((struct cil_catset*)level->catset)->cat_list->head;
	else
		cat = level->cat_list->head;

	fprintf(file_arr[file_index], "%s:", sens_str);
	while (cat != NULL) {
		if (cat->flavor == CIL_LIST) {
			curr = ((struct cil_list*)cat->data)->head;
			start_range = curr;
			while (curr != NULL) {
				if (curr->next == NULL) {
					end_range = curr;
					break;
				}
				curr = curr->next;
			}
			fprintf(file_arr[file_index], "%s.%s", ((struct cil_cat*)start_range->data)->datum.name, ((struct cil_cat*)end_range->data)->datum.name);
		}
		else
			fprintf(file_arr[file_index], "%s", ((struct cil_cat*)cat->data)->datum.name);
		if (cat->next != NULL)
			fprintf(file_arr[file_index], ",");
		cat = cat->next;
	}
}

void cil_context_to_policy(FILE **file_arr, uint32_t file_index, struct cil_context *context)
{
	struct cil_user *user = context->user;
	struct cil_role *role = context->role;
	struct cil_type *type = context->type;
	struct cil_level *low = context->low;
	struct cil_level *high = context->high;

	fprintf(file_arr[file_index], "%s:%s:%s:", user->datum.name, role->datum.name, type->datum.name);
	cil_level_to_policy(file_arr, file_index, low);
	fprintf(file_arr[file_index], " - ");
	cil_level_to_policy(file_arr, file_index, high);
}

void cil_constrain_to_policy(FILE **file_arr, uint32_t file_index, struct cil_constrain *cons)
{
	struct cil_list_item *class_curr = cons->class_list->head;
	struct cil_list_item *perm_curr = cons->perm_list->head;
	if (class_curr->next == NULL)
		fprintf(file_arr[CONSTRAINS], "%s ", ((struct cil_class*)class_curr->data)->datum.name);
	else {
		fprintf(file_arr[CONSTRAINS], "{ ");
		while (class_curr != NULL) {
			fprintf(file_arr[CONSTRAINS], "%s ", ((struct cil_class*)class_curr->data)->datum.name);
			class_curr = class_curr->next;
		}
		fprintf(file_arr[CONSTRAINS], "}\n\t\t");
	}
	fprintf(file_arr[CONSTRAINS], "{ ");
	while (perm_curr != NULL) {
		fprintf(file_arr[CONSTRAINS], "%s ", ((struct cil_perm*)perm_curr->data)->datum.name);
		perm_curr = perm_curr->next;
	}
	fprintf(file_arr[CONSTRAINS], "}\n\t");
	cil_expr_stack_to_policy(file_arr, CONSTRAINS, cons->expr);
	fprintf(file_arr[CONSTRAINS], ";\n");
}

int cil_avrule_to_policy(FILE **file_arr, uint32_t file_index, struct cil_avrule *rule)
{
	char *src_str = ((struct cil_symtab_datum*)(struct cil_type*)rule->src)->name;
	char *tgt_str = ((struct cil_symtab_datum*)(struct cil_type*)rule->tgt)->name;
	char *obj_str = ((struct cil_symtab_datum*)(struct cil_type*)rule->obj)->name;
	struct cil_list_item *perm_item = rule->perms_list->head;
	switch (rule->rule_kind) {
		case CIL_AVRULE_ALLOWED:
			fprintf(file_arr[file_index], "allow %s %s:%s { ", src_str, tgt_str, obj_str);
			break;
		case CIL_AVRULE_AUDITALLOW:
			fprintf(file_arr[file_index], "auditallow %s %s:%s { ", src_str, tgt_str, obj_str);
			break;
		case CIL_AVRULE_DONTAUDIT:
			fprintf(file_arr[file_index], "dontaudit %s %s:%s { ", src_str, tgt_str, obj_str);
			break;
		case CIL_AVRULE_NEVERALLOW:
			fprintf(file_arr[file_index], "neverallow %s %s:%s { ", src_str, tgt_str, obj_str);
			break;
		default : {
			printf("Unknown avrule kind: %d\n", rule->rule_kind);
			return SEPOL_ERR;
		}
	}
	while (perm_item != NULL) {
		fprintf(file_arr[file_index], "%s ", ((struct cil_perm*)(perm_item->data))->datum.name);
		perm_item = perm_item->next;
	}
	fprintf(file_arr[file_index], "};\n");

	return SEPOL_OK;
}

int cil_typerule_to_policy(FILE **file_arr, uint32_t file_index, struct cil_type_rule *rule)
{
	char *src_str = ((struct cil_symtab_datum*)(struct cil_type*)rule->src)->name;
	char *tgt_str = ((struct cil_symtab_datum*)(struct cil_type*)rule->tgt)->name;
	char *obj_str = ((struct cil_symtab_datum*)(struct cil_class*)rule->obj)->name;
	char *result_str = ((struct cil_symtab_datum*)(struct cil_type*)rule->result)->name;
		
	switch (rule->rule_kind) {
		case CIL_TYPE_TRANSITION:
			fprintf(file_arr[ALLOWS], "type_transition %s %s : %s %s;\n", src_str, tgt_str, obj_str, result_str);
			break;
		case CIL_TYPE_CHANGE:
			fprintf(file_arr[ALLOWS], "type_change %s %s : %s %s\n;", src_str, tgt_str, obj_str, result_str);
			break;
		case CIL_TYPE_MEMBER:
			fprintf(file_arr[ALLOWS], "type_member %s %s : %s %s;\n", src_str, tgt_str, obj_str, result_str);
			break;
		default : {
			printf("Unknown type_rule kind: %d\n", rule->rule_kind);
			return SEPOL_ERR;
		}
	}

	return SEPOL_OK;
}

int cil_expr_stack_to_policy(FILE **file_arr, uint32_t file_index, struct cil_tree_node *stack)
{
	struct cil_conditional *cond = NULL;
	struct cil_tree_node *new = NULL;
	char *oper1_str = NULL;
	char *oper2_str = NULL;
	char *oper = NULL;
	char *policy = NULL;
	struct cil_tree_node *prev_stack = NULL;

	while (stack != NULL) {
		cond = (struct cil_conditional*)stack->data;
		if ((cond->flavor == CIL_AND) || (cond->flavor == CIL_OR) || (cond->flavor == CIL_XOR) ||
			(cond->flavor == CIL_NOT) || (cond->flavor == CIL_EQ) || (cond->flavor == CIL_NEQ) ||
			(cond->flavor == CIL_CONS_AND) || (cond->flavor == CIL_CONS_DOM) ||
			(cond->flavor == CIL_CONS_DOMBY) || (cond->flavor == CIL_CONS_EQ) ||
			(cond->flavor == CIL_CONS_INCOMP) || (cond->flavor == CIL_CONS_NOT) ||
			(cond->flavor == CIL_CONS_OR)) {
			
			cil_tree_node_init(&new);
			int len1 = 0;
			int len2 = 0;
			

			if (stack->parent->flavor != CIL_COND)
				oper1_str = (char *)stack->parent->data;
			else {
				struct cil_conditional *cond1 = stack->parent->data;
				if (cond1->flavor == CIL_BOOL) 
					oper1_str = ((struct cil_bool *)cond1->data)->datum.name;
				else if (cond1->flavor == CIL_TYPE)
					oper1_str = ((struct cil_type *)cond1->data)->datum.name;
				else if (cond1->flavor == CIL_ROLE)
					oper1_str = ((struct cil_role *)cond1->data)->datum.name;
				else if (cond1->flavor == CIL_USER)
					oper1_str = ((struct cil_user *)cond1->data)->datum.name;
				else
					oper1_str = cond1->str;
			}

			len1 = strlen(oper1_str);

			if (cond->flavor != CIL_NOT && cond->flavor != CIL_CONS_NOT) {
				if (stack->parent->parent->flavor != CIL_COND)
					oper2_str = (char *)stack->parent->parent->data;
				else {
					struct cil_conditional *cond2 = stack->parent->parent->data;
					if (cond2->flavor == CIL_BOOL) 
						oper2_str = ((struct cil_bool *)cond2->data)->datum.name;
					else if (cond2->flavor == CIL_TYPE)
						oper2_str = ((struct cil_type *)cond2->data)->datum.name;
					else if (cond2->flavor == CIL_ROLE)
						oper2_str = ((struct cil_role *)cond2->data)->datum.name;
					else if (cond2->flavor == CIL_USER)
						oper2_str = ((struct cil_user *)cond2->data)->datum.name;
					else
						oper2_str = cond2->str;
				}
				len2 = strlen(oper2_str);
			}
			
			oper = ((struct cil_conditional*)stack->data)->str;
			int oplen = strlen(oper);

			if (cond->flavor != CIL_NOT && cond->flavor != CIL_CONS_NOT) {
				new->data = cil_malloc(len1 + len2 + oplen + 5);
				strcpy(new->data, "(");
				strncat(new->data, oper1_str, len1);
				strncat(new->data, " ", 1);
				strncat(new->data, oper, oplen);
				strncat(new->data, " ", 1);
				strncat(new->data, oper2_str, len2);
				strncat(new->data, ")", 1);
			}
			else {
				new->data = cil_malloc(len1 + len2 + oplen + 4);
				strcpy(new->data, "(");
				strncat(new->data, oper, oplen);
				strncat(new->data, " ", 1);
				strncat(new->data, oper1_str, len1);
				strncat(new->data, ")", 1);
			}
		
			new->flavor = CIL_AST_STR;
			new->cl_head = stack->cl_head;

			if (cond->flavor != CIL_NOT && cond->flavor != CIL_CONS_NOT)
				new->parent = stack->parent->parent->parent;
			else
				new->parent = stack->parent->parent;

			if (cond->flavor != CIL_NOT && cond->flavor != CIL_CONS_NOT) {
				if (stack->parent->parent->parent != NULL)
					stack->parent->parent->parent->cl_head = new;
			}
			else {
				if (stack->parent->parent != NULL)
					stack->parent->parent->cl_head = new;
			}

			if (stack->cl_head != NULL)
				stack->cl_head->parent = new;

			if (cond->flavor != CIL_NOT && cond->flavor != CIL_CONS_NOT)
				if (stack->parent->parent != NULL)
					cil_tree_node_destroy(&stack->parent->parent);
			cil_tree_node_destroy(&stack->parent);
			cil_tree_node_destroy(&stack);

			
			stack = new;
		}
		prev_stack = stack;
		stack = stack->cl_head;
	}

	if (prev_stack == NULL || prev_stack->parent != NULL || prev_stack->cl_head != NULL) {
		/* there should only be one item on the stack at this point */
		return SEPOL_ERR;
	}

	if (prev_stack->flavor == CIL_COND) {
		cond = prev_stack->data;
		if (cond->flavor == CIL_BOOL) {
			/* a single boolean is left on the stack, e.g (booleanif foo */
			char * bname = ((struct cil_bool *)cond->data)->datum.name;
			policy = cil_malloc(strlen(bname) + 3);
			strcpy(policy, "(");
			strncat(policy, bname, strlen(bname));
			strncat(policy, ")", 1);

			struct cil_tree_node *bnode;
			cil_tree_node_init(&bnode);
			bnode->data = policy;
			bnode->flavor = CIL_AST_STR;
			cil_tree_node_destroy(&prev_stack);
			prev_stack = bnode;
		} else {
			return SEPOL_ERR;
		}
	}
	
	fprintf(file_arr[file_index], "%s", (char *)prev_stack->data);

	cil_tree_node_destroy(&prev_stack);

	return SEPOL_OK;
}


int __cil_booleanif_node_helper(struct cil_tree_node *node, uint32_t *finished, struct cil_list *other)
{
	int rc = SEPOL_ERR;
	FILE **file_arr = (FILE**)other->head->data;
	uint32_t *file_index = (uint32_t*)other->head->next->data;

	switch (node->flavor) {
		case CIL_AVRULE : {
			rc = cil_avrule_to_policy(file_arr, *file_index, (struct cil_avrule*)node->data);
			if (rc != SEPOL_OK) {
				printf("cil_avrule_to_policy failed, rc: %d\n", rc);
				return rc;
			}
			break;
		}
		case CIL_TYPE_RULE : {
			rc = cil_typerule_to_policy(file_arr, *file_index, (struct cil_type_rule*)node->data);
			if (rc != SEPOL_OK) {
				printf("cil_typerule_to_policy failed, rc: %d\n", rc);
				return rc;
			}
			break;
		}
		case CIL_ELSE : {
			fprintf(file_arr[*file_index], "else {\n");
			break;
		}
		default: return SEPOL_ERR;
	}

	return SEPOL_OK;
}

int __cil_booleanif_reverse_helper(struct cil_tree_node *node, struct cil_list *other)
{
	FILE **file_arr = (FILE**)other->head->data;
	uint32_t *file_index = (uint32_t*)other->head->next->data;

	if (node->flavor == CIL_ELSE)
		fprintf(file_arr[*file_index], "}\n");
	
	return SEPOL_OK;
}
int cil_booleanif_to_policy(FILE **file_arr, uint32_t file_index, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	struct cil_booleanif *bif = node->data;
	struct cil_tree_node *stack = bif->expr_stack;
	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	cil_list_item_init(&other->head->next);

	other->head->data = file_arr;
	other->head->next->data = &file_index;

	fprintf(file_arr[file_index], "if ");

	rc = cil_expr_stack_to_policy(file_arr, file_index, stack);
	if (rc != SEPOL_OK) {
		printf("cil_expr_stack_to_policy failed, rc: %d\n", rc);
		return rc;
	}
	bif->expr_stack = NULL;
	fprintf(file_arr[file_index], "{\n");
	rc = cil_tree_walk(node, __cil_booleanif_node_helper, __cil_booleanif_reverse_helper, NULL, other);
	if (rc != SEPOL_OK) {
		printf("Failed to write booleanif content to file, rc: %d\n", rc);
		return rc;
	}
	fprintf(file_arr[file_index], "}");

	return SEPOL_OK;
}

int cil_name_to_policy(FILE **file_arr, struct cil_tree_node *current) 
{
	char *name = ((struct cil_symtab_datum*)current->data)->name;
	uint32_t flavor = current->flavor;
	int rc = SEPOL_ERR;

	switch(flavor) {
		case CIL_ATTR: {
			fprintf(file_arr[ATTRTYPES], "attribute %s;\n", name);
			break;
		}
		case CIL_TYPE: {
			fprintf(file_arr[ATTRTYPES], "type %s;\n", name);
			break;
		}
		case CIL_TYPE_ATTR: {
			struct cil_typeattribute *typeattr = (struct cil_typeattribute*)current->data;
			char *type_str = ((struct cil_symtab_datum*)typeattr->type)->name;
			char *attr_str = ((struct cil_symtab_datum*)typeattr->attr)->name;
			fprintf(file_arr[ALLOWS], "typeattribute %s %s;\n", type_str, attr_str);
			break;
		}
		case CIL_TYPEALIAS: {
			struct cil_typealias *alias = (struct cil_typealias*)current->data;
			fprintf(file_arr[ALIASES], "typealias %s alias %s;\n", ((struct cil_symtab_datum*)alias->type)->name, name);
			break;
		}
		case CIL_ROLE: {
			fprintf(file_arr[ATTRTYPES], "role %s;\n", name);
			break;
		}
		case CIL_BOOL: {
			char *boolean = ((struct cil_bool*)current->data)->value ? "true" : "false";
			fprintf(file_arr[ATTRTYPES], "bool %s %s;\n", name, boolean);
			break;
		}
		case CIL_COMMON: {
			if (current->cl_head != NULL) {
				current = current->cl_head;
				fprintf(file_arr[COMMONS], "common %s { ", name);
			}
			else {
				printf("No permissions given\n");
				return SEPOL_ERR;
			}

			while (current != NULL) {	
				if (current->flavor == CIL_PERM)
					fprintf(file_arr[COMMONS], "%s ", ((struct cil_symtab_datum*)current->data)->name);
				else {
					printf("Improper data type found in common permissions: %d\n", current->flavor);
					return SEPOL_ERR;
				}
				current = current->next;
			}
			fprintf(file_arr[COMMONS], "};\n");
			return SEPOL_DONE;
		}
		case CIL_CLASS: {
			fprintf(file_arr[CLASS_DECL], "class %s\n", ((struct cil_class*)current->data)->datum.name);

			if (current->cl_head != NULL) {
				fprintf(file_arr[CLASSES], "class %s ", ((struct cil_class*)(current->data))->datum.name);
			}
			else if (((struct cil_class*)current->data)->common == NULL) {
				printf("No permissions given\n");
				return SEPOL_ERR;
			}

			if (((struct cil_class*)current->data)->common != NULL) 
				fprintf(file_arr[CLASSES], "inherits %s ", ((struct cil_class*)current->data)->common->datum.name);

			fprintf(file_arr[CLASSES], "{ ");

			if (current->cl_head != NULL) 
				current = current->cl_head;

			while (current != NULL) {
				if (current->flavor == CIL_PERM)
					fprintf(file_arr[CLASSES], "%s ", ((struct cil_symtab_datum*)current->data)->name);
				else {
					printf("Improper data type found in class permissions: %d\n", current->flavor);
					return SEPOL_ERR;
				}
				current = current->next;
			}
			fprintf(file_arr[CLASSES], "};\n");
			return SEPOL_DONE;
		}
		case CIL_AVRULE: {
			struct cil_avrule *avrule = (struct cil_avrule*)current->data;
			rc = cil_avrule_to_policy(file_arr, ALLOWS, avrule);
			if (rc != SEPOL_OK) {
				printf("Failed to write avrule to policy\n");
				return rc;
			}
			break;
		}
		case CIL_TYPE_RULE: {
			struct cil_type_rule *rule = (struct cil_type_rule*)current->data;
			rc = cil_typerule_to_policy(file_arr, ALLOWS, rule);
			if (rc != SEPOL_OK) {
				printf("Failed to write type rule to policy\n");
				return rc;
			}
			break;
		}
		case CIL_ROLETRANS: {
			struct cil_role_trans *roletrans = (struct cil_role_trans*)current->data;
			char *src_str = ((struct cil_symtab_datum*)(struct cil_role*)roletrans->src)->name;
			char *tgt_str = ((struct cil_symtab_datum*)(struct cil_type*)roletrans->tgt)->name;
			char *obj_str = ((struct cil_symtab_datum*)(struct cil_class*)roletrans->obj)->name;
			char *result_str = ((struct cil_symtab_datum*)(struct cil_role*)roletrans->result)->name;
			
			fprintf(file_arr[ALLOWS], "role_transition %s %s:%s %s;\n", src_str, tgt_str, obj_str, result_str);
			break;
		}
		case CIL_ROLEALLOW: {
			struct cil_role_allow *roleallow = (struct cil_role_allow*)current->data;
			char *src_str = ((struct cil_symtab_datum*)(struct cil_role*)roleallow->src)->name;
			char *tgt_str = ((struct cil_symtab_datum*)(struct cil_type*)roleallow->tgt)->name;
			
			fprintf(file_arr[ALLOWS], "roleallow %s %s;\n", src_str, tgt_str);
			break;
		}
		case CIL_ROLETYPE : {
			struct cil_roletype *roletype = (struct cil_roletype*)current->data;
			char *role_str = ((struct cil_symtab_datum*)(struct cil_role*)roletype->role)->name;
			char *type_str = ((struct cil_symtab_datum*)(struct cil_type*)roletype->type)->name;
		
			fprintf(file_arr[ALIASES], "role %s types %s\n", role_str, type_str);
			break;
		}
		case CIL_ROLEDOMINANCE : {
			struct cil_roledominance *roledom = (struct cil_roledominance*)current->data;
			char *role_str = ((struct cil_symtab_datum*)(struct cil_role*)roledom->role)->name;
			char *domed_str = ((struct cil_symtab_datum*)(struct cil_role*)roledom->domed)->name;
			fprintf(file_arr[ATTRTYPES], "dominance { role %s { role %s; } }\n", role_str, domed_str);
			break;
		}
		case CIL_LEVEL : {
			fprintf(file_arr[LEVELS], "level ");
			cil_level_to_policy(file_arr, LEVELS, (struct cil_level*)current->data);
			fprintf(file_arr[LEVELS], ";\n");
			break;
		}
		case CIL_CONSTRAIN : {
			fprintf(file_arr[CONSTRAINS], "constrain ");
			cil_constrain_to_policy(file_arr, CONSTRAINS, (struct cil_constrain*)current->data);
			break;
		}
		case CIL_MLSCONSTRAIN : {
			fprintf(file_arr[CONSTRAINS], "mlsconstrain ");
			cil_constrain_to_policy(file_arr, CONSTRAINS, (struct cil_constrain*)current->data);
			break;
		}
		case CIL_NETIFCON : {
			struct cil_netifcon *netifcon = (struct cil_netifcon*)current->data;
			fprintf(file_arr[NETIFCONS], "netifcon %s ", netifcon->datum.name);
			cil_context_to_policy(file_arr, NETIFCONS, netifcon->if_context);
			fprintf(file_arr[NETIFCONS], " ");
			cil_context_to_policy(file_arr, NETIFCONS, netifcon->packet_context);
			fprintf(file_arr[NETIFCONS], "\n");
			
			break;
		}
		case CIL_SID : {
			fprintf(file_arr[ISIDS], "sid %s\n", name);
			break;
		}
		case CIL_SIDCONTEXT : {
			struct cil_sidcontext *sidcon = (struct cil_sidcontext*)current->data;
			fprintf(file_arr[SIDS], "sid %s ", ((struct cil_symtab_datum*)(struct sid*)sidcon->sid)->name);
			cil_context_to_policy(file_arr, SIDS, sidcon->context);
			fprintf(file_arr[SIDS], "\n");
			break;
		}
		case CIL_POLICYCAP : {
			fprintf(file_arr[ATTRTYPES], "policycap %s;\n", name);
			break;
		}

		default : {
			break;
		}
	}

	return SEPOL_OK;
}

/* other is a list containing users list, sensitivities list, categories list, and the file array */
int __cil_gen_policy_node_helper(struct cil_tree_node *node, uint32_t *finished, struct cil_list *other)
{
	if (other == NULL || other->head == NULL || other->head->next == NULL || other->head->next->next == NULL)
		return SEPOL_ERR;
	
	uint32_t rc = SEPOL_ERR;
	struct cil_list *users = NULL, *sens = NULL, *cats = NULL;
	FILE **file_arr = NULL;
	*finished = CIL_TREE_SKIP_NOTHING;

	if (other->head->flavor == CIL_LIST)
		users = other->head->data;
	else
		return SEPOL_ERR;

	if (other->head->next->flavor == CIL_LIST)
		sens = other->head->next->data;
	else
		return SEPOL_ERR;

	if (other->head->next->next->flavor == CIL_LIST)
		cats = other->head->next->next->data;
	else
		return SEPOL_ERR;

	if (other->head->next->next->next->flavor == CIL_FILES)
		file_arr = other->head->next->next->next->data;
	else
		return SEPOL_ERR;

	if (node->cl_head != NULL) {
		if (node->flavor == CIL_MACRO) {
			*finished = CIL_TREE_SKIP_HEAD;
			return SEPOL_OK;
		}
		if (node->flavor == CIL_BOOLEANIF) {
			rc = cil_booleanif_to_policy(file_arr, CONDS, node);
			if (rc != SEPOL_OK) {
				printf("Failed to write booleanif contents to file\n");
				return rc;
			}
			*finished = CIL_TREE_SKIP_HEAD;
			return SEPOL_OK;
		}
		if (node->flavor == CIL_OPTIONAL) {
			if (((struct cil_symtab_datum *)node->data)->state != CIL_STATE_ENABLED) {
				*finished = CIL_TREE_SKIP_HEAD;
			}
			return SEPOL_OK;
		}
		if (node->flavor != CIL_ROOT) {
			rc = cil_name_to_policy(file_arr, node);
			if (rc != SEPOL_OK && rc != SEPOL_DONE) {
				printf("Error converting node to policy %d\n", node->flavor);
				return SEPOL_ERR;
			}
		}
	}
	else {
		switch (node->flavor) {
			case CIL_USER: {
				cil_multimap_insert(users, node->data, NULL, CIL_USERROLE, 0);
				break;
			}
			case CIL_USERROLE: {
				cil_multimap_insert(users, &((struct cil_userrole*)node->data)->user->datum, &((struct cil_userrole*)node->data)->role->datum, CIL_USERROLE, CIL_ROLE);
				break;
			}
			case CIL_CATALIAS: {
				cil_multimap_insert(cats, &((struct cil_catalias*)node->data)->cat->datum, node->data, CIL_CAT, CIL_CATALIAS);
				break;
			}
			case CIL_SENSALIAS: {
				cil_multimap_insert(sens, &((struct cil_sensalias*)node->data)->sens->datum, node->data, CIL_SENS, CIL_SENSALIAS);
				break;
			}
			default : {
				rc = cil_name_to_policy(file_arr, node);
				if (rc != SEPOL_OK && rc != SEPOL_DONE) {
					printf("Error converting node to policy %d\n", rc);
					return SEPOL_ERR;
				}
				break;
			}
		}
	}

	return SEPOL_OK;
}

int cil_gen_policy(struct cil_db *db)
{
	struct cil_tree_node *curr = db->ast->root;
	struct cil_list_item *catorder;
	struct cil_list_item *dominance;
	int rc = SEPOL_ERR;
	FILE *policy_file;
	FILE **file_arr = cil_malloc(sizeof(FILE*) * NUM_POLICY_FILES);
	char *file_path_arr[NUM_POLICY_FILES];
	char temp[32];

	struct cil_list *users;
	cil_list_init(&users);
	struct cil_list *cats;
	cil_list_init(&cats);
	struct cil_list *sens;
	cil_list_init(&sens);

	strcpy(temp, "/tmp/cil_classdecl-XXXXXX");
	file_arr[CLASS_DECL] = fdopen(mkstemp(temp), "w+");
	file_path_arr[CLASS_DECL] = cil_strdup(temp);

	strcpy(temp, "/tmp/cil_isids-XXXXXX");
	file_arr[ISIDS] = fdopen(mkstemp(temp), "w+");
	file_path_arr[ISIDS] = cil_strdup(temp);

	strcpy(temp,"/tmp/cil_common-XXXXXX");
	file_arr[COMMONS] = fdopen(mkstemp(temp), "w+");
	file_path_arr[COMMONS] = cil_strdup(temp);
	
	strcpy(temp, "/tmp/cil_class-XXXXXX");
	file_arr[CLASSES] = fdopen(mkstemp(temp), "w+");
	file_path_arr[CLASSES] = cil_strdup(temp);

	strcpy(temp, "/tmp/cil_interf-XXXXXX");
	file_arr[INTERFACES] = fdopen(mkstemp(temp), "w+");
	file_path_arr[INTERFACES] = cil_strdup(temp);

	strcpy(temp, "/tmp/cil_sens-XXXXXX");
	file_arr[SENS] = fdopen(mkstemp(temp), "w+");
	file_path_arr[SENS] = cil_strdup(temp);

	strcpy(temp, "/tmp/cil_cats-XXXXXX");
	file_arr[CATS] = fdopen(mkstemp(temp), "w+");
	file_path_arr[CATS] = cil_strdup(temp);

	strcpy(temp, "/tmp/cil_levels-XXXXXX");
	file_arr[LEVELS] = fdopen(mkstemp(temp), "w+");
	file_path_arr[LEVELS] = cil_strdup(temp);

	strcpy(temp, "/tmp/cil_mlscon-XXXXXX");
	file_arr[CONSTRAINS] = fdopen(mkstemp(temp), "w+");
	file_path_arr[CONSTRAINS] = cil_strdup(temp);

	strcpy(temp, "/tmp/cil_attrtypes-XXXXXX");
	file_arr[ATTRTYPES] = fdopen(mkstemp(temp), "w+");
	file_path_arr[ATTRTYPES] = cil_strdup(temp);
	
	strcpy(temp, "/tmp/cil_aliases-XXXXXX");
	file_arr[ALIASES] = fdopen(mkstemp(temp), "w+");
	file_path_arr[ALIASES] = cil_strdup(temp);
	
	strcpy(temp, "/tmp/cil_allows-XXXXXX");
	file_arr[ALLOWS] = fdopen(mkstemp(temp), "w+");
	file_path_arr[ALLOWS] = cil_strdup(temp);
	
	strcpy(temp, "/tmp/cil_conds-XXXXXX");
	file_arr[CONDS] = fdopen(mkstemp(temp), "w+");
	file_path_arr[CONDS] = cil_strdup(temp);
	
	strcpy(temp, "/tmp/cil_userroles-XXXXXX");
	file_arr[USERROLES] = fdopen(mkstemp(temp), "w+");
	file_path_arr[USERROLES] = cil_strdup(temp);

	strcpy(temp, "/tmp/cil_sids-XXXXXX");
	file_arr[SIDS] = fdopen(mkstemp(temp), "w+");
	file_path_arr[SIDS] = cil_strdup(temp);

	strcpy(temp, "/tmp/cil_netifcons-XXXXXX");
	file_arr[NETIFCONS] = fdopen(mkstemp(temp), "w+");
	file_path_arr[NETIFCONS] = cil_strdup(temp);

	policy_file = fopen("policy.conf", "w+");

	if (db->catorder->head != NULL) {
		catorder = db->catorder->head;
		while (catorder != NULL) {
			cil_multimap_insert(cats, catorder->data, NULL, CIL_CAT, 0);
			catorder = catorder->next;
		}
	}

	if (db->dominance->head != NULL) {
		dominance = db->dominance->head;
		fprintf(file_arr[SENS], "dominance { ");
		while (dominance != NULL) { 
			fprintf(file_arr[SENS], "%s ", ((struct cil_sens*)dominance->data)->datum.name);
			dominance = dominance->next;
		}
		fprintf(file_arr[SENS], "};\n");
	}

	struct cil_list *other;
	cil_list_init(&other);
	cil_list_item_init(&other->head);
	other->head->flavor = CIL_LIST;
	other->head->data = users;
	cil_list_item_init(&other->head->next);
	other->head->next->flavor = CIL_LIST;
	other->head->next->data = sens;
	cil_list_item_init(&other->head->next->next);
	other->head->next->next->flavor = CIL_LIST;
	other->head->next->next->data = cats;
	cil_list_item_init(&other->head->next->next->next);
	other->head->next->next->next->flavor = CIL_FILES;
	other->head->next->next->next->data = file_arr;

	rc = cil_tree_walk(curr, __cil_gen_policy_node_helper, NULL, NULL, other);
	if (rc != SEPOL_OK) {
		printf("Error walking tree\n");
		return rc;
	}

	rc = cil_userrole_to_policy(file_arr, users);
	if (rc != SEPOL_OK) {
		printf("Error creating policy.conf\n");
		return SEPOL_ERR;
	}

	rc = cil_sens_to_policy(file_arr, sens);
	if (rc != SEPOL_OK) {
		printf("Error creating policy.conf\n");
		return SEPOL_ERR;
	}

	rc = cil_cat_to_policy(file_arr, cats);
	if (rc != SEPOL_OK) {
		printf("Error creating policy.conf\n");
		return SEPOL_ERR;
	}

	rc = cil_combine_policy(file_arr, policy_file);
	if (rc != SEPOL_OK) {
		printf("Error creating policy.conf\n");
		return SEPOL_ERR;
	}

	// Remove temp files
	int i;
	for (i=0; i<NUM_POLICY_FILES; i++) {
		rc = fclose(file_arr[i]);
		if (rc != 0) {
			printf("Error closing temporary file\n");
			return SEPOL_ERR;
		}
		rc = unlink(file_path_arr[i]);
		if (rc != 0) {
			printf("Error unlinking temporary files\n");
			return SEPOL_ERR;
		}
		free(file_path_arr[i]);
	}

	rc = fclose(policy_file);
	if (rc != 0) {
		printf("Error closing policy.conf\n");
		return SEPOL_ERR;
	}
	free(file_arr);

	return SEPOL_OK;
}
