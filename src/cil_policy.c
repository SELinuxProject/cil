#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sepol/errcodes.h>
#include "cil_tree.h" 
#include "cil.h"
#include "cil_policy.h"

#define SEPOL_DONE			555

#define COMMONS				0
#define CLASSES				1
#define INTERFACES			2
#define ATTRTYPES			3
#define ALIASES				4
#define ALLOWS				5
#define USERROLES			6

#define BUFFER				1024
#define NUM_POLICY_FILES 	7 

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

static int __cil_user_list_insert_user(struct cil_list_item **current_user, struct cil_user *user, struct cil_role *role)
{
	struct cil_list_item *new_user = NULL;
	cil_list_item_init(&new_user);
	struct cil_user_list_item *new_data = cil_malloc(sizeof(struct cil_user_list_item));
	new_data->user = user;
	cil_list_init(&new_data->roles);
	if (role != NULL) {
		cil_list_item_init(&new_data->roles->head);
		new_data->roles->head->data = role;
		new_data->roles->head->flavor = CIL_ROLE;
	}
	new_user->flavor = CIL_USERROLE;
	new_user->data = new_data;
	if (*current_user == NULL)
		*current_user = new_user;
	else
		(*current_user)->next = new_user;

	return SEPOL_OK;
}

int cil_user_list_insert(struct cil_list *list, struct cil_user *user, struct cil_role *role)
{
	if (list == NULL || user == NULL) 
		return SEPOL_ERR;

	struct cil_list_item *current_user = list->head;
	struct cil_list_item *current_role = NULL;
	int rc = SEPOL_ERR;

	if (current_user == NULL) {
		__cil_user_list_insert_user(&list->head, user, role);
	}
	while(current_user != NULL) {
		if ((struct cil_user_list_item*)current_user->data != NULL) {
			if (((struct cil_user_list_item*)current_user->data)->user != NULL && ((struct cil_user_list_item*)current_user->data)->user == user) {
				current_role = ((struct cil_user_list_item*)current_user->data)->roles->head;
				if (current_role == NULL) {
					struct cil_list_item *new_role = NULL;
					cil_list_item_init(&new_role);
					new_role->data = role;
					new_role->flavor = CIL_ROLE;
					((struct cil_user_list_item*)current_user->data)->roles->head = new_role;
					return SEPOL_OK;
				}
				while (current_role != NULL) {
					if (current_role == role) {
						printf("Duplicate declaration of userrole\n");
						return SEPOL_ERR;
					}
					if (current_role->next == NULL) {
						struct cil_list_item *new_role = NULL;
						cil_list_item_init(&new_role);
						new_role->data = role;
						new_role->flavor = CIL_ROLE;
						current_role->next = new_role;
						return SEPOL_OK;
					}
					current_role = current_role->next;
				}
			}	
			else if (current_user->next == NULL) {
				__cil_user_list_insert_user(&current_user, user, role);
				return SEPOL_OK;
			}
		}
		else {
			printf("No data in list item\n");
			return SEPOL_ERR;
		}
		current_user = current_user->next;
	}
	return SEPOL_OK;
}

int cil_userrole_to_policy(FILE **file_arr, struct cil_list *userroles)
{
	if (userroles == NULL) 
		return SEPOL_OK;
	
	struct cil_list_item *current_user = userroles->head;
	while (current_user != NULL) {
		if (((struct cil_user_list_item*)current_user->data)->roles->head == NULL) {
			printf("No roles associated with user %s (line %d)\n",  ((struct cil_user_list_item*)current_user->data)->user->datum.name,  ((struct cil_user_list_item*)current_user->data)->user->datum.node->line);
			return SEPOL_ERR;
		}
		fprintf(file_arr[USERROLES], "user %s roles {", ((struct cil_user_list_item*)current_user->data)->user->datum.name);
		struct cil_list_item *current_role = ((struct cil_user_list_item*)current_user->data)->roles->head;
		while (current_role != NULL) {
			fprintf(file_arr[USERROLES], " %s",  ((struct cil_role*)current_role->data)->datum.name);
			current_role = current_role->next;
		}
		fprintf(file_arr[USERROLES], " };\n"); 
		current_user = current_user->next;
	}
	return SEPOL_OK;
}

int cil_name_to_policy(FILE **file_arr, struct cil_tree_node *current) 
{
	char *name = ((struct cil_symtab_datum*)current->data)->name;
	uint32_t flavor = current->flavor;

	switch(flavor) {
		case CIL_BLOCK: {
			break;  // Ignore
		}
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
			char *attr_str = ((struct cil_symtab_datum*)typeattr->attrib)->name;
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
			if (current->cl_head != NULL) {
				current = current->cl_head;
				fprintf(file_arr[CLASSES], "class %s { ", name);
			}
			else {
				printf("No permissions given\n");
				return SEPOL_ERR;
			}

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
			struct cil_avrule *rule = (struct cil_avrule*)current->data;
			char *src_str = ((struct cil_symtab_datum*)(struct cil_type*)rule->src)->name;
			char *tgt_str = ((struct cil_symtab_datum*)(struct cil_type*)rule->tgt)->name;
			char *obj_str = ((struct cil_symtab_datum*)(struct cil_type*)rule->obj)->name;
			struct cil_list_item *perm_item = rule->perms_list->head;
			switch (rule->rule_kind) {
				case CIL_AVRULE_ALLOWED:
					fprintf(file_arr[ALLOWS], "allow %s %s:%s { ", src_str, tgt_str, obj_str);
					break;
				case CIL_AVRULE_AUDITALLOW:
					fprintf(file_arr[ALLOWS], "auditallow %s %s:%s { ", src_str, tgt_str, obj_str);
					break;
				case CIL_AVRULE_DONTAUDIT:
					fprintf(file_arr[ALLOWS], "dontaudit %s %s:%s { ", src_str, tgt_str, obj_str);
					break;
				case CIL_AVRULE_NEVERALLOW:
					fprintf(file_arr[ALLOWS], "neverallow %s %s:%s { ", src_str, tgt_str, obj_str);
					break;
				default : {
					printf("Unknown avrule kind: %d\n", rule->rule_kind);
					return SEPOL_ERR;
				}
			}
			while (perm_item != NULL) {
				fprintf(file_arr[ALLOWS], "%s ", ((struct cil_perm*)(perm_item->data))->datum.name);
				perm_item = perm_item->next;
			}
			fprintf(file_arr[ALLOWS], "};\n");
			break;
		}
		case CIL_TYPE_RULE: {
			struct cil_type_rule *rule = (struct cil_type_rule*)current->data;
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
			break;
		}
		case CIL_ROLETRANS: {
			struct cil_role_trans *roletrans = (struct cil_role_trans*)current->data;
			char *src_str = ((struct cil_symtab_datum*)(struct cil_role*)roletrans->src)->name;
			char *tgt_str = ((struct cil_symtab_datum*)(struct cil_type*)roletrans->tgt)->name;
			char *result_str = ((struct cil_symtab_datum*)(struct cil_role*)roletrans->result)->name;
			
			fprintf(file_arr[ALLOWS], "role_transition %s %s %s;\n", src_str, tgt_str, result_str);
			break;
		}
		case CIL_ROLEALLOW: {
			struct cil_role_allow *roleallow = (struct cil_role_allow*)current->data;
			char *src_str = ((struct cil_symtab_datum*)(struct cil_role*)roleallow->src)->name;
			char *tgt_str = ((struct cil_symtab_datum*)(struct cil_type*)roleallow->tgt)->name;
			
			fprintf(file_arr[ALLOWS], "roleallow %s %s;\n", src_str, tgt_str);
			break;
		}
		case CIL_SENS: {
			break;
		}
		case CIL_SENSALIAS: {
			break;
		}
		default : {
			printf("Unknown data flavor: %d\n", flavor);
			return SEPOL_ERR;
			break;
		}
	}

	return SEPOL_OK;
}

int cil_gen_policy(struct cil_tree_node *root)
{
	struct cil_tree_node *curr = root;
	int rc = SEPOL_ERR;
	int reverse = 0;
	FILE *policy_file;
	FILE **file_arr = cil_malloc(sizeof(FILE*) * NUM_POLICY_FILES);
	char *file_path_arr[NUM_POLICY_FILES];
	char temp[32];

	struct cil_list *users;
	cil_list_init(&users);

	strcpy(temp,"/tmp/common-XXXXXX");
	file_arr[COMMONS] = fdopen(mkstemp(temp), "w+");
	file_path_arr[COMMONS] = strdup(temp);
	
	strcpy(temp, "/tmp/class-XXXXXX");
	file_arr[CLASSES] = fdopen(mkstemp(temp), "w+");
	file_path_arr[CLASSES] = strdup(temp);

	strcpy(temp, "/tmp/interf-XXXXXX");
	file_arr[INTERFACES] = fdopen(mkstemp(temp), "w+");
	file_path_arr[INTERFACES] = strdup(temp);
	
	strcpy(temp, "/tmp/attrtypes-XXXXXX");
	file_arr[ATTRTYPES] = fdopen(mkstemp(temp), "w+");
	file_path_arr[ATTRTYPES] = strdup(temp);
	
	strcpy(temp, "/tmp/aliases-XXXXXX");
	file_arr[ALIASES] = fdopen(mkstemp(temp), "w+");
	file_path_arr[ALIASES] = strdup(temp);
	
	strcpy(temp, "/tmp/allows-XXXXXX");
	file_arr[ALLOWS] = fdopen(mkstemp(temp), "w+");
	file_path_arr[ALLOWS] = strdup(temp);
	
	strcpy(temp, "/tmp/userroles-XXXXXX");
	file_arr[USERROLES] = fdopen(mkstemp(temp), "w+");
	file_path_arr[USERROLES] = strdup(temp);

	policy_file = fopen("policy.conf", "w+");	

	do {
		if (curr->cl_head != NULL) {
			if (!reverse) {
				if (curr->flavor != CIL_ROOT) {
					rc = cil_name_to_policy(file_arr, curr);
					if (rc != SEPOL_OK && rc != SEPOL_DONE) {
						printf("Error converting node to policy %d\n", curr->flavor);
						return SEPOL_ERR;
					}
				}
			}
		}
		else {
			if (curr->flavor == CIL_USERROLE) {
				cil_user_list_insert(users, ((struct cil_userrole*)curr->data)->user, ((struct cil_userrole*)curr->data)->role);
			}
			else if (curr->flavor == CIL_USER) {
				cil_user_list_insert(users, (struct cil_user*)curr->data, NULL);
			}
			else {
				rc = cil_name_to_policy(file_arr, curr);
				if (rc != SEPOL_OK && rc != SEPOL_DONE) {
					printf("Error converting node to policy %d\n", rc);
					return SEPOL_ERR;
				}
			}
		}
	
		if (curr->cl_head != NULL && !reverse && rc != SEPOL_DONE)
			curr = curr->cl_head;
		else if (curr->next != NULL) {
			curr = curr->next;
			reverse = 0;
		}
		else {
			curr = curr->parent;
			reverse = 1;
		}
	} while (curr->flavor != CIL_ROOT);

	rc = cil_userrole_to_policy(file_arr, users);
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
