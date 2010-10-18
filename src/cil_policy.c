#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sepol/errcodes.h>
#include "cil_tree.h" 
#include "cil.h"

#define SEPOL_DONE			555

#define COMMONS				0
#define CLASSES				1
#define INTERFACES			2
#define ATTRTYPES			3
#define ALIASES				4
#define ALLOWS				5

#define BUFFER				1024
#define NUM_POLICY_FILES 	6 

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
			struct cil_list_item *perm_item = rule->perms_list->list;
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

	policy_file = fopen("policy.conf", "w+");	

	do {
		if (curr->cl_head != NULL) {
			if (!reverse) {
				if (curr->flavor != CIL_ROOT) {
					rc = cil_name_to_policy(file_arr, curr);
					if (rc != SEPOL_OK && rc != SEPOL_DONE) {
						printf("Error converting node to policy %d\n", rc);
						return SEPOL_ERR;
					}
				}
			}
		}
		else {
			rc = cil_name_to_policy(file_arr, curr);
			if (rc != SEPOL_OK && rc != SEPOL_DONE) {
				printf("Error converting node to policy %d\n", rc);
				return SEPOL_ERR;
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
