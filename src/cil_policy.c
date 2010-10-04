#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sepol/errcodes.h>
#include "cil_tree.h" 
#include "cil.h"

#define SEPOL_DONE	5

int cil_name_to_policy(FILE *pFile, struct cil_tree_node *current) 
{
	char *name = ((cil_symtab_datum_t*)current->data)->name;
	uint32_t flavor = current->flavor;

	switch(flavor) {
		case CIL_BLOCK: {
			break;  // Ignore
		}
		case CIL_TYPE: {
			fprintf(pFile, "type %s;\n", name);
			break;
		}
		case CIL_TYPEALIAS: {
			struct cil_typealias *alias = (struct cil_typealias*)current->data;
			fprintf(pFile, "typealias %s alias %s;\n", ((cil_symtab_datum_t*)alias->type)->name, name);
			break;
		}
		case CIL_ROLE: {
			fprintf(pFile, "role %s;\n", name);
			break;
		}
		case CIL_BOOL: {
			char *boolean = ((struct cil_bool*)current->data)->value ? "true" : "false";
			fprintf(pFile, "bool %s %s;\n", name, boolean);
			break;
		}
		case CIL_CLASS: {
			if (current->cl_head != NULL) {
				current = current->cl_head;
				fprintf(pFile, "class %s { ", name);
			}
			else {
				printf("No permissions given\n");
				return SEPOL_ERR;
			}

			while (current != NULL) {
				if (current->flavor == CIL_PERM)
					fprintf(pFile, "%s ", ((cil_symtab_datum_t*)current->data)->name);
				else {
					printf("Improper data type found in class permissions: %d\n", current->flavor);
					return SEPOL_ERR;
				}
				current = current->next;
			}
			fprintf(pFile, "};\n");
			return SEPOL_DONE;
			break;
		}
		case CIL_AVRULE: {
			struct cil_avrule *rule = (struct cil_avrule*)current->data;
			char *src_str = ((cil_symtab_datum_t*)(struct cil_type*)rule->src)->name;
			char *tgt_str = ((cil_symtab_datum_t*)(struct cil_type*)rule->tgt)->name;
			char *obj_str = ((cil_symtab_datum_t*)(struct cil_type*)rule->obj)->name;
//			struct cil_list *perm_list = 
			fprintf(pFile, "allow %s %s:%s { ", src_str, tgt_str, obj_str);
			fprintf(pFile, "};\n");
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
	FILE *policy_file;
	policy_file = fopen("policy.conf", "w+");

	struct cil_tree_node *curr = root;
	uint16_t reverse = 0;
	int rc;

	do {
		if (curr->cl_head != NULL) {
			if (!reverse) {
				if (curr->flavor != CIL_ROOT)
					rc = cil_name_to_policy(policy_file, curr);
			}
		}
		else 
			rc = cil_name_to_policy(policy_file, curr);
	
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

	fclose(policy_file);

	return SEPOL_OK;
}
