#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "cil.h"
#include "cil_mem.h"
#include "cil_tree.h"

#define MAX_CIL_NAME_LENGTH 2048
int cil_qualify_name(struct cil_tree_node *root)
{
	struct cil_tree_node *curr = root;
	uint16_t reverse = 0;
	uint32_t length;
	char fqp[MAX_CIL_NAME_LENGTH];
	*fqp = '\0';
	char *fqn, *uqn;

	do {
		if (curr->cl_head != NULL && (curr->flavor != CIL_MACRO && curr->flavor != CIL_CALL)) {
			if (!reverse) {
				if (curr->flavor >= CIL_MIN_DECLARATIVE) { // append name
					strcat(fqp, ((struct cil_symtab_datum*)curr->data)->name);
					strcat(fqp, ".");
				}
			}
			else {
				length = strlen(fqp) - (strlen(((struct cil_symtab_datum*)curr->data)->name) + 1);
				fqp[length] = '\0';
			}
		}
		else if (curr->flavor >= CIL_MIN_DECLARATIVE){
			uqn = ((struct cil_symtab_datum*)curr->data)->name; 
			length = strlen(fqp) + strlen(uqn) + 1;
			fqn = cil_malloc(length + 1);

			strcpy(fqn, fqp);
			strcat(fqn, uqn);

			((struct cil_symtab_datum*)curr->data)->name = fqn;	// Replace with new, fully qualified string
			free(uqn);
		}

		if (curr->cl_head != NULL && !reverse) 
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

	return SEPOL_OK;
}

