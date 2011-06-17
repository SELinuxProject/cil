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
	char *fqn, *uqn;

	*fqp = '\0';

	do {
		if (curr->cl_head != NULL &&
			(curr->flavor != CIL_MACRO &&
			 curr->flavor != CIL_CALL &&
			 curr->flavor != CIL_BOOLEANIF &&
			 curr->flavor != CIL_ELSE &&
			 curr->flavor != CIL_OPTIONAL)) {
			if (!reverse) {
				if (curr->flavor >= CIL_MIN_DECLARATIVE) { // append name
					strcat(fqp, ((struct cil_symtab_datum*)curr->data)->name);
					strcat(fqp, ".");
				}
			} else {
				length = strlen(fqp) - (strlen(((struct cil_symtab_datum*)curr->data)->name) + 1);
				fqp[length] = '\0';
			}
		} else if (curr->flavor >= CIL_MIN_DECLARATIVE){
			uqn = ((struct cil_symtab_datum*)curr->data)->name; 
			length = strlen(fqp) + strlen(uqn) + 1;
			fqn = cil_malloc(length + 1);

			strcpy(fqn, fqp);
			strcat(fqn, uqn);

			((struct cil_symtab_datum*)curr->data)->name = fqn;	// Replace with new, fully qualified string
			free(uqn);
		}

		if (curr->cl_head != NULL && !reverse) {
			curr = curr->cl_head;
		} else if (curr->next != NULL) {
			curr = curr->next;
			reverse = 0;
		} else {
			curr = curr->parent;
			reverse = 1;
		}
	} while (curr->flavor != CIL_ROOT);

	return SEPOL_OK;
}

