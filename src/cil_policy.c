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
#define SIDS				14
#define NETIFCONS			15 

#define BUFFER				1024
#define NUM_POLICY_FILES		16

struct cil_args_genpolicy {
	struct cil_list *users;
	struct cil_list *sens;
	struct cil_list *cats;
	FILE **file_arr;
};

struct cil_args_booleanif {
	FILE **file_arr;
	uint32_t *file_index;
};


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

void fc_fill_data(struct fc_data *fc, char *path)
{
	int c = 0;
	fc->meta = 0;
	fc->stem_len = 0;
	fc->str_len = 0;
	
	while (path[c] != '\0') {
		switch (path[c]) {
		case '.':
		case '^':
		case '$':
		case '?':
		case '*':
		case '+':
		case '|':
		case '[':
		case '(':
		case '{':
			fc->meta = 1;
			break;
		case '\\':
			c++;
		default:
			if (!fc->meta) {
				fc->stem_len++;
			}
			break;
		}
		fc->str_len++;
		c++;
	}
}

int cil_filecon_compare(const void *a, const void *b)
{
	int rc = 0;
	struct cil_filecon *a_filecon = *(struct cil_filecon**)a;
	struct cil_filecon *b_filecon = *(struct cil_filecon**)b;
	struct fc_data *a_data = cil_malloc(sizeof(*a_data));
	struct fc_data *b_data = cil_malloc(sizeof(*b_data));
	char *a_path = cil_malloc(strlen(a_filecon->root_str)+strlen(a_filecon->path_str));
	a_path[0] = '\0';
	char *b_path = cil_malloc(strlen(b_filecon->root_str)+strlen(b_filecon->path_str));
	b_path[0] = '\0';
	strcat(a_path, a_filecon->root_str);
	strcat(a_path, a_filecon->path_str);
	strcat(b_path, b_filecon->root_str);
	strcat(b_path, b_filecon->path_str);
	fc_fill_data(a_data, a_path);
	fc_fill_data(b_data, b_path);
	if (a_data->meta && !b_data->meta) {
		rc = -1;
	} else if (b_data->meta && !a_data->meta) {
		rc = 1;
	} else if (a_data->stem_len < b_data->stem_len) {
		rc = -1;
	} else if (b_data->stem_len < a_data->stem_len) {
		rc = 1;
	} else if (a_data->str_len < b_data->str_len) {
		rc = -1;
	} else if (b_data->str_len < a_data->str_len) {
		rc = 1;
	} else if (a_filecon->type < b_filecon->type) {
		rc = -1;
	} else if (b_filecon->type < a_filecon->type) {
		rc = 1;
	}

	free(a_path);
	free(b_path);
	free(a_data);
	free(b_data);

	return rc;
}

int cil_filecon_to_policy(struct cil_sort *sort)
{
	int rc = SEPOL_ERR;
	uint32_t i = 0;
	FILE *file_contexts = fopen("file_contexts", "w+");

	for (i=0; i<sort->count; i++) {
		struct cil_filecon *filecon = (struct cil_filecon*)sort->array[i];
		fprintf(file_contexts, "filecon %s%s ", filecon->root_str, filecon->path_str);
		if (filecon->type == CIL_FILECON_FILE) {
			fprintf(file_contexts, "-- ");
		} else if (filecon->type == CIL_FILECON_DIR) {
			fprintf(file_contexts, "-d ");
		} else if (filecon->type == CIL_FILECON_CHAR) {
			fprintf(file_contexts, "-c ");
		} else if (filecon->type == CIL_FILECON_BLOCK) {
			fprintf(file_contexts, "-b ");
		} else if (filecon->type == CIL_FILECON_SOCKET) {
			fprintf(file_contexts, "-s ");
		} else if (filecon->type == CIL_FILECON_PIPE) {
			fprintf(file_contexts, "-p ");
		} else if (filecon->type == CIL_FILECON_SYMLINK) {
			fprintf(file_contexts, "-l ");
		} else if (filecon->type == CIL_FILECON_ANY) {
			fprintf(file_contexts, "  ");
		} else {
			fclose(file_contexts);
			return SEPOL_ERR;
		}
		cil_context_to_policy(&file_contexts, 0, filecon->context);
		fprintf(file_contexts, ";\n");
	}
	rc = fclose(file_contexts);
	if (rc != 0) {
		return SEPOL_ERR;
	}

	return SEPOL_OK;
}

int cil_portcon_compare(const void *a, const void *b)
{
	int rc = SEPOL_ERR;
	struct cil_portcon *aportcon = *(struct cil_portcon**)a;
	struct cil_portcon *bportcon = *(struct cil_portcon**)b;

	rc = (aportcon->port_high - aportcon->port_low) 
		- (bportcon->port_high - bportcon->port_low);
	if (rc == 0) {
		if (aportcon->port_low < bportcon->port_low) {
			rc = -1;
		} else if (bportcon->port_low < aportcon->port_low) {
			rc = 1;
		}
	}

	return rc;
}

int cil_portcon_to_policy(FILE **file_arr, struct cil_sort *sort)
{
	uint32_t i = 0;

	for (i=0; i<sort->count; i++) {
		struct cil_portcon *portcon = (struct cil_portcon*)sort->array[i];
		fprintf(file_arr[NETIFCONS], "portcon %s ", portcon->type_str);
		fprintf(file_arr[NETIFCONS], "%d ", portcon->port_low);
		fprintf(file_arr[NETIFCONS], "%d ", portcon->port_high);
		cil_context_to_policy(file_arr, NETIFCONS, portcon->context);
		fprintf(file_arr[NETIFCONS], ";\n");
	}

	return SEPOL_OK;
}

int cil_genfscon_compare(const void *a, const void *b)
{
	int rc = SEPOL_ERR;
	struct cil_genfscon *agenfscon = *(struct cil_genfscon**)a;
	struct cil_genfscon *bgenfscon = *(struct cil_genfscon**)b;

	rc = strcmp(agenfscon->type_str, bgenfscon->type_str);
	if (rc == 0) {
		rc = strcmp(agenfscon->path_str, bgenfscon->path_str);
	}

	return rc;
}

int cil_genfscon_to_policy(FILE **file_arr, struct cil_sort *sort)
{
	uint32_t i = 0;

	for (i=0; i<sort->count; i++) {
		struct cil_genfscon *genfscon = (struct cil_genfscon*)sort->array[i];
		fprintf(file_arr[NETIFCONS], "genfscon %s ", genfscon->type_str);
		fprintf(file_arr[NETIFCONS], "%s ", genfscon->path_str);
		cil_context_to_policy(file_arr, NETIFCONS, genfscon->context);
		fprintf(file_arr[NETIFCONS], ";\n");
	}

	return SEPOL_OK;
}

int cil_netifcon_compare(const void *a, const void *b)
{
	struct cil_netifcon *anetifcon = *(struct cil_netifcon**)a;
	struct cil_netifcon *bnetifcon = *(struct cil_netifcon**)b;

	return  strcmp(anetifcon->interface_str, bnetifcon->interface_str);
}

int cil_netifcon_to_policy(FILE **file_arr, struct cil_sort *sort)
{
	uint32_t i = 0;

	for (i=0; i<sort->count; i++) {
		struct cil_netifcon *netifcon = (struct cil_netifcon*)sort->array[i];
		fprintf(file_arr[NETIFCONS], "netifcon %s ", netifcon->interface_str);
		cil_context_to_policy(file_arr, NETIFCONS, netifcon->if_context);
		fprintf(file_arr[NETIFCONS], " ");
		cil_context_to_policy(file_arr, NETIFCONS, netifcon->packet_context);
		fprintf(file_arr[NETIFCONS], ";\n");
	}

	return SEPOL_OK;
}

int cil_nodecon_compare(const void *a, const void *b)
{
	struct cil_nodecon *anodecon;
	struct cil_nodecon *bnodecon;
	anodecon = *(struct cil_nodecon**)a;
	bnodecon = *(struct cil_nodecon**)b;

	/* sort ipv4 before ipv6 */
	if (anodecon->addr->family != bnodecon->addr->family) {
		if (anodecon->addr->family == AF_INET) {
			return -1;
		} else {
			return 1;
		}
	}

	/* most specific netmask goes first, then order by ip addr */
	if (anodecon->addr->family == AF_INET) {
		int rc = memcmp(&anodecon->mask->ip.v4, &bnodecon->mask->ip.v4, sizeof(anodecon->mask->ip.v4));
		if (rc != 0) {
			return -1 * rc;
		}
		return memcmp(&anodecon->addr->ip.v4, &bnodecon->addr->ip.v4, sizeof(anodecon->addr->ip.v4));
	} else {
		int rc = memcmp(&anodecon->mask->ip.v6, &bnodecon->mask->ip.v6, sizeof(anodecon->mask->ip.v6));
		if (rc != 0) {
			return -1 * rc;
		}
		return memcmp(&anodecon->addr->ip.v6, &bnodecon->addr->ip.v6, sizeof(anodecon->addr->ip.v6));
	}
}

int cil_nodecon_to_policy(FILE **file_arr, struct cil_sort *sort)
{
	uint32_t i = 0;

	for (i=0; i<sort->count; i++) {
		struct cil_nodecon *nodecon = (struct cil_nodecon*)sort->array[i];
		fprintf(file_arr[NETIFCONS], "nodecon %s ", nodecon->addr_str);
		fprintf(file_arr[NETIFCONS], "%s ", nodecon->mask_str);
		cil_context_to_policy(file_arr, NETIFCONS, nodecon->context);
		fprintf(file_arr[NETIFCONS], ";\n");
	}

	return SEPOL_OK;
}

int cil_fsuse_compare(const void *a, const void *b)
{
	int rc;
	struct cil_fsuse *afsuse;
	struct cil_fsuse *bfsuse;
	afsuse = *(struct cil_fsuse**)a;
	bfsuse = *(struct cil_fsuse**)b;
	if (afsuse->type < bfsuse->type) {
		rc = -1;
	} else if (bfsuse->type < afsuse->type) {
		rc = 1;
	} else {
		rc = strcmp(afsuse->fs_str, bfsuse->fs_str);
	}
	return rc;
}

int cil_fsuse_to_policy(FILE **file_arr, struct cil_sort *sort)
{
	uint32_t i = 0;

	for (i=0; i<sort->count; i++) {
		struct cil_fsuse *fsuse = (struct cil_fsuse*)sort->array[i];
		if (fsuse->type == CIL_FSUSE_XATTR) {
			fprintf(file_arr[NETIFCONS], "fs_use_xattr ");
		} else if (fsuse->type == CIL_FSUSE_TASK) {
			fprintf(file_arr[NETIFCONS], "fs_use_task ");
		} else if (fsuse->type == CIL_FSUSE_TRANS) {
			fprintf(file_arr[NETIFCONS], "fs_use_trans ");
		} else {
			return SEPOL_ERR;
		}
		fprintf(file_arr[NETIFCONS], "%s ", fsuse->fs_str);
		cil_context_to_policy(file_arr, NETIFCONS, fsuse->context);
		fprintf(file_arr[NETIFCONS], ";\n");
	}

	return SEPOL_OK;
}

static int __cil_multimap_insert_key(struct cil_list_item **curr_key, struct cil_symtab_datum *key, struct cil_symtab_datum *value, uint32_t key_flavor, uint32_t val_flavor)
{
	struct cil_list_item *new_key = NULL;
	struct cil_multimap_item *new_data = cil_malloc(sizeof(*new_data));

	cil_list_item_init(&new_key);
	new_data->key = key;
	cil_list_init(&new_data->values);
	if (value != NULL) {
		cil_list_item_init(&new_data->values->head);
		new_data->values->head->data = value;
		new_data->values->head->flavor = val_flavor;
	}
	new_key->flavor = key_flavor;
	new_key->data = new_data;
	if (*curr_key == NULL) {
		*curr_key = new_key;
	} else {
		(*curr_key)->next = new_key;
	}

	return SEPOL_OK;
}

int cil_multimap_insert(struct cil_list *list, struct cil_symtab_datum *key, struct cil_symtab_datum *value, uint32_t key_flavor, uint32_t val_flavor)
{
	struct cil_list_item *curr_key = NULL;
	struct cil_list_item *curr_value = NULL;

	if (list == NULL || key == NULL) {
		return SEPOL_ERR;
	}

	curr_key = list->head;

	if (curr_key == NULL) {
		__cil_multimap_insert_key(&list->head, key, value, key_flavor, val_flavor);
	}

	while(curr_key != NULL) {
		if ((struct cil_multimap_item*)curr_key->data != NULL) {
			if (((struct cil_multimap_item*)curr_key->data)->key != NULL && ((struct cil_multimap_item*)curr_key->data)->key == key) {
				struct cil_list_item *new_value = NULL;
				cil_list_item_init(&new_value);
				new_value->data = value;
				new_value->flavor = val_flavor;

				curr_value = ((struct cil_multimap_item*)curr_key->data)->values->head;

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
			} else if (curr_key->next == NULL) {
				__cil_multimap_insert_key(&curr_key, key, value, key_flavor, val_flavor);
				return SEPOL_OK;
			}
		} else {
			printf("No data in list item\n");
			return SEPOL_ERR;
		}
		curr_key = curr_key->next;
	}

	return SEPOL_OK;
}

int cil_userrole_to_policy(FILE **file_arr, struct cil_list *userroles)
{
	struct cil_list_item *current_user = NULL;

	if (userroles == NULL) {
		return SEPOL_OK;
	}
	
	current_user = userroles->head;

	while (current_user != NULL) {
		struct cil_list_item *current_role = NULL;
		if (((struct cil_multimap_item*)current_user->data)->values->head == NULL) {
			printf("No roles associated with user %s (line %d)\n",  ((struct cil_multimap_item*)current_user->data)->key->name,  ((struct cil_multimap_item*)current_user->data)->key->node->line);
			return SEPOL_ERR;
		}

		fprintf(file_arr[USERROLES], "user %s roles {", ((struct cil_multimap_item*)current_user->data)->key->name);

		current_role = ((struct cil_multimap_item*)current_user->data)->values->head;
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
	struct cil_list_item *curr_cat = NULL;

	if (cats == NULL) {
		return SEPOL_OK;
	}
	
	curr_cat = cats->head;
	while (curr_cat != NULL) {
		if (((struct cil_multimap_item*)curr_cat->data)->values->head == NULL) {
			fprintf(file_arr[CATS], "category %s;\n", ((struct cil_multimap_item*)curr_cat->data)->key->name);
		} else {
			struct cil_list_item *curr_catalias = ((struct cil_multimap_item*)curr_cat->data)->values->head;
			fprintf(file_arr[CATS], "category %s alias", ((struct cil_multimap_item*)curr_cat->data)->key->name);
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
	struct cil_list_item *curr_sens = NULL;

	if (sens == NULL) {
		return SEPOL_OK;
	}
	
	curr_sens = sens->head;
	while (curr_sens != NULL) {
		if (((struct cil_multimap_item*)curr_sens->data)->values->head == NULL) 
			fprintf(file_arr[SENS], "sensitivity %s;\n", ((struct cil_multimap_item*)curr_sens->data)->key->name);
		else {
			struct cil_list_item *curr_sensalias = ((struct cil_multimap_item*)curr_sens->data)->values->head;
			fprintf(file_arr[SENS], "sensitivity %s alias", ((struct cil_multimap_item*)curr_sens->data)->key->name);
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

	if (curr->flavor == CIL_ROOT) {
		curr = curr->cl_head;
	}

	while (curr != NULL) {
		if (curr->cl_head != NULL) {
			fprintf(file_arr[CONSTRAINS], "( ");
			rc = cil_print_constrain_expr(file_arr, curr->cl_head);
			if (rc != SEPOL_OK) {
				printf("Failed to print constrain expression\n");
				return rc;
			}
		} else {
			if (curr->flavor == CIL_CONSTRAIN_NODE) {
				fprintf(file_arr[CONSTRAINS], "%s", (char*)curr->data);
			} else {
				fprintf(file_arr[CONSTRAINS], "%s", ((struct cil_type*)curr->data)->datum.name);
			}
		}
		if (curr->next != NULL) {
			fprintf(file_arr[CONSTRAINS], " %s ", (char*)curr->parent->data);
		} else if (curr->parent->flavor != CIL_ROOT) {
			fprintf(file_arr[CONSTRAINS], " )");
		}

		curr = curr->next;
	}

	return SEPOL_OK;
}

void cil_level_to_policy(FILE **file_arr, uint32_t file_index, struct cil_level *level)
{
	struct cil_list_item *cat = NULL;
	struct cil_list_item *curr = NULL;
	struct cil_list_item *start_range = NULL;
	struct cil_list_item *end_range = NULL;
	char *sens_str = level->sens->datum.name;

	if (level->catset != NULL) {
		cat = ((struct cil_catset*)level->catset)->cat_list->head;
	} else {
		cat = level->cat_list->head;
	}

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
		} else {
			fprintf(file_arr[file_index], "%s", ((struct cil_cat*)cat->data)->datum.name);
		}

		if (cat->next != NULL) {
			fprintf(file_arr[file_index], ",");
		}

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
	fprintf(file_arr[file_index], "-");
	cil_level_to_policy(file_arr, file_index, high);
}

void cil_constrain_to_policy(FILE **file_arr, __attribute__((unused)) uint32_t file_index, struct cil_constrain *cons)
{
	struct cil_list_item *class_curr = cons->class_list->head;
	struct cil_list_item *perm_curr = cons->perm_list->head;

	if (class_curr->next == NULL) {
		fprintf(file_arr[CONSTRAINS], "%s ", ((struct cil_class*)class_curr->data)->datum.name);
	} else {
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
	default :
		printf("Unknown avrule kind: %d\n", rule->rule_kind);
		return SEPOL_ERR;
	}

	while (perm_item != NULL) {
		fprintf(file_arr[file_index], "%s ", ((struct cil_perm*)(perm_item->data))->datum.name);
		perm_item = perm_item->next;
	}
	fprintf(file_arr[file_index], "};\n");

	return SEPOL_OK;
}

int cil_typerule_to_policy(FILE **file_arr, __attribute__((unused)) uint32_t file_index, struct cil_type_rule *rule)
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
	default:
		printf("Unknown type_rule kind: %d\n", rule->rule_kind);
		return SEPOL_ERR;
	}

	return SEPOL_OK;
}

int cil_filetransition_to_policy(FILE **file_arr, uint32_t file_index, struct cil_filetransition *filetrans)
{
	char *src_str = ((struct cil_symtab_datum*)(struct cil_type*)filetrans->src)->name;
	char *exec_str = ((struct cil_symtab_datum*)(struct cil_type*)filetrans->exec)->name;
	char *proc_str = ((struct cil_symtab_datum*)(struct cil_class*)filetrans->proc)->name;
	char *dest_str = ((struct cil_symtab_datum*)(struct cil_type*)filetrans->dest)->name;

	fprintf(file_arr[file_index], "type_transition %s %s : %s %s %s;\n", src_str, exec_str, proc_str, dest_str, filetrans->path_str);
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
			
			int len1 = 0;
			int len2 = 0;
			int oplen = 0;
			cil_tree_node_init(&new);
			

			if (stack->parent->flavor != CIL_COND) {
				oper1_str = (char *)stack->parent->data;
			} else {
				struct cil_conditional *cond1 = stack->parent->data;
				if (cond1->flavor == CIL_BOOL) {
					oper1_str = ((struct cil_bool *)cond1->data)->datum.name;
				} else if (cond1->flavor == CIL_TYPE) {
					oper1_str = ((struct cil_type *)cond1->data)->datum.name;
				} else if (cond1->flavor == CIL_ROLE) {
					oper1_str = ((struct cil_role *)cond1->data)->datum.name;
				} else if (cond1->flavor == CIL_USER) {
					oper1_str = ((struct cil_user *)cond1->data)->datum.name;
				} else {
					oper1_str = cond1->str;
				}
			}

			len1 = strlen(oper1_str);

			if (cond->flavor != CIL_NOT && cond->flavor != CIL_CONS_NOT) {
				if (stack->parent->parent->flavor != CIL_COND) {
					oper2_str = (char *)stack->parent->parent->data;
				} else {
					struct cil_conditional *cond2 = stack->parent->parent->data;
					if (cond2->flavor == CIL_BOOL) {
						oper2_str = ((struct cil_bool *)cond2->data)->datum.name;
					} else if (cond2->flavor == CIL_TYPE) {
						oper2_str = ((struct cil_type *)cond2->data)->datum.name;
					} else if (cond2->flavor == CIL_ROLE) {
						oper2_str = ((struct cil_role *)cond2->data)->datum.name;
					} else if (cond2->flavor == CIL_USER) {
						oper2_str = ((struct cil_user *)cond2->data)->datum.name;
					} else {
						oper2_str = cond2->str;
					}
				}
				len2 = strlen(oper2_str);
			}
			
			oper = ((struct cil_conditional*)stack->data)->str;
			oplen = strlen(oper);

			if (cond->flavor != CIL_NOT && cond->flavor != CIL_CONS_NOT) {
				new->data = cil_malloc(len1 + len2 + oplen + 5);
				strcpy(new->data, "(");
				strncat(new->data, oper1_str, len1);
				strncat(new->data, " ", 1);
				strncat(new->data, oper, oplen);
				strncat(new->data, " ", 1);
				strncat(new->data, oper2_str, len2);
				strncat(new->data, ")", 1);
			} else {
				new->data = cil_malloc(len1 + len2 + oplen + 4);
				strcpy(new->data, "(");
				strncat(new->data, oper, oplen);
				strncat(new->data, " ", 1);
				strncat(new->data, oper1_str, len1);
				strncat(new->data, ")", 1);
			}
		
			new->flavor = CIL_AST_STR;
			new->cl_head = stack->cl_head;

			if (cond->flavor != CIL_NOT && cond->flavor != CIL_CONS_NOT) {
				new->parent = stack->parent->parent->parent;
			} else {
				new->parent = stack->parent->parent;
			}

			if (cond->flavor != CIL_NOT && cond->flavor != CIL_CONS_NOT) {
				if (stack->parent->parent->parent != NULL) {
					stack->parent->parent->parent->cl_head = new;
				}
			} else {
				if (stack->parent->parent != NULL) {
					stack->parent->parent->cl_head = new;
				}
			}

			if (stack->cl_head != NULL) {
				stack->cl_head->parent = new;
			}

			if (cond->flavor != CIL_NOT && cond->flavor != CIL_CONS_NOT) {
				if (stack->parent->parent != NULL) {
					cil_tree_node_destroy(&stack->parent->parent);
				}
			}
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
			struct cil_tree_node *bnode = NULL;
			policy = cil_malloc(strlen(bname) + 3);
			strcpy(policy, "(");
			strncat(policy, bname, strlen(bname));
			strncat(policy, ")", 1);

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


int __cil_booleanif_node_helper(struct cil_tree_node *node, __attribute__((unused)) uint32_t *finished, void *extra_args)
{
	int rc = SEPOL_ERR;
	struct cil_args_booleanif *args;
	FILE **file_arr;
	uint32_t *file_index;

	args = extra_args;
	file_arr = args->file_arr;
	file_index = args->file_index;

	switch (node->flavor) {
	case CIL_AVRULE:
		rc = cil_avrule_to_policy(file_arr, *file_index, (struct cil_avrule*)node->data);
		if (rc != SEPOL_OK) {
			printf("cil_avrule_to_policy failed, rc: %d\n", rc);
			return rc;
		}
		break;
	case CIL_TYPE_RULE:
		rc = cil_typerule_to_policy(file_arr, *file_index, (struct cil_type_rule*)node->data);
		if (rc != SEPOL_OK) {
			printf("cil_typerule_to_policy failed, rc: %d\n", rc);
			return rc;
		}
		break;
	case CIL_ELSE:
		fprintf(file_arr[*file_index], "else {\n");
		break;
	default:
		return SEPOL_ERR;
	}

	return SEPOL_OK;
}

int __cil_booleanif_reverse_helper(struct cil_tree_node *node, void *extra_args)
{
	struct cil_args_booleanif *args;
	FILE **file_arr;
	uint32_t *file_index;

	args = extra_args;
	file_arr = args->file_arr;
	file_index = args->file_index;

	if (node->flavor == CIL_ELSE) {
		fprintf(file_arr[*file_index], "}\n");
	}
	
	return SEPOL_OK;
}

int cil_booleanif_to_policy(FILE **file_arr, uint32_t file_index, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	struct cil_booleanif *bif = node->data;
	struct cil_tree_node *stack = bif->expr_stack;
	struct cil_args_booleanif extra_args;

	extra_args.file_arr = file_arr;
	extra_args.file_index = &file_index;;

	fprintf(file_arr[file_index], "if ");

	rc = cil_expr_stack_to_policy(file_arr, file_index, stack);
	if (rc != SEPOL_OK) {
		printf("cil_expr_stack_to_policy failed, rc: %d\n", rc);
		return rc;
	}

	bif->expr_stack = NULL;

	fprintf(file_arr[file_index], "{\n");

	rc = cil_tree_walk(node, __cil_booleanif_node_helper, __cil_booleanif_reverse_helper, NULL, &extra_args);
	if (rc != SEPOL_OK) {
		printf("Failed to write booleanif content to file, rc: %d\n", rc);
		return rc;
	}

	fprintf(file_arr[file_index], "}\n");

	return SEPOL_OK;
}

int cil_name_to_policy(FILE **file_arr, struct cil_tree_node *current) 
{
	char *name = ((struct cil_symtab_datum*)current->data)->name;
	uint32_t flavor = current->flavor;
	int rc = SEPOL_ERR;

	switch(flavor) {
	case CIL_ATTR:
		fprintf(file_arr[ATTRTYPES], "attribute %s;\n", name);
		break;
	case CIL_TYPE:
		fprintf(file_arr[ATTRTYPES], "type %s;\n", name);
		break;
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
	case CIL_TYPEBOUNDS: {
		struct cil_typebounds *typebnds = (struct cil_typebounds*)current->data;
		char *parent_str = ((struct cil_symtab_datum*)typebnds->parent)->name;
		char *child_str = ((struct cil_symtab_datum*)typebnds->child)->name;
		fprintf(file_arr[ALLOWS], "typebounds %s %s;\n", parent_str, child_str);
	}
	case CIL_TYPEPERMISSIVE: {
		struct cil_typepermissive *typeperm = (struct cil_typepermissive*)current->data;
		fprintf(file_arr[ATTRTYPES], "permissive %s;\n", ((struct cil_symtab_datum*)typeperm->type)->name);
		break;
	}
	case CIL_ROLE:
		fprintf(file_arr[ATTRTYPES], "role %s;\n", name);
		break;
	case CIL_BOOL: {
		char *boolean = ((struct cil_bool*)current->data)->value ? "true" : "false";
		fprintf(file_arr[ATTRTYPES], "bool %s %s;\n", name, boolean);
		break;
	}
	case CIL_COMMON:
		if (current->cl_head != NULL) {
			current = current->cl_head;
			fprintf(file_arr[COMMONS], "common %s { ", name);
		} else {
			printf("No permissions given\n");
			return SEPOL_ERR;
		}

		while (current != NULL) {
			if (current->flavor == CIL_PERM) {
				fprintf(file_arr[COMMONS], "%s ", ((struct cil_symtab_datum*)current->data)->name);
			} else {
				printf("Improper data type found in common permissions: %d\n", current->flavor);
				return SEPOL_ERR;
			}
			current = current->next;
		}
		fprintf(file_arr[COMMONS], "};\n");

		return SEPOL_DONE;
	case CIL_CLASS:
		fprintf(file_arr[CLASS_DECL], "class %s\n", ((struct cil_class*)current->data)->datum.name);

		if (current->cl_head != NULL) {
			fprintf(file_arr[CLASSES], "class %s ", ((struct cil_class*)(current->data))->datum.name);
		} else if (((struct cil_class*)current->data)->common == NULL) {
			printf("No permissions given\n");
			return SEPOL_ERR;
		}

		if (((struct cil_class*)current->data)->common != NULL) {
			fprintf(file_arr[CLASSES], "inherits %s ", ((struct cil_class*)current->data)->common->datum.name);
		}

		fprintf(file_arr[CLASSES], "{ ");

		if (current->cl_head != NULL) {
			current = current->cl_head;
		}

		while (current != NULL) {
			if (current->flavor == CIL_PERM) {
				fprintf(file_arr[CLASSES], "%s ", ((struct cil_symtab_datum*)current->data)->name);
			} else {
				printf("Improper data type found in class permissions: %d\n", current->flavor);
				return SEPOL_ERR;
			}
			current = current->next;
		}
		fprintf(file_arr[CLASSES], "};\n");

		return SEPOL_DONE;
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
	case CIL_FILETRANSITION: {
		struct cil_filetransition *filetrans = (struct cil_filetransition*)current->data;
		rc = cil_filetransition_to_policy(file_arr, ALLOWS, filetrans);
		if (rc != SEPOL_OK) {
			printf("Failed to write filetransition to policy\n");
			return rc;
		}
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
	case CIL_ROLETYPE: {
		struct cil_roletype *roletype = (struct cil_roletype*)current->data;
		char *role_str = ((struct cil_symtab_datum*)(struct cil_role*)roletype->role)->name;
		char *type_str = ((struct cil_symtab_datum*)(struct cil_type*)roletype->type)->name;

		fprintf(file_arr[ALIASES], "role %s types %s\n", role_str, type_str);
		break;
	}
	case CIL_ROLEDOMINANCE: {
		struct cil_roledominance *roledom = (struct cil_roledominance*)current->data;
		char *role_str = ((struct cil_symtab_datum*)(struct cil_role*)roledom->role)->name;
		char *domed_str = ((struct cil_symtab_datum*)(struct cil_role*)roledom->domed)->name;
		fprintf(file_arr[ATTRTYPES], "dominance { role %s { role %s; } }\n", role_str, domed_str);
		break;
	}
	case CIL_LEVEL:
		fprintf(file_arr[LEVELS], "level ");
		cil_level_to_policy(file_arr, LEVELS, (struct cil_level*)current->data);
			fprintf(file_arr[LEVELS], ";\n");
			break;
	case CIL_CONSTRAIN:
		fprintf(file_arr[CONSTRAINS], "constrain ");
		cil_constrain_to_policy(file_arr, CONSTRAINS, (struct cil_constrain*)current->data);
		break;
	case CIL_MLSCONSTRAIN:
		fprintf(file_arr[CONSTRAINS], "mlsconstrain ");
		cil_constrain_to_policy(file_arr, CONSTRAINS, (struct cil_constrain*)current->data);
		break;
	case CIL_SID:
		fprintf(file_arr[ISIDS], "sid %s\n", name);
		break;
	case CIL_SIDCONTEXT: {
		struct cil_sidcontext *sidcon = (struct cil_sidcontext*)current->data;
		fprintf(file_arr[SIDS], "sid %s ", ((struct cil_symtab_datum*)(struct sid*)sidcon->sid)->name);
		cil_context_to_policy(file_arr, SIDS, sidcon->context);
		fprintf(file_arr[SIDS], "\n");
		break;
	}
	case CIL_POLICYCAP:
		fprintf(file_arr[ATTRTYPES], "policycap %s;\n", name);
		break;
	default:
		break;
	}

	return SEPOL_OK;
}

int __cil_gen_policy_node_helper(struct cil_tree_node *node, uint32_t *finished, void *extra_args)
{
	int rc = SEPOL_ERR;
	struct cil_args_genpolicy *args = NULL;
	struct cil_list *users = NULL;
	struct cil_list *sens = NULL;
	struct cil_list *cats = NULL;
	FILE **file_arr = NULL;

	if (extra_args == NULL) {
		return SEPOL_ERR;
	}

	*finished = CIL_TREE_SKIP_NOTHING;

	args = extra_args;
	users = args->users;
	sens = args->sens;
	cats = args->cats;
	file_arr = args->file_arr;

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
	} else {
		switch (node->flavor) {
		case CIL_USER:
			cil_multimap_insert(users, node->data, NULL, CIL_USERROLE, 0);
			break;
		case CIL_USERROLE:
			cil_multimap_insert(users, &((struct cil_userrole*)node->data)->user->datum, &((struct cil_userrole*)node->data)->role->datum, CIL_USERROLE, CIL_ROLE);
			break;
		case CIL_CATALIAS:
			cil_multimap_insert(cats, &((struct cil_catalias*)node->data)->cat->datum, node->data, CIL_CAT, CIL_CATALIAS);
			break;
		case CIL_SENSALIAS:
			cil_multimap_insert(sens, &((struct cil_sensalias*)node->data)->sens->datum, node->data, CIL_SENS, CIL_SENSALIAS);
			break;
		default:
			rc = cil_name_to_policy(file_arr, node);
			if (rc != SEPOL_OK && rc != SEPOL_DONE) {
				printf("Error converting node to policy %d\n", rc);
				return SEPOL_ERR;
			}
			break;
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

	struct cil_list *users = NULL;
	struct cil_list *cats = NULL;
	struct cil_list *sens = NULL;
	struct cil_args_genpolicy extra_args;

	cil_list_init(&users);
	cil_list_init(&cats);
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

	extra_args.users = users;
	extra_args.sens = sens;
	extra_args.cats = cats;
	extra_args.file_arr= file_arr;

	rc = cil_tree_walk(curr, __cil_gen_policy_node_helper, NULL, NULL, &extra_args);
	if (rc != SEPOL_OK) {
		printf("Error walking tree\n");
		return rc;
	}

	qsort(db->netifcon->array, db->netifcon->count, sizeof(db->netifcon->array), cil_netifcon_compare);
	rc = cil_netifcon_to_policy(file_arr, db->netifcon);
	if (rc != SEPOL_OK) {
		printf("Error creating policy.conf\n");
		return rc;
	}

	qsort(db->genfscon->array, db->genfscon->count, sizeof(db->genfscon->array), cil_genfscon_compare);
	rc = cil_genfscon_to_policy(file_arr, db->genfscon);
	if (rc != SEPOL_OK) {
		printf("Error creating policy.conf\n");
		return rc;
	}

	qsort(db->portcon->array, db->portcon->count, sizeof(db->portcon->array), cil_portcon_compare);
	rc = cil_portcon_to_policy(file_arr, db->portcon);
	if (rc != SEPOL_OK) {
		printf("Error creating policy.conf\n");
		return rc;
	}

	qsort(db->nodecon->array, db->nodecon->count, sizeof(db->nodecon->array), cil_nodecon_compare);
	rc = cil_nodecon_to_policy(file_arr, db->nodecon);
	if (rc != SEPOL_OK) {
		printf("Error creating policy.conf\n");
		return rc;
	}

	qsort(db->fsuse->array, db->fsuse->count, sizeof(db->fsuse->array), cil_fsuse_compare);
	rc = cil_fsuse_to_policy(file_arr, db->fsuse);
	if (rc != SEPOL_OK) {
		printf("Error creating policy.conf\n");
		return rc;
	}

	qsort(db->filecon->array, db->filecon->count, sizeof(db->filecon->array), cil_filecon_compare);
	rc = cil_filecon_to_policy(db->filecon);
	if (rc != SEPOL_OK) {
		printf("Error creating policy.conf\n");
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
