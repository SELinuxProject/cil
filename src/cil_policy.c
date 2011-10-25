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

#include <sepol/policydb/conditional.h>
#include <sepol/errcodes.h>

#include "cil.h"
#include "cil_log.h"
#include "cil_mem.h"
#include "cil_tree.h"
#include "cil_list.h"
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
#define TYPEATTRTYPES			9
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


int cil_expr_stack_to_policy(FILE **file_arr, uint32_t file_index, struct cil_list *stack);

int cil_combine_policy(FILE **file_arr, FILE *policy_file)
{
	char temp[BUFFER];
	int i, rc, rc_read, rc_write;

	for(i=0; i<NUM_POLICY_FILES; i++) {
		fseek(file_arr[i], 0, SEEK_SET);
		while (!feof(file_arr[i])) {
			rc_read = fread(temp, 1, BUFFER, file_arr[i]);
			if (rc_read == 0 && ferror(file_arr[i])) {
				cil_log(CIL_ERR, "Error reading temp policy file\n");
				return SEPOL_ERR;
			}
			rc_write = 0;
			while (rc_read > rc_write) {
				rc = fwrite(temp+rc_write, 1, rc_read-rc_write, policy_file);
				rc_write += rc;
				if (rc == 0 && ferror(file_arr[i])) {
					cil_log(CIL_ERR, "Error writing to policy.conf\n");
					return SEPOL_ERR;
				}
			}
		}
	}

	return SEPOL_OK;
}

int cil_portcon_to_policy(FILE **file_arr, struct cil_sort *sort)
{
	uint32_t i = 0;

	for (i=0; i<sort->count; i++) {
		struct cil_portcon *portcon = (struct cil_portcon*)sort->array[i];
		fprintf(file_arr[NETIFCONS], "portcon ");
		if (portcon->proto == CIL_PROTOCOL_UDP) {
			fprintf(file_arr[NETIFCONS], "udp ");
		} else if (portcon->proto == CIL_PROTOCOL_TCP) {
			fprintf(file_arr[NETIFCONS], "tcp ");
		}
		fprintf(file_arr[NETIFCONS], "%d ", portcon->port_low);
		fprintf(file_arr[NETIFCONS], "%d ", portcon->port_high);
		cil_context_to_policy(file_arr, NETIFCONS, portcon->context);
		fprintf(file_arr[NETIFCONS], ";\n");
	}

	return SEPOL_OK;
}

int cil_genfscon_to_policy(FILE **file_arr, struct cil_sort *sort)
{
	uint32_t i = 0;

	for (i=0; i<sort->count; i++) {
		struct cil_genfscon *genfscon = (struct cil_genfscon*)sort->array[i];
		fprintf(file_arr[NETIFCONS], "genfscon %s ", genfscon->fs_str);
		fprintf(file_arr[NETIFCONS], "%s ", genfscon->path_str);
		cil_context_to_policy(file_arr, NETIFCONS, genfscon->context);
		fprintf(file_arr[NETIFCONS], ";\n");
	}

	return SEPOL_OK;
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

int cil_nodecon_to_policy(FILE **file_arr, struct cil_sort *sort)
{
	uint32_t i = 0;
	int rc = SEPOL_ERR;

	for (i=0; i<sort->count; i++) {
		struct cil_nodecon *nodecon = (struct cil_nodecon*)sort->array[i];
		char *buf = NULL;
		errno = 0;
		if (nodecon->addr->family == AF_INET) {
			buf = cil_malloc(INET_ADDRSTRLEN);
			inet_ntop(nodecon->addr->family, &nodecon->addr->ip.v4, buf, INET_ADDRSTRLEN);
		} else if (nodecon->addr->family == AF_INET6) {
			buf = cil_malloc(INET6_ADDRSTRLEN);
			inet_ntop(nodecon->addr->family, &nodecon->addr->ip.v6, buf, INET6_ADDRSTRLEN);
		}

		if (errno != 0) {
			cil_log(CIL_INFO, "Failed to convert ip address to string\n");
			rc = SEPOL_ERR;
			goto exit;
		}

		fprintf(file_arr[NETIFCONS], "nodecon %s ", buf);
		free(buf);

		if (nodecon->mask->family == AF_INET) {
			buf = cil_malloc(INET_ADDRSTRLEN);
			inet_ntop(nodecon->mask->family, &nodecon->mask->ip.v4, buf, INET_ADDRSTRLEN);
		} else if (nodecon->mask->family == AF_INET6) {
			buf = cil_malloc(INET6_ADDRSTRLEN);
			inet_ntop(nodecon->mask->family, &nodecon->mask->ip.v6, buf, INET6_ADDRSTRLEN);
		}

		if (errno != 0) {
			cil_log(CIL_INFO, "Failed to convert mask to string\n");
			rc = SEPOL_ERR;
			goto exit;
		}

		fprintf(file_arr[NETIFCONS], "%s ", buf);
		free(buf);

		cil_context_to_policy(file_arr, NETIFCONS, nodecon->context);
		fprintf(file_arr[NETIFCONS], ";\n");
	}

	return SEPOL_OK;

exit:
	return rc;
}


int cil_pirqcon_to_policy(FILE **file_arr, struct cil_sort *sort)
{
	uint32_t i = 0;

	for (i = 0; i < sort->count; i++) {
		struct cil_pirqcon *pirqcon = (struct cil_pirqcon*)sort->array[i];
		fprintf(file_arr[NETIFCONS], "pirqcon %d ", pirqcon->pirq);
		cil_context_to_policy(file_arr, NETIFCONS, pirqcon->context);
		fprintf(file_arr[NETIFCONS], ";\n");
	}

	return SEPOL_OK;
}
int cil_iomemcon_to_policy(FILE **file_arr, struct cil_sort *sort)
{
	uint32_t i = 0;

	for (i = 0; i < sort->count; i++) {
		struct cil_iomemcon *iomemcon = (struct cil_iomemcon*)sort->array[i];
		fprintf(file_arr[NETIFCONS], "iomemcon %d-%d ", iomemcon->iomem_low, iomemcon->iomem_high);
		cil_context_to_policy(file_arr, NETIFCONS, iomemcon->context);
		fprintf(file_arr[NETIFCONS], ";\n");
	}

	return SEPOL_OK;
}

int cil_ioportcon_to_policy(FILE **file_arr, struct cil_sort *sort)
{
	uint32_t i = 0;

	for (i = 0; i < sort->count; i++) {
		struct cil_ioportcon *ioportcon = (struct cil_ioportcon*)sort->array[i];
		fprintf(file_arr[NETIFCONS], "ioportcon %d-%d ", ioportcon->ioport_low, ioportcon->ioport_high);
		cil_context_to_policy(file_arr, NETIFCONS, ioportcon->context);
		fprintf(file_arr[NETIFCONS], ";\n");
	}

	return SEPOL_OK;
}

int cil_pcidevicecon_to_policy(FILE **file_arr, struct cil_sort *sort)
{
	uint32_t i = 0;

	for (i = 0; i < sort->count; i++) {
		struct cil_pcidevicecon *pcidevicecon = (struct cil_pcidevicecon*)sort->array[i];
		fprintf(file_arr[NETIFCONS], "pcidevicecon %d ", pcidevicecon->dev);
		cil_context_to_policy(file_arr, NETIFCONS, pcidevicecon->context);
		fprintf(file_arr[NETIFCONS], ";\n");
	}

	return SEPOL_OK;
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
			cil_log(CIL_INFO, "No data in list item\n");
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
			cil_log(CIL_INFO, "No roles associated with user %s (line %d)\n",  ((struct cil_multimap_item*)current_user->data)->key->name,  ((struct cil_multimap_item*)current_user->data)->key->node->line);
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

void cil_catrange_to_policy(FILE **file_arr, uint32_t file_index, struct cil_catrange *catrange)
{
	fprintf(file_arr[file_index], "%s.%s", catrange->cat_low->datum.name, catrange->cat_high->datum.name);
}

void cil_catset_to_policy(FILE **file_arr, uint32_t file_index, struct cil_catset *catset)
{
	struct cil_list_item *cat_item;

	for (cat_item = catset->cat_list->head; cat_item != NULL; cat_item = cat_item->next) {
		switch (cat_item->flavor) {
		case CIL_CATRANGE: {
			cil_catrange_to_policy(file_arr, file_index, cat_item->data);
			break;
		}
		case CIL_CAT: {
			struct cil_cat *cat = cat_item->data;
			fprintf(file_arr[file_index], "%s", cat->datum.name);
		}
		default:
			break;
		}

		if (cat_item->next != NULL) {
			fprintf(file_arr[file_index], ",");
		}
	}
}

void cil_level_to_policy(FILE **file_arr, uint32_t file_index, struct cil_level *level)
{
	char *sens_str = level->sens->datum.name;

	fprintf(file_arr[file_index], "%s:", sens_str);
	cil_catset_to_policy(file_arr, file_index, level->catset);
}

void cil_levelrange_to_policy(FILE **file_arr, uint32_t file_index, struct cil_levelrange *lvlrange)
{
	struct cil_level *low = lvlrange->low;
	struct cil_level *high = lvlrange->high;

	cil_level_to_policy(file_arr, file_index, low);
	fprintf(file_arr[file_index], "-");
	cil_level_to_policy(file_arr, file_index, high);
}

void cil_context_to_policy(FILE **file_arr, uint32_t file_index, struct cil_context *context)
{
	char *user_str = ((struct cil_symtab_datum*)context->user)->name;
	char *role_str = ((struct cil_symtab_datum*)context->role)->name;
	char *type_str = ((struct cil_symtab_datum*)context->type)->name;
	struct cil_levelrange *lvlrange = context->range;

	fprintf(file_arr[file_index], "%s:%s:%s:", user_str, role_str, type_str);
	cil_levelrange_to_policy(file_arr, file_index, lvlrange);
}

void cil_constrain_to_policy(FILE **file_arr, __attribute__((unused)) uint32_t file_index, struct cil_constrain *cons, enum cil_flavor flavor)
{
	struct cil_list_item *curr_cmp = NULL;
	struct cil_list_item *curr_cps = NULL;
	char *obj_str = NULL;
	struct cil_list_item *perm = NULL;
	char *statement = NULL;

	if (flavor == CIL_CONSTRAIN) {
		statement = CIL_KEY_CONSTRAIN;
	} else if (flavor == CIL_MLSCONSTRAIN) {
		statement = CIL_KEY_MLSCONSTRAIN;
	}

	if (cons->classpermset->flavor == CIL_CLASS) {
		fprintf(file_arr[CONSTRAINS], "%s", statement);
		fprintf(file_arr[CONSTRAINS], " %s {", ((struct cil_class*)cons->classpermset->class)->datum.name);

		perm = cons->classpermset->perms->head;
		while (perm != NULL) {
			fprintf(file_arr[CONSTRAINS], " %s", ((struct cil_perm*)(perm->data))->datum.name);
			perm = perm->next;
		}
		fprintf(file_arr[CONSTRAINS], " };\n\t");

		cil_expr_stack_to_policy(file_arr, CONSTRAINS, cons->expr);
		fprintf(file_arr[CONSTRAINS], ";\n");

	} else if (cons->classpermset->flavor == CIL_CLASSMAP) {
		curr_cmp = cons->classpermset->perms->head;
		while (curr_cmp != NULL) {
			curr_cps = ((struct cil_classmap_perm*)curr_cmp->data)->classperms->head;
			while(curr_cps != NULL) {
				fprintf(file_arr[CONSTRAINS], "%s", statement);
				obj_str = ((struct cil_class*)((struct cil_classpermset*)curr_cps->data)->class)->datum.name;
				fprintf(file_arr[CONSTRAINS], " %s {", obj_str);

				perm = ((struct cil_classpermset*)curr_cps->data)->perms->head;

				while (perm != NULL) {
					fprintf(file_arr[CONSTRAINS], " %s", ((struct cil_perm*)(perm->data))->datum.name);
					perm = perm->next;
				}
				fprintf(file_arr[CONSTRAINS], " };\n\t");
				cil_expr_stack_to_policy(file_arr, CONSTRAINS, cons->expr);
				fprintf(file_arr[CONSTRAINS], ";\n");

				curr_cps = curr_cps->next;
			}

			curr_cmp = curr_cmp->next;
		}
	}
}

int cil_avrule_to_policy(FILE **file_arr, uint32_t file_index, struct cil_avrule *rule)
{
	char *src_str = ((struct cil_symtab_datum*)(struct cil_type*)rule->src)->name;
	char *tgt_str = ((struct cil_symtab_datum*)(struct cil_type*)rule->tgt)->name;
	char *obj_str = NULL;
	struct cil_list *classperms = NULL;
	struct cil_list_item *new = NULL;
	struct cil_list_item *curr_cmp = NULL;
	struct cil_list_item *curr_cps = NULL;
	struct cil_list_item *tail = NULL;
	struct cil_list_item *perm = NULL;

	cil_list_init(&classperms);

	if (rule->classpermset->flavor == CIL_CLASS) {
		cil_list_item_init(&new);
		new->data = rule->classpermset;
		new->flavor = CIL_CLASSPERMSET;
		classperms->head = new;
	} else if (rule->classpermset->flavor == CIL_CLASSMAP) {
		curr_cmp = rule->classpermset->perms->head;
		while (curr_cmp != NULL) {
			curr_cps = ((struct cil_classmap_perm*)curr_cmp->data)->classperms->head;
			while(curr_cps != NULL) {
				cil_list_item_init(&new);
				new->data = curr_cps->data;
				new->flavor = curr_cps->flavor;

				if (classperms->head == NULL) {
					classperms->head = new;
				} else {
					tail->next = new;
				}
				tail = new;

				curr_cps = curr_cps->next;
			}

			curr_cmp = curr_cmp->next;
		}
	}

	curr_cps = classperms->head;

	while (curr_cps != NULL) {

		switch (rule->rule_kind) {
		case CIL_AVRULE_ALLOWED:
			fprintf(file_arr[file_index], "allow");
			break;
		case CIL_AVRULE_AUDITALLOW:
			fprintf(file_arr[file_index], "auditallow");
			break;
		case CIL_AVRULE_DONTAUDIT:
			fprintf(file_arr[file_index], "dontaudit");
			break;
		case CIL_AVRULE_NEVERALLOW:
			fprintf(file_arr[file_index], "neverallow");
			break;
		default :
			cil_log(CIL_INFO, "Unknown avrule kind: %d\n", rule->rule_kind);
			return SEPOL_ERR;
		}

		fprintf(file_arr[file_index], " %s %s:", src_str, tgt_str);

		obj_str = ((struct cil_class*)((struct cil_classpermset*)curr_cps->data)->class)->datum.name;
		fprintf(file_arr[file_index], " %s {", obj_str);

		perm = ((struct cil_classpermset*)curr_cps->data)->perms->head;

		while (perm != NULL) {
			fprintf(file_arr[file_index], " %s", ((struct cil_perm*)(perm->data))->datum.name);
			perm = perm->next;
		}
		fprintf(file_arr[file_index], " };\n");

		curr_cps = curr_cps->next;
	}

	cil_list_destroy(&classperms, 0);

	return SEPOL_OK;
}

int cil_typerule_to_policy(FILE **file_arr, __attribute__((unused)) uint32_t file_index, struct cil_type_rule *rule)
{
	char *src_str = ((struct cil_symtab_datum*)rule->src)->name;
	char *tgt_str = ((struct cil_symtab_datum*)rule->tgt)->name;
	char *obj_str = ((struct cil_symtab_datum*)rule->obj)->name;
	char *result_str = ((struct cil_symtab_datum*)rule->result)->name;
		
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
		cil_log(CIL_INFO, "Unknown type_rule kind: %d\n", rule->rule_kind);
		return SEPOL_ERR;
	}

	return SEPOL_OK;
}

int cil_filetransition_to_policy(FILE **file_arr, uint32_t file_index, struct cil_filetransition *filetrans)
{
	char *src_str = ((struct cil_symtab_datum*)filetrans->src)->name;
	char *exec_str = ((struct cil_symtab_datum*)filetrans->exec)->name;
	char *proc_str = ((struct cil_symtab_datum*)filetrans->proc)->name;
	char *dest_str = ((struct cil_symtab_datum*)filetrans->dest)->name;

	fprintf(file_arr[file_index], "type_transition %s %s : %s %s %s;\n", src_str, exec_str, proc_str, dest_str, filetrans->path_str);
	return SEPOL_OK;
}

int cil_expr_stack_to_policy(FILE **file_arr, uint32_t file_index, struct cil_list *stack)
{
	int rc = SEPOL_ERR;
	struct cil_conditional *cond = NULL;
	struct cil_list_item *curr = stack->head;
	char *str_stack[COND_EXPR_MAXDEPTH] = {};
	char *expr_str = NULL;
	char *oper_str = NULL;
	int pos = 0;
	int len = 0;
	int i;

	while (curr != NULL) {
		cond = curr->data;
		if ((cond->flavor == CIL_AND) || (cond->flavor == CIL_OR)
		|| (cond->flavor == CIL_XOR) || (cond->flavor == CIL_NOT)
		|| (cond->flavor == CIL_EQ) || (cond->flavor == CIL_NEQ)
		|| (cond->flavor == CIL_CONS_DOM) || (cond->flavor == CIL_CONS_DOMBY)
		|| (cond->flavor == CIL_CONS_INCOMP)) {

			oper_str = cond->str;
			if (cond->flavor != CIL_NOT) {
				if (pos <= 1) {
					rc = SEPOL_ERR;
					goto exit;
				}

				len = strlen(str_stack[pos - 1]) + strlen(str_stack[pos - 2]) + strlen(oper_str) + 5;
				expr_str = cil_malloc(len);
				rc = snprintf(expr_str, len, "(%s %s %s)", str_stack[pos - 1], oper_str, str_stack[pos - 2]);
				if (rc < 0) {
					free(expr_str);
					goto exit;
				}
				free(str_stack[pos - 2]);
				free(str_stack[pos - 1]);
				str_stack[pos - 2] = expr_str;
				str_stack[pos - 1] = 0;
				pos--;
			} else {
				if (pos == 0) {
					rc = SEPOL_ERR;
					goto exit;
				}

				len = strlen(str_stack[pos - 1]) + strlen(oper_str) + 4;
				expr_str = cil_malloc(len);
				rc = snprintf(expr_str, len, "(%s %s)", oper_str, str_stack[pos - 1]);
				if (rc < 0) {
					rc = SEPOL_ERR;
					goto exit;
				}
				free(str_stack[pos - 1]);
				str_stack[pos - 1] = expr_str;
			}
		} else {
			if (pos >= COND_EXPR_MAXDEPTH) {
				rc = SEPOL_ERR;
				goto exit;
			}

			if (cond->flavor == CIL_BOOL || (cond->flavor == CIL_TYPE)
				|| (cond->flavor == CIL_ROLE) || (cond->flavor == CIL_USER)) {

				oper_str = ((struct cil_symtab_datum *)cond->data)->name;
			} else {
				oper_str = cond->str;
			}
			str_stack[pos] = cil_strdup(oper_str);
			pos++;
		}
		curr = curr->next;
	}
	fprintf(file_arr[file_index], "%s", str_stack[0]);
	free(str_stack[0]);

	return SEPOL_OK;

exit:
	for (i = 0; i < pos; i++) {
		free(str_stack[i]);
	}
	return rc;
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
			cil_log(CIL_INFO, "cil_avrule_to_policy failed, rc: %d\n", rc);
			return rc;
		}
		break;
	case CIL_TYPE_RULE:
		rc = cil_typerule_to_policy(file_arr, *file_index, (struct cil_type_rule*)node->data);
		if (rc != SEPOL_OK) {
			cil_log(CIL_INFO, "cil_typerule_to_policy failed, rc: %d\n", rc);
			return rc;
		}
		break;
	case CIL_FALSE:
		fprintf(file_arr[*file_index], "else {\n");
		break;
	case CIL_TRUE:
		break;
	default:
		return SEPOL_ERR;
	}

	return SEPOL_OK;
}

int __cil_booleanif_last_child_helper(struct cil_tree_node *node, void *extra_args)
{
	struct cil_args_booleanif *args;
	FILE **file_arr;
	uint32_t *file_index;

	args = extra_args;
	file_arr = args->file_arr;
	file_index = args->file_index;

	if (node->parent->flavor == CIL_FALSE) {
		fprintf(file_arr[*file_index], "}\n");
	}
	
	return SEPOL_OK;
}

int cil_booleanif_to_policy(FILE **file_arr, uint32_t file_index, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	struct cil_booleanif *bif = node->data;
	struct cil_list *stack = bif->expr_stack;
	struct cil_args_booleanif extra_args;

	extra_args.file_arr = file_arr;
	extra_args.file_index = &file_index;;

	fprintf(file_arr[file_index], "if ");

	rc = cil_expr_stack_to_policy(file_arr, file_index, stack);
	if (rc != SEPOL_OK) {
		cil_log(CIL_INFO, "cil_expr_stack_to_policy failed, rc: %d\n", rc);
		return rc;
	}


	fprintf(file_arr[file_index], "{\n");
	if (bif->condtrue != NULL) {
		rc = cil_tree_walk(bif->condtrue, __cil_booleanif_node_helper, __cil_booleanif_last_child_helper, NULL, &extra_args);
		if (rc != SEPOL_OK) {
			cil_log(CIL_INFO, "Failed to write booleanif content to file, rc: %d\n", rc);
			return rc;
		}
	}
	fprintf(file_arr[file_index], "}\n");

	if (bif->condfalse != NULL) {
		fprintf(file_arr[file_index], "else {\n");
		rc = cil_tree_walk(bif->condfalse, __cil_booleanif_node_helper, __cil_booleanif_last_child_helper, NULL, &extra_args);
		if (rc != SEPOL_OK) {
			cil_log(CIL_INFO, "Failed to write booleanif false content to file, rc: %d\n", rc);
			return rc;
		}
		fprintf(file_arr[file_index], "}\n");
	}

	return SEPOL_OK;
}

int cil_name_to_policy(FILE **file_arr, struct cil_tree_node *current) 
{
	uint32_t flavor = current->flavor;
	int rc = SEPOL_ERR;

	switch(flavor) {
	case CIL_TYPEATTRIBUTE:
		fprintf(file_arr[TYPEATTRTYPES], "attribute %s;\n", ((struct cil_symtab_datum*)current->data)->name);
		break;
	case CIL_TYPE:
		fprintf(file_arr[TYPEATTRTYPES], "type %s;\n", ((struct cil_symtab_datum*)current->data)->name);
		break;
	case CIL_TYPEALIAS: {
		struct cil_typealias *alias = (struct cil_typealias*)current->data;
		fprintf(file_arr[ALIASES], "typealias %s alias %s;\n", ((struct cil_symtab_datum*)alias->type)->name, ((struct cil_symtab_datum*)current->data)->name);
		break;
	}
	case CIL_TYPEBOUNDS: {
		struct cil_typebounds *typebnds = (struct cil_typebounds*)current->data;
		fprintf(file_arr[ALLOWS], "typebounds %s %s;\n", typebnds->type_str, typebnds->bounds_str);
		break;
	}
	case CIL_TYPEPERMISSIVE: {
		struct cil_typepermissive *typeperm = (struct cil_typepermissive*)current->data;
		fprintf(file_arr[TYPEATTRTYPES], "permissive %s;\n", ((struct cil_symtab_datum*)typeperm->type)->name);
		break;
	}
	case CIL_ROLE:
		fprintf(file_arr[TYPEATTRTYPES], "role %s;\n", ((struct cil_symtab_datum*)current->data)->name);
		break;
	case CIL_BOOL: {
		char *boolean = ((struct cil_bool*)current->data)->value ? "true" : "false";
		fprintf(file_arr[TYPEATTRTYPES], "bool %s %s;\n", ((struct cil_symtab_datum*)current->data)->name, boolean);
		break;
	}
	case CIL_COMMON:
		fprintf(file_arr[COMMONS], "common %s", ((struct cil_symtab_datum*)current->data)->name);

		if (current->cl_head != NULL) {
			current = current->cl_head;
			fprintf(file_arr[COMMONS], " {");
		} else {
			cil_log(CIL_INFO, "No permissions given\n");
			return SEPOL_ERR;
		}

		while (current != NULL) {
			if (current->flavor == CIL_PERM) {
				fprintf(file_arr[COMMONS], "%s ", ((struct cil_symtab_datum*)current->data)->name);
			} else {
				cil_log(CIL_INFO, "Improper data type found in common permissions: %d\n", current->flavor);
				return SEPOL_ERR;
			}
			current = current->next;
		}
		fprintf(file_arr[COMMONS], "}\n");

		return SEPOL_DONE;
	case CIL_CLASS:
		fprintf(file_arr[CLASS_DECL], "class %s\n", ((struct cil_class*)current->data)->datum.name);

		fprintf(file_arr[CLASSES], "class %s ", ((struct cil_class*)(current->data))->datum.name);

		if (((struct cil_class*)current->data)->common != NULL) {
			fprintf(file_arr[CLASSES], "inherits %s ", ((struct cil_class*)current->data)->common->datum.name);
		}


		if (current->cl_head != NULL) {
			fprintf(file_arr[CLASSES], "{ ");
			current = current->cl_head;
			while (current != NULL) {
				if (current->flavor == CIL_PERM) {
					fprintf(file_arr[CLASSES], "%s ", ((struct cil_symtab_datum*)current->data)->name);
				} else {
					cil_log(CIL_INFO, "Improper data type found in class permissions: %d\n", current->flavor);
					return SEPOL_ERR;
				}
				current = current->next;
			}
			fprintf(file_arr[CLASSES], "}");
		}

		fprintf(file_arr[CLASSES], "\n");

		return SEPOL_DONE;
	case CIL_AVRULE: {
		struct cil_avrule *avrule = (struct cil_avrule*)current->data;
		rc = cil_avrule_to_policy(file_arr, ALLOWS, avrule);
		if (rc != SEPOL_OK) {
			cil_log(CIL_INFO, "Failed to write avrule to policy\n");
			return rc;
		}
		break;
	}
	case CIL_TYPE_RULE: {
		struct cil_type_rule *rule = (struct cil_type_rule*)current->data;
		rc = cil_typerule_to_policy(file_arr, ALLOWS, rule);
		if (rc != SEPOL_OK) {
			cil_log(CIL_INFO, "Failed to write type rule to policy\n");
			return rc;
		}
		break;
	}
	case CIL_FILETRANSITION: {
		struct cil_filetransition *filetrans = (struct cil_filetransition*)current->data;
		rc = cil_filetransition_to_policy(file_arr, ALLOWS, filetrans);
		if (rc != SEPOL_OK) {
			cil_log(CIL_INFO, "Failed to write filetransition to policy\n");
			return rc;
		}
	}
	case CIL_ROLETRANSITION: {
		struct cil_roletransition *roletrans = (struct cil_roletransition*)current->data;
		char *src_str = ((struct cil_symtab_datum*)roletrans->src)->name;
		char *tgt_str = ((struct cil_symtab_datum*)roletrans->tgt)->name;
		char *obj_str = ((struct cil_symtab_datum*)roletrans->obj)->name;
		char *result_str = ((struct cil_symtab_datum*)roletrans->result)->name;
		
		fprintf(file_arr[ALLOWS], "role_transition %s %s:%s %s;\n", src_str, tgt_str, obj_str, result_str);
		break;
	}
	case CIL_ROLEALLOW: {
		struct cil_roleallow *roleallow = (struct cil_roleallow*)current->data;
		char *src_str = ((struct cil_symtab_datum*)roleallow->src)->name;
		char *tgt_str = ((struct cil_symtab_datum*)roleallow->tgt)->name;

		fprintf(file_arr[ALLOWS], "roleallow %s %s;\n", src_str, tgt_str);
		break;
	}
	case CIL_ROLETYPE: {
		struct cil_roletype *roletype = (struct cil_roletype*)current->data;
		char *role_str = ((struct cil_symtab_datum*)roletype->role)->name;
		char *type_str = ((struct cil_symtab_datum*)roletype->type)->name;

		fprintf(file_arr[ALIASES], "role %s types %s\n", role_str, type_str);
		break;
	}
	case CIL_ROLEDOMINANCE: {
		struct cil_roledominance *roledom = (struct cil_roledominance*)current->data;
		char *role_str = ((struct cil_symtab_datum*)roledom->role)->name;
		char *domed_str = ((struct cil_symtab_datum*)roledom->domed)->name;
		fprintf(file_arr[TYPEATTRTYPES], "dominance { role %s { role %s; } }\n", role_str, domed_str);
		break;
	}
	case CIL_LEVEL:
		fprintf(file_arr[LEVELS], "level ");
		cil_level_to_policy(file_arr, LEVELS, (struct cil_level*)current->data);
			fprintf(file_arr[LEVELS], ";\n");
			break;
	case CIL_CONSTRAIN:
		cil_constrain_to_policy(file_arr, CONSTRAINS, (struct cil_constrain*)current->data, flavor);
		break;
	case CIL_MLSCONSTRAIN:
		cil_constrain_to_policy(file_arr, CONSTRAINS, (struct cil_constrain*)current->data, flavor);
		break;
	case CIL_VALIDATETRANS: {
		struct cil_validatetrans *vt = current->data;
		fprintf(file_arr[CONSTRAINS], "validatetrans");
		fprintf(file_arr[CONSTRAINS], " %s ", ((struct cil_class*)vt->class)->datum.name);
		cil_expr_stack_to_policy(file_arr, CONSTRAINS, vt->expr);
		fprintf(file_arr[CONSTRAINS], ";\n");
		break;
	}
	case CIL_MLSVALIDATETRANS: {
		struct cil_validatetrans *vt = current->data;
		fprintf(file_arr[CONSTRAINS], "mlsvalidatetrans");
		fprintf(file_arr[CONSTRAINS], " %s " , ((struct cil_class*)vt->class)->datum.name);
		cil_expr_stack_to_policy(file_arr, CONSTRAINS, vt->expr);
		fprintf(file_arr[CONSTRAINS], ";\n");
		break;
	}
	case CIL_SID:
		fprintf(file_arr[ISIDS], "sid %s\n", ((struct cil_symtab_datum*)current->data)->name);
		break;
	case CIL_SIDCONTEXT: {
		struct cil_sidcontext *sidcon = (struct cil_sidcontext*)current->data;
		fprintf(file_arr[SIDS], "sid %s ", sidcon->sid_str);
		cil_context_to_policy(file_arr, SIDS, sidcon->context);
		fprintf(file_arr[SIDS], "\n");
		break;
	}
	case CIL_POLICYCAP:
		fprintf(file_arr[TYPEATTRTYPES], "policycap %s;\n", ((struct cil_symtab_datum*)current->data)->name);
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
				cil_log(CIL_INFO, "Failed to write booleanif contents to file\n");
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

		if (node->flavor == CIL_BLOCK && ((struct cil_block*)node->data)->is_abstract == CIL_TRUE) {
			*finished = CIL_TREE_SKIP_HEAD;
			return SEPOL_OK;
		}

		if (node->flavor != CIL_ROOT) {
			rc = cil_name_to_policy(file_arr, node);
			if (rc != SEPOL_OK && rc != SEPOL_DONE) {
				cil_log(CIL_ERR, "Error converting node to policy %d\n", node->flavor);
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
				cil_log(CIL_ERR, "Error converting node to policy %d\n", rc);
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
	file_arr[TYPEATTRTYPES] = fdopen(mkstemp(temp), "w+");
	file_path_arr[TYPEATTRTYPES] = cil_strdup(temp);
	
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
		cil_log(CIL_ERR, "Error walking tree\n");
		return rc;
	}

	rc = cil_netifcon_to_policy(file_arr, db->netifcon);
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Error creating policy.conf\n");
		return rc;
	}
	
	rc = cil_genfscon_to_policy(file_arr, db->genfscon);
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Error creating policy.conf\n");
		return rc;
	}

	rc = cil_portcon_to_policy(file_arr, db->portcon);
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Error creating policy.conf\n");
		return rc;
	}

	rc = cil_nodecon_to_policy(file_arr, db->nodecon);
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Error creating policy.conf\n");
		return rc;
	}

	rc = cil_fsuse_to_policy(file_arr, db->fsuse);
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Error creating policy.conf\n");
		return rc;
	}

	rc = cil_pirqcon_to_policy(file_arr, db->pirqcon);
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Error creating policy.conf\n");
		return rc;
	}

	rc = cil_iomemcon_to_policy(file_arr, db->iomemcon);
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Error creating policy.conf\n");
		return rc;
	}

	rc = cil_ioportcon_to_policy(file_arr, db->ioportcon);
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Error creating policy.conf\n");
		return rc;
	}

	rc = cil_pcidevicecon_to_policy(file_arr, db->pcidevicecon);
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Error creating policy.conf\n");
		return rc;
	}

	rc = cil_userrole_to_policy(file_arr, users);
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Error creating policy.conf\n");
		return SEPOL_ERR;
	}

	rc = cil_sens_to_policy(file_arr, sens);
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Error creating policy.conf\n");
		return SEPOL_ERR;
	}

	rc = cil_cat_to_policy(file_arr, cats);
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Error creating policy.conf\n");
		return SEPOL_ERR;
	}

	rc = cil_combine_policy(file_arr, policy_file);
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Error creating policy.conf\n");
		return SEPOL_ERR;
	}

	// Remove temp files
	int i;
	for (i=0; i<NUM_POLICY_FILES; i++) {
		rc = fclose(file_arr[i]);
		if (rc != 0) {
			cil_log(CIL_ERR, "Error closing temporary file\n");
			return SEPOL_ERR;
		}
		rc = unlink(file_path_arr[i]);
		if (rc != 0) {
			cil_log(CIL_ERR, "Error unlinking temporary files\n");
			return SEPOL_ERR;
		}
		free(file_path_arr[i]);
	}

	rc = fclose(policy_file);
	if (rc != 0) {
		cil_log(CIL_ERR, "Error closing policy.conf\n");
		return SEPOL_ERR;
	}
	free(file_arr);
	
	cil_list_destroy(&users, CIL_FALSE);
	cil_list_destroy(&cats, CIL_FALSE);
	cil_list_destroy(&sens, CIL_FALSE);
	
	return SEPOL_OK;
}
