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

#include "cil_internal.h"
#include "cil_log.h"
#include "cil_mem.h"
#include "cil_tree.h"
#include "cil_list.h"
#include "cil_post.h"
#include "cil_policy.h"
#include "cil_verify.h"

void cil_post_fc_fill_data(struct fc_data *fc, char *path)
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

int cil_post_filecon_compare(const void *a, const void *b)
{
	int rc = 0;
	struct cil_filecon *a_filecon = *(struct cil_filecon**)a;
	struct cil_filecon *b_filecon = *(struct cil_filecon**)b;
	struct fc_data *a_data = cil_malloc(sizeof(*a_data));
	struct fc_data *b_data = cil_malloc(sizeof(*b_data));
	char *a_path = cil_malloc(strlen(a_filecon->root_str) + strlen(a_filecon->path_str) + 1);
	a_path[0] = '\0';
	char *b_path = cil_malloc(strlen(b_filecon->root_str) + strlen(b_filecon->path_str) + 1);
	b_path[0] = '\0';
	strcat(a_path, a_filecon->root_str);
	strcat(a_path, a_filecon->path_str);
	strcat(b_path, b_filecon->root_str);
	strcat(b_path, b_filecon->path_str);
	cil_post_fc_fill_data(a_data, a_path);
	cil_post_fc_fill_data(b_data, b_path);
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

int cil_post_portcon_compare(const void *a, const void *b)
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

int cil_post_genfscon_compare(const void *a, const void *b)
{
	int rc = SEPOL_ERR;
	struct cil_genfscon *agenfscon = *(struct cil_genfscon**)a;
	struct cil_genfscon *bgenfscon = *(struct cil_genfscon**)b;

	rc = strcmp(agenfscon->fs_str, bgenfscon->fs_str);
	if (rc == 0) {
		rc = strcmp(agenfscon->path_str, bgenfscon->path_str);
	}

	return rc;
}

int cil_post_netifcon_compare(const void *a, const void *b)
{
	struct cil_netifcon *anetifcon = *(struct cil_netifcon**)a;
	struct cil_netifcon *bnetifcon = *(struct cil_netifcon**)b;

	return  strcmp(anetifcon->interface_str, bnetifcon->interface_str);
}

int cil_post_nodecon_compare(const void *a, const void *b)
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

int cil_post_pirqcon_compare(const void *a, const void *b)
{
	int rc = SEPOL_ERR;
	struct cil_pirqcon *apirqcon = *(struct cil_pirqcon**)a;
	struct cil_pirqcon *bpirqcon = *(struct cil_pirqcon**)b;

	if (apirqcon->pirq < bpirqcon->pirq) {
		rc = -1;
	} else if (bpirqcon->pirq < apirqcon->pirq) {
		rc = 1;
	} else {
		rc = 0;
	}

	return rc;
}

int cil_post_iomemcon_compare(const void *a, const void *b)
{
	int rc = SEPOL_ERR;
	struct cil_iomemcon *aiomemcon = *(struct cil_iomemcon**)a;
	struct cil_iomemcon *biomemcon = *(struct cil_iomemcon**)b;

	rc = (aiomemcon->iomem_high - aiomemcon->iomem_low) 
		- (biomemcon->iomem_high - biomemcon->iomem_low);
	if (rc == 0) {
		if (aiomemcon->iomem_low < biomemcon->iomem_low) {
			rc = -1;
		} else if (biomemcon->iomem_low < aiomemcon->iomem_low) {
			rc = 1;
		}
	}

	return rc;
}

int cil_post_ioportcon_compare(const void *a, const void *b)
{
	int rc = SEPOL_ERR;
	struct cil_ioportcon *aioportcon = *(struct cil_ioportcon**)a;
	struct cil_ioportcon *bioportcon = *(struct cil_ioportcon**)b;

	rc = (aioportcon->ioport_high - aioportcon->ioport_low) 
		- (bioportcon->ioport_high - bioportcon->ioport_low);
	if (rc == 0) {
		if (aioportcon->ioport_low < bioportcon->ioport_low) {
			rc = -1;
		} else if (bioportcon->ioport_low < aioportcon->ioport_low) {
			rc = 1;
		}
	}

	return rc;
}

int cil_post_pcidevicecon_compare(const void *a, const void *b)
{
	int rc = SEPOL_ERR;
	struct cil_pcidevicecon *apcidevicecon = *(struct cil_pcidevicecon**)a;
	struct cil_pcidevicecon *bpcidevicecon = *(struct cil_pcidevicecon**)b;

	if (apcidevicecon->dev < bpcidevicecon->dev) {
		rc = -1;
	} else if (bpcidevicecon->dev < apcidevicecon->dev) {
		rc = 1;
	} else {
		rc = 0;
	}

	return rc;
}

int cil_post_fsuse_compare(const void *a, const void *b)
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

int __cil_post_db_count_helper(struct cil_tree_node *node, uint32_t *finished, void *extra_args)
{
	int rc = SEPOL_ERR;
	struct cil_db *db = NULL;

	if (node == NULL || extra_args == NULL) {
		goto exit;
	}

	db = (struct cil_db*)extra_args;

	switch(node->flavor) {
	case CIL_BLOCK: {
		struct cil_block *blk = node->data;
		if (blk->is_abstract == CIL_TRUE) {
			*finished = CIL_TREE_SKIP_HEAD;
		}
		break;
	}
	case CIL_TYPE: {
		struct cil_type *type = node->data;
		type->value = db->num_types;
		db->num_types++;
		break;
	}
	case CIL_ROLE: {
		struct cil_role *role = node->data;
		role->value = db->num_roles;
		db->num_roles++;
		break;
	}
	case CIL_OPTIONAL: {
                struct cil_optional *opt = node->data;
                if (opt->datum.state != CIL_STATE_ENABLED) {
                        *finished = CIL_TREE_SKIP_HEAD;
                }
		break;
	}
        case CIL_MACRO:
                *finished = CIL_TREE_SKIP_HEAD;
		break;
	case CIL_NETIFCON:
		db->netifcon->count++;
		break;
	case CIL_GENFSCON:
		db->genfscon->count++;
		break;
	case CIL_FILECON:
		db->filecon->count++;
		break;
	case CIL_NODECON:
		db->nodecon->count++;
		break;
	case CIL_PORTCON:
		db->portcon->count++;
		break;
	case CIL_PIRQCON:
		db->pirqcon->count++;
		break;
	case CIL_IOMEMCON:
		db->iomemcon->count++;
		break;
	case CIL_IOPORTCON:
		db->ioportcon->count++;
		break;
	case CIL_PCIDEVICECON:
		db->pcidevicecon->count++;
		break;	
	case CIL_FSUSE:
		db->fsuse->count++;
		break;
	default:
		break;
	}

	return SEPOL_OK;

exit:
	cil_log(CIL_INFO, "cil_post_db_count_helper failed\n");
	return rc;
}

int __cil_post_db_array_helper(struct cil_tree_node *node, __attribute__((unused)) uint32_t *finished, void *extra_args)
{
	int rc = SEPOL_ERR;
	struct cil_db *db = NULL;

	if (node == NULL || extra_args == NULL) {
		goto exit;
	}

	db = extra_args;

	switch(node->flavor) {
	case CIL_BLOCK: {
		struct cil_block *blk = node->data;
		if (blk->is_abstract == CIL_TRUE) {
			*finished = CIL_TREE_SKIP_HEAD;
		}
		break;
	}
	case CIL_TYPE: {
		struct cil_type *type = node->data;
		if (db->val_to_type == NULL) {
			db->val_to_type = cil_malloc(sizeof(*db->val_to_type) * db->num_types);
		}
		db->val_to_type[type->value] = type;
		break;
	}
	case CIL_ROLE: {
		struct cil_role *role = node->data;
		if (db->val_to_role == NULL) {
			db->val_to_role = cil_malloc(sizeof(*db->val_to_role) * db->num_roles);
		}
		db->val_to_role[role->value] = role;
		break;
	}
	case CIL_USERPREFIX: {
		cil_list_append(db->userprefixes, CIL_USERPREFIX, node->data);
		break;
	}
	case CIL_SELINUXUSER: {
		cil_list_prepend(db->selinuxusers, CIL_SELINUXUSER, node->data);
		break;
	}
	case CIL_SELINUXUSERDEFAULT: {
		cil_list_append(db->selinuxusers, CIL_SELINUXUSERDEFAULT, node->data);
		break;
	}
	case CIL_OPTIONAL: {
                struct cil_optional *opt = node->data;
                if (opt->datum.state != CIL_STATE_ENABLED) {
                        *finished = CIL_TREE_SKIP_HEAD;
                }
		break;
	}
        case CIL_MACRO:
                *finished = CIL_TREE_SKIP_HEAD;
		break;
	case CIL_NETIFCON: {
		struct cil_sort *sort = db->netifcon;
		uint32_t count = sort->count;
		uint32_t i = sort->index;
		if (sort->array == NULL) {
			sort->array = cil_malloc(sizeof(*sort->array)*count);
		}
		sort->array[i] = node->data;
		sort->index++;
		break;
	}
	case CIL_FSUSE: {
		struct cil_sort *sort = db->fsuse;
		uint32_t count = sort->count;
		uint32_t i = sort->index;
		if (sort->array == NULL) {
			sort->array = cil_malloc(sizeof(*sort->array)*count);
		}
		sort->array[i] = node->data;
		sort->index++;
		break;
	}
	case CIL_GENFSCON: {
		struct cil_sort *sort = db->genfscon;
		uint32_t count = sort->count;
		uint32_t i = sort->index;
		if (sort->array == NULL) {
			sort->array = cil_malloc(sizeof(*sort->array)*count);
		}
		sort->array[i] = node->data;
		sort->index++;
		break;
	}
	case CIL_FILECON: {
		struct cil_sort *sort = db->filecon;
		uint32_t count = sort->count;
		uint32_t i = sort->index;
		if (sort->array == NULL) {
		sort->array = cil_malloc(sizeof(*sort->array)*count);
		}
		sort->array[i] = node->data;
		sort->index++;
		break;
	}
	case CIL_NODECON: {
		struct cil_sort *sort = db->nodecon;
		uint32_t count = sort->count;
		uint32_t i = sort->index;
		if (sort->array == NULL) {
			sort->array = cil_malloc(sizeof(*sort->array)*count);
		}
		sort->array[i] = node->data;
		sort->index++;
		break;
	}
	case CIL_PORTCON: {
		struct cil_sort *sort = db->portcon;
		uint32_t count = sort->count;
		uint32_t i = sort->index;
		if (sort->array == NULL) {
			sort->array = cil_malloc(sizeof(*sort->array)*count);
		}
		sort->array[i] = node->data;
		sort->index++;
		break;
	}
	case CIL_PIRQCON: {
		struct cil_sort *sort = db->pirqcon;
		uint32_t count = sort->count;
		uint32_t i = sort->index;
		if (sort->array == NULL) {
			sort->array = cil_malloc(sizeof(*sort->array)*count);
		}
		sort->array[i] = node->data;
		sort->index++;
		break;
	}
	case CIL_IOMEMCON: {
		struct cil_sort *sort = db->iomemcon;
		uint32_t count = sort->count;
		uint32_t i = sort->index;
		if (sort->array == NULL) {
			sort->array = cil_malloc(sizeof(*sort->array)*count);
		}
		sort->array[i] = node->data;
		sort->index++;
		break;
	}
	case CIL_IOPORTCON: {
		struct cil_sort *sort = db->ioportcon;
		uint32_t count = sort->count;
		uint32_t i = sort->index;
		if (sort->array == NULL) {
			sort->array = cil_malloc(sizeof(*sort->array)*count);
		}
		sort->array[i] = node->data;
		sort->index++;
		break;
	}
	case CIL_PCIDEVICECON: {
		struct cil_sort *sort = db->pcidevicecon;
		uint32_t count = sort->count;
		uint32_t i = sort->index;
		if (sort->array == NULL) {
			sort->array = cil_malloc(sizeof(*sort->array)*count);
		}
		sort->array[i] = node->data;
		sort->index++;
		break;
	}
	default:
		break;
	}

	return SEPOL_OK;

exit:
	cil_log(CIL_INFO, "cil_post_db_array_helper failed\n");
	return rc;
}

int __cil_expr_stack_to_bitmap(struct cil_db *db, enum cil_flavor flavor, struct cil_list *expr_stack_list, ebitmap_t *out)
{
	int rc = SEPOL_ERR;
	int max = 0;
	uint16_t pos;
	struct cil_list_item *expr_stack;
	ebitmap_t bitmap_tmp;
	ebitmap_t bitmap_stack[COND_EXPR_MAXDEPTH];

	if (expr_stack_list == NULL) {
		rc = SEPOL_OK;
		goto exit;
	}

	if (flavor == CIL_ROLE) {
		max = db->num_roles;
	} else {
		max = db->num_types;
	}

	cil_list_for_each(expr_stack, expr_stack_list) {
		struct cil_list_item *expr;
		pos = 0;
		cil_list_for_each(expr, (struct cil_list *)expr_stack->data) {
			struct cil_conditional *cond = expr->data;

			switch (cond->flavor) {
			case CIL_TYPE: {
				struct cil_symtab_datum *datum = cond->data;
				struct cil_tree_node *node = datum->nodes->head->data;

				ebitmap_init(&bitmap_tmp);
				if (node->flavor == CIL_TYPEATTRIBUTE) {
					struct cil_typeattribute *attr = cond->data;
					rc = __cil_expr_stack_to_bitmap(db, CIL_TYPE, attr->expr_stack_list, &bitmap_tmp);
					if (rc != SEPOL_OK) {
						rc = SEPOL_ERR;
						cil_log(CIL_INFO, "Failure while expanding expression stack to bitmap\n");
						goto exit;
					}
				} else if (node->flavor == CIL_TYPEALIAS) {
					struct cil_typealias *alias = cond->data;
					struct cil_type *type = alias->type;
					if (ebitmap_set_bit(&bitmap_tmp, type->value, 1)) {
						rc = SEPOL_ERR;
						cil_log(CIL_INFO, "Failed to set type bit\n");
						goto exit;
					}
				} else {
					struct cil_type *type = cond->data;
					if (ebitmap_set_bit(&bitmap_tmp, type->value, 1)) {
						rc = SEPOL_ERR;
						cil_log(CIL_INFO, "Failed to set type bit\n");
						goto exit;
					}
				}
				bitmap_stack[pos] = bitmap_tmp;
				pos++;
				break;
			}
			case CIL_ROLE: {
				struct cil_symtab_datum *datum = cond->data;
				struct cil_tree_node *node = datum->nodes->head->data;

				ebitmap_init(&bitmap_tmp);
				if (node->flavor == CIL_ROLEATTRIBUTE) {
					struct cil_roleattribute *attr = cond->data;
					rc = __cil_expr_stack_to_bitmap(db, CIL_ROLE, attr->expr_stack_list, &bitmap_tmp);
					if (rc != SEPOL_OK) {
						rc = SEPOL_ERR;
						cil_log(CIL_INFO, "Failure while expanding expression stack to bitmap\n");
						goto exit;
					}
				} else {
					struct cil_role *role = cond->data;
					if (ebitmap_set_bit(&bitmap_tmp, role->value, 1)) {
						rc = SEPOL_ERR;
						cil_log(CIL_INFO, "Failed to set role bit\n");
						goto exit;
					}
				}
				bitmap_stack[pos] = bitmap_tmp;
				pos++;
				break;
			}
			case CIL_STAR: {
				ebitmap_t all_zeros;
				ebitmap_init(&all_zeros);
				if (ebitmap_not(&bitmap_tmp, &all_zeros, max)) {
					rc = SEPOL_ERR;
					cil_log(CIL_INFO, "Failure Expanding *\n");
					goto exit;
				}
				bitmap_stack[pos] = bitmap_tmp;
				pos++;
			}
				break;
			case CIL_NOT:
				if (ebitmap_not(&bitmap_tmp, &bitmap_stack[pos - 1], max)) {
					rc = SEPOL_ERR;
					cil_log(CIL_INFO, "Failure NOTing bitmap\n");
					goto exit;
				}
				ebitmap_destroy(&bitmap_stack[pos - 1]);
				bitmap_stack[pos - 1] = bitmap_tmp;
				break;
			case CIL_OR:
				if (ebitmap_or(&bitmap_tmp, &bitmap_stack[pos - 2], &bitmap_stack[pos - 1])) {
					rc = SEPOL_ERR;
					cil_log(CIL_INFO, "Failure ORing attribute bitmaps\n");
					goto exit;
				}
				ebitmap_destroy(&bitmap_stack[pos - 2]);
				ebitmap_destroy(&bitmap_stack[pos - 1]);
				bitmap_stack[pos - 2] = bitmap_tmp;
				pos--;
				break;
			case CIL_AND:
				if (ebitmap_and(&bitmap_tmp, &bitmap_stack[pos - 2], &bitmap_stack[pos - 1])) {
					rc = SEPOL_ERR;
					cil_log(CIL_INFO, "Failure ANDing attribute bitmaps\n");
					goto exit;
				}
				ebitmap_destroy(&bitmap_stack[pos - 2]);
				ebitmap_destroy(&bitmap_stack[pos - 1]);
				bitmap_stack[pos - 2] = bitmap_tmp;
				pos--;
				break;
			case CIL_XOR:
				if (ebitmap_xor(&bitmap_tmp, &bitmap_stack[pos - 2], &bitmap_stack[pos - 1])) {
					rc = SEPOL_ERR;
					cil_log(CIL_INFO, "Failure XORing attribute bitmaps\n");
					goto exit;
				}
				ebitmap_destroy(&bitmap_stack[pos - 2]);
				ebitmap_destroy(&bitmap_stack[pos - 1]);
				bitmap_stack[pos - 2] = bitmap_tmp;
				pos--;
				break;
			default:
				break;
			}
		}
		ebitmap_union(out, &bitmap_stack[0]);
		ebitmap_destroy(&bitmap_stack[0]);
	}

	rc = SEPOL_OK;
exit:
	return rc;
}

int __cil_post_db_attr_helper(struct cil_tree_node *node, __attribute__((unused)) uint32_t *finished, void *extra_args)
{
	int rc = SEPOL_ERR;
	struct cil_db *db = NULL;

	if (node == NULL || extra_args == NULL) {
		goto exit;
	}

	db = extra_args;

	switch (node->flavor) {
	case CIL_BLOCK: {
		struct cil_block *blk = node->data;
		if (blk->is_abstract == CIL_TRUE) {
			*finished = CIL_TREE_SKIP_HEAD;
		}
		break;
	}
	case CIL_OPTIONAL: {
		struct cil_optional *opt = node->data;
		if (opt->datum.state != CIL_STATE_ENABLED) {
			*finished = CIL_TREE_SKIP_HEAD;
		}
		break;
	}
	case CIL_MACRO: {
		*finished = CIL_TREE_SKIP_HEAD;
		break;
	}
	case CIL_TYPEATTRIBUTE: {
		struct cil_typeattribute *attr = node->data;
		struct cil_list *expr_list = attr->expr_stack_list;

		attr->types = cil_malloc(sizeof(*attr->types));
		ebitmap_init(attr->types);

		rc = __cil_expr_stack_to_bitmap(db, CIL_TYPE, expr_list, attr->types);
		if (rc != SEPOL_OK) {
			cil_log(CIL_ERR, "Failure while expanding expression stack to bitmap\n");
			goto exit;
		}
		break;
	}
	case CIL_ROLEATTRIBUTE: {
		struct cil_roleattribute *attr = node->data;
		struct cil_list *expr_list = attr->expr_stack_list;

		attr->roles = cil_malloc(sizeof(*attr->roles));
		ebitmap_init(attr->roles);

		rc = __cil_expr_stack_to_bitmap(db, CIL_ROLE, expr_list, attr->roles);
		if (rc != SEPOL_OK) {
			cil_log(CIL_ERR, "Failure while expanding expression stack to bitmap\n");
			goto exit;
		}
		break;
	}
	default:
		break;
	}

	return SEPOL_OK;
exit:
	cil_log(CIL_INFO, "cil_post_db_attr_helper failed\n");
	return rc;

}

int __cil_role_assign_types(struct cil_role *role, struct cil_symtab_datum *datum)
{
	int rc = SEPOL_ERR;
	ebitmap_t bitmap_tmp;
	struct cil_tree_node *node = datum->nodes->head->data;

	if (role->types == NULL) {
		role->types = cil_malloc(sizeof(*role->types));
		ebitmap_init(role->types);
	}

	if (node->flavor == CIL_TYPE) {
		struct cil_type *type = (struct cil_type *)datum;
		if (ebitmap_set_bit(role->types, type->value, 1)) {
			cil_log(CIL_INFO, "Failure while setting bit in role types bitmap\n");
			goto exit;
		}
	} else if (node->flavor == CIL_TYPEALIAS) {
		struct cil_typealias *typealias = (struct cil_typealias *)datum;
		struct cil_type *type = typealias->type;
		if (ebitmap_set_bit(role->types, type->value, 1)) {
			cil_log(CIL_INFO, "Failure while setting bit in role types bitmap\n");
			goto exit;
		}
	} else if (node->flavor == CIL_TYPEATTRIBUTE) {
		struct cil_typeattribute *attr = (struct cil_typeattribute *)datum;
		if (ebitmap_or(&bitmap_tmp, attr->types, role->types)) {
			cil_log(CIL_INFO, "Failure ORing role attribute bitmaps\n");
			goto exit;
		}
		ebitmap_union(role->types, &bitmap_tmp);
		ebitmap_destroy(&bitmap_tmp);
	}

	rc = SEPOL_OK;
exit:
	return rc;
}

int __cil_post_db_roletype_helper(struct cil_tree_node *node, __attribute__((unused)) uint32_t *finished, void *extra_args)
{
	int rc = SEPOL_ERR;
	struct cil_db *db = extra_args;

	if (node == NULL || extra_args == NULL) {
		goto exit;
	}

	switch (node->flavor) {
	case CIL_BLOCK: {
		struct cil_block *blk = node->data;
		if (blk->is_abstract == CIL_TRUE) {
			*finished = CIL_TREE_SKIP_HEAD;
		}
		break;
	}
	case CIL_OPTIONAL: {
		struct cil_optional *opt = node->data;
		if (opt->datum.state != CIL_STATE_ENABLED) {
			*finished = CIL_TREE_SKIP_HEAD;
		}
		break;
	}
	case CIL_MACRO: {
		*finished = CIL_TREE_SKIP_HEAD;
		break;
	}
	case CIL_ROLETYPE: {
		struct cil_roletype *roletype = node->data;
		struct cil_symtab_datum *role_datum = roletype->role;
		struct cil_symtab_datum *type_datum = roletype->type;
		struct cil_tree_node *role_node = role_datum->nodes->head->data;

		if (role_node->flavor == CIL_ROLEATTRIBUTE) {
			struct cil_roleattribute *attr = roletype->role;
			ebitmap_node_t *rnode;
			unsigned int i;
	
			ebitmap_for_each_bit(attr->roles, rnode, i) {
				struct cil_role *role = NULL;

				if (!ebitmap_get_bit(attr->roles, i)) {
					continue;
				}

				role = db->val_to_role[i];

				rc = __cil_role_assign_types(role, type_datum);
				if (rc != SEPOL_OK) {
					goto exit;
				}
			}
		} else {
			struct cil_role *role = roletype->role;

			rc = __cil_role_assign_types(role, type_datum);
			if (rc != SEPOL_OK) {
				goto exit;
			}
		}
		break;
	}
	default:
		break;
	}

	return SEPOL_OK;
exit:
	cil_log(CIL_INFO, "cil_post_db_roletype_helper failed\n");
	return rc;
}

int cil_post_db(struct cil_db *db)
{
	int rc = SEPOL_ERR;

	rc = cil_tree_walk(db->ast->root, __cil_post_db_count_helper, NULL, NULL, db);
	if (rc != SEPOL_OK) {
		cil_log(CIL_INFO, "Failure during cil databse count helper\n");
		goto exit;
	}

	rc = cil_tree_walk(db->ast->root, __cil_post_db_array_helper, NULL, NULL, db);
	if (rc != SEPOL_OK) {
		cil_log(CIL_INFO, "Failure during cil database array helper\n");
		goto exit;
	}

	rc = cil_tree_walk(db->ast->root, __cil_post_db_attr_helper, NULL, NULL, db);
	if (rc != SEPOL_OK) {
		cil_log(CIL_INFO, "Failed to create attribute bitmaps\n");
		goto exit;
	}

	rc = cil_tree_walk(db->ast->root, __cil_post_db_roletype_helper, NULL, NULL, db);
	if (rc != SEPOL_OK) {
		cil_log(CIL_INFO, "Failed during roletype association\n");
		goto exit;
	}


	qsort(db->netifcon->array, db->netifcon->count, sizeof(db->netifcon->array), cil_post_netifcon_compare);
	qsort(db->genfscon->array, db->genfscon->count, sizeof(db->genfscon->array), cil_post_genfscon_compare);
	qsort(db->portcon->array, db->portcon->count, sizeof(db->portcon->array), cil_post_portcon_compare);
	qsort(db->nodecon->array, db->nodecon->count, sizeof(db->nodecon->array), cil_post_nodecon_compare);
	qsort(db->fsuse->array, db->fsuse->count, sizeof(db->fsuse->array), cil_post_fsuse_compare);
	qsort(db->filecon->array, db->filecon->count, sizeof(db->filecon->array), cil_post_filecon_compare);
	qsort(db->pirqcon->array, db->pirqcon->count, sizeof(db->pirqcon->array), cil_post_pirqcon_compare);
	qsort(db->iomemcon->array, db->iomemcon->count, sizeof(db->iomemcon->array), cil_post_iomemcon_compare);
	qsort(db->ioportcon->array, db->ioportcon->count, sizeof(db->ioportcon->array), cil_post_ioportcon_compare);
	qsort(db->pcidevicecon->array, db->pcidevicecon->count, sizeof(db->pcidevicecon->array), cil_post_pcidevicecon_compare);

exit:
	return rc;
}

int cil_post_verify(struct cil_db *db)
{
	int rc = SEPOL_ERR;
	int avrule_cnt = 0;
	int nseuserdflt = 0;
	int pass = 0;
	struct cil_args_verify extra_args;
	struct cil_complex_symtab csymtab;
	symtab_t senstab;
	cil_symtab_init(&senstab, CIL_CLASS_SYM_SIZE);

	cil_complex_symtab_init(&csymtab, CIL_CLASS_SYM_SIZE);

	extra_args.db = db;
	extra_args.csymtab = &csymtab;
	extra_args.senstab = &senstab;
	extra_args.avrule_cnt = &avrule_cnt;
	extra_args.nseuserdflt = &nseuserdflt;
	extra_args.pass = &pass;

	for (pass = 0; pass < 2; pass++) {
		rc = cil_tree_walk(db->ast->root, __cil_verify_helper, NULL, NULL, &extra_args);
		if (rc != SEPOL_OK) {
			cil_log(CIL_ERR, "Failed to verify cil database\n");
			goto exit;
		}
	}

	if (avrule_cnt == 0) {
		cil_log(CIL_ERR, "Policy must include at least one avrule\n");
		rc = SEPOL_ERR;
		goto exit;
	}

	if (nseuserdflt > 1) {
		cil_log(CIL_ERR, "Policy cannot contain more than one selinuxuserdefault, found: %d\n", nseuserdflt);
		rc = SEPOL_ERR;
		goto exit;
	}

exit:
	cil_symtab_destroy(&senstab);
	cil_complex_symtab_destroy(&csymtab);
	return rc;
}

int cil_post_process(struct cil_db *db)
{
	int rc = SEPOL_ERR;

	rc = cil_post_db(db);
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Failed post db handling\n");
		goto exit;
	}

	rc = cil_post_verify(db);
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Failed to verify cil database\n");
		goto exit;
	}
exit:
	return rc;
		
}
