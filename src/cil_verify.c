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
#include <ctype.h>

#include <sepol/policydb/polcaps.h>
#include <sepol/errcodes.h>

#include "cil_internal.h"
#include "cil_flavor.h"
#include "cil_log.h"
#include "cil_mem.h"
#include "cil_tree.h"
#include "cil_list.h"

#include "cil_verify.h"

int __cil_verify_name(const char *name)
{
	int rc = SEPOL_ERR;
	int len = strlen(name);
	int i = 0;

	if (len >= CIL_MAX_NAME_LENGTH) {
		cil_log(CIL_ERR, "Name length greater than max name length of %d", 
			CIL_MAX_NAME_LENGTH);
		rc = SEPOL_ERR;
		goto exit;
	}

	for (i = 0; i < len; i++) {
		if (!isalnum(name[i]) && name[i] != '_') {
			cil_log(CIL_ERR, "Invalid character \"%c\" in %s\n", name[i], name);
			goto exit;
		}
	}
	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Invalid name\n");
	return rc;
}

int __cil_verify_syntax(struct cil_tree_node *parse_current, enum cil_syntax s[], int len)
{
	int rc = SEPOL_ERR;
	int num_extras = 0;
	struct cil_tree_node *c = parse_current;
	int i = 0;
	while (i < len) {
		if ((s[i] & CIL_SYN_END) && c == NULL) {
			break;
		}

		if (s[i] & CIL_SYN_N_LISTS || s[i] & CIL_SYN_N_STRINGS) {
			if (c == NULL) {
				if (num_extras > 0) {
					break;
				} else {
					goto exit;
				}
			} else if ((s[i] & CIL_SYN_N_LISTS) && (c->data == NULL && c->cl_head != NULL)) {
				c = c->next;
				num_extras++;
				continue;
			} else if ((s[i] & CIL_SYN_N_STRINGS) && (c->data != NULL && c->cl_head == NULL)) {
				c = c->next;
				num_extras++;
				continue;
			}
		}

		if (c == NULL) {
			goto exit;
		}

		if (s[i] & CIL_SYN_STRING) {
			if (c->data != NULL && c->cl_head == NULL) {
				c = c->next;
				i++;
				continue;
			}
		}

		if (s[i] & CIL_SYN_LIST) {
			if (c->data == NULL && c->cl_head != NULL) {
				c = c->next;
				i++;
				continue;
			}
		}

		if (s[i] & CIL_SYN_EMPTY_LIST) {
			if (c->data == NULL && c->cl_head == NULL) {
				c = c->next;
				i++;
				continue;
			}
		}
		goto exit;
	}
	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Invalid syntax\n");
	return rc;
}

int cil_verify_expr_syntax(struct cil_tree_node *current, enum cil_flavor op, enum cil_flavor expr_flavor)
{
	int rc;
	enum cil_syntax syntax[] = {
		CIL_SYN_STRING,
		CIL_SYN_STRING | CIL_SYN_LIST,
		CIL_SYN_STRING | CIL_SYN_LIST,
		CIL_SYN_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);

	switch (op) {
	case CIL_NOT:
		syntax[2] = CIL_SYN_END;
		syntax_len = 3;
		break;
	case CIL_AND:
	case CIL_OR:
	case CIL_XOR:
		break;
	case CIL_EQ:
	case CIL_NEQ:
		if (expr_flavor != CIL_BOOL && expr_flavor != CIL_TUNABLE ) {
			cil_log(CIL_ERR,"Invalid operator (%s) for set expression\n", current->data);
			goto exit;
		}
		break;
	case CIL_ALL:
		if (expr_flavor == CIL_BOOL || expr_flavor == CIL_TUNABLE) {
			cil_log(CIL_ERR,"Invalid operator (%s) for boolean or tunable expression\n", current->data);
			goto exit;
		}
		syntax[1] = CIL_SYN_END;
		syntax_len = 2;
		break;
	case CIL_NONE: /* String or List */
		syntax[0] = CIL_SYN_N_STRINGS | CIL_SYN_N_LISTS;
		syntax[1] = CIL_SYN_END;
		syntax_len = 2;
		break;
	default:
		cil_log(CIL_ERR,"Unexpected value (%s) for expression operator\n", current->data);
		goto exit;
	}

	rc = __cil_verify_syntax(current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	return SEPOL_OK;

exit:
	return SEPOL_ERR;
}

int cil_verify_constraint_leaf_expr_syntax(enum cil_flavor l_flavor, enum cil_flavor r_flavor, enum cil_flavor op, enum cil_flavor expr_flavor)
{
	if (r_flavor == CIL_STRING || r_flavor == CIL_LIST) {
		if (l_flavor == CIL_CONS_L1 || l_flavor == CIL_CONS_L2 || l_flavor == CIL_CONS_H1 || l_flavor == CIL_CONS_H2 ) {
			cil_log(CIL_ERR, "l1, l2, h1, and h2 cannot be used on the left side with a string or list on the right side\n");
			goto exit;
		} else if (l_flavor == CIL_CONS_U3 || l_flavor == CIL_CONS_R3 || l_flavor == CIL_CONS_T3) {
			if (expr_flavor != CIL_MLSVALIDATETRANS) {
				cil_log(CIL_ERR, "u3, r3, and t3 can only be used with mlsvalidatetrans rules\n");
				goto exit;
			}
		}
	} else {
		if (r_flavor == CIL_CONS_U2) {
			if (op != CIL_EQ && op != CIL_NEQ) {
				cil_log(CIL_ERR, "u2 on the right side must be used with eq or neq as the operator\n");
				goto exit;
			} else if (l_flavor != CIL_CONS_U1) {
				cil_log(CIL_ERR, "u2 on the right side must be used with u1 on the left\n");
				goto exit;
			}
		} else if (r_flavor == CIL_CONS_R2) {
			if (l_flavor != CIL_CONS_R1) {
				cil_log(CIL_ERR, "r2 on the right side must be used with r1 on the left\n");
				goto exit;
			}
		} else if (r_flavor == CIL_CONS_T2) {
			if (op != CIL_EQ && op != CIL_NEQ) {
				cil_log(CIL_ERR, "t2 on the right side must be used with eq or neq as the operator\n");
				goto exit;
			} else if (l_flavor != CIL_CONS_T1) {
				cil_log(CIL_ERR, "t2 on the right side must be used with t1 on the left\n");
				goto exit;
			}
		} else if (r_flavor == CIL_CONS_L2) {
			if (l_flavor != CIL_CONS_L1 && l_flavor != CIL_CONS_H1) {
				cil_log(CIL_ERR, "l2 on the right side must be used with l1 or h1 on the left\n");
				goto exit;
			}
		} else if (r_flavor == CIL_CONS_H2) {
			if (l_flavor != CIL_CONS_L1 && l_flavor != CIL_CONS_L2 && l_flavor != CIL_CONS_H1 ) {
				cil_log(CIL_ERR, "h2 on the right side must be used with l1, l2, or h1 on the left\n");
				goto exit;
			}
		} else if (r_flavor == CIL_CONS_H1) {
			if (l_flavor != CIL_CONS_L1) {
				cil_log(CIL_ERR, "h1 on the right side must be used with l1 on the left\n");
				goto exit;
			}
		}
	}

	return SEPOL_OK;

exit:
	return SEPOL_ERR;
}

int cil_verify_constraint_expr_syntax(struct cil_tree_node *current, enum cil_flavor op)
{
	int rc;
	enum cil_syntax syntax[] = {
		CIL_SYN_STRING,
		CIL_SYN_END,
		CIL_SYN_END,
		CIL_SYN_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);

	switch (op) {
	case CIL_NOT:
		syntax[1] = CIL_SYN_LIST;
		syntax_len--;
		break;
	case CIL_AND:
	case CIL_OR:
		syntax[1] = CIL_SYN_LIST;
		syntax[2] = CIL_SYN_LIST;
		break;
	case CIL_EQ:
	case CIL_NEQ:
		syntax[1] = CIL_SYN_STRING;
		syntax[2] = CIL_SYN_STRING | CIL_SYN_LIST;
		break;
	case CIL_CONS_DOM:
	case CIL_CONS_DOMBY:
	case CIL_CONS_INCOMP:
		syntax[1] = CIL_SYN_STRING;
		syntax[2] = CIL_SYN_STRING;
		break;
	default:
		cil_log(CIL_ERR,"Invalid operator (%s) for constraint expression\n",current->data);
		goto exit;
	}

	rc = __cil_verify_syntax(current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Invalid constraint syntax\n");
		goto exit;
	}

	return SEPOL_OK;

exit:
	return SEPOL_ERR;
}

int cil_verify_no_self_reference(struct cil_symtab_datum *datum, struct cil_list *datum_list)
{
	struct cil_list_item *i;

	cil_list_for_each(i, datum_list) {
		if (i->flavor == CIL_DATUM) {
			struct cil_symtab_datum *d = i->data;
			if (d == datum) {
				cil_log(CIL_ERR,"Self-reference found for %s\n",datum->name);
				return SEPOL_ERR;
			}
		} else if (i->flavor == CIL_LIST) {
			int rc = cil_verify_no_self_reference(datum, i->data);
			if (rc != SEPOL_OK) {
				return SEPOL_ERR;
			}
		}
	}

	return SEPOL_OK;
}

int __cil_verify_ranges(struct cil_list *list)
{
	int rc = SEPOL_ERR;
	struct cil_list_item *curr;
	struct cil_list_item *range = NULL;

	if (list == NULL || list->head == NULL) {
		goto exit;
	}

	cil_list_for_each(curr, list) {
		/* range */
		if (curr->flavor == CIL_LIST) {
			range = ((struct cil_list*)curr->data)->head;
			if (range == NULL || range->next == NULL || range->next->next != NULL) {
				goto exit;
			}
		}
	}

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR,"Invalid Range syntax\n");
	return rc;
}

struct cil_args_verify_order {
	uint32_t *flavor;
};

int __cil_verify_ordered_node_helper(struct cil_tree_node *node, __attribute__((unused)) uint32_t *finished, void *extra_args)
{
	struct cil_args_verify_order *args = extra_args;
	uint32_t *flavor = args->flavor;

	if (node->flavor == *flavor) {
		if (node->flavor == CIL_SID) {
			struct cil_sid *sid = node->data;
			if (sid->ordered == CIL_FALSE) {
				cil_log(CIL_ERR, "SID %s not in sidorder statement at line %d of %s\n", sid->datum.name, node->line, node->path);
				return SEPOL_ERR;
			}
		} else if (node->flavor == CIL_CAT) {
			struct cil_cat *cat = node->data;
			if (cat->ordered == CIL_FALSE) {
				cil_log(CIL_ERR, "Category %s not in categoryorder statement at line %d of %s\n", cat->datum.name, node->line, node->path);
				return SEPOL_ERR;
			}
		} else if (node->flavor == CIL_SENS) {
			struct cil_sens *sens = node->data;
			if (sens->ordered == CIL_FALSE) {
				cil_log(CIL_ERR, "Sensitivity %s not in sensitivityorder statement at line %d of %s\n", sens->datum.name, node->line, node->path);
				return SEPOL_ERR;
			}
		}
	}

	return SEPOL_OK;
}

int __cil_verify_ordered(struct cil_tree_node *current, enum cil_flavor flavor)
{
	struct cil_args_verify_order extra_args;
	int rc = SEPOL_ERR;

	extra_args.flavor = &flavor;

	rc = cil_tree_walk(current, __cil_verify_ordered_node_helper, NULL, NULL, &extra_args);

	return rc;
}

int __cil_verify_catrange(struct cil_db *db, struct cil_catrange *catrange, struct cil_cat *cat)
{
	struct cil_list_item *cat_item;
	int rc = SEPOL_ERR;

	if (catrange->cat_low == cat || catrange->cat_high == cat) {
		rc = SEPOL_OK;
		goto exit;
	}

	cil_list_for_each(cat_item, db->catorder) {
		if (cat_item->data == catrange->cat_low) {
			break;
		}
	}

	if (cat_item == NULL) {
		rc = SEPOL_ERR;
		cil_log(CIL_ERR,"Could not find category range\n");
		goto exit;
	}


	for (cat_item = cat_item->next; cat_item != NULL; cat_item = cat_item->next) {
		if (cat_item->data == catrange->cat_high) {
			break;
		}
		
		if (cat_item->data == cat) {
			rc = SEPOL_OK;
			goto exit;
		}
	}

	cil_log(CIL_ERR,"Category %s not found in category range\n", cat->datum.name);
	return SEPOL_ERR;

exit:
	return rc;
}

int __cil_verify_senscat(struct cil_db *db, struct cil_sens *sens, struct cil_cat *cat)
{
	struct cil_list_item *catset_item;
	int rc = SEPOL_ERR;

	cil_list_for_each(catset_item, sens->catsets) {
		struct cil_catset *catset = catset_item->data;
		struct cil_list_item *cat_item;
		cil_list_for_each(cat_item, catset->cat_list) {
			switch (cat_item->flavor) {
			case CIL_CAT: {
				if (cat_item->data == cat) {
					rc = SEPOL_OK;
					goto exit;
				}
				break;
			}
			case CIL_CATRANGE: {
				rc = __cil_verify_catrange(db, cat_item->data, cat);
				if (rc == SEPOL_OK) {
					goto exit;
				}
				break;
			}
			default:
				rc = SEPOL_ERR;
				cil_log(CIL_ERR, "Category %s cannot be used with sensitivity %s\n", 
					cat->datum.name, sens->datum.name);
				goto exit;
			}
		}
	}

	cil_log(CIL_ERR, "Category %s cannot be used with sensitivity %s\n", 
		cat->datum.name, sens->datum.name);
	return SEPOL_ERR;

exit:
	return rc;
}

int __cil_verify_senscatset(struct cil_db *db, struct cil_sens *sens, struct cil_catset *catset)
{
	struct cil_list_item *catset_item;
	int rc = SEPOL_OK;

	cil_list_for_each(catset_item, catset->cat_list) {
		switch (catset_item->flavor) {
		case CIL_CAT: {
			struct cil_cat *cat = catset_item->data;
			rc = __cil_verify_senscat(db, sens, cat);
			if (rc != SEPOL_OK) {
				goto exit;
			}
			break;
		}
		case CIL_CATRANGE: {
			struct cil_catrange *catrange = catset_item->data;
			struct cil_list_item *catorder;

			cil_list_for_each(catorder, db->catorder) { 
				if (catorder->data == catrange->cat_low) {
					break;
				}
			}

			if (catorder == NULL) {
				rc = SEPOL_ERR;
				goto exit;
			}

			for (; catorder != NULL; catorder = catorder->next) {
				struct cil_cat *cat = catorder->data;
				rc = __cil_verify_senscat(db, sens, cat);
				if (rc != SEPOL_OK) {
					goto exit;
				}
				if (catorder->data == catrange->cat_high) {
					break;
				}
			}

			if (catorder == NULL) {
				rc = SEPOL_ERR;
				goto exit;
			}

			break;
		}
		default:
			rc = SEPOL_ERR;
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Invalid category set for sensitivity %s\n", sens->datum.name);
	return rc;
}

int __cil_verify_levelrange_sensitivityorder(struct cil_db *db, struct cil_sens *low, struct cil_sens *high)
{
	struct cil_list_item *curr;
	int found = CIL_FALSE;
	int rc = SEPOL_ERR;

	cil_list_for_each(curr, db->sensitivityorder) {
		if (curr->data == low) {
			found = CIL_TRUE;
		}

		if ((found == CIL_TRUE) && (curr->data == high)) {
			break;
		}
	}

	if (found != CIL_TRUE || curr == NULL) {
		goto exit;
	}

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Sensitivity %s does not dominate %s\n", 
		high->datum.name, low->datum.name);
	return rc;

}

int __cil_verify_cat_in_catset(struct cil_db *db, struct cil_cat *cat, struct cil_catset *set)
{
	int rc = SEPOL_ERR;
	struct cil_list_item *set_curr;

	cil_list_for_each(set_curr, set->cat_list) {
		switch (set_curr->flavor) {
		case CIL_CAT:
			if (cat == set_curr->data) {
				return SEPOL_OK;
			}
			break;
		case CIL_CATRANGE:
			rc = __cil_verify_catrange(db, set_curr->data, cat);
			if (rc == SEPOL_OK) {
				return SEPOL_OK;
			}
			break;
		default:
			goto exit;
		}
	}

exit:
	cil_log(CIL_ERR, "Failed to find %s in category set\n", cat->datum.name);
	return SEPOL_ERR;
}

int __cil_verify_levelrange_cats(struct cil_db *db, struct cil_catset *low, struct cil_catset *high)
{
	int rc = SEPOL_ERR;
	struct cil_list_item *low_curr;
	struct cil_list_item *order_curr;
	struct cil_cat *range_low = NULL;
	struct cil_cat *range_high = NULL;
	int found = CIL_FALSE;

	if (low == NULL || (low == NULL && high == NULL)) {
		return SEPOL_OK;
	}

	if (high == NULL) {
		rc = SEPOL_ERR;
		goto exit;
	}

	cil_list_for_each(low_curr, low->cat_list) {
		switch (low_curr->flavor) {
		case CIL_CAT:
			rc = __cil_verify_cat_in_catset(db, low_curr->data, high);
			if (rc != SEPOL_OK) {
				goto exit;
			}
			break;
		case CIL_CATRANGE:
			range_low = ((struct cil_catrange*)low_curr->data)->cat_low;
			range_high = ((struct cil_catrange*)low_curr->data)->cat_high;
			cil_list_for_each(order_curr, db->catorder) {
				if (order_curr->data == range_low) {
					found = CIL_TRUE;
				} else if (order_curr->data == range_high) {
					break;
				}

				if (found == CIL_TRUE) {
					rc = __cil_verify_cat_in_catset(db, order_curr->data, high);
					if (rc != SEPOL_OK) {
						goto exit;
					}
				}
			}
			break;
		default:
			rc = SEPOL_ERR;
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Low level category set must be a subset of the high level category set\n");
	return rc;
}

int __cil_verify_levelrange(struct cil_db *db, struct cil_levelrange *lr)
{
	int rc = SEPOL_ERR;

	rc = __cil_verify_levelrange_sensitivityorder(db, lr->low->sens, lr->high->sens);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	rc = __cil_verify_levelrange_cats(db, lr->low->catset, lr->high->catset);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Invalid range\n");
	return rc;
}

int __cil_verify_named_levelrange(struct cil_db *db, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	struct cil_levelrange *lr = node->data;

	rc = __cil_verify_levelrange(db, lr);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	return SEPOL_OK;
exit:
	cil_log(CIL_ERR, "Invalid named range at line %d of %s\n", node->line, node->path);
	return rc;
}

int __cil_verify_user(struct cil_db *db, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	struct cil_user *user = node->data;

	if (user->dftlevel == NULL) {
		cil_log(CIL_ERR, "User %s does not have a default level\n", user->datum.name);
		goto exit;
	} else if (user->range == NULL) {
		cil_log(CIL_ERR, "User %s does not have a level range\n", user->datum.name);
		goto exit;
	} else if (user->bounds != NULL) {
		struct cil_user *bnds = user->bounds;
		if (user == bnds) {
			cil_log(CIL_ERR, "User %s cannot bound self\n", user->datum.name);
			goto exit;
		} else if (bnds->bounds != NULL) {
			bnds = bnds->bounds;
			if (user == bnds) {
				cil_log(CIL_ERR, "Circular bounds found for user %s\n", 
					user->datum.name);
				goto exit;
			}
		}
	}

	/* Verify user range only if anonymous */
	if (user->range->datum.name == NULL) {
		rc = __cil_verify_levelrange(db, user->range);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	return SEPOL_OK;
exit:
	cil_log(CIL_ERR, "Invalid user at line %d of %s\n", node->line, node->path);
	return rc;
}

int __cil_verify_role(struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	int steps = 0;
	int limit = 2;
	struct cil_role *bnding = node->data;
	struct cil_role *bnded = node->data;

	if (bnding->bounds != NULL) {
		while (1) {
			if (bnding == NULL) {
				break;
			}
			bnding = bnding->bounds;

			steps += 1;

			if (bnding == bnded) {
				cil_log(CIL_ERR, "Circular role bounds found that includes %s\n", 
					bnding->datum.name);
				rc = SEPOL_ERR;
				goto exit;
			}

			if (steps == limit) {
				steps = 0;
				limit *= 2;
				bnded = bnding;
			}
		}
	}

	return SEPOL_OK;
exit:
	cil_log(CIL_ERR, "Invalid role at line %d of %s\n", node->line, node->path);
	return rc;
}

int __cil_verify_type(struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	int steps = 0;
	int limit = 2;
	struct cil_type *bnding = node->data;
	struct cil_type *bnded = node->data;

	if (bnding->bounds != NULL) {
		while (1) {
			if (bnding == NULL) {
				break;
			}
			bnding = bnding->bounds;
			steps += 1;

			if (bnding == bnded) {
				cil_log(CIL_ERR, "Circular type bounds found that includes %s\n", 
					bnding->datum.name);
				rc = SEPOL_ERR;
				goto exit;
			}

			if (steps == limit) {
				steps = 0;
				limit *= 2;
				bnded = bnding;
			}
		}
	}

	return SEPOL_OK;
exit:
	cil_log(CIL_ERR, "Invalid type at line %d of %s\n", node->line, node->path);
	return rc;
}

int __cil_verify_context(struct cil_db *db, struct cil_context *ctx)
{
	int rc = SEPOL_ERR;
	struct cil_user *user = ctx->user;
	struct cil_role *role = ctx->role;
	struct cil_type *type = ctx->type;
	struct cil_level *user_low = user->range->low;
	struct cil_level *user_high = user->range->high;
	struct cil_level *ctx_low = ctx->range->low;
	struct cil_level *ctx_high = ctx->range->high;
	struct cil_list *sensitivityorder = db->sensitivityorder;
	struct cil_list_item *curr;
	int found = CIL_FALSE;

	if (user->roles != NULL) {
		cil_list_for_each(curr, user->roles) {
			struct cil_role *userrole = curr->data;
			if (userrole == role) {
				break;
			}
		}

		if (curr == NULL) {
			cil_log(CIL_ERR, "Role %s is invalid for user %s\n",
					ctx->role_str, ctx->user_str);
			rc = SEPOL_ERR;
			goto exit;
		}
	} else {
		cil_log(CIL_ERR, "No roles given to the user %s\n", ctx->user_str);
		rc = SEPOL_ERR;
		goto exit;
	}

	if (role->types != NULL) {
		if (!ebitmap_get_bit(role->types, type->value)) {
			cil_log(CIL_ERR, "Type %s is invalid for role %s\n", ctx->type_str, ctx->role_str);
			rc = SEPOL_ERR;
			goto exit;
		}
	} else {
		cil_log(CIL_ERR, "No types associated with role %s\n", ctx->role_str);
		rc = SEPOL_ERR;
		goto exit;
	}

	/* Verify range only when anonymous */
	if (ctx->range->datum.name == NULL) {
		rc = __cil_verify_levelrange(db, ctx->range);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	for (curr = sensitivityorder->head; curr != NULL; curr = curr->next) {
		struct cil_sens *sens = curr->data;

		if (found == CIL_FALSE) {
			if (sens == user_low->sens) {
				found = CIL_TRUE;
			} else if (sens == ctx_low->sens) {
				cil_log(CIL_ERR, "Range %s is invalid for user %s\n", 
					ctx->range_str, ctx->user_str);
				rc = SEPOL_ERR;
				goto exit;
			}
		}

		if (found == CIL_TRUE) {
			if (sens == ctx_high->sens) {
				break;
			} else if (sens == user_high->sens) {
				cil_log(CIL_ERR, "Range %s is invalid for user %s\n", 
					ctx->range_str, ctx->user_str);
				rc = SEPOL_ERR;
				goto exit;
			}
		}
	}

	return SEPOL_OK;
exit:
	cil_log(CIL_ERR, "Invalid context\n");
	return rc;
}

int __cil_verify_named_context(struct cil_db *db, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	struct cil_context *ctx = node->data;

	rc = __cil_verify_context(db, ctx);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	return SEPOL_OK;
exit:
	cil_log(CIL_ERR, "Invalid named context at line %d of %s\n", node->line, node->path);
	return rc;
}

int __cil_verify_rule(struct cil_tree_node *node, struct cil_complex_symtab *symtab)
{

	int rc = SEPOL_ERR;
	struct cil_type_rule *typerule = NULL;
	struct cil_roletransition *roletrans = NULL;
	struct cil_complex_symtab_key ckey;

	switch (node->flavor) {
	case CIL_ROLETRANSITION: {
		roletrans = node->data;
		ckey.key1 = (intptr_t)roletrans->src;
		ckey.key2 = (intptr_t)roletrans->tgt;
		ckey.key3 = (intptr_t)roletrans->obj;
		ckey.key4 = CIL_ROLETRANSITION;
		break;
	}
	case CIL_TYPE_RULE: {
		typerule = node->data;
		ckey.key1 = (intptr_t)typerule->src;
		ckey.key2 = (intptr_t)typerule->tgt;
		ckey.key3 = (intptr_t)typerule->obj;
		ckey.key4 = (intptr_t)typerule->rule_kind;
		break;
	}
	default:
		break;
	}


	rc = cil_complex_symtab_insert(symtab, &ckey, NULL);
	if (rc == SEPOL_EEXIST) {
		struct cil_complex_symtab_datum *datum = NULL;
		cil_complex_symtab_search(symtab, &ckey, &datum);
		if (datum == NULL) {
			cil_log(CIL_ERR, "Duplicate rule defined on line %d of %s\n", 
				node->line, node->path);
			rc = SEPOL_ERR;
			goto exit;
		}
	}

	return SEPOL_OK;
exit:
	cil_log(CIL_ERR, "Invalid rule at line %d of %s\n", node->line, node->path);
	return rc;
}

int __cil_verify_booleanif_helper(struct cil_tree_node *node, __attribute__((unused)) uint32_t *finished, __attribute__((unused)) void *extra_args)
{
	int rc = SEPOL_ERR;
	struct cil_tree_node *rule_node = node;

	switch (rule_node->flavor) {
	case CIL_AVRULE: {
		struct cil_avrule *avrule = NULL;
		avrule = rule_node->data;
		if (avrule->rule_kind == CIL_AVRULE_NEVERALLOW) {
			cil_log(CIL_ERR, "Neverallow found in booleanif block at line %d or %s\n", 
				node->line, node->path);
			rc = SEPOL_ERR;
			goto exit;
		}
		break;
	}
	case CIL_TYPE_RULE: /*
	struct cil_type_rule *typerule = NULL;
	struct cil_tree_node *temp_node = NULL;
	struct cil_complex_symtab *symtab = extra_args;
	struct cil_complex_symtab_key ckey;
	struct cil_complex_symtab_datum datum;
		typerule = rule_node->data;

		ckey.key1 = (intptr_t)typerule->src;
		ckey.key2 = (intptr_t)typerule->tgt;
		ckey.key3 = (intptr_t)typerule->obj;
		ckey.key4 = (intptr_t)typerule->rule_kind;

		datum.data = node;

		rc = cil_complex_symtab_insert(symtab, &ckey, &datum);
		if (rc != SEPOL_OK) {
			goto exit;
		}

		for (temp_node = rule_node->next;
			temp_node != NULL;
			temp_node = temp_node->next) {

			if (temp_node->flavor == CIL_TYPE_RULE) {
				typerule = temp_node->data;
				if ((intptr_t)typerule->src == ckey.key1 &&
					(intptr_t)typerule->tgt == ckey.key2 &&
					(intptr_t)typerule->obj == ckey.key3 &&
					(intptr_t)typerule->rule_kind == ckey.key4) {
					cil_log(CIL_ERR, "Duplicate type rule found (line: %d)\n", node->line);
					rc = SEPOL_ERR;
					goto exit;
				}
			}
		}
		break;*/

		//TODO Fix duplicate type_rule detection
		break;
	case CIL_CALL:
		//Fall through to check content of call
		break;
	case CIL_TUNABLEIF:
		//Fall through
		break;
	case CIL_NAMETYPETRANSITION:
		/* While type transitions with file component are not allowed in
		   booleanif statements if they don't have "*" as the file. We
		   can't check that here. Or at least we won't right now. */
		break;
	default: {
		const char * flavor = cil_node_to_string(node);
		cil_log(CIL_ERR, "Invalid %s statement in booleanif at line %d of %s\n", 
				flavor, node->line, node->path);
		goto exit;
	}
	}

	rc = SEPOL_OK;
exit:
	return rc;
}

int __cil_verify_booleanif(struct cil_tree_node *node, struct cil_complex_symtab *symtab)
{
	int rc = SEPOL_ERR;
	struct cil_tree_node *cond_block = node->cl_head;

	while (cond_block != NULL) {
		rc = cil_tree_walk(cond_block->cl_head, __cil_verify_booleanif_helper, NULL, NULL, symtab);
		if (rc != SEPOL_OK) {
			goto exit;
		}
		cond_block = cond_block->next;
	}

	return SEPOL_OK;
exit:
	cil_log(CIL_ERR, "Invalid booleanif at line %d of %s\n", node->line, node->path);
	return rc;
}

int __cil_verify_netifcon(struct cil_db *db, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	struct cil_netifcon *netif = node->data;
	struct cil_context *if_ctx = netif->if_context;
	struct cil_context *pkt_ctx = netif->packet_context;

	/* Verify only when anonymous */
	if (if_ctx->datum.name == NULL) {
		rc = __cil_verify_context(db, if_ctx);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	/* Verify only when anonymous */
	if (pkt_ctx->datum.name == NULL) {
		rc = __cil_verify_context(db, pkt_ctx);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Invalid netifcon at line %d of %s\n", node->line, node->path);
	return rc;
}

int __cil_verify_genfscon(struct cil_db *db, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	struct cil_genfscon *genfs = node->data;
	struct cil_context *ctx = genfs->context;

	/* Verify only when anonymous */
	if (ctx->datum.name == NULL) {
		rc = __cil_verify_context(db, ctx);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Invalid genfscon at line %d of %s\n", node->line, node->path);
	return rc;
}

int __cil_verify_filecon(struct cil_db *db, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	struct cil_filecon *file = node->data;
	struct cil_context *ctx = file->context;

	if (ctx == NULL) {
		rc = SEPOL_OK;
		goto exit;
	}

	/* Verify only when anonymous */
	if (ctx->datum.name == NULL) {
		rc = __cil_verify_context(db, ctx);
		if (rc != SEPOL_OK) {
			cil_log(CIL_ERR, "Invalid filecon at line %d of %s\n", 
				node->line, node->path);
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	return rc;
}

int __cil_verify_nodecon(struct cil_db *db, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	struct cil_nodecon *nodecon = node->data;
	struct cil_context *ctx = nodecon->context;

	/* Verify only when anonymous */
	if (ctx->datum.name == NULL) {
		rc = __cil_verify_context(db, ctx);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Invalid nodecon at line %d of %s\n", node->line, node->path);
	return rc;
}

int __cil_verify_portcon(struct cil_db *db, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	struct cil_portcon *port = node->data;
	struct cil_context *ctx = port->context;

	/* Verify only when anonymous */
	if (ctx->datum.name == NULL) {
		rc = __cil_verify_context(db, ctx);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Invalid portcon at line %d of %s\n", node->line, node->path);
	return rc;
}

int __cil_verify_pirqcon(struct cil_db *db, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	struct cil_pirqcon *pirq = node->data;
	struct cil_context *ctx = pirq->context;

	/* Verify only when anonymous */
	if (ctx->datum.name == NULL) {
		rc = __cil_verify_context(db, ctx);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Invalid pirqcon at line %d of %s\n", node->line, node->path);
	return rc;
}

int __cil_verify_iomemcon(struct cil_db *db, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	struct cil_iomemcon *iomem = node->data;
	struct cil_context *ctx = iomem->context;

	/* Verify only when anonymous */
	if (ctx->datum.name == NULL) {
		rc = __cil_verify_context(db, ctx);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Invalid iomemcon at line %d of %s\n", node->line, node->path);
	return rc;
}

int __cil_verify_ioportcon(struct cil_db *db, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	struct cil_ioportcon *ioport = node->data;
	struct cil_context *ctx = ioport->context;

	/* Verify only when anonymous */
	if (ctx->datum.name == NULL) {
		rc = __cil_verify_context(db, ctx);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Invalid ioportcon at line %d of %s\n", node->line, node->path);
	return rc;
}

int __cil_verify_pcidevicecon(struct cil_db *db, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	struct cil_pcidevicecon *pcidev = node->data;
	struct cil_context *ctx = pcidev->context;

	/* Verify only when anonymous */
	if (ctx->datum.name == NULL) {
		rc = __cil_verify_context(db, ctx);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Invalid pcidevicecon at line %d of %s\n", node->line, node->path);
	return rc;
}

int __cil_verify_fsuse(struct cil_db *db, struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	struct cil_fsuse *fsuse = node->data;
	struct cil_context *ctx = fsuse->context;

	/* Verify only when anonymous */
	if (ctx->datum.name == NULL) {
		rc = __cil_verify_context(db, ctx);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Invalid fsuse at line %d of %s\n", node->line, node->path);
	return rc;
}

int __cil_verify_class(struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	struct cil_class *class = node->data;

	if (class->common != NULL) {
		struct cil_common *common = class->common;
		struct cil_tree_node *common_node = common->datum.nodes->head->data;
		struct cil_tree_node *curr_com_perm = NULL;

		for (curr_com_perm = common_node->cl_head;
			curr_com_perm != NULL;
			curr_com_perm = curr_com_perm->next) {
			struct cil_perm *com_perm = curr_com_perm->data;
			struct cil_tree_node *curr_class_perm = NULL;

			for (curr_class_perm = node->cl_head;
				curr_class_perm != NULL;
				curr_class_perm = curr_class_perm->next) {
				struct cil_perm *class_perm = curr_class_perm->data;

				if (!strcmp(com_perm->datum.name, class_perm->datum.name)) {
					cil_log(CIL_ERR, "Duplicate permissions between %s common and class declarations\n", class_perm->datum.name);
					goto exit;
				}
			}
		}
	}

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Invalid class at line %d of %s\n", node->line, node->path);
	return rc;
}

int __cil_verify_policycap(struct cil_tree_node *node)
{
	int rc;
	struct cil_policycap *polcap = node->data;

	rc = sepol_polcap_getnum((const char*)polcap->datum.name);
	if (rc == SEPOL_ERR) {
		goto exit;
	}

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Invalid policycap (%s) at line %d of %s\n", 
		(const char*)polcap->datum.name, node->line, node->path);
	return rc;
}

int __cil_verify_helper(struct cil_tree_node *node, __attribute__((unused)) uint32_t *finished, void *extra_args)
{
	int rc = SEPOL_ERR;
	int *avrule_cnt = 0;
	int *nseuserdflt = 0;
	int state = 0;
	int *pass = 0;
	struct cil_args_verify *args = extra_args;
	struct cil_complex_symtab *csymtab = NULL;
	struct cil_db *db = NULL;

	if (node == NULL || extra_args == NULL) {
		goto exit;
	}

	db = args->db;
	avrule_cnt = args->avrule_cnt;
	nseuserdflt = args->nseuserdflt;
	csymtab = args->csymtab;
	pass = args->pass;

	if (node->flavor == CIL_OPTIONAL) {
		state = ((struct cil_symtab_datum *)node->data)->state;
		if (state == CIL_STATE_DISABLED) {
			*finished = CIL_TREE_SKIP_HEAD;
		}
		rc = SEPOL_OK;
		goto exit;
	} else if (node->flavor == CIL_MACRO) {
		*finished = CIL_TREE_SKIP_HEAD;
		rc = SEPOL_OK;
		goto exit;
	} else if (node->flavor == CIL_BLOCK) {
		struct cil_block *blk = node->data;
		if (blk->is_abstract == CIL_TRUE) {
			*finished = CIL_TREE_SKIP_HEAD;
		}
		rc = SEPOL_OK;
		goto exit;
	}

	switch (*pass) {
	case 0: {
		switch (node->flavor) {
		case CIL_USER:
			rc = __cil_verify_user(db, node);
			break;
		case CIL_SELINUXUSERDEFAULT:
			(*nseuserdflt)++;
			rc = SEPOL_OK;
			break;
		case CIL_ROLE:
			rc = __cil_verify_role(node);
			break;
		case CIL_TYPE:
			rc = __cil_verify_type(node);
			break;
		case CIL_AVRULE:
			(*avrule_cnt)++;
			rc = SEPOL_OK;
			break;
		case CIL_ROLETRANSITION:
			rc = SEPOL_OK; //TODO __cil_verify_rule doesn't work quite right
			//rc = __cil_verify_rule(node, csymtab);
			break;
		case CIL_TYPE_RULE:
			rc = SEPOL_OK; //TODO __cil_verify_rule doesn't work quite right
			//rc = __cil_verify_rule(node, csymtab);
			break;
		case CIL_BOOLEANIF:
			rc = __cil_verify_booleanif(node, csymtab);
			*finished = CIL_TREE_SKIP_HEAD;
			break;
		case CIL_LEVELRANGE:
			rc = __cil_verify_named_levelrange(db, node);
			break;
		case CIL_CLASS:
			rc = __cil_verify_class(node);
			break;
		case CIL_POLICYCAP:
			rc = __cil_verify_policycap(node);
			break;
		default:
			rc = SEPOL_OK;
			break;
		}
		break;
	}
	case 1:	{
		switch (node->flavor) {
		case CIL_CONTEXT:
			rc = __cil_verify_named_context(db, node);
			break;
		case CIL_NETIFCON:
			rc = __cil_verify_netifcon(db, node);
			break;
		case CIL_GENFSCON:
			rc = __cil_verify_genfscon(db, node);
			break;
		case CIL_FILECON:
			rc = __cil_verify_filecon(db, node);
			break;
		case CIL_NODECON:
			rc = __cil_verify_nodecon(db, node);
			break;
		case CIL_PORTCON:
			rc = __cil_verify_portcon(db, node);
			break;
		case CIL_PIRQCON:
			rc = __cil_verify_pirqcon(db, node);
			break;
		case CIL_IOMEMCON:
			rc = __cil_verify_iomemcon(db, node);
			break;
		case CIL_IOPORTCON:
			rc = __cil_verify_ioportcon(db, node);
			break;
		case CIL_PCIDEVICECON:
			rc = __cil_verify_pcidevicecon(db, node);
			break;
		case CIL_FSUSE:
			rc = __cil_verify_fsuse(db, node);
			break;
		case CIL_RANGETRANSITION:
			rc = SEPOL_OK;
			break;
		default:
			rc = SEPOL_OK;
			break;
		}
		break;
	}
	default:
		rc = SEPOL_ERR;
	}

exit:
	return rc;
}
