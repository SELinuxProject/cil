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

#include <sepol/policydb/conditional.h>
#include <sepol/errcodes.h>

#include "cil.h"
#include "cil_log.h"
#include "cil_mem.h"
#include "cil_tree.h"
#include "cil_list.h"

#include "cil_verify_internal.h"

int __cil_verify_name(const char *name)
{
	int rc = SEPOL_ERR;
	int len = strlen(name);
	int i = 0;

	if (len >= CIL_MAX_NAME_LENGTH) {
		cil_log(CIL_ERR, "Name length greater than max name length of %d", CIL_MAX_NAME_LENGTH);
		rc = SEPOL_ERR;
		goto exit;
	}

	for (i = 0; i < len; i++) {
		if (!isalnum(name[i]) && name[i] != '_') {
			cil_log(CIL_ERR, "Invalid character %c in %s\n", name[i], name);
			goto exit;
		}
	}
	return SEPOL_OK;

exit:
	return rc;
}

int __cil_verify_syntax(struct cil_tree_node *parse_current, enum cil_syntax s[], int len)
{
	int rc = SEPOL_ERR;
	int num_extras = 0;
	struct cil_tree_node *c = parse_current;
	int i = 0;
	while (i < len) {
		if ((s[i] & SYM_END) && c == NULL) {
			break;
		}

		if (s[i] & SYM_N_LISTS || s[i] & SYM_N_STRINGS) {
			if (c == NULL) {
				if (num_extras > 0) {
					break;
				} else {
					goto exit;
				}
			} else if ((s[i] & SYM_N_LISTS) && (c->data == NULL && c->cl_head != NULL)) {
				c = c->next;
				num_extras++;
				continue;
			} else if ((s[i] & SYM_N_STRINGS) && (c->data != NULL && c->cl_head == NULL)) {
				c = c->next;
				num_extras++;
				continue;
			}
		}

		if (c == NULL) {
			goto exit;
		}

		if (s[i] & SYM_STRING) {
			if (c->data != NULL && c->cl_head == NULL) {
				c = c->next;
				i++;
				continue;
			}
		}

		if (s[i] & SYM_LIST) {
			if (c->data == NULL && c->cl_head != NULL) {
				c = c->next;
				i++;
				continue;
			}
		}

		if (s[i] & SYM_EMPTY_LIST) {
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
	return rc;
}

int __cil_verify_constrain_expr(struct cil_tree_node *current, enum cil_flavor flavor, struct cil_conditional *cond, struct cil_list *stack)
{
	int rc = SEPOL_ERR;
	struct cil_conditional *opcond = cond;
	struct cil_conditional *lcond = NULL;
	struct cil_conditional *rcond = NULL;
	struct cil_list_item *opnode = NULL;
	struct cil_list_item *lnode = NULL;
	struct cil_list_item *rnode = NULL;
	char * lstr = NULL;
	char * rstr = NULL;
	int riskeyword = 0;

	opcond->str = cil_strdup(current->data);

	cil_list_item_init(&opnode);

	opnode->data = opcond;
	opnode->flavor = CIL_COND;

	rc = cil_list_prepend_item(stack, opnode);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	cil_list_item_init(&lnode);

	cil_conditional_init(&lcond);

	cil_list_item_init(&rnode);

	cil_conditional_init(&rcond);

	lstr = current->next->data;
	rstr = current->next->next->data;

	lnode->data = lcond;
	rnode->data = rcond;
	lnode->flavor = CIL_COND;
	rnode->flavor = CIL_COND;

	rc = cil_list_prepend_item(stack, rnode);
	if (rc != SEPOL_OK) {
		goto exit;
	}
	rc = cil_list_prepend_item(stack, lnode);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	if (strcmp(lstr, CIL_KEY_CONS_T1) && strcmp(lstr, CIL_KEY_CONS_T2) &&
	    strcmp(lstr, CIL_KEY_CONS_R1) && strcmp(lstr, CIL_KEY_CONS_R2) &&
	    strcmp(lstr, CIL_KEY_CONS_U1) && strcmp(lstr, CIL_KEY_CONS_U2) &&
	    strcmp(lstr, CIL_KEY_CONS_L1) && strcmp(lstr, CIL_KEY_CONS_L2) &&
	    strcmp(lstr, CIL_KEY_CONS_H1)) {
		cil_log(CIL_ERR, "Left hand side must be valid keyword\n");
		rc = SEPOL_ERR;
		goto exit;
	}

	if (!strcmp(rstr, CIL_KEY_CONS_T1) || !strcmp(rstr, CIL_KEY_CONS_T2) ||
	    !strcmp(rstr, CIL_KEY_CONS_R1) || !strcmp(rstr, CIL_KEY_CONS_R2) ||
	    !strcmp(rstr, CIL_KEY_CONS_U1) || !strcmp(rstr, CIL_KEY_CONS_U2) ||
	    !strcmp(rstr, CIL_KEY_CONS_L1) || !strcmp(rstr, CIL_KEY_CONS_L2) ||
	    !strcmp(rstr, CIL_KEY_CONS_H1) || !strcmp(rstr, CIL_KEY_CONS_H2)) {
		riskeyword = 1;
	}

	/* t1 op something */
	if (!strcmp(lstr, CIL_KEY_CONS_T1)) {
		lcond->flavor = CIL_CONS_T1;
		if (!strcmp(rstr, CIL_KEY_CONS_T2)) {
			rcond->flavor = CIL_CONS_T2;
		} else {
			if (riskeyword) {
				cil_log(CIL_ERR, "Keyword %s not allowed on right side of expression\n", rstr);
				rc = SEPOL_ERR;
				goto exit;
			}
			rcond->flavor = CIL_TYPE;
		}
		if (opcond->flavor != CIL_EQ && opcond->flavor != CIL_NEQ) {
			rc = SEPOL_ERR;
			goto exit;
		}

	/* t2 op something */
	} else if (!strcmp(lstr, CIL_KEY_CONS_T2)) {
		lcond->flavor = CIL_CONS_T2;
		if (riskeyword) {
			cil_log(CIL_ERR, "Keyword %s not allowed on right side of expression\n", rstr);
			rc = SEPOL_ERR;
			goto exit;
		}
		if (opcond->flavor != CIL_EQ && opcond->flavor != CIL_NEQ) {
			rc = SEPOL_ERR;
			goto exit;
		}
		rcond->flavor = CIL_TYPE;

	/* r1 op something */
	} else if (!strcmp(lstr, CIL_KEY_CONS_R1)) {
		lcond->flavor = CIL_CONS_R1;
		if (!strcmp(rstr, CIL_KEY_CONS_R2)) {
			rcond->flavor = CIL_CONS_R2;
		} else {
			if (riskeyword) {
				cil_log(CIL_ERR, "Keyword %s not allowed on right side of expression\n", rstr);
				rc = SEPOL_ERR;
				goto exit;
			}
			rcond->flavor = CIL_ROLE;
			if (opcond->flavor != CIL_EQ && opcond->flavor != CIL_NEQ) {
				rc = SEPOL_ERR;
				goto exit;
			}
		}

	/* r2 op something */
	} else if (!strcmp(lstr, CIL_KEY_CONS_R2)) {
		lcond->flavor = CIL_CONS_R2;
		if (riskeyword) {
			cil_log(CIL_ERR, "Keyword %s not allowed on right side of expression\n", rstr);
			rc = SEPOL_ERR;
			goto exit;
		}
		rcond->flavor = CIL_ROLE;
		if (opcond->flavor != CIL_EQ && opcond->flavor != CIL_NEQ) {
			rc = SEPOL_ERR;
			goto exit;
		}

	/* u1 op something */
	} else if (!strcmp(lstr, CIL_KEY_CONS_U1)) {
		lcond->flavor = CIL_CONS_U1;
		if (!strcmp(rstr, CIL_KEY_CONS_U2)) {
			rcond->flavor = CIL_CONS_U2;
		} else {
			if (riskeyword) {
				cil_log(CIL_ERR, "Keyword %s not allowed on right side of expression\n", rstr);
				rc = SEPOL_ERR;
				goto exit;
			}
			rcond->flavor = CIL_USER;
		}
		if (opcond->flavor != CIL_EQ && opcond->flavor != CIL_NEQ) {
			rc = SEPOL_ERR;
			goto exit;
		}

	/* u2 op something */
	} else if (!strcmp(lstr, CIL_KEY_CONS_U2)) {
		lcond->flavor = CIL_CONS_U2;
		if (riskeyword) {
			cil_log(CIL_ERR, "Keyword %s not allowed on right side of expression\n", rstr);
			rc = SEPOL_ERR;
			goto exit;
		}
		rcond->flavor = CIL_USER;
		if (opcond->flavor != CIL_EQ && opcond->flavor != CIL_NEQ) {
			rc = SEPOL_ERR;
			goto exit;
		}

	/* mls specific levels */
	} else if (flavor == CIL_MLSCONSTRAIN) {

		/* l1 op something */
		if (!strcmp(lstr, CIL_KEY_CONS_L1)) {
			lcond->flavor = CIL_CONS_L1;
			if (!strcmp(rstr, CIL_KEY_CONS_L2)) {
				rcond->flavor = CIL_CONS_L2;
			} else if (!strcmp(rstr, CIL_KEY_CONS_H1)) {
				rcond->flavor = CIL_CONS_H1;
			} else if (!strcmp(rstr, CIL_KEY_CONS_H2)) {
				rcond->flavor = CIL_CONS_H2;
			} else {
				cil_log(CIL_ERR, "Right side of expression must be correct keyword\n");
				rc = SEPOL_ERR;
				goto exit;
			}

		/* l2 op something */
		} else if (!strcmp(lstr, CIL_KEY_CONS_L2)) {
			lcond->flavor = CIL_CONS_L2;
			if (!strcmp(rstr, CIL_KEY_CONS_H2)) {
				rcond->flavor = CIL_CONS_H2;
			} else {
				cil_log(CIL_ERR, "Right side of expression must be correct keyword\n");
				rc = SEPOL_ERR;
				goto exit;
			}

		/* h1 op something */
		} else if (!strcmp(lstr, CIL_KEY_CONS_H1)) {
			lcond->flavor = CIL_CONS_H1;
			if (!strcmp(rstr, CIL_KEY_CONS_L2)) {
				rcond->flavor = CIL_CONS_L2;
			} else if (!strcmp(rstr, CIL_KEY_CONS_H2)) {
				rcond->flavor = CIL_CONS_H2;
			} else {
				cil_log(CIL_ERR, "Right side of expression must be correct keyword\n");
				rc = SEPOL_ERR;
				goto exit;
			}
		} else {
			cil_log(CIL_ERR, "Unknown left hand side\n");
			rc = SEPOL_ERR;
			goto exit;
		}
	} else {
		cil_log(CIL_ERR, "Unknown left hand side\n");
		rc = SEPOL_ERR;
		goto exit;
	}

	lcond->str = cil_strdup(lstr);
	rcond->str = cil_strdup(rstr);

	return SEPOL_OK;

exit:
	return rc;
}

int __cil_verify_expr_oper_flavor(const char *key, struct cil_conditional *cond, enum cil_flavor flavor)
{
	int rc = SEPOL_ERR;

	if (!strcmp(key, CIL_KEY_AND)) {
		cond->flavor = CIL_AND;
	} else if (!strcmp(key, CIL_KEY_OR)) {
		cond->flavor = CIL_OR;
	} else if (!strcmp(key, CIL_KEY_NOT)) {
		cond->flavor = CIL_NOT;
	} else if (!strcmp(key, CIL_KEY_EQ)) {
		cond->flavor = CIL_EQ;
	} else if (!strcmp(key, CIL_KEY_NEQ)) {
		cond->flavor = CIL_NEQ;
	} else if (flavor != CIL_CONSTRAIN && flavor != CIL_MLSCONSTRAIN && !strcmp(key, CIL_KEY_XOR)) {
		cond->flavor = CIL_XOR;
	} else if (flavor == CIL_CONSTRAIN || flavor == CIL_MLSCONSTRAIN) {
		if (!strcmp(key, CIL_KEY_CONS_DOM)) {
			cond->flavor = CIL_CONS_DOM;
		} else if (!strcmp(key, CIL_KEY_CONS_DOMBY)) {
			cond->flavor = CIL_CONS_DOMBY;
		} else if (!strcmp(key, CIL_KEY_CONS_INCOMP)) {
			cond->flavor = CIL_CONS_INCOMP;
		} else 	{
			rc = SEPOL_ERR;
			goto exit;
		}
	} else {
		rc = SEPOL_ERR;
		goto exit;
	}

	return SEPOL_OK;

exit:
	return rc;
}

/* Parameters:
 * node:	current node in tree
 * nflavor:	current node flavor
 * eflavor:	current expression item flavor
 * */
int __cil_verify_expr_syntax(struct cil_tree_node *node, enum cil_flavor nflavor, enum cil_flavor eflavor)
{
	int rc = SEPOL_ERR;

	if (nflavor == CIL_CONSTRAIN || nflavor == CIL_MLSCONSTRAIN) {
		if (eflavor == CIL_NOT) {
			enum cil_syntax syntax[] = {
				SYM_STRING,
				SYM_LIST,
				SYM_END
			};
			int syntax_len = sizeof(syntax)/sizeof(*syntax);
			rc = __cil_verify_syntax(node, syntax, syntax_len);
			if (rc != SEPOL_OK) {
				goto exit;
			}
		} else if (eflavor == CIL_AND || eflavor == CIL_OR) {
			enum cil_syntax syntax[] = {
				SYM_STRING,
				SYM_LIST,
				SYM_LIST,
				SYM_END
			};
			int syntax_len = sizeof(syntax)/sizeof(*syntax);
			rc = __cil_verify_syntax(node, syntax, syntax_len);
			if (rc != SEPOL_OK) {
				goto exit;
			}
		} else {
			enum cil_syntax syntax[] = {
				SYM_STRING,
				SYM_STRING,
				SYM_STRING,
				SYM_END
			};
			int syntax_len = sizeof(syntax)/sizeof(*syntax);
			rc = __cil_verify_syntax(node, syntax, syntax_len);
			if (rc != SEPOL_OK) {
				goto exit;
			}
		}
	} else {
		if (eflavor == CIL_NOT) {
			enum cil_syntax syntax[] = {
				SYM_STRING,
				SYM_STRING | SYM_LIST,
				SYM_END
			};
			int syntax_len = sizeof(syntax)/sizeof(*syntax);
			rc = __cil_verify_syntax(node, syntax, syntax_len);
			if (rc != SEPOL_OK) {
				goto exit;
			}
		} else {
			enum cil_syntax syntax[] = {
				SYM_STRING,
				SYM_STRING | SYM_LIST,
				SYM_STRING | SYM_LIST,
				SYM_END
			};
			int syntax_len = sizeof(syntax)/sizeof(*syntax);
			rc = __cil_verify_syntax(node, syntax, syntax_len);
			if (rc != SEPOL_OK) {
				goto exit;
			}
		}
	}

	return SEPOL_OK;

exit:
	return rc;
}

int __cil_verify_ranges(struct cil_list *list)
{
	int rc = SEPOL_ERR;
	struct cil_list_item *curr = NULL;
	struct cil_list_item *range = NULL;

	if (list == NULL || list->head == NULL) {
		goto exit;
	}

	curr = list->head;

	while (curr != NULL) {
		/* range */
		if (curr->flavor == CIL_LIST) {
			range = ((struct cil_list*)curr->data)->head;
			if (range == NULL || range->next == NULL || range->next->next != NULL) {
				goto exit;
			}
		}
		curr = curr->next;
	}

	return SEPOL_OK;

exit:
	return rc;
}

int __cil_verify_order_node_helper(struct cil_tree_node *node, uint32_t *finished, void *extra_args)
{
	struct cil_args_verify_order *args;
	struct cil_list *order = NULL;
	struct cil_list_item *ordered = NULL;
	uint32_t *found = NULL;
	uint32_t *empty = NULL;
	uint32_t *flavor = NULL;
	int rc = SEPOL_ERR;

	if (node == NULL || extra_args == NULL) {
		goto exit;
	}

	args = extra_args;
	order = args->order;
	ordered = args->ordered;
	found = args->found;
	empty = args->empty;
	flavor = args->flavor;

        if (node->flavor == CIL_OPTIONAL) {
                struct cil_optional *opt = node->data;
                if (opt->datum.state != CIL_STATE_ENABLED) {
                        *finished = CIL_TREE_SKIP_HEAD;
                        rc = SEPOL_OK;
                        goto exit;
                }
        } else if (node->flavor == CIL_MACRO) {
                *finished = CIL_TREE_SKIP_HEAD;
                rc = SEPOL_OK;
                goto exit;
        }

	if (node->flavor == *flavor) {
		if (*empty) {
			cil_log(CIL_ERR, "Error: ordering is empty\n");
			goto exit;
		}
		ordered = order->head;
		while (ordered != NULL) {
			if (ordered->data == node->data) {
				*found = 1;
				break;
			}
			ordered = ordered->next;
		}
		if (!(*found)) {
			cil_log(CIL_ERR, "Item not ordered: %s\n", ((struct cil_symtab_datum*)node->data)->name);
			goto exit;
		}
		*found = 0;
	}

	return SEPOL_OK;

exit:
	return rc;
}

int __cil_verify_order(struct cil_list *order, struct cil_tree_node *current, enum cil_flavor flavor)
{

	struct cil_list_item *ordered = NULL;
	struct cil_args_verify_order extra_args;
	uint32_t found = 0;
	uint32_t empty = 0;
	int rc = SEPOL_ERR;

	if (order == NULL || current == NULL) {
		goto exit;
	}

	if (order->head == NULL) {
		empty = 1;
	} else {
		ordered = order->head;
		if (ordered->next != NULL) {
			cil_log(CIL_ERR, "Disjoint category ordering exists\n");
			goto exit;
		}

		if (ordered->data != NULL) {
			order->head = ((struct cil_list*)ordered->data)->head;
		}
	}

	extra_args.order = order;
	extra_args.ordered = ordered;
	extra_args.found = &found;
	extra_args.empty = &empty;
	extra_args.flavor = &flavor;

	rc = cil_tree_walk(current, __cil_verify_order_node_helper, NULL, NULL, &extra_args);
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Failed to verify category order\n");
		goto exit;
	}

	return SEPOL_OK;

exit:
	return rc;
}

int __cil_verify_catrange(struct cil_db *db, struct cil_catrange *catrange, struct cil_cat *cat)
{
	struct cil_list_item *cat_item = NULL;
	int rc = SEPOL_ERR;

	if (catrange->cat_low == cat || catrange->cat_high == cat) {
		rc = SEPOL_OK;
		goto exit;
	}

	for (cat_item = db->catorder->head; cat_item != NULL; cat_item = cat_item->next) {
		if (cat_item->data == catrange->cat_low) {
			break;
		}
	}

	if (cat_item == NULL) {
		rc = SEPOL_ERR;
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

	return SEPOL_ERR;

exit:
	return rc;
}

int __cil_verify_senscat(struct cil_db *db, struct cil_sens *sens, struct cil_cat *cat)
{
	struct cil_list_item *cat_item = NULL;
	struct cil_list_item *catset_item = NULL;
	int rc = SEPOL_ERR;

	for (catset_item = sens->catsets->head; catset_item != NULL; catset_item = catset_item->next) {
		struct cil_catset *catset = catset_item->data;
		for (cat_item = catset->cat_list->head; cat_item != NULL; cat_item = cat_item->next) {
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
				goto exit;
			}
		}
	}

	return SEPOL_ERR;

exit:
	return rc;
}

int __cil_verify_senscatset(struct cil_db *db, struct cil_sens *sens, struct cil_catset *catset)
{
	struct cil_list_item *catset_item = NULL;
	int rc = SEPOL_OK;

	for (catset_item = catset->cat_list->head; catset_item != NULL; catset_item = catset_item->next) {
		switch (catset_item->flavor) {
		case CIL_CAT: {
			struct cil_cat *cat = catset_item->data;
			rc = __cil_verify_senscat(db, sens, cat);
			if (rc != SEPOL_OK) {
				cil_log(CIL_ERR, "Category %s can't be used with sensitivity %s\n", cat->datum.name, sens->datum.name);
				goto exit;
			}
			break;
		}
		case CIL_CATRANGE: {
			struct cil_catrange *catrange = catset_item->data;
			struct cil_list_item *catorder = NULL;

			for (catorder = db->catorder->head; catorder != NULL; catorder = catorder->next) {
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
					cil_log(CIL_ERR, "Category %s can't be used with sensitivity %s\n", cat->datum.name, sens->datum.name);
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
	return rc;
}

int __cil_verify_levelrange_dominance(struct cil_db *db, struct cil_sens *low, struct cil_sens *high)
{
	struct cil_list_item *curr = db->dominance->head;
	int found = CIL_FALSE;
	int rc = SEPOL_ERR;

	while (curr != NULL) {
		if (curr->data == low) {
			found = CIL_TRUE;
		}

		if ((found == CIL_TRUE) && (curr->data == high)) {
			break;
		}

		curr = curr->next;
	}

	if (found != CIL_TRUE || curr == NULL) {
		goto exit;
	}

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Failed to verify levelrange dominance\n");
	return rc;

}

int __cil_verify_cat_in_catset(struct cil_db *db, struct cil_cat *cat, struct cil_catset *set)
{
	int rc = SEPOL_ERR;
	struct cil_list_item *set_curr = NULL;
	int found = CIL_FALSE;

	for (set_curr = set->cat_list->head; set_curr != NULL && found != CIL_TRUE; set_curr = set_curr->next) {
		switch (set_curr->flavor) {
		case CIL_CAT:
			if (cat == set_curr->data) {
				found = CIL_TRUE;
			}
			break;
		case CIL_CATRANGE:
			rc = __cil_verify_catrange(db, set_curr->data, cat);
			if (rc == SEPOL_OK) {
				found = CIL_TRUE;
			}
			break;
		default:
			rc = SEPOL_ERR;
			goto exit;
		}
	}

	if (found != CIL_TRUE) {
		goto exit;
	}

	return SEPOL_OK;
exit:
	cil_log(CIL_ERR, "Failed to find cat in catset\n");
	return rc;
}

int __cil_verify_levelrange_cats(struct cil_db *db, struct cil_catset *low, struct cil_catset *high)
{
	int rc = SEPOL_ERR;
	struct cil_list_item *low_curr = NULL;
	struct cil_list_item *order_curr = NULL;
	struct cil_cat *range_low = NULL;
	struct cil_cat *range_high = NULL;
	int found = CIL_FALSE;

	for (low_curr = low->cat_list->head; low_curr != NULL; low_curr = low_curr->next) {
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
			order_curr = db->catorder->head;
			while (order_curr != NULL && order_curr->data != range_high) {
				if (order_curr->data == range_low) {
					found = CIL_TRUE;
				}

				if (found == CIL_TRUE) {
					rc = __cil_verify_cat_in_catset(db, order_curr->data, high);
					if (rc != SEPOL_OK) {
						goto exit;
					}
				}

				order_curr = order_curr->next;
			}
			break;
		default:
			rc = SEPOL_ERR;
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Failed to verify levelrange categories\n");
	return rc;
}

int __cil_verify_levelrange(struct cil_db *db, struct cil_levelrange *lr)
{
	int rc = SEPOL_ERR;

	rc = __cil_verify_levelrange_dominance(db, lr->low->sens, lr->high->sens);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	rc = __cil_verify_levelrange_cats(db, lr->low->catset, lr->high->catset);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Failed to verify levelrange\n");
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

	rc = SEPOL_OK;
exit:
	return rc;
}

int __cil_add_level_sens_to_symtab(struct cil_level *lvl, symtab_t *senstab)
{
	int rc = SEPOL_ERR;
	char *key = NULL;
	struct cil_symtab_datum *sensdatum = NULL;

	sensdatum = cil_malloc(sizeof(*sensdatum));
	cil_symtab_datum_init(sensdatum);

	key = lvl->sens->datum.name;
	rc = cil_symtab_insert(senstab, key, sensdatum, NULL);
	if (rc != SEPOL_OK) {
		if ( rc == SEPOL_EEXIST) {
			cil_symtab_datum_destroy(*sensdatum);
			free(sensdatum);
		} else {
			cil_log(CIL_ERR, "Failed to insert level sensitivity into symtab\n");
			goto exit;
		}
	}

	rc = SEPOL_OK;
exit:
	return rc;
}

int __cil_add_levelrange_sens_to_symtab(struct cil_levelrange *lvlrange, symtab_t *senstab)
{
	int rc = SEPOL_ERR;

	rc = __cil_add_level_sens_to_symtab(lvlrange->low, senstab);
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Failed to add low level sens to symtab\n");
		goto exit;
	}

	rc = __cil_add_level_sens_to_symtab(lvlrange->high, senstab);
	if (rc !=  SEPOL_OK) {
		cil_log(CIL_ERR, "Failed to add high level sens to symtab\n");
		goto exit;
	}

exit:
	return rc;
}

int __cil_verify_user(struct cil_db *db, struct cil_tree_node *node, symtab_t *senstab)
{
	int rc = SEPOL_ERR;
	struct cil_user *user = node->data;

	if (user->dftlevel == NULL) {
		cil_log(CIL_ERR, "User does not have a default level: %s", user->datum.name);
		goto exit;
	} else if (user->range == NULL) {
		cil_log(CIL_ERR, "User does not have a level range: %s", user->datum.name);
		goto exit;
	} else if (user->prefix == NULL) {
		cil_log(CIL_ERR, "User does not have a prefix: %s\n", user->datum.name);
		goto exit;
	} else if (user->bounds != NULL) {
		struct cil_user *bnds = user->bounds;
		if (user == bnds) {
			cil_log(CIL_ERR, "User cannot bound self: %s", user->datum.name);
			goto exit;
		} else if (bnds->bounds != NULL) {
			bnds = bnds->bounds;
			if (user == bnds) {
				cil_log(CIL_ERR, "Circular userbounds found: %s\n", user->datum.name);
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

	rc = __cil_add_level_sens_to_symtab(user->dftlevel, senstab);
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Failed to add user default level sensitivty to symtab\n");
		goto exit;
	}

	rc = __cil_add_levelrange_sens_to_symtab(user->range, senstab);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	rc = SEPOL_OK;
exit:
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
				cil_log(CIL_ERR, "Circular rolebounds found: %s\n", bnding->datum.name);
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

	rc = SEPOL_OK;
exit:
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
				cil_log(CIL_ERR, "Circular typebounds found: %s\n", bnding->datum.name);
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

	rc = SEPOL_OK;
exit:
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
	struct cil_list *dominance = db->dominance;
	struct cil_list_item *curr = NULL;
	int found = CIL_FALSE;

	if (user->roles != NULL) {
		for (curr = user->roles->head; curr != NULL; curr = curr->next) {
			struct cil_role *userrole = curr->data;
			if (userrole == role) {
				break;
			}
		}

		if (curr == NULL) {
			cil_log(CIL_ERR, "Invalid role for specified user\n");
			rc = SEPOL_ERR;
			goto exit;
		}
	} else {
		cil_log(CIL_ERR, "No roles given to the specified user\n");
		rc = SEPOL_ERR;
		goto exit;
	}

	if (role->types != NULL) {
		for (curr = role->types->head; curr != NULL; curr = curr->next) {
			struct cil_type *roletype = curr->data;
			if (roletype == type) {
				break;
			}
		}

		if (curr == NULL) {
			cil_log(CIL_ERR, "Invalid type for specified role\n");
			rc = SEPOL_ERR;
			goto exit;
		}
	} else {
		cil_log(CIL_ERR, "No types given to the specified role\n");
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

	for (curr = dominance->head; curr != NULL; curr = curr->next) {
		struct cil_sens *sens = curr->data;

		if (found == CIL_FALSE) {
			if (sens == user_low->sens) {
				found = CIL_TRUE;
			} else if (sens == ctx_low->sens) {
				cil_log(CIL_ERR, "Invalid context level range for specified user\n");
				rc = SEPOL_ERR;
				goto exit;
			}
		}

		if (found == CIL_TRUE) {
			if (sens == ctx_high->sens) {
				break;
			} else if (sens == user_high->sens) {
				cil_log(CIL_ERR, "Invalid context level range for specified user\n");
				rc = SEPOL_ERR;
				goto exit;
			}
		}
	}

	rc = SEPOL_OK;
exit:
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

exit:
	return rc;
}

int __cil_verify_type_rule(struct cil_tree_node *node, struct cil_complex_symtab *symtab)
{

	int rc = SEPOL_ERR;
	struct cil_type_rule *typerule = node->data;
	struct cil_complex_symtab_key ckey;

	ckey.key1 = (intptr_t)typerule->src;
	ckey.key2 = (intptr_t)typerule->tgt;
	ckey.key3 = (intptr_t)typerule->obj;
	ckey.key4 = (intptr_t)typerule->rule_kind;

	rc = cil_complex_symtab_insert(symtab, &ckey, NULL);
	if (rc != SEPOL_OK) {
		if (rc == SEPOL_EEXIST) {
			struct cil_complex_symtab_datum *datum = NULL;
			rc = cil_complex_symtab_search(symtab, &ckey, &datum);
			if (rc != SEPOL_OK) {
				goto exit;
			}
			if (datum == NULL) {
				rc = SEPOL_ERR;
				goto exit;
			}
		}
		goto exit;
	}

	rc = SEPOL_OK;
exit:
	return rc;
}

int __cil_verify_booleanif(struct cil_tree_node *node, struct cil_complex_symtab *symtab)
{
	int rc = SEPOL_ERR;
	struct cil_tree_node *cond_block = node->cl_head;
	struct cil_tree_node *rule_node = NULL;
	struct cil_tree_node *temp_node = NULL;
	struct cil_avrule *avrule = NULL;
	struct cil_type_rule *typerule = NULL;
	struct cil_complex_symtab_key ckey;
	struct cil_complex_symtab_datum datum;

	while (cond_block != NULL) {
		for (rule_node = cond_block->cl_head;
			rule_node != NULL;
			rule_node = rule_node->next) {

			switch (rule_node->flavor) {
				case CIL_AVRULE:
					avrule = rule_node->data;
					if (avrule->rule_kind == CIL_AVRULE_NEVERALLOW) {
						cil_log(CIL_ERR, "Neverallow within booleanif block (line: %d)\n", node->line);
						rc = SEPOL_ERR;
						goto exit;
					}
				case CIL_TYPE_RULE:
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
					break;
				default:
					cil_log(CIL_ERR, "Invalid statement within booleanif (line: %d)\n", node->line);
					goto exit;
			}
		}

		cond_block = cond_block->next;
	}

	rc = SEPOL_OK;
exit:
	return rc;
}

int __cil_verify_netifcon(struct cil_db *db, struct cil_tree_node *node, symtab_t *senstab)
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

	rc = __cil_add_levelrange_sens_to_symtab(if_ctx->range, senstab);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	rc = __cil_add_levelrange_sens_to_symtab(pkt_ctx->range, senstab);
	if (rc != SEPOL_OK) {
		goto exit;
	}

exit:
	return rc;
}

int __cil_verify_genfscon(struct cil_db *db, struct cil_tree_node *node, symtab_t *senstab)
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

	rc = __cil_add_levelrange_sens_to_symtab(ctx->range, senstab);
	if (rc != SEPOL_OK) {
		goto exit;
	}

exit:
	return rc;
}

int __cil_verify_filecon(struct cil_db *db, struct cil_tree_node *node, symtab_t *senstab)
{
	int rc = SEPOL_ERR;
	struct cil_filecon *file = node->data;
	struct cil_context *ctx = file->context;

	/* Verify only when anonymous */
	if (ctx->datum.name == NULL) {
		rc = __cil_verify_context(db, ctx);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	rc = __cil_add_levelrange_sens_to_symtab(ctx->range, senstab);
	if (rc != SEPOL_OK) {
		goto exit;
	}

exit:
	return rc;
}

int __cil_verify_nodecon(struct cil_db *db, struct cil_tree_node *node, symtab_t *senstab)
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

	rc = __cil_add_levelrange_sens_to_symtab(ctx->range, senstab);
	if (rc != SEPOL_OK) {
		goto exit;
	}

exit:
	return rc;
}

int __cil_verify_portcon(struct cil_db *db, struct cil_tree_node *node, symtab_t *senstab)
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

	rc = __cil_add_levelrange_sens_to_symtab(ctx->range, senstab);
	if (rc != SEPOL_OK) {
		goto exit;
	}

exit:
	return rc;
}

int __cil_verify_pirqcon(struct cil_db *db, struct cil_tree_node *node, symtab_t *senstab)
{
	int rc = SEPOL_ERR;
	struct cil_genfscon *pirq = node->data;
	struct cil_context *ctx = pirq->context;

	/* Verify only when anonymous */
	if (ctx->datum.name == NULL) {
		rc = __cil_verify_context(db, ctx);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	rc = __cil_add_levelrange_sens_to_symtab(ctx->range, senstab);
	if (rc != SEPOL_OK) {
		goto exit;
	}

exit:
	return rc;
}

int __cil_verify_iomemcon(struct cil_db *db, struct cil_tree_node *node, symtab_t *senstab)
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

	rc = __cil_add_levelrange_sens_to_symtab(ctx->range, senstab);
	if (rc != SEPOL_OK) {
		goto exit;
	}

exit:
	return rc;
}

int __cil_verify_ioportcon(struct cil_db *db, struct cil_tree_node *node, symtab_t *senstab)
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

	rc = __cil_add_levelrange_sens_to_symtab(ctx->range, senstab);
	if (rc != SEPOL_OK) {
		goto exit;
	}

exit:
	return rc;
}

int __cil_verify_pcidevicecon(struct cil_db *db, struct cil_tree_node *node, symtab_t *senstab)
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

	rc = __cil_add_levelrange_sens_to_symtab(ctx->range, senstab);
	if (rc != SEPOL_OK) {
		goto exit;
	}

exit:
	return rc;
}

int __cil_verify_fsuse(struct cil_db *db, struct cil_tree_node *node, symtab_t *senstab)
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

	rc = __cil_add_levelrange_sens_to_symtab(ctx->range, senstab);
	if (rc != SEPOL_OK) {
		goto exit;
	}

exit:
	return rc;
}

int __cil_verify_rangetransition(struct cil_tree_node *node, symtab_t *senstab)
{
	int rc = SEPOL_ERR;
	struct cil_rangetransition *rangetrans = node->data;
	struct cil_levelrange *range = rangetrans->range;

	rc = __cil_add_levelrange_sens_to_symtab(range, senstab);
	if (rc != SEPOL_OK) {
		goto exit;
	}

exit:
	return rc;
}

int __cil_verify_class(struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	struct cil_class *class = node->data;

	if (class->common != NULL) {
		struct cil_common *common = class->common;
		struct cil_tree_node *common_node = common->datum.node;
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
					cil_log(CIL_ERR, "Duplicate permissions within common and class: %s\n",
											class_perm->datum.name);
					goto exit;
				}
			}
		}
	}

	rc = SEPOL_OK;
exit:
	return rc;
}

int __cil_verify_helper(struct cil_tree_node *node, __attribute__((unused)) uint32_t *finished, void *extra_args)
{
	int rc = SEPOL_ERR;
	int *avrule_cnt = 0;
	int state = 0;
	struct cil_args_verify *args = extra_args;
	struct cil_complex_symtab *csymtab = NULL;
	struct cil_db *db = NULL;
	symtab_t *senstab = NULL;

	if (node == NULL || extra_args == NULL) {
		goto exit;
	}

	db = args->db;
	senstab = args->senstab;
	avrule_cnt = args->avrule_cnt;
	csymtab = args->csymtab;

	switch (node->flavor) {
	case CIL_USER:
		rc = __cil_verify_user(db, node, senstab);
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
	case CIL_TYPE_RULE:
		rc = __cil_verify_type_rule(node, csymtab);
		break;
	case CIL_BOOLEANIF:
		rc = __cil_verify_booleanif(node, csymtab);
		*finished = CIL_TREE_SKIP_HEAD;
		break;
	case CIL_OPTIONAL:
		state = ((struct cil_symtab_datum *)node->data)->state;
		if (state == CIL_STATE_DISABLED) {
			*finished = CIL_TREE_SKIP_HEAD;
		}
		rc = SEPOL_OK;
		break;
	case CIL_MACRO:
		*finished = CIL_TREE_SKIP_HEAD;
		rc = SEPOL_OK;
		break;
	case CIL_CONTEXT:
		rc = __cil_verify_named_context(db, node);
		break;
	case CIL_LEVELRANGE:
		rc = __cil_verify_named_levelrange(db, node);
		break;
	case CIL_NETIFCON:
		rc = __cil_verify_netifcon(db, node, senstab);
		break;
	case CIL_GENFSCON:
		rc = __cil_verify_genfscon(db, node, senstab);
		break;
	case CIL_FILECON:
		rc = __cil_verify_filecon(db, node, senstab);
		break;
	case CIL_NODECON:
		rc = __cil_verify_nodecon(db, node, senstab);
		break;
	case CIL_PORTCON:
		rc = __cil_verify_portcon(db, node, senstab);
		break;
	case CIL_PIRQCON:
		rc = __cil_verify_pirqcon(db, node, senstab);
		break;
	case CIL_IOMEMCON:
		rc = __cil_verify_iomemcon(db, node, senstab);
		break;
	case CIL_IOPORTCON:
		rc = __cil_verify_ioportcon(db, node, senstab);
		break;
	case CIL_PCIDEVICECON:
		rc = __cil_verify_pcidevicecon(db, node, senstab);
		break;
	case CIL_FSUSE:
		rc = __cil_verify_fsuse(db, node, senstab);
		break;
	case CIL_RANGETRANSITION:
		rc = __cil_verify_rangetransition(node, senstab);
		break;
	case CIL_CLASS:
		rc = __cil_verify_class(node);
		break;
	default:
		rc = SEPOL_OK;
		break;
	}

exit:
	return rc;
}
