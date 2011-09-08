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
		printf("Name length greater than max name length of %d", CIL_MAX_NAME_LENGTH);
		rc = SEPOL_ERR;
		goto exit;
	}

	for (i = 0; i < len; i++) {
		if (!isalnum(name[i]) && name[i] != '_') {
			printf("Invalid character %c in %s\n", name[i], name);
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
		printf("Left hand side must be valid keyword\n");
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
				printf("Keyword %s not allowed on right side of expression\n", rstr);
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
			printf("Keyword %s not allowed on right side of expression\n", rstr);
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
				printf("Keyword %s not allowed on right side of expression\n", rstr);
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
			printf("Keyword %s not allowed on right side of expression\n", rstr);
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
				printf("Keyword %s not allowed on right side of expression\n", rstr);
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
			printf("Keyword %s not allowed on right side of expression\n", rstr);
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
				printf("Right side of expression must be correct keyword\n");
				rc = SEPOL_ERR;
				goto exit;
			}

		/* l2 op something */
		} else if (!strcmp(lstr, CIL_KEY_CONS_L2)) {
			lcond->flavor = CIL_CONS_L2;
			if (!strcmp(rstr, CIL_KEY_CONS_H2)) {
				rcond->flavor = CIL_CONS_H2;
			} else {
				printf("Right side of expression must be correct keyword\n");
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
				printf("Right side of expression must be correct keyword\n");
				rc = SEPOL_ERR;
				goto exit;
			}
		} else {
			printf("Unknown left hand side\n");
			rc = SEPOL_ERR;
			goto exit;
		}
	} else {
		printf("Unknown left hand side\n");
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
			printf("Error: ordering is empty\n");
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
			printf("Item not ordered: %s\n", ((struct cil_symtab_datum*)node->data)->name);
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
			printf("Disjoint category ordering exists\n");
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
		printf("Failed to verify category order\n");
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
				printf("Category %s can't be used with sensitivity %s\n", cat->datum.name, sens->datum.name);
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
					printf("Category %s can't be used with sensitivity %s\n", cat->datum.name, sens->datum.name);
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

int __cil_verify_user(struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	struct cil_user *user = node->data;

	if (user->dftlevel == NULL) {
		printf("user does not have a default level: %s", user->datum.name);
		goto exit;
	} else if (user->range == NULL) {
		printf("user does not have a level range: %s", user->datum.name);
		goto exit;
	} else if (user->bounds != NULL) {
		struct cil_user *bnds = user->bounds;
		if (user == bnds) {
			printf("user cannot bound self: %s", user->datum.name);
			goto exit;
		} else if (bnds->bounds != NULL) {
			bnds = bnds->bounds;
			if (user == bnds) {
				printf("circular userbounds found: %s\n", user->datum.name);
				goto exit;
			}
		}
	}

	rc = SEPOL_OK;
exit:
	return rc;
}

int __cil_verify_role(struct cil_tree_node *node)
{
	int rc = SEPOL_ERR;
	struct cil_role *role = node->data;

	if (role->bounds != NULL) {
		struct cil_role *bnds = role->bounds;
		if (role == bnds) {
			printf("role cannot bound self: %s\n", role->datum.name);
			goto exit;
		} else if (bnds->bounds != NULL) {
			bnds = bnds->bounds;
			if (role == bnds) {
				printf("circular rolebounds found: %s\n", role->datum.name);
				goto exit;
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
	struct cil_type *type = node->data;

	if (type->bounds != NULL) {
		struct cil_type *bnds = type->bounds;
		struct cil_tree_node *type_node = bnds->datum.node;
		enum cil_flavor flavor = type_node->flavor;

		while (flavor == CIL_TYPEALIAS) {
			bnds = ((struct cil_typealias *)bnds)->type;
			type_node = bnds->datum.node;
			flavor = type_node->flavor;
		}

		if (type == bnds) {
			printf("type cannot bound self: %s\n", type->datum.name);
			goto exit;
		} else if (bnds->bounds != NULL) {
			bnds = bnds->bounds;
			if (type == bnds) {
				printf("circular typebounds found: %s\n", type->datum.name);
				goto exit;
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
	struct cil_db *db = NULL;

	if (node == NULL || extra_args == NULL) {
		goto exit;
	}

	db = extra_args;

	switch (node->flavor) {
	case CIL_USER:
		rc = __cil_verify_user(node);
		break;
	case CIL_ROLE:
		rc = __cil_verify_role(node);
		break;
	case CIL_TYPE:
		rc = __cil_verify_type(node);
		break;
	default:
		rc = SEPOL_OK;
		break;
	}

exit:
	return rc;
}
