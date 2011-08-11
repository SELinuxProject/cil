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
#include <ctype.h>

#include "cil.h"
#include "cil_mem.h"
#include "cil_tree.h"
#include "cil_list.h"
#include "cil_parser.h"
#include "cil_build_ast.h"
#include "cil_copy_ast.h"

struct cil_args_build {
	struct cil_tree_node *ast;
	struct cil_db *db;
	struct cil_tree_node *macro;
};

struct cil_args_stack {
	struct cil_list *expr_stack;
	enum cil_flavor flavor;
};

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

int cil_gen_node(struct cil_db *db, struct cil_tree_node *ast_node, struct cil_symtab_datum *datum, hashtab_key_t key, enum cil_sym_index sflavor, enum cil_flavor nflavor)
{
	symtab_t *symtab = NULL;
	int rc = SEPOL_ERR;

	rc = __cil_verify_name((const char*)key);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	rc = cil_get_parent_symtab(db, ast_node, &symtab, sflavor);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, datum, ast_node);
	if (rc != SEPOL_OK) {
		printf("Failed to insert %s into symtab, rc: %d\n", key, rc);
		goto exit;
	}

	ast_node->data = datum;
	ast_node->flavor = nflavor;

	return SEPOL_OK;

exit:
	return rc;
}

int cil_parse_to_list(struct cil_tree_node *parse_cl_head, struct cil_list *ast_cl, enum cil_flavor flavor)
{
	struct cil_list_item *new_item = NULL;
	struct cil_tree_node *parse_current = parse_cl_head;
	struct cil_list_item *list_tail = NULL;
	int rc = SEPOL_ERR;

	if (parse_current == NULL || ast_cl == NULL) {
		goto exit;
	}

	while(parse_current != NULL) {
		cil_list_item_init(&new_item);
		new_item->flavor = flavor;
		new_item->data = cil_strdup(parse_current->data);

		if (ast_cl->head == NULL) {
			ast_cl->head = new_item;
		} else {
			list_tail->next = new_item;
		}

		list_tail = new_item;
		parse_current = parse_current->next;
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_gen_block(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node, uint16_t is_abstract, char *condition)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_N_LISTS
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	char *key = NULL;
	struct cil_block *block = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid block declaration (line: %d)\n", parse_current->line);
		goto exit;
	}

	rc = cil_block_init(&block);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	block->is_abstract = is_abstract;
	block->condition = condition;

	key = parse_current->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)block, (hashtab_key_t)key, CIL_SYM_BLOCKS, CIL_BLOCK);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	return SEPOL_OK;

exit:
	if (block != NULL) {
		cil_destroy_block(block);
	}
	return rc;
}

void cil_destroy_block(struct cil_block *block)
{
	if (block == NULL) {
		return;
	}

	cil_symtab_datum_destroy(block->datum);
	cil_symtab_array_destroy(block->symtab);
	free(block);
}

int cil_gen_class(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_LIST,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	char *key = NULL;
	struct cil_class *class = NULL;
	struct cil_tree_node *perms = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid class declaration (line: %d)\n", parse_current->line);
		goto exit;
	}

	rc = cil_class_init(&class);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	key = parse_current->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)class, (hashtab_key_t)key, CIL_SYM_CLASSES, CIL_CLASS);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	perms = parse_current->next->next->cl_head;

	rc = cil_gen_perm_nodes(db, perms, ast_node);
	if (rc != SEPOL_OK) {
		printf("Class: failed to parse perms\n");
		goto exit;
	}

	return SEPOL_OK;

exit:
	if (class != NULL) {
		cil_destroy_class(class);
	}
	return rc;
}

void cil_destroy_class(struct cil_class *class)
{
	if (class == NULL) {
		return;
	}

	cil_symtab_datum_destroy(class->datum);
	cil_symtab_destroy(&class->perms);

	free(class);
}

int cil_gen_perm(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	char *key = NULL;
	struct cil_perm *perm = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = cil_perm_init(&perm);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	key = parse_current->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)perm, (hashtab_key_t)key, CIL_SYM_UNKNOWN, CIL_PERM);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	return SEPOL_OK;

exit:
	if (perm != NULL) {
		cil_destroy_perm(perm);
	}
	return rc;
}

void cil_destroy_perm(struct cil_perm *perm)
{
	if (perm == NULL) {
		return;
	}

	cil_symtab_datum_destroy(perm->datum);
	free(perm);
}

int cil_gen_perm_nodes(struct cil_db *db, struct cil_tree_node *current_perm, struct cil_tree_node *ast_node)
{
	int rc = SEPOL_ERR;
	struct cil_tree_node *new_ast = NULL;

	while(current_perm != NULL) {
		if (current_perm->cl_head != NULL) {
			printf("Invalid permission declaration\n");
			rc = SEPOL_ERR;
			goto exit;
		}
		cil_tree_node_init(&new_ast);
		new_ast->parent = ast_node;
		new_ast->line = current_perm->line;
		rc = cil_gen_perm(db, current_perm, new_ast);
		if (rc != SEPOL_OK) {
			printf("CLASS: Failed to gen perm\n");
			goto exit;
		}

		if (ast_node->cl_head == NULL) {
			ast_node->cl_head = new_ast;
		} else {
			ast_node->cl_tail->next = new_ast;
		}
		ast_node->cl_tail = new_ast;

		current_perm = current_perm->next;
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_gen_permset(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_LIST,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	char *key = NULL;
	struct cil_permset *permset = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid permissionset declaration (line: %d)\n", parse_current->line);
		goto exit;
	}

	rc = cil_permset_init(&permset);
	if (rc != SEPOL_OK) {
		printf("Failed to init permissionset\n");
		goto exit;
	}

	key = parse_current->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)permset, (hashtab_key_t)key, CIL_SYM_PERMSETS, CIL_PERMSET);
	if (rc != SEPOL_OK) {
		printf("Failed to create permissionset node\n");
		goto exit;
	}

	cil_list_init(&permset->perms_list_str);
	rc = cil_parse_to_list(parse_current->next->next->cl_head, permset->perms_list_str, CIL_AST_STR);
	if (rc != SEPOL_OK) {
		printf("Failed to parse perms\n");
		goto exit;
	}

	return SEPOL_OK;

exit:
	if (permset != NULL) {
		cil_destroy_permset(permset);
	}
	return rc;
}

void cil_destroy_permset(struct cil_permset *permset)
{
	if (permset == NULL) {
		return;
	}

	cil_symtab_datum_destroy(permset->datum);
	cil_list_destroy(&permset->perms_list_str, 1);
	free(permset);
}

// TODO try to merge some of this with cil_gen_class (helper function for both)
int cil_gen_common(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_LIST,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	char *key = NULL;
	struct cil_common *common = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid common declaration (line: %d)\n", parse_current->line);
		goto exit;
	}

	rc = cil_common_init(&common);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	key = parse_current->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)common, (hashtab_key_t)key, CIL_SYM_COMMONS, CIL_COMMON);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	rc = cil_gen_perm_nodes(db, parse_current->next->next->cl_head, ast_node);
	if (rc != SEPOL_OK) {
		printf("Common: failed to parse perms\n");
		goto exit;
	}

	return SEPOL_OK;

exit:
	if (common != NULL) {
		cil_destroy_common(common);
	}
	return rc;

}

void cil_destroy_common(struct cil_common *common)
{
	if (common == NULL) {
		return;
	}

	cil_symtab_datum_destroy(common->datum);
	cil_symtab_destroy(&common->perms);
	free(common);
}

int cil_gen_classcommon(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_STRING,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	struct cil_classcommon *clscom = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid classcommon declaration (line: %d)\n", parse_current->line);
		goto exit;
	}

	rc = cil_classcommon_init(&clscom);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	clscom->class_str = cil_strdup(parse_current->next->data);
	clscom->common_str = cil_strdup(parse_current->next->next->data);

	ast_node->data = clscom;
	ast_node->flavor = CIL_CLASSCOMMON;

	return SEPOL_OK;

exit:
	if (clscom != NULL) {
		cil_destroy_classcommon(clscom);
	}
	return rc;

}

void cil_destroy_classcommon(struct cil_classcommon *clscom)
{
	if (clscom == NULL) {
		return;
	}

	if (clscom->class_str != NULL) {
		free(clscom->class_str);
	}

	if (clscom->common_str != NULL) {
		free(clscom->common_str);
	}

	free(clscom);
}

int cil_gen_sid(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	char *key = NULL;
	struct cil_sid *sid = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid sid declaration (line: %d)\n", parse_current->line);
		goto exit;
	}

	rc = cil_sid_init(&sid);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	key = parse_current->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)sid, (hashtab_key_t)key, CIL_SYM_SIDS, CIL_SID);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	return SEPOL_OK;

exit:
	if (sid != NULL) {
		cil_destroy_sid(sid);
	}
	return rc;
}

void cil_destroy_sid(struct cil_sid *sid)
{
	if (sid == NULL) {
		return;
	}

	cil_symtab_datum_destroy(sid->datum);
	free(sid);
}

int cil_gen_sidcontext(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_STRING | SYM_LIST,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	struct cil_sidcontext *sidcon = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid sidcontext declaration (line: %d)\n", parse_current->line);
		goto exit;
	}

	rc = cil_sidcontext_init(&sidcon);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	sidcon->sid_str = cil_strdup(parse_current->next->data);

	if (parse_current->next->next->cl_head == NULL) {
		sidcon->context_str = cil_strdup(parse_current->next->next->data);
	} else {
		rc = cil_context_init(&sidcon->context);
		if (rc != SEPOL_OK) {
			printf("Failed to init context\n");
			goto exit;
		}

		rc = cil_fill_context(parse_current->next->next->cl_head, sidcon->context);
		if (rc != SEPOL_OK) {
			printf("Failed to fill sid context\n");
			goto exit;
		}
	}

	ast_node->data = sidcon;
	ast_node->flavor = CIL_SIDCONTEXT;

	return SEPOL_OK;

exit:
	if (sidcon != NULL) {
		cil_destroy_sidcontext(sidcon);
	}
	return rc;
}

void cil_destroy_sidcontext(struct cil_sidcontext *sidcon)
{
	if (sidcon == NULL) {
		return;
	}

	if (sidcon->sid_str != NULL) {
		free(sidcon->sid_str);
	}

	if (sidcon->context_str != NULL) {
		free(sidcon->context_str);
	} else if (sidcon->context != NULL && sidcon->context->datum.name == NULL) {
		cil_destroy_context(sidcon->context);
	}

	free(sidcon);
}

int cil_gen_user(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	char *key = NULL;
	struct cil_user *user = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid user declaration (line: %d)\n", parse_current->line);
		goto exit;
	}

	rc = cil_user_init(&user);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	key = parse_current->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)user, (hashtab_key_t)key, CIL_SYM_USERS, CIL_USER);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	return SEPOL_OK;

exit:
	if (user != NULL) {
		cil_destroy_user(user);\
	}
	return rc;
}

void cil_destroy_user(struct cil_user *user)
{
	if (user == NULL) {
		return;
	}

	cil_symtab_datum_destroy(user->datum);
	free(user);
}

int cil_gen_userlevel(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_STRING | SYM_LIST,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	struct cil_userlevel *usrlvl = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid userlevel declaration (line: %d)\n", parse_current->line);
		goto exit;
	}

	rc = cil_userlevel_init(&usrlvl);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	usrlvl->user_str = cil_strdup(parse_current->next->data);

	if (parse_current->next->next->cl_head == NULL) {
		usrlvl->level_str = cil_strdup(parse_current->next->next->data);
	} else {
		rc = cil_level_init(&usrlvl->level);
		if (rc != SEPOL_OK) {
			printf("Failed to initialize level\n");
			goto exit;
		}

		rc = cil_fill_level(parse_current->next->next->cl_head, usrlvl->level);
		if (rc != SEPOL_OK) {
			printf("cil_gen_userlevel: Failed to fill level, rc: %d\n", rc);
			goto exit;
		}
	}

	ast_node->data = usrlvl;
	ast_node->flavor = CIL_USERLEVEL;

	return SEPOL_OK;

exit:
	if (usrlvl != NULL) {
		cil_destroy_userlevel(usrlvl);
	}
	return rc;
}

void cil_destroy_userlevel(struct cil_userlevel *usrlvl)
{
	if (usrlvl == NULL) {
		return;
	}

	if (usrlvl->user_str != NULL) {
		free(usrlvl->user_str);
	}

	if (usrlvl->level_str != NULL) {
		free(usrlvl->level_str);
	} else if (usrlvl->level != NULL) {
		cil_destroy_level(usrlvl->level);
	}

	free(usrlvl);
}

int cil_gen_userrange(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_STRING | SYM_LIST,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	struct cil_userrange *userrange = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid userrange declaration (line: %d)\n", parse_current->line);
		goto exit;
	}

	rc = cil_userrange_init(&userrange);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	userrange->user_str = cil_strdup(parse_current->next->data);

	if (parse_current->next->next->cl_head == NULL) {
		userrange->range_str = cil_strdup(parse_current->next->next->data);
	} else {
		rc = cil_levelrange_init(&userrange->range);
		if (rc != SEPOL_OK) {
			printf("Failed to initialize range\n");
			goto exit;
		}

		rc = cil_fill_levelrange(parse_current->next->next->cl_head, userrange->range);
		if (rc != SEPOL_OK) {
			printf("cil_gen_userrange: Failed to fill levelrange, rc: %d\n", rc);
			goto exit;
		}
	}

	ast_node->data = userrange;
	ast_node->flavor = CIL_USERRANGE;

	return SEPOL_OK;

exit:
	if (userrange != NULL) {
		cil_destroy_userrange(userrange);
	}
	return rc;
}

void cil_destroy_userrange(struct cil_userrange *userrange)
{
	if (userrange == NULL) {
		return;
	}

	if (userrange->user_str != NULL) {
		free(userrange->user_str);
	}

	if (userrange->range_str != NULL) {
		free(userrange->range_str);
	} else if (userrange->range != NULL) {
		cil_destroy_levelrange(userrange->range);
	}

	free(userrange);
}

int cil_gen_userbounds(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_STRING,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	struct cil_userbounds *userbnds = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid userbounds declaration (line: %d)\n", parse_current->line);
		goto exit;
	}

	rc = cil_userbounds_init(&userbnds);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	userbnds->user_str = cil_strdup(parse_current->next->data);
	userbnds->bounds_str = cil_strdup(parse_current->next->next->data);

	ast_node->data = userbnds;
	ast_node->flavor = CIL_USERBOUNDS;

	return SEPOL_OK;

exit:
	if (userbnds != NULL) {
		cil_destroy_userbounds(userbnds);
	}
	return rc;
}

void cil_destroy_userbounds(struct cil_userbounds *userbnds)
{
	if (userbnds == NULL) {
		return;
	}

	if (userbnds->user_str != NULL) {
		free(userbnds->user_str);
	}

	if (userbnds->bounds_str != NULL) {
		free(userbnds->bounds_str);
	}

	free(userbnds);
}

int cil_gen_role(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	char *key = NULL;
	struct cil_role *role = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid role declaration (line: %d)\n", parse_current->line);
		goto exit;
	}

	rc = cil_role_init(&role);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	key = parse_current->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)role, (hashtab_key_t)key, CIL_SYM_ROLES, CIL_ROLE);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	return SEPOL_OK;

exit:
	if (role != NULL) {
		cil_destroy_role(role);
	}
	return rc;
}

void cil_destroy_role(struct cil_role *role)
{
	if (role == NULL) {
		return;
	}

	cil_symtab_datum_destroy(role->datum);
	free(role);
}

int cil_gen_roletype(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_STRING,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	struct cil_roletype *roletype = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid roletype declaration (line: %d)\n", parse_current->line);
		goto exit;
	}

	rc = cil_roletype_init(&roletype);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	roletype->role_str = cil_strdup(parse_current->next->data);
	roletype->type_str = cil_strdup(parse_current->next->next->data);

	ast_node->data = roletype;
	ast_node->flavor = CIL_ROLETYPE;

	return SEPOL_OK;

exit:
	if (roletype != NULL) {
		cil_destroy_roletype(roletype);
	}
	return rc;
}

void cil_destroy_roletype(struct cil_roletype *roletype)
{
	if (roletype == NULL) {
		return;
	}

	if (roletype->role_str != NULL) {
		free(roletype->role_str);
	}

	if (roletype->type_str != NULL) {
		free(roletype->type_str);
	}

	free(roletype);
}

int cil_gen_userrole(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_STRING,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	struct cil_userrole *userrole = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid userrole declaration (line: %d)\n", parse_current->line);
		goto exit;
	}

	rc = cil_userrole_init(&userrole);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	userrole->user_str = cil_strdup(parse_current->next->data);
	userrole->role_str = cil_strdup(parse_current->next->next->data);

	ast_node->data = userrole;
	ast_node->flavor = CIL_USERROLE;

	return SEPOL_OK;

exit:
	if (userrole != NULL) {
		cil_destroy_userrole(userrole);
	}
	return rc;
}

void cil_destroy_userrole(struct cil_userrole *userrole)
{
	if (userrole == NULL) {
		return;
	}

	if (userrole->user_str != NULL) {
		free(userrole->user_str);
	}

	if (userrole->role_str != NULL) {
		free(userrole->role_str);
	}

	free(userrole);
}

int cil_gen_roletrans(struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_STRING,
		SYM_STRING,
		SYM_STRING,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	struct cil_role_trans *roletrans = NULL;
	int rc = SEPOL_ERR;

	if (parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid roletransition declaration (line: %d)\n", parse_current->line);
		goto exit;
	}

	rc = cil_role_trans_init(&roletrans);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	roletrans->src_str = cil_strdup(parse_current->next->data);
	roletrans->tgt_str = cil_strdup(parse_current->next->next->data);
	roletrans->obj_str = cil_strdup(parse_current->next->next->next->data);
	roletrans->result_str = cil_strdup(parse_current->next->next->next->next->data);

	ast_node->data = roletrans;
	ast_node->flavor = CIL_ROLETRANS;

	return SEPOL_OK;

exit:
	if (roletrans != NULL) {
		cil_destroy_roletrans(roletrans);
	}
	return rc;
}

void cil_destroy_roletrans(struct cil_role_trans *roletrans)
{
	if (roletrans == NULL) {
		return;
	}

	if (roletrans->src_str != NULL) {
		free(roletrans->src_str);
	}

	if (roletrans->tgt_str != NULL) {
		free(roletrans->tgt_str);
	}

	if (roletrans->obj_str != NULL) {
		free(roletrans->obj_str);
	}

	if (roletrans->result_str != NULL) {
		free(roletrans->result_str);
	}

	free(roletrans);
}

int cil_gen_roleallow(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_STRING,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	struct cil_role_allow *roleallow = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid roleallow declaration (line: %d)\n", parse_current->line);
		goto exit;
	}

	rc = cil_role_allow_init(&roleallow);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	roleallow->src_str = cil_strdup(parse_current->next->data);
	roleallow->tgt_str = cil_strdup(parse_current->next->next->data);

	ast_node->data = roleallow;
	ast_node->flavor = CIL_ROLEALLOW;

	return SEPOL_OK;

exit:
	if (roleallow != NULL) {
		cil_destroy_roleallow(roleallow);
	}
	return rc;
}

void cil_destroy_roleallow(struct cil_role_allow *roleallow)
{
	if (roleallow == NULL) {
		return;
	}

	if (roleallow->src_str != NULL) {
		free(roleallow->src_str);
	}

	if (roleallow->tgt_str != NULL) {
		free(roleallow->tgt_str);
	}

	free(roleallow);
}

int cil_gen_roledominance(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_STRING,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	struct cil_roledominance *roledom = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid roledominance delcaration (line: %d)\n", parse_current->line);
		goto exit;
	}

	rc = cil_roledominance_init(&roledom);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	roledom->role_str = cil_strdup(parse_current->next->data);
	roledom->domed_str = cil_strdup(parse_current->next->next->data);

	ast_node->data = roledom;
	ast_node->flavor = CIL_ROLEDOMINANCE;

	return SEPOL_OK;

exit:
	if (roledom != NULL) {
		cil_destroy_roledominance(roledom);
	}
	return rc;
}

void cil_destroy_roledominance(struct cil_roledominance *roledom)
{
	if (roledom == NULL) {
		return;
	}

	if (roledom->role_str != NULL) {
		free(roledom->role_str);
	}

	if (roledom->domed_str != NULL) {
		free(roledom->domed_str);
	}

	free(roledom);
}

int cil_gen_rolebounds(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_STRING,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	struct cil_rolebounds *rolebnds = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid rolebounds declaration (line: %d)\n", parse_current->line);
		goto exit;
	}

	rc = cil_rolebounds_init(&rolebnds);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	rolebnds->role_str = cil_strdup(parse_current->next->data);
	rolebnds->bounds_str = cil_strdup(parse_current->next->next->data);

	ast_node->data = rolebnds;
	ast_node->flavor = CIL_ROLEBOUNDS;

	return SEPOL_OK;

exit:
	if (rolebnds != NULL) {
		cil_destroy_rolebounds(rolebnds);
	}
	return rc;
}

void cil_destroy_rolebounds(struct cil_rolebounds *rolebnds)
{
	if (rolebnds == NULL) {
		return;
	}

	if (rolebnds->role_str != NULL) {
		free(rolebnds->role_str);
	}

	if (rolebnds->bounds_str != NULL) {
		free(rolebnds->bounds_str);
	}

	free(rolebnds);
}

int cil_gen_avrule(struct cil_tree_node *parse_current, struct cil_tree_node *ast_node, uint32_t rule_kind)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_STRING,
		SYM_STRING,
		SYM_STRING | SYM_LIST,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	struct cil_avrule *rule = NULL;
	int rc = SEPOL_ERR;

	if (parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid allow rule (line: %d)\n", parse_current->line);
		goto exit;
	}

	rc = cil_avrule_init(&rule);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	rule->rule_kind = rule_kind;

	rule->src_str = cil_strdup(parse_current->next->data);
	rule->tgt_str = cil_strdup(parse_current->next->next->data);
	rule->obj_str = cil_strdup(parse_current->next->next->next->data);

	if (parse_current->next->next->next->next->cl_head != NULL) {
		cil_list_init(&rule->perms_list_str);
		cil_parse_to_list(parse_current->next->next->next->next->cl_head, rule->perms_list_str, CIL_AST_STR);
	} else if (parse_current->next->next->next->next->cl_head == NULL && parse_current->next->next->next->next->data != NULL) {
		rule->permset_str = cil_strdup(parse_current->next->next->next->next->data);
	}

	ast_node->data = rule;
	ast_node->flavor = CIL_AVRULE;

	return SEPOL_OK;

exit:
	if (rule != NULL) {
		cil_destroy_avrule(rule);
	}
	return rc;
}

void cil_destroy_avrule(struct cil_avrule *rule)
{
	if (rule == NULL) {
		return;
	}

	if (rule->src_str != NULL) {
		free(rule->src_str);
	}

	if (rule->tgt_str != NULL) {
		free(rule->tgt_str);
	}

	if (rule->obj_str != NULL) {
		free(rule->obj_str);
	}

	if (rule->perms_list_str != NULL) {
		cil_list_destroy(&rule->perms_list_str, 1);
	}

	if (rule->perms_list != NULL) {
		cil_list_destroy(&rule->perms_list, 0);
	}

	free(rule);
}

int cil_gen_type_rule(struct cil_tree_node *parse_current, struct cil_tree_node *ast_node, uint32_t rule_kind)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_STRING,
		SYM_STRING,
		SYM_STRING,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	struct cil_type_rule *rule = NULL;
	int rc = SEPOL_ERR;

	if (parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid type rule (line: %d)\n", parse_current->line);
		goto exit;
	}

	rc = cil_type_rule_init(&rule);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	rule->rule_kind = rule_kind;
	rule->src_str = cil_strdup(parse_current->next->data);
	rule->tgt_str = cil_strdup(parse_current->next->next->data);
	rule->obj_str = cil_strdup(parse_current->next->next->next->data);
	rule->result_str = cil_strdup(parse_current->next->next->next->next->data);

	ast_node->data = rule;
	ast_node->flavor = CIL_TYPE_RULE;

	return SEPOL_OK;

exit:
	if (rule != NULL) {
		cil_destroy_type_rule(rule);
	}
	return rc;
}

void cil_destroy_type_rule(struct cil_type_rule *rule)
{
	if (rule == NULL) {
		return;
	}

	if (rule->src_str != NULL) {
		free(rule->src_str);
	}

	if (rule->tgt_str != NULL) {
		free(rule->tgt_str);
	}

	if (rule->obj_str != NULL) {
		free(rule->obj_str);
	}

	if (rule->result_str != NULL) {
		free(rule->result_str);
	}

	free(rule);
}

int cil_gen_type(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	char *key = NULL;
	struct cil_type *type = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid %s declaration (line: %d)\n", (char*)parse_current->data, parse_current->line);
		goto exit;
	}

	if (!strcmp(parse_current->next->data, CIL_KEY_SELF)) {
		printf("The keyword '%s' is reserved and cannot be used for a type name\n", CIL_KEY_SELF);
		rc = SEPOL_ERR;
		goto exit;
	}
	
	rc = cil_type_init(&type);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	key = parse_current->next->data;
	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)type, (hashtab_key_t)key, CIL_SYM_TYPES, CIL_TYPE);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	return SEPOL_OK;

exit:
	if (type != NULL) {
		cil_destroy_type(type);
	}
	return rc;
}

void cil_destroy_type(struct cil_type *type)
{
	if (type == NULL) {
		return;
	}

	cil_symtab_datum_destroy(type->datum);
	free(type);
}

int cil_gen_typeattribute(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	char *key = NULL;
	struct cil_typeattribute *attr = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid %s declaration (line: %d)\n", (char*)parse_current->data, parse_current->line);
		goto exit;
	}
	
	if (!strcmp(parse_current->next->data, CIL_KEY_SELF)) {
		printf("The keyword '%s' is reserved and cannot be used for a typeattribute name\n", CIL_KEY_SELF);
		rc = SEPOL_ERR;
		goto exit;
	}

	rc = cil_typeattribute_init(&attr);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	key = parse_current->next->data;
	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)attr, (hashtab_key_t)key, CIL_SYM_TYPES, CIL_TYPEATTRIBUTE);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	return SEPOL_OK;

exit:
	if (attr != NULL) {
		cil_destroy_typeattribute(attr);
	}
	return rc;
}

void cil_destroy_typeattribute(struct cil_typeattribute *attr)
{
	if (attr == NULL) {
		return;
	}

	cil_symtab_datum_destroy(attr->datum);

	if (attr->types_list != NULL) {
		cil_list_destroy(&attr->types_list, CIL_FALSE);
	}
	
	if (attr->neg_list) {
		cil_list_destroy(&attr->neg_list, CIL_FALSE);
	}

	free(attr);
}

int cil_gen_bool(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node, enum cil_flavor flavor)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_STRING,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	char *key = NULL;
	struct cil_bool *boolean = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid boolean declaration (line: %d)\n", parse_current->line);
		goto exit;
	}

	rc = cil_bool_init(&boolean);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	key = parse_current->next->data;

	if (!strcmp(parse_current->next->next->data, "true")) {
		boolean->value = CIL_TRUE;
	} else if (!strcmp(parse_current->next->next->data, "false")) {
		boolean->value = CIL_FALSE;
	} else {
		printf("Error: value must be \'true\' or \'false\'");
		rc = SEPOL_ERR;
		goto exit;
	}

	if (flavor == CIL_BOOL)	{
		rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)boolean, (hashtab_key_t)key, CIL_SYM_BOOLS, CIL_BOOL);
	} else {
		rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)boolean, (hashtab_key_t)key, CIL_SYM_TUNABLES, CIL_TUNABLE);
	}

	if (rc != SEPOL_OK) {
		goto exit;
	}

	return SEPOL_OK;

exit:
	if (boolean != NULL) {
		cil_destroy_bool(boolean);
	}
	return rc;
}

void cil_destroy_bool(struct cil_bool *boolean)
{
	if (boolean == NULL) {
		return;
	}

	cil_symtab_datum_destroy(boolean->datum);
	free(boolean);
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

	rc = cil_conditional_init(&lcond);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	cil_list_item_init(&rnode);

	rc = cil_conditional_init(&rcond);
	if (rc != SEPOL_OK) {
		goto exit;
	}

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

int __cil_gen_expr_stack_helper(struct cil_tree_node *node, __attribute__((unused)) uint32_t *finished, void *extra_args)
{
	int rc = SEPOL_ERR;
	struct cil_args_stack *args = extra_args;
	struct cil_list *stack = args->expr_stack;
	enum cil_flavor flavor = args->flavor;
	struct cil_list_item *new = NULL;
	struct cil_conditional *cond = NULL;

	if (node->data == NULL) {
		if (node == node->parent->cl_head &&
			    node->parent->data == NULL) {
			rc = SEPOL_ERR;
			goto exit;
		}
		rc = SEPOL_OK;
		goto exit;
	}

	rc = cil_conditional_init(&cond);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	if (node == node->parent->cl_head) {
		rc = __cil_verify_expr_oper_flavor(node->data, cond, flavor);
		if (rc != SEPOL_OK) {
			goto exit;
		}

		rc = __cil_verify_expr_syntax(node, flavor, cond->flavor);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	} else {
		cond->flavor = flavor;
	}

	if (cond->flavor != CIL_AND && cond->flavor != CIL_OR && cond->flavor != CIL_NOT &&
		(flavor == CIL_MLSCONSTRAIN  || flavor == CIL_CONSTRAIN)) {
		rc = __cil_verify_constrain_expr(node, flavor, cond, stack);
		if (rc != SEPOL_OK) {
			goto exit;
		}
		*finished = CIL_TREE_SKIP_ALL;
	} else {
		cond->str = cil_strdup(node->data);

		cil_list_item_init(&new);

		new->data = cond;
		new->flavor = CIL_COND;

		rc = cil_list_prepend_item(stack, new);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	free(cond);
	free(new);
	return rc;
}

int cil_gen_expr_stack(struct cil_tree_node *current, enum cil_flavor flavor, struct cil_list **stack)
{
	int rc = SEPOL_ERR;
	struct cil_args_stack extra_args;
	struct cil_list *new_stack;

	if (current == NULL || stack == NULL) {
		goto exit;
	}

	cil_list_init(&new_stack);
	if (current->cl_head == NULL) {
		struct cil_conditional *cond = NULL;
		struct cil_list_item *stack_item = NULL;
		if (current->data == NULL || flavor == CIL_CONSTRAIN 
					  || flavor == CIL_MLSCONSTRAIN) {
			printf("Invalid expression (line: %d)\n", current->line);
			rc = SEPOL_ERR;
			goto exit;
		}
		cil_list_item_init(&stack_item);
		rc = cil_conditional_init(&cond);
		if (rc != SEPOL_OK) {
			goto exit;
		}
		cond->str = cil_strdup(current->data);
		cond->flavor = CIL_BOOL;
		stack_item->data = cond;
		stack_item->flavor = CIL_COND;
		new_stack->head = stack_item;
	} else {
		extra_args.expr_stack = new_stack;
		extra_args.flavor = flavor;
		rc = cil_tree_walk(current, __cil_gen_expr_stack_helper, NULL, NULL, &extra_args);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	*stack = new_stack;

	return SEPOL_OK;

exit:
	return rc;
}

int cil_gen_boolif(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING | SYM_LIST,
		SYM_LIST,
		SYM_LIST | SYM_END,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	struct cil_booleanif *bif = NULL;
	struct cil_tree_node *next = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid booleanif declaration (line: %d)\n", parse_current->line);
		goto exit;
	}

	rc = cil_boolif_init(&bif);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	rc = cil_gen_expr_stack(parse_current->next, CIL_BOOL, &bif->expr_stack);
	if (rc != SEPOL_OK) {
		printf("cil_gen_boolif (line %d): failed to create expr tree, rc: %d\n", parse_current->line, rc);
		goto exit;
	}

	next = parse_current->next->next;
	cil_tree_subtree_destroy(parse_current->next);
	parse_current->next = next;

	ast_node->flavor = CIL_BOOLEANIF;
	ast_node->data = bif;

	return SEPOL_OK;

exit:
	if (bif != NULL) {
		cil_destroy_boolif(bif);
	}
	return rc;
}

void cil_destroy_boolif(struct cil_booleanif *bif)
{
	if (bif == NULL) {
		return;
	}

	if (bif->expr_stack != NULL) {
		cil_list_destroy(&bif->expr_stack, CIL_TRUE);
	}

	free(bif);
}

void cil_destroy_conditional(struct cil_conditional *cond)
{
	if (cond == NULL) {
		return;
	}

	if (cond->str != NULL) {
		free(cond->str);
	}

	free(cond);
}

int cil_gen_tunif(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING | SYM_LIST,
		SYM_LIST,
		SYM_LIST | SYM_END,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	struct cil_tunableif *tif = NULL;
	struct cil_tree_node *next = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid tunableif declaration (line: %d)\n", parse_current->line);
		goto exit;
	}

	rc = cil_tunif_init(&tif);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	rc = cil_gen_expr_stack(parse_current->next, CIL_TUNABLE, &tif->expr_stack);
	if (rc != SEPOL_OK) {
		printf("cil_gen_tunif (line %d): failed to create expr tree, rc: %d\n", parse_current->line, rc);
		goto exit;
	}

	next = parse_current->next->next;
	cil_tree_subtree_destroy(parse_current->next);
	parse_current->next = next;

	ast_node->flavor = CIL_TUNABLEIF;
	ast_node->data = tif;

	return SEPOL_OK;

exit:
	if (tif != NULL) {
		cil_destroy_tunif(tif);
	}
	return rc;
}

void cil_destroy_tunif(struct cil_tunableif *tif)
{
	if (tif == NULL) {
		return;
	}

	if (tif->expr_stack != NULL) {
		cil_list_destroy(&tif->expr_stack, CIL_TRUE);
	}
	cil_symtab_array_destroy(tif->symtab);

	free(tif);
}

int cil_gen_condtrue(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_N_LISTS
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid true condition declaration (line: %d)\n", parse_current->line);
		goto exit;
	}

	ast_node->flavor = CIL_CONDTRUE;

	if (ast_node->parent->flavor == CIL_TUNABLEIF) {
		struct cil_tunableif *tif = ast_node->parent->data;
		if (tif->condtrue == NULL) {
			tif->condtrue = ast_node;
		} else {
			printf("Duplicate true condition declaration (line: %d)\n", parse_current->line);
			rc = SEPOL_ERR;
			goto exit;
		}
	} else if (ast_node->parent->flavor == CIL_BOOLEANIF) {
		struct cil_booleanif *bif = ast_node->parent->data;
		if (bif->condtrue == NULL) {
			bif->condtrue = ast_node;
		} else {
			printf("Duplicate true condition declaration (line: %d)\n", parse_current->line);
			rc = SEPOL_ERR;
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	return rc;	
}

int cil_gen_condfalse(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_N_LISTS
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid false condition declaration (line: %d\n", parse_current->line);
		goto exit;
	}

	ast_node->flavor = CIL_CONDFALSE;

	if (ast_node->parent->flavor == CIL_TUNABLEIF) {
		struct cil_tunableif *tif = ast_node->parent->data;
		if (tif->condfalse == NULL) {
			tif->condfalse = ast_node;
		} else {
			printf("Duplicate false condition declaration (line: %d)\n", parse_current->line);
			rc = SEPOL_ERR;
			goto exit;
		}
	} else if (ast_node->parent->flavor == CIL_BOOLEANIF) {
		struct cil_booleanif *bif = ast_node->parent->data;
		if (bif->condfalse == NULL) {
			bif->condfalse = ast_node;
		} else {
			printf("Duplicate false condition declaration (line: %d)\n", parse_current->line);
			rc = SEPOL_ERR;
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_gen_typealias(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_STRING,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	char *key = NULL;
	struct cil_typealias *alias = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid typealias declaration (line: %d)\n", parse_current->line);
		goto exit;
	}

	if (!strcmp(parse_current->next->data, CIL_KEY_SELF)) {
		printf("The keyword '%s' is reserved and cannot be used for a typealias name\n", CIL_KEY_SELF);
		rc = SEPOL_ERR;
		goto exit;
	}

	rc = cil_typealias_init(&alias);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	key = parse_current->next->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)alias, (hashtab_key_t)key, CIL_SYM_TYPES, CIL_TYPEALIAS);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	alias->type_str = cil_strdup(parse_current->next->data);

	return SEPOL_OK;

exit:
	if (alias != NULL) {
		cil_destroy_typealias(alias);
	}
	return rc;
}

void cil_destroy_typealias(struct cil_typealias *alias)
{
	if (alias == NULL) {
		return;
	}

	cil_symtab_datum_destroy(alias->datum);

	if (alias->type_str != NULL) {
		free(alias->type_str);
	}

	free(alias);
}

int cil_gen_typeattributetypes(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_LIST,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	struct cil_typeattributetypes *attrtypes = NULL;
	struct cil_tree_node *curr = NULL;
	struct cil_list_item *new_type = NULL;
	char *type = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid attributetypes statement (line: %d)\n", parse_current->line);
		goto exit;
	}

	rc = cil_typeattributetypes_init(&attrtypes);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	attrtypes->attr_str = cil_strdup(parse_current->next->data);

	curr = parse_current->next->next->cl_head;

	while(curr != NULL) {
		if (curr->cl_head != NULL) {
			printf("Invalid attributetypes statement (line: %d)\n", parse_current->line);
			rc = SEPOL_ERR;
			goto exit;
		}

		cil_list_item_init(&new_type);
		new_type->flavor = CIL_AST_STR;

		type = curr->data;
		if (type[0] == '-') {
			if (type[1] == '\0') {
				printf("Invalid negative type in attributetypes statement\n");
				rc = SEPOL_ERR;
				goto exit;
			}

			if (attrtypes->neg_list_str == NULL) {
				cil_list_init(&attrtypes->neg_list_str);
			}

			new_type->data = cil_strdup(&type[1]);
			rc = cil_list_prepend_item(attrtypes->neg_list_str, new_type);
			if (rc != SEPOL_OK) {
				goto exit;
			}
		} else {
			if (attrtypes->types_list_str == NULL) {
				cil_list_init(&attrtypes->types_list_str);
			}

			new_type->data = cil_strdup(type);
			rc = cil_list_prepend_item(attrtypes->types_list_str, new_type);
			if (rc != SEPOL_OK) {
				goto exit;
			}
		}

		curr = curr->next;
	}

	ast_node->data = attrtypes;
	ast_node->flavor = CIL_TYPEATTRIBUTETYPES;

	return SEPOL_OK;

exit:
	if (attrtypes != NULL) {
		cil_destroy_typeattributetypes(attrtypes);
	}
	return rc;
}

void cil_destroy_typeattributetypes(struct cil_typeattributetypes *attrtypes)
{
	if (attrtypes == NULL) {
		return;
	}

	if (attrtypes->attr_str != NULL) {
		free(attrtypes->attr_str);
	}

	if (attrtypes->types_list_str != NULL) {
		cil_list_destroy(&attrtypes->types_list_str, 1);
	}

	if (attrtypes->neg_list_str != NULL) {
		cil_list_destroy(&attrtypes->neg_list_str, 1);
	}

	free(attrtypes);
}

int cil_gen_typebounds(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_STRING,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	struct cil_typebounds *typebnds = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid typebounds declaration (line: %d)\n", parse_current->line);
		goto exit;
	}

	rc = cil_typebounds_init(&typebnds);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	typebnds->type_str = cil_strdup(parse_current->next->data);
	typebnds->bounds_str = cil_strdup(parse_current->next->next->data);

	ast_node->data = typebnds;
	ast_node->flavor = CIL_TYPEBOUNDS;

	return SEPOL_OK;

exit:
	if (typebnds != NULL) {
		cil_destroy_typebounds(typebnds);
	}
	return rc;
}

void cil_destroy_typebounds(struct cil_typebounds *typebnds)
{
	if (typebnds == NULL) {
		return;
	}

	if (typebnds->type_str != NULL) {
		free(typebnds->type_str);
	}

	if (typebnds->bounds_str != NULL) {
		free(typebnds->bounds_str);
	}

	free(typebnds);
}

int cil_gen_typepermissive(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	struct cil_typepermissive *typeperm = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid typepermissive declaration (line: %d)\n", parse_current->line);
		goto exit;
	}

	rc = cil_typepermissive_init(&typeperm);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	typeperm->type_str = cil_strdup(parse_current->next->data);

	ast_node->data = typeperm;
	ast_node->flavor = CIL_TYPEPERMISSIVE;

	return SEPOL_OK;

exit:
	if (typeperm != NULL) {
		cil_destroy_typepermissive(typeperm);
	}
	return rc;
}

void cil_destroy_typepermissive(struct cil_typepermissive *typeperm)
{
	if (typeperm == NULL) {
		return;
	}

	if (typeperm->type_str != NULL) {
		free(typeperm->type_str);
	}

	free(typeperm);
}

int cil_gen_filetransition(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_STRING,
		SYM_STRING,
		SYM_STRING,
		SYM_STRING,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	struct cil_filetransition *filetrans = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL ) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid filetransition declaration (line: %d)\n", parse_current->line);
		goto exit;
	}

	rc = cil_filetransition_init(&filetrans);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	filetrans->src_str = cil_strdup(parse_current->next->data);
	filetrans->exec_str = cil_strdup(parse_current->next->next->data);
	filetrans->proc_str = cil_strdup(parse_current->next->next->next->data);
	filetrans->dest_str = cil_strdup(parse_current->next->next->next->next->data);
	filetrans->path_str = cil_strdup(parse_current->next->next->next->next->next->data);

	ast_node->data = filetrans;
	ast_node->flavor = CIL_FILETRANSITION;

	return SEPOL_OK;

exit:
	if (filetrans != NULL) {
		cil_destroy_filetransition(filetrans);
	}
	return rc;
}

void cil_destroy_filetransition(struct cil_filetransition *filetrans)
{
	if (filetrans == NULL) {
		return;
	}

	if (filetrans->src_str != NULL) {
		free(filetrans->src_str);
	}
	if (filetrans->exec_str != NULL) {
		free(filetrans->exec_str);
	}
	if (filetrans->proc_str != NULL) {
		free(filetrans->proc_str);
	}
	if (filetrans->dest_str != NULL) {
		free(filetrans->dest_str);
	}
	if (filetrans->path_str != NULL) {
		free(filetrans->path_str);
	}
}

int cil_gen_rangetransition(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_STRING,
		SYM_STRING,
		SYM_STRING | SYM_LIST,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	struct cil_rangetransition *rangetrans = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL ) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid rangetransition declaration (line: %d)\n", parse_current->line);
		goto exit;
	}

	rc = cil_rangetransition_init(&rangetrans);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	rangetrans->src_str = cil_strdup(parse_current->next->data);
	rangetrans->exec_str = cil_strdup(parse_current->next->next->data);
	rangetrans->obj_str = cil_strdup(parse_current->next->next->next->data);

	rangetrans->range_str = NULL;

	if (parse_current->next->next->next->next->cl_head == NULL) {
		rangetrans->range_str = cil_strdup(parse_current->next->next->next->next->data);
	} else {
		rc = cil_levelrange_init(&rangetrans->range);
		if (rc != SEPOL_OK) {
			printf("Couldn't initialize levelrange\n");
			goto exit;
		}

		rc = cil_fill_levelrange(parse_current->next->next->next->next->cl_head, rangetrans->range);
		if (rc != SEPOL_OK) {
			printf("cil_gen_rangetransition: Failed to fill levelrange, rc: %d\n", rc);
			goto exit;
		}
	}

	ast_node->data = rangetrans;
	ast_node->flavor = CIL_RANGETRANSITION;

	return SEPOL_OK;

exit:
	if (rangetrans != NULL) {
		cil_destroy_rangetransition(rangetrans);
	}
	return rc;
}

void cil_destroy_rangetransition(struct cil_rangetransition *rangetrans)
{
	if (rangetrans == NULL) {
		return;
	}

	if (rangetrans->src_str != NULL) {
		free(rangetrans->src_str);
	}
	if (rangetrans->exec_str != NULL) {
		free(rangetrans->exec_str);
	}
	if (rangetrans->obj_str != NULL) {
		free(rangetrans->obj_str);
	}
	if (rangetrans->range_str != NULL) {
		free(rangetrans->range_str);
	}
}

int cil_gen_sensitivity(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	char *key = NULL;
	struct cil_sens *sens = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid sensitivity declaration (line: %d)\n", parse_current->line);
		goto exit;
	}

	rc = cil_sens_init(&sens);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	key = parse_current->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)sens, (hashtab_key_t)key, CIL_SYM_SENS, CIL_SENS);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	return SEPOL_OK;

exit:
	if (sens != NULL) {
		cil_destroy_sensitivity(sens);
	}
	return rc;
}

void cil_destroy_sensitivity(struct cil_sens *sens)
{
	if (sens == NULL) {
		return;
	}

	cil_symtab_datum_destroy(sens->datum);
	cil_list_destroy(&sens->catsets, CIL_FALSE);
	free(sens);
}

int cil_gen_sensalias(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_STRING,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	char *key = NULL;
	struct cil_sensalias *alias = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid sensitivityalias declaration (line: %d)\n", parse_current->line);
		goto exit;
	}

	rc = cil_sensalias_init(&alias);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	key = parse_current->next->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)alias, (hashtab_key_t)key, CIL_SYM_SENS, CIL_SENSALIAS);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	alias->sens_str = cil_strdup(parse_current->next->data);

	return SEPOL_OK;

exit:
	if (alias != NULL) {
		cil_destroy_sensalias(alias);
	}
	return rc;
}

void cil_destroy_sensalias(struct cil_sensalias *alias)
{
	if (alias == NULL) {
		return;
	}

	cil_symtab_datum_destroy(alias->datum);

	if (alias->sens_str != NULL) {
		free(alias->sens_str);
	}

	free(alias);
}

int cil_gen_category(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	char *key = NULL;
	struct cil_cat *cat = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid category declaration (line: %d)\n", parse_current->line);
		goto exit;
	}

	rc = cil_cat_init(&cat);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	key = parse_current->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)cat, (hashtab_key_t)key, CIL_SYM_CATS, CIL_CAT);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	return SEPOL_OK;

exit:
	if (cat != NULL) {
		cil_destroy_category(cat);
	}
	return rc;
}

void cil_destroy_category(struct cil_cat *cat)
{
	if (cat == NULL) {
		return;
	}

	cil_symtab_datum_destroy(cat->datum);
	free(cat);
}

int cil_gen_catalias(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_STRING,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	char *key = NULL;
	struct cil_catalias *alias = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid sensitivityalias declaration (line: %d)\n", parse_current->line);
		goto exit;
	}

	rc = cil_catalias_init(&alias);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	key = parse_current->next->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)alias, (hashtab_key_t)key, CIL_SYM_CATS, CIL_CATALIAS);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	alias->cat_str = cil_strdup(parse_current->next->data);

	return SEPOL_OK;

exit:
	if (alias != NULL) {
		cil_destroy_catalias(alias);
	}
	return rc;
}

void cil_destroy_catalias(struct cil_catalias *alias)
{
	if (alias == NULL) {
		return;
	}

	cil_symtab_datum_destroy(alias->datum);

	if (alias->cat_str != NULL) {
		free(alias->cat_str);
	}

	free(alias);
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

int cil_set_to_list(struct cil_tree_node *parse_current, struct cil_list *ast_cl, uint8_t sublists)
{
	struct cil_list *sub_list = NULL;
	struct cil_list_item *new_item = NULL;
	struct cil_list_item *list_tail = NULL;
	struct cil_tree_node *curr = parse_current;
	int rc = SEPOL_ERR;

	if (parse_current == NULL || ast_cl == NULL) {
		goto exit;
	}

	if (parse_current->cl_head == NULL) {
		printf("Error: Invalid list\n");
		goto exit;
	}

	curr = curr->cl_head;
	while (curr != NULL) {
		cil_list_item_init(&new_item);
		if (curr->cl_head == NULL) {
			new_item->flavor = CIL_AST_STR;
			new_item->data = cil_strdup(curr->data);
		} else if (sublists) {
			cil_list_init(&sub_list);
			new_item->flavor = CIL_LIST;
			new_item->data = sub_list;
			rc = cil_set_to_list(curr, sub_list, sublists);
			if (rc != SEPOL_OK) {
				printf("Error while building sublist\n");
				goto exit;
			}
		} else {
			printf("cil_set_to_list: invalid sublist\n");
			rc = SEPOL_ERR;
			goto exit;
		}

		if (ast_cl->head == NULL) {
			ast_cl->head = new_item;
		} else {
			list_tail->next = new_item;
		}
		list_tail = new_item;
		curr = curr->next;
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_gen_catrange(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_LIST,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	char *key = NULL;
	struct cil_catrange *catrange = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid categoryrange declaration (line: %d)\n", parse_current->line);
		goto exit;
	}

	rc = cil_catrange_init(&catrange);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	key = parse_current->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)catrange, (hashtab_key_t)key, CIL_SYM_CATS, CIL_CATRANGE);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	rc = cil_fill_catrange(parse_current->next->next->cl_head, catrange);
	if (rc != SEPOL_OK) {
		printf("Failed to fill categoryset\n");
		goto exit;
	}

	return SEPOL_OK;

exit:
	if (catrange != NULL) {
		cil_destroy_catrange(catrange);
	}
	return rc;
}

void cil_destroy_catrange(struct cil_catrange *catrange)
{
	if (catrange == NULL) {
		return;
	}

	cil_symtab_datum_destroy(catrange->datum);
	
	if (catrange->cat_low_str != NULL) {
		free(catrange->cat_low_str);
	}

	if (catrange->cat_high_str != NULL) {
		free(catrange->cat_high_str);
	}

	free(catrange);
}

int cil_gen_catset(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_LIST,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	char *key = NULL;
	struct cil_catset *catset = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid categoryset declaration (line: %d)\n", parse_current->line);
		goto exit;
	}

	rc = cil_catset_init(&catset);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	key = parse_current->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)catset, (hashtab_key_t)key, CIL_SYM_CATS, CIL_CATSET);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	rc = cil_fill_catset(parse_current->next->next->cl_head, catset);
	if (rc != SEPOL_OK) {
		printf("Failed to fill categoryset\n");
		goto exit;
	}

	return SEPOL_OK;

exit:
	if (catset != NULL) {
		cil_destroy_catset(catset);
	}
	return rc;
}

void cil_destroy_catset(struct cil_catset *catset)
{
	if (catset == NULL) {
		return;
	}

	cil_symtab_datum_destroy(catset->datum);

	if (catset->cat_list_str != NULL) {
		cil_list_destroy(&catset->cat_list_str, 1);
	}

	if (catset->cat_list != NULL) {
		cil_list_destroy(&catset->cat_list, 0);
	}

	free(catset);
}

int cil_gen_catorder(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_LIST,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	struct cil_catorder *catorder = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc !=  SEPOL_OK) {
		printf("Invalid categoryorder declaration (line: %d)\n", parse_current->line);
		goto exit;
	}

	rc = cil_catorder_init(&catorder);
	if (rc != SEPOL_OK) {
		goto exit;
	}
	cil_list_init(&catorder->cat_list_str);

	rc = cil_set_to_list(parse_current->next, catorder->cat_list_str, 0);
	if (rc != SEPOL_OK) {
		printf("Failed to create category list\n");
		goto exit;
	}
	ast_node->data = catorder;
	ast_node->flavor = CIL_CATORDER;

	return SEPOL_OK;

exit:
	if (catorder != NULL) {
		cil_destroy_catorder(catorder);
	}
	return rc;
}

void cil_destroy_catorder(struct cil_catorder *catorder)
{
	if (catorder == NULL) {
		return;
	}

	if (catorder->cat_list_str != NULL) {
		cil_list_destroy(&catorder->cat_list_str, 1);
	}

	free(catorder);
}

int cil_gen_dominance(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_LIST,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	struct cil_sens_dominates *dom = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid dominance declaration (line: %d)\n", parse_current->line);
		goto exit;
	}

	rc = cil_sens_dominates_init(&dom);
	if (rc != SEPOL_OK) {
		goto exit;
	}
	cil_list_init(&dom->sens_list_str);

	rc = cil_set_to_list(parse_current->next, dom->sens_list_str, 0);
	if (rc != SEPOL_OK) {
		printf("Failed to create sensitivity list\n");
		goto exit;
	}

	ast_node->data = dom;
	ast_node->flavor = CIL_DOMINANCE;

	return SEPOL_OK;

exit:
	if (dom != NULL) {
		cil_destroy_dominance(dom);
	}
	return rc;
}

void cil_destroy_dominance(struct cil_sens_dominates *dom)
{
	if (dom == NULL) {
		return;
	}

	if (dom->sens_list_str != NULL) {
		cil_list_destroy(&dom->sens_list_str, 1);
	}

	free(dom);
}

int cil_gen_senscat(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_STRING | SYM_LIST
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	struct cil_senscat *senscat = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid sensitivitycategory declaration (line: %d)\n", parse_current->line);
		goto exit;
	}

	rc = cil_senscat_init(&senscat);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	senscat->sens_str = cil_strdup(parse_current->next->data);

	if (parse_current->next->next->cl_head == NULL) {
		senscat->catset_str = cil_strdup(parse_current->next->next->data);
	} else {
		rc = cil_catset_init(&senscat->catset);
		if (rc != SEPOL_OK) {
			goto exit;
		}

		rc = cil_fill_catset(parse_current->next->next->cl_head, senscat->catset);
		if (rc != SEPOL_OK) {
			printf("Failed to fill category list\n");
			goto exit;
		}
	}

	ast_node->data = senscat;
	ast_node->flavor = CIL_SENSCAT;

	return SEPOL_OK;

exit:
	if (senscat != NULL) {
		cil_destroy_senscat(senscat);
	}
	return rc;
}

void cil_destroy_senscat(struct cil_senscat *senscat)
{
	if (senscat == NULL) {
		return;
	}

	if (senscat->sens_str != NULL) {
		free(senscat->sens_str);
	}

	if (senscat->catset_str == NULL) {
		cil_destroy_catset(senscat->catset);
	}
	
	if (senscat->catset_str != NULL) {
		free(senscat->catset_str);
	}

	free(senscat);
}

int cil_gen_level(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_LIST,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	char *key = NULL;
	struct cil_level *level = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid level declaration (line: %d)\n", parse_current->line);
		goto exit;
	}

	rc = cil_level_init(&level);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	key = parse_current->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)level, (hashtab_key_t)key, CIL_SYM_LEVELS, CIL_LEVEL);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	rc = cil_fill_level(parse_current->next->next->cl_head, level);
	if (rc != SEPOL_OK) {
		printf("Failed to populate level\n");
		goto exit;
	}

	return SEPOL_OK;

exit:
	if (level != NULL) {
		cil_destroy_level(level);
	}
	return rc;
}

void cil_destroy_level(struct cil_level *level)
{
	if (level == NULL) {
		return;
	}

	cil_symtab_datum_destroy(level->datum);

	if (level->sens_str != NULL) {
		free(level->sens_str);
	}

	if (level->catset_str == NULL) {
		cil_destroy_catset(level->catset);
	}

	if (level->catset_str != NULL) {
		free(level->catset_str);
	}

	free(level);
}

/* low should be pointing to either the name of the low level or to an open paren for an anonymous low level */
int cil_fill_levelrange(struct cil_tree_node *low, struct cil_levelrange *lvlrange)
{
	enum cil_syntax syntax[] = {
		SYM_STRING | SYM_LIST,
		SYM_STRING | SYM_LIST,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	int rc = SEPOL_ERR;

	if (low == NULL || lvlrange == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(low, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid levelrange declaration (line: %d)\n", low->line);
		goto exit;
	}

	if (low->cl_head == NULL) {
		lvlrange->low_str = cil_strdup(low->data);
	} else {
		rc = cil_level_init(&lvlrange->low);
		if (rc != SEPOL_OK) {
			printf("Failed to initialize low level\n");
			goto exit;
		}

		rc = cil_fill_level(low->cl_head, lvlrange->low);
		if (rc != SEPOL_OK) {
			printf("cil_fill_levelrange: Failed to fill low level, rc: %d\n", rc);
			goto exit;
		}
	}

	if (low->next->cl_head == NULL) {
		lvlrange->high_str = cil_strdup(low->next->data);
	} else {
		rc = cil_level_init(&lvlrange->high);
		if (rc != SEPOL_OK) {
			printf("Failed to initialize high level\n");
			goto exit;
		}

		rc = cil_fill_level(low->next->cl_head, lvlrange->high);
		if (rc != SEPOL_OK) {
			printf("cil_fill_levelrange: Failed to fill high level, rc: %d\n", rc);
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_gen_levelrange(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_LIST,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	char *key = NULL;
	struct cil_levelrange *lvlrange = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid levelrange declaration (line: %d)\n", parse_current->line);
		goto exit;
	}

	rc = cil_levelrange_init(&lvlrange);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	key = parse_current->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)lvlrange, (hashtab_key_t)key, CIL_SYM_LEVELRANGES, CIL_LEVELRANGE);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	rc = cil_fill_levelrange(parse_current->next->next->cl_head, lvlrange);
	if (rc != SEPOL_OK) {
		printf("Failed to pupulate levelrange\n");
		goto exit;
	}

	return SEPOL_OK;

exit:
	if (lvlrange != NULL) {
		cil_destroy_levelrange(lvlrange);
	}
	return rc;
}

void cil_destroy_levelrange(struct cil_levelrange *lvlrange)
{
	if (lvlrange == NULL) {
		return;
	}

	cil_symtab_datum_destroy(lvlrange->datum);

	if (lvlrange->low_str == NULL) {
		cil_destroy_level(lvlrange->low);
	} else {
		free(lvlrange->low_str);
	}

	if (lvlrange->high_str == NULL) {
		cil_destroy_level(lvlrange->high);
	} else {
		free(lvlrange->high_str);
	}

	free(lvlrange);
}

int cil_gen_constrain(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node, enum cil_flavor flavor)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_LIST,
		SYM_LIST,
		SYM_LIST,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	struct cil_constrain *cons = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid constrain declaration (line: %d)\n", parse_current->line);
		goto exit;
	}

	rc = cil_constrain_init(&cons);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	cil_list_init(&cons->class_list_str);
	cil_parse_to_list(parse_current->next->cl_head, cons->class_list_str, CIL_AST_STR);
	cil_list_init(&cons->perm_list_str);
	cil_parse_to_list(parse_current->next->next->cl_head, cons->perm_list_str, CIL_AST_STR);

	rc = cil_gen_expr_stack(parse_current->next->next->next, flavor, &cons->expr);
	if (rc != SEPOL_OK) {
		printf("Failed to build constrain expression tree\n");
		goto exit;
	}

	ast_node->data = cons;
	ast_node->flavor = flavor;

	return SEPOL_OK;

exit:
	if (cons != NULL) {
		cil_destroy_constrain(cons);
	}
	return rc;
}

void cil_destroy_constrain(struct cil_constrain *cons)
{
	if (cons == NULL) {
		return;
	}

	if (cons->class_list_str != NULL) {
		cil_list_destroy(&cons->class_list_str, 1);
	}
	if (cons->class_list != NULL) {
		cil_list_destroy(&cons->class_list, 0);
	}
	if (cons->perm_list_str != NULL) {
		cil_list_destroy(&cons->perm_list_str, 1);
	}
	if (cons->perm_list != NULL) {
		cil_list_destroy(&cons->perm_list, 0);
	}
	if (cons->expr != NULL) {
		cil_list_destroy(&cons->expr, CIL_FALSE);
	}

	free(cons);
}

/* Fills in context starting from user */
int cil_fill_context(struct cil_tree_node *user_node, struct cil_context *context)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_STRING,
		SYM_STRING | SYM_LIST,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	int rc = SEPOL_ERR;

	if (user_node == NULL || context == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(user_node, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid context (line: %d)\n", user_node->line);
		goto exit;
	}

	context->user_str = cil_strdup(user_node->data);
	context->role_str = cil_strdup(user_node->next->data);
	context->type_str = cil_strdup(user_node->next->next->data);

	context->range_str = NULL;

	if (user_node->next->next->next->cl_head == NULL) {
		context->range_str = cil_strdup(user_node->next->next->next->data);
	} else {
		rc = cil_levelrange_init(&context->range);
		if (rc != SEPOL_OK) {
			printf("Couldn't initialize levelrange\n");
			goto exit;
		}

		rc = cil_fill_levelrange(user_node->next->next->next->cl_head, context->range);
		if (rc != SEPOL_OK) {
			printf("cil_fill_context: Failed to fill levelrange, rc: %d\n", rc);
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_gen_context(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_LIST,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	char *key = NULL;
	struct cil_context *context = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid context declaration (line: %d)\n", parse_current->line);
		goto exit;
	}

	rc = cil_context_init(&context);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	key = parse_current->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)context, (hashtab_key_t)key, CIL_SYM_CONTEXTS, CIL_CONTEXT);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	rc = cil_fill_context(parse_current->next->next->cl_head, context);
	if (rc != SEPOL_OK) {
		printf("Failed to fill context, rc: %d\n", rc);
		goto exit;
	}

	return SEPOL_OK;

exit:
	if (context != NULL) {
		cil_destroy_context(context);
	}
	return SEPOL_ERR;
}

void cil_destroy_context(struct cil_context *context)
{
	if (context == NULL) {
		return;
	}
	
	cil_symtab_datum_destroy(context->datum);;

	if (context->user_str != NULL) {
		free(context->user_str);
	}

	if (context->role_str != NULL) {
		free(context->role_str);
	}

	if (context->type_str != NULL) {
		free(context->type_str);
	}

	if (context->range_str != NULL) {
		free(context->range_str);
	} else if (context->range != NULL) {
		cil_destroy_levelrange(context->range);
	}
}

int cil_gen_filecon(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_STRING,
		SYM_STRING,
		SYM_STRING | SYM_LIST,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	int rc = SEPOL_ERR;
	struct cil_filecon *filecon = NULL;
	char *type = NULL;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid filecon declaration (line: %d)\n", parse_current->line);
		goto exit;
	}

	type = parse_current->next->next->next->data;
	rc = cil_filecon_init(&filecon);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	filecon->root_str = cil_strdup(parse_current->next->data);
	filecon->path_str = cil_strdup(parse_current->next->next->data);

	if (!strcmp(type, "file")) {
		filecon->type = CIL_FILECON_FILE;
	} else if (!strcmp(type, "dir")) {
		filecon->type = CIL_FILECON_DIR;
	} else if (!strcmp(type, "char")) {
		filecon->type = CIL_FILECON_CHAR;
	} else if (!strcmp(type, "block")) {
		filecon->type = CIL_FILECON_BLOCK;
	} else if (!strcmp(type, "socket")) {
		filecon->type = CIL_FILECON_SOCKET;
	} else if (!strcmp(type, "pipe")) {
		filecon->type = CIL_FILECON_PIPE;
	} else if (!strcmp(type, "symlink")) {
		filecon->type = CIL_FILECON_SYMLINK;
	} else if (!strcmp(type, "any")) {
		filecon->type = CIL_FILECON_ANY;
	} else {
		printf("cil_gen_filecon: Invalid file type\n");
		rc = SEPOL_ERR;
		goto exit;
	}

	if (parse_current->next->next->next->next->cl_head == NULL) {
		filecon->context_str = cil_strdup(parse_current->next->next->next->next->data);
	} else {
		rc = cil_context_init(&filecon->context);
		if (rc != SEPOL_OK) {
			printf("Failed to init file context\n");
			goto exit;
		}

		rc = cil_fill_context(parse_current->next->next->next->next->cl_head, filecon->context);
		if (rc != SEPOL_OK) {
			printf("Failed to fill file context\n");
			goto exit;
		}
	}

	ast_node->data = filecon;
	ast_node->flavor = CIL_FILECON;

	return SEPOL_OK;

exit:
	if (filecon != NULL) {
		cil_destroy_filecon(filecon);
	}
	return rc;
}

//TODO: Should we be checking if the pointer is NULL when passed in?
void cil_destroy_filecon(struct cil_filecon *filecon)
{
	if (filecon == NULL) {
		return;
	}

	if (filecon->root_str != NULL) {
		free(filecon->root_str);
	}

	if (filecon->path_str != NULL) {
		free(filecon->path_str);
	}

	if (filecon->context_str != NULL) {
		free(filecon->context_str);
	} else if (filecon->context != NULL) {
		cil_destroy_context(filecon->context);
	}

	free(filecon);
}

int cil_gen_portcon(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_STRING | SYM_LIST,
		SYM_STRING | SYM_LIST,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	int rc = SEPOL_ERR;
	struct cil_portcon *portcon = NULL;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid portcon declaration (line: %d)\n", parse_current->line);
		goto exit;
	}

	rc = cil_portcon_init(&portcon);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	portcon->type_str = cil_strdup(parse_current->next->data);

	if (parse_current->next->next->cl_head != NULL) {
		if (parse_current->next->next->cl_head->next != NULL
		&& parse_current->next->next->cl_head->next->next == NULL) {
			rc = cil_fill_integer(parse_current->next->next->cl_head, &portcon->port_low);
			if (rc != SEPOL_OK) {
				printf("Error: Improper port specified\n");
				goto exit;
			}
			rc = cil_fill_integer(parse_current->next->next->cl_head->next, &portcon->port_high);
			if (rc != SEPOL_OK) {
				printf("Error: Improper port specified\n");
				goto exit;
			}
		} else {
			printf("Error: Improper port range specified\n");
			rc = SEPOL_ERR;
			goto exit;
		}
	} else {
		rc = cil_fill_integer(parse_current->next->next, &portcon->port_low);
		if (rc != SEPOL_OK) {
			printf("Error: Improper port specified\n");
			goto exit;
		}
		portcon->port_high = portcon->port_low;
	}

	if (parse_current->next->next->next->cl_head == NULL ) {
		portcon->context_str = cil_strdup(parse_current->next->next->next->data);
	} else {
		rc = cil_context_init(&portcon->context);
		if (rc != SEPOL_OK) {
			printf("Failed to init port context\n");
			goto exit;
		}

		rc = cil_fill_context(parse_current->next->next->next->cl_head, portcon->context);
		if (rc != SEPOL_OK) {
			printf("Failed to fill port context\n");
			goto exit;
		}
	}

	ast_node->data = portcon;
	ast_node->flavor = CIL_PORTCON;

	return SEPOL_OK;

exit:
	if (portcon != NULL) {
		cil_destroy_portcon(portcon);
	}
	return rc;
}

void cil_destroy_portcon(struct cil_portcon *portcon)
{
	if (portcon == NULL) {
		return;
	}

	if (portcon->type_str != NULL) {
		free(portcon->type_str);
	}

	if (portcon->context_str != NULL) {
		free(portcon->context_str);
	} else if (portcon->context != NULL) {
		cil_destroy_context(portcon->context);
	}

	free(portcon);
}

int cil_gen_nodecon(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING | SYM_LIST,
		SYM_STRING | SYM_LIST,
		SYM_STRING | SYM_LIST,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	int rc = SEPOL_ERR;
	struct cil_nodecon *nodecon = NULL;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid nodecon declaration (line: %d)\n", parse_current->line);
		goto exit;
	}

	rc = cil_nodecon_init(&nodecon);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	if (parse_current->next->cl_head == NULL ) {
		nodecon->addr_str = cil_strdup(parse_current->next->data);
	} else {
		rc = cil_ipaddr_init(&nodecon->addr);
		if (rc != SEPOL_OK) {
			printf("Failed to init node address\n");
			goto exit;
		}

		rc = cil_fill_ipaddr(parse_current->next->cl_head, nodecon->addr);
		if (rc != SEPOL_OK) {
			printf("Failed to fill node address\n");
			goto exit;
		}
	}

	if (parse_current->next->next->cl_head == NULL ) {
		nodecon->mask_str = cil_strdup(parse_current->next->next->data);
	} else {
		rc = cil_ipaddr_init(&nodecon->mask);
		if (rc != SEPOL_OK) {
			printf("Failed to init node netmask\n");
			goto exit;
		}

		rc = cil_fill_ipaddr(parse_current->next->next->cl_head, nodecon->mask);
		if (rc != SEPOL_OK) {
			printf("Failed to fill node netmask\n");
			goto exit;
		}
	}

	if (parse_current->next->next->next->cl_head == NULL ) {
		nodecon->context_str = cil_strdup(parse_current->next->next->next->data);
	} else {
		rc = cil_context_init(&nodecon->context);
		if (rc != SEPOL_OK) {
			printf("Failed to init node context\n");
			goto exit;
		}

		rc = cil_fill_context(parse_current->next->next->next->cl_head, nodecon->context);
		if (rc != SEPOL_OK) {
			printf("Failed to fill node context\n");
			goto exit;
		}
	}

	ast_node->data = nodecon;
	ast_node->flavor = CIL_NODECON;

	return SEPOL_OK;

exit:
	if (nodecon != NULL) {
		cil_destroy_nodecon(nodecon);
	}
	return rc;
}

void cil_destroy_nodecon(struct cil_nodecon *nodecon)
{
	if (nodecon == NULL) {
		return;
	}

	if (nodecon->addr_str != NULL) {
		free(nodecon->addr_str);
	} else if (nodecon->addr != NULL) {
		cil_destroy_ipaddr(nodecon->addr);
	}

	if (nodecon->mask_str != NULL) {
		free(nodecon->mask_str);
	} else if (nodecon->mask != NULL) {
		cil_destroy_ipaddr(nodecon->mask);
	}

	if (nodecon->context_str != NULL) {
		free(nodecon->context_str);
	} else if (nodecon->context != NULL) {
		cil_destroy_context(nodecon->context);
	}

	free(nodecon);
}

int cil_gen_genfscon(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_STRING,
		SYM_STRING | SYM_LIST,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	int rc = SEPOL_ERR;
	struct cil_genfscon *genfscon = NULL;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid genfscon declaration (line: %d)\n", parse_current->line);
		goto exit;
	}

	rc = cil_genfscon_init(&genfscon);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	genfscon->type_str = cil_strdup(parse_current->next->data);
	genfscon->path_str = cil_strdup(parse_current->next->next->data);

	if (parse_current->next->next->next->cl_head == NULL ) {
		genfscon->context_str = cil_strdup(parse_current->next->next->next->data);
	} else {
		rc = cil_context_init(&genfscon->context);
		if (rc != SEPOL_OK) {
			printf("Failed to init genfs context\n");
			goto exit;
		}

		rc = cil_fill_context(parse_current->next->next->next->cl_head, genfscon->context);
		if (rc != SEPOL_OK) {
			printf("Failed to fill genfs context\n");
			goto exit;
		}
	}

	ast_node->data = genfscon;
	ast_node->flavor = CIL_GENFSCON;

	return SEPOL_OK;

exit:
	if (genfscon != NULL) {
		cil_destroy_genfscon(genfscon);
	}
	return SEPOL_ERR;
}

void cil_destroy_genfscon(struct cil_genfscon *genfscon)
{
	if (genfscon == NULL) {
		return;
	}

	if (genfscon->type_str != NULL) {
		free(genfscon->type_str);
	}

	if (genfscon->path_str != NULL) {
		free(genfscon->path_str);
	}

	if (genfscon->context_str != NULL) {
		free(genfscon->context_str);
	} else if (genfscon->context != NULL) {
		cil_destroy_context(genfscon->context);
	}

	free(genfscon);
}


int cil_gen_netifcon(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_STRING | SYM_LIST,
		SYM_STRING | SYM_LIST,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	int rc = SEPOL_ERR;
	struct cil_netifcon *netifcon = NULL;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid netifcon declaration (line: %d)\n", parse_current->line);
		goto exit;
	}

	rc = cil_netifcon_init(&netifcon);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	netifcon->interface_str = cil_strdup(parse_current->next->data);

	if (parse_current->next->next->cl_head == NULL) {
		if (parse_current->next->next->data != NULL) {
			netifcon->if_context_str = cil_strdup(parse_current->next->next->data);
		} else {
			rc = SEPOL_ERR;
			goto exit;
		}
	} else {
		rc = cil_context_init(&netifcon->if_context);
		if (rc != SEPOL_OK) {
			printf("Failed to init if_context\n");
			goto exit;
		}

		rc = cil_fill_context(parse_current->next->next->cl_head, netifcon->if_context);
		if (rc != SEPOL_OK) {
			printf("Failed to fill interface context\n");
			goto exit;
		}
	}

	if (parse_current->next->next->next->cl_head == NULL) {
		if (parse_current->next->next->next->data != NULL) {
			netifcon->packet_context_str = cil_strdup(parse_current->next->next->next->data);
		} else {
			rc = SEPOL_ERR;
			goto exit;
		}
	} else {
		rc = cil_context_init(&netifcon->packet_context);
		if (rc != SEPOL_OK) {
			printf("Failed to init packet_context\n");
			goto exit;
		}

		rc = cil_fill_context(parse_current->next->next->next->cl_head, netifcon->packet_context);
		if (rc != SEPOL_OK) {
			printf("Failed to fill packet context\n");
			goto exit;
		}
	}

	ast_node->data = netifcon;
	ast_node->flavor = CIL_NETIFCON;

	return SEPOL_OK;

exit:
	if (netifcon != NULL) {
		cil_destroy_netifcon(netifcon);
	}
	return SEPOL_ERR;
}

void cil_destroy_netifcon(struct cil_netifcon *netifcon)
{
	if (netifcon == NULL) {
		return;
	}

	if (netifcon->interface_str != NULL) {
		free(netifcon->interface_str);
	}

	if (netifcon->if_context_str != NULL) {
		free(netifcon->if_context_str);
	} else if (netifcon->if_context != NULL) {
		cil_destroy_context(netifcon->if_context);
	}

	if (netifcon->packet_context_str != NULL) {
		free(netifcon->packet_context_str);
	} else if (netifcon->packet_context != NULL) {
		cil_destroy_context(netifcon->packet_context);
	}

	free(netifcon);
}

int cil_gen_pirqcon(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_STRING | SYM_LIST,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	int rc = SEPOL_ERR;
	struct cil_pirqcon *pirqcon = NULL;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid pirqcon declaration (line: %d)\n", parse_current->line);
		goto exit;
	}

	rc = cil_pirqcon_init(&pirqcon);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	rc = cil_fill_integer(parse_current->next, &pirqcon->pirq);
	if (rc != SEPOL_OK) {
		printf("Failed to parse pirq\n");
		goto exit;
	}

	if (parse_current->next->next->cl_head == NULL) {
		pirqcon->context_str = cil_strdup(parse_current->next->next->data);
	} else {
		rc = cil_context_init(&pirqcon->context);
		if (rc != SEPOL_OK) {
			printf("Failed to init pirq context\n");
			goto exit;
		}

		rc = cil_fill_context(parse_current->next->next->cl_head, pirqcon->context);
		if (rc != SEPOL_OK) {
			printf("Failed to fill port context\n");
			goto exit;
		}
	}

	ast_node->data = pirqcon;
	ast_node->flavor = CIL_PIRQCON;

	return SEPOL_OK;

exit:
	if (pirqcon != NULL) {
		cil_destroy_pirqcon(pirqcon);
	}
	return rc;
}

void cil_destroy_pirqcon(struct cil_pirqcon *pirqcon)
{
	if (pirqcon == NULL) {
		return;
	}

	if (pirqcon->context_str != NULL) {
		free(pirqcon->context_str);
	} else if (pirqcon->context != NULL) {
		cil_destroy_context(pirqcon->context);
	}

	free(pirqcon);
}

int cil_gen_iomemcon(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING | SYM_LIST,
		SYM_STRING | SYM_LIST,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	int rc = SEPOL_ERR;
	struct cil_iomemcon *iomemcon = NULL;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid iomemcon declaration (line: %d)\n", parse_current->line);
		goto exit;
	}

	rc = cil_iomemcon_init(&iomemcon);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	if (parse_current->next->cl_head != NULL) {
		if (parse_current->next->cl_head->next != NULL &&
		    parse_current->next->cl_head->next->next == NULL) {
			rc = cil_fill_integer(parse_current->next->cl_head, &iomemcon->iomem_low);
			if (rc != SEPOL_OK) {
				printf("Error: Improper iomem specified\n");
				goto exit;
			}
			rc = cil_fill_integer(parse_current->next->cl_head->next, &iomemcon->iomem_high);
			if (rc != SEPOL_OK) {
				printf("Error: Improper iomem specified\n");
				goto exit;
			}
		} else {
			printf("Error: Improper iomem range specified\n");
			rc = SEPOL_ERR;
			goto exit;
		}
	} else {
		rc = cil_fill_integer(parse_current->next, &iomemcon->iomem_low);;
		if (rc != SEPOL_OK) {
			printf("Error: Improper iomem specified\n");
			goto exit;
		}
		iomemcon->iomem_high = iomemcon->iomem_low;
	}

	if (parse_current->next->next->cl_head == NULL ) {
		iomemcon->context_str = cil_strdup(parse_current->next->next->data);
	} else {
		rc = cil_context_init(&iomemcon->context);
		if (rc != SEPOL_OK) {
			printf("Failed to init iomem context\n");
			goto exit;
		}

		rc = cil_fill_context(parse_current->next->next->cl_head, iomemcon->context);
		if (rc != SEPOL_OK) {
			printf("Failed to fill iomem context\n");
			goto exit;
		}
	}

	ast_node->data = iomemcon;
	ast_node->flavor = CIL_IOMEMCON;

	return SEPOL_OK;

exit:
	if (iomemcon != NULL) {
		cil_destroy_iomemcon(iomemcon);
	}
	return rc;
}

void cil_destroy_iomemcon(struct cil_iomemcon *iomemcon)
{
	if (iomemcon == NULL) {
		return;
	}

	if (iomemcon->context_str != NULL) {
		free(iomemcon->context_str);
	} else if (iomemcon->context != NULL) {
		cil_destroy_context(iomemcon->context);
	}

	free(iomemcon);
}

int cil_gen_ioportcon(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING | SYM_LIST,
		SYM_STRING | SYM_LIST,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	int rc = SEPOL_ERR;
	struct cil_ioportcon *ioportcon = NULL;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid ioportcon declaration (line: %d)\n", parse_current->line);
		goto exit;
	}

	rc = cil_ioportcon_init(&ioportcon);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	if (parse_current->next->cl_head != NULL) {
		if (parse_current->next->cl_head->next != NULL &&
		    parse_current->next->cl_head->next->next == NULL) {
			rc = cil_fill_integer(parse_current->next->cl_head, &ioportcon->ioport_low);
			if (rc != SEPOL_OK) {
				printf("Error: Improper ioport specified\n");
				goto exit;
			}
			rc = cil_fill_integer(parse_current->next->cl_head->next, &ioportcon->ioport_high);
			if (rc != SEPOL_OK) {
				printf("Error: Improper ioport specified\n");
				goto exit;
			}
		} else {
			printf("Error: Improper ioport range specified\n");
			rc = SEPOL_ERR;
			goto exit;
		}
	} else {
		rc = cil_fill_integer(parse_current->next, &ioportcon->ioport_low);
		if (rc != SEPOL_OK) {
			printf("Error: Improper ioport specified\n");
			goto exit;
		}
		ioportcon->ioport_high = ioportcon->ioport_low;
	}

	if (parse_current->next->next->cl_head == NULL ) {
		ioportcon->context_str = cil_strdup(parse_current->next->next->data);
	} else {
		rc = cil_context_init(&ioportcon->context);
		if (rc != SEPOL_OK) {
			printf("Failed to init ioport context\n");
			goto exit;
		}

		rc = cil_fill_context(parse_current->next->next->cl_head, ioportcon->context);
		if (rc != SEPOL_OK) {
			printf("Failed to fill ioport context\n");
			goto exit;
		}
	}

	ast_node->data = ioportcon;
	ast_node->flavor = CIL_IOPORTCON;

	return SEPOL_OK;

exit:
	if (ioportcon != NULL) {
		cil_destroy_ioportcon(ioportcon);
	}
	return rc;
}

void cil_destroy_ioportcon(struct cil_ioportcon *ioportcon)
{
	if (ioportcon == NULL) {
		return;
	}

	if (ioportcon->context_str != NULL) {
		free(ioportcon->context_str);
	} else if (ioportcon->context != NULL) {
		cil_destroy_context(ioportcon->context);
	}

	free(ioportcon);
}

int cil_gen_pcidevicecon(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_STRING | SYM_LIST,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	int rc = SEPOL_ERR;
	struct cil_pcidevicecon *pcidevicecon = NULL;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid pcidevicecon declaration (line: %d)\n", parse_current->line);
		goto exit;
	}

	rc = cil_pcidevicecon_init(&pcidevicecon);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	rc = cil_fill_integer(parse_current->next, &pcidevicecon->dev);
	if (rc != SEPOL_OK) {
		printf("Failed to parse pcidevice number\n");
		goto exit;
	}

	if (parse_current->next->next->cl_head == NULL) {
		pcidevicecon->context_str = cil_strdup(parse_current->next->next->data);
	} else {
		rc = cil_context_init(&pcidevicecon->context);
		if (rc != SEPOL_OK) {
			printf("Failed to init pcidevice context\n");
			goto exit;
		}

		rc = cil_fill_context(parse_current->next->next->cl_head, pcidevicecon->context);
		if (rc != SEPOL_OK) {
			printf("Failed to fill pcidevice context\n");
			goto exit;
		}
	}

	ast_node->data = pcidevicecon;
	ast_node->flavor = CIL_PCIDEVICECON;

	return SEPOL_OK;

exit:
	if (pcidevicecon != NULL) {
		cil_destroy_pcidevicecon(pcidevicecon);
	}
	return rc;
}

void cil_destroy_pcidevicecon(struct cil_pcidevicecon *pcidevicecon)
{
	if (pcidevicecon == NULL) {
		return;
	}

	if (pcidevicecon->context_str != NULL) {
		free(pcidevicecon->context_str);
	} else if (pcidevicecon->context != NULL) {
		cil_destroy_context(pcidevicecon->context);
	}

	free(pcidevicecon);
}

int cil_gen_fsuse(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_STRING,
		SYM_STRING | SYM_LIST,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	char *type = NULL;
	struct cil_fsuse *fsuse = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid fsuse declaration (line: %d)\n", parse_current->line);
		goto exit;
	}

	type = parse_current->next->data;

	rc = cil_fsuse_init(&fsuse);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	if (!strcmp(type, "xattr")) {
		fsuse->type = CIL_FSUSE_XATTR;
	} else if (!strcmp(type, "task")) {
		fsuse->type = CIL_FSUSE_TASK;
	} else if (!strcmp(type, "trans")) {
		fsuse->type = CIL_FSUSE_TRANS;
	} else {
		printf("Invalid fsuse type\n");
		goto exit;
	}

	fsuse->fs_str = cil_strdup(parse_current->next->next->data);

	if (parse_current->next->next->next->cl_head == NULL) {
		fsuse->context_str = cil_strdup(parse_current->next->next->next->data);
	} else {
		rc = cil_context_init(&fsuse->context);
		if (rc != SEPOL_OK) {
			printf("Failed to init fsuse context\n");
			goto exit;
		}

		rc = cil_fill_context(parse_current->next->next->next->cl_head, fsuse->context);
		if (rc != SEPOL_OK) {
			printf("Failed to fill fsuse context\n");
			goto exit;
		}
	}

	ast_node->data = fsuse;
	ast_node->flavor = CIL_FSUSE;

	return SEPOL_OK;

exit:
	if (fsuse != NULL) {
		cil_destroy_fsuse(fsuse);\
	}
	return SEPOL_ERR;
}

void cil_destroy_fsuse(struct cil_fsuse *fsuse)
{
	if (fsuse == NULL) {
		return;
	}

	if (fsuse->fs_str != NULL) {
		free(fsuse->fs_str);
	}

	if (fsuse->context_str != NULL) {
		free(fsuse->context_str);
	} else if (fsuse->context != NULL) {
		cil_destroy_context(fsuse->context);
	}

	free(fsuse);
}

void cil_destroy_param(struct cil_param *param)
{
	if (param == NULL) {
		return;
	}

	if (param->str != NULL) {
		free(param->str);
	}

	free(param);
}

int cil_gen_macro(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_LIST | SYM_EMPTY_LIST,
		SYM_N_LISTS
	};
	int syntax_len = sizeof(syntax)/ sizeof(*syntax);
	char *key = NULL;
	struct cil_macro *macro = NULL;
	struct cil_tree_node *macro_content = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc =__cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid macro declaration (line: %d)\n", parse_current->line);
		goto exit;
	}

	rc = cil_macro_init(&macro);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	key = parse_current->next->data;

	struct cil_tree_node *current_item = parse_current->next->next->cl_head;
	struct cil_list_item *params_tail = NULL;
	while (current_item != NULL) {
		char *kind = NULL;
		struct cil_param *param = NULL;

		if (macro->params == NULL) {
			cil_list_init(&macro->params);
		}

		if (current_item->cl_head == NULL) {
			printf("Invalid macro declaration (line: %d)\n", parse_current->line);
			goto exit;
		}

		kind = current_item->cl_head->data;
		cil_param_init(&param);

		if (!strcmp(kind, CIL_KEY_TYPE)) {
			param->flavor = CIL_TYPE;
		} else if (!strcmp(kind, CIL_KEY_ROLE)) {
			param->flavor = CIL_ROLE;
		} else if (!strcmp(kind, CIL_KEY_USER)) {
			param->flavor = CIL_USER;
		} else if (!strcmp(kind, CIL_KEY_SENSITIVITY)) {
			param->flavor = CIL_SENS;
		} else if (!strcmp(kind, CIL_KEY_CATEGORY)) {
			param->flavor = CIL_CAT;
		} else if (!strcmp(kind, CIL_KEY_CATSET)) {
			param->flavor = CIL_CATSET;
		} else if (!strcmp(kind, CIL_KEY_LEVEL)) {
			param->flavor = CIL_LEVEL;
		} else if (!strcmp(kind, CIL_KEY_LEVELRANGE)) {
			param->flavor = CIL_LEVELRANGE;
		} else if (!strcmp(kind, CIL_KEY_CLASS)) {
			param->flavor = CIL_CLASS;
		} else if (!strcmp(kind, CIL_KEY_IPADDR)) {
			param->flavor = CIL_IPADDR;
		} else if (!strcmp(kind, CIL_KEY_PERMSET)) {
			param->flavor = CIL_PERMSET;
		} else {
			printf("Invalid macro declaration (line: %d)\n", parse_current->line);
			cil_destroy_param(param);
			goto exit;
		}

		param->str =  cil_strdup(current_item->cl_head->next->data);

		if (strchr(param->str, '.')) {
			printf("Invalid macro declaration: parameter names cannot contain a '.' (line: %d)\n", parse_current->line);
			cil_destroy_param(param);
			goto exit;
		}

		if (params_tail == NULL) {
			cil_list_item_init(&macro->params->head);
			macro->params->head->data = param;
			macro->params->head->flavor = CIL_PARAM;

			params_tail = macro->params->head;
		} else {
			//walk current list and check for duplicate parameters
			struct cil_list_item *curr_param = macro->params->head;
			while (curr_param != NULL) {
				if (!strcmp(param->str, ((struct cil_param*)curr_param->data)->str)) {
					if (param->flavor == ((struct cil_param*)curr_param->data)->flavor) {
						printf("Invalid macro declaration (line: %d): Duplicate parameter\n", parse_current->line);
						cil_destroy_param(param);
						goto exit;
					}
				}
				curr_param = curr_param->next;
			}

			cil_list_item_init(&params_tail->next);
			params_tail->next->data = param;
			params_tail->next->flavor = CIL_PARAM;

			params_tail = params_tail->next;
		}

		current_item = current_item->next;
	}

	/* we don't want the tree walker to walk the macro parameters (they were just handled above), so the subtree is deleted, and the next pointer of the
           node containing the macro name is updated to point to the start of the macro content */
	macro_content = parse_current->next->next->next;
	cil_tree_subtree_destroy(parse_current->next->next);
	parse_current->next->next = macro_content;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)macro, (hashtab_key_t)key, CIL_SYM_MACROS, CIL_MACRO);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	return SEPOL_OK;

exit:
	if (macro != NULL) {
		cil_destroy_macro(macro);
	}
	return SEPOL_ERR;
}

void cil_destroy_macro(struct cil_macro *macro)
{
	if (macro == NULL) {
		return;
	}

	cil_symtab_datum_destroy(macro->datum);
	cil_symtab_array_destroy(macro->symtab);

	if (macro->params != NULL) {
		cil_list_destroy(&macro->params, 1);
	}

	free(macro);
}

int cil_gen_call(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_LIST | SYM_END,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	struct cil_call *call = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid call declaration (line: %d)\n", parse_current->line);
		goto exit;
	}

	rc = cil_call_init(&call);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	call->macro_str = cil_strdup(parse_current->next->data);

	if (parse_current->next->next != NULL) {
		cil_tree_init(&call->args_tree);
		cil_tree_node_init(&call->args_tree->root);
		cil_copy_ast(db, parse_current->next->next, call->args_tree->root);
	}

	ast_node->data = call;
	ast_node->flavor = CIL_CALL;

	return SEPOL_OK;

exit:
	if (call != NULL) {
		cil_destroy_call(call);
	}
	return rc;
}

void cil_destroy_call(struct cil_call *call)
{
	if (call == NULL) {
		return;
	}

	if (call->macro_str != NULL) {
		free(call->macro_str);
	}

	call->macro = NULL;

	if (call->args_tree != NULL) {
		cil_tree_destroy(&call->args_tree);
	}

	if (call->args != NULL) {
		cil_list_destroy(&call->args, 1);
	}

	free(call);
}

void cil_destroy_args(struct cil_args *args)
{
	if (args == NULL) {
		return;
	}

	args->param_str = NULL;
	if (args->arg_str == NULL) {
		switch (args->arg->flavor) {
		case CIL_LEVEL:
			cil_tree_node_destroy(&args->arg);
			args->arg = NULL;
			break;
		case CIL_CATSET:
			cil_tree_node_destroy(&args->arg);
			args->arg = NULL;
			break;
		case CIL_IPADDR:
			cil_tree_node_destroy(&args->arg);
			args->arg = NULL;
			break;
		}
	}

	if (args->arg_str != NULL) {
		free(args->arg_str);
	}

	free(args);
}

int cil_gen_optional(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_N_LISTS
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	char *key = NULL;
	struct cil_optional *optional = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid optional declaration (line: %d)\n", parse_current->line);
		goto exit;
	}

	rc = cil_optional_init(&optional);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	key = parse_current->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)optional, (hashtab_key_t)key, CIL_SYM_OPTIONALS, CIL_OPTIONAL);
	if (rc != SEPOL_OK)
		goto exit;

	return SEPOL_OK;

exit:
	if (optional != NULL) {
		cil_destroy_optional(optional);
	}
	return rc;
}

void cil_destroy_optional(struct cil_optional *optional)
{
	if (optional == NULL) {
		return;
	}

	cil_symtab_datum_destroy(optional->datum);
	free(optional);
}

int cil_gen_policycap(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	char *key = NULL;
	struct cil_policycap *polcap = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid policycap declaration (line: %d)\n", parse_current->line);
		goto exit;
	}

	rc = cil_policycap_init(&polcap);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	key = parse_current->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)polcap, (hashtab_key_t)key, CIL_SYM_POLICYCAPS, CIL_POLICYCAP);
	if (rc != SEPOL_OK)
		goto exit;

	return SEPOL_OK;

exit:
	if (polcap != NULL) {
		cil_destroy_policycap(polcap);
	}
	return rc;
}

void cil_destroy_policycap(struct cil_policycap *polcap)
{
	if (polcap == NULL) {
		return;
	}

	cil_symtab_datum_destroy(polcap->datum);
	free(polcap);
}

int cil_gen_ipaddr(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_STRING,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	char *key = NULL;
	struct cil_ipaddr *ipaddr = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid ipaddr rule (line: %d)\n", parse_current->line);
		goto exit;
	}

	rc = cil_ipaddr_init(&ipaddr);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	key  = parse_current->next->data;

	rc = cil_fill_ipaddr(parse_current->next->next, ipaddr);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)ipaddr, (hashtab_key_t)key, CIL_SYM_IPADDRS, CIL_IPADDR);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	return SEPOL_OK;

exit:
	if (ipaddr != NULL) {
		cil_destroy_ipaddr(ipaddr);
	}
	return rc;
}

void cil_destroy_ipaddr(struct cil_ipaddr *ipaddr)
{
	if (ipaddr == NULL) {
		return;
	}

	cil_symtab_datum_destroy(ipaddr->datum);
	free(ipaddr);
}

int cil_fill_cat_list(struct cil_tree_node *start, struct cil_list *list)
{
	int rc = SEPOL_ERR;

	if (start == NULL || list == NULL) {
		goto exit;
	}

	rc = cil_set_to_list(start, list, 1);
	if (rc != SEPOL_OK) {
		printf("Failed to create category list\n");
		goto exit;
	}

	rc = __cil_verify_ranges(list);
	if (rc != SEPOL_OK) {
		printf("Error verifying range syntax\n");
		goto exit;
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_fill_integer(struct cil_tree_node *int_node, uint32_t *integer)
{
	int rc = SEPOL_ERR;
	char *endptr = NULL;
	int val;

	if (int_node == NULL || integer == NULL) {
		goto exit;	
	}

	errno = 0;
	val = strtol(int_node->data, &endptr, 10);
	if (errno != 0 || endptr == int_node->data || *endptr != '\0') {
		rc = SEPOL_ERR;
		goto exit;
	}

	*integer = val;
	
	return SEPOL_OK;

exit:
	return rc;
}

int cil_fill_ipaddr(struct cil_tree_node *addr_node, struct cil_ipaddr *addr)
{
	int rc = SEPOL_ERR;

	if (addr_node == NULL || addr == NULL) {
		goto exit;
	}

	if (addr_node->cl_head != NULL ||  addr_node->next != NULL) {
		printf("Invalid ip address (line: %d)\n", addr_node->line);
		goto exit;
	}

	if (strchr(addr_node->data, '.') != NULL) {
		addr->family = AF_INET;
	} else {
		addr->family = AF_INET6;
	}

	rc = inet_pton(addr->family, addr_node->data, &addr->ip);
	if (rc != 1) {
		printf("Invalid ip address (line: %d)\n", addr_node->line);
		rc = SEPOL_ERR;
		goto exit;
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_fill_level(struct cil_tree_node *sens, struct cil_level *level)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING | SYM_LIST | SYM_END,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	int rc = SEPOL_ERR;

	if (sens == NULL || level == NULL) {
		goto exit;
	}
	
	rc = __cil_verify_syntax(sens, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid categoryrange declaration (line: %d)\n", sens->line);
		goto exit;
	}

	level->sens_str = cil_strdup(sens->data);

	if (sens->next != NULL) {
		if (sens->next->cl_head == NULL) {
			level->catset_str = cil_strdup(sens->next->data);
		} else {
			rc = cil_catset_init(&level->catset);
			if (rc != SEPOL_OK) {
				goto exit;
			}

			rc = cil_fill_catset(sens->next->cl_head, level->catset);
			if (rc != SEPOL_OK) {
				goto exit;
			}
		}
	}

	return SEPOL_OK;

exit:
	return rc;
}
	
int cil_fill_catrange(struct cil_tree_node *cats, struct cil_catrange *catrange)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	int rc = SEPOL_ERR;

	if (cats == NULL || catrange == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(cats, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid categoryrange declaration (line: %d)\n", cats->line);
		goto exit;
	}

	catrange->cat_low_str = cil_strdup(cats->data);
	catrange->cat_high_str = cil_strdup(cats->next->data);

	return SEPOL_OK;

exit:
	return rc;
}

int cil_fill_catset(struct cil_tree_node *cats, struct cil_catset *catset)
{
	enum cil_syntax syntax[] = {
		SYM_N_STRINGS | SYM_N_LISTS
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);

	struct cil_tree_node *curr = NULL;
	struct cil_list *cat_list = NULL;
	struct cil_list_item *cat_item = NULL;
	struct cil_catrange *catrange = NULL;
	int rc = SEPOL_ERR;

	if (cats == NULL || catset == NULL) {
		rc = SEPOL_ERR;
		goto exit;
	}

	rc = __cil_verify_syntax(cats, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid category set (line %d)\n", cats->line);
		goto exit;
	}

	cil_list_init(&cat_list);

	for (curr = cats; curr != NULL; curr = curr->next) {
		cil_list_item_init(&cat_item);

		if (curr->data != NULL) {
			/* named category or categoryrange */
			cat_item->flavor = CIL_AST_STR;
			cat_item->data = cil_strdup(curr->data);
		} else {
			/* anonymous category range */
			rc = cil_catrange_init(&catrange);
			if (rc != SEPOL_OK) {
				goto exit;
			}

			rc = cil_fill_catrange(curr->cl_head, catrange);
			if (rc != SEPOL_OK) {
				goto exit;
			}
			
			cat_item->flavor = CIL_CATRANGE;
			cat_item->data = catrange;		
		}
		
		rc = cil_list_append_item(cat_list, cat_item);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	catset->cat_list_str = cat_list;

	return SEPOL_OK;

exit:
	return rc;
}

int __cil_build_ast_node_helper(struct cil_tree_node *parse_current, uint32_t *finished, void *extra_args)
{
	struct cil_args_build *args = NULL;
	struct cil_tree_node *ast_current = NULL;
	struct cil_db *db = NULL;
	struct cil_tree_node *ast_node = NULL;
	struct cil_tree_node *macro = NULL;
	int rc = SEPOL_ERR;

	if (parse_current == NULL || finished == NULL || extra_args == NULL) {
		goto exit;
	}

	args = extra_args;
	ast_current = args->ast;
	db = args->db;
	macro = args->macro;

	if (parse_current->parent->cl_head != parse_current) {
		/* ignore anything that isn't following a parenthesis */
		rc = SEPOL_OK;
		goto exit;
	} else if (parse_current->data == NULL) {
		/* the only time parenthsis can immediately following parenthesis is if
		 * the parent is the root node */
		if (parse_current->parent->parent == NULL) {
			rc = SEPOL_OK;
		} else {
			printf("Syntax Error: Keyword expected after open parenthesis, line: %d\n", parse_current->line);
		}
		goto exit;
	}

	rc = cil_tree_node_init(&ast_node);
	if (rc != SEPOL_OK) {
		printf("Failed to init tree node, rc: %d\n", rc);
		goto exit;
	}

	ast_node->parent = ast_current;
	ast_node->line = parse_current->line;
	if (ast_current->cl_head == NULL) {
		ast_current->cl_head = ast_node;
	} else {
		ast_current->cl_tail->next = ast_node;
	}
	ast_current->cl_tail = ast_node;
	ast_current = ast_node;
	args->ast = ast_current;

	if (!strcmp(parse_current->data, CIL_KEY_BLOCK)) {
		rc = cil_gen_block(db, parse_current, ast_node, 0, NULL);
		if (rc != SEPOL_OK) {
			printf("cil_gen_block failed, rc: %d\n", rc);
			goto exit;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_CLASS)) {
		rc = cil_gen_class(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_class failed, rc: %d\n", rc);
			goto exit;
		}
		// To avoid parsing list of perms again
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_PERMSET)) {
		rc = cil_gen_permset(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_permset failed, rc: %d\n", rc);
			goto exit;
		}
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_COMMON)) {
		rc = cil_gen_common(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_common failed, rc: %d\n", rc);
			goto exit;
		}
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_CLASSCOMMON)) {
		rc = cil_gen_classcommon(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_classcommon failed, rc: %d\n", rc);
			goto exit;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_SID)) {
		rc = cil_gen_sid(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_sid failed, rc: %d\n", rc);
			goto exit;
		}
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_SIDCONTEXT)) {
		rc = cil_gen_sidcontext(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_sidcontext failed, rc: %d\n", rc);
			goto exit;
		}
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_USER)) {
		rc = cil_gen_user(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_user failed, rc: %d\n", rc);
			goto exit;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_USERLEVEL)) {
		rc = cil_gen_userlevel(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_userlevel failed, rc: %d\n", rc);
			goto exit;
		}
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_USERRANGE)) {
		rc = cil_gen_userrange(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_userrange failed, rc: %d\n", rc);
			goto exit;
		}
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_USERBOUNDS)) {
		rc = cil_gen_userbounds(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_userbounds failed, rc: %d\n", rc);
			goto exit;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_TYPE)) {
		rc = cil_gen_type(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_type failed, rc: %d\n", rc);
			goto exit;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_TYPEATTRIBUTE)) {
		rc = cil_gen_typeattribute(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_typeattribute failed, rc: %d\n", rc);
			goto exit;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_TYPEATTRIBUTETYPES)) {
		rc = cil_gen_typeattributetypes(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_typeattributetypes failed, rc: %d\n", rc);
			goto exit;
		}
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_TYPEALIAS)) {
		rc = cil_gen_typealias(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_typealias failed, rc: %d\n", rc);
			goto exit;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_TYPEBOUNDS)) {
		rc = cil_gen_typebounds(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_typebounds failed, rc: %d\n", rc);
			goto exit;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_TYPEPERMISSIVE)) {
		rc = cil_gen_typepermissive(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_typepermissive failed, rc: %d\n", rc);
			goto exit;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_FILETRANSITION)) {
		rc = cil_gen_filetransition(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_filetransition failed, rc: %d\n", rc);
			goto exit;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_RANGETRANSITION)) {
		rc = cil_gen_rangetransition(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_rangetransition failed, rc: %d\n", rc);
			goto exit;
		}
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_ROLE)) {
		rc = cil_gen_role(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_role failed, rc: %d\n", rc);
			goto exit;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_USERROLE)) {
		rc = cil_gen_userrole(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_userrole failed, rc: %d\n", rc);
			goto exit;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_ROLETYPE)) {
		rc = cil_gen_roletype(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_roletype failed, rc: %d\n", rc);
			goto exit;
		}
	}
	else if (!strcmp(parse_current->data, CIL_KEY_ROLETRANS)) {
		rc = cil_gen_roletrans(parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_roletrans failed, rc: %d\n", rc);
			goto exit;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_ROLEALLOW)) {
		rc = cil_gen_roleallow(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_roleallow failed, rc: %d\n", rc);
			goto exit;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_ROLEDOMINANCE)) {
		rc = cil_gen_roledominance(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_roledominance failed, rc: %d\n", rc);
			goto exit;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_ROLEBOUNDS)) {
		rc = cil_gen_rolebounds(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_rolebounds failed, rc: %d\n", rc);
			goto exit;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_BOOL)) {
		rc = cil_gen_bool(db, parse_current, ast_node, CIL_BOOL);
		if (rc != SEPOL_OK) {
			printf("cil_gen_bool failed, rc: %d\n", rc);
			goto exit;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_BOOLEANIF)) {
		rc = cil_gen_boolif(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_boolif failed, rc: %d\n", rc);
			goto exit;
		}
	} else if(!strcmp(parse_current->data, CIL_KEY_TUNABLE)) {
		rc = cil_gen_bool(db, parse_current, ast_node, CIL_TUNABLE);
		if (rc != SEPOL_OK) {
			printf("cil_gen_bool failed, rc: %d\n", rc);
			goto exit;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_TUNABLEIF)) {
		rc = cil_gen_tunif(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_tunif failed, rc: %d\n", rc);
			goto exit;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_CONDTRUE)) {
		rc = cil_gen_condtrue(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_condtrue failed, rc: %d\n", rc);
			goto exit;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_CONDFALSE)) {
		rc = cil_gen_condfalse(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_condfalse failed, rc: %d\n", rc);
			goto exit;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_ALLOW)) {
		rc = cil_gen_avrule(parse_current, ast_node, CIL_AVRULE_ALLOWED);
		if (rc != SEPOL_OK) {
			printf("cil_gen_avrule (allow) failed, rc: %d\n", rc);
			goto exit;
		}
		// So that the object and perms lists do not get parsed again
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_AUDITALLOW)) {
		rc = cil_gen_avrule(parse_current, ast_node, CIL_AVRULE_AUDITALLOW);
		if (rc != SEPOL_OK) {
			printf("cil_gen_avrule (auditallow) failed, rc: %d\n", rc);
			goto exit;
		}
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_DONTAUDIT)) {
		rc = cil_gen_avrule(parse_current, ast_node, CIL_AVRULE_DONTAUDIT);
		if (rc != SEPOL_OK) {
			printf("cil_gen_avrule (dontaudit) failed, rc: %d\n", rc);
			goto exit;
		}
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_NEVERALLOW)) {
		rc = cil_gen_avrule(parse_current, ast_node, CIL_AVRULE_NEVERALLOW);
		if (rc != SEPOL_OK) {
			printf("cil_gen_avrule (neverallow) failed, rc: %d\n", rc);
			goto exit;
		}
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_TYPETRANS)) {
		rc = cil_gen_type_rule(parse_current, ast_node, CIL_TYPE_TRANSITION);
		if (rc != SEPOL_OK) {
			printf("cil_gen_type_rule (typetransition) failed, rc: %d\n", rc);
			goto exit;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_TYPECHANGE)) {
		rc = cil_gen_type_rule(parse_current, ast_node, CIL_TYPE_CHANGE);
		if (rc != SEPOL_OK) {
			printf("cil_gen_type_rule (typechange) failed, rc: %d\n", rc);
			goto exit;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_TYPEMEMBER)) {
		rc = cil_gen_type_rule(parse_current, ast_node, CIL_TYPE_MEMBER);
		if (rc != SEPOL_OK) {
			printf("cil_gen_type_rule (typemember) failed, rc: %d\n", rc);
			goto exit;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_SENSITIVITY)) {
		rc = cil_gen_sensitivity(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_sensitivity (sensitivity) failed, rc: %d\n", rc);
			goto exit;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_SENSALIAS)) {
		rc = cil_gen_sensalias(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_sensalias (sensitivityalias) failed, rc: %d\n", rc);
			goto exit;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_CATEGORY)) {
		rc = cil_gen_category(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_category (category) failed, rc: %d\n", rc);
			goto exit;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_CATALIAS)) {
		rc = cil_gen_catalias(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_catalias (categoryalias) failed, rc: %d\n", rc);
			goto exit;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_CATRANGE)) {
		rc = cil_gen_catrange(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_catrange (categoryrange) failed, rc: %d\n", rc);
			goto exit;
		}
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_CATSET)) {
		rc = cil_gen_catset(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_catset (categoryset) failed, rc: %d\n", rc);
			goto exit;
		}
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_CATORDER)) {
		rc = cil_gen_catorder(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_catorder failed, rc: %d\n", rc);
			goto exit;
		}
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_DOMINANCE)) {
		rc = cil_gen_dominance(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_dominance failed, rc: %d\n", rc);
			goto exit;
		}
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_SENSCAT)) {
		rc = cil_gen_senscat(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_senscat failed, rc: %d\n", rc);
			goto exit;
		}
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_LEVEL)) {
		rc = cil_gen_level(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_level failed, rc: %d\n", rc);
			goto exit;
		}
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_LEVELRANGE)) {
		rc = cil_gen_levelrange(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_levelrange failed, rc: %d\n", rc);
			goto exit;
		}
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_CONSTRAIN)) {
		rc = cil_gen_constrain(db, parse_current, ast_node, CIL_CONSTRAIN);
		if (rc != SEPOL_OK) {
			printf("cil_gen_constrain failed, rc: %d\n", rc);
			goto exit;
		}
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_MLSCONSTRAIN)) {
		rc = cil_gen_constrain(db, parse_current, ast_node, CIL_MLSCONSTRAIN);
		if (rc != SEPOL_OK) {
			printf("cil_gen_constrain failed, rc: %d\n", rc);
			goto exit;
		}
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_CONTEXT)) {
		rc = cil_gen_context(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_context failed, rc: %d\n", rc);
			goto exit;
		}
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_FILECON)) {
		rc = cil_gen_filecon(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_filecon failed, rc: %d\n", rc);
			goto exit;
		}
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_PORTCON)) {
		rc = cil_gen_portcon(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_portcon failed, rc: %d\n", rc);
			goto exit;
		}
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_NODECON)) {
		rc = cil_gen_nodecon(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_nodecon failed, rc: %d\n", rc);
			goto exit;
		}
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_GENFSCON)) {
		rc = cil_gen_genfscon(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_genfscon failed, rc: %d\n", rc);
			goto exit;
		}
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_NETIFCON)) {
		rc = cil_gen_netifcon(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_netifcon failed, rc: %d\n", rc);
			goto exit;
		}
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_PIRQCON)) {
		rc = cil_gen_pirqcon(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_pirqcon failed, rc: %d\n", rc);
			goto exit;
		}
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_IOMEMCON)) {
		rc = cil_gen_iomemcon(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_iomemcon failed, rc: %d\n", rc);
			goto exit;
		}
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_IOPORTCON)) {
		rc = cil_gen_ioportcon(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_ioportcon failed, rc: %d\n", rc);
			goto exit;
		}
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_PCIDEVICECON)) {
		rc = cil_gen_pcidevicecon(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_pcidevicecon failed, rc: %d\n", rc);
			goto exit;
		}
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_FSUSE)) {
		rc = cil_gen_fsuse(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_fsuse failed, rc: %d\n", rc);
			goto exit;
		}
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_MACRO)) {
		rc = cil_gen_macro(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_macro failed, rc: %d\n", rc);
			goto exit;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_CALL)) {
		rc = cil_gen_call(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_call failed, rc: %d\n", rc);
			goto exit;
		}
		*finished = 1;
	} else if (!strcmp(parse_current->data, CIL_KEY_POLICYCAP)) {
		rc = cil_gen_policycap(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_policycap failed, rc: %d\n", rc);
			goto exit;
		}
		*finished = 1;
	} else if (!strcmp(parse_current->data, CIL_KEY_OPTIONAL)) {
		rc = cil_gen_optional(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_optional failed, rc: %d\n", rc);
			goto exit;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_IPADDR)) {
		rc = cil_gen_ipaddr(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_ipaddr failed, rc: %d\n", rc);
			goto exit;
		}
	} else {
		printf("Error: Unknown keyword %s\n", (char*)parse_current->data);
		rc = SEPOL_ERR;
		goto exit;
	}

	if (macro != NULL) {
		if (!strcmp(parse_current->data, CIL_KEY_MACRO)) {
			rc = SEPOL_ERR;
			goto exit;
		}

		if (!strcmp(parse_current->data, CIL_KEY_TUNABLEIF)) {
			rc = SEPOL_ERR;
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	return rc;
}

int __cil_build_ast_first_child_helper(__attribute__((unused)) struct cil_tree_node *parse_current, void *extra_args)
{
	int rc = SEPOL_ERR;
	struct cil_args_build *args = NULL;

	if (extra_args == NULL) {
		goto exit;
	}

	args = extra_args;

	if (args->ast->flavor == CIL_MACRO) {
		args->macro = args->ast; 
	}

	return SEPOL_OK;

exit:
	return rc;
}

int __cil_build_ast_last_child_helper(__attribute__((unused)) struct cil_tree_node *parse_current, void *extra_args)
{
	int rc = SEPOL_ERR;
	struct cil_tree_node *ast = NULL;
	struct cil_args_build *args = NULL;

	if (extra_args == NULL) {
		goto exit;
	}

	args = extra_args;
	ast = args->ast;

	if (ast->flavor == CIL_ROOT) {
		rc = SEPOL_OK;
		goto exit;
	}

	args->ast = ast->parent;

	if (args->ast->flavor == CIL_MACRO) {
		args->macro = NULL;
	}

	if (args->ast->flavor == CIL_TUNABLEIF) {
		cil_symtab_destroy(((struct cil_tunableif*)args->ast->data)->symtab);
	}

	return SEPOL_OK;

exit:
	return rc;
}

int cil_build_ast(struct cil_db *db, struct cil_tree_node *parse_tree, struct cil_tree_node *ast)
{
	int rc = SEPOL_ERR;
	struct cil_args_build extra_args;

	if (db == NULL || parse_tree == NULL || ast == NULL) {
		goto exit;
	}

	extra_args.ast = ast;
	extra_args.db = db;
	extra_args.macro = NULL;

	rc = cil_tree_walk(parse_tree, __cil_build_ast_node_helper, __cil_build_ast_first_child_helper, __cil_build_ast_last_child_helper, &extra_args);
	if (rc != SEPOL_OK) {
		printf("cil_tree_walk failed, rc: %d\n", rc);
		goto exit;
	}

	return SEPOL_OK;

exit:
	return rc;
}
