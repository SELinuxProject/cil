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

int __cil_verify_name(const char *name)
{
	int rc = SEPOL_ERR;
	int len = strlen(name);
	int i = 0;
	for (i = 0; i < len; i++) {
		if (!isalnum(name[i]) && name[i] != '_') {
			printf("Invalid character %c in %s\n", name[i], name);
			goto verify_name_out;
		}
	}
	return SEPOL_OK;

verify_name_out:
	return rc;
}

int __cil_verify_syntax(struct cil_tree_node *parse_current, enum cil_syntax s[], int len)
{
	int rc = SEPOL_ERR;
	int num_lists = 0;
	struct cil_tree_node *c = parse_current;
	int i = 0;
	while (i < len) {
		if ((s[i] & SYM_END) && c == NULL) {
			break;
		}

		if (s[i] & SYM_N_LISTS) {
			if (c == NULL) {
				if (num_lists > 0) {
					break;
				} else {
					goto verify_syntax_out;
				}
			} else if (c->data == NULL && c->cl_head != NULL) {
				c = c->next;
				num_lists++;
				continue;
			}
		}

		if (c == NULL) {
			goto verify_syntax_out;
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
		goto verify_syntax_out;
	}
	return SEPOL_OK;

verify_syntax_out:
	return rc;
}

int cil_gen_node(struct cil_db *db, struct cil_tree_node *ast_node, struct cil_symtab_datum *datum, hashtab_key_t key, enum cil_sym_index sflavor, enum cil_flavor nflavor)
{
	symtab_t *symtab = NULL;
	int rc = SEPOL_ERR;

	rc = __cil_verify_name((const char*)key);
	if (rc != SEPOL_OK) {
		goto gen_node_out;
	}

	rc = cil_get_parent_symtab(db, ast_node, &symtab, sflavor);
	if (rc != SEPOL_OK) {
		goto gen_node_out;
	}

	rc = cil_symtab_insert(symtab, (hashtab_key_t)key, datum, ast_node);
	if (rc != SEPOL_OK) {
		printf("Failed to insert %s into symtab, rc: %d\n", key, rc);
		goto gen_node_out;
	}

	ast_node->data = datum;
	ast_node->flavor = nflavor;

	return SEPOL_OK;

gen_node_out:
	return rc;
}

int cil_parse_to_list(struct cil_tree_node *parse_cl_head, struct cil_list *ast_cl, enum cil_flavor flavor)
{
	struct cil_list_item *new_item = NULL;
	struct cil_tree_node *parse_current = parse_cl_head;
	struct cil_list_item *list_tail = NULL;
	int rc = SEPOL_ERR;
	
	if (parse_current == NULL || ast_cl == NULL) {
		goto parse_to_list_out;
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

parse_to_list_out:
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
		goto gen_block_cleanup;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid block declaration (line: %d)\n", parse_current->line);
		goto gen_block_cleanup;
	}

	rc = cil_block_init(&block);
	if (rc != SEPOL_OK) {
		goto gen_block_cleanup;
	}

	block->is_abstract = is_abstract;
	block->condition = condition;

	key = parse_current->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)block, (hashtab_key_t)key, CIL_SYM_BLOCKS, CIL_BLOCK);
	if (rc != SEPOL_OK) {
		goto gen_block_cleanup;
	}

	return SEPOL_OK;

gen_block_cleanup:
	if (block != NULL) {
		cil_destroy_block(block);
	}
	return rc;
}

void cil_destroy_block(struct cil_block *block)
{
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
		goto gen_class_cleanup;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid class declaration (line: %d)\n", parse_current->line);
		goto gen_class_cleanup;
	}

	rc = cil_class_init(&class);
	if (rc != SEPOL_OK) {
		goto gen_class_cleanup;
	}

	key = parse_current->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)class, (hashtab_key_t)key, CIL_SYM_CLASSES, CIL_CLASS);
	if (rc != SEPOL_OK) {
		goto gen_class_cleanup;
	}

	perms = parse_current->next->next->cl_head;

	rc = cil_gen_perm_nodes(db, perms, ast_node);
	if (rc != SEPOL_OK) {
		printf("Class: failed to parse perms\n");
		goto gen_class_cleanup;
	}

	return SEPOL_OK;

gen_class_cleanup:
	if (class != NULL) {
		cil_destroy_class(class);
	}
	return rc;
}

void cil_destroy_class(struct cil_class *class)
{
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
		goto gen_perm_cleanup;
	}

	rc = cil_perm_init(&perm);
	if (rc != SEPOL_OK) {
		goto gen_perm_cleanup;
	}

	key = parse_current->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)perm, (hashtab_key_t)key, CIL_SYM_UNKNOWN, CIL_PERM);
	if (rc != SEPOL_OK) {
		goto gen_perm_cleanup;
	}

	return SEPOL_OK;

gen_perm_cleanup:
	if (perm != NULL) {
		cil_destroy_perm(perm);
	}
	return rc;
}

void cil_destroy_perm(struct cil_perm *perm)
{
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
			goto gen_perm_nodes_out;
		}
		cil_tree_node_init(&new_ast);
		new_ast->parent = ast_node;
		new_ast->line = current_perm->line;
		rc = cil_gen_perm(db, current_perm, new_ast);
		if (rc != SEPOL_OK) {
			printf("CLASS: Failed to gen perm\n");
			goto gen_perm_nodes_out;
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

gen_perm_nodes_out:
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
		goto gen_permset_cleanup;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid permissionset declaration (line: %d)\n", parse_current->line);
		goto gen_permset_cleanup;
	}

	rc = cil_permset_init(&permset);
	if (rc != SEPOL_OK) {
		printf("Failed to init permissionset\n");
		goto gen_permset_cleanup;
	}

	key = parse_current->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)permset, (hashtab_key_t)key, CIL_SYM_PERMSETS, CIL_PERMSET);
	if (rc != SEPOL_OK) {
		printf("Failed to create permissionset node\n");
		goto gen_permset_cleanup;
	}

	cil_list_init(&permset->perms_list_str);
	rc = cil_parse_to_list(parse_current->next->next->cl_head, permset->perms_list_str, CIL_AST_STR);
	if (rc != SEPOL_OK) {
		printf("Failed to parse perms\n");
		goto gen_permset_cleanup;
	}

	return SEPOL_OK;

gen_permset_cleanup:
	if (permset != NULL) {
		cil_destroy_permset(permset);
	}
	return rc;
}

void cil_destroy_permset(struct cil_permset *permset)
{
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
		goto gen_common_cleanup;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid common declaration (line: %d)\n", parse_current->line);
		goto gen_common_cleanup;
	}

	rc = cil_common_init(&common);
	if (rc != SEPOL_OK) {
		goto gen_common_cleanup;
	}

	key = parse_current->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)common, (hashtab_key_t)key, CIL_SYM_COMMONS, CIL_COMMON);
	if (rc != SEPOL_OK) {
		goto gen_common_cleanup;
	}

	rc = cil_gen_perm_nodes(db, parse_current->next->next->cl_head, ast_node);
	if (rc != SEPOL_OK) {
		printf("Common: failed to parse perms\n");
		goto gen_common_cleanup;
	}
	
	return SEPOL_OK;

gen_common_cleanup:
	if (common != NULL) {
		cil_destroy_common(common);
	}
	return rc;
	
}

void cil_destroy_common(struct cil_common *common)
{
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
		goto gen_classcommon_cleanup;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid classcommon declaration (line: %d)\n", parse_current->line);
		goto gen_classcommon_cleanup;
	}

	rc = cil_classcommon_init(&clscom);
	if (rc != SEPOL_OK) {
		goto gen_classcommon_cleanup;
	}

	clscom->class_str = cil_strdup(parse_current->next->data);
	clscom->common_str = cil_strdup(parse_current->next->next->data);

	ast_node->data = clscom;
	ast_node->flavor = CIL_CLASSCOMMON;
	
	return SEPOL_OK;

gen_classcommon_cleanup:
	if (clscom != NULL) {
		cil_destroy_classcommon(clscom);
	}
	return rc;

}

void cil_destroy_classcommon(struct cil_classcommon *clscom)
{
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
		goto gen_sid_cleanup;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid sid declaration (line: %d)\n", parse_current->line);
		goto gen_sid_cleanup;
	}

	rc = cil_sid_init(&sid);
	if (rc != SEPOL_OK) {
		goto gen_sid_cleanup;
	}

	key = parse_current->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)sid, (hashtab_key_t)key, CIL_SYM_SIDS, CIL_SID);
	if (rc != SEPOL_OK) {
		goto gen_sid_cleanup;
	}

	return SEPOL_OK;

gen_sid_cleanup:
	if (sid != NULL) {
		cil_destroy_sid(sid);
	}
	return rc;
}

void cil_destroy_sid(struct cil_sid *sid)
{
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
		goto gen_sidcontext_cleanup;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid sidcontext declaration (line: %d)\n", parse_current->line);
		goto gen_sidcontext_cleanup;
	}

	rc = cil_sidcontext_init(&sidcon);
	if (rc != SEPOL_OK) {
		goto gen_sidcontext_cleanup;
	}

	sidcon->sid_str = cil_strdup(parse_current->next->data);

	if (parse_current->next->next->cl_head == NULL) {
		sidcon->context_str = cil_strdup(parse_current->next->next->data);
	} else {
		rc = cil_context_init(&sidcon->context);
		if (rc != SEPOL_OK) {
			printf("Failed to init context\n");	
			goto gen_sidcontext_cleanup;
		}

		rc = cil_fill_context(parse_current->next->next->cl_head, sidcon->context);
		if (rc != SEPOL_OK) {
			printf("Failed to fill sid context\n");
			goto gen_sidcontext_cleanup;
		}
	}

	ast_node->data = sidcon;
	ast_node->flavor = CIL_SIDCONTEXT;

	return SEPOL_OK;

gen_sidcontext_cleanup:
	if (sidcon != NULL) {
		cil_destroy_sidcontext(sidcon);
	}
	return rc;
}

void cil_destroy_sidcontext(struct cil_sidcontext *sidcon)
{
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
		goto gen_user_cleanup;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid user declaration (line: %d)\n", parse_current->line);
		goto gen_user_cleanup;
	}

	rc = cil_user_init(&user);
	if (rc != SEPOL_OK) {
		goto gen_user_cleanup;
	}

	key = parse_current->next->data;
	
	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)user, (hashtab_key_t)key, CIL_SYM_USERS, CIL_USER);
	if (rc != SEPOL_OK) {
		goto gen_user_cleanup;
	}
	
	return SEPOL_OK;

gen_user_cleanup:
	if (user != NULL) {
		cil_destroy_user(user);\
	}
	return rc;
}

void cil_destroy_user(struct cil_user *user)
{
	cil_symtab_datum_destroy(user->datum);
	free(user);
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
		goto gen_role_cleanup;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid role declaration (line: %d)\n", parse_current->line);
		goto gen_role_cleanup;
	}

	rc = cil_role_init(&role);
	if (rc != SEPOL_OK) {
		goto gen_role_cleanup;
	}

	key = parse_current->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)role, (hashtab_key_t)key, CIL_SYM_ROLES, CIL_ROLE);
	if (rc != SEPOL_OK) {
		goto gen_role_cleanup;
	}
	
	return SEPOL_OK;

gen_role_cleanup:
	if (role != NULL) {
		cil_destroy_role(role);
	}
	return rc;
}

void cil_destroy_role(struct cil_role *role)
{
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
		goto gen_roletype_cleanup;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid roletype declaration (line: %d)\n", parse_current->line);
		goto gen_roletype_cleanup;
	}

	rc = cil_roletype_init(&roletype);
	if (rc != SEPOL_OK) {
		goto gen_roletype_cleanup;
	}

	roletype->role_str = cil_strdup(parse_current->next->data);
	roletype->type_str = cil_strdup(parse_current->next->next->data);

	ast_node->data = roletype;
	ast_node->flavor = CIL_ROLETYPE;
	
	return SEPOL_OK;

gen_roletype_cleanup:
	if (roletype != NULL) {
		cil_destroy_roletype(roletype);
	}
	return rc;
}

void cil_destroy_roletype(struct cil_roletype *roletype)
{
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
		goto gen_userrole_cleanup;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid userrole declaration (line: %d)\n", parse_current->line);
		goto gen_userrole_cleanup;
	}

	rc = cil_userrole_init(&userrole);
	if (rc != SEPOL_OK) {
		goto gen_userrole_cleanup;
	}

	userrole->user_str = cil_strdup(parse_current->next->data);
	userrole->role_str = cil_strdup(parse_current->next->next->data);

	ast_node->data = userrole;
	ast_node->flavor = CIL_USERROLE;
	
	return SEPOL_OK;

gen_userrole_cleanup:
	if (userrole != NULL) {
		cil_destroy_userrole(userrole);
	}
	return rc;
}

void cil_destroy_userrole(struct cil_userrole *userrole)
{
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
		goto gen_roletrans_cleanup;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid roletransition declaration (line: %d)\n", parse_current->line);
		goto gen_roletrans_cleanup;
	}

	rc = cil_role_trans_init(&roletrans);
	if (rc != SEPOL_OK) {
		goto gen_roletrans_cleanup;
	}

	roletrans->src_str = cil_strdup(parse_current->next->data);
	roletrans->tgt_str = cil_strdup(parse_current->next->next->data);
	roletrans->obj_str = cil_strdup(parse_current->next->next->next->data);
	roletrans->result_str = cil_strdup(parse_current->next->next->next->next->data);

	ast_node->data = roletrans;
	ast_node->flavor = CIL_ROLETRANS;

	return SEPOL_OK;

gen_roletrans_cleanup:
	if (roletrans != NULL) {
		cil_destroy_roletrans(roletrans);
	}
	return rc;
}

void cil_destroy_roletrans(struct cil_role_trans *roletrans)
{
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
		goto gen_roleallow_cleanup;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid roleallow declaration (line: %d)\n", parse_current->line);
		goto gen_roleallow_cleanup;
	}

	rc = cil_role_allow_init(&roleallow);
	if (rc != SEPOL_OK) {
		goto gen_roleallow_cleanup;
	}

	roleallow->src_str = cil_strdup(parse_current->next->data);
	roleallow->tgt_str = cil_strdup(parse_current->next->next->data);

	ast_node->data = roleallow;
	ast_node->flavor = CIL_ROLEALLOW;

	return SEPOL_OK;

gen_roleallow_cleanup:
	if (roleallow != NULL) {
		cil_destroy_roleallow(roleallow);
	}
	return rc;
}

void cil_destroy_roleallow(struct cil_role_allow *roleallow)
{
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
		goto gen_roledominance_cleanup;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid roledominance delcaration (line: %d)\n", parse_current->line);
		goto gen_roledominance_cleanup;
	}

	rc = cil_roledominance_init(&roledom);
	if (rc != SEPOL_OK) {
		goto gen_roledominance_cleanup;
	}

	roledom->role_str = cil_strdup(parse_current->next->data);
	roledom->domed_str = cil_strdup(parse_current->next->next->data);

	ast_node->data = roledom;
	ast_node->flavor = CIL_ROLEDOMINANCE;

	return SEPOL_OK;

gen_roledominance_cleanup:
	if (roledom != NULL) {
		cil_destroy_roledominance(roledom);
	}
	return rc;
}

void cil_destroy_roledominance(struct cil_roledominance *roledom)
{
	if (roledom->role_str != NULL) {
		free(roledom->role_str);
	}

	if (roledom->domed_str != NULL) {
		free(roledom->domed_str);
	}

	free(roledom);
}

int cil_gen_avrule(struct cil_tree_node *parse_current, struct cil_tree_node *ast_node, uint32_t rule_kind)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING | SYM_LIST,
		SYM_STRING | SYM_LIST,
		SYM_STRING,
		SYM_STRING | SYM_LIST,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	struct cil_avrule *rule = NULL;
	int rc = SEPOL_ERR;

	if (parse_current == NULL || ast_node == NULL) {
		goto gen_avrule_cleanup;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid allow rule (line: %d)\n", parse_current->line);
		goto gen_avrule_cleanup;
	}
	
	rc = cil_avrule_init(&rule);
	if (rc != SEPOL_OK) {
		goto gen_avrule_cleanup;
	}

	rule->rule_kind = rule_kind;

	if (parse_current->next->cl_head == NULL) {
		rule->src_str = cil_strdup(parse_current->next->data);
	} else {
		cil_typeset_init((struct cil_typeset**)&rule->src);
		rule->src_flavor = CIL_TYPESET;	
		rc = cil_fill_typeset(parse_current->next->cl_head, rule->src);
		if (rc != SEPOL_OK) {
			printf("Failed to fill src typeset\n");
			goto gen_avrule_cleanup;
		}
	}

	if (parse_current->next->next->cl_head == NULL) {
		rule->tgt_str = cil_strdup(parse_current->next->next->data);
	} else {
		cil_typeset_init((struct cil_typeset**)&rule->tgt);
		rule->tgt_flavor = CIL_TYPESET;	
		rc = cil_fill_typeset(parse_current->next->next->cl_head, rule->tgt);
		if (rc != SEPOL_OK) {
			printf("Failed to fill tgt typeset\n");
			goto gen_avrule_cleanup;
		}
	}
	
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

gen_avrule_cleanup:
	if (rule != NULL) {
		cil_destroy_avrule(rule);
	}
	return rc;
}

void cil_destroy_avrule(struct cil_avrule *rule)
{
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
		goto gen_type_rule_cleanup;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid type rule (line: %d)\n", parse_current->line);
		goto gen_type_rule_cleanup;
	}

	rc = cil_type_rule_init(&rule);
	if (rc != SEPOL_OK) {
		goto gen_type_rule_cleanup;
	}

	rule->rule_kind = rule_kind;
	rule->src_str = cil_strdup(parse_current->next->data);
	rule->tgt_str = cil_strdup(parse_current->next->next->data);
	rule->obj_str = cil_strdup(parse_current->next->next->next->data);	
	rule->result_str = cil_strdup(parse_current->next->next->next->next->data);

	ast_node->data = rule;
	ast_node->flavor = CIL_TYPE_RULE;

	return SEPOL_OK;

gen_type_rule_cleanup:
	if (rule != NULL) {
		cil_destroy_type_rule(rule);
	}
	return rc;
}

void cil_destroy_type_rule(struct cil_type_rule *rule)
{
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

int cil_gen_type(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node, enum cil_flavor flavor)
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
		goto gen_type_cleanup;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid %s declaration (line: %d)\n", (char*)parse_current->data, parse_current->line);
		goto gen_type_cleanup;
	}

	rc = cil_type_init(&type);
	if (rc != SEPOL_OK) {
		goto gen_type_cleanup;
	}

	key = parse_current->next->data; 

	if (flavor == CIL_TYPE || flavor == CIL_ATTR) { 
		rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)type, (hashtab_key_t)key, CIL_SYM_TYPES, CIL_TYPE);
	} else {
		printf("Error: cil_gen_type called on invalid node\n");
		rc = SEPOL_ERR;
		goto gen_type_cleanup;
	}

	if (rc != SEPOL_OK) {
		printf("Failed to insert %s (line: %d), rc:%d\n", key, parse_current->line, rc);
		goto gen_type_cleanup;
	}
	
	ast_node->data = type;
	ast_node->flavor = flavor;	

	return SEPOL_OK;

gen_type_cleanup:
	if (type != NULL) {
		cil_destroy_type(type);
	}
	return rc;
}

void cil_destroy_type(struct cil_type *type)
{
	cil_symtab_datum_destroy(type->datum);
	free(type);
}

int cil_fill_typeset(struct cil_tree_node *set_start, struct cil_typeset *typeset)
{
	struct cil_tree_node *curr = set_start;
	struct cil_list_item *new_type = NULL;
	struct cil_list_item *types_list_tail = NULL;
	struct cil_list_item *neg_list_tail = NULL;
	char first;

	if (set_start == NULL || typeset == NULL) {
		return SEPOL_ERR;
	}

	cil_list_init(&typeset->types_list_str);
	cil_list_init(&typeset->neg_list_str);

	while(curr != NULL) {
		cil_list_item_init(&new_type);
		new_type->flavor = CIL_AST_STR;

		first = *((char*)curr->data);
		if (first == '-') {
			new_type->data = cil_strdup((char*)curr->data + 1);
			if (typeset->neg_list_str->head == NULL) {
				typeset->neg_list_str->head = new_type;
			} else {
				neg_list_tail->next = new_type;
			}
			neg_list_tail = new_type;
		} else {
			new_type->data = cil_strdup((char*)curr->data);
			if (typeset->types_list_str->head == NULL) {
				typeset->types_list_str->head = new_type;
			} else {
				types_list_tail->next = new_type;
			}
			types_list_tail = new_type;
		}

		curr = curr->next;
	}

	return SEPOL_OK;
}

int cil_gen_typeset(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_LIST,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	int rc = SEPOL_ERR;
	char *key = NULL;
	struct cil_typeset *typeset = NULL;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		return SEPOL_ERR;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid typeset declaration (line: %d)\n", parse_current->line);
		return SEPOL_ERR;
	}

	rc = cil_typeset_init(&typeset);
	if (rc != SEPOL_OK) {
		return rc;
	}

	key = parse_current->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)typeset, (hashtab_key_t)key, CIL_SYM_TYPES, CIL_TYPESET);
	if (rc != SEPOL_OK) {
		goto gen_typeset_cleanup;
	}	

	cil_fill_typeset(parse_current->next->next->cl_head, typeset);

	return SEPOL_OK;

	gen_typeset_cleanup:
		cil_destroy_typeset(typeset);
		return rc;
}

void cil_destroy_typeset(struct cil_typeset *typeset)
{
	cil_symtab_datum_destroy(typeset->datum);

	if (typeset->types_list_str != NULL) {
		cil_list_destroy(&typeset->types_list_str, 1);
	}
	if (typeset->types_list != NULL) {
		cil_list_destroy(&typeset->types_list, 0);
	}

	if (typeset->neg_list_str != NULL) {
		cil_list_destroy(&typeset->neg_list_str, 1);
	}
	if (typeset->neg_list != NULL) {
		cil_list_destroy(&typeset->neg_list, 0);
	}

	free(typeset);
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
		goto gen_bool_cleanup;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid boolean declaration (line: %d)\n", parse_current->line);
		goto gen_bool_cleanup;
	}

	rc = cil_bool_init(&boolean);
	if (rc != SEPOL_OK) {
		goto gen_bool_cleanup;
	}

	key = parse_current->next->data;

	if (!strcmp(parse_current->next->next->data, "true")) {
		boolean->value = CIL_TRUE;
	} else if (!strcmp(parse_current->next->next->data, "false")) {
		boolean->value = CIL_FALSE;
	} else {
		printf("Error: value must be \'true\' or \'false\'");
		rc = SEPOL_ERR;	
		goto gen_bool_cleanup;
	}

	if (flavor == CIL_BOOL)	{
		rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)boolean, (hashtab_key_t)key, CIL_SYM_BOOLS, CIL_BOOL);
	} else {
		rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)boolean, (hashtab_key_t)key, CIL_SYM_TUNABLES, CIL_TUNABLE);
	}

	if (rc != SEPOL_OK) {
		goto gen_bool_cleanup;
	}
	
	return SEPOL_OK;

gen_bool_cleanup:
	if (boolean != NULL) {
		cil_destroy_bool(boolean);
	}
	return rc;
}

void cil_destroy_bool(struct cil_bool *boolean)
{
	cil_symtab_datum_destroy(boolean->datum);
	free(boolean);
}

int cil_gen_constrain_expr_stack(struct cil_tree_node *current, enum cil_flavor flavor, struct cil_tree_node **stack)
{
	int rc = SEPOL_ERR;
	struct cil_tree_node *opnode = NULL;
	struct cil_conditional *opcond = NULL;
	struct cil_tree_node *lnode = NULL;
	struct cil_conditional *lcond = NULL;
	char * lstr = NULL;
	struct cil_tree_node *rnode = NULL;
	struct cil_conditional *rcond = NULL;
	char * rstr = NULL;
	int riskeyword = 0;
	
	if (current == NULL || stack == NULL) {
		goto not_valid;
	}

	if (current->cl_head != NULL) {
		goto not_valid;
	}
	
	if (current->parent->cl_head != current) {
		goto not_valid;
	}

	cil_tree_node_init(&opnode);

	rc = cil_conditional_init(&opcond);
	if (rc != SEPOL_OK) {
		goto not_valid;
	}

	if (!strcmp((char*)current->data, CIL_KEY_EQ)) {
		opcond->flavor = CIL_EQ;
	} else if (!strcmp((char*)current->data, CIL_KEY_NEQ)) {
		opcond->flavor = CIL_NEQ;
	} else if (!strcmp((char*)current->data, CIL_KEY_CONS_NOT)) {
		opcond->flavor = CIL_CONS_NOT;
	} else if (!strcmp((char*)current->data, CIL_KEY_CONS_OR)) {
		opcond->flavor = CIL_CONS_OR;
	} else if (!strcmp((char*)current->data, CIL_KEY_CONS_AND)) {
		opcond->flavor = CIL_CONS_AND;
	} else if (!strcmp((char*)current->data, CIL_KEY_CONS_EQ)) {
		opcond->flavor = CIL_CONS_EQ;
	} else if (!strcmp((char*)current->data, CIL_KEY_CONS_DOM)) {
		opcond->flavor = CIL_CONS_DOM;
	} else if (!strcmp((char*)current->data, CIL_KEY_CONS_DOMBY)) {
		opcond->flavor = CIL_CONS_DOMBY;
	} else if (!strcmp((char*)current->data, CIL_KEY_CONS_INCOMP)) {
		opcond->flavor = CIL_CONS_INCOMP;
	} else {
		rc = SEPOL_ERR;
		goto not_valid;
	}

	if (opcond->flavor == CIL_CONS_NOT) {
		enum cil_syntax not_syntax[] = {
			SYM_STRING,
			SYM_LIST,
			SYM_END

		};
		int not_syntax_len = sizeof(not_syntax)/sizeof(*not_syntax);
		rc = __cil_verify_syntax(current, not_syntax, not_syntax_len);
		if (rc != SEPOL_OK) {
			goto not_valid;
		}
	} else if (opcond->flavor == CIL_CONS_AND || opcond->flavor == CIL_CONS_OR) {
		enum cil_syntax andor_syntax[] = {
			SYM_STRING,
			SYM_LIST,
			SYM_LIST,
			SYM_END
		};
		int andor_syntax_len = sizeof(andor_syntax)/sizeof(*andor_syntax);
		rc = __cil_verify_syntax(current, andor_syntax, andor_syntax_len);
		if (rc != SEPOL_OK) {
			goto not_valid;
		}
	} else {
		enum cil_syntax other_syntax[] = {
			SYM_STRING,
			SYM_STRING,
			SYM_STRING,
			SYM_END
		};
		int other_syntax_len = sizeof(other_syntax)/sizeof(*other_syntax);
		rc = __cil_verify_syntax(current, other_syntax, other_syntax_len);
		if (rc != SEPOL_OK) {
			goto not_valid;
		}
	}

	opcond->str = cil_strdup(current->data);

	opnode->data = opcond;
	opnode->flavor = CIL_COND;

	if (*stack != NULL) {
		(*stack)->parent = opnode;
		opnode->cl_head = *stack;
	}
	*stack = opnode;

	if (opcond->flavor == CIL_CONS_NOT) {
		return cil_gen_constrain_expr_stack(current->next->cl_head, flavor, stack);
	} else if (opcond->flavor == CIL_CONS_OR || opcond->flavor == CIL_CONS_AND) {
		rc = cil_gen_constrain_expr_stack(current->next->cl_head, flavor, stack);
		if (rc != SEPOL_OK) {
			goto not_valid;
		}
		return cil_gen_constrain_expr_stack(current->next->next->cl_head, flavor, stack);
	}

	/* this wasn't an expression, figure out left and right of the constrain op */
	rc = cil_tree_node_init(&lnode);
	if (rc != SEPOL_OK) {
		goto not_valid;
	}
	
	rc = cil_conditional_init(&lcond);
	if (rc != SEPOL_OK) {
		goto not_valid;
	}

	rc = cil_tree_node_init(&rnode);
	if (rc != SEPOL_OK) {
		goto not_valid;
	}

	rc = cil_conditional_init(&rcond);
	if (rc != SEPOL_OK) {
		goto not_valid;
	}
	
	lstr = current->next->data;
	rstr = current->next->next->data;

	lnode->data = lcond;
	rnode->data = rcond;
	lnode->flavor = CIL_COND;
	rnode->flavor = CIL_COND;

	lnode->parent = rnode;
	lnode->cl_head = *stack;

	(*stack)->parent = lnode;

	rnode->cl_head = lnode;
	*stack = rnode;
	
	if (strcmp(lstr, CIL_KEY_CONS_T1) && strcmp(lstr, CIL_KEY_CONS_T2) &&
	    strcmp(lstr, CIL_KEY_CONS_R1) && strcmp(lstr, CIL_KEY_CONS_R2) &&
	    strcmp(lstr, CIL_KEY_CONS_U1) && strcmp(lstr, CIL_KEY_CONS_U2) &&
	    strcmp(lstr, CIL_KEY_CONS_L1) && strcmp(lstr, CIL_KEY_CONS_L2) &&
	    strcmp(lstr, CIL_KEY_CONS_H1)) {
		printf("Left hand side must be valid keyword\n");
		rc = SEPOL_ERR;
		goto not_valid;
	}
	
	if (!strcmp(rstr, CIL_KEY_CONS_T1) || !strcmp(rstr, CIL_KEY_CONS_T2) ||
        !strcmp(rstr, CIL_KEY_CONS_R1) || !strcmp(rstr, CIL_KEY_CONS_R2) ||
		!strcmp(rstr, CIL_KEY_CONS_U1) || !strcmp(rstr, CIL_KEY_CONS_U2) ||
		!strcmp(rstr, CIL_KEY_CONS_L1) || !strcmp(rstr, CIL_KEY_CONS_L2) ||
		!strcmp(rstr, CIL_KEY_CONS_H1) || !strcmp(rstr, CIL_KEY_CONS_H2)) {
		riskeyword = 1;
	}

	if (opcond->flavor == CIL_EQ || opcond->flavor == CIL_NEQ) {
		/* type constraints */
		if (!strcmp(lstr, CIL_KEY_CONS_T1)) {
			lcond->flavor = CIL_CONS_T1;
			if (!strcmp(rstr, CIL_KEY_CONS_T2)) {
				rcond->flavor = CIL_CONS_T2;
			} else {
				if (riskeyword) {
					printf("Keyword %s not allowed on right side of expression\n", rstr);
					rc = SEPOL_ERR;
					goto not_valid;
				}
				rcond->flavor = CIL_TYPE;
			}
			goto valid;
		} else if (!strcmp(lstr, CIL_KEY_CONS_T2)) {
			lcond->flavor = CIL_CONS_T2;
			if (riskeyword) {
				printf("Keyword %s not allowed on right side of expression\n", rstr);
				rc = SEPOL_ERR;
				goto not_valid;
			}
			rcond->flavor = CIL_TYPE;
			goto valid;
	
		/* role constrains */	
		} else if (!strcmp(lstr, CIL_KEY_CONS_R1)) {
			lcond->flavor = CIL_CONS_R1;
			if (!strcmp(rstr, CIL_KEY_CONS_R2)) {
				rcond->flavor = CIL_CONS_R2;
			} else {
				if (riskeyword) {
					printf("Keyword %s not allowed on right side of expression\n", rstr);
					rc = SEPOL_ERR;
					goto not_valid;
				}
				rcond->flavor = CIL_ROLE;
			}
			goto valid;
		} else if (!strcmp(lstr, CIL_KEY_CONS_R2)) {
			if (riskeyword) {
				printf("Keyword %s not allowed on right side of expression\n", rstr);
				rc = SEPOL_ERR;
				goto not_valid;
			}
			rcond->flavor = CIL_ROLE;		
			goto valid;

		/* user constrains */
		} else if (!strcmp(lstr, CIL_KEY_CONS_U1)) {
			lcond->flavor = CIL_CONS_U1;
			if (!strcmp(rstr, CIL_KEY_CONS_U2)) {
				rcond->flavor = CIL_CONS_U2;
			} else {
				if (riskeyword) {
					printf("Keyword %s not allowed on right side of expression\n", rstr);
					rc = SEPOL_ERR;
					goto not_valid;
				}
				rcond->flavor = CIL_USER;
			}
			goto valid;
		} else if (!strcmp(lstr, CIL_KEY_CONS_U2)) {
			lcond->flavor = CIL_CONS_U2;
			if (riskeyword) {
				printf("Keyword %s not allowed on right side of expression\n", rstr);
				rc = SEPOL_ERR;
				goto not_valid;
			}
			rcond->flavor = CIL_USER;
			goto valid;

		/* error if not mlsconstrain*/
		} else if (flavor == CIL_CONSTRAIN) {
			printf("Left hand side must be a valid keyword\n");
			rc = SEPOL_ERR;
			goto not_valid;
		}

	} else {
		/* only roles allow in eq, dom, domby, or incomp in non-mlsconstrain */
		if (!strcmp(lstr, CIL_KEY_CONS_R1) && !strcmp(rstr, CIL_KEY_CONS_R2)) {
			lcond->flavor = CIL_CONS_R1;
			rcond->flavor = CIL_CONS_R2;
			goto valid;
		}
	}
	
	if (flavor == CIL_MLSCONSTRAIN) {
		/* check mls specific levels */
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
				goto not_valid;
			}
			goto valid;
		} else if (!strcmp(lstr, CIL_KEY_CONS_L2)) {
			lcond->flavor = CIL_CONS_L2;
			if (!strcmp(rstr, CIL_KEY_CONS_H2)) {
				rcond->flavor = CIL_CONS_H2;
			} else {
				printf("Right side of expression must be correct keyword\n");
				rc = SEPOL_ERR;
				goto not_valid;
			}
			goto valid;
		} else if (!strcmp(lstr, CIL_KEY_CONS_H1)) {
			lcond->flavor = CIL_CONS_H1;
			if (!strcmp(rstr, CIL_KEY_CONS_L2)) {
				rcond->flavor = CIL_CONS_L2;
			} else if (!strcmp(rstr, CIL_KEY_CONS_H2)) {
				rcond->flavor = CIL_CONS_H2;
			} else {
				printf("Right side of expression must be correct keyword\n");
				rc = SEPOL_ERR;
				goto not_valid;
			}
			goto valid;
		}
	}

	return SEPOL_ERR;

valid:
	lcond->str = cil_strdup(lstr);
	rcond->str = cil_strdup(rstr);

	return SEPOL_OK;

not_valid:
	return rc;
}

int cil_gen_expr_stack(struct cil_tree_node *current, enum cil_flavor flavor, struct cil_tree_node **stack)
{
	int rc = SEPOL_ERR;

	if (current == NULL || stack == NULL) {
		goto gen_expr_stack_out;
	}

	if (current->cl_head == NULL) {
		struct cil_conditional *cond;
		struct cil_tree_node *new = NULL;
		cil_tree_node_init(&new);
		rc = cil_conditional_init(&cond);
		if (rc != SEPOL_OK) {
			goto gen_expr_stack_out;
		}

		if (current == current->parent->cl_head) {
			if (!strcmp((char*)current->data, CIL_KEY_AND)) {
				cond->flavor = CIL_AND;
			} else if (!strcmp((char*)current->data, CIL_KEY_OR)) {
				cond->flavor = CIL_OR;
			} else if (!strcmp((char*)current->data, CIL_KEY_XOR)) {
				cond->flavor = CIL_XOR;
			} else if (!strcmp((char*)current->data, CIL_KEY_NOT)) {
				cond->flavor = CIL_NOT;
			} else if (!strcmp((char*)current->data, CIL_KEY_EQ)) {
				cond->flavor = CIL_EQ;
			} else if (!strcmp((char*)current->data, CIL_KEY_NEQ)) {
				cond->flavor = CIL_NEQ;
			} else {
				rc = SEPOL_ERR;
				goto gen_expr_stack_out;
			}

			if (cond->flavor == CIL_NOT) {
				enum cil_syntax not_syntax[] = {
					SYM_STRING,
					SYM_STRING,
					SYM_END
				};
				int not_syntax_len = sizeof(not_syntax)/sizeof(*not_syntax);
				rc = __cil_verify_syntax(current, not_syntax, not_syntax_len);
				if (rc != SEPOL_OK) {
					rc = SEPOL_ERR;
					goto gen_expr_stack_out;
				}
			} else {
				enum cil_syntax other_syntax[] = {
					SYM_STRING,
					SYM_STRING | SYM_LIST,
					SYM_STRING | SYM_LIST,
					SYM_END
				};
				int other_syntax_len = sizeof(other_syntax)/sizeof(*other_syntax);
				rc = __cil_verify_syntax(current, other_syntax, other_syntax_len);
				if (rc != SEPOL_OK) {
					goto gen_expr_stack_out;
				}
			}
		} else {
			cond->flavor = flavor;
		}
		
		cond->str = cil_strdup(current->data);

		new->data = cond;
		new->flavor = CIL_COND;

		if (*stack != NULL) {
			(*stack)->parent = new;
			new->cl_head = *stack;
		}
		*stack = new;
	} else {
		if (current == current->parent->cl_head) {
			printf("Invalid booleanif expression\n");
			rc = SEPOL_ERR;
			goto gen_expr_stack_out;
		}
		rc = cil_gen_expr_stack(current->cl_head, flavor, stack);
		if (rc != SEPOL_OK) {
			goto gen_expr_stack_out;
		}
	}/* else if (current->data == NULL) {
		printf("cil_gen_expr_stack: Expression cannot contain empty lists\n");
		rc = SEPOL_ERR;
		goto gen_expr_stack_out;
	}*/

	if (current->next != NULL) {
		rc = cil_gen_expr_stack(current->next, flavor, stack);
		if (rc != SEPOL_OK) {
			goto gen_expr_stack_out;
		}
	}

	return SEPOL_OK;

gen_expr_stack_out:
	return rc;
}

int cil_gen_boolif(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING | SYM_LIST,
		SYM_N_LISTS
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	struct cil_booleanif *bif = NULL;
	struct cil_tree_node *next = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto gen_boolif_cleanup;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid booleanif declaration (line: %d)\n", parse_current->line);
		goto gen_boolif_cleanup;
	}

	rc = cil_boolif_init(&bif);
	if (rc != SEPOL_OK) {
		goto gen_boolif_cleanup;
	}
	
	if (parse_current->next->cl_head == NULL) {
		struct cil_conditional *cond = NULL;
		if (parse_current->next->data == NULL) {
			printf("Invalid booleanif expression (line: %d)\n", parse_current->line);
			rc = SEPOL_ERR;
			goto gen_boolif_cleanup;
		}
		cil_conditional_init(&cond);
		cil_tree_node_init(&bif->expr_stack);
		bif->expr_stack->flavor = CIL_COND;
		cond->str = cil_strdup(parse_current->next->data);
		cond->flavor = CIL_BOOL;
		bif->expr_stack->data = cond;
	} else {
		rc = cil_gen_expr_stack(parse_current->next->cl_head, CIL_BOOL, &bif->expr_stack);
		if (rc != SEPOL_OK) {
			printf("cil_gen_boolif (line %d): failed to create expr tree, rc: %d\n", parse_current->line, rc);
			goto gen_boolif_cleanup;
		}
	}

	next = parse_current->next->next;
	cil_tree_subtree_destroy(parse_current->next);
	parse_current->next = next;

	ast_node->flavor = CIL_BOOLEANIF;
	ast_node->data = bif;
	
	return SEPOL_OK;

gen_boolif_cleanup:
	if (bif != NULL) {
		cil_destroy_boolif(bif);
	}
	return rc;
}

void cil_destroy_boolif(struct cil_booleanif *bif) 
{
	struct cil_tree_node *curr = NULL;
	struct cil_tree_node *next = NULL;

	if (bif->expr_stack != NULL) {
		curr = bif->expr_stack;
		while (curr != NULL) {
			if (curr->flavor == CIL_COND && curr->data != NULL) {
				if (((struct cil_conditional*)curr->data)->str != NULL) {
					free(((struct cil_conditional*)curr->data)->str);
					((struct cil_conditional*)curr->data)->str = NULL;
				}
			}
			next = curr->next;
			free(curr->data);
			free(curr);
			curr = next;
		}
	}

	free(bif);
}

void cil_destroy_conditional(struct cil_conditional *cond)
{
	if (cond->str != NULL) {
		free(cond->str);
	}

	free(cond);
}

int cil_gen_else(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto gen_else_cleanup;
	}

	if (ast_node->parent->flavor != CIL_BOOLEANIF) {
		printf("Invalid else statement: Not within booleanif\n");
		goto gen_else_cleanup;
	}

	ast_node->flavor = CIL_ELSE;
	ast_node->data = "else";

	return SEPOL_OK;

gen_else_cleanup:
	return rc;
}

int cil_gen_tunif(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING | SYM_LIST,
		SYM_N_LISTS
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	struct cil_tunableif *tif = NULL;
	struct cil_tree_node *next = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto gen_tunif_cleanup;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid tunableif declaration (line: %d)\n", parse_current->line);
		goto gen_tunif_cleanup;
	}

	rc = cil_tunif_init(&tif);
	if (rc != SEPOL_OK) {
		goto gen_tunif_cleanup;
	}

	if (parse_current->next->cl_head == NULL) {
		struct cil_conditional *cond;
		cil_conditional_init(&cond);
		cil_tree_node_init(&tif->expr_stack);
		tif->expr_stack->flavor = CIL_COND;
		cond->str = cil_strdup(parse_current->next->data);
		cond->flavor = CIL_TUNABLE;
		tif->expr_stack->data = cond;
	} else {
		rc = cil_gen_expr_stack(parse_current->next->cl_head, CIL_TUNABLE, &tif->expr_stack);
		if (rc != SEPOL_OK) {
			printf("cil_gen_tunif (line %d): failed to create expr tree, rc: %d\n", parse_current->line, rc);
			goto gen_tunif_cleanup;
		}
	}

	next = parse_current->next->next;
	cil_tree_subtree_destroy(parse_current->next);
	parse_current->next = next;

	ast_node->flavor = CIL_TUNABLEIF;
	ast_node->data = tif;
	
	return SEPOL_OK;

gen_tunif_cleanup:
	if (tif != NULL) {
		cil_destroy_tunif(tif);
	}
	return rc;
}

void cil_destroy_tunif(struct cil_tunableif *tif) 
{
	struct cil_tree_node *curr = NULL;
	struct cil_tree_node *next = NULL;

	if (tif->expr_stack != NULL) {
		curr = tif->expr_stack;
		while (curr != NULL) {
			if (curr->flavor == CIL_COND && curr->data != NULL) {
				if (((struct cil_conditional*)curr->data)->str != NULL) {
					free(((struct cil_conditional*)curr->data)->str);
					((struct cil_conditional*)curr->data)->str = NULL;
				}
			}
			next = curr->next;
			free(curr->data);
			free(curr);
			curr = next;
		}
	}

	cil_symtab_array_destroy(tif->symtab);

	free(tif);
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
		goto gen_typealias_cleanup;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid typealias declaration (line: %d)\n", parse_current->line);
		goto gen_typealias_cleanup;
	}

	rc = cil_typealias_init(&alias);
	if (rc != SEPOL_OK) {
		goto gen_typealias_cleanup;
	}

	key = parse_current->next->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)alias, (hashtab_key_t)key, CIL_SYM_TYPES, CIL_TYPEALIAS);
	if (rc != SEPOL_OK) {
		goto gen_typealias_cleanup;
	}
	
	alias->type_str = cil_strdup(parse_current->next->data);
	
	return SEPOL_OK;
	
gen_typealias_cleanup:
	if (alias != NULL) {
		cil_destroy_typealias(alias);
	}
	return rc;
}

void cil_destroy_typealias(struct cil_typealias *alias)
{
	cil_symtab_datum_destroy(alias->datum);

	if (alias->type_str != NULL) {
		free(alias->type_str);
	}

	free(alias);
}

int cil_gen_typeattr(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_STRING,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	struct cil_typeattribute *typeattr = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto cil_gen_typeattr_cleanup;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid typeattribute declaration (line: %d)\n", parse_current->line);
		goto cil_gen_typeattr_cleanup;
	}

	rc = cil_typeattribute_init(&typeattr);
	if (rc != SEPOL_OK) {
		goto cil_gen_typeattr_cleanup;
	}

	typeattr->type_str = cil_strdup(parse_current->next->data);
	typeattr->attr_str = cil_strdup(parse_current->next->next->data);

	ast_node->data = typeattr;
	ast_node->flavor = CIL_TYPE_ATTR;

	return SEPOL_OK;

cil_gen_typeattr_cleanup:
	if (typeattr != NULL) {
		cil_destroy_typeattr(typeattr);
	}
	return rc;
}

void cil_destroy_typeattr(struct cil_typeattribute *typeattr)
{
	if (typeattr->type_str != NULL) {
		free(typeattr->type_str);
	}

	if (typeattr->attr_str != NULL) {
		free(typeattr->attr_str);
	}
	free(typeattr);
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
		goto gen_typebounds_cleanup;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid typebounds declaration (line: %d)\n", parse_current->line);
		goto gen_typebounds_cleanup;
	}

	rc = cil_typebounds_init(&typebnds);
	if (rc != SEPOL_OK) {
		goto gen_typebounds_cleanup;
	}

	typebnds->parent_str = cil_strdup(parse_current->next->data);
	typebnds->child_str = cil_strdup(parse_current->next->next->data);

	ast_node->data = typebnds;
	ast_node->flavor = CIL_TYPEBOUNDS;

	return SEPOL_OK;

gen_typebounds_cleanup:
	if (typebnds != NULL) {
		cil_destroy_typebounds(typebnds);
	}
	return rc;
}

void cil_destroy_typebounds(struct cil_typebounds *typebnds)
{
	if (typebnds->parent_str != NULL) {
		free(typebnds->parent_str);
	}

	if (typebnds->child_str != NULL) {
		free(typebnds->child_str);
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
		goto gen_typepermissive_cleanup;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid typepermissive declaration (line: %d)\n", parse_current->line);
		goto gen_typepermissive_cleanup;
	}

	rc = cil_typepermissive_init(&typeperm);
	if (rc != SEPOL_OK) {
		goto gen_typepermissive_cleanup;
	}

	typeperm->type_str = cil_strdup(parse_current->next->data);

	ast_node->data = typeperm;
	ast_node->flavor = CIL_TYPEPERMISSIVE;

	return SEPOL_OK;

gen_typepermissive_cleanup:
	if (typeperm != NULL) {
		cil_destroy_typepermissive(typeperm);
	}
	return rc;
}

void cil_destroy_typepermissive(struct cil_typepermissive *typeperm)
{
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
		goto gen_filetransition_cleanup;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid filetransition declaration (line: %d)\n", parse_current->line);
		goto gen_filetransition_cleanup;
	}

	rc = cil_filetransition_init(&filetrans);
	if (rc != SEPOL_OK) {
		goto gen_filetransition_cleanup;
	}

	filetrans->src_str = cil_strdup(parse_current->next->data);
	filetrans->exec_str = cil_strdup(parse_current->next->next->data);
	filetrans->proc_str = cil_strdup(parse_current->next->next->next->data);
	filetrans->dest_str = cil_strdup(parse_current->next->next->next->next->data);
	filetrans->path_str = cil_strdup(parse_current->next->next->next->next->next->data);

	ast_node->data = filetrans;
	ast_node->flavor = CIL_FILETRANSITION;

	return SEPOL_OK;

gen_filetransition_cleanup:
	if (filetrans != NULL) {
		cil_destroy_filetransition(filetrans);
	}
	return rc;
}

void cil_destroy_filetransition(struct cil_filetransition *filetrans)
{
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
		goto gen_sens_cleanup;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid sensitivity declaration (line: %d)\n", parse_current->line);
		goto gen_sens_cleanup;
	}

	rc = cil_sens_init(&sens);
	if (rc != SEPOL_OK) {
		goto gen_sens_cleanup;
	}

	key = parse_current->next->data;
	
	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)sens, (hashtab_key_t)key, CIL_SYM_SENS, CIL_SENS);
	if (rc != SEPOL_OK) {
		goto gen_sens_cleanup;
	}
	
	return SEPOL_OK;

gen_sens_cleanup:
	if (sens != NULL) {
		cil_destroy_sensitivity(sens);
	}
	return rc;
}

void cil_destroy_sensitivity(struct cil_sens *sens)
{
	cil_symtab_datum_destroy(sens->datum);
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
		goto gen_sensalias_cleanup;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid sensitivityalias declaration (line: %d)\n", parse_current->line);
		goto gen_sensalias_cleanup;
	}

	rc = cil_sensalias_init(&alias);
	if (rc != SEPOL_OK) {
		goto gen_sensalias_cleanup;
	}
	
	key = parse_current->next->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)alias, (hashtab_key_t)key, CIL_SYM_SENS, CIL_SENSALIAS);
	if (rc != SEPOL_OK) {
		goto gen_sensalias_cleanup;
	}
	
	alias->sens_str = cil_strdup(parse_current->next->data);

	return SEPOL_OK;
	
gen_sensalias_cleanup:
	if (alias != NULL) {
		cil_destroy_sensalias(alias);
	}
	return rc;
}

void cil_destroy_sensalias(struct cil_sensalias *alias)
{
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
		goto gen_cat_cleanup;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid category declaration (line: %d)\n", parse_current->line);
		goto gen_cat_cleanup;
	}

	rc = cil_cat_init(&cat);
	if (rc != SEPOL_OK) {
		goto gen_cat_cleanup;
	}

	key = parse_current->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)cat, (hashtab_key_t)key, CIL_SYM_CATS, CIL_CAT);
	if (rc != SEPOL_OK) {
		goto gen_cat_cleanup;
	}
	
	return SEPOL_OK;

gen_cat_cleanup:
	if (cat != NULL) {
		cil_destroy_category(cat);
	}
	return rc;
}

void cil_destroy_category(struct cil_cat *cat)
{
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
		goto gen_catalias_cleanup;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid sensitivityalias declaration (line: %d)\n", parse_current->line);
		goto gen_catalias_cleanup;
	}

	rc = cil_catalias_init(&alias);
	if (rc != SEPOL_OK) {
		goto gen_catalias_cleanup;
	}

	key = parse_current->next->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)alias, (hashtab_key_t)key, CIL_SYM_CATS, CIL_CATALIAS);
	if (rc != SEPOL_OK) {
		goto gen_catalias_cleanup;
	}
	
	alias->cat_str = cil_strdup(parse_current->next->data);
	
	return SEPOL_OK;
	
gen_catalias_cleanup:
	if (alias != NULL) {
		cil_destroy_catalias(alias);
	}
	return rc;
}

void cil_destroy_catalias(struct cil_catalias *alias)
{
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
		goto verify_ranges_out;
	}

	curr = list->head;

	while (curr != NULL) {
		/* range */
		if (curr->flavor == CIL_LIST) {
			range = ((struct cil_list*)curr->data)->head;
			if (range == NULL || range->next == NULL || range->next->next != NULL) {
				goto verify_ranges_out;
			}
		}
		curr = curr->next;
	}

	return SEPOL_OK;

verify_ranges_out:
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
		goto set_to_list_out;
	}

	if (parse_current->cl_head == NULL) {
		printf("Error: Invalid list\n");
		goto set_to_list_out;
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
				goto set_to_list_out;
			}
		} else {
			printf("cil_set_to_list: invalid sublist\n");
			rc = SEPOL_ERR;
			goto set_to_list_out;
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

set_to_list_out:
	return rc;
}

int cil_fill_cat_list(struct cil_tree_node *start, struct cil_list *list)
{
	int rc = SEPOL_ERR;

	if (start == NULL || list == NULL) {
		goto fill_cat_list_out;
	}
	
	rc = cil_set_to_list(start, list, 1);
	if (rc != SEPOL_OK) {
		printf("Failed to create category list\n");
		goto fill_cat_list_out;
	}

	rc = __cil_verify_ranges(list);
	if (rc != SEPOL_OK) {
		printf("Error verifying range syntax\n");
		goto fill_cat_list_out;
	}

	return SEPOL_OK;

fill_cat_list_out:
	return rc;
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
		goto gen_catset_cleanup;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid categoryset declaration (line: %d)\n", parse_current->line);
		goto gen_catset_cleanup;
	}

	rc = cil_catset_init(&catset);
	if (rc != SEPOL_OK) {
		goto gen_catset_cleanup;
	}

	key = parse_current->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)catset, (hashtab_key_t)key, CIL_SYM_CATS, CIL_CATSET);
	if (rc != SEPOL_OK) {
		goto gen_catset_cleanup;
	}

	cil_list_init(&catset->cat_list_str);
	rc = cil_fill_cat_list(parse_current->next->next, catset->cat_list_str);
	if (rc != SEPOL_OK) {
		printf("Failed to fill categoryset\n");
		goto gen_catset_cleanup;
	}

	return SEPOL_OK;

gen_catset_cleanup:
	if (catset != NULL) {
		cil_destroy_catset(catset);
	}
	return rc;	
}

void cil_destroy_catset(struct cil_catset *catset)
{
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
		goto gen_catorder_cleanup;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc !=  SEPOL_OK) {
		printf("Invalid categoryorder declaration (line: %d)\n", parse_current->line);
		goto gen_catorder_cleanup;
	}

	rc = cil_catorder_init(&catorder);
	if (rc != SEPOL_OK) {
		goto gen_catorder_cleanup;
	}
	cil_list_init(&catorder->cat_list_str);
	
	rc = cil_set_to_list(parse_current->next, catorder->cat_list_str, 0);
	if (rc != SEPOL_OK) {
		printf("Failed to create category list\n");
		goto gen_catorder_cleanup;
	}
	ast_node->data = catorder;
	ast_node->flavor = CIL_CATORDER;

	return SEPOL_OK;

gen_catorder_cleanup:
	if (catorder != NULL) {
		cil_destroy_catorder(catorder);
	}
	return rc;
}

void cil_destroy_catorder(struct cil_catorder *catorder)
{
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
		goto gen_dominance_cleanup;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid dominance declaration (line: %d)\n", parse_current->line);
		goto gen_dominance_cleanup;
	}

	rc = cil_sens_dominates_init(&dom);
	if (rc != SEPOL_OK) {
		goto gen_dominance_cleanup;
	}
	cil_list_init(&dom->sens_list_str);
	
	rc = cil_set_to_list(parse_current->next, dom->sens_list_str, 0);
	if (rc != SEPOL_OK) {
		printf("Failed to create sensitivity list\n");
		goto gen_dominance_cleanup;
	}

	ast_node->data = dom;
	ast_node->flavor = CIL_DOMINANCE;

	return SEPOL_OK;

gen_dominance_cleanup:
	if (dom != NULL) {
		cil_destroy_dominance(dom);
	}
	return rc;
}

void cil_destroy_dominance(struct cil_sens_dominates *dom)
{
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
		goto gen_senscat_cleanup;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid sensitivitycategory declaration (line: %d)\n", parse_current->line);
		goto gen_senscat_cleanup;
	}

	rc = cil_senscat_init(&senscat);
	if (rc != SEPOL_OK) {
		goto gen_senscat_cleanup;
	}

	senscat->sens_str = cil_strdup(parse_current->next->data);

	if (parse_current->next->next->cl_head == NULL && parse_current->next->next->data != NULL) {
		senscat->catset_str = cil_strdup(parse_current->next->next->data);
	} else {
		cil_list_init(&senscat->cat_list_str);
		rc = cil_fill_cat_list(parse_current->next->next, senscat->cat_list_str);
		if (rc != SEPOL_OK) {
			printf("Failed to fill category list\n");
			goto gen_senscat_cleanup;
		}
	}

	ast_node->data = senscat;
	ast_node->flavor = CIL_SENSCAT;

	return SEPOL_OK;

gen_senscat_cleanup:
	if (senscat != NULL) {
		cil_destroy_senscat(senscat);
	}
	return rc;
}

void cil_destroy_senscat(struct cil_senscat *senscat)
{
	if (senscat->sens_str != NULL) {
		free(senscat->sens_str);
	}

	if (senscat->cat_list_str != NULL) {
		cil_list_destroy(&senscat->cat_list_str, 1);
	}

	free(senscat);
}

int cil_fill_level(struct cil_tree_node *sens, struct cil_level *level)
{
	int rc = SEPOL_ERR;

	if (sens == NULL || level == NULL) {
		goto cil_fill_level_cleanup;
	}

	level->sens_str = cil_strdup(sens->data);

	if (sens->next == NULL) {
		rc = SEPOL_OK;
		goto cil_fill_level_cleanup;
	}

	if (sens->next->cl_head == NULL) {
		if (sens->next->data != NULL) {
			level->catset_str = cil_strdup(sens->next->data);
		} else {
			rc = SEPOL_ERR;
			goto cil_fill_level_cleanup;
		}
	} else {
		cil_list_init(&level->cat_list_str);
		rc = cil_fill_cat_list(sens->next, level->cat_list_str);
		if (rc != SEPOL_OK) {
			printf("Failed to create level category list\n");
			goto cil_fill_level_cleanup;
		}
	}

	return SEPOL_OK;

cil_fill_level_cleanup:
	return rc;
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
		goto gen_level_cleanup;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid level declaration (line: %d)\n", parse_current->line);
		goto gen_level_cleanup;
	}

	rc = cil_level_init(&level);
	if (rc != SEPOL_OK) {
		goto gen_level_cleanup;
	}

	key = parse_current->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)level, (hashtab_key_t)key, CIL_SYM_LEVELS, CIL_LEVEL);
	if (rc != SEPOL_OK) {
		goto gen_level_cleanup;
	}
	
	rc = cil_fill_level(parse_current->next->next->cl_head, level);
	if (rc != SEPOL_OK) {
		printf("Failed to populate level\n");
		goto gen_level_cleanup;
	}
	
	return SEPOL_OK;

gen_level_cleanup:
	if (level != NULL) {
		cil_destroy_level(level);
	}
	return rc;
}

void cil_destroy_level(struct cil_level *level)
{
	cil_symtab_datum_destroy(level->datum);

	if (level->sens_str != NULL) {
		free(level->sens_str);
	}

	if (level->cat_list_str != NULL) {
		cil_list_destroy(&level->cat_list_str, 1);
	}

	if (level->cat_list != NULL) {
		cil_list_destroy(&level->cat_list, 0);
	}

	if (level->catset_str != NULL) {
		free(level->catset_str);
	}

	free(level);
}

int __cil_build_constrain_tree(struct cil_tree_node *parse_current, struct cil_tree_node *expr_root, enum cil_flavor flavor)
{
	struct cil_tree_node *curr = parse_current;
	struct cil_tree_node *expr_curr = expr_root;
	struct cil_tree_node *new_node = NULL;
	int rc = SEPOL_ERR;

	if (expr_root == NULL || parse_current == NULL) {
		goto build_constrain_tree_out;
	}

	while (curr != NULL) {
		if (curr->cl_head == NULL) {
			cil_tree_node_init(&new_node);
			new_node->parent = expr_curr;
			new_node->line = expr_curr->line;
			new_node->data = cil_strdup(curr->data);
			new_node->flavor = CIL_CONSTRAIN_NODE;

			if (expr_curr->cl_head == NULL) {
				expr_curr->cl_head = new_node;
			} else {
				expr_curr->cl_tail->next = new_node;
			}
			expr_curr->cl_tail = new_node;

			if (curr->data != NULL) {
				if (strstr(CIL_CONSTRAIN_OPER, curr->data) != NULL) {
					expr_curr = new_node;
				} else if (flavor == CIL_CONSTRAIN && strstr(CIL_MLS_LEVELS, curr->data) != NULL) {
					rc = SEPOL_ERR;
					goto build_constrain_tree_out;
				}
			} else {
				rc = SEPOL_ERR;
				goto build_constrain_tree_out;
			}
		} else {
			rc = __cil_build_constrain_tree(curr->cl_head, expr_curr, flavor);
			if (rc != SEPOL_OK) {
				printf("Error building constrain expression tree\n");
				goto build_constrain_tree_out;
			}
		}
		curr = curr->next;
	}
	expr_curr = expr_curr->parent;
	
	return SEPOL_OK;

build_constrain_tree_out:
	return rc;
}

void cil_destroy_constrain_node(struct cil_tree_node *cons_node)
{
	if (cons_node->data != NULL) {
		free(cons_node->data);
	}

	cons_node->data = NULL;
	cons_node->parent = NULL;

	free(cons_node);
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
		goto gen_constrain_cleanup;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid constrain declaration (line: %d)\n", parse_current->line);
		goto gen_constrain_cleanup;
	}

	rc = cil_constrain_init(&cons);
	if (rc != SEPOL_OK) {
		goto gen_constrain_cleanup;
	}

	cil_list_init(&cons->class_list_str);
	cil_parse_to_list(parse_current->next->cl_head, cons->class_list_str, CIL_AST_STR);
	cil_list_init(&cons->perm_list_str);
	cil_parse_to_list(parse_current->next->next->cl_head, cons->perm_list_str, CIL_AST_STR);

	rc = cil_gen_constrain_expr_stack(parse_current->next->next->next->cl_head, flavor, &cons->expr);
	if (rc != SEPOL_OK) {
		printf("Failed to build constrain expression tree\n");
		goto gen_constrain_cleanup;
	}

	ast_node->data = cons;
	ast_node->flavor = flavor;

	return SEPOL_OK;

gen_constrain_cleanup:
	if (cons != NULL) {
		cil_destroy_constrain(cons);
	}
	return rc;
}

void cil_destroy_constrain(struct cil_constrain *cons)
{
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
		struct cil_tree_node *curr = cons->expr;
		struct cil_tree_node *next = NULL;
		while (curr != NULL) {
			if (curr->flavor == CIL_COND && curr->data != NULL) {
				if (((struct cil_conditional*)curr->data)->str != NULL) {
					free(((struct cil_conditional*)curr->data)->str);
					((struct cil_conditional*)curr->data)->str = NULL;
				}
			}
			next = curr->next;
			free(curr->data);
			free(curr);
			curr = next;
		}
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
		SYM_STRING | SYM_LIST,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	int rc = SEPOL_ERR;

	if (user_node == NULL || context == NULL) {
		goto cil_fill_context_cleanup;
	}

	rc = __cil_verify_syntax(user_node, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid context (line: %d)\n", user_node->line);
		goto cil_fill_context_cleanup;
	}

	context->user_str = cil_strdup(user_node->data);
	context->role_str = cil_strdup(user_node->next->data);
	context->type_str = cil_strdup(user_node->next->next->data);
	
	context->low_str = NULL;
	context->high_str = NULL;

	if (user_node->next->next->next->cl_head == NULL) {
		context->low_str = cil_strdup(user_node->next->next->next->data);
	} else {
		rc = cil_level_init(&context->low);
		if (rc != SEPOL_OK) {
			printf("Couldn't initialize low level\n");
			goto cil_fill_context_cleanup;
		}

		rc = cil_fill_level(user_node->next->next->next->cl_head, context->low);
		if (rc != SEPOL_OK) {
			printf("cil_fill_context: Failed to fill low level, rc: %d\n", rc); 
			goto cil_fill_context_cleanup;
		}
	}

	if (user_node->next->next->next->next->cl_head == NULL) {
		context->high_str = cil_strdup(user_node->next->next->next->next->data);
	} else {
		rc = cil_level_init(&context->high);
		if (rc != SEPOL_OK) {
			printf("Couldn't initialize high level\n");
			goto cil_fill_context_cleanup;
		}

		rc = cil_fill_level(user_node->next->next->next->next->cl_head, context->high);
		if (rc != SEPOL_OK) {
			printf("cil_fill_context: Failed to fill high level, rc %d\n", rc);
			goto cil_fill_context_cleanup;
		}
	}

	return SEPOL_OK;
	
cil_fill_context_cleanup:
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
		goto gen_context_cleanup;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid context declaration (line: %d)\n", parse_current->line);
		goto gen_context_cleanup;
	}

	rc = cil_context_init(&context);
	if (rc != SEPOL_OK) {
		goto gen_context_cleanup;
	}

	key = parse_current->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)context, (hashtab_key_t)key, CIL_SYM_CONTEXTS, CIL_CONTEXT);
	if (rc != SEPOL_OK) {
		goto gen_context_cleanup;
	}
	
	rc = cil_fill_context(parse_current->next->next->cl_head, context);
	if (rc != SEPOL_OK) {
		printf("Failed to fill context, rc: %d\n", rc);
		goto gen_context_cleanup;
	}
	
	return SEPOL_OK;
	
gen_context_cleanup:
	if (context != NULL) {
		cil_destroy_context(context);
	}
	return SEPOL_ERR;
}

void cil_destroy_context(struct cil_context *context)
{
	if (context->user_str != NULL) {
		free(context->user_str);
	}

	if (context->role_str != NULL) {
		free(context->role_str);
	}

	if (context->type_str != NULL) {
		free(context->type_str);
	}

	if (context->low_str != NULL) {
		free(context->low_str);
	} else if (context->low != NULL) {
		cil_destroy_level(context->low);
	}

	if (context->high_str != NULL) {
		free(context->high_str);
	} else if (context->high != NULL) {
		cil_destroy_level(context->high);
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
		goto gen_filecon_cleanup;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid filecon declaration (line: %d)\n", parse_current->line);
		goto gen_filecon_cleanup;
	}

	type = parse_current->next->next->next->data;
	rc = cil_filecon_init(&filecon);
	if (rc != SEPOL_OK) {
		goto gen_filecon_cleanup;
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
		goto gen_filecon_cleanup;
	}
		
	if (parse_current->next->next->next->next->cl_head == NULL) {
		filecon->context_str = cil_strdup(parse_current->next->next->next->next->data);
	} else {
		rc = cil_context_init(&filecon->context);
		if (rc != SEPOL_OK) {
			printf("Failed to init file context\n");
			goto gen_filecon_cleanup;
		}

		rc = cil_fill_context(parse_current->next->next->next->next->cl_head, filecon->context);
		if (rc != SEPOL_OK) {
			printf("Failed to fill file context\n");
			goto gen_filecon_cleanup;
		}
	}

	ast_node->data = filecon;
	ast_node->flavor = CIL_FILECON; 

	return SEPOL_OK;

gen_filecon_cleanup:
	if (filecon != NULL) {
		cil_destroy_filecon(filecon);
	}
	return rc;
}

//TODO: Should we be checking if the pointer is NULL when passed in?
void cil_destroy_filecon(struct cil_filecon *filecon)
{
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
		goto gen_portcon_cleanup;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid portcon declaration (line: %d)\n", parse_current->line);
		goto gen_portcon_cleanup;
	}

	rc = cil_portcon_init(&portcon);
	if (rc != SEPOL_OK) {
		goto gen_portcon_cleanup;
	}

	portcon->type_str = cil_strdup(parse_current->next->data);

	if (parse_current->next->next->cl_head != NULL) {
		if (parse_current->next->next->cl_head->next != NULL
		&& parse_current->next->next->cl_head->next->next == NULL) {
			portcon->port_low = (uint32_t)atoi(parse_current->next->next->cl_head->data);
			portcon->port_high = (uint32_t)atoi(parse_current->next->next->cl_head->next->data);
		} else {
			printf("Error: Improper port range specified\n");
			rc = SEPOL_ERR;
			goto gen_portcon_cleanup;
		}
	} else {
		portcon->port_low = (uint32_t)atoi(parse_current->next->next->data);
		portcon->port_high = (uint32_t)atoi(parse_current->next->next->data);
	}

	if (parse_current->next->next->next->cl_head == NULL ) {
		portcon->context_str = cil_strdup(parse_current->next->next->next->data);
	} else {
		rc = cil_context_init(&portcon->context);
		if (rc != SEPOL_OK) {
			printf("Failed to init port context\n");
			goto gen_portcon_cleanup;
		}

		rc = cil_fill_context(parse_current->next->next->next->cl_head, portcon->context);
		if (rc != SEPOL_OK) {
			printf("Failed to fill port context\n");
			goto gen_portcon_cleanup;
		}
	}

	ast_node->data = portcon;
	ast_node->flavor = CIL_PORTCON; 

	return SEPOL_OK;

gen_portcon_cleanup:
	if (portcon != NULL) {
		cil_destroy_portcon(portcon);
	}
	return rc;
}

void cil_destroy_portcon(struct cil_portcon *portcon)
{
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

int cil_fill_ipaddr(struct cil_tree_node *addr_node, struct cil_ipaddr *addr)
{
	int rc = SEPOL_ERR;

	if (addr_node == NULL || addr == NULL) {
		goto fill_ipaddr_cleanup;
	}

	if (addr_node->cl_head != NULL ||  addr_node->next != NULL) {
		printf("Invalid ip address (line: %d)\n", addr_node->line);
		goto fill_ipaddr_cleanup;
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
		goto fill_ipaddr_cleanup;
	}

	return SEPOL_OK;

fill_ipaddr_cleanup:
	return rc;
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
		goto gen_nodecon_cleanup;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid nodecon declaration (line: %d)\n", parse_current->line);
		goto gen_nodecon_cleanup;
	}

	rc = cil_nodecon_init(&nodecon);
	if (rc != SEPOL_OK) {
		goto gen_nodecon_cleanup;
	}

	if (parse_current->next->cl_head == NULL ) {
		nodecon->addr_str = cil_strdup(parse_current->next->data);
	} else {
		rc = cil_ipaddr_init(&nodecon->addr);
		if (rc != SEPOL_OK) {
			printf("Failed to init node address\n");
			goto gen_nodecon_cleanup;
		}

		rc = cil_fill_ipaddr(parse_current->next->cl_head, nodecon->addr);
		if (rc != SEPOL_OK) {
			printf("Failed to fill node address\n");
			goto gen_nodecon_cleanup;
		}
	}

	if (parse_current->next->next->cl_head == NULL ) {
		nodecon->mask_str = cil_strdup(parse_current->next->next->data);
	} else {
		rc = cil_ipaddr_init(&nodecon->mask);
		if (rc != SEPOL_OK) {
			printf("Failed to init node netmask\n");
			goto gen_nodecon_cleanup;
		}

		rc = cil_fill_ipaddr(parse_current->next->next->cl_head, nodecon->mask);
		if (rc != SEPOL_OK) {
			printf("Failed to fill node netmask\n");
			goto gen_nodecon_cleanup;
		}
	}

	if (parse_current->next->next->next->cl_head == NULL ) {
		nodecon->context_str = cil_strdup(parse_current->next->next->next->data);
	} else {
		rc = cil_context_init(&nodecon->context);
		if (rc != SEPOL_OK) {
			printf("Failed to init node context\n");
			goto gen_nodecon_cleanup;
		}

		rc = cil_fill_context(parse_current->next->next->next->cl_head, nodecon->context);
		if (rc != SEPOL_OK) {
			printf("Failed to fill node context\n");
			goto gen_nodecon_cleanup;
		}
	}

	ast_node->data = nodecon;
	ast_node->flavor = CIL_NODECON; 

	return SEPOL_OK;

gen_nodecon_cleanup:
	if (nodecon != NULL) {
		cil_destroy_nodecon(nodecon);
	}
	return rc;
}

void cil_destroy_nodecon(struct cil_nodecon *nodecon)
{
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
		goto gen_genfscon_cleanup;
	}
	
	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid genfscon declaration (line: %d)\n", parse_current->line);
		goto gen_genfscon_cleanup;
	}

	rc = cil_genfscon_init(&genfscon);
	if (rc != SEPOL_OK) {
		goto gen_genfscon_cleanup;
	}

	genfscon->type_str = cil_strdup(parse_current->next->data);
	genfscon->path_str = cil_strdup(parse_current->next->next->data);

	if (parse_current->next->next->next->cl_head == NULL ) {
		genfscon->context_str = cil_strdup(parse_current->next->next->next->data);
	} else {
		rc = cil_context_init(&genfscon->context);
		if (rc != SEPOL_OK) {
			printf("Failed to init genfs context\n");
			goto gen_genfscon_cleanup;
		}

		rc = cil_fill_context(parse_current->next->next->next->cl_head, genfscon->context);
		if (rc != SEPOL_OK) {
			printf("Failed to fill genfs context\n");
			goto gen_genfscon_cleanup;
		}
	}

	ast_node->data = genfscon;
	ast_node->flavor = CIL_GENFSCON; 

	return SEPOL_OK;

gen_genfscon_cleanup:
	if (genfscon != NULL) {
		cil_destroy_genfscon(genfscon);
	}
	return SEPOL_ERR;
}

void cil_destroy_genfscon(struct cil_genfscon *genfscon)
{
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
		goto gen_netifcon_cleanup;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid netifcon declaration (line: %d)\n", parse_current->line);
		goto gen_netifcon_cleanup;
	}
	
	rc = cil_netifcon_init(&netifcon);
	if (rc != SEPOL_OK) {
		goto gen_netifcon_cleanup;
	}
	
	netifcon->interface_str = cil_strdup(parse_current->next->data);
	
	if (parse_current->next->next->cl_head == NULL) {
		if (parse_current->next->next->data != NULL) {
			netifcon->if_context_str = cil_strdup(parse_current->next->next->data);
		} else {
			rc = SEPOL_ERR;
			goto gen_netifcon_cleanup;
		}
	} else {
		rc = cil_context_init(&netifcon->if_context);
		if (rc != SEPOL_OK) {
			printf("Failed to init if_context\n");	
			goto gen_netifcon_cleanup;	
		}

		rc = cil_fill_context(parse_current->next->next->cl_head, netifcon->if_context);
		if (rc != SEPOL_OK) {
			printf("Failed to fill interface context\n");
			goto gen_netifcon_cleanup;
		}
	}

	if (parse_current->next->next->next->cl_head == NULL) {
		if (parse_current->next->next->next->data != NULL) {
			netifcon->packet_context_str = cil_strdup(parse_current->next->next->next->data);
		} else {
			rc = SEPOL_ERR;
			goto gen_netifcon_cleanup;
		}
	} else {
		rc = cil_context_init(&netifcon->packet_context);
		if (rc != SEPOL_OK) {
			printf("Failed to init packet_context\n");
			goto gen_netifcon_cleanup;
		}

		rc = cil_fill_context(parse_current->next->next->next->cl_head, netifcon->packet_context);
		if (rc != SEPOL_OK) {
			printf("Failed to fill packet context\n");
			goto gen_netifcon_cleanup;
		}
	}

	ast_node->data = netifcon;
	ast_node->flavor = CIL_NETIFCON; 

	return SEPOL_OK;

gen_netifcon_cleanup:
	if (netifcon != NULL) {
		cil_destroy_netifcon(netifcon);
	}
	return SEPOL_ERR;
}

void cil_destroy_netifcon(struct cil_netifcon *netifcon)
{
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
		goto gen_fsuse_cleanup;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid fsuse declaration (line: %d)\n", parse_current->line);
		goto gen_fsuse_cleanup;
	}

	type = parse_current->next->data;

	rc = cil_fsuse_init(&fsuse);
	if (rc != SEPOL_OK) {
		goto gen_fsuse_cleanup;
	}

	if (!strcmp(type, "xattr")) {
		fsuse->type = CIL_FSUSE_XATTR;
	} else if (!strcmp(type, "task")) {
		fsuse->type = CIL_FSUSE_TASK;
	} else if (!strcmp(type, "trans")) {
		fsuse->type = CIL_FSUSE_TRANS;
	} else {
		printf("Invalid fsuse type\n");
		goto gen_fsuse_cleanup;
	}

	fsuse->fs_str = cil_strdup(parse_current->next->next->data);

	if (parse_current->next->next->next->cl_head == NULL) {
		fsuse->context_str = cil_strdup(parse_current->next->next->next->data);
	} else {
		rc = cil_context_init(&fsuse->context);
		if (rc != SEPOL_OK) {
			printf("Failed to init fsuse context\n");
			goto gen_fsuse_cleanup;
		}

		rc = cil_fill_context(parse_current->next->next->next->cl_head, fsuse->context);
		if (rc != SEPOL_OK) {
			printf("Failed to fill fsuse context\n");
			goto gen_fsuse_cleanup;
		}
	}

	ast_node->data = fsuse;
	ast_node->flavor = CIL_FSUSE;

	return SEPOL_OK;

gen_fsuse_cleanup:
	if (fsuse != NULL) {
		cil_destroy_fsuse(fsuse);\
	}
	return SEPOL_ERR;
}

void cil_destroy_fsuse(struct cil_fsuse *fsuse)
{
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
	struct cil_tree_node *next = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto gen_macro_cleanup;
	}

	rc =__cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid macro declaration (line: %d)\n", parse_current->line);
		goto gen_macro_cleanup;
	}

	rc = cil_macro_init(&macro);
	if (rc != SEPOL_OK) {
		goto gen_macro_cleanup;
	}

	key = parse_current->next->data;

	if (parse_current->next->next->cl_head != NULL) {
		struct cil_tree_node *current_item = parse_current->next->next->cl_head;
		struct cil_list_item *params_tail = NULL;
		cil_list_init(&macro->params);
		while (current_item != NULL) {
			char *kind = NULL;
			struct cil_param *param = NULL;

			if (current_item->cl_head == NULL) {
				printf("Invalid macro declaration (line: %d)\n", parse_current->line);
				goto gen_macro_cleanup;
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
			} else if (!strcmp(kind, CIL_KEY_CLASS)) {
				param->flavor = CIL_CLASS;
			} else if (!strcmp(kind, CIL_KEY_IPADDR)) {
				param->flavor = CIL_IPADDR;
			} else if (!strcmp(kind, CIL_KEY_PERMSET)) {
				param->flavor = CIL_PERMSET;
			} else {
				printf("Invalid macro declaration (line: %d)\n", parse_current->line);
				goto gen_macro_cleanup;
			}

			param->str =  cil_strdup(current_item->cl_head->next->data);

			if (strchr(param->str, '.')) {
				printf("Invalid macro declaration: parameter names cannot contain a '.' (line: %d)\n", parse_current->line);
				cil_destroy_param(param);
				goto gen_macro_cleanup;
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
							goto gen_macro_cleanup;
						}
					}
					curr_param = curr_param->next;
				}

				cil_list_item_init(&params_tail->next);
				params_tail->next->data = param;
				params_tail->next->flavor = CIL_PARAM;
				
				params_tail = params_tail->next;
				params_tail->next = NULL;
			}

			current_item = current_item->next;
		}
	}

	next = parse_current->next->next->next;
	cil_tree_subtree_destroy(parse_current->next->next);
	parse_current->next->next = next;
	
	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)macro, (hashtab_key_t)key, CIL_SYM_MACROS, CIL_MACRO);
	if (rc != SEPOL_OK) {
		goto gen_macro_cleanup;
	}

	ast_node->data = macro;
	ast_node->flavor = CIL_MACRO; 

	return SEPOL_OK;

gen_macro_cleanup:
	if (macro != NULL) {
		cil_destroy_macro(macro);
	}
	return SEPOL_ERR;
}

void cil_destroy_macro(struct cil_macro *macro)
{
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
		SYM_STRING | SYM_LIST | SYM_END,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	struct cil_call *call = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto gen_call_cleanup;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid call declaration (line: %d)\n", parse_current->line);
		goto gen_call_cleanup;
	}

	rc = cil_call_init(&call);
	if (rc != SEPOL_OK) {
		goto gen_call_cleanup;
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

gen_call_cleanup:
	if (call != NULL) {
		cil_destroy_call(call);
	}
	return rc;
}

void cil_destroy_call(struct cil_call *call)
{
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
}

void cil_destroy_args(struct cil_args *args)
{
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
		goto gen_optional_cleanup;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid optional declaration (line: %d)\n", parse_current->line);
		goto gen_optional_cleanup;
	}

	rc = cil_optional_init(&optional);
	if (rc != SEPOL_OK) {
		goto gen_optional_cleanup;
	}
	
	key = parse_current->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)optional, (hashtab_key_t)key, CIL_SYM_OPTIONALS, CIL_OPTIONAL);
	if (rc != SEPOL_OK) 
		goto gen_optional_cleanup;

	return SEPOL_OK;

gen_optional_cleanup:
	if (optional != NULL) {
		cil_destroy_optional(optional);
	}
	return rc;
}

void cil_destroy_optional(struct cil_optional *optional)
{
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
		goto gen_policycap_cleanup;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid policycap declaration (line: %d)\n", parse_current->line);
		goto gen_policycap_cleanup;
	}

	rc = cil_policycap_init(&polcap);
	if (rc != SEPOL_OK) {
		goto gen_policycap_cleanup;
	}

	key = parse_current->next->data;
	
	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)polcap, (hashtab_key_t)key, CIL_SYM_POLICYCAPS, CIL_POLICYCAP);
	if (rc != SEPOL_OK)
		goto gen_policycap_cleanup;
	
	return SEPOL_OK;

gen_policycap_cleanup:
	if (polcap != NULL) {
		cil_destroy_policycap(polcap);
	}
	return rc;
}

void cil_destroy_policycap(struct cil_policycap *polcap)
{
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
		goto gen_ipaddr_cleanup;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		printf("Invalid ipaddr rule (line: %d)\n", parse_current->line);
		goto gen_ipaddr_cleanup;
	}

	rc = cil_ipaddr_init(&ipaddr);
	if (rc != SEPOL_OK) {
		goto gen_ipaddr_cleanup;
	}

	key  = parse_current->next->data;

	rc = cil_fill_ipaddr(parse_current->next->next, ipaddr);
	if (rc != SEPOL_OK) {
		goto gen_ipaddr_cleanup;
	}

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)ipaddr, (hashtab_key_t)key, CIL_SYM_IPADDRS, CIL_IPADDR);
	if (rc != SEPOL_OK) {
		goto gen_ipaddr_cleanup;
	}

	return SEPOL_OK;

gen_ipaddr_cleanup:
	if (ipaddr != NULL) {
		cil_destroy_ipaddr(ipaddr);
	}
	return rc;
}

void cil_destroy_ipaddr(struct cil_ipaddr *ipaddr)
{
	cil_symtab_datum_destroy(ipaddr->datum);
	free(ipaddr);
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
		goto build_ast_node_helper_out;
	}

	args = extra_args;
	ast_current = args->ast;
	db = args->db;
	macro = args->macro;

	if (parse_current->parent->cl_head != parse_current) {
		/* ignore anything that isn't following a parenthesis */
		rc = SEPOL_OK;
		goto build_ast_node_helper_out;
	} else if (parse_current->data == NULL) {
		/* the only time parenthsis can immediately following parenthesis is if
		 * the parent is the root node */
		if (parse_current->parent->parent == NULL) {
			rc = SEPOL_OK;
		} else {
			printf("Syntax Error: Keyword expected after open parenthesis, line: %d\n", parse_current->line);
		}
		goto build_ast_node_helper_out;
	}

	rc = cil_tree_node_init(&ast_node);
	if (rc != SEPOL_OK) {
		printf("Failed to init tree node, rc: %d\n", rc);
		goto build_ast_node_helper_out;
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
			goto build_ast_node_helper_out;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_CLASS)) {
		rc = cil_gen_class(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_class failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
		// To avoid parsing list of perms again
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_PERMSET)) {
		rc = cil_gen_permset(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_permset failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_COMMON)) {
		rc = cil_gen_common(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_common failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_CLASSCOMMON)) {
		rc = cil_gen_classcommon(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_classcommon failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_SID)) {
		rc = cil_gen_sid(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_sid failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_SIDCONTEXT)) {
		rc = cil_gen_sidcontext(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_sidcontext failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_USER)) {
		rc = cil_gen_user(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_user failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_TYPE)) {
		rc = cil_gen_type(db, parse_current, ast_node, CIL_TYPE);
		if (rc != SEPOL_OK) {
			printf("cil_gen_type failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_TYPESET)) {
		rc = cil_gen_typeset(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_typeset failed, rc: %d\n", rc);
			return rc;
		}
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_ATTR)) {
		rc = cil_gen_type(db, parse_current, ast_node, CIL_ATTR);
		if (rc != SEPOL_OK) {
			printf("cil_gen_type (attr) failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_TYPEATTR)) {
		rc = cil_gen_typeattr(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_typeattr failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_TYPEALIAS)) {
		rc = cil_gen_typealias(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_typealias failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_TYPEBOUNDS)) {
		rc = cil_gen_typebounds(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_typebounds failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_TYPEPERMISSIVE)) {
		rc = cil_gen_typepermissive(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_typepermissive failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_FILETRANSITION)) {
		rc = cil_gen_filetransition(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_filetransition failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_ROLE)) {
		rc = cil_gen_role(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_role failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_USERROLE)) {
		rc = cil_gen_userrole(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_userrole failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_ROLETYPE)) {
		rc = cil_gen_roletype(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_roletype failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
	}
	else if (!strcmp(parse_current->data, CIL_KEY_ROLETRANS)) {
		rc = cil_gen_roletrans(parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_roletrans failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_ROLEALLOW)) {
		rc = cil_gen_roleallow(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_roleallow failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_ROLEDOMINANCE)) {
		rc = cil_gen_roledominance(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_roledominance failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_BOOL)) {
		rc = cil_gen_bool(db, parse_current, ast_node, CIL_BOOL);
		if (rc != SEPOL_OK) {
			printf("cil_gen_bool failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_BOOLEANIF)) {
		rc = cil_gen_boolif(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_boolif failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
	} else if(!strcmp(parse_current->data, CIL_KEY_TUNABLE)) {
		rc = cil_gen_bool(db, parse_current, ast_node, CIL_TUNABLE);
		if (rc != SEPOL_OK) {
			printf("cil_gen_bool failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_TUNABLEIF)) {
		rc = cil_gen_tunif(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_tunif failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_ELSE)) {
		rc = cil_gen_else(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_else failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_ALLOW)) {
		rc = cil_gen_avrule(parse_current, ast_node, CIL_AVRULE_ALLOWED); 
		if (rc != SEPOL_OK) {
			printf("cil_gen_avrule (allow) failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
		// So that the object and perms lists do not get parsed again
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_AUDITALLOW)) {
		rc = cil_gen_avrule(parse_current, ast_node, CIL_AVRULE_AUDITALLOW);
		if (rc != SEPOL_OK) {
			printf("cil_gen_avrule (auditallow) failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_DONTAUDIT)) {
		rc = cil_gen_avrule(parse_current, ast_node, CIL_AVRULE_DONTAUDIT);
		if (rc != SEPOL_OK) {
			printf("cil_gen_avrule (dontaudit) failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_NEVERALLOW)) {
		rc = cil_gen_avrule(parse_current, ast_node, CIL_AVRULE_NEVERALLOW);
		if (rc != SEPOL_OK) {
			printf("cil_gen_avrule (neverallow) failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_TYPETRANS)) {
		rc = cil_gen_type_rule(parse_current, ast_node, CIL_TYPE_TRANSITION);
		if (rc != SEPOL_OK) {
			printf("cil_gen_type_rule (typetransition) failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_TYPECHANGE)) {
		rc = cil_gen_type_rule(parse_current, ast_node, CIL_TYPE_CHANGE);
		if (rc != SEPOL_OK) {
			printf("cil_gen_type_rule (typechange) failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_TYPEMEMBER)) {
		rc = cil_gen_type_rule(parse_current, ast_node, CIL_TYPE_MEMBER);
		if (rc != SEPOL_OK) {
			printf("cil_gen_type_rule (typemember) failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_SENSITIVITY)) {
		rc = cil_gen_sensitivity(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_sensitivity (sensitivity) failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_SENSALIAS)) {
		rc = cil_gen_sensalias(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_sensalias (sensitivityalias) failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_CATEGORY)) {
		rc = cil_gen_category(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_category (category) failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_CATALIAS)) {
		rc = cil_gen_catalias(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_catalias (categoryalias) failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_CATSET)) {
		rc = cil_gen_catset(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_catset (categoryset) failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_CATORDER)) {
		rc = cil_gen_catorder(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_catorder failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_DOMINANCE)) {
		rc = cil_gen_dominance(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_dominance failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_SENSCAT)) {
		rc = cil_gen_senscat(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_senscat failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_LEVEL)) {
		rc = cil_gen_level(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_level failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_CONSTRAIN)) {
		rc = cil_gen_constrain(db, parse_current, ast_node, CIL_CONSTRAIN);
		if (rc != SEPOL_OK) {
			printf("cil_gen_constrain failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_MLSCONSTRAIN)) {
		rc = cil_gen_constrain(db, parse_current, ast_node, CIL_MLSCONSTRAIN);
		if (rc != SEPOL_OK) {
			printf("cil_gen_constrain failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_CONTEXT)) {
		rc = cil_gen_context(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_context failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_FILECON)) {
		rc = cil_gen_filecon(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_filecon failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_PORTCON)) {
		rc = cil_gen_portcon(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_portcon failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_NODECON)) {
		rc = cil_gen_nodecon(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_nodecon failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_GENFSCON)) {
		rc = cil_gen_genfscon(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_genfscon failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_NETIFCON)) {
		rc = cil_gen_netifcon(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_netifcon failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_FSUSE)) {
		rc = cil_gen_fsuse(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_fsuse failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_MACRO)) {
		rc = cil_gen_macro(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_macro failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_CALL)) {
		rc = cil_gen_call(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_call failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
		*finished = 1;
	} else if (!strcmp(parse_current->data, CIL_KEY_POLICYCAP)) {
		rc = cil_gen_policycap(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_policycap failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
		*finished = 1;
	} else if (!strcmp(parse_current->data, CIL_KEY_OPTIONAL)) {
		rc = cil_gen_optional(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_optional failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
	} else if (!strcmp(parse_current->data, CIL_KEY_IPADDR)) {
		rc = cil_gen_ipaddr(db, parse_current, ast_node);
		if (rc != SEPOL_OK) {
			printf("cil_gen_ipaddr failed, rc: %d\n", rc);
			goto build_ast_node_helper_out;
		}
	} else {
		printf("Error: Unknown keyword %s\n", (char*)parse_current->data);
		rc = SEPOL_ERR;
		goto build_ast_node_helper_out;
	}

	if (macro != NULL) {
		if (!strcmp(parse_current->data, CIL_KEY_MACRO)) {
			rc = SEPOL_ERR;
			goto build_ast_node_helper_out;
		}

		if (!strcmp(parse_current->data, CIL_KEY_TUNABLEIF)) {
			rc = SEPOL_ERR;
			goto build_ast_node_helper_out;
		}
	}

	return SEPOL_OK;

build_ast_node_helper_out:
	return rc;
}

int __cil_build_ast_reverse_helper(struct cil_tree_node *current, void *extra_args)
{
	int rc = SEPOL_ERR;
	struct cil_args_build *args = extra_args;

	if (current == NULL || extra_args == NULL) {
		goto build_ast_reverse_helper_out;
	}

	if (current->flavor == CIL_MACRO) {
		args->macro = NULL;
	}
	
	return SEPOL_OK;

build_ast_reverse_helper_out:
	return rc;
}

int __cil_build_ast_branch_helper(__attribute__((unused)) struct cil_tree_node *parse_current, void *extra_args)
{
	int rc = SEPOL_ERR;
	struct cil_tree_node *ast;
	struct cil_args_build *args;

	if (extra_args == NULL) {
		goto build_ast_branch_helper_out;
	}

	args = extra_args;
	ast = args->ast;
	args->ast = ast->parent;

	return SEPOL_OK;

build_ast_branch_helper_out:
	return rc;
}

int cil_build_ast(struct cil_db *db, struct cil_tree_node *parse_tree, struct cil_tree_node *ast)
{
	int rc = SEPOL_ERR;
	struct cil_args_build extra_args;

	if (db == NULL || parse_tree == NULL || ast == NULL) {
		goto build_ast_out;
	}

	extra_args.ast = ast;
	extra_args.db = db;
	extra_args.macro = NULL;	

	rc = cil_tree_walk(parse_tree, __cil_build_ast_node_helper, __cil_build_ast_reverse_helper, __cil_build_ast_branch_helper, &extra_args); 
	if (rc != SEPOL_OK) {
		printf("cil_tree_walk failed, rc: %d\n", rc);
		goto build_ast_out;
	}

	return SEPOL_OK;

build_ast_out:
	return rc;
}
