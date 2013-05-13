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

#include <sepol/policydb/conditional.h>

#include "cil_internal.h"
#include "cil_log.h"
#include "cil_mem.h"
#include "cil_tree.h"
#include "cil_list.h"
#include "cil_parser.h"
#include "cil_build_ast.h"
#include "cil_copy_ast.h"
#include "cil_verify.h"

struct cil_args_build {
	struct cil_tree_node *ast;
	struct cil_db *db;
	struct cil_tree_node *macro;
	struct cil_tree_node *tifstack;
};

int cil_gen_node(struct cil_db *db, struct cil_tree_node *ast_node, struct cil_symtab_datum *datum, hashtab_key_t key, enum cil_sym_index sflavor, enum cil_flavor nflavor)
{
	int rc = SEPOL_ERR;
	symtab_t *symtab = NULL;

	rc = __cil_verify_name((const char*)key);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	rc = cil_get_symtab(db, ast_node->parent, &symtab, sflavor);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	ast_node->data = datum;
	ast_node->flavor = nflavor;

	if (symtab != NULL) {
		rc = cil_symtab_insert(symtab, (hashtab_key_t)key, datum, ast_node);
		if (rc == SEPOL_EEXIST) {
			cil_log(CIL_ERR, "Re-declaration of %s %s\n", 
				cil_node_to_string(ast_node), key);
			if (cil_symtab_get_datum(symtab, key, &datum) == SEPOL_OK) {
				if (sflavor == CIL_SYM_BLOCKS) {
					struct cil_tree_node *node = datum->nodes->head->data;
					cil_log(CIL_ERR, "Previous declaration at line %d of %s\n",
						node->line, node->path);
				}
			}
			goto exit;
		}
	}

	if (ast_node->flavor >= CIL_MIN_DECLARATIVE && ast_node->parent->flavor == CIL_MACRO) {
		struct cil_list_item *item;
		struct cil_list *param_list = ((struct cil_macro*)ast_node->parent->data)->params;
		if (param_list != NULL) {
			cil_list_for_each(item, param_list) {
				struct cil_param *param = item->data;
				if (param->flavor == ast_node->flavor) {
					if (!strcmp(param->str, key)) {
						cil_log(CIL_ERR, "%s %s shadows a macro parameter in macro declaration\n", cil_node_to_string(ast_node), key);
						rc = SEPOL_ERR;
						goto exit;
					}
				}
			}
		}
	}

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Failed to create node\n");
	return rc;
}

int cil_gen_block(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node, uint16_t is_abstract)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_N_LISTS | SYM_END
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
		goto exit;
	}

	cil_block_init(&block);

	block->is_abstract = is_abstract;

	key = parse_current->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)block, (hashtab_key_t)key, CIL_SYM_BLOCKS, CIL_BLOCK);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad block declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_block(block);
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

int cil_gen_blockinherit(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	struct cil_blockinherit *inherit = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	cil_blockinherit_init(&inherit);

	inherit->block_str = cil_strdup(parse_current->next->data);

	ast_node->data = inherit;
	ast_node->flavor = CIL_BLOCKINHERIT;

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad blockinherit declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_blockinherit(inherit);
	return rc;
}

void cil_destroy_blockinherit(struct cil_blockinherit *inherit)
{
	if (inherit == NULL) {
		return;
	}

	if (inherit->block_str != NULL) {
		free(inherit->block_str);
	}

	free(inherit);
}

int cil_gen_blockabstract(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	struct cil_blockabstract *abstract = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	cil_blockabstract_init(&abstract);

	abstract->block_str = cil_strdup(parse_current->next->data);

	ast_node->data = abstract;
	ast_node->flavor = CIL_BLOCKABSTRACT;

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad blockabstract declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_blockabstract(abstract);
	return rc;
}

void cil_destroy_blockabstract(struct cil_blockabstract *abstract)
{
	if (abstract == NULL) {
		return;
	}

	if (abstract->block_str != NULL) {
		free(abstract->block_str);
	}

	free(abstract);
}

int cil_gen_in(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_N_LISTS
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	int rc = SEPOL_ERR;
	struct cil_in *in = NULL;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	cil_in_init(&in);

	in->block_str = cil_strdup(parse_current->next->data);

	ast_node->data = in;
	ast_node->flavor = CIL_IN;

	return SEPOL_OK;
exit:
	cil_log(CIL_ERR, "Bad in statement at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_in(in);
	return rc;
}

void cil_destroy_in(struct cil_in *in)
{
	if (in == NULL) {
		return;
	}

	if (in->block_str != NULL) {
		free(in->block_str);
	}

	cil_symtab_array_destroy(in->symtab);

	free(in);
}

int cil_gen_class(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_LIST | SYM_END,
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
		goto exit;
	}

	cil_class_init(&class);

	key = parse_current->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)class, (hashtab_key_t)key, CIL_SYM_CLASSES, CIL_CLASS);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	if (parse_current->next->next != NULL) {
		perms = parse_current->next->next->cl_head;
		rc = cil_gen_perm_nodes(db, perms, ast_node, CIL_PERM, &class->num_perms);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad class declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_class(class);
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

int cil_gen_perm(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node, unsigned int *num_perms)
{
	char *key = NULL;
	struct cil_perm *perm = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	cil_perm_init(&perm);

	key = parse_current->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)perm, (hashtab_key_t)key, CIL_SYM_UNKNOWN, CIL_PERM);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	perm->value = *num_perms;
	(*num_perms)++;

	return SEPOL_OK;

exit:
	cil_destroy_perm(perm);
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

int cil_gen_map_perm(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node, unsigned int *num_perms)
{
	int rc = SEPOL_ERR;
	struct cil_map_perm *cmp = NULL;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	cil_map_perm_init(&cmp);

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)cmp, (hashtab_key_t)parse_current->data, CIL_SYM_UNKNOWN, CIL_MAP_PERM);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	cmp->value = *num_perms;
	(*num_perms)++;

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad map permissions\n");
	cil_destroy_map_perm(cmp);
	return rc;
}

void cil_destroy_map_perm(struct cil_map_perm *cmp)
{
	if (cmp == NULL) {
		return;
	}

	cil_symtab_datum_destroy(cmp->datum);
	if (cmp->classperms != NULL) {
		cil_list_destroy(&cmp->classperms, 0);
	}

	free(cmp);
}

int cil_gen_perm_nodes(struct cil_db *db, struct cil_tree_node *current_perm, struct cil_tree_node *ast_node, enum cil_flavor flavor, unsigned int *num_perms)
{
	int rc = SEPOL_ERR;
	struct cil_tree_node *new_ast = NULL;

	while(current_perm != NULL) {
		if (current_perm->cl_head != NULL) {
		
			rc = SEPOL_ERR;
			goto exit;
		}
		cil_tree_node_init(&new_ast);
		new_ast->parent = ast_node;
		new_ast->line = current_perm->line;
		new_ast->path = current_perm->path;
		if (flavor == CIL_PERM) {
			rc = cil_gen_perm(db, current_perm, new_ast, num_perms);
		} else if (flavor == CIL_MAP_PERM) {
			rc = cil_gen_map_perm(db, current_perm, new_ast, num_perms);
		}
		if (rc != SEPOL_OK) {
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
	cil_log(CIL_ERR, "Bad permissions\n");
	return rc;
}

int cil_fill_perms(struct cil_tree_node *start_perm, struct cil_list **perms, int allow_expr_ops)
{
	int rc = SEPOL_ERR;
	enum cil_syntax syntax[] = {
		SYM_N_STRINGS | SYM_N_LISTS,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);

	rc = __cil_verify_syntax(start_perm->cl_head, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	rc = cil_gen_expr(start_perm, CIL_PERM, perms, allow_expr_ops);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad permission list or expression\n");
	return rc;
}

int cil_fill_classperms(struct cil_tree_node *parse_current, struct cil_classperms **cp, int allow_set, int allow_expr_ops)
{
	int rc = SEPOL_ERR;

	cil_classperms_init(cp);

	if (parse_current->cl_head == NULL) {
		if (!allow_set) {
			cil_log(CIL_ERR, "Class-permission set not allowed in this rule\n");
			goto exit;
		}	
		(*cp)->flavor = CIL_CLASSPERMSET;
		(*cp)->u.classpermset_str = cil_strdup(parse_current->data);
	} else {
		struct cil_tree_node *class_node = parse_current->cl_head;
		enum cil_syntax syntax[] = {
			SYM_STRING,
			SYM_LIST,
			SYM_END
		};
		int syntax_len = sizeof(syntax)/sizeof(*syntax);

		rc = __cil_verify_syntax(class_node, syntax, syntax_len);
		if (rc != SEPOL_OK) {
			goto exit;
		}

		(*cp)->flavor = CIL_CLASSPERMS; /* But could be map classperms */
		(*cp)->u.cp.class_str = cil_strdup(class_node->data);

		rc = cil_fill_perms(class_node->next, &(*cp)->u.cp.perm_strs, allow_expr_ops);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad class permissions\n");
	cil_destroy_classperms(*cp);
	*cp = NULL;
	return rc;
}

void cil_destroy_classperms(struct cil_classperms *cp)
{
	if (cp == NULL) {
		return;
	}

	switch (cp->flavor) {
	case CIL_CLASSPERMSET:
		free(cp->u.classpermset_str);
		break;
	case CIL_CLASS:
		free(cp->u.cp.class_str);
		cil_list_destroy(&cp->u.cp.perm_strs, CIL_TRUE);
		cil_list_destroy(&cp->r.cp.perms, CIL_FALSE);
		break;
	case CIL_MAP_CLASS:
		free(cp->u.cp.class_str);
		cil_list_destroy(&cp->u.cp.perm_strs, CIL_TRUE);
		cil_list_destroy(&cp->r.mcp.perms, CIL_FALSE);
		break;
	default:
		break;
	}

	free(cp);
}

int cil_fill_classperms_exprs_list(struct cil_tree_node *parse_current, struct cil_list **expr_list, int allow_sets, int allow_expr_ops)
{
	int rc = SEPOL_ERR;
	struct cil_tree_node *curr;
	enum cil_syntax syntax[] = {
		SYM_N_STRINGS | SYM_N_LISTS,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);

	if (parse_current == NULL || expr_list == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	cil_list_init(expr_list, CIL_CLASSPERMS);

	for (curr = parse_current; curr != NULL; curr = curr->next) {
		struct cil_classperms *new_cp;

		rc = cil_fill_classperms(curr, &new_cp, allow_sets, allow_expr_ops);
		if (rc != SEPOL_OK) {
			goto exit;
		}

		cil_list_append(*expr_list, CIL_CLASSPERMS, new_cp);
	}
	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Problem filling class-permissions expression list\n");
	cil_list_destroy(expr_list, CIL_TRUE);
	return rc;
}

int cil_gen_classpermset(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	int rc = SEPOL_ERR;
	char *key = NULL;
	struct cil_classpermset *cps = NULL;
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_LIST,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	cil_classpermset_init(&cps);

	key = parse_current->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)cps, (hashtab_key_t)key, CIL_SYM_CLASSPERMSETS, CIL_CLASSPERMSET);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	rc = cil_fill_classperms(parse_current->next->next, &cps->classperms, CIL_FALSE, CIL_TRUE);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad classpermissionset declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_classpermset(cps);
	return rc;
}

void cil_destroy_classpermset(struct cil_classpermset *cps)
{
	if (cps == NULL) {
		return;
	}

	cil_symtab_datum_destroy(cps->datum);

	cil_destroy_classperms(cps->classperms);

	free(cps);
}

int cil_gen_map_class(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_LIST,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	char *key = NULL;
	struct cil_map_class *map = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	cil_map_class_init(&map);

	key = parse_current->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)map, (hashtab_key_t)key, CIL_SYM_CLASSES, CIL_MAP_CLASS);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	rc = cil_gen_perm_nodes(db, parse_current->next->next->cl_head, ast_node, CIL_MAP_PERM, &map->num_perms);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad map class declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_map_class(map);
	return rc;
}

void cil_destroy_map_class(struct cil_map_class *map)
{
	if (map == NULL) {
		return;
	}

	cil_symtab_datum_destroy(map->datum);
	cil_symtab_destroy(&map->perms);

	free(map);
}

int cil_gen_classmapping(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	int rc = SEPOL_ERR;
	struct cil_classmapping *mapping = NULL;
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_STRING,
		SYM_N_STRINGS | SYM_N_LISTS,
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	cil_classmapping_init(&mapping);

	mapping->map_class_str = cil_strdup(parse_current->next->data);
	mapping->map_perm_str = cil_strdup(parse_current->next->next->data);

	rc = cil_fill_classperms_exprs_list(parse_current->next->next->next, &mapping->classperms, CIL_FALSE, CIL_TRUE);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	ast_node->data = mapping;
	ast_node->flavor = CIL_CLASSMAPPING;

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad classmapping declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_classmapping(mapping);
	return rc;
}

void cil_destroy_classmapping(struct cil_classmapping *mapping)
{
	if (mapping == NULL) {
		return;
	}

	free(mapping->map_class_str);
	free(mapping->map_perm_str);
	cil_list_destroy(&mapping->classperms, 1);

	free(mapping);
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
		goto exit;
	}

	cil_common_init(&common);

	key = parse_current->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)common, (hashtab_key_t)key, CIL_SYM_COMMONS, CIL_COMMON);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	rc = cil_gen_perm_nodes(db, parse_current->next->next->cl_head, ast_node, CIL_PERM, &common->num_perms);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad common declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_common(common);
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
		goto exit;
	}

	cil_classcommon_init(&clscom);

	clscom->class_str = cil_strdup(parse_current->next->data);
	clscom->common_str = cil_strdup(parse_current->next->next->data);

	ast_node->data = clscom;
	ast_node->flavor = CIL_CLASSCOMMON;

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad classcommon declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_classcommon(clscom);
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
		goto exit;
	}

	cil_sid_init(&sid);

	key = parse_current->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)sid, (hashtab_key_t)key, CIL_SYM_SIDS, CIL_SID);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad sid declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_sid(sid);
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
		goto exit;
	}

	cil_sidcontext_init(&sidcon);

	sidcon->sid_str = cil_strdup(parse_current->next->data);

	if (parse_current->next->next->cl_head == NULL) {
		sidcon->context_str = cil_strdup(parse_current->next->next->data);
	} else {
		cil_context_init(&sidcon->context);

		rc = cil_fill_context(parse_current->next->next->cl_head, sidcon->context);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	ast_node->data = sidcon;
	ast_node->flavor = CIL_SIDCONTEXT;

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad sidcontext declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_sidcontext(sidcon);
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
		goto exit;
	}

	cil_user_init(&user);

	key = parse_current->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)user, (hashtab_key_t)key, CIL_SYM_USERS, CIL_USER);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad user declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_user(user);\
	return rc;
}

void cil_destroy_user(struct cil_user *user)
{
	if (user == NULL) {
		return;
	}

	cil_symtab_datum_destroy(user->datum);
	cil_list_destroy(&user->roles, CIL_FALSE);
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
		goto exit;
	}

	cil_userlevel_init(&usrlvl);

	usrlvl->user_str = cil_strdup(parse_current->next->data);

	if (parse_current->next->next->cl_head == NULL) {
		usrlvl->level_str = cil_strdup(parse_current->next->next->data);
	} else {
		cil_level_init(&usrlvl->level);

		rc = cil_fill_level(parse_current->next->next->cl_head, usrlvl->level);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	ast_node->data = usrlvl;
	ast_node->flavor = CIL_USERLEVEL;

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad userlevel declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_userlevel(usrlvl);
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
		goto exit;
	}

	cil_userrange_init(&userrange);

	userrange->user_str = cil_strdup(parse_current->next->data);

	if (parse_current->next->next->cl_head == NULL) {
		userrange->range_str = cil_strdup(parse_current->next->next->data);
	} else {
		cil_levelrange_init(&userrange->range);

		rc = cil_fill_levelrange(parse_current->next->next->cl_head, userrange->range);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	ast_node->data = userrange;
	ast_node->flavor = CIL_USERRANGE;

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad userrange declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_userrange(userrange);
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
		goto exit;
	}

	cil_userbounds_init(&userbnds);

	userbnds->user_str = cil_strdup(parse_current->next->data);
	userbnds->bounds_str = cil_strdup(parse_current->next->next->data);

	ast_node->data = userbnds;
	ast_node->flavor = CIL_USERBOUNDS;

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad userbounds declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_userbounds(userbnds);
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

int cil_gen_userprefix(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_STRING,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	struct cil_userprefix *userprefix = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	cil_userprefix_init(&userprefix);

	userprefix->user_str = cil_strdup(parse_current->next->data);
	userprefix->prefix_str = cil_strdup(parse_current->next->next->data);

	ast_node->data = userprefix;
	ast_node->flavor = CIL_USERPREFIX;

	return SEPOL_OK;
exit:
	cil_log(CIL_ERR, "Bad userprefix declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_userprefix(userprefix);
	return rc;
}

void cil_destroy_userprefix(struct cil_userprefix *userprefix)
{
	if (userprefix == NULL) {
		return;
	}
	free(userprefix->user_str);
	free(userprefix->prefix_str);
	free(userprefix);
}

int cil_gen_selinuxuser(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_STRING,
		SYM_STRING | SYM_LIST,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	struct cil_selinuxuser *selinuxuser = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	cil_selinuxuser_init(&selinuxuser);

	selinuxuser->name_str = cil_strdup(parse_current->next->data);
	selinuxuser->user_str = cil_strdup(parse_current->next->next->data);

	if (parse_current->next->next->next->cl_head == NULL) {
		selinuxuser->range_str = cil_strdup(parse_current->next->next->next->data);
	} else {
		cil_levelrange_init(&selinuxuser->range);

		rc = cil_fill_levelrange(parse_current->next->next->next->cl_head, selinuxuser->range);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	ast_node->data = selinuxuser;
	ast_node->flavor = CIL_SELINUXUSER;

	return SEPOL_OK;
exit:
	cil_log(CIL_ERR, "Bad selinuxuser declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_selinuxuser(selinuxuser);
	return rc;
}

int cil_gen_selinuxuserdefault(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_STRING | SYM_LIST,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	struct cil_selinuxuser *selinuxuser = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	cil_selinuxuser_init(&selinuxuser);

	selinuxuser->name_str = cil_strdup("__default__");
	selinuxuser->user_str = cil_strdup(parse_current->next->data);

	if (parse_current->next->next->cl_head == NULL) {
		selinuxuser->range_str = cil_strdup(parse_current->next->next->data);
	} else {
		cil_levelrange_init(&selinuxuser->range);

		rc = cil_fill_levelrange(parse_current->next->next->cl_head, selinuxuser->range);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	ast_node->data = selinuxuser;
	ast_node->flavor = CIL_SELINUXUSERDEFAULT;

	return SEPOL_OK;
exit:
	cil_log(CIL_ERR, "Bad selinuxuserdefault declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_selinuxuser(selinuxuser);
	return rc;
}

void cil_destroy_selinuxuser(struct cil_selinuxuser *selinuxuser)
{
	if (selinuxuser == NULL) {
		return;
	}
	free(selinuxuser->name_str);
	free(selinuxuser->user_str);
	free(selinuxuser->range_str);
	free(selinuxuser);
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
		goto exit;
	}

	cil_role_init(&role);

	key = parse_current->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)role, (hashtab_key_t)key, CIL_SYM_ROLES, CIL_ROLE);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad role declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_role(role);
	return rc;
}

void cil_destroy_role(struct cil_role *role)
{
	if (role == NULL) {
		return;
	}

	cil_symtab_datum_destroy(role->datum);
	ebitmap_destroy(role->types);
	free(role->types);
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
		goto exit;
	}

	cil_roletype_init(&roletype);

	roletype->role_str = cil_strdup(parse_current->next->data);
	roletype->type_str = cil_strdup(parse_current->next->next->data);

	ast_node->data = roletype;
	ast_node->flavor = CIL_ROLETYPE;

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad roletype declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_roletype(roletype);
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
		goto exit;
	}

	cil_userrole_init(&userrole);

	userrole->user_str = cil_strdup(parse_current->next->data);
	userrole->role_str = cil_strdup(parse_current->next->next->data);

	ast_node->data = userrole;
	ast_node->flavor = CIL_USERROLE;

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad userrole declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_userrole(userrole);
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

int cil_gen_roletransition(struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
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
	struct cil_roletransition *roletrans = NULL;
	int rc = SEPOL_ERR;

	if (parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	cil_roletransition_init(&roletrans);

	roletrans->src_str = cil_strdup(parse_current->next->data);
	roletrans->tgt_str = cil_strdup(parse_current->next->next->data);
	roletrans->obj_str = cil_strdup(parse_current->next->next->next->data);
	roletrans->result_str = cil_strdup(parse_current->next->next->next->next->data);

	ast_node->data = roletrans;
	ast_node->flavor = CIL_ROLETRANSITION;

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad roletransition rule at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_roletransition(roletrans);
	return rc;
}

void cil_destroy_roletransition(struct cil_roletransition *roletrans)
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
	struct cil_roleallow *roleallow = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	cil_roleallow_init(&roleallow);

	roleallow->src_str = cil_strdup(parse_current->next->data);
	roleallow->tgt_str = cil_strdup(parse_current->next->next->data);

	ast_node->data = roleallow;
	ast_node->flavor = CIL_ROLEALLOW;

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad roleallow rule at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_roleallow(roleallow);
	return rc;
}

void cil_destroy_roleallow(struct cil_roleallow *roleallow)
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

int cil_gen_roleattribute(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	char *key = NULL;
	struct cil_roleattribute *attr = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	if (!strcmp(parse_current->next->data, CIL_KEY_SELF)) {
		cil_log(CIL_ERR, "The keyword '%s' is reserved\n", CIL_KEY_SELF);
		rc = SEPOL_ERR;
		goto exit;
	}

	cil_roleattribute_init(&attr);

	key = parse_current->next->data;
	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)attr, (hashtab_key_t)key, CIL_SYM_ROLES, CIL_ROLEATTRIBUTE);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	return SEPOL_OK;
exit:
	cil_log(CIL_ERR, "Bad roleattribute declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_roleattribute(attr);
	return rc;
}

void cil_destroy_roleattribute(struct cil_roleattribute *attr)
{
	if (attr == NULL) {
		return;
	}

	if (attr->expr_list != NULL) {
		/* we don't want to destroy the expression stacks (cil_list) inside
		 * this list cil_list_destroy destroys sublists, so we need to do it
		 * manually */
		struct cil_list_item *expr = attr->expr_list->head;
		while (expr != NULL) {
			struct cil_list_item *next = expr->next;
			cil_list_item_destroy(&expr, CIL_FALSE);
			expr = next;
		}
		free(attr->expr_list);
		attr->expr_list = NULL;
	}

	cil_symtab_datum_destroy(attr->datum);
	ebitmap_destroy(attr->roles);
	free(attr->roles);
	free(attr);
}

int cil_gen_roleattributeset(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_STRING | SYM_LIST,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	struct cil_roleattributeset *attrset = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	cil_roleattributeset_init(&attrset);

	attrset->attr_str = cil_strdup(parse_current->next->data);

	rc = cil_gen_expr(parse_current->next->next, CIL_ROLE, &attrset->str_expr, CIL_TRUE);
	if (rc != SEPOL_OK) {
		goto exit;
	}
	ast_node->data = attrset;
	ast_node->flavor = CIL_ROLEATTRIBUTESET;

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad roleattributeset declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_roleattributeset(attrset);

	return rc;
}

void cil_destroy_roleattributeset(struct cil_roleattributeset *attrset)
{
	if (attrset == NULL) {
		return;
	}

	cil_list_destroy(&attrset->str_expr, CIL_TRUE);
	free(attrset->attr_str);
	free(attrset);
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
		goto exit;
	}

	cil_rolebounds_init(&rolebnds);

	rolebnds->role_str = cil_strdup(parse_current->next->data);
	rolebnds->bounds_str = cil_strdup(parse_current->next->next->data);

	ast_node->data = rolebnds;
	ast_node->flavor = CIL_ROLEBOUNDS;

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad rolebounds declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_rolebounds(rolebnds);
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
		goto exit;
	}

	cil_avrule_init(&rule);

	rule->rule_kind = rule_kind;

	rule->src_str = cil_strdup(parse_current->next->data);
	rule->tgt_str = cil_strdup(parse_current->next->next->data);

	rc = cil_fill_classperms(parse_current->next->next->next, &rule->classperms, CIL_TRUE, CIL_FALSE);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	ast_node->data = rule;
	ast_node->flavor = CIL_AVRULE;

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad allow rule at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_avrule(rule);
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
	
	cil_destroy_classperms(rule->classperms);

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
		goto exit;
	}

	cil_type_rule_init(&rule);

	rule->rule_kind = rule_kind;
	rule->src_str = cil_strdup(parse_current->next->data);
	rule->tgt_str = cil_strdup(parse_current->next->next->data);
	rule->obj_str = cil_strdup(parse_current->next->next->next->data);
	rule->result_str = cil_strdup(parse_current->next->next->next->next->data);

	ast_node->data = rule;
	ast_node->flavor = CIL_TYPE_RULE;

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad type rule at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_type_rule(rule);
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
		goto exit;
	}

	if (!strcmp(parse_current->next->data, CIL_KEY_SELF)) {
		cil_log(CIL_ERR, "The keyword '%s' is reserved\n", CIL_KEY_SELF);
		rc = SEPOL_ERR;
		goto exit;
	}

	cil_type_init(&type);

	key = parse_current->next->data;
	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)type, (hashtab_key_t)key, CIL_SYM_TYPES, CIL_TYPE);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad type declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_type(type);
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
		goto exit;
	}

	if (!strcmp(parse_current->next->data, CIL_KEY_SELF)) {
		cil_log(CIL_ERR, "The keyword '%s' is reserved\n", CIL_KEY_SELF);
		rc = SEPOL_ERR;
		goto exit;
	}

	cil_typeattribute_init(&attr);

	key = parse_current->next->data;
	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)attr, (hashtab_key_t)key, CIL_SYM_TYPES, CIL_TYPEATTRIBUTE);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad typeattribute declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_typeattribute(attr);
	return rc;
}

void cil_destroy_typeattribute(struct cil_typeattribute *attr)
{
	if (attr == NULL) {
		return;
	}

	cil_symtab_datum_destroy(attr->datum);

	if (attr->expr_list != NULL) {
		/* we don't want to destroy the expression stacks (cil_list) inside
		 * this list cil_list_destroy destroys sublists, so we need to do it
		 * manually */
		struct cil_list_item *expr = attr->expr_list->head;
		while (expr != NULL) {
			struct cil_list_item *next = expr->next;
			cil_list_item_destroy(&expr, CIL_FALSE);
			expr = next;
		}
		free(attr->expr_list);
		attr->expr_list = NULL;
	}
	ebitmap_destroy(attr->types);
	free(attr->types);
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
		goto exit;
	}

	cil_bool_init(&boolean);

	key = parse_current->next->data;

	if (!strcmp(parse_current->next->next->data, "true")) {
		boolean->value = CIL_TRUE;
	} else if (!strcmp(parse_current->next->next->data, "false")) {
		boolean->value = CIL_FALSE;
	} else {
		cil_log(CIL_ERR, "Value must be either \'true\' or \'false\'");
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
	cil_log(CIL_ERR, "Bad boolean declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_bool(boolean);
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

enum cil_flavor __cil_get_operator_flavor(const char *op)
{
	enum cil_flavor op_flavor = CIL_NONE;

	if (!strcmp(op, CIL_KEY_AND))
		op_flavor = CIL_AND;
	else if (!strcmp(op, CIL_KEY_OR))
		op_flavor = CIL_OR;
	else if (!strcmp(op, CIL_KEY_NOT))
		op_flavor = CIL_NOT;
	else if (!strcmp(op, CIL_KEY_STAR))
		op_flavor = CIL_STAR;
	else if (!strcmp(op, CIL_KEY_EQ))
		op_flavor = CIL_EQ;
	else if (!strcmp(op, CIL_KEY_NEQ))
		op_flavor = CIL_NEQ;
	else if (!strcmp(op, CIL_KEY_XOR))
		op_flavor = CIL_XOR;
	else if (!strcmp(op, CIL_KEY_CONS_DOM))
		op_flavor = CIL_CONS_DOM;
	else if (!strcmp(op, CIL_KEY_CONS_DOMBY))
		op_flavor = CIL_CONS_DOMBY;
	else if (!strcmp(op, CIL_KEY_CONS_INCOMP))
		op_flavor = CIL_CONS_INCOMP;

	return op_flavor;
}

void __cil_gen_constrain_expr(struct cil_tree_node *current, enum cil_flavor op_flavor, struct cil_list **sub_expr)
{
	char * lstr = NULL;
	char * rstr = NULL;
	enum cil_flavor sub_expr_flavor = CIL_NONE;
	enum cil_flavor l_flavor = CIL_NONE;
	enum cil_flavor r_flavor = CIL_NONE;

	lstr = current->next->data;
	rstr = current->next->next->data;

	if (!strcmp(lstr, CIL_KEY_CONS_T1)) {
		sub_expr_flavor = CIL_TYPE;
		l_flavor = CIL_CONS_T1;
		if (!strcmp(rstr, CIL_KEY_CONS_T2)) {
			r_flavor = CIL_CONS_T2;
		} else {
			r_flavor = CIL_TYPE;
		}
	} else if (!strcmp(lstr, CIL_KEY_CONS_T2)) {
		sub_expr_flavor = CIL_TYPE;
		l_flavor = CIL_CONS_T2;
		r_flavor = CIL_TYPE;
	} else if (!strcmp(lstr, CIL_KEY_CONS_T3)) {
		sub_expr_flavor = CIL_TYPE;
		l_flavor = CIL_CONS_T3;
		r_flavor = CIL_TYPE;
	} else if (!strcmp(lstr, CIL_KEY_CONS_R1)) {
		sub_expr_flavor = CIL_ROLE;
		l_flavor = CIL_CONS_R1;
		if (!strcmp(rstr, CIL_KEY_CONS_R2)) {
			r_flavor = CIL_CONS_R2;
		} else {
			r_flavor = CIL_ROLE;
		}
	} else if (!strcmp(lstr, CIL_KEY_CONS_R2)) {
		sub_expr_flavor = CIL_ROLE;
		l_flavor = CIL_CONS_R2;
		r_flavor = CIL_ROLE;
	} else if (!strcmp(lstr, CIL_KEY_CONS_R3)) {
		sub_expr_flavor = CIL_ROLE;
		l_flavor = CIL_CONS_R3;
	} else if (!strcmp(lstr, CIL_KEY_CONS_U1)) {
		sub_expr_flavor = CIL_USER;
		l_flavor = CIL_CONS_U1;
		if (!strcmp(rstr, CIL_KEY_CONS_U2)) {
			r_flavor = CIL_CONS_U2;
		} else {
			r_flavor = CIL_USER;
		}
	} else if (!strcmp(lstr, CIL_KEY_CONS_U2)) {
		sub_expr_flavor = CIL_USER;
		l_flavor = CIL_CONS_U2;
		r_flavor = CIL_USER;
	} else if (!strcmp(lstr, CIL_KEY_CONS_U3)) {
		sub_expr_flavor = CIL_USER;
		l_flavor = CIL_CONS_U3;
		r_flavor = CIL_USER;
	} else if (!strcmp(lstr, CIL_KEY_CONS_L1)) {
		sub_expr_flavor = CIL_LEVEL;
		l_flavor = CIL_CONS_L1;
		if (!strcmp(rstr, CIL_KEY_CONS_L2)) {
			r_flavor = CIL_CONS_L2;
		} else if (!strcmp(rstr, CIL_KEY_CONS_H1)) {
			r_flavor = CIL_CONS_H1;
		} else {
			r_flavor = CIL_CONS_H2;
		}
	} else if (!strcmp(lstr, CIL_KEY_CONS_L2)) {
		sub_expr_flavor = CIL_LEVEL;
		l_flavor = CIL_CONS_L2;
		r_flavor = CIL_CONS_H2;
	} else {
		sub_expr_flavor = CIL_LEVEL;
		l_flavor = CIL_CONS_H1;
		if (!strcmp(rstr, CIL_KEY_CONS_L2)) {
			r_flavor = CIL_CONS_L2;
		} else {
			r_flavor = CIL_CONS_H2;
		}
	}

	cil_list_init(sub_expr, sub_expr_flavor);

	cil_list_append(*sub_expr, CIL_CONS_OPERAND, cil_flavordup(l_flavor));

	if (r_flavor == CIL_TYPE || r_flavor == CIL_ROLE || r_flavor == CIL_USER) {
		cil_list_append(*sub_expr, CIL_STRING, cil_strdup(rstr));
	} else {
		cil_list_append(*sub_expr, CIL_CONS_OPERAND, cil_flavordup(r_flavor));
	}

	cil_list_append(*sub_expr, CIL_OP, cil_flavordup(op_flavor));
}

struct cil_expr_args {
	struct cil_list *expr;
	struct cil_list *expr_stack[32];
	int n;
	int first;
	enum cil_flavor flavor;
	int depth;
	int maxdepth;
	int isconstraint;
	int nbools; // Number of bools in an expression stack
	int allow_ops;
};

int __cil_gen_expr_helper(struct cil_tree_node *node, uint32_t *finished, void *extra_args)
{
	int rc = SEPOL_ERR;
	struct cil_expr_args *args = extra_args;
	struct cil_list *expr = args->expr;
	enum cil_flavor expr_flavor = args->flavor;
	int *depth = &args->depth;
	int maxdepth = args->maxdepth;
	int isconstraint = args->isconstraint;
	int *nbools = &args->nbools;

	if (node == node->parent->cl_head && !isconstraint) {
		return SEPOL_OK;
	}

	if (node->data == NULL) {
		return SEPOL_OK;
	}

	if (isconstraint) {
		enum cil_flavor op_flavor;

		rc = __cil_verify_expr_operator(node->data, expr_flavor);
		if (rc != SEPOL_OK) {
			goto exit;
		}

		op_flavor = __cil_get_operator_flavor(node->data);

		if (op_flavor != CIL_AND && op_flavor != CIL_OR && op_flavor != CIL_NOT) {
			/* op == eq, neq, dom, domby, or incomp */
			struct cil_list *sub_expr;

			rc = __cil_verify_constrain_expr(node, expr_flavor, op_flavor);
			if (rc != SEPOL_OK) {
				goto exit;
			}
			__cil_gen_constrain_expr(node, op_flavor, &sub_expr);
			cil_list_append(expr, CIL_LIST, sub_expr);
			(*depth)++;
			*finished = CIL_TREE_SKIP_ALL;
		}
	} else {
		if (expr_flavor == CIL_BOOL) {
			(*nbools)++;
			if (*nbools > COND_MAX_BOOLS) {
				cil_log(CIL_ERR, "Expression exceeds max number of bools (%d)\n", COND_MAX_BOOLS);
				rc = SEPOL_ERR;
				goto exit;
			}
		}

		cil_list_append(expr, CIL_STRING, cil_strdup(node->data));

		if (expr_flavor != CIL_PERM) {
			(*depth)++;
		}
	}

	if (*depth > maxdepth) {
		cil_log(CIL_ERR, "Max depth (%d) exceeded for expression\n", maxdepth);
		rc = SEPOL_ERR;
		goto exit;
	}

	return SEPOL_OK;

exit:
	return rc;
}

int __cil_gen_expr_first_helper(struct cil_tree_node *node, __attribute__((unused))void *extra_args)
{
	int rc = SEPOL_ERR;
	struct cil_expr_args *args = extra_args;
	enum cil_flavor expr_flavor = args->flavor;
	int allow_ops = args->allow_ops;
	enum cil_flavor op_flavor;

	if (node->data == NULL) {
		if (node == node->parent->cl_head && node->parent->data == NULL) {
			goto exit;
		}
		return SEPOL_OK;
	}

	op_flavor = __cil_get_operator_flavor(node->data);

	if (!allow_ops && op_flavor != CIL_NONE) {
		cil_log(CIL_ERR, "Operators not allowed in this expression\n");
		rc = SEPOL_ERR;
		goto exit;
	}

	rc = __cil_verify_expr_operator(node->data, expr_flavor);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	rc = __cil_verify_expr_syntax(node, expr_flavor, op_flavor);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	if (op_flavor == CIL_NONE) {
		if (args->first == CIL_FALSE) {
			struct cil_list *new;
			cil_list_init(&new, expr_flavor);
			cil_list_append(args->expr, CIL_LIST, new);
			args->n++;
			args->expr_stack[args->n] = new;
			args->expr = new;
		}
		cil_list_append(args->expr, CIL_STRING, cil_strdup( node->data));
	}

	args->first = CIL_FALSE;

	return SEPOL_OK;

exit:
	return rc;
}

int __cil_gen_expr_last_helper(struct cil_tree_node *node, void *extra_args)
{
	struct cil_tree_node *first;
	struct cil_expr_args *args = extra_args;
	struct cil_list *expr = args->expr;
	enum cil_flavor expr_flavor = args->flavor;
	enum cil_flavor op_flavor;
	int *depth = &args->depth;
	int isconstraint = args->isconstraint;

	first = node->parent->cl_head;

	if (first->data == NULL) {
		return SEPOL_OK;
	}

	op_flavor = __cil_get_operator_flavor(first->data);

	if (op_flavor == CIL_NONE) {
		if (args->n > 0) {
			args->n--;
			args->expr = args->expr_stack[args->n];
		}
	} else if ((op_flavor == CIL_AND || op_flavor == CIL_OR || op_flavor == CIL_NOT) ||
		(!isconstraint && op_flavor == CIL_XOR) ||
		((expr_flavor == CIL_BOOL || expr_flavor == CIL_TUNABLE) &&
		 (op_flavor == CIL_EQ || op_flavor == CIL_NEQ))) {
		/* Constraint expressions with eq and neq are handled above. */
		enum cil_flavor *flavor;

		flavor = cil_malloc(sizeof(enum cil_flavor));
		*flavor = op_flavor;

		(*depth)--;

		cil_list_append(expr, CIL_OP, flavor);
	}

	return SEPOL_OK;
}

int cil_gen_expr(struct cil_tree_node *current, enum cil_flavor flavor, struct cil_list **expr, int allow_ops)
{
	int rc = SEPOL_ERR;
	struct cil_expr_args extra_args;
	int isconstraint;

	if (current == NULL || expr == NULL) {
		goto exit;
	}
	isconstraint = (flavor == CIL_CONSTRAIN || flavor == CIL_VALIDATETRANS || flavor == CIL_MLSCONSTRAIN || flavor == CIL_MLSVALIDATETRANS);

	cil_list_init(expr, flavor);
	if (current->cl_head == NULL) {
		if (current->data == NULL || isconstraint) {
			goto exit;
		}
		cil_list_append(*expr, CIL_STRING, cil_strdup(current->data));
	} else {
		extra_args.n = 0;
		extra_args.expr_stack[0] = *expr;
		extra_args.expr = *expr;
		extra_args.flavor = flavor;
		extra_args.depth = 0;
		extra_args.first = CIL_TRUE;
		extra_args.maxdepth = isconstraint ? CEXPR_MAXDEPTH : COND_EXPR_MAXDEPTH;
		extra_args.isconstraint = isconstraint;
		extra_args.nbools = 0;
		extra_args.allow_ops = allow_ops;
		rc = cil_tree_walk(current, __cil_gen_expr_helper, __cil_gen_expr_first_helper, __cil_gen_expr_last_helper, &extra_args);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad expression tree\n");
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
	struct cil_tree_node *cond = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	cil_boolif_init(&bif);

	rc = cil_gen_expr(parse_current->next, CIL_BOOL, &bif->str_expr, CIL_TRUE);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	cond = parse_current->next->next;

	/* Destroying expr tree after stack is created*/
	if ((strcmp(cond->cl_head->data, CIL_KEY_CONDTRUE)) &&
		(strcmp(cond->cl_head->data, CIL_KEY_CONDFALSE))) {
		rc = SEPOL_ERR;
		cil_log(CIL_ERR, "Conditional neither true nor false\n");
		goto exit;
	}

	if (cond->next != NULL) {
		cond = cond->next;
		if ((strcmp(cond->cl_head->data, CIL_KEY_CONDTRUE)) &&
			(strcmp(cond->cl_head->data, CIL_KEY_CONDFALSE))) {
			rc = SEPOL_ERR;
			cil_log(CIL_ERR, "Conditional neither true nor false\n");
			goto exit;
		}
	}


	next = parse_current->next->next;
	cil_tree_subtree_destroy(parse_current->next);
	parse_current->next = next;

	ast_node->flavor = CIL_BOOLEANIF;
	ast_node->data = bif;

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad booleanif declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_boolif(bif);
	return rc;
}

void cil_destroy_boolif(struct cil_booleanif *bif)
{
	if (bif == NULL) {
		return;
	}

	cil_list_destroy(&bif->str_expr, CIL_TRUE);

	free(bif);
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
	struct cil_tree_node *cond = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	cil_tunif_init(&tif);

	rc = cil_gen_expr(parse_current->next, CIL_TUNABLE, &tif->str_expr, CIL_TRUE);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	cond = parse_current->next->next;

	if ((strcmp(cond->cl_head->data, CIL_KEY_CONDTRUE)) &&
	    (strcmp(cond->cl_head->data, CIL_KEY_CONDFALSE))) {
		rc = SEPOL_ERR;
		cil_log(CIL_ERR, "Conditional neither true nor false\n");
		goto exit;
	}

	if (cond->next != NULL) {
		cond = cond->next;

		if ((strcmp(cond->cl_head->data, CIL_KEY_CONDTRUE)) &&
		    (strcmp(cond->cl_head->data, CIL_KEY_CONDFALSE))) {
			rc = SEPOL_ERR;
			cil_log(CIL_ERR, "Conditional neither true nor false\n");
			goto exit;
		}
	}

	/* Destroying expr tree after stack is created*/
	next = parse_current->next->next;
	cil_tree_subtree_destroy(parse_current->next);
	parse_current->next = next;

	ast_node->flavor = CIL_TUNABLEIF;
	ast_node->data = tif;

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad tunableif declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_tunif(tif);
	return rc;
}

void cil_destroy_tunif(struct cil_tunableif *tif)
{
	if (tif == NULL) {
		return;
	}

	cil_list_destroy(&tif->str_expr, CIL_TRUE);

	free(tif);
}

int cil_gen_condblock(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node, enum cil_flavor flavor)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_N_LISTS
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	int rc = SEPOL_ERR;
	struct cil_condblock *cb = NULL;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	ast_node->flavor = CIL_CONDBLOCK;

	cil_condblock_init(&cb);
	cb->flavor = flavor;

	ast_node->data = cb;

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad true condition declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_condblock(cb);
	return rc;
}

void cil_destroy_condblock(struct cil_condblock *cb)
{
	if (cb == NULL) {
		return;
	}

	cil_symtab_array_destroy(cb->symtab);
	free(cb);
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
		goto exit;
	}

	if (!strcmp(parse_current->next->data, CIL_KEY_SELF)) {
		cil_log(CIL_ERR, "The keyword '%s' is reserved\n", CIL_KEY_SELF);
		rc = SEPOL_ERR;
		goto exit;
	}

	cil_typealias_init(&alias);

	key = parse_current->next->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)alias, (hashtab_key_t)key, CIL_SYM_TYPES, CIL_TYPEALIAS);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	alias->type_str = cil_strdup(parse_current->next->data);

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad typealias declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_typealias(alias);
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

int cil_gen_typeattributeset(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_STRING | SYM_LIST,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	struct cil_typeattributeset *attrset = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	cil_typeattributeset_init(&attrset);

	attrset->attr_str = cil_strdup(parse_current->next->data);

	rc = cil_gen_expr(parse_current->next->next, CIL_TYPE, &attrset->str_expr, CIL_TRUE);
	if (rc != SEPOL_OK) {
		goto exit;
	}
	ast_node->data = attrset;
	ast_node->flavor = CIL_TYPEATTRIBUTESET;

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad typeattributeset statement at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_typeattributeset(attrset);
	return rc;
}

void cil_destroy_typeattributeset(struct cil_typeattributeset *attrset)
{
	if (attrset == NULL) {
		return;
	}

	cil_list_destroy(&attrset->str_expr, CIL_TRUE);

	if (attrset->attr_str != NULL) {
		free(attrset->attr_str);
	}

	free(attrset);
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
		goto exit;
	}

	cil_typebounds_init(&typebnds);

	typebnds->type_str = cil_strdup(parse_current->next->data);
	typebnds->bounds_str = cil_strdup(parse_current->next->next->data);

	ast_node->data = typebnds;
	ast_node->flavor = CIL_TYPEBOUNDS;

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad typebounds declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_typebounds(typebnds);
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
		goto exit;
	}

	cil_typepermissive_init(&typeperm);

	typeperm->type_str = cil_strdup(parse_current->next->data);

	ast_node->data = typeperm;
	ast_node->flavor = CIL_TYPEPERMISSIVE;

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad typepermissive declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_typepermissive(typeperm);
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

int cil_gen_nametypetransition(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
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
	struct cil_nametypetransition *nametypetrans = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL ) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	cil_nametypetransition_init(&nametypetrans);

	nametypetrans->path_str = cil_strdup(parse_current->next->data);
	nametypetrans->src_str = cil_strdup(parse_current->next->next->data);
	nametypetrans->exec_str = cil_strdup(parse_current->next->next->next->data);
	nametypetrans->proc_str = cil_strdup(parse_current->next->next->next->next->data);
	nametypetrans->dest_str = cil_strdup(parse_current->next->next->next->next->next->data);

	ast_node->data = nametypetrans;
	ast_node->flavor = CIL_NAMETYPETRANSITION;

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad nametypetransition declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_nametypetransition(nametypetrans);
	return rc;
}

void cil_destroy_nametypetransition(struct cil_nametypetransition *nametypetrans)
{
	if (nametypetrans == NULL) {
		return;
	}

	if (nametypetrans->src_str != NULL) {
		free(nametypetrans->src_str);
	}
	if (nametypetrans->exec_str != NULL) {
		free(nametypetrans->exec_str);
	}
	if (nametypetrans->proc_str != NULL) {
		free(nametypetrans->proc_str);
	}
	if (nametypetrans->dest_str != NULL) {
		free(nametypetrans->dest_str);
	}
	if (nametypetrans->path_str != NULL) {
		free(nametypetrans->path_str);
	}

	free(nametypetrans);
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
		goto exit;
	}

	cil_rangetransition_init(&rangetrans);

	rangetrans->src_str = cil_strdup(parse_current->next->data);
	rangetrans->exec_str = cil_strdup(parse_current->next->next->data);
	rangetrans->obj_str = cil_strdup(parse_current->next->next->next->data);

	rangetrans->range_str = NULL;

	if (parse_current->next->next->next->next->cl_head == NULL) {
		rangetrans->range_str = cil_strdup(parse_current->next->next->next->next->data);
	} else {
		cil_levelrange_init(&rangetrans->range);

		rc = cil_fill_levelrange(parse_current->next->next->next->next->cl_head, rangetrans->range);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	ast_node->data = rangetrans;
	ast_node->flavor = CIL_RANGETRANSITION;

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad rangetransition declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_rangetransition(rangetrans);
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
	} else if (rangetrans->range != NULL) {
		cil_destroy_levelrange(rangetrans->range);
	}

	free(rangetrans);
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
		goto exit;
	}

	cil_sens_init(&sens);

	key = parse_current->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)sens, (hashtab_key_t)key, CIL_SYM_SENS, CIL_SENS);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad sensitivity declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_sensitivity(sens);
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
		goto exit;
	}

	cil_sensalias_init(&alias);

	key = parse_current->next->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)alias, (hashtab_key_t)key, CIL_SYM_SENS, CIL_SENSALIAS);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	alias->sens_str = cil_strdup(parse_current->next->data);

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad sensitivityalias declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_sensalias(alias);
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
		goto exit;
	}

	cil_cat_init(&cat);

	key = parse_current->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)cat, (hashtab_key_t)key, CIL_SYM_CATS, CIL_CAT);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad category declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_category(cat);
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
		goto exit;
	}

	cil_catalias_init(&alias);

	key = parse_current->next->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)alias, (hashtab_key_t)key, CIL_SYM_CATS, CIL_CATALIAS);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	alias->cat_str = cil_strdup(parse_current->next->data);

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad categoryalias declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_catalias(alias);
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

int cil_set_to_list(struct cil_tree_node *parse_current, struct cil_list *ast_cl)
{
	int rc = SEPOL_ERR;
	struct cil_tree_node *curr = parse_current;
	enum cil_syntax syntax[] = {
		SYM_N_STRINGS,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
 
	rc = __cil_verify_syntax(parse_current->cl_head, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		goto exit;
 	}

	for (curr = curr->cl_head; curr != NULL; curr = curr->next) {
		cil_list_append(ast_cl, CIL_STRING, cil_strdup(curr->data));
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
		goto exit;
	}

	cil_catrange_init(&catrange);

	key = parse_current->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)catrange, (hashtab_key_t)key, CIL_SYM_CATS, CIL_CATRANGE);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	rc = cil_fill_catrange(parse_current->next->next->cl_head, catrange);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad categoryrange declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_catrange(catrange);
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
		goto exit;
	}

	cil_catset_init(&catset);

	key = parse_current->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)catset, (hashtab_key_t)key, CIL_SYM_CATS, CIL_CATSET);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	rc = cil_fill_catset(parse_current->next->next->cl_head, catset);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad categoryset declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_catset(catset);
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
		goto exit;
	}

	cil_catorder_init(&catorder);

	cil_list_init(&catorder->cat_list_str, CIL_LIST_ITEM);

	rc = cil_set_to_list(parse_current->next, catorder->cat_list_str);
	if (rc != SEPOL_OK) {
		goto exit;
	}
	ast_node->data = catorder;
	ast_node->flavor = CIL_CATORDER;

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad categoryorder declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_catorder(catorder);
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
		goto exit;
	}

	cil_sens_dominates_init(&dom);

	cil_list_init(&dom->sens_list_str, CIL_LIST_ITEM);

	rc = cil_set_to_list(parse_current->next, dom->sens_list_str);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	ast_node->data = dom;
	ast_node->flavor = CIL_DOMINANCE;

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad dominance declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_dominance(dom);
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
		goto exit;
	}

	cil_senscat_init(&senscat);

	senscat->sens_str = cil_strdup(parse_current->next->data);

	if (parse_current->next->next->cl_head == NULL) {
		senscat->catset_str = cil_strdup(parse_current->next->next->data);
	} else {
		cil_catset_init(&senscat->catset);

		rc = cil_fill_catset(parse_current->next->next->cl_head, senscat->catset);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	ast_node->data = senscat;
	ast_node->flavor = CIL_SENSCAT;

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad sensitivitycategory declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_senscat(senscat);
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
		goto exit;
	}

	cil_level_init(&level);

	key = parse_current->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)level, (hashtab_key_t)key, CIL_SYM_LEVELS, CIL_LEVEL);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	rc = cil_fill_level(parse_current->next->next->cl_head, level);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad level declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_level(level);
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

		goto exit;
	}

	if (low->cl_head == NULL) {
		lvlrange->low_str = cil_strdup(low->data);
	} else {
		cil_level_init(&lvlrange->low);

		rc = cil_fill_level(low->cl_head, lvlrange->low);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	if (low->next->cl_head == NULL) {
		lvlrange->high_str = cil_strdup(low->next->data);
	} else {
		cil_level_init(&lvlrange->high);

		rc = cil_fill_level(low->next->cl_head, lvlrange->high);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad levelrange\n");
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
		goto exit;
	}

	cil_levelrange_init(&lvlrange);

	key = parse_current->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)lvlrange, (hashtab_key_t)key, CIL_SYM_LEVELRANGES, CIL_LEVELRANGE);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	rc = cil_fill_levelrange(parse_current->next->next->cl_head, lvlrange);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad levelrange declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_levelrange(lvlrange);
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
		SYM_STRING | SYM_LIST,
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
		goto exit;
	}

	cil_constrain_init(&cons);

	rc = cil_fill_classperms(parse_current->next, &cons->classperms, CIL_TRUE, CIL_FALSE);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	rc = cil_gen_expr(parse_current->next->next, flavor, &cons->str_expr, CIL_TRUE);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	ast_node->data = cons;
	ast_node->flavor = flavor;

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad constrain declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_constrain(cons);
	return rc;
}

void cil_destroy_constrain(struct cil_constrain *cons)
{
	if (cons == NULL) {
		return;
	}

	cil_destroy_classperms(cons->classperms);

	cil_list_destroy(&cons->str_expr, CIL_TRUE);

	free(cons);
}

int cil_gen_validatetrans(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node, enum cil_flavor flavor)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_LIST,
		SYM_END
	};
	int syntax_len = sizeof(syntax)/sizeof(*syntax);
	struct cil_validatetrans *validtrans = NULL;
	int rc = SEPOL_ERR;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	cil_validatetrans_init(&validtrans);

	validtrans->class_str = cil_strdup(parse_current->next->data);

	rc = cil_gen_expr(parse_current->next->next, flavor, &validtrans->str_expr, CIL_TRUE);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	ast_node->data = validtrans;
	ast_node->flavor = flavor;

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad validatetrans declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_validatetrans(validtrans);
	return rc;


}

void cil_destroy_validatetrans(struct cil_validatetrans *validtrans)
{
	if (validtrans == NULL) {
		return;
	}

	free(validtrans->class_str);

	cil_list_destroy(&validtrans->str_expr, CIL_TRUE);

	free(validtrans);
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
		goto exit;
	}

	context->user_str = cil_strdup(user_node->data);
	context->role_str = cil_strdup(user_node->next->data);
	context->type_str = cil_strdup(user_node->next->next->data);

	context->range_str = NULL;

	if (user_node->next->next->next->cl_head == NULL) {
		context->range_str = cil_strdup(user_node->next->next->next->data);
	} else {
		cil_levelrange_init(&context->range);

		rc = cil_fill_levelrange(user_node->next->next->next->cl_head, context->range);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad context\n");
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
		goto exit;
	}

	cil_context_init(&context);

	key = parse_current->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)context, (hashtab_key_t)key, CIL_SYM_CONTEXTS, CIL_CONTEXT);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	rc = cil_fill_context(parse_current->next->next->cl_head, context);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad context declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_context(context);
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

	free(context);
}

int cil_gen_filecon(struct cil_db *db, struct cil_tree_node *parse_current, struct cil_tree_node *ast_node)
{
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_STRING,
		SYM_STRING,
		SYM_STRING | SYM_LIST | SYM_EMPTY_LIST,
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
		goto exit;
	}

	type = parse_current->next->next->next->data;
	cil_filecon_init(&filecon);

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
		cil_log(CIL_ERR, "Invalid file type\n");
		rc = SEPOL_ERR;
		goto exit;
	}

	if (parse_current->next->next->next->next->cl_head == NULL) {
		filecon->context_str = cil_strdup(parse_current->next->next->next->next->data);
	} else {
		if (parse_current->next->next->next->next->cl_head->next == NULL) {
			filecon->context = NULL;
		} else {
			cil_context_init(&filecon->context);

			rc = cil_fill_context(parse_current->next->next->next->next->cl_head, filecon->context);
			if (rc != SEPOL_OK) {
				goto exit;
			}
		}
	}

	ast_node->data = filecon;
	ast_node->flavor = CIL_FILECON;

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad filecon declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_filecon(filecon);
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
	char *proto;

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc = __cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	cil_portcon_init(&portcon);

	proto = parse_current->next->data;
	if (!strcmp(proto, CIL_KEY_UDP)) {
		portcon->proto = CIL_PROTOCOL_UDP;
	} else if (!strcmp(proto, CIL_KEY_TCP)) {
		portcon->proto = CIL_PROTOCOL_TCP;
	} else {
		cil_log(CIL_ERR, "Invalid protocol\n");
		rc = SEPOL_ERR;
		goto exit;
	}

	if (parse_current->next->next->cl_head != NULL) {
		if (parse_current->next->next->cl_head->next != NULL
		&& parse_current->next->next->cl_head->next->next == NULL) {
			rc = cil_fill_integer(parse_current->next->next->cl_head, &portcon->port_low);
			if (rc != SEPOL_OK) {
				cil_log(CIL_ERR, "Improper port specified\n");
				goto exit;
			}
			rc = cil_fill_integer(parse_current->next->next->cl_head->next, &portcon->port_high);
			if (rc != SEPOL_OK) {
				cil_log(CIL_ERR, "Improper port specified\n");
				goto exit;
			}
		} else {
			cil_log(CIL_ERR, "Improper port range specified\n");
			rc = SEPOL_ERR;
			goto exit;
		}
	} else {
		rc = cil_fill_integer(parse_current->next->next, &portcon->port_low);
		if (rc != SEPOL_OK) {
			cil_log(CIL_ERR, "Improper port specified\n");
			goto exit;
		}
		portcon->port_high = portcon->port_low;
	}

	if (parse_current->next->next->next->cl_head == NULL ) {
		portcon->context_str = cil_strdup(parse_current->next->next->next->data);
	} else {
		cil_context_init(&portcon->context);

		rc = cil_fill_context(parse_current->next->next->next->cl_head, portcon->context);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	ast_node->data = portcon;
	ast_node->flavor = CIL_PORTCON;

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad portcon declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_portcon(portcon);
	return rc;
}

void cil_destroy_portcon(struct cil_portcon *portcon)
{
	if (portcon == NULL) {
		return;
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
		goto exit;
	}

	cil_nodecon_init(&nodecon);

	if (parse_current->next->cl_head == NULL ) {
		nodecon->addr_str = cil_strdup(parse_current->next->data);
	} else {
		cil_ipaddr_init(&nodecon->addr);

		rc = cil_fill_ipaddr(parse_current->next->cl_head, nodecon->addr);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	if (parse_current->next->next->cl_head == NULL ) {
		nodecon->mask_str = cil_strdup(parse_current->next->next->data);
	} else {
		cil_ipaddr_init(&nodecon->mask);

		rc = cil_fill_ipaddr(parse_current->next->next->cl_head, nodecon->mask);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	if (parse_current->next->next->next->cl_head == NULL ) {
		nodecon->context_str = cil_strdup(parse_current->next->next->next->data);
	} else {
		cil_context_init(&nodecon->context);

		rc = cil_fill_context(parse_current->next->next->next->cl_head, nodecon->context);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	ast_node->data = nodecon;
	ast_node->flavor = CIL_NODECON;

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad nodecon declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_nodecon(nodecon);
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
		goto exit;
	}

	cil_genfscon_init(&genfscon);

	genfscon->fs_str = cil_strdup(parse_current->next->data);
	genfscon->path_str = cil_strdup(parse_current->next->next->data);

	if (parse_current->next->next->next->cl_head == NULL ) {
		genfscon->context_str = cil_strdup(parse_current->next->next->next->data);
	} else {
		cil_context_init(&genfscon->context);

		rc = cil_fill_context(parse_current->next->next->next->cl_head, genfscon->context);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	ast_node->data = genfscon;
	ast_node->flavor = CIL_GENFSCON;

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad genfscon declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_genfscon(genfscon);
	return SEPOL_ERR;
}

void cil_destroy_genfscon(struct cil_genfscon *genfscon)
{
	if (genfscon == NULL) {
		return;
	}

	if (genfscon->fs_str != NULL) {
		free(genfscon->fs_str);
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
		goto exit;
	}

	cil_netifcon_init(&netifcon);

	netifcon->interface_str = cil_strdup(parse_current->next->data);

	if (parse_current->next->next->cl_head == NULL) {
		netifcon->if_context_str = cil_strdup(parse_current->next->next->data);
	} else {
		cil_context_init(&netifcon->if_context);

		rc = cil_fill_context(parse_current->next->next->cl_head, netifcon->if_context);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	if (parse_current->next->next->next->cl_head == NULL) {
		netifcon->packet_context_str = cil_strdup(parse_current->next->next->next->data);
	} else {
		cil_context_init(&netifcon->packet_context);

		rc = cil_fill_context(parse_current->next->next->next->cl_head, netifcon->packet_context);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	ast_node->data = netifcon;
	ast_node->flavor = CIL_NETIFCON;

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad netifcon declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_netifcon(netifcon);
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
		goto exit;
	}

	cil_pirqcon_init(&pirqcon);

	rc = cil_fill_integer(parse_current->next, &pirqcon->pirq);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	if (parse_current->next->next->cl_head == NULL) {
		pirqcon->context_str = cil_strdup(parse_current->next->next->data);
	} else {
		cil_context_init(&pirqcon->context);

		rc = cil_fill_context(parse_current->next->next->cl_head, pirqcon->context);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	ast_node->data = pirqcon;
	ast_node->flavor = CIL_PIRQCON;

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad pirqcon declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_pirqcon(pirqcon);
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
		goto exit;
	}

	cil_iomemcon_init(&iomemcon);

	if (parse_current->next->cl_head != NULL) {
		if (parse_current->next->cl_head->next != NULL &&
		    parse_current->next->cl_head->next->next == NULL) {
			rc = cil_fill_integer(parse_current->next->cl_head, &iomemcon->iomem_low);
			if (rc != SEPOL_OK) {
				cil_log(CIL_ERR, "Improper iomem specified\n");
				goto exit;
			}
			rc = cil_fill_integer(parse_current->next->cl_head->next, &iomemcon->iomem_high);
			if (rc != SEPOL_OK) {
				cil_log(CIL_ERR, "Improper iomem specified\n");
				goto exit;
			}
		} else {
			cil_log(CIL_ERR, "Improper iomem range specified\n");
			rc = SEPOL_ERR;
			goto exit;
		}
	} else {
		rc = cil_fill_integer(parse_current->next, &iomemcon->iomem_low);;
		if (rc != SEPOL_OK) {
			cil_log(CIL_ERR, "Improper iomem specified\n");
			goto exit;
		}
		iomemcon->iomem_high = iomemcon->iomem_low;
	}

	if (parse_current->next->next->cl_head == NULL ) {
		iomemcon->context_str = cil_strdup(parse_current->next->next->data);
	} else {
		cil_context_init(&iomemcon->context);

		rc = cil_fill_context(parse_current->next->next->cl_head, iomemcon->context);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	ast_node->data = iomemcon;
	ast_node->flavor = CIL_IOMEMCON;

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad iomemcon declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_iomemcon(iomemcon);
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
		goto exit;
	}

	cil_ioportcon_init(&ioportcon);

	if (parse_current->next->cl_head != NULL) {
		if (parse_current->next->cl_head->next != NULL &&
		    parse_current->next->cl_head->next->next == NULL) {
			rc = cil_fill_integer(parse_current->next->cl_head, &ioportcon->ioport_low);
			if (rc != SEPOL_OK) {
				cil_log(CIL_ERR, "Improper ioport specified\n");
				goto exit;
			}
			rc = cil_fill_integer(parse_current->next->cl_head->next, &ioportcon->ioport_high);
			if (rc != SEPOL_OK) {
				cil_log(CIL_ERR, "Improper ioport specified\n");
				goto exit;
			}
		} else {
			cil_log(CIL_ERR, "Improper ioport range specified\n");
			rc = SEPOL_ERR;
			goto exit;
		}
	} else {
		rc = cil_fill_integer(parse_current->next, &ioportcon->ioport_low);
		if (rc != SEPOL_OK) {
			cil_log(CIL_ERR, "Improper ioport specified\n");
			goto exit;
		}
		ioportcon->ioport_high = ioportcon->ioport_low;
	}

	if (parse_current->next->next->cl_head == NULL ) {
		ioportcon->context_str = cil_strdup(parse_current->next->next->data);
	} else {
		cil_context_init(&ioportcon->context);

		rc = cil_fill_context(parse_current->next->next->cl_head, ioportcon->context);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	ast_node->data = ioportcon;
	ast_node->flavor = CIL_IOPORTCON;

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad ioportcon declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_ioportcon(ioportcon);
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
		goto exit;
	}

	cil_pcidevicecon_init(&pcidevicecon);

	rc = cil_fill_integer(parse_current->next, &pcidevicecon->dev);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	if (parse_current->next->next->cl_head == NULL) {
		pcidevicecon->context_str = cil_strdup(parse_current->next->next->data);
	} else {
		cil_context_init(&pcidevicecon->context);

		rc = cil_fill_context(parse_current->next->next->cl_head, pcidevicecon->context);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	ast_node->data = pcidevicecon;
	ast_node->flavor = CIL_PCIDEVICECON;

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad pcidevicecon declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_pcidevicecon(pcidevicecon);
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
		goto exit;
	}

	type = parse_current->next->data;

	cil_fsuse_init(&fsuse);

	if (!strcmp(type, "xattr")) {
		fsuse->type = CIL_FSUSE_XATTR;
	} else if (!strcmp(type, "task")) {
		fsuse->type = CIL_FSUSE_TASK;
	} else if (!strcmp(type, "trans")) {
		fsuse->type = CIL_FSUSE_TRANS;
	} else {
		cil_log(CIL_ERR, "Invalid fsuse type\n");
		goto exit;
	}

	fsuse->fs_str = cil_strdup(parse_current->next->next->data);

	if (parse_current->next->next->next->cl_head == NULL) {
		fsuse->context_str = cil_strdup(parse_current->next->next->next->data);
	} else {
		cil_context_init(&fsuse->context);

		rc = cil_fill_context(parse_current->next->next->next->cl_head, fsuse->context);
		if (rc != SEPOL_OK) {
			goto exit;
		}
	}

	ast_node->data = fsuse;
	ast_node->flavor = CIL_FSUSE;

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad fsuse declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_fsuse(fsuse);
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
	int rc = SEPOL_ERR;
	char *key = NULL;
	struct cil_macro *macro = NULL;
	struct cil_tree_node *macro_content = NULL;
	enum cil_syntax syntax[] = {
		SYM_STRING,
		SYM_STRING,
		SYM_LIST | SYM_EMPTY_LIST,
		SYM_N_LISTS | SYM_END,
	};
	int syntax_len = sizeof(syntax)/ sizeof(*syntax);

	if (db == NULL || parse_current == NULL || ast_node == NULL) {
		goto exit;
	}

	rc =__cil_verify_syntax(parse_current, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	cil_macro_init(&macro);

	key = parse_current->next->data;

	struct cil_tree_node *current_item = parse_current->next->next->cl_head;
	while (current_item != NULL) {
		enum cil_syntax param_syntax[] = {
			SYM_STRING,
			SYM_STRING,
			SYM_END
		};
		int param_syntax_len = sizeof(param_syntax)/sizeof(*param_syntax);
		char *kind = NULL;
		struct cil_param *param = NULL;

		rc =__cil_verify_syntax(current_item->cl_head, param_syntax, param_syntax_len);
		if (rc != SEPOL_OK) {
			goto exit;
		}

		if (macro->params == NULL) {
			cil_list_init(&macro->params, CIL_LIST_ITEM);
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
		} else if (!strcmp(kind, CIL_KEY_MAP_CLASS)) {
			param->flavor = CIL_MAP_CLASS;
		} else if (!strcmp(kind, CIL_KEY_CLASSPERMSET)) {
			param->flavor = CIL_CLASSPERMSET;
		} else if (!strcmp(kind, CIL_KEY_BOOL)) {
			param->flavor = CIL_BOOL;
		} else {
			cil_log(CIL_ERR, "The kind %s is not allowed as a parameter\n",kind);
			cil_destroy_param(param);
			goto exit;
		}

		param->str =  cil_strdup(current_item->cl_head->next->data);

		rc = __cil_verify_name(param->str);
		if (rc != SEPOL_OK) {
			cil_destroy_param(param);
			goto exit;
		}

		//walk current list and check for duplicate parameters
		struct cil_list_item *curr_param;
		cil_list_for_each(curr_param, macro->params) {
			if (!strcmp(param->str, ((struct cil_param*)curr_param->data)->str)) {
				if (param->flavor == ((struct cil_param*)curr_param->data)->flavor) {
					cil_log(CIL_ERR, "Duplicate parameter\n");
					cil_destroy_param(param);
					goto exit;
				}
			}
		}

		cil_list_append(macro->params, CIL_PARAM, param);

		current_item = current_item->next;
	}

	/* we don't want the tree walker to walk the macro parameters (they were just handled above), so the subtree is deleted, and the next pointer of the
           node containing the macro name is updated to point to the start of the macro content */
	macro_content = parse_current->next->next->next;
	cil_tree_subtree_destroy(parse_current->next->next);
	parse_current->next->next = macro_content;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)macro, (hashtab_key_t)key, CIL_SYM_BLOCKS, CIL_MACRO);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad macro declaration at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_macro(macro);
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
		goto exit;
	}

	cil_call_init(&call);

	call->macro_str = cil_strdup(parse_current->next->data);

	if (parse_current->next->next != NULL) {
		cil_tree_init(&call->args_tree);
		cil_copy_ast(db, parse_current->next->next, call->args_tree->root);
	}

	ast_node->data = call;
	ast_node->flavor = CIL_CALL;

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad macro call at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_call(call);
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
		if (args->arg != NULL && args->arg->nodes != NULL && args->arg->nodes->head != NULL) {
			switch (args->arg->nodes->head->flavor) {
			struct cil_tree_node *node = args->arg->nodes->head->data;
			case CIL_LEVEL:
				cil_tree_node_destroy(&node);
				args->arg = NULL;
				break;
			case CIL_CATSET:
				cil_tree_node_destroy(&node);
				args->arg = NULL;
				break;
			case CIL_IPADDR:
				cil_tree_node_destroy(&node);
				args->arg = NULL;
				break;
			}
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
		SYM_N_LISTS | SYM_END
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
		goto exit;
	}

	cil_optional_init(&optional);

	key = parse_current->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)optional, (hashtab_key_t)key, CIL_SYM_BLOCKS, CIL_OPTIONAL);
	if (rc != SEPOL_OK)
		goto exit;

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad optional at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_optional(optional);
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
		goto exit;
	}

	cil_policycap_init(&polcap);

	key = parse_current->next->data;

	rc = cil_gen_node(db, ast_node, (struct cil_symtab_datum*)polcap, (hashtab_key_t)key, CIL_SYM_POLICYCAPS, CIL_POLICYCAP);
	if (rc != SEPOL_OK)
		goto exit;

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad policycap statement at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_policycap(polcap);
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
		goto exit;
	}

	cil_ipaddr_init(&ipaddr);

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
	cil_log(CIL_ERR, "Bad ipaddr statement at line %d of %s\n", 
		parse_current->line, parse_current->path);
	cil_destroy_ipaddr(ipaddr);
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
	cil_log(CIL_ERR, "Failed to create integer from string\n");
	return rc;
}

int cil_fill_ipaddr(struct cil_tree_node *addr_node, struct cil_ipaddr *addr)
{
	int rc = SEPOL_ERR;

	if (addr_node == NULL || addr == NULL) {
		goto exit;
	}

	if (addr_node->cl_head != NULL ||  addr_node->next != NULL) {
		goto exit;
	}

	if (strchr(addr_node->data, '.') != NULL) {
		addr->family = AF_INET;
	} else {
		addr->family = AF_INET6;
	}

	rc = inet_pton(addr->family, addr_node->data, &addr->ip);
	if (rc != 1) {
		rc = SEPOL_ERR;
		goto exit;
	}

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad ip address or netmask\n"); 
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
		goto exit;
	}

	level->sens_str = cil_strdup(sens->data);

	if (sens->next != NULL) {
		if (sens->next->cl_head == NULL) {
			level->catset_str = cil_strdup(sens->next->data);
		} else {
			cil_catset_init(&level->catset);

			rc = cil_fill_catset(sens->next->cl_head, level->catset);
			if (rc != SEPOL_OK) {
				goto exit;
			}
		}
	}

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad level");
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
		goto exit;
	}

	catrange->cat_low_str = cil_strdup(cats->data);
	catrange->cat_high_str = cil_strdup(cats->next->data);

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad categoryrange\n");
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
	struct cil_catrange *catrange = NULL;
	int rc = SEPOL_ERR;

	if (cats == NULL || catset == NULL) {
		rc = SEPOL_ERR;
		goto exit;
	}

	rc = __cil_verify_syntax(cats, syntax, syntax_len);
	if (rc != SEPOL_OK) {
		goto exit;
	}

	cil_list_init(&cat_list, CIL_LIST_ITEM);

	for (curr = cats; curr != NULL; curr = curr->next) {
		if (curr->data != NULL) {
			/* named category or categoryrange */
			cil_list_append(cat_list, CIL_STRING, cil_strdup(curr->data));
		} else {
			/* anonymous category range */
			cil_catrange_init(&catrange);

			rc = cil_fill_catrange(curr->cl_head, catrange);
			if (rc != SEPOL_OK) {
				goto exit;
			}

			cil_list_append(cat_list, CIL_CATRANGE, catrange);
		}
	}

	catset->cat_list_str = cat_list;

	return SEPOL_OK;

exit:
	cil_log(CIL_ERR, "Bad category set\n");
	return rc;
}

int __cil_build_ast_node_helper(struct cil_tree_node *parse_current, uint32_t *finished, void *extra_args)
{
	struct cil_args_build *args = NULL;
	struct cil_tree_node *ast_current = NULL;
	struct cil_db *db = NULL;
	struct cil_tree_node *ast_node = NULL;
	struct cil_tree_node *macro = NULL;
	struct cil_tree_node *tifstack = NULL;
	int rc = SEPOL_ERR;

	if (parse_current == NULL || finished == NULL || extra_args == NULL) {
		goto exit;
	}

	args = extra_args;
	ast_current = args->ast;
	db = args->db;
	macro = args->macro;
	tifstack = args->tifstack;

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
			cil_log(CIL_ERR, "Keyword expected after open parenthesis in line %d of %s\n", parse_current->line, parse_current->path);
		}
		goto exit;
	}

	if (macro != NULL) {
		if (!strcmp(parse_current->data, CIL_KEY_MACRO)) {
			rc = SEPOL_ERR;
			cil_log(CIL_ERR, "Found macro at line %d of %s\n",
				parse_current->line, parse_current->path);
			cil_log(CIL_ERR, "Macros cannot be defined within macro statement\n");
			goto exit;
		}

		if (!strcmp(parse_current->data, CIL_KEY_TUNABLE)) {
			rc = SEPOL_ERR;
			cil_log(CIL_ERR, "Found tunable at line %d of %s\n",
				parse_current->line, parse_current->path);
			cil_log(CIL_ERR, "Tunables cannot be defined within macro statment\n");
			goto exit;
		}
	}

	if (tifstack != NULL) {
		if (!strcmp(parse_current->data, CIL_KEY_TUNABLE)) {
			rc = SEPOL_ERR;
			cil_log(CIL_ERR, "Found tunable at line %d of %s\n",
				parse_current->line, parse_current->path);
			cil_log(CIL_ERR, "Tunables cannot be defined within tunableif statement\n");
			goto exit;
		}
	}

	cil_tree_node_init(&ast_node);

	ast_node->parent = ast_current;
	ast_node->line = parse_current->line;
	ast_node->path = parse_current->path;
	if (ast_current->cl_head == NULL) {

		if (ast_current->flavor == CIL_MACRO) {
			args->macro = ast_current;
		}

		if (ast_current->flavor == CIL_TUNABLEIF) {
			struct cil_tree_node *new;
			cil_tree_node_init(&new);
			new->data = ast_current->data;
			new->flavor = ast_current->flavor;
			if (args->tifstack != NULL) {
				args->tifstack->parent = new;
				new->cl_head = args->tifstack;
			}
			args->tifstack = new;
		}
		
		ast_current->cl_head = ast_node;
	} else {
		ast_current->cl_tail->next = ast_node;
	}
	ast_current->cl_tail = ast_node;
	ast_current = ast_node;
	args->ast = ast_current;

	if (!strcmp(parse_current->data, CIL_KEY_BLOCK)) {
		rc = cil_gen_block(db, parse_current, ast_node, 0);
	} else if (!strcmp(parse_current->data, CIL_KEY_BLOCKINHERIT)) {
		rc = cil_gen_blockinherit(db, parse_current, ast_node);
	} else if (!strcmp(parse_current->data, CIL_KEY_BLOCKABSTRACT)) {
		rc = cil_gen_blockabstract(db, parse_current, ast_node);
	} else if (!strcmp(parse_current->data, CIL_KEY_IN)) {
		rc = cil_gen_in(db, parse_current, ast_node);
	} else if (!strcmp(parse_current->data, CIL_KEY_CLASS)) {
		rc = cil_gen_class(db, parse_current, ast_node);
		// To avoid parsing list of perms again
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_CLASSMAP)) {
		rc = cil_gen_map_class(db, parse_current, ast_node);
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_CLASSMAPPING)) {
		rc = cil_gen_classmapping(db, parse_current, ast_node);
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_CLASSPERMSET)) {
		rc = cil_gen_classpermset(db, parse_current, ast_node);
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_COMMON)) {
		rc = cil_gen_common(db, parse_current, ast_node);
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_CLASSCOMMON)) {
		rc = cil_gen_classcommon(db, parse_current, ast_node);
	} else if (!strcmp(parse_current->data, CIL_KEY_SID)) {
		rc = cil_gen_sid(db, parse_current, ast_node);
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_SIDCONTEXT)) {
		rc = cil_gen_sidcontext(db, parse_current, ast_node);
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_USER)) {
		rc = cil_gen_user(db, parse_current, ast_node);
	} else if (!strcmp(parse_current->data, CIL_KEY_USERLEVEL)) {
		rc = cil_gen_userlevel(db, parse_current, ast_node);
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_USERRANGE)) {
		rc = cil_gen_userrange(db, parse_current, ast_node);
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_USERBOUNDS)) {
		rc = cil_gen_userbounds(db, parse_current, ast_node);
	} else if (!strcmp(parse_current->data, CIL_KEY_USERPREFIX)) {
		rc = cil_gen_userprefix(db, parse_current, ast_node);
	} else if (!strcmp(parse_current->data, CIL_KEY_SELINUXUSER)) {
		rc = cil_gen_selinuxuser(db, parse_current, ast_node);
	} else if (!strcmp(parse_current->data, CIL_KEY_SELINUXUSERDEFAULT)) {
		rc = cil_gen_selinuxuserdefault(db, parse_current, ast_node);
	} else if (!strcmp(parse_current->data, CIL_KEY_TYPE)) {
		rc = cil_gen_type(db, parse_current, ast_node);
	} else if (!strcmp(parse_current->data, CIL_KEY_TYPEATTRIBUTE)) {
		rc = cil_gen_typeattribute(db, parse_current, ast_node);
	} else if (!strcmp(parse_current->data, CIL_KEY_TYPEATTRIBUTESET)) {
		rc = cil_gen_typeattributeset(db, parse_current, ast_node);
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_TYPEALIAS)) {
		rc = cil_gen_typealias(db, parse_current, ast_node);
	} else if (!strcmp(parse_current->data, CIL_KEY_TYPEBOUNDS)) {
		rc = cil_gen_typebounds(db, parse_current, ast_node);
	} else if (!strcmp(parse_current->data, CIL_KEY_TYPEPERMISSIVE)) {
		rc = cil_gen_typepermissive(db, parse_current, ast_node);
	} else if (!strcmp(parse_current->data, CIL_KEY_NAMETYPETRANSITION)) {
		rc = cil_gen_nametypetransition(db, parse_current, ast_node);
	} else if (!strcmp(parse_current->data, CIL_KEY_RANGETRANSITION)) {
		rc = cil_gen_rangetransition(db, parse_current, ast_node);
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_ROLE)) {
		rc = cil_gen_role(db, parse_current, ast_node);
	} else if (!strcmp(parse_current->data, CIL_KEY_USERROLE)) {
		rc = cil_gen_userrole(db, parse_current, ast_node);
	} else if (!strcmp(parse_current->data, CIL_KEY_ROLETYPE)) {
		rc = cil_gen_roletype(db, parse_current, ast_node);
	} else if (!strcmp(parse_current->data, CIL_KEY_ROLETRANSITION)) {
		rc = cil_gen_roletransition(parse_current, ast_node);
	} else if (!strcmp(parse_current->data, CIL_KEY_ROLEALLOW)) {
		rc = cil_gen_roleallow(db, parse_current, ast_node);
	} else if (!strcmp(parse_current->data, CIL_KEY_ROLEATTRIBUTE)) {
		rc = cil_gen_roleattribute(db, parse_current, ast_node);
	} else if (!strcmp(parse_current->data, CIL_KEY_ROLEATTRIBUTESET)) {
		rc = cil_gen_roleattributeset(db, parse_current, ast_node);
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_ROLEBOUNDS)) {
		rc = cil_gen_rolebounds(db, parse_current, ast_node);
	} else if (!strcmp(parse_current->data, CIL_KEY_BOOL)) {
		rc = cil_gen_bool(db, parse_current, ast_node, CIL_BOOL);
	} else if (!strcmp(parse_current->data, CIL_KEY_BOOLEANIF)) {
		rc = cil_gen_boolif(db, parse_current, ast_node);
	} else if(!strcmp(parse_current->data, CIL_KEY_TUNABLE)) {
		rc = cil_gen_bool(db, parse_current, ast_node, CIL_TUNABLE);
	} else if (!strcmp(parse_current->data, CIL_KEY_TUNABLEIF)) {
		rc = cil_gen_tunif(db, parse_current, ast_node);
	} else if (!strcmp(parse_current->data, CIL_KEY_CONDTRUE)) {
		rc = cil_gen_condblock(db, parse_current, ast_node, CIL_CONDTRUE);
	} else if (!strcmp(parse_current->data, CIL_KEY_CONDFALSE)) {
		rc = cil_gen_condblock(db, parse_current, ast_node, CIL_CONDFALSE);
	} else if (!strcmp(parse_current->data, CIL_KEY_ALLOW)) {
		rc = cil_gen_avrule(parse_current, ast_node, CIL_AVRULE_ALLOWED);
		// So that the object and perms lists do not get parsed again
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_AUDITALLOW)) {
		rc = cil_gen_avrule(parse_current, ast_node, CIL_AVRULE_AUDITALLOW);
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_DONTAUDIT)) {
		rc = cil_gen_avrule(parse_current, ast_node, CIL_AVRULE_DONTAUDIT);
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_NEVERALLOW)) {
		rc = cil_gen_avrule(parse_current, ast_node, CIL_AVRULE_NEVERALLOW);
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_TYPETRANS)) {
		rc = cil_gen_type_rule(parse_current, ast_node, CIL_TYPE_TRANSITION);
	} else if (!strcmp(parse_current->data, CIL_KEY_TYPECHANGE)) {
		rc = cil_gen_type_rule(parse_current, ast_node, CIL_TYPE_CHANGE);
	} else if (!strcmp(parse_current->data, CIL_KEY_TYPEMEMBER)) {
		rc = cil_gen_type_rule(parse_current, ast_node, CIL_TYPE_MEMBER);
	} else if (!strcmp(parse_current->data, CIL_KEY_SENSITIVITY)) {
		rc = cil_gen_sensitivity(db, parse_current, ast_node);
	} else if (!strcmp(parse_current->data, CIL_KEY_SENSALIAS)) {
		rc = cil_gen_sensalias(db, parse_current, ast_node);
	} else if (!strcmp(parse_current->data, CIL_KEY_CATEGORY)) {
		rc = cil_gen_category(db, parse_current, ast_node);
	} else if (!strcmp(parse_current->data, CIL_KEY_CATALIAS)) {
		rc = cil_gen_catalias(db, parse_current, ast_node);
	} else if (!strcmp(parse_current->data, CIL_KEY_CATRANGE)) {
		rc = cil_gen_catrange(db, parse_current, ast_node);
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_CATSET)) {
		rc = cil_gen_catset(db, parse_current, ast_node);
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_CATORDER)) {
		rc = cil_gen_catorder(db, parse_current, ast_node);
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_DOMINANCE)) {
		rc = cil_gen_dominance(db, parse_current, ast_node);
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_SENSCAT)) {
		rc = cil_gen_senscat(db, parse_current, ast_node);
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_LEVEL)) {
		rc = cil_gen_level(db, parse_current, ast_node);
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_LEVELRANGE)) {
		rc = cil_gen_levelrange(db, parse_current, ast_node);
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_CONSTRAIN)) {
		rc = cil_gen_constrain(db, parse_current, ast_node, CIL_CONSTRAIN);
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_MLSCONSTRAIN)) {
		rc = cil_gen_constrain(db, parse_current, ast_node, CIL_MLSCONSTRAIN);
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_VALIDATETRANS)) {
		rc = cil_gen_validatetrans(db, parse_current, ast_node, CIL_VALIDATETRANS);
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_MLSVALIDATETRANS)) {
		rc = cil_gen_validatetrans(db, parse_current, ast_node, CIL_MLSVALIDATETRANS);
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_CONTEXT)) {
		rc = cil_gen_context(db, parse_current, ast_node);
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_FILECON)) {
		rc = cil_gen_filecon(db, parse_current, ast_node);
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_PORTCON)) {
		rc = cil_gen_portcon(db, parse_current, ast_node);
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_NODECON)) {
		rc = cil_gen_nodecon(db, parse_current, ast_node);
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_GENFSCON)) {
		rc = cil_gen_genfscon(db, parse_current, ast_node);
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_NETIFCON)) {
		rc = cil_gen_netifcon(db, parse_current, ast_node);
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_PIRQCON)) {
		rc = cil_gen_pirqcon(db, parse_current, ast_node);
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_IOMEMCON)) {
		rc = cil_gen_iomemcon(db, parse_current, ast_node);
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_IOPORTCON)) {
		rc = cil_gen_ioportcon(db, parse_current, ast_node);
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_PCIDEVICECON)) {
		rc = cil_gen_pcidevicecon(db, parse_current, ast_node);
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_FSUSE)) {
		rc = cil_gen_fsuse(db, parse_current, ast_node);
		*finished = CIL_TREE_SKIP_NEXT;
	} else if (!strcmp(parse_current->data, CIL_KEY_MACRO)) {
		rc = cil_gen_macro(db, parse_current, ast_node);
	} else if (!strcmp(parse_current->data, CIL_KEY_CALL)) {
		rc = cil_gen_call(db, parse_current, ast_node);
		*finished = 1;
	} else if (!strcmp(parse_current->data, CIL_KEY_POLICYCAP)) {
		rc = cil_gen_policycap(db, parse_current, ast_node);
		*finished = 1;
	} else if (!strcmp(parse_current->data, CIL_KEY_OPTIONAL)) {
		rc = cil_gen_optional(db, parse_current, ast_node);
	} else if (!strcmp(parse_current->data, CIL_KEY_IPADDR)) {
		rc = cil_gen_ipaddr(db, parse_current, ast_node);
	} else {
		cil_log(CIL_ERR, "Error: Unknown keyword %s\n", (char*)parse_current->data);
		rc = SEPOL_ERR;
	}

exit:
	return rc;
}

int __cil_build_ast_last_child_helper(__attribute__((unused)) struct cil_tree_node *parse_current, void *extra_args)
{
	int rc = SEPOL_ERR;
	struct cil_tree_node *ast = NULL;
	struct cil_args_build *args = NULL;
	struct cil_tree_node *tifstack = NULL;

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

	if (ast->flavor == CIL_MACRO) {
		args->macro = NULL;
	}

	if (ast->flavor == CIL_TUNABLEIF) {
		/* pop off the stack */
		tifstack = args->tifstack;
		args->tifstack = tifstack->cl_head;
		if (tifstack->cl_head) {
			tifstack->cl_head->parent = NULL;
		}
		free(tifstack);
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
	extra_args.tifstack = NULL;

	rc = cil_tree_walk(parse_tree, __cil_build_ast_node_helper, NULL, __cil_build_ast_last_child_helper, &extra_args);
	if (rc != SEPOL_OK) {
		cil_log(CIL_ERR, "Failed to build AST\n");
		goto exit;
	}

	return SEPOL_OK;

exit:
	return rc;
}
