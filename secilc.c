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
#include <stdint.h>
#include <sys/stat.h>
#include <string.h>

#include "src/cil.h"
#include "src/cil_tree.h"
#include "src/cil_lexer.h"
#include "src/cil_parser.h"
#include "src/cil_build_ast.h"
#include "src/cil_resolve_ast.h"
#include "src/cil_fqn.h"
#include "src/cil_policy.h"

#include "src/cil_copy_ast.h"

#include <sepol/policydb/hashtab.h>

int main(int argc, char *argv[])
{
	struct stat filedata;
	uint32_t file_size;
	char *buffer;
	FILE *file;
	
	struct cil_tree *parse_tree;
	cil_tree_init(&parse_tree);

	struct cil_tree *copy_ast;
	cil_tree_init(&copy_ast);

	struct cil_db *copy_db;
	cil_db_init(&copy_db);

	struct cil_db *db;
	cil_db_init(&db);
	
	int i;
	int rc;

	if (argc <= 1) {
		printf("Usage: %s [files]\n", argv[0]);
		exit(1);
	}

	for (i = 1; i < argc; i++) {
		file = fopen(argv[i], "r");
		if (!file) {
			fprintf(stderr, "Could not open file: %s\n", argv[i]);
			goto main_out;
		}
		if (stat(argv[i], &filedata) == -1) {
			printf("Could not stat file: %s\n", argv[i]);
			goto main_out;
		}
		file_size = filedata.st_size;	

		buffer = malloc(file_size + 2);
		rc = fread(buffer, file_size, 1, file);
		if (rc != 1) {
			fprintf(stderr, "Failure reading file: %s\n", argv[i]);
			goto main_out;
		}
		memset(buffer+file_size, 0, 2);
		fclose(file);
		file = NULL;

		printf("Building Parse Tree...\n");
		if (cil_parser(buffer, file_size + 2, &parse_tree)) {
			printf("Failed to parse CIL policy, exiting\n");
			goto main_out;
		}
#ifdef DEBUG
	cil_tree_print(parse_tree->root, 0);
#endif
	}

	printf("Building AST from Parse Tree...\n");
	if (cil_build_ast(db, parse_tree->root, db->ast->root)) {
		printf("Failed to build ast, exiting\n");
		goto main_out;
	}
#ifdef DEBUG
	cil_tree_print(db->ast->root, 0);
#endif	
	printf("Destroying Parse Tree...\n");
	cil_tree_destroy(&parse_tree);

	printf("Resolving AST...\n");
	if (cil_resolve_ast(db, db->ast->root)) {
		printf("Failed to resolve ast, exiting\n");
		goto main_out;
	}

#ifdef DEBUG
	cil_tree_print(db->ast->root, 0);
#endif
	printf("Destroying AST Symtabs...\n");
	if (cil_destroy_ast_symtabs(db->ast->root)) {
		printf("Failed to destroy ast symtabs, exiting\n");
		goto main_out;
	}

	printf("Qualifying Names...\n");
	if (cil_qualify_name(db->ast->root)) {
		printf("Failed to qualify names, exiting\n");
		goto main_out;
	}

#ifdef DEBUG
	cil_tree_print(db->ast->root, 0);
#endif
	printf("Generating Policy...\n");
	if (cil_gen_policy(db)){
		printf("Failed to generate policy, exiting\n");
		goto main_out;
	}

	printf("Destroying DB...\n");
	cil_db_destroy(&db);

	return SEPOL_OK;

main_out:
	if (file != NULL) {
		fclose(file);
	}
	return SEPOL_ERR;
}
