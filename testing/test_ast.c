#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/stat.h>
#include <string.h>

#include "../src/cil.h"
#include "../src/cil_tree.h"
#include "../src/cil_lexer.h"
#include "../src/cil_parser.h"
#include "../src/cil_build_ast.h"
#include "../src/cil_resolve_ast.h"
#include "../src/cil_fqn.h"
#include "../src/cil_policy.h"

#include "../src/cil_copy_ast.h"

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

	if (argc <= 1) {
		printf("Usage: %s [files]\n", argv[0]);
		exit(1);
	}

	for (i = 1; i < argc; i++) {
		file = fopen(argv[i], "r");
		if (!file) {
			 fprintf(stderr, "Could not open file: %s\n", argv[i]);
			 return SEPOL_ERR;
		}
		if (stat(argv[1], &filedata) == -1) {
			printf("Could not stat file: %s\n", argv[i]);
			return SEPOL_ERR;
		}
		file_size = filedata.st_size;	

		buffer = malloc(file_size + 2);
		fread(buffer, file_size, 1, file);
		memset(buffer+file_size, 0, 2);
		fclose(file);

		printf("Building Parse Tree...\n");
		if (cil_parser(buffer, file_size + 2, &parse_tree)) {
			printf("Failed to parse CIL policy, exiting\n");
			return SEPOL_ERR;
		}
	}
#ifdef DEBUG
	cil_tree_print(parse_tree->root, 0);
#endif

	printf("Building AST from Parse Tree...\n");
	if (cil_build_ast(db, parse_tree->root, db->ast->root)) {
		printf("Failed to build ast, exiting\n");
		return SEPOL_ERR;
	}
#ifdef DEBUG
	cil_tree_print(db->ast->root, 0);
#endif	
	printf("Destroying Parse Tree...\n");
	cil_tree_destroy(&parse_tree);

	printf("Resolving AST...\n");
	if (cil_resolve_ast(db, db->ast->root)) {
		printf("Failed to resolve ast, exiting\n");
		return SEPOL_ERR;
	}

#ifdef DEBUG
	cil_tree_print(db->ast->root, 0);
#endif
	printf("Destroying AST Symtabs...\n");
	if (cil_destroy_ast_symtabs(db->ast->root)) {
		printf("Failed to destroy ast symtabs, exiting\n");
		return SEPOL_ERR;
	}

	printf("Qualifying Names...\n");
	if (cil_qualify_name(db->ast->root)) {
		printf("Failed to qualify names, exiting\n");
		return SEPOL_ERR;
	}

#ifdef DEBUG
	cil_tree_print(db->ast->root, 0);
#endif
	printf("Generating Policy...\n");
	if (cil_gen_policy(db)){
		printf("Failed to generate policy, exiting\n");
		return SEPOL_ERR;
	}

	printf("Destroying DB...\n");
	cil_db_destroy(&db);

	return SEPOL_OK;
}
