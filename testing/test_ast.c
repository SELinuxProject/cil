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

	if (argc > 1) {
		file = fopen(argv[1], "r");
		if (!file) {
			 fprintf(stderr, "Could not open file\n");
			 return SEPOL_ERR;
		}
		if (stat(argv[1], &filedata) == -1) {
			printf("Could not stat file\n");
			return SEPOL_ERR;
		}
		file_size = filedata.st_size;	

		buffer = malloc(file_size + 2);
		fread(buffer, file_size, 1, file);
		memset(buffer+file_size, 0, 2);
		fclose(file);

		printf("----------------------------------------------\n\n");
		printf("Building parse tree\n");
		if (cil_parser(buffer, file_size + 2, &parse_tree)) {
			printf("Failed to parse CIL policy, exiting\n");
			return SEPOL_ERR;
		}
		cil_tree_print(parse_tree->root, 0);

		printf("----------------------------------------------\n\n");
		printf("Building ast from parse tree\n\n");
		if (cil_build_ast(db, parse_tree->root, db->ast->root)) {
			printf("Failed to build ast, exiting\n");
			return SEPOL_ERR;
		}
		cil_tree_print(db->ast->root, 0);
	
		printf("----------------------------------------------\n\n");
		printf("Destroying parse tree\n");
		cil_tree_destroy(&parse_tree);
		printf("Parse tree destroyed\n\n");

		printf("----------------------------------------------\n\n");
		printf("Resolve ast ...\n\n");
		if (cil_resolve_ast(db, db->ast->root)) {
			printf("Failed to resolve ast, exiting\n");
			return SEPOL_ERR;
		}

		cil_tree_print(db->ast->root, 0);

		printf("----------------------------------------------\n\n");
		printf("Destroying AST symtabs\n");
		cil_destroy_ast_symtabs(db->ast->root);
		printf("Symtabs destroyed\n\n");
	
		printf("----------------------------------------------\n\n");
		printf("Qualifying names\n");
		cil_qualify_name(db->ast->root);
		printf("Names fully qualified\n\n");

		cil_tree_print(db->ast->root, 0);

		printf("----------------------------------------------\n\n");
		printf("Generating policy\n");
		cil_gen_policy(db);
		printf("Policy generated\n\n");
	
		printf("----------------------------------------------\n\n");
		printf("Destroying db\n");
		cil_db_destroy(&db);
		printf("db destroyed\n\n");
	}

	return SEPOL_OK;
}
