#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/stat.h>
#include <string.h>

#include "../src/cil_lexer.h"
#include "../src/cil.h"
#include "../src/cil_tree.h"
#include "../src/cil_parser.h"
#include "../src/cil_ast.h"

#include <sepol/policydb/hashtab.h>

int main(int argc, char *argv[])
{
	struct stat filedata;
	uint32_t file_size;
	char *buffer;
	FILE *file;
	
	struct cil_tree *parse_root;
	cil_tree_init(&parse_root);

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
		if (cil_parser(buffer, file_size + 2, &parse_root)) {
			printf("Failed to parse CIL policy, exiting\n");
			return SEPOL_ERR;
		}
		cil_tree_print(parse_root->root, 0);

		printf("----------------------------------------------\n\n");
		printf("Building ast from parse tree\n\n");
		if (cil_build_ast(&db, parse_root)) {
			printf("Failed to build ast, exiting\n");
			return SEPOL_ERR;
		}
		cil_tree_print(db->ast_root->root, 0);
	
		printf("----------------------------------------------\n\n");
		printf("Resolving ast\n\n");
		if (cil_resolve_ast(&db, db->ast_root->root)) {
			printf("Failed to resolve ast, exiting\n");
			return SEPOL_ERR;
		}

		cil_tree_print(db->ast_root->root, 0);
	}

	return SEPOL_OK;
}
