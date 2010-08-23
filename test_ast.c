#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/stat.h>

#include "cil_lexer.h"
#include "cil.h"
#include "cil_tree.h"
#include "cil_parser.h"
#include "cil_ast.h"

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
                        exit(1);
                }
		if (stat(argv[1], &filedata) == -1) {
			printf("Could not stat file\n");
			exit(1);
		}
		file_size = filedata.st_size;	

                buffer = malloc(file_size + 1);
                fread(buffer, file_size, 1, file); 
                fclose(file);           

		cil_parser(buffer, file_size, &parse_root);

		cil_tree_print(parse_root->root, 0);
	
		cil_build_ast(&db, parse_root);	
		cil_tree_print(db->ast_root->root, 0);
        }

        exit(0);
}

