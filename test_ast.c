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
                        return SEPOL_ERR;
                }
		if (stat(argv[1], &filedata) == -1) {
			printf("Could not stat file\n");
			return SEPOL_ERR;
		}
		file_size = filedata.st_size;	

                buffer = malloc(file_size + 1);
                fread(buffer, file_size, 1, file); 
                fclose(file);           

		cil_parser(buffer, file_size, &parse_root);

		cil_tree_print(parse_root->root, 0);
	
		cil_build_ast(&db, parse_root);	
		cil_tree_print(db->ast_root->root, 0);
		
	/*	struct cil_block *search;
		search = (struct cil_block*)hashtab_search(db->symtab[CIL_SYM_BLOCKS].table, "apache.test");
		
		printf("id: %d\n", search->datum.value);
		printf("first child is of type: %d\n", search->self->cl_head->flavor);	*/	

        }

        return SEPOL_OK;
}

