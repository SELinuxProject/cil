#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include "cil_lexer.h"
#include "cil.h"
#include "cil_tree.h"
#include "cil_parser.h"

int main(int argc, char *argv[])
{
        uint32_t file_size;
        char *buffer;
        FILE *file;

	struct cil_db *db;
	db = cil_db_init();

        if (argc > 1){
                file = fopen(argv[1], "r");
                if (!file){
                        fprintf(stderr, "Could not open file\n");
                        exit(1);
                }
                fseek(file, 0L, SEEK_END);
                file_size = ftell(file);
                fseek(file, 0, SEEK_SET);

                buffer = (char*)malloc(file_size + 1);
                fread(buffer, file_size, 1, file); 
                fclose(file);           

		db->parse_root = cil_parser(buffer, file_size);

//		cil_print_tree(tree->root, 0); //Separate print_tree functions for parse and ast? Wrap so depth isn't shown
		
		cil_build_ast(db->parse_root->root, db->ast_root);				

        }

        exit(0);
}

