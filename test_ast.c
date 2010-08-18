#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include "cil_lexer.h"
#include "cil.h"
#include "cil_tree.h"
#include "cil_parser.h"
#include "cil_ast.h"

#include <sepol/policydb/hashtab.h>

int main(int argc, char *argv[])
{
        uint32_t file_size;
        char *buffer;
        FILE *file;

	struct cil_db *db;
	db = cil_db_init();

        if (argc > 1) {
                file = fopen(argv[1], "r");
                if (!file) {
                        fprintf(stderr, "Could not open file\n");
                        exit(1);
                }
		/* TODO CDS - use stat() to figure out size */
                fseek(file, 0L, SEEK_END);
                file_size = ftell(file);
                fseek(file, 0, SEEK_SET);

                buffer = malloc(file_size + 1);
                fread(buffer, file_size, 1, file); 
                fclose(file);           

		db->parse_root = cil_parser(buffer, file_size);

		cil_print_tree(db->parse_root->root, 0);
		
		cil_build_ast(db);	
		//cil_print_tree(db->ast_root->root, 0);
		//hashtab_datum_t key;
		//key = ".main.a.a2.aa";
		//if (hashtab_search(db->symtab[CIL_SYM_ATTRS].table, key))
		//	printf("found\n");
        }

        exit(0);
}

