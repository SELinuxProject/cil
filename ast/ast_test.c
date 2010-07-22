#include <stdlib.h>
#include <stdio.h>
#include "../s_parser/cil_lexer.h"
#include "../s_parser/cil_parser.h"
#include "cil.h"

int main(int argc, char *argv[])
{
        int file_size;
        char *buffer;
        FILE *file;

	struct element *tree;
	struct cil_tree *ast;

	ast = (struct cil_tree *)malloc(sizeof(struct cil_tree));

        char buf[10];

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

		tree = cil_parser(buffer, file_size);

		cil_print_tree(tree, 0);
		
		cil_build_ast(tree, ast);				

        }

        exit(0);
}

