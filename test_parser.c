#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

#include "cil_lexer.h"
#include "cil_tree.h"
#include "cil.h"
#include "cil_parser.h"

int main(int argc, char *argv[])
{
        uint32_t file_size;
        char *buffer;
        FILE *file;

        char buf[10];

        if (argc > 1) {
                file = fopen(argv[1], "r");
                if (!file) {
                        fprintf(stderr, "Could not open file\n");
                        exit(1);
                }
                fseek(file, 0L, SEEK_END);
                file_size = ftell(file);
                fseek(file, 0, SEEK_SET);

                buffer = (char*)malloc(file_size + 1);
                fread(buffer, file_size, 1, file); 
                fclose(file);           

		cil_print_tree((cil_parser(buffer, file_size))->root, 0);
        }

        exit(0);
}

