#!/bin/sh
flex -o cil_lexer.c cil_lexer.l
gcc -Wall -o ast test_ast.c cil.c cil_tree.c cil_ast.c cil_parser.c cil_lexer.c cil_symtab.c /usr/lib64/libsepol.a -lfl
