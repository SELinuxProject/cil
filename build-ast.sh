#!/bin/sh
flex -o cil_lexer.c cil_lexer.lex
gcc test_ast.c cil.c cil_tree.c cil_ast.c cil_parser.c cil_lexer.c -lfl -o ast
