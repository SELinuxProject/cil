%{
	#include <stdint.h>
	#include "cil_lexer.h"
	char * value;
	int line = 1;
%}

digit		[0-9]
alpha		[a-zA-Z]
spec_char	[\[\]\.\@\=\/\*\-\_\$\%\@\+\-\!]
symbol		({digit}|{alpha}|{spec_char})+
white		[ \t]
newline		[\n\r]
qstring		\"[^"\n\']*\"
comment		;.*$

%%
{newline}	line++; 
{comment}	value=yytext; return COMMENT;
"("		value=yytext; return OPAREN;
")"		value=yytext; return CPAREN;	
{symbol}	value=yytext; return SYMBOL;
{white}		//printf("white, ");
{qstring}	value=yytext; return QSTRING;
.		value=yytext; return NONE;
%%

void cil_lexer_setup(char *buffer, uint32_t size)
{
	size = (yy_size_t)size;
	yy_scan_buffer(buffer, size + 2);
}

struct token * cil_lexer_next()
{
	struct token *n;
	n = (struct token*) malloc( sizeof(struct token));
	n->type = yylex();
	n->value = value;
	n->line = line;
}

