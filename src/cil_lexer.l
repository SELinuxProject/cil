/* 
 * Copyright (C) 2011 Tresys Technology, LLC
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

%{
	#include <stdint.h>
	#include <sepol/errcodes.h>
	#include "cil_lexer.h"
	#include "cil_mem.h"
	char *value;
	int line = 1;
%}

%option nounput
%option noinput

digit		[0-9]
alpha		[a-zA-Z]
spec_char	[\[\]\.\@\=\/\*\-\_\$\%\@\+\-\!\|\&\^\:]
symbol		({digit}|{alpha}|{spec_char})+
white		[ \t]
newline		[\n\r]
qstring		\"[^"\n\']*\"
comment		;[^\n]*

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

int cil_lexer_setup(char *buffer, uint32_t size)
{
	size = (yy_size_t)size;
	if (yy_scan_buffer(buffer, size) == NULL) {
		printf("Lexer failed to setup buffer\n");
		return SEPOL_ERR;
	}
	
	return SEPOL_OK;
}

int cil_lexer_next(struct token *tok)
{
	tok->type = yylex();
	tok->value = value;
	tok->line = line;
	
	return SEPOL_OK;
}

