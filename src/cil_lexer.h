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

#ifndef CIL_LEXER_H_
#define CIL_LEXER_H_

#include <stdint.h>

#define OPAREN 1
#define CPAREN 2
#define SYMBOL 3
#define QSTRING 4
#define COMMENT 5
#define NONE 6

struct token {
	uint32_t type;
	char * value;
	uint32_t line;
};

int cil_lexer_next(struct token *);
int cil_lexer_setup(char*, uint32_t);

#endif /* CIL_LEXER_H_ */
