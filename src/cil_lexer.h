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

int cil_lexer_next(struct token **);
int cil_lexer_setup(char*, uint32_t);

#endif /* CIL_LEXER_H_ */
