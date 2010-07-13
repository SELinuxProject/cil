#ifndef CIL_LEXER_H_
#define CIL_LEXER_H_

#define OPAREN 1
#define CPAREN 2
#define SYMBOL 3
#define QSTRING 4
#define COMMENT 5
#define NONE 6

struct token
{
	int type;
	char * value;
	int line;
};

struct token * cil_lexer_next();
void cil_lexer_setup(char*, int);

#endif /* CIL_LEXER_H_ */
