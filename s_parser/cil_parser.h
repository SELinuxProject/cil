#ifndef CIL_PARSER_H_
#define CIL_PARSER_H_

struct element
{
        struct element *parent;
        struct element *cl_head;	//Head of child_list
	struct element *cl_tail;	//Tail of child_list
        struct element *next;		//Each element in the list points to the next element
        char *data;
	int line;
};

struct element * cil_parser(char *, int);
void cil_print_tree(struct element *, int);

#endif /* CIL_PARSER_H_ */
