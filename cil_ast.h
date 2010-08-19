#ifndef CIL_AST_H_
#define CIL_AST_H_

#include <stdint.h>

#include "cil_tree.h"
#include "cil.h"

void cil_build_ast(struct cil_db *, struct cil_tree *);
void __cil_build_ast(struct cil_db *, struct cil_stack *, char *, struct cil_tree_node *, struct cil_tree_node *);

#endif /* CIL_AST_H_ */

