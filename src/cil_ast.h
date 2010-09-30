#ifndef CIL_AST_H_
#define CIL_AST_H_

#include <stdint.h>

#include "cil_tree.h"
#include "cil.h"

int cil_build_ast(struct cil_db *, struct cil_tree_node *, struct cil_tree_node *);
int cil_resolve_ast(struct cil_db *, struct cil_tree_node *);
int cil_resolve_name(struct cil_db *, struct cil_tree_node *, char *, uint32_t, struct cil_tree_node **);
int cil_resolve_name_global(symtab_t, char *, void **);
int cil_qualify_name(struct cild_db *);

#endif /* CIL_AST_H_ */

