#ifndef CIL_AST_H_
#define CIL_AST_H_

#include <stdint.h>

#include "cil_tree.h"
#include "cil.h"

int cil_build_ast(struct cil_db *, struct cil_tree_node *, struct cil_tree_node *);
int cil_resolve_avrule(struct cil_db *, struct cil_tree_node *);
int cil_resolve_typerule(struct cil_db *, struct cil_tree_node *);
int cil_resolve_typeattr(struct cil_db *, struct cil_tree_node *);
int cil_resolve_typealias(struct cil_db *, struct cil_tree_node *);
int cil_resolve_class(struct cil_db *, struct cil_tree_node *);
int cil_resolve_userrole(struct cil_db *, struct cil_tree_node *);
int cil_resolve_roletype(struct cil_db *, struct cil_tree_node *);
int cil_resolve_roletrans(struct cil_db *, struct cil_tree_node *);
int cil_resolve_roleallow(struct cil_db *, struct cil_tree_node *);
int cil_resolve_sensalias(struct cil_db *, struct cil_tree_node *);
int cil_resolve_catalias(struct cil_db *, struct cil_tree_node *);
int cil_resolve_catset(struct cil_db *, struct cil_tree_node *);
int cil_resolve_ast(struct cil_db *, struct cil_tree_node *);
int cil_resolve_name(struct cil_db *, struct cil_tree_node *, char *, uint32_t, struct cil_tree_node **);
int cil_resolve_name_global(symtab_t, char *, void **);
int cil_destroy_ast_symtabs(struct cil_tree_node *);
int cil_qualify_name(struct cil_tree_node *);

#endif /* CIL_AST_H_ */

