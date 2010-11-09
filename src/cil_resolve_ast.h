#ifndef CIL_RESOLVE_AST_H_
#define CIL_RESOLVE_AST_H_

#include <stdint.h>

#include "cil.h"
#include "cil_tree.h"

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
int cil_resolve_level(struct cil_db *, struct cil_tree_node *); 
int cil_resolve_context(struct cil_db *, struct cil_tree_node *);

int cil_resolve_ast(struct cil_db *, struct cil_tree_node *, uint32_t pass);
int cil_resolve_name(struct cil_db *, struct cil_tree_node *, char *, uint32_t, struct cil_tree_node **);
int cil_resolve_name_global(symtab_t, char *, void **);

#endif /* CIL_RESOLVE_AST_H_ */
