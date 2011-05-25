#ifndef CIL_RESOLVE_AST_H_
#define CIL_RESOLVE_AST_H_

#include <stdint.h>

#include "cil.h"
#include "cil_tree.h"

int cil_resolve_avrule(struct cil_db *, struct cil_tree_node *, struct cil_call *);
int cil_resolve_type_rule(struct cil_db *, struct cil_tree_node *, struct cil_call *);
int cil_resolve_typeattr(struct cil_db *, struct cil_tree_node *, struct cil_call *);
int cil_resolve_typealias(struct cil_db *, struct cil_tree_node *, struct cil_call *);
int cil_resolve_userrole(struct cil_db *, struct cil_tree_node *, struct cil_call *);
int cil_resolve_roletype(struct cil_db *, struct cil_tree_node *, struct cil_call *);
int cil_resolve_roletrans(struct cil_db *, struct cil_tree_node *, struct cil_call *);
int cil_resolve_roleallow(struct cil_db *, struct cil_tree_node *, struct cil_call *);
int cil_resolve_roledominance(struct cil_db *, struct cil_tree_node *, struct cil_call *);
int cil_resolve_sensalias(struct cil_db *, struct cil_tree_node *, struct cil_call *);
int cil_resolve_catalias(struct cil_db *, struct cil_tree_node *, struct cil_call *);
int cil_resolve_catorder(struct cil_db *, struct cil_tree_node *, struct cil_call *);
int cil_resolve_dominance(struct cil_db *, struct cil_tree_node *, struct cil_call *);
int cil_resolve_cat_list(struct cil_db *, struct cil_tree_node *, struct cil_list *, struct cil_list *, struct cil_call *);
int cil_resolve_catset(struct cil_db *, struct cil_tree_node *, struct cil_catset *, struct cil_call *);
int cil_resolve_senscat(struct cil_db *, struct cil_tree_node *, struct cil_call *);
int cil_resolve_level(struct cil_db *, struct cil_tree_node *, struct cil_level *, struct cil_call *); 
int cil_resolve_constrain(struct cil_db *, struct cil_tree_node *, struct cil_call *);
int cil_resolve_context(struct cil_db *, struct cil_tree_node *, struct cil_context *, struct cil_call *);
int cil_resolve_filecon(struct cil_db *, struct cil_tree_node *, struct cil_call *);
int cil_resolve_portcon(struct cil_db *, struct cil_tree_node *, struct cil_call *);
int cil_resolve_genfscon(struct cil_db *, struct cil_tree_node *, struct cil_call *);
int cil_resolve_nodecon(struct cil_db *, struct cil_tree_node *, struct cil_call *);
int cil_resolve_netifcon(struct cil_db *, struct cil_tree_node *, struct cil_call *);
int cil_resolve_sidcontext(struct cil_db *, struct cil_tree_node *, struct cil_call *);
int cil_resolve_classcommon(struct cil_db *, struct cil_tree_node *, struct cil_call *);
int cil_resolve_call1(struct cil_db *, struct cil_tree_node *, struct cil_call *);
int cil_resolve_call2(struct cil_db *, struct cil_tree_node *, struct cil_call *);
int cil_resolve_expr_stack(struct cil_db *db, struct cil_tree_node *current, struct cil_tree_node *bif, struct cil_call *call, uint32_t flavor);
int cil_resolve_tunif(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call);
int cil_resolve_boolif(struct cil_db *db, struct cil_tree_node *current, struct cil_call *call);
int cil_evaluate_expr_stack(struct cil_tree_node *stack, uint16_t *result);
int cil_resolve_name_call_args(struct cil_call *, char *, uint32_t, struct cil_tree_node **);

int cil_resolve_ast(struct cil_db *, struct cil_tree_node *);
int cil_resolve_name(struct cil_db *, struct cil_tree_node *, char *, uint32_t, uint32_t, struct cil_call *, struct cil_tree_node **);
int cil_resolve_name_global(symtab_t, char *, void **);

int cil_reset_class(struct cil_db *, struct cil_tree_node *, struct cil_call *);
int cil_reset_sens(struct cil_db *, struct cil_tree_node *, struct cil_call *);

#endif /* CIL_RESOLVE_AST_H_ */
