#ifndef CIL_POLICY_H_
#define CIL_POLICY_H_

#include "cil_tree.h"
#include "cil.h"

int cil_combine_policy(FILE **, FILE *);
int cil_name_to_policy(FILE *, struct cil_tree_node *); 
int cil_gen_policy(struct cil_tree_node *);

#endif
