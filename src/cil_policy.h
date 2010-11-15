#ifndef CIL_POLICY_H_
#define CIL_POLICY_H_

#include "cil_tree.h"
#include "cil_list.h"
#include "cil.h"

struct cil_multimap_item {
	struct cil_symtab_datum *key;
	struct cil_list *values;
};

int cil_combine_policy(FILE **, FILE *);
int cil_name_to_policy(FILE **, struct cil_tree_node *); 
int cil_gen_policy(struct cil_db *);

#endif
