#ifndef CIL_POLICY_H_
#define CIL_POLICY_H_

#include "cil_tree.h"
#include "cil_list.h"
#include "cil.h"

struct cil_multimap_item {
	struct cil_symtab_datum *key;
	struct cil_list *values;
};

struct fc_data {
	int meta;
	int stem_len;
	int str_len;
};

int cil_combine_policy(FILE **, FILE *);
int cil_name_to_policy(FILE **, struct cil_tree_node *);
void cil_context_to_policy(FILE **, uint32_t, struct cil_context *);
int cil_gen_policy(struct cil_db *);
int cil_nodecon_compare(const void *a, const void *b);
int cil_filecon_compare(const void *a, const void *b);
int cil_portcon_compare(const void *a, const void *b);
int cil_genfscon_compare(const void *a, const void *b);
int cil_netifcon_compare(const void *a, const void *b);
int cil_fsuse_compare(const void *a, const void *b);

#endif
