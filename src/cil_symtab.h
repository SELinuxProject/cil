#ifndef __CIL_SYMTAB_H_
#define __CIL_SYMTAB_H_

#include <sepol/policydb/symtab.h>
#include <sepol/policydb/hashtab.h>

struct cil_symtab_datum {
	struct cil_tree_node *node;
	char *name;
};

void cil_symtab_datum_destroy(struct cil_symtab_datum);
int cil_symtab_insert(symtab_t *, hashtab_key_t, struct cil_symtab_datum *, struct cil_tree_node *);
int cil_symtab_get_node(symtab_t *, char *, struct cil_tree_node **);
void cil_symtab_destroy(symtab_t *);

#endif
