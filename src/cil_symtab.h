#ifndef __CIL_SYMTAB_H_
#define __CIL_SYMTAB_H_

#include <sepol/policydb/symtab.h>
#include <sepol/policydb/hashtab.h>

typedef struct cil_symtab_datum {
	uint32_t value;
	struct cil_tree_node *node;
	char *name;
} cil_symtab_datum_t;

int cil_symtab_insert(symtab_t *, hashtab_key_t, cil_symtab_datum_t *, struct cil_tree_node *);
int cil_symtab_get_node(symtab_t *, char *, struct cil_tree_node **);
int cil_symtab_get_value(symtab_t *, char *, uint32_t *);

#endif
