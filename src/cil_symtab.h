#ifndef __CIL_SYMTAB_H_
#define __CIL_SYMTAB_H_

#include <sepol/policydb/symtab.h>
#include <sepol/policydb/hashtab.h>

typedef struct cil_symtab_datum {
	uint32_t value;
	struct cil_tree_node *self;
} cil_symtab_datum_t;

int cil_symtab_insert(symtab_t *, hashtab_key_t, cil_symtab_datum_t *);

#endif
