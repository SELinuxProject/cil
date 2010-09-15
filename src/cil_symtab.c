#include <sepol/errcodes.h>
#include <sepol/policydb/hashtab.h>
#include "cil_symtab.h"

int cil_symtab_insert(symtab_t *symtab, hashtab_key_t key, cil_symtab_datum_t *datum, struct cil_tree_node *node)
{
	int rc = hashtab_insert(symtab->table, key, (hashtab_datum_t)datum);
	if (rc) {
		return rc;
	}
	else {
		datum->value = ++symtab->nprim;
		datum->self = node;
	}
	
	return SEPOL_OK;
}

