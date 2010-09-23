#include <sepol/errcodes.h>
#include <sepol/policydb/hashtab.h>
#include "cil_symtab.h"

int cil_symtab_insert(symtab_t *symtab, hashtab_key_t key, cil_symtab_datum_t *datum, struct cil_tree_node *node)
{
	// TODO CDS newkey = strdup(key)
	int rc = hashtab_insert(symtab->table, key, (hashtab_datum_t)datum);
	if (rc) {
		// TODO CDS don't forget to free - free(newkey)
		return rc;
	}
	else {
		datum->value = ++symtab->nprim;
		datum->self = node;
	}
	
	return SEPOL_OK;
}

