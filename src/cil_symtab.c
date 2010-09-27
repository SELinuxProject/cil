#include <stdlib.h>
#include <sepol/errcodes.h>
#include <sepol/policydb/hashtab.h>
#include <string.h>
#include "cil_tree.h"
#include "cil_symtab.h"

int cil_symtab_insert(symtab_t *symtab, hashtab_key_t key, cil_symtab_datum_t *datum, struct cil_tree_node *node)
{
	char *newkey = strdup(key);
	int rc = hashtab_insert(symtab->table, newkey, (hashtab_datum_t)datum);
	if (rc) {
		free(newkey);
		return rc;
	}
	else {
		datum->value = ++symtab->nprim;
		datum->node = node;
	}
	
	return SEPOL_OK;
}

