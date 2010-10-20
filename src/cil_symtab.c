#include <stdlib.h>
#include <sepol/errcodes.h>
#include <sepol/policydb/hashtab.h>
#include <string.h>
#include "cil_tree.h"
#include "cil_symtab.h"

void cil_symtab_datum_destroy(struct cil_symtab_datum datum)
{
	free(datum.name);
}

int cil_symtab_insert(symtab_t *symtab, hashtab_key_t key, struct cil_symtab_datum *datum, struct cil_tree_node *node)
{
	char *newkey = strdup(key);
	int rc = hashtab_insert(symtab->table, newkey, (hashtab_datum_t)datum);
	if (rc != SEPOL_OK) {
		free(newkey);
		return rc;
	}
	else {
		datum->node = node;
		datum->name = newkey;
	}
	
	return SEPOL_OK;
}

int cil_symtab_get_node(symtab_t *symtab, char *key, struct cil_tree_node **node)
{
	struct cil_symtab_datum *datum = (struct cil_symtab_datum*)hashtab_search(symtab->table, (hashtab_key_t)key);
	if (datum == NULL)
		return SEPOL_ERR;

	*node = datum->node;

	return SEPOL_OK;
}

void cil_symtab_destroy(symtab_t *symtab)
{
	if (symtab->table != NULL){
		hashtab_destroy(symtab->table);
		symtab->table = NULL;
	}
}

