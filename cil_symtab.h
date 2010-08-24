#ifndef __CIL_SYMTAB_H_
#define __CIL_SYMTAB_H_

#include <sepol/policydb/symtab.h>
#include <sepol/policydb/hashtab.h>

int sepol_symtab_insert(symtab_t *, hashtab_key_t, symtab_datum_t *);

#endif
