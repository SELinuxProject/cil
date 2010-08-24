#include <sepol/errcodes.h>
#include <sepol/policydb/hashtab.h>
#include <sepol/policydb/symtab.h>

int sepol_symtab_insert(symtab_t *symtab, hashtab_key_t key, symtab_datum_t *datum)
{
        int rc = hashtab_insert(symtab->table, key, (hashtab_datum_t)datum);
        if (rc) {
                printf("Failed to insert into symtab\n");
                return SEPOL_ERR;
        }
        else
                datum->value = ++symtab->nprim;

        return SEPOL_OK;
}

