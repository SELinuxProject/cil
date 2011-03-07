#ifndef TEST_CIL_H_
#define TEST_CIL_H_

#include "CuTest.h"

void test_cil_symtab_array_init(CuTest *);
void test_cil_symtab_array_init_null_symtab_neg(CuTest *);
void test_cil_db_init(CuTest *);
void test_cil_get_parent_symtab_block(CuTest *);
void test_cil_get_parent_symtab_class(CuTest *);
void test_cil_get_parent_symtab_root(CuTest *);
void test_cil_get_parent_symtab_other_neg(CuTest *);
void test_cil_get_parent_symtab_null_neg(CuTest *);
void test_cil_get_parent_symtab_node_null_neg(CuTest *);
void test_cil_get_parent_symtab_parent_null_neg(CuTest *);


#endif
