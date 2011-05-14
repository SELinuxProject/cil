#ifndef TEST_CIL_COPY_AST_H_
#define TEST_CIL_COPY_AST_H_

#include "CuTest.h"

void test_cil_copy_list(CuTest *);
void test_cil_copy_list_sublist(CuTest *);
void test_cil_copy_list_sublist_extra(CuTest *);
void test_cil_copy_list_orignull_neg(CuTest *);

void test_cil_copy_class(CuTest *);

void test_cil_copy_type(CuTest *);

void test_cil_copy_avrule(CuTest *);

void test_cil_copy_cat(CuTest *);

void test_cil_copy_catalias(CuTest *);

void test_cil_copy_level(CuTest *);

void test_cil_copy_fill_level(CuTest *);

void test_cil_copy_context(CuTest *);

void test_cil_copy_fill_context(CuTest *);
void test_cil_copy_fill_context_anonlow(CuTest *);
void test_cil_copy_fill_context_anonhigh(CuTest *);

#endif
