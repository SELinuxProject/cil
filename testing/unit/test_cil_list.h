#ifndef TEST_CIL_LIST_H_
#define TEST_CIL_LIST_H_

#include "CuTest.h"

void test_cil_list_init(CuTest *);
void test_cil_list_item_init(CuTest *);
void test_cil_list_append_item(CuTest *);
void test_cil_list_append_item_append(CuTest *);
void test_cil_list_append_item_append_extra(CuTest *);
void test_cil_list_append_item_listnull_neg(CuTest *);
void test_cil_list_append_item_itemnull_neg(CuTest *);
void test_cil_list_prepend_item_prepend(CuTest *);
void test_cil_list_prepend_item_prepend_neg(CuTest *);
void test_cil_list_prepend_item_listnull_neg(CuTest *);
void test_cil_list_prepend_item_itemnull_neg(CuTest *);

#endif
