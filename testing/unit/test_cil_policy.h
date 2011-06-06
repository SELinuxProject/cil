#ifndef TEST_CIL_POLICY_H_
#define TEST_CIL_POLICY_H_

#include "CuTest.h"

void test_cil_nodecon_compare_aipv4_bipv6(CuTest *tc);
void test_cil_nodecon_compare_aipv6_bipv4(CuTest *tc);
void test_cil_nodecon_compare_aipv4_greaterthan_bipv4(CuTest *tc);
void test_cil_nodecon_compare_aipv4_lessthan_bipv4(CuTest *tc);
void test_cil_nodecon_compare_amaskipv4_greaterthan_bmaskipv4(CuTest *tc);
void test_cil_nodecon_compare_amaskipv4_lessthan_bmaskipv4(CuTest *tc);
void test_cil_nodecon_compare_aipv6_greaterthan_bipv6(CuTest *tc);
void test_cil_nodecon_compare_aipv6_lessthan_bipv6(CuTest *tc);
void test_cil_nodecon_compare_amaskipv6_greaterthan_bmaskipv6(CuTest *tc);
void test_cil_nodecon_compare_amaskipv6_lessthan_bmaskipv6(CuTest *tc);
#endif
