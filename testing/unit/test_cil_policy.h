/* 
 * Copyright (C) 2011 Tresys Technology, LLC
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef TEST_CIL_POLICY_H_
#define TEST_CIL_POLICY_H_

#include "CuTest.h"

void test_cil_filecon_compare_meta_a_not_b(CuTest *tc);
void test_cil_filecon_compare_meta_b_not_a(CuTest *tc);
void test_cil_filecon_compare_meta_a_and_b_strlen_a_greater_b(CuTest *tc);
void test_cil_filecon_compare_meta_a_and_b_strlen_b_greater_a(CuTest *tc);
void test_cil_filecon_compare_type_atype_greater_btype(CuTest *tc);
void test_cil_filecon_compare_type_btype_greater_atype(CuTest *tc);
void test_cil_filecon_compare_stemlen_a_greater_b(CuTest *tc);
void test_cil_filecon_compare_stemlen_b_greater_a(CuTest *tc);
void test_cil_filecon_compare_equal(CuTest *tc);

void test_cil_portcon_compare_atotal_greater_btotal(CuTest *tc);
void test_cil_portcon_compare_btotal_greater_atotal(CuTest *tc);
void test_cil_portcon_compare_aportlow_greater_bportlow(CuTest *tc);
void test_cil_portcon_compare_bportlow_greater_aportlow(CuTest *tc);
void test_cil_portcon_compare_equal(CuTest *tc);

void test_cil_genfscon_compare_atypestr_greater_btypestr(CuTest *tc);
void test_cil_genfscon_compare_btypestr_greater_atypestr(CuTest *tc);
void test_cil_genfscon_compare_apathstr_greater_bpathstr(CuTest *tc);
void test_cil_genfscon_compare_bpathstr_greater_apathstr(CuTest *tc);
void test_cil_genfscon_compare_equal(CuTest *tc);

void test_cil_netifcon_compare_a_greater_b(CuTest *tc);
void test_cil_netifcon_compare_b_greater_a(CuTest *tc);
void test_cil_netifcon_compare_equal(CuTest *tc);

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

void test_cil_fsuse_compare_type_a_greater_b(CuTest *tc);
void test_cil_fsuse_compare_type_b_greater_a(CuTest *tc);
void test_cil_fsuse_compare_fsstr_a_greater_b(CuTest *tc);
void test_cil_fsuse_compare_fsstr_b_greater_a(CuTest *tc);
void test_cil_fsuse_compare_equal(CuTest *tc);

#endif
