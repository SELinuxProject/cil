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
