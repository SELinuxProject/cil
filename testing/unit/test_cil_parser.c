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

#include <sepol/policydb/policydb.h>

#include "CuTest.h"
#include "CilTest.h"
#include "test_cil_parser.h"

#include "../../src/cil_parser.h"
#include "../../src/cil.h"

// TODO rewrite to use the gen_tree function
void test_cil_parser(CuTest *tc) {
	int rc = 0;
	struct cil_file_data *data;

	struct cil_tree *test_parse_root;
	cil_tree_init(&test_parse_root);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	set_cil_file_data(&data);

	rc = cil_parser(data->buffer, data->file_size + 2, &test_parse_root);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, test_parse_root);
	// TODO add checking of the parse tree that is returned
}

