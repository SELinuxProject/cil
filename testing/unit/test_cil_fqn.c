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

#include "../../src/cil_fqn.h"
#include "../../src/cil_build_ast.h"

void test_cil_qualify_name(CuTest *tc) {
	char *line[] = {"(", "category", "c0", ")",
			"(", "categoryorder", "(", "c0", ")", ")",
			"(", "sensitivity", "s0", ")",
			"(", "sensitivitycategory", "s0", "(", "c0", ")", ")",
			"(", "type", "blah_t", ")",
			"(", "role", "blah_r", ")",
			"(", "user", "blah_u", ")",
			"(", "context", "con", "(", "blah_u", "blah_r", "blah_t", "(", "s0", "(", "c0", ")", ")", "(", "s0", "(", "c0", ")", ")", ")", ")",
			"(", "sid", "test", "con", NULL};

	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	cil_build_ast(test_db, tree->root, test_db->ast->root);

	int rc = cil_qualify_name(test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}

void test_cil_qualify_name_cil_flavor(CuTest *tc) {
	char *line[] = {"(", "class",  "file", "inherits", "file",
			"(", "open", ")", ")", NULL};

	struct cil_tree *tree;
	gen_test_tree(&tree, line);

	struct cil_db *test_db;
	cil_db_init(&test_db);

	cil_build_ast(test_db, tree->root, test_db->ast->root);

	int rc = cil_qualify_name(test_db->ast->root);
	CuAssertIntEquals(tc, SEPOL_OK, rc);
}
