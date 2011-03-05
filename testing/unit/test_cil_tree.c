#include <sepol/policydb/policydb.h>

#include "CuTest.h"

#include "../../src/cil_tree.h"

void test_cil_tree_node_init(CuTest *tc) {
   struct cil_tree_node *test_node;

   int rc = cil_tree_node_init(&test_node);

   CuAssertIntEquals(tc, SEPOL_OK, rc);
   CuAssertPtrNotNull(tc, test_node);
   CuAssertPtrEquals(tc, NULL, test_node->cl_head);
   CuAssertPtrEquals(tc, NULL, test_node->cl_tail);
   CuAssertPtrEquals(tc, NULL, test_node->parent);
   CuAssertPtrEquals(tc, NULL, test_node->data);
   CuAssertPtrEquals(tc, NULL, test_node->next);
   CuAssertIntEquals(tc, 0, test_node->flavor);
   CuAssertIntEquals(tc, 0, test_node->line);

   free(test_node);
}

void test_cil_tree_init(CuTest *tc) {
	struct cil_tree *test_tree;

	int rc = cil_tree_init(&test_tree);

	CuAssertIntEquals(tc, SEPOL_OK, rc);
	CuAssertPtrNotNull(tc, test_tree);
	CuAssertPtrEquals(tc, NULL, test_tree->root->cl_head);
	CuAssertPtrEquals(tc, NULL, test_tree->root->cl_tail);
	CuAssertPtrEquals(tc, NULL, test_tree->root->parent);
	CuAssertPtrEquals(tc, NULL, test_tree->root->data);
	CuAssertPtrEquals(tc, NULL, test_tree->root->next);
	CuAssertIntEquals(tc, 0, test_tree->root->flavor);
	CuAssertIntEquals(tc, 0, test_tree->root->line);

	free(test_tree);
}

