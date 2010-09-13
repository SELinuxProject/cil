#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sepol/policydb/symtab.h>
#include "CuTest.h"
#include "../../src/cil_tree.h"
#include "../../src/cil_lexer.h"
#include "../../src/cil.h"
#include "../../src/cil_symtab.h"

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

void test_symtab_init(CuTest *tc) {
    struct cil_db *test_new_db;
    test_new_db = malloc(sizeof(struct cil_db));

    uint32_t rc = 0, i =0;
    
    for (i=0; i<CIL_SYM_GLOBAL_NUM; i++) {
        rc = symtab_init(test_new_db->global_symtab, CIL_SYM_SIZE);
        CuAssertIntEquals(tc, 0, rc);
    }

    free(test_new_db);
}

void test_cil_symtab_array_init(CuTest *tc) {
    struct cil_db *test_new_db;
    test_new_db = malloc(sizeof(struct cil_db));

    int rc = cil_symtab_array_init(test_new_db->global_symtab, CIL_SYM_GLOBAL_NUM);
    CuAssertIntEquals(tc, SEPOL_OK, rc);

    free(test_new_db);
}

void test_cil_db_init(CuTest *tc) {
    struct cil_db *test_db;

    int rc = cil_db_init(&test_db);

    CuAssertIntEquals(tc, 0, rc);
    CuAssertPtrNotNull(tc, test_db->ast_root);
    CuAssertPtrNotNull(tc, test_db->global_symtab);
    CuAssertPtrNotNull(tc, test_db->local_symtab);
}

void test_cil_parser(CuTest *tc) {
    struct stat filedata;
    uint32_t file_size, rc = 0;
    char *buffer;
    FILE *file;

    struct cil_tree *test_parse_root;
    cil_tree_init(&test_parse_root);

    struct cil_db *test_db;
    cil_db_init(&test_db);

    file = fopen("testing/test.cil", "r");
    CuAssertPtrNotNull(tc, file);

    rc = stat("testing/test.cil", &filedata);
    CuAssertIntEquals(tc, 0, rc);

    file_size = filedata.st_size;

    buffer = malloc(file_size + 2);
    fread(buffer, file_size, 1, file);
    memset(buffer+file_size, 0, 2);
    fclose(file);

    rc = cil_parser(buffer, file_size + 2, &test_parse_root);
    CuAssertIntEquals(tc, SEPOL_OK, rc);
    CuAssertPtrNotNull(tc, test_parse_root);
    cil_tree_print(test_parse_root->root, 0);
}

void test_cil_lexer_setup(CuTest *tc) {
   char *test_str = "(test \"qstring\");comment\n";
   uint32_t str_size = strlen(test_str);
   char *buffer = malloc(str_size + 2);

   memset(buffer+str_size, 0, 2);
   strncpy(buffer, test_str, str_size);

   int rc = cil_lexer_setup(buffer, str_size + 2);
   CuAssertIntEquals(tc, SEPOL_OK, rc);

   free(buffer);
}

void test_cil_lexer_next(CuTest *tc) {
   char *test_str = "(test \"qstring\") ;comment\n";
   uint32_t str_size = strlen(test_str);
   char *buffer = malloc(str_size + 2);

   memset(buffer+str_size, 0, 2);
   strcpy(buffer, test_str);

   cil_lexer_setup(buffer, str_size + 2);

   struct token *test_tok;

   int rc = cil_lexer_next(&test_tok);
   CuAssertIntEquals(tc, SEPOL_OK, rc);

   CuAssertIntEquals(tc, OPAREN, test_tok->type);
   CuAssertStrEquals(tc, "(", test_tok->value);
   CuAssertIntEquals(tc, 1, test_tok->line);

   rc = cil_lexer_next(&test_tok);
   CuAssertIntEquals(tc, SEPOL_OK, rc);
   
   CuAssertIntEquals(tc, SYMBOL, test_tok->type);
   CuAssertStrEquals(tc, "test", test_tok->value);
   CuAssertIntEquals(tc, 1, test_tok->line);
 
   rc = cil_lexer_next(&test_tok);
   CuAssertIntEquals(tc, SEPOL_OK, rc);
   
   CuAssertIntEquals(tc, QSTRING, test_tok->type);
   CuAssertStrEquals(tc, "\"qstring\"", test_tok->value);
   CuAssertIntEquals(tc, 1, test_tok->line);
 
   rc = cil_lexer_next(&test_tok);
   CuAssertIntEquals(tc, SEPOL_OK, rc);
   
   CuAssertIntEquals(tc, CPAREN, test_tok->type);
   CuAssertStrEquals(tc, ")", test_tok->value);
   CuAssertIntEquals(tc, 1, test_tok->line);

   rc = cil_lexer_next(&test_tok);
   CuAssertIntEquals(tc, SEPOL_OK, rc);
  
   CuAssertIntEquals(tc, COMMENT, test_tok->type);
   CuAssertStrEquals(tc, ";comment", test_tok->value);
   CuAssertIntEquals(tc, 1, test_tok->line);

   free(buffer);
}

CuSuite* CilTreeGetSuite() {
    CuSuite* suite = CuSuiteNew();
    SUITE_ADD_TEST(suite, test_cil_tree_node_init);
    SUITE_ADD_TEST(suite, test_cil_tree_init);
    SUITE_ADD_TEST(suite, test_cil_lexer_setup);
    SUITE_ADD_TEST(suite, test_cil_lexer_next);
    SUITE_ADD_TEST(suite, test_symtab_init);
    SUITE_ADD_TEST(suite, test_cil_symtab_array_init);
    SUITE_ADD_TEST(suite, test_cil_db_init);
    SUITE_ADD_TEST(suite, test_cil_parser);

    return suite;
}
