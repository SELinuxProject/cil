#include <sepol/policydb/policydb.h>

#include "CuTest.h"
#include "test_cil_lexer.h"

#include "../../src/cil_lexer.h"

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

   struct token test_tok;

   int rc = cil_lexer_next(&test_tok);
   CuAssertIntEquals(tc, SEPOL_OK, rc);

   CuAssertIntEquals(tc, OPAREN, test_tok.type);
   CuAssertStrEquals(tc, "(", test_tok.value);
   CuAssertIntEquals(tc, 1, test_tok.line);

   rc = cil_lexer_next(&test_tok);
   CuAssertIntEquals(tc, SEPOL_OK, rc);
   
   CuAssertIntEquals(tc, SYMBOL, test_tok.type);
   CuAssertStrEquals(tc, "test", test_tok.value);
   CuAssertIntEquals(tc, 1, test_tok.line);
 
   rc = cil_lexer_next(&test_tok);
   CuAssertIntEquals(tc, SEPOL_OK, rc);
   
   CuAssertIntEquals(tc, QSTRING, test_tok.type);
   CuAssertStrEquals(tc, "\"qstring\"", test_tok.value);
   CuAssertIntEquals(tc, 1, test_tok.line);
 
   rc = cil_lexer_next(&test_tok);
   CuAssertIntEquals(tc, SEPOL_OK, rc);
   
   CuAssertIntEquals(tc, CPAREN, test_tok.type);
   CuAssertStrEquals(tc, ")", test_tok.value);
   CuAssertIntEquals(tc, 1, test_tok.line);

   rc = cil_lexer_next(&test_tok);
   CuAssertIntEquals(tc, SEPOL_OK, rc);
  
   CuAssertIntEquals(tc, COMMENT, test_tok.type);
   CuAssertStrEquals(tc, ";comment", test_tok.value);
   CuAssertIntEquals(tc, 1, test_tok.line);

   free(buffer);
}

