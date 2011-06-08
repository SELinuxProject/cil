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

