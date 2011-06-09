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

#include <stdio.h>
#include "CuTest.h"

CuSuite* CilTreeGetSuite(void);
CuSuite* CilTreeGetResolveSuite(void);
CuSuite* CilTreeGetBuildSuite(void);

void RunAllTests(void) {
    CuString *output  = CuStringNew();
    CuSuite* suite = CuSuiteNew();
    CuSuite* suiteResolve = CuSuiteNew();
    CuSuite* suiteBuild = CuSuiteNew();

    CuSuiteAddSuite(suite, CilTreeGetSuite());
    CuSuiteAddSuite(suiteResolve, CilTreeGetResolveSuite());
    CuSuiteAddSuite(suiteBuild, CilTreeGetBuildSuite());

    CuSuiteRun(suite);
    CuSuiteSummary(suite, output);
    CuSuiteDetails(suite, output);
    printf("%s\n", output->buffer);

    CuSuiteRun(suiteResolve);
    CuSuiteSummary(suiteResolve, output);
    CuSuiteDetails(suiteResolve, output);
    printf("%s\n", output->buffer);

    CuSuiteRun(suiteBuild);
    CuSuiteSummary(suiteBuild, output);
    CuSuiteDetails(suiteBuild, output);
    printf("%s\n", output->buffer);
}

int main(__attribute__((unused)) int argc, __attribute__((unused)) char *argv[]) {
    RunAllTests();

    return 0;
}
