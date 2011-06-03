#include <stdio.h>
#include "CuTest.h"

CuSuite* CilTreeGetSuite();
CuSuite* CilTreeGetResolveSuite();
CuSuite* CilTreeGetBuildSuite();

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

int main() {
    RunAllTests();

    return 0;
}
