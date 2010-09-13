#include <stdio.h>
#include "CuTest.h"

CuSuite* CilTreeGetSuite();

void RunAllTests(void) {
    CuString *output  = CuStringNew();
    CuSuite* suite = CuSuiteNew();

    CuSuiteAddSuite(suite, CilTreeGetSuite());

    CuSuiteRun(suite);
    CuSuiteSummary(suite, output);
    CuSuiteDetails(suite, output);
    printf("%s\n", output->buffer);
}

int main() {
    RunAllTests();

    return 0;
}
