#ifndef CILTEST_H_
#define CILTEST_H_

#include "../../src/cil_tree.h"

// TODO Check more in the data structures
struct cil_file_data {
	char *buffer;
	uint32_t file_size;
};

void set_cil_file_data(struct cil_file_data **);
void gen_test_tree(struct cil_tree **, char **);
 
#endif
