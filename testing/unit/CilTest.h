#ifndef CILTEST_H_
#define CILTEST_H_

// TODO Check more in the data structures
struct cil_file_data {
	char *buffer;
	uint32_t file_size;
};

void set_cil_file_data(struct cil_file_data **);

#endif
