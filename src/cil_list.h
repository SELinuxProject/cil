#ifndef CIL_LIST_H_
#define CIL_LIST_H_

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

struct cil_list {
	struct cil_list_item *head;
};

struct cil_list_item {
	struct cil_list_item *next;
	uint32_t flavor;
	void *data;
};

int cil_list_init(struct cil_list **);
void cil_list_destroy (struct cil_list **, uint8_t);
int cil_list_item_init(struct cil_list_item **);
void cil_list_item_destroy(struct cil_list_item **, uint8_t);

#endif
