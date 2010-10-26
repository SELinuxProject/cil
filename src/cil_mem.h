#ifndef CIL_MEM_H_
#define CIL_MEM_H_

/* Wrapped malloc that catches errors and calls the error callback */
void *cil_malloc(size_t size);
void *cil_strdup(char *);
void cil_set_malloc_error_handler(void (*handler)());

#endif /* CIL_MEM_H_ */

