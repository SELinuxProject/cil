#include <stdlib.h>
#include <stdio.h>
#include <string.h>

__attribute__((noreturn)) void cil_default_malloc_error_handler()
{
	fprintf(stderr, "Unable to proceed, failed to allocate memory\n");
	exit(1);
}

static void (*cil_malloc_error_handler)() = &cil_default_malloc_error_handler;

void cil_set_malloc_error_handler(void (*handler)())
{
	cil_malloc_error_handler = handler;
}

void *cil_malloc(size_t size)
{
	void *mem = malloc(size);
	if (mem == NULL){
		if (size == 0)
			return NULL;
		(*cil_malloc_error_handler)();
	}
	return mem;
}

void *cil_strdup(char *str)
{
	if (str == NULL)
		return NULL;
	void *mem = strdup(str);
	if (mem == NULL) 
		(*cil_malloc_error_handler)();
	return mem;
}

