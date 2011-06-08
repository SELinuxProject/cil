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

char *cil_strdup(char *str)
{
	if (str == NULL)
		return NULL;
	char *mem = strdup(str);
	if (mem == NULL) 
		(*cil_malloc_error_handler)();
	return mem;
}

