#pragma once
#include <stddef.h>

void *__minimal_malloc (size_t n);
void *__minimal_calloc (size_t nmemb, size_t size);
void *__minimal_realloc (void *ptr, size_t n);
void __minimal_free (void *ptr);

#define malloc  __minimal_malloc
#define calloc  __minimal_calloc
#define realloc __minimal_realloc
#define free    __minimal_free
