/* Adapted from glibc's elf/dl-minimal-malloc.c */

#include <assert.h>
#include <string.h>

#include <inttypes.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/user.h>
#define MALLOC_ALIGNMENT 16

#include "dl-minimal-malloc.h"

static char *alloc_ptr, *alloc_end, *alloc_last_block;

// Limit things just to avoid OOM
static size_t max_total_size = 0x10000;

/* Allocate an aligned memory block.  */
void *
__minimal_malloc (size_t n)
{
  if (max_total_size < n) {
    fputs("Out of memory!", stderr);
    exit(1);
  }

  max_total_size -= n;

  /* Make sure the allocation pointer is ideally aligned.  */
  alloc_ptr = (char *) 0 + ((((uintptr_t) alloc_ptr) + MALLOC_ALIGNMENT - 1)
			    & ~(MALLOC_ALIGNMENT - 1));

  if (alloc_ptr + n >= alloc_end || n >= -(uintptr_t) alloc_ptr)
    {
      /* Insufficient space left; allocate another page plus one extra
	 page to reduce number of mmap calls.  */
      char *page;
      size_t nup = (n + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
      if (__builtin_expect (nup == 0 && n != 0, 0))
	return NULL;
      nup += PAGE_SIZE;
      page = mmap (NULL, nup, PROT_READ|PROT_WRITE,
		     MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
      if (page == MAP_FAILED)
	return NULL;
    //   __set_vma_name (page, nup, " glibc: loader malloc");
      if (page != alloc_end)
	alloc_ptr = page;
      alloc_end = page + nup;
    }

  alloc_last_block = (void *)alloc_ptr;
  alloc_ptr += n;
  return alloc_last_block;
}

/* We use this function occasionally since the real implementation may
   be optimized when it can assume the memory it returns already is
   set to NUL.  */
void *
__minimal_calloc (size_t nmemb, size_t size)
{
  /* New memory from the trivial malloc above is always already cleared.
     (We make sure that's true in the rare occasion it might not be,
     by clearing memory in free, below.)  */
  size_t bytes = nmemb * size;

#define HALF_SIZE_T (((size_t) 1) << (8 * sizeof (size_t) / 2))
  if (__builtin_expect ((nmemb | size) >= HALF_SIZE_T, 0)
      && size != 0 && bytes / size != nmemb)
    return NULL;

  return __minimal_malloc (bytes);
}

/* This will rarely be called.  */
void
__minimal_free (void *ptr)
{
  /* We can free only the last block allocated.  */
  if (ptr == alloc_last_block)
    {
      /* Since this is rare, we clear the freed block here
	 so that calloc can presume malloc returns cleared memory.  */
      memset (alloc_last_block, '\0', alloc_ptr - alloc_last_block);
      alloc_ptr = alloc_last_block;
    }
}

/* This is only called with the most recent block returned by malloc.  */
void *
__minimal_realloc (void *ptr, size_t n)
{
  if (ptr == NULL)
    return __minimal_malloc (n);
  assert (ptr == alloc_last_block);
  size_t old_size = alloc_ptr - alloc_last_block;
  alloc_ptr = alloc_last_block;
  void *new = __minimal_malloc (n);
  return new != ptr ? memcpy (new, ptr, old_size) : new;
}
