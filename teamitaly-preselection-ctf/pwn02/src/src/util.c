/**
 * @mebeim - 2024-06-10
 */

#include <stdio.h>
#include <stdlib.h>

#include "util.h"

void die(const char *msg) {
	puts(msg);
	fflush(stdout);
	exit(1);
}
