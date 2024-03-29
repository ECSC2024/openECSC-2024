#pragma once

#include <stdbool.h>
#include <stdint.h>

struct object {
	size_t size;
	struct object *next;
	char properties[];
};

struct object *obj_new(void);
struct object *obj_set_properties(struct object *obj, char *raw_properties);
void obj_print(const struct object *obj);
void obj_free(struct object *obj);
