#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "dl-minimal-malloc.h"
#include "object.h"

static void parse_properties(char *out, const char *in) {
	char *p = out;
	size_t off = 0;

	strcpy(out, in);

	while (true) {
		char *name = p;
		size_t len = 0;

		// First, find where the name ends.
		while (p[len] != '=' && p[len] != ';' && p[len] != '\0')
			len++;

		// If we reach the end of the string before getting a valid name-value pair, bail out.
		if (p[len] == '\0') {
			out[off] = '\0';
			return;
		}

		// We did not find a valid name-value pair before encountering a separator.
		if (p[len]== ';') {
			p += len + 1;
			continue;
		}

		p += len + 1;

		// Take the value from the valstring since we need to NUL terminate it.
		const char *value = &in[p - out];
		len = 0;

		while (p[len] != ';' && p[len] != '\0')
			len++;

		if (off > 0)
			out[off++] = '\0';

		while (*name != '=')
			out[off++] = *name++;
		out[off++] = '\0';

		for (size_t j = 0; j < len; j++)
			out[off++] = value[j];

		// BUG: if the end is reached we should stop processing the string here.
		// Instead, we keep going without incrementing p, so in the case of a
		// string of the form "AAA=BBB=CCC" we copy the whole string to out,
		// then we get here with p pointing after the first '=', and in the next
		// iteration we copy "BBB=CCC" to out again.
		if (p[len] != '\0')
			p += len + 1;
	}
}

struct object *obj_new(void) {
	return calloc(1, sizeof(struct object));
}

struct object *obj_set_properties(struct object *obj, char *raw_properties) {
	size_t new_size = strlen(raw_properties) + 1;

	if (obj->size < new_size) {
		obj = realloc(obj, sizeof(*obj) + new_size);
		if (obj == NULL)
			return NULL;

		obj->size = new_size;
	}

	parse_properties(obj->properties, raw_properties);
	return obj;
}

void obj_print(const struct object *obj) {
	char *cur = (char *)obj->properties;

	if (obj->size == 0) {
		puts("{}");
		return;
	}

	puts("{");

	while (cur < obj->properties + obj->size) {
		size_t name_len = strlen(cur);
		char *value = cur + name_len + 1;
		size_t value_len = strlen(value);

		printf("\t\"%.*s\": \"%.*s\",\n", (int)name_len, cur, (int)value_len, value);
		cur += name_len + 1 + value_len + 1;
	}

	puts("}");
}

void obj_free(struct object *obj) {
	free(obj);
}
