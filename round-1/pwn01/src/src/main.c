#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dl-minimal-malloc.h"
#include "object.h"
#include "seccomp.h"

#define MAX_PROPERTIES_SZ 0x1000

static struct object *head;
static char properties[MAX_PROPERTIES_SZ];

static void print_help(void) {
	fputs(
		"Available commands:\n"
		"\tn) New object\n"
		"\ts) Set object properties\n"
		"\tp) Print object\n"
		"\tz) Get object size\n"
		"\td) Delete object\n"
		"\th) Help\n"
		"\te) Exit\n\n",
		stdout
	);

	fflush(stdout);
}

static unsigned get_index(void) {
	unsigned res;

	fputs("Index: ", stdout);
	fflush(stdout);

	if (scanf("%u%*c", &res) != 1)
		exit(1);

	return res;
}

static void set_head_properties(void) {
	struct object *new;
	char *nl;

	puts("Properties (format: foo=bar;baz=123;...):");
	fflush(stdout);

	if (!fgets(properties, sizeof(properties), stdin))
		exit(1);

	nl = strchr(properties, '\n');
	if (nl)
		*nl = '\0';

	new = obj_set_properties(head, properties);
	if (new == NULL) {
		puts("Cannot edit this object!");
		return;
	}

	head = new;
}

static struct object *get_obj_at_index(unsigned idx) {
	struct object *o = head;

	for (unsigned i = 0; o && i < idx; i++) {
		if (o->size > 0x10000) {
			fputs("Bad object size!", stderr);
			exit(1);
		}

		o = o->next;
	}

	return o;
}

static struct object **get_obj_ref_at_index(unsigned idx) {
	struct object *o = head;

	if (idx == 0 && head)
		return &head;

	for (unsigned i = 0; o && i < idx - 1; i++) {
		if (o->size > 0x10000) {
			fputs("Bad object size!", stderr);
			exit(1);
		}

		o = o->next;
	}

	return o ? &o->next : NULL;
}

static void print_obj_at_index(unsigned idx) {
	struct object *o = get_obj_at_index(idx);

	if (!o) {
		puts("Invalid index");
		return;
	}

	obj_print(o);
}

static void get_obj_size_at_index(unsigned idx) {
	struct object *o = get_obj_at_index(idx);

	if (!o) {
		puts("Invalid index");
		return;
	}

	printf("%zu\n", o->size);
}

static void del_obj_at_index(unsigned idx) {
	struct object **o = get_obj_ref_at_index(idx);
	struct object *tmp;

	if (!o) {
		puts("Invalid index");
		return;
	}

	tmp = *o;
	*o = tmp->next;
	obj_free(tmp);
}

int main(void) {
	struct object *o;
	int choice;

	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
	init_seccomp();

	print_help();

	while (1) {
		fputs("> ", stdout);
		fflush(stdout);

		choice = getchar();
		if (choice == EOF)
			break;

		getchar();

		switch (choice) {
		case 'n':
			o = head;
			head = obj_new();
			head->next = o;
			break;

		case 's':
			set_head_properties();
			break;

		case 'p':
			print_obj_at_index(get_index());
			break;

		case 'z':
			get_obj_size_at_index(get_index());
			break;

		case 'd':
			del_obj_at_index(get_index());
			break;

		case 'h':
			print_help();
			break;

		case 'e':
			goto out;

		default:
			puts("Invalid choice");
			break;
		}
	}

out:
	return 0;
}
