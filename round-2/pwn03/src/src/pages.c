#include "../include/pages.h"
#include "../include/utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int get_idx()
{
    int idx;

    idx = (int)get_num();
    if (idx < 0 || idx >= MAX_PAGES) {
        puts("Invalid index!");
        puts("Hey! I'm blind not dumb...\nGoodbye!");
        exit(-1);
    }
    return idx;
}

void add_page()
{
    int    idx;
    size_t size, len;

    for (idx = 0; idx < MAX_PAGES; idx++) {
        if (book[idx] == NULL) {
            break;
        }
    }
    if (idx == MAX_PAGES) {
        puts("Book is full!");
        return;
    }

    fputs("Size: ", stdout);
    size = get_num();

    if (size < MIN_SIZE || size > MAX_SIZE) {
        puts("Invalid size!");
        return;
    }

    page_p page = malloc(sizeof(*page));
    if (page == NULL) {
        puts("malloc() failed!");
        return;
    }
    page->data = malloc(size);
    if (page->data == NULL) {
        puts("malloc() failed!");
        free(page);
        return;
    }

    fputs("Title: ", stdout);
    len = read(0, page->title, sizeof(page->title));
    if (page->title[len - 1] == '\n') {
        page->title[len - 1] = '\0';
    }

    fputs("Data: ", stdout);
    page->size = size;
    len        = read(0, page->data, size);
    if (page->data[len - 1] == '\n') {
        page->data[len - 1] = '\0';
    }

    book[idx] = page;
}

void edit_page(int idx)
{
    page_p page = NULL;
    size_t len;

    if ((page = book[idx]) == NULL) {
        puts("No page at this index!");
        return;
    }

    fputs("Data: ", stdout);
    len = read(0, page->data, page->size);
    if (page->data[len - 1] == '\n') {
        page->data[len - 1] = '\0';
    }
}

void delete_page(int idx)
{
    page_p page = NULL;

    if ((page = book[idx]) == NULL) {
        puts("No page at this index!");
        return;
    }

    free(page->data);
    free(page);

    book[idx] = NULL;
}

void merge_pages(int idx1, int idx2)
{
    size_t size1, size2;

    if (idx1 == idx2) {
        puts("Invalid index!");
        return;
    }

    page_p page1 = book[idx1];
    page_p page2 = book[idx2];

    if (page1 == NULL || page2 == NULL) {
        puts("No page at this index!");
        return;
    }

    size1 = strlen(page1->data);
    size2 = strlen(page2->data);

    if (page1->size < size1 + size2) {
        puts("Page is too small!");
        return;
    }

    strcat(page1->data, page2->data);
    delete_page(idx2);
}
