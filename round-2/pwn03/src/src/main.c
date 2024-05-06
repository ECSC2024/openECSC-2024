#include "../include/pages.h"
#include "../include/utils.h"
#include <stdio.h>

// Global variables
page_p book[MAX_PAGES];

// Main
int main()
{
    uint64_t choice;
    int      idx, idx2;
    setup();

    print_banner();
    print_description();

    while (1) {
        print_menu();
        choice = get_num();

        switch (choice) {
        case 1:
            add_page();
            break;
        case 2:
            fputs("Index: ", stdout);
            idx = get_idx();
            edit_page(idx);
            break;
        case 3:
            fputs("Index: ", stdout);
            idx = get_idx();
            delete_page(idx);
            break;
        case 4:
            fputs("First index: ", stdout);
            idx = get_idx();
            fputs("Second index: ", stdout);
            idx2 = get_idx();
            merge_pages(idx, idx2);
            break;
        case 5:
            puts("Exiting...");
            return 0;
        default:
            printf("Invalid choice: %lu\n", choice);
            break;
        }
    }
}
