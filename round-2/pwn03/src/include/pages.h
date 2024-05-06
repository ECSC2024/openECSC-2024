#include <stdint.h>

// Defines
#define MIN_SIZE  0x410
#define MAX_SIZE  0x900
#define MAX_PAGES 8
#define MAX_TITLE 0x400

// Typedefs
struct page {
    uint64_t size;
    char    *data;
    char     title[MAX_TITLE];
};

typedef struct page  page_t;
typedef struct page *page_p;

// Globals
extern page_p book[MAX_PAGES];

// Function prototypes
int  get_idx();
void add_page(void);
void edit_page(int idx);
void delete_page(int idx);
void merge_pages(int idx1, int idx2);
