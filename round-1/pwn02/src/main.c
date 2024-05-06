#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>


#define MAX_CUSTOM_ANSWERS 0x20
#define MAX_CUSTOM_PROMPTS 0x10
#define PROMPT_SIZE 0x400
#define ANSWER_SIZE 0x200

unsigned int answer_used = 0;
unsigned int prompt_used = 0;
unsigned int max_count = 0;

struct Prompt {
  char* content;
  unsigned long long number_of_completions;
};


struct Answer {
  char* content;
};


void fatal(const char* fmt, ...) {
  perror(fmt);
  va_list args;
  va_start(args, fmt);
  vprintf(fmt, args);
  puts("");
  va_end(args);
  exit(-1);
}



void print_menu() {
  puts("1) Play");
  puts("2) Create custom card");
  puts("3) Show custom card");
  puts("4) Exit");
}


struct Prompt default_prompts[] = {
  { .number_of_completions = 1, .content = "Nothing better than ___ to start the party" },
  { .number_of_completions = 2, .content = "Man, I really wish that ___ could be replaced by ___" },
  { .number_of_completions = 1, .content = "If you want to make some angry, just ask him to ___" },
};


struct Answer default_answers[] = {
  { .content = "a salty webber" },
  { .content = "some cruncy compiler optimization" },
  { .content = "a very interesting user input reflection" },
  { .content = "page 706 of volume 2 of Intel x86 architecture manual" },
  { .content = "undefined behaviour" },
  { .content = "checking the boundaries" },
  { .content = "forgetting to remove debug symbols" },
  { .content = "the C programming language" },
  { .content = "blazing fast" },
  { .content = "spamming 'unsafe' in rust" },
  { .content = "find out that the linux manual lies too many times" },
  { .content = "a non random stack-protector" },
};

unsigned int total_prompts = sizeof(default_prompts) / sizeof(struct Prompt);
unsigned int total_answers = sizeof(default_answers) / sizeof(struct Answer);


int compute_score() {
  puts("WARN: Our score department is sleeping, we cannot give a reasonable score");
  return 3;
}

void play(struct Answer* answers, struct Prompt* prompts) {
  unsigned int choice = 0;
  int score = 0;
  struct Prompt* prompt = NULL;
  unsigned int prompt_choice = rand() % (total_prompts + prompt_used);

  if (prompt_choice < total_prompts) {
    prompt = &default_prompts[prompt_choice];
  } else {
    prompt = &prompts[prompt_choice - total_prompts];
  }

  printf("Completions: %llu\n%s\n", prompt->number_of_completions, prompt->content);

  for (unsigned int i = 0; i < total_answers; i++) {
    printf("%d: %s\n", i, default_answers[i].content);
  }
  for (unsigned int i = 0; i < answer_used; i++) {
    printf("%d: %s\n", i + total_answers, answers[i].content);
  }

  puts("What are your choices?");
  for (unsigned int i = 0; i < prompt->number_of_completions; i++) {
    if (scanf("%u", &choice) != 1) fatal("Scanf");
  }
  score = compute_score(prompt, &default_answers[choice]);

  printf("That's an insane score of %d! Go on, everybody is laughing\n", score);
}



void create_custom_card(struct Answer* answers, struct Prompt* prompts) {
  char c;
  int choice = 0;
  unsigned long long choice2 = 0;
  char* dest = NULL;
  char buf[PROMPT_SIZE - 0x20];
  puts("Answer (1) or prompt (2)?");
  if (scanf("%d", &choice) != 1) fatal("scanf");
  while ((c = getchar()) != '\n' && c != EOF);

  switch (choice) {
  case 1:
    if (answer_used >= MAX_CUSTOM_ANSWERS) {
      puts("Too many");
      return;
    }
    puts("Write your answer");
    dest = (char*) malloc(ANSWER_SIZE);
    if (dest == NULL) fatal("malloc");

    if (fgets(buf, ANSWER_SIZE, stdin) == NULL) fatal("fgets");
    answers[answer_used].content = dest;
    strncpy(dest, buf, ANSWER_SIZE);
    answer_used++;
    break;
  case 2:
    if (prompt_used >= MAX_CUSTOM_PROMPTS) {
      puts("Too many");
      return;
    }

    puts("Write your prompt");
    if (fgets(buf, PROMPT_SIZE + 1, stdin) == NULL) fatal("fgets");
    dest = (char*) malloc(PROMPT_SIZE);
    if (dest == NULL) fatal("malloc");
    prompts[prompt_used].content = dest;
    strncpy(dest, buf, PROMPT_SIZE);
    puts("How many completions?");
    if (scanf("%llu", &choice2) != 1) fatal("scanf");
    prompts[prompt_used].number_of_completions = choice2;
    prompt_used++;
    break;
  default:
    fatal("Invalid choice"); break;
  }
}

void show_custom_card(struct Answer* answers, struct Prompt* prompts) {
  int choice = 0;
  int choice2 = 0;

  puts("Answer (1) or prompt (2)?");
  if (scanf("%d", &choice) != 1) fatal("scanf");
  puts("Which one?");
  if (scanf("%d", &choice2) != 1) fatal("scanf");

  switch (choice) {
  case 1:
    printf("Answer: '%s'\n", answers[choice2].content);
    break;
  case 2:
    printf("Prompt (%llu completions): '%s'\n", prompts[choice2].number_of_completions, prompts[choice2].content);
    break;
  default:
    fatal("Invalid choice");
  }
}


void main_loop(struct Answer* custom_answers, struct Prompt* custom_prompts) {

  puts("Welcome to Cards Against Hackers TM");
  puts("Who will be the first to cross the line and `buttarla di fuori`?");


  int choice = 0;
  int cont = 1;

  while (max_count < 20 && cont) {
    max_count++;
    print_menu();

    if (scanf("%d", &choice) != 1) fatal("scanf");

    switch (choice) {
    case 1:
      play(custom_answers, custom_prompts);
      break;
    case 2:
      create_custom_card(custom_answers, custom_prompts);
      break;
    case 3:
      show_custom_card(custom_answers, custom_prompts);
      break;
    case 4:
      cont = 0;
      break;
    default:
      fatal("Invalid choice");
    }
  }
}

void initialize() {
  setvbuf(stdin, NULL, _IOLBF, 0);
  setvbuf(stdout, NULL, _IOLBF, 0);
  setvbuf(stderr, NULL, _IOLBF, 0);
}


int main() {
  struct Answer custom_answers[MAX_CUSTOM_ANSWERS];
  struct Prompt custom_prompts[MAX_CUSTOM_PROMPTS];

  initialize();

  main_loop(custom_answers, custom_prompts);
  return 0;
}
