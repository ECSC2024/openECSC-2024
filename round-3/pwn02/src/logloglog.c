#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <pcre.h>


#define OVECCOUNT 9    /* should be a multiple of 3 */


__attribute__((noreturn))
void fatal(const char* fmt, ...) {
  perror(fmt);
  va_list args;
  va_start(args, fmt);
  vprintf(fmt, args);
  puts("");
  va_end(args);
  exit(-1);
}


enum LogLevel {
  Debug,
  Info,
  Warning,
  Error,
};

enum LogLevel GLOBAL_LOG_LEVEL = Info;
unsigned int OLD_LOG = 0;
char *default_log_format = "[%s-%s:%d] %s\n";
char custom_log_format[0x10];
char* LOG_FORMAT = NULL;
char log_msg_base[0x100];
char command[0x800];

char* llts(enum LogLevel lvl) {
  switch (lvl) {
  case Debug: {
    return "DBG";
  }
  case Info: {
    return "INFO";
  }
  case Warning: {
    return "WARN";
  }
  case Error: {
    return "ERR";
  }
  }
  fatal("Unknown log level: %d", lvl);
}


#define VA_ARGS(...) , ##__VA_ARGS__

#define LOG_SMTH(LEVEL, fmt, ...)                                       \
  if (LEVEL >= GLOBAL_LOG_LEVEL) {                                      \
    if (__LINE__ != OLD_LOG) {                                          \
      char* lk = llts(LEVEL);                                           \
      sprintf(log_msg_base, LOG_FORMAT, lk, __FILE__, __LINE__, fmt);   \
      OLD_LOG = __LINE__;                                               \
    }                                                                   \
    printf(log_msg_base VA_ARGS(__VA_ARGS__));                         \
  }

#define LOG_DEBUG(...) LOG_SMTH(Debug, __VA_ARGS__)
#define LOG_INFO(...)  LOG_SMTH(Info, __VA_ARGS__)
#define LOG_WARN(...) LOG_SMTH(Warning, __VA_ARGS__)
#define LOG_ERR(...) LOG_SMTH(Error, __VA_ARGS__)


void validate_log_format() {
  pcre *re;
  const char* error;
  int erroffset;
  int ovector[OVECCOUNT];
  int rc;


  re = pcre_compile(
  "%[#0\\- \\+'I][0-9]+",               /* the pattern */
  0,                                    /* default options */
  &error,                               /* for error message */
  &erroffset,                           /* for error offset */
  NULL);
  if (re == NULL) fatal("Failed compilation of regex");

  if (strstr(custom_log_format, "$") != NULL) fatal("no $ allowed");
  if (strstr(custom_log_format, "*") != NULL) fatal("no * allowed");

  rc = pcre_exec(re, NULL, custom_log_format, 0x10, 0, 0, ovector, OVECCOUNT);

  if (rc != PCRE_ERROR_NOMATCH) fatal("Invalid log format, aborting");
}



void change_log_format() {
  if (fgets(custom_log_format, 10, stdin) == NULL) fatal("fgets");
  LOG_DEBUG("Successfully read some bytes");
  validate_log_format();
  LOG_FORMAT = custom_log_format;
}


void change_log_level(char* newlvl) {
  LOG_DEBUG("Requesting log level change");
  if (!strcmp(newlvl, "debug")) {
    GLOBAL_LOG_LEVEL = Debug;
  } else if (!strcmp(newlvl, "info")) {
    GLOBAL_LOG_LEVEL = Info;
  } else if (!strcmp(newlvl, "warning")) {
    GLOBAL_LOG_LEVEL = Warning;
  } else if (!strcmp(newlvl, "error")) {
    LOG_WARN("Watch out, this is the last warning message you will see");
    GLOBAL_LOG_LEVEL = Error;
  } else {
    fatal("Unknown log level: '%s'", newlvl);
  }
}

void initialize() {
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
}


void calculator(char* operation, int arg1, int arg2) {
  int result;
  LOG_DEBUG("Requested operation '%s' with args %d %d", operation, arg1, arg2);
  if (!strcmp(operation, "add")) {
    result = arg1 + arg2;
  } else if (!strcmp(operation, "sub")) {
    result = arg1 - arg2;
  } else if (!strcmp(operation, "mul")) {
    result = arg1 * arg2;
  } else if (!strcmp(operation, "div")) {
    if (!arg2) {
      LOG_ERR("Bruh, really wanna do %d/%d?", arg1, arg2);
      return;
    }
    result = arg1 / arg2;
  }

  LOG_DEBUG("Computed operation with success! Result is: %d", result);
  printf("The result is: %d\n", result);
}

int main() {

  char cmd[64];
  char arg1[32];
  char arg2[32];
  char arg3[32];

  int cont = 1;
  int iarg1 = 0;
  int iarg2 = 0;


  GLOBAL_LOG_LEVEL = Debug;
  LOG_FORMAT = default_log_format;
  initialize();


  while (cont) {
    printf("> ");
    iarg1 = 0;
    iarg2 = 0;

    if (fgets(command, 0x800, stdin) == NULL) fatal("fgets");
    sscanf(command, "%63s %31s %31s %31s", cmd, arg1, arg2, arg3);

    iarg1 = atoi(arg2);
    iarg2 = atoi(arg3);

    if (!strcmp(cmd, "change_log_format")) {
      change_log_format();
      LOG_INFO("Changed log format to: '%s'", LOG_FORMAT);
    } else if (!strcmp(cmd, "reset_log_format")) {
      LOG_FORMAT = default_log_format;
      LOG_INFO("Reset log format to: '%s'", LOG_FORMAT);
    } else if (!strcmp(cmd, "change_log_level")) {
      change_log_level(arg1);
      char* lk = llts(GLOBAL_LOG_LEVEL);
      LOG_INFO("Log level changed to: %s", lk);

    } else if (!strcmp(cmd, "calculator")) {
      calculator(arg1, iarg1, iarg2);

    } else if (!strncmp(cmd, "save_and_exit", 13)) {
      cont = 0;
    } else {
      LOG_DEBUG("Invalid command tried: %s", cmd);
    }
  }

  return 0;
}
