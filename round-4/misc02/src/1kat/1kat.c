#include <stdio.h>

int main(int argc, char **argv)
{
  printf("Usage: 1kat file\nReads the first kB of file\n");

  if (argc != 2)
  {
    printf("Please provide a file to read and nothing more\n");
    return 1;
  }

  FILE *f = fopen(argv[1], "r");
  if (f == NULL)
  {
    printf("File not found!\n");
    return 1;
  }

  char buffer[1024];
  size_t bytesRead = fread(buffer, 1, 1024, f);
  if (bytesRead == 0)
  {
    printf("Could not read the file\n");
    return 1;
  }

  for (size_t i = 0; i < bytesRead; i++)
  {
    printf("%c", buffer[i]);
  }
}