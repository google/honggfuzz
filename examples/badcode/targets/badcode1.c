#include <stdio.h>
#include <stdlib.h>

int output(char * filename)
{
  FILE * fp;
  char str[64];

  if((fp = fopen(filename, "r")) == NULL) {
    printf("Cannot open file %s.\n", filename);
    return 1;
  }

  while(!feof(fp)) {
    if(fgets(str, 128, fp)) {
      printf("%s", str);
    }
  }

  fclose(fp);
  return 0;
}

           
       

int main(int argc, char ** argv)
{
  if(argc < 2)
  {
    printf("Syntax: %s <input file>\n", argv[0]);
    exit(1);
  }
  return output(argv[1]);
}

