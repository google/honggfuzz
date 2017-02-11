#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>

#define EXPORT   __attribute__((visibility("default")))
#define NOINLINE __attribute__ ((noinline))

EXPORT NOINLINE void crash()
{
  char src[128];
  char dst[2];
  memcpy(src, dst, 8192);
}

EXPORT NOINLINE void func1()
{
  printf("func1\n");
  crash();
}

EXPORT NOINLINE void func2() 
{
  printf("func2\n");
  crash();
}

EXPORT NOINLINE void driver()
{
  srand(time(0));
  sleep(1);
  if (rand() % 2 == 1) func1();
  else func2();
}

int main(int argc, char ** argv)
{
  driver();
  return 0;
}

