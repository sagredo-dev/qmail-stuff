/*
 *
 * Tomislav Randjic 20060926
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main()
{
  char *user = getenv("SMTPAUTHUSER");

  if (user != NULL && strlen(user) > 0)
    puts("N");
  return 0;
}
