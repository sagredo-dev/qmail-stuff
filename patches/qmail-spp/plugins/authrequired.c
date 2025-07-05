/*
 *
 * Tomislav Randjic 20060929
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int main()
{
  char *user = getenv("SMTPAUTHUSER");
  pid_t ppid = getppid();

  if (user == NULL || strlen(user) == 0)
  {
    puts("E550 SMTP AUTH required");
    fprintf(stderr, "authrequired: pid %d - message rejected, SMTP AUTH required.\n", ppid);
  }
  return 0;
}
