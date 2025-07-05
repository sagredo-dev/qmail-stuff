#include <stdio.h>
#include <stdlib.h>

int main()
{
  const char *remote_host = getenv("TCPREMOTEHOST");

  if (remote_host == NULL)
  {
    const char *remote_ip = getenv("TCPREMOTEIP");
    (void)printf("E550 Reverse DNS validation for %s failed (#5.7.25)\n", remote_ip);
    (void)fprintf(stderr, "DNS: %s: reverse DNS failed\n", remote_ip);
  }
  return 0;
}
