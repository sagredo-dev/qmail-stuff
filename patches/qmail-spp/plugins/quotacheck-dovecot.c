/*
 * Copyright (c) 2016, Manuel Mausz <manuel at mausz dot at>,
 * All rights reserved.
 *
 * Some maildir specified code is copied from dovecot (dovecot.org),
 * Copyright by Timo Sirainen <tss at iki dot fi> (and others).
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301 USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>

#define LOGPREFIX "QUOTA: "

typedef struct
{
  const char *action, *msg;
} policy_reply;

int check_parent(void)
{
  /* check parent */
  pid_t parent = getppid();
  char buf[256];
  int num = snprintf(buf, sizeof(buf), "/proc/%d/exe", parent);
  if (num < 0 || num > sizeof(buf))
  {
    (void)fprintf(stderr, LOGPREFIX "Unable to copy string to buffer\n");
    return 0;
  }

  char buf2[256];
  num = readlink(buf, buf2, sizeof(buf2));
  if (num < 0)
  {
    (void)fprintf(stderr, LOGPREFIX "Unable to read parent from proc-fs: %m\n");
    return 0;
  }
  buf2[num] = '\0';

  const char *smtpbin = "/var/qmail/bin/qmail-smtpd";
  if (strcmp(smtpbin, buf2) != 0)
  {
    (void)fprintf(stderr, LOGPREFIX "Parent \"%s\" doesn't match qmail-smtp\n", buf2);
    return 0;
  }

  return 1;
}

static int net_connect_inet(const char *host, const char *port)
{
  struct addrinfo hints = {
    .ai_family = AF_UNSPEC,
    .ai_socktype = SOCK_STREAM
  };
  struct addrinfo *result;

  int s = getaddrinfo(host, port, &hints, &result);
  if (s != 0)
  {
    (void)fprintf(stderr, LOGPREFIX "getaddrinfo: %s\n", gai_strerror(s));
    return -1;
  }

  //FIXME: connect might hang
  int sockfd = -1;
  struct addrinfo *r;
  for (r = result; r != NULL; r=r->ai_next)
  {
    sockfd = socket(r->ai_family, r->ai_socktype | SOCK_CLOEXEC,
      r->ai_protocol);
    if (sockfd == -1)
      continue;
    if (connect(sockfd, r->ai_addr, r->ai_addrlen) != -1)
      break; /* success */
    (void)close(sockfd);
    sockfd = -1;
    break; /* we only try the first record */
  }

  (void)freeaddrinfo(result);
  return sockfd;
}

static int net_connect_unix(const char *path)
{
  int sockfd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (sockfd < 0)
    return -1;

  struct sockaddr_un saddr;
  saddr.sun_family = AF_UNIX;
  (void)strcpy(saddr.sun_path, path);
  int conn = connect(sockfd, (struct sockaddr *)&saddr, sizeof(saddr));
  if (conn != -1)
    return sockfd;
  (void)close(sockfd);
  return -1;
}

static int net_connect(const char *uri, bool readenv)
{
  int sockfd = -1;
  if (strncmp(uri, "tcp://", strlen("tcp://")) == 0)
  {
    char *path = strdup(uri + strlen("tcp://"));

    char *portptr = strrchr(path, ':');
    if (portptr == NULL)
    {
      (void)fprintf(stderr, LOGPREFIX "Invalid uri: port missing?\n");
      (void)free(path);
      return -1;
    }
    *portptr = '\0';

    char *host = path;
    if (host[0] == '[' && *(portptr - 1) == ']')
    {
      host++;
      *(portptr - 1) = '\0';
    }

    sockfd = net_connect_inet(host, portptr + 1);
    (void)free(path);
  }
  else if (strncmp(uri, "unix://", strlen("unix://")) == 0)
    sockfd = net_connect_unix(uri + strlen("unix://"));
  else if (readenv && strncmp(uri, "env://", strlen("env://")) == 0)
  {
    if ((uri = getenv(uri + strlen("env://"))) != NULL)
      return net_connect(uri, false);
    (void)fprintf(stderr, LOGPREFIX "Invalid uri: env var undefined\n");
    return -1;
  }
  else
  {
    (void)fprintf(stderr, LOGPREFIX "Invalid uri: unknown syntax\n");
    return -1;
  }

  if (sockfd < 0)
    (void)fprintf(stderr, LOGPREFIX "Unable to connect to socket: %m\n");
  return sockfd;
}

static const policy_reply policy_check(const char *uri, const char *format, ...)
{
  policy_reply reply = { .action = NULL, .msg = NULL };

  /* connect to policy server */
  int sockfd = net_connect(uri, true);
  if (sockfd < 0)
    goto end;

  /* send data */
  va_list ap;
  va_start(ap, format);
  (void)vdprintf(sockfd, format, ap);
  (void)dprintf(sockfd, "\n");
  va_end(ap);
  if (errno)
  {
    (void)fprintf(stderr, LOGPREFIX "Error while sending to policy server: %m\n");
    goto end;
  }

  /* wait for reply */
  static char buf[2048];
  ssize_t read = recv(sockfd, &buf, sizeof(buf) - 1, 0);
  if (read <= 0)
  {
    (void)fprintf(stderr, LOGPREFIX "Error while receiving from policy server: %m\n");
    goto end;
  }

  /* parse reply */
  if (read < strlen("action=") + 3 /* 1x reply char + 2x LF */
      || strncmp("action=", buf, strlen("action=")) != 0
      || buf[read - 2] != '\n')
  {
    (void)fprintf(stderr, LOGPREFIX "Uknown reply format from policy server\n");
    goto end;
  }
  buf[read - 2] = '\0';

  reply.action = buf + strlen("action=");
  char *msgptr = strchr(reply.action, ' ');
  if (msgptr)
  {
    *msgptr = '\0';
    reply.msg = ++msgptr;
  }

end:
  (void)close(sockfd);
  return reply;
}

int main(int argc, char *argv[])
{
  if (argc != 2)
    return 0;

  const char *username = getenv("DTUSER");
  if (!username)
    return 0;

  /* check parent */
  if (!check_parent())
    return 0;

  // size not exported by qmail (at least for now)
  // assume a minimum size of 500 bytes
  size_t size = 500;

  const policy_reply reply = policy_check(argv[1],
      "recipient=%s\nsize=%zu\n", username, size);
  if (reply.action == NULL)
    return 0;

  if (*reply.action == '5' || *reply.action == '4'
      || strcmp(reply.action, "REJECT") == 0)
  {
    const char *code = (*reply.action == '5' || *reply.action == '4')
      ? reply.action : "552";
    const char *msg = (reply.msg) ? reply.msg : "User over quota. (#5.2.2)";
    (void)fprintf(stderr, LOGPREFIX "User \"%s\" is over quota.\n", username);
    (void)printf("E%s %s\n", code, msg);
  }
  else if (strcmp(reply.action, "OK") == 0
      || strcmp(reply.action, "DUNNO") == 0)
    { ; } /* nothing here */
  else
  {
    (void)fprintf(stderr, LOGPREFIX "Unsupported reply from policy server:"
        " reply=%s msg=%s\n", reply.action, (reply.msg) ? reply.msg : "NULL");
  }

  return 0;
}
