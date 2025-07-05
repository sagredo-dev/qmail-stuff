/*
 * Copyright (C) 2006-2015 Manuel Mausz (manuel@mausz.at)
 * Origin code copyright (c) mjd@digitaleveryware.com 2003
 *  (http://www.digitaleveryware.com/projects/greylisting/)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#define _BSD_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <mysql.h>
#include <stdbool.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

/*
 * 0 ... query does an exact ip match
 * 1 ... query matches anything in the same subnet (ipv4=/24, ipv6=/64)
 */
#define IPMATCH_RANGE 1

#define SQLCMDSIZE     2048
#define GL_NOTFOUND    0
#define GL_ACCEPT      1
#define GL_REJECT      2
#define GL_TEMPREJECT  3
#define CMD_TEMPREJECT "E451 temporary failure (#4.3.0)\n"
#define CMD_REJECT     "E553 sorry, your envelope sender has been denied (#5.7.1)\n"
#define LOGLEVEL_FATAL 1
#define LOGLEVEL_ERROR 2
#define LOGLEVEL_WARN  3
#define LOGLEVEL_INFO  4
#define LOGLEVEL_DEBUG 5
#define MAXCONFIGLINESIZE 1024 // change this to dynamic allocation sometime
#define QUERYSIZE 500
#define V4MAPPREFIX    "::ffff:"

#if MYSQL_VERSION_ID < 50603
# error "MySQL 5.6.3 or above required"
#endif

static char *configfile = "control/greylisting";
static char *mysql_default_file = NULL;
unsigned int block_expire  = 55;
unsigned int record_expire = 500;
unsigned int record_expire_good = 36;
static int loglevel = LOGLEVEL_WARN;
static char explicit = 0;

static char *relay_ip;
static char *mail_from;
static char *rcpt_to;
bool ipv6;

static inline char tohex(char c)
{
  return (c >= 10) ? c - 10 + 'a' : c + '0';
}

void gllog(unsigned int level,  char* format, ...)
{
  va_list args;
  if (level > loglevel)
    return;
  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);
}

int load_config(void)
{
  char *tmp, *delim, *atpos;
  FILE *config;
  char buf[MAXCONFIGLINESIZE];
  int i;
  unsigned int userlen;

  /* first check for logging var */
  tmp = getenv("GLLOGLEVEL");
  if (tmp)
    loglevel = atoi(tmp);

  /* check if greylisting is enabled */
  if (!getenv("GREYLISTING") || getenv("RELAYCLIENT"))
  {
    gllog(LOGLEVEL_DEBUG, "greylisting: greylisting is not enabled\n");
    return 0;
  }

  /* basic environment variables needed */
  relay_ip  = getenv("TCPREMOTEIP");
  mail_from = getenv("SMTPMAILFROM");
  rcpt_to   = getenv("SMTPRCPTTO");
  if (!relay_ip || !mail_from || !rcpt_to)
  {
    gllog(LOGLEVEL_FATAL, "greylisting: one of the following envvars is undefined: TCPREMOTEIP, SMTPMAILFROM, SMTPRCPTTO\n");
    return 0;
  }

  /* check for ipv4 mapped ipv6 address */
  ipv6 = false;
  tmp = getenv("PROTO");
  if (tmp && !strcmp(tmp, "TCP6"))
  {
    if (!strncmp(relay_ip, V4MAPPREFIX, strlen(V4MAPPREFIX)))
      relay_ip += strlen(V4MAPPREFIX);
    else
      ipv6 = true;
  }

  /* check for BATV ("prvs=X=u@d.t" minimum) */
  if (strlen(mail_from) > 11
      && mail_from[0] == 'p' && mail_from[1] == 'r' && mail_from[2] == 'v'
      && mail_from[3] == 's' && mail_from[4] == '=')
  {
    /* BATV: prvs=HASH=user@domain.tld */
    if ((delim = strchr(mail_from + 5, '=')))
      mail_from = delim + 1;
    /* BATV: prvs=user/HASH@domain.tld */
    else if ((delim = strchr(mail_from + 5, '/')) && (atpos = strchr(delim, '@')))
    {
      userlen = delim - mail_from - 5;
      memmove(atpos - userlen, mail_from + 5, userlen);
      mail_from = atpos - userlen;
    }
  }

  /* avoid buffer overflows (max. query is ~410 chars long) */
  if (strlen(relay_ip) + strlen(mail_from) + strlen(rcpt_to) > SQLCMDSIZE - QUERYSIZE)
  {
    gllog(LOGLEVEL_FATAL, "greylisting: buffer overflow protection occurs\n");
    return 0;
  }

  /* fetch config file path */
  tmp = getenv("GLCONFIGFILE");
  if (tmp)
    configfile = tmp;

  /* fetch config file content */
  gllog(LOGLEVEL_DEBUG, "greylisting: configfile=%s\n", configfile);
  config = fopen(configfile, "r");
  if (!config)
    gllog(LOGLEVEL_DEBUG, "greylisting: configfile error: %s\n", strerror(errno));
  else
  {
    while((tmp = fgets(buf, sizeof(buf), config)))
    {
      if (buf[0] == '#' || buf[0] == ';')
        continue;
      for(i = 0; i < strlen(buf) && buf[i] != '\r' && buf[i] != '\n'; i++);
      buf[i] = 0;
      if (strstr(tmp, "mysql_default_file=") == tmp)
      {
        free(mysql_default_file);
        mysql_default_file = strdup(tmp + strlen("mysql_default_file="));
      }
      else if (strstr(tmp, "block_expire=") == tmp)
        block_expire = atoi(tmp + strlen("block_expire="));
      else if (strstr(tmp, "record_expire=") == tmp)
        record_expire = atoi(tmp + strlen("record_expire="));
      else if (strstr(tmp, "record_expire_good=") == tmp)
        record_expire_good = atoi(tmp + strlen("record_expire_good="));
      else if (strstr(tmp, "loglevel=") == tmp && !getenv("GLLOGLEVEL"))
        loglevel = atoi(tmp + strlen("loglevel="));
      else if (strstr(tmp, "explicit=") == tmp)
        explicit = (atoi(tmp + strlen("explicit=")) != 0);
    }
    fclose(config);
  }

  /* environment variables */
  tmp = getenv("GLMYSQLDEFAULTFILE");
  if (tmp)
  {
    free(mysql_default_file);
    mysql_default_file = strdup(tmp);
  }

  tmp = getenv("GLBLOCKEXPIRE");
  if (tmp)
    block_expire = atoi(tmp);

  tmp = getenv("GLRECORDEXPIRE");
  if (tmp)
    record_expire = atoi(tmp);

  tmp = getenv("GLRECORDEXPIREGOOD");
  if (tmp)
    record_expire_good = atoi(tmp);

  tmp = getenv("GLEXPLICIT");
  if (tmp)
    explicit = (atoi(tmp) != 0);

  /* logging */
  gllog(LOGLEVEL_DEBUG, "greylisting: mysql: default_file=%s\n",
      mysql_default_file);
  gllog(LOGLEVEL_DEBUG, "greylisting: block_expire=%d, record_expire=%d, record_expire_good=%d\n",
      block_expire, record_expire, record_expire_good);
  if (explicit)
    gllog(LOGLEVEL_DEBUG, "greylisting: explicit mode enabled\n");
  return 1;
}

void cleanup()
{
  free(mysql_default_file);
}

int mysql_query_wrapper(MYSQL *mysql, char *query)
{
  int result = mysql_query(mysql, query);
  gllog(LOGLEVEL_DEBUG, "greylisting: mysql: %s - ret=%d\n", query, result);
  return result;
}

/* check if relay_ip or rcpt_to is white-/blacklisted */
int check_listed(MYSQL *mysql)
{
  char query[SQLCMDSIZE];

  char *domain = strrchr(rcpt_to, '@');
  /* fallback to full rcpt_to if there's no domain */
  domain = (domain) ? domain + 1 : rcpt_to;
  char *domain_esc = malloc(strlen(domain)*2 + 1);
  mysql_real_escape_string(mysql, domain_esc, domain, strlen(domain));

  sprintf(query,
    "SELECT `id`, `block_expires` >= UTC_TIMESTAMP(), `block_expires` < UTC_TIMESTAMP(), `rcpt_to` "
    "FROM `greylisting_lists` "
    "WHERE `record_expires` > UTC_TIMESTAMP() "
    "AND ( "
      "INET6_ATON('%s') BETWEEN `ipaddr_start` AND `ipaddr_end` "
      "OR "
      "`rcpt_to` = '%s' "
    ") "
    "ORDER BY `rcpt_to` ASC, `ipaddr_prefixsize` DESC "
    "LIMIT 1", relay_ip, domain_esc);
  free(domain_esc);

  MYSQL_RES *res;
  if (mysql_query_wrapper(mysql, query) ||
      !(res = mysql_store_result(mysql)))
  {
    gllog(LOGLEVEL_ERROR, "greylisting: mysql: %s\n", mysql_error(mysql));
    return GL_NOTFOUND;
  }

  MYSQL_ROW row;
  int retval = GL_NOTFOUND;
  if ((row = mysql_fetch_row(res)))
  {
    if (atoi(row[1]))
    {
      retval = GL_REJECT;
      gllog(LOGLEVEL_INFO, "greylisting: %s/%s is blacklisted (id=%s) - rejecting\n",
          relay_ip, domain, row[0]);
    }
    else if ((!explicit && atoi(row[2])) || (explicit && !row[3]))
    {
      retval = GL_ACCEPT;
      gllog(LOGLEVEL_INFO, "greylisting: %s/%s is whitelisted (id=%s) - accepting\n",
          relay_ip, domain, row[0]);
    }
    else if (explicit)
    {
      retval = GL_NOTFOUND;
      gllog(LOGLEVEL_DEBUG, "greylisting: enabled for %s (id=%s)\n", domain,
          row[0]);
    }
  }
  else if (explicit)
  {
    retval = GL_ACCEPT;
    gllog(LOGLEVEL_DEBUG, "greylisting: disabled for %s - accepting\n", domain);
  }
  mysql_free_result(res);

  return retval;
}

int check_greylisted(MYSQL *mysql)
{
  char query[SQLCMDSIZE];
  int retval = GL_NOTFOUND;

#if IPMATCH_RANGE
  struct in6_addr ipaddr;

  unsigned base   = (!ipv6) ? 32 : 128;
  unsigned prefix = (!ipv6) ? 24 : 64;

  uint8_t hexlen = base / 8 * 2;
  unsigned char range_begin[32], range_end[32];
  int bits = base - prefix;

  if (inet_pton((!ipv6) ? AF_INET : AF_INET6, relay_ip, &ipaddr) <= 0)
  {
    gllog(LOGLEVEL_ERROR, "greylisting: invalid ip: %s\n", relay_ip);
    return GL_NOTFOUND;
  }

  for(int i = base / 8 - 1; i >= 0; i--)
  {
    int j = (bits > 8) ? 8 : bits;
    unsigned char x = (1 << j) - 1;

    unsigned char y = ipaddr.s6_addr[i] & ~x;
    range_begin[i*2 + 1]  = tohex(y & 0xF);
    range_begin[i*2]      = tohex(y >> 4);

    y = ipaddr.s6_addr[i] | x;
    range_end[i*2 + 1]  = tohex(y & 0xF);
    range_end[i*2]      = tohex(y >> 4);

    bits -= j;
  }
#endif

  char *mail_from_esc = malloc(strlen(mail_from)*2 + 1);
  char *rcpt_to_esc   = malloc(strlen(rcpt_to)*2 + 1);
  mysql_real_escape_string(mysql, mail_from_esc, mail_from, strlen(mail_from));
  mysql_real_escape_string(mysql, rcpt_to_esc, rcpt_to, strlen(rcpt_to));

#if IPMATCH_RANGE
  sprintf(query,
    "SELECT `id`, `block_expires` < UTC_TIMESTAMP() "
    "FROM `greylisting_data` "
    "WHERE `record_expires` > UTC_TIMESTAMP() "
      "AND `relay_ip` BETWEEN x'%.*s' AND x'%.*s' "
      "AND `mail_from` = '%s' "
      "AND `rcpt_to` = '%s' "
    "LIMIT 1",
    hexlen, range_begin, hexlen, range_end,
    mail_from_esc,
    rcpt_to_esc);
#else
  sprintf(query,
    "SELECT `id`, `block_expires` < UTC_TIMESTAMP() "
    "FROM `greylisting_data` "
    "WHERE `record_expires` > UTC_TIMESTAMP() "
      "AND `relay_ip` = INET6_ATON('%s') "
      "AND `mail_from` = '%s' "
      "AND `rcpt_to` = '%s' "
    "LIMIT 1",
    relay_ip,
    mail_from_esc,
    rcpt_to_esc);
#endif

  MYSQL_RES *res;
  if (mysql_query_wrapper(mysql, query) ||
      !(res = mysql_store_result(mysql)))
  {
    gllog(LOGLEVEL_ERROR, "greylisting: mysql: %s\n", mysql_error(mysql));
    retval = GL_NOTFOUND;
    goto _cleanup;
  }

  MYSQL_ROW row;
  if ((row = mysql_fetch_row(res)))
  {
    if (atoi(row[1]))
    {
      sprintf(query,
        "UPDATE `greylisting_data` "
        "SET `record_expires` = UTC_TIMESTAMP() + INTERVAL %u DAY, `passed_count` = `passed_count` + 1 "
        "WHERE `id` = '%s'",
        record_expire_good, row[0]);
      retval = GL_ACCEPT;
      gllog(LOGLEVEL_INFO, "greylisting: %s (%s -> %s) exists (id=%s) - accepting\n",
          relay_ip, mail_from, rcpt_to, row[0]);
    }
    else
    {
      sprintf(query,
        "UPDATE `greylisting_data` "
        "SET `blocked_count` = `blocked_count` + 1 "
        "WHERE `id` = '%s'",
        row[0]);
      retval = GL_TEMPREJECT;
      gllog(LOGLEVEL_INFO, "greylisting: %s (%s -> %s) is blocked (id=%s) - temp. rejecting\n",
          relay_ip, mail_from, rcpt_to, row[0]);
    }
  }
  else
  {
    sprintf(query,
      "INSERT INTO `greylisting_data` "
      "VALUES (0, INET6_ATON('%s'), '%s', '%s', UTC_TIMESTAMP() + INTERVAL %u MINUTE, UTC_TIMESTAMP() + INTERVAL %u MINUTE, 1, 0, 0, NOW(), NOW())",
      relay_ip, mail_from_esc, rcpt_to_esc, block_expire, record_expire);
    retval = GL_TEMPREJECT;
    gllog(LOGLEVEL_INFO, "greylisting: %s (%s -> %s) doesn't exist. - temp. rejecting\n", relay_ip, mail_from, rcpt_to);
  }
  mysql_free_result(res);

  if (mysql_query_wrapper(mysql, query))
  {
    gllog(LOGLEVEL_ERROR, "greylisting: mysql: %s\n", mysql_error(mysql));
    retval = GL_NOTFOUND;
    goto _cleanup;
  }

_cleanup:
  free(mail_from_esc);
  free(rcpt_to_esc);
  return retval;
}

int main()
{
  int greylisted = 0;

  /* load config */
  if (!load_config())
    goto _end;

  /* initialize mysql library */
  mysql_library_init(-1, NULL, NULL);
  MYSQL *mysql = mysql_init(NULL);
  if (!mysql)
  {
    gllog(LOGLEVEL_FATAL, "greylisting: mysql: %s\n", mysql_error(mysql));
    goto _cleanup;
  }

  if (mysql_default_file)
    mysql_options(mysql, MYSQL_READ_DEFAULT_FILE, mysql_default_file);

  /* connect to mysql */
  if (!mysql_real_connect(mysql, NULL, NULL, NULL, NULL, 0, NULL, 0))
  {
    gllog(LOGLEVEL_FATAL, "greylisting: mysql: %s\n", mysql_error(mysql));
    goto _cleanup;
  }

  /* greylisting checks */
  greylisted = check_listed(mysql);
  if (greylisted == GL_NOTFOUND)
    greylisted = check_greylisted(mysql);

  /* print smtp error code */
  switch(greylisted)
  {
    case GL_REJECT:
      printf(CMD_REJECT);
      break;
    case GL_TEMPREJECT:
      printf(CMD_TEMPREJECT);
      break;
  }

  /* cleanup stuff */
_cleanup:
  gllog(LOGLEVEL_DEBUG, "greylisting: exiting\n");
  if (mysql)
    mysql_close(mysql);
  mysql_library_end();
_end:
  cleanup();
  return 0;
}
