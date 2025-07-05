/*
 * Copyright (C) 2015-2016 Manuel Mausz (manuel@mausz.at)
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

#define _DEFAULT_SOURCE
#define _BSD_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <mysql.h>
#include <stdbool.h>

#define SQLCMDSIZE     2048
#define CMD_REJECT     "E553 sorry, you've exceeded the number of recipients per period (#5.7.1)\n"
#define LOGLEVEL_FATAL 1
#define LOGLEVEL_ERROR 2
#define LOGLEVEL_WARN  3
#define LOGLEVEL_INFO  4
#define LOGLEVEL_DEBUG 5
#define MAXCONFIGLINESIZE 1024 // change this to dynamic allocation sometime
#define MAXUSERLEN     12

static char *configfile = "control/smtp_ratelimit";
static char *mysql_default_file = NULL;
unsigned int max_tokens    = 300;
unsigned int refill_tokens = 100;
unsigned int refill_time   = 600;
static int loglevel = LOGLEVEL_WARN;

static char *auth_user;
static unsigned int rcpt_count;

void rllog(unsigned int level,  char* format, ...)
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
  char *tmp;

  /* first check for logging var */
  tmp = getenv("RLLOGLEVEL");
  if (tmp)
    loglevel = atoi(tmp);

  /* check if ratelimit is enabled */
  if (!getenv("RATELIMIT"))
  {
    rllog(LOGLEVEL_DEBUG, "ratelimit: ratelimit is not enabled\n");
    return 0;
  }

  /* check if user is authenticated */
  auth_user = getenv("SMTPAUTHUSER");
  if (!auth_user || strlen(auth_user) == 0)
  {
    rllog(LOGLEVEL_DEBUG, "ratelimit: no user. ratelimit disabled\n");
    return 0;
  }

  /* avoid overflows */
  if (strlen(auth_user) > MAXUSERLEN)
  {
    rllog(LOGLEVEL_FATAL, "ratelimit: user too long. buffer overflow protection\n");
    return 0;
  }

  /* fetch recipient count: qmail-spp updates SMTPRCPTCOUNT on RCPT commands
   * only. so we're always 1 behind */
  tmp = getenv("SMTPRCPTCOUNT");
  if (!tmp)
  {
    rllog(LOGLEVEL_FATAL, "ratelimit: SMTPRCPTCOUNT is undefined\n");
    return 0;
  }
  rcpt_count = atoi(tmp) + 1;

  /* fetch config file path */
  tmp = getenv("RLCONFIGFILE");
  if (tmp)
    configfile = tmp;

  /* fetch config file content */
  char buf[MAXCONFIGLINESIZE];
  rllog(LOGLEVEL_DEBUG, "ratelimit: configfile=%s\n", configfile);
  FILE *config = fopen(configfile, "r");
  if (!config)
    rllog(LOGLEVEL_DEBUG, "ratelimit: configfile error: %s\n", strerror(errno));
  else
  {
    while((tmp = fgets(buf, sizeof(buf), config)))
    {
      if (buf[0] == '#' || buf[0] == ';')
        continue;
      int i;
      for(i = 0; i < strlen(buf) && buf[i] != '\r' && buf[i] != '\n'; i++);
      buf[i] = 0;
      if (strstr(tmp, "mysql_default_file=") == tmp)
      {
        free(mysql_default_file);
        mysql_default_file = strdup(tmp + strlen("mysql_default_file="));
      }
      else if (strstr(tmp, "max_tokens=") == tmp)
        max_tokens = atoi(tmp + strlen("max_tokens="));
      else if (strstr(tmp, "refill_tokens=") == tmp)
        refill_tokens = atoi(tmp + strlen("refill_tokens="));
      else if (strstr(tmp, "refill_time=") == tmp)
        refill_time = atoi(tmp + strlen("refill_time="));
      else if (strstr(tmp, "loglevel=") == tmp && !getenv("RLLOGLEVEL"))
        loglevel = atoi(tmp + strlen("loglevel="));
    }
    fclose(config);
  }

  /* logging */
  rllog(LOGLEVEL_DEBUG, "ratelimit: mysql: default_file=%s\n",
      mysql_default_file);
  rllog(LOGLEVEL_DEBUG, "ratelimit: max_tokens=%u, refill_tokens=%u, refill_time=%u\n",
      max_tokens, refill_tokens, refill_time);
  return 1;
}

void cleanup()
{
  free(mysql_default_file);
}

int mysql_query_wrapper(MYSQL *mysql, char *query)
{
  int result = mysql_query(mysql, query);
  rllog(LOGLEVEL_DEBUG, "ratelimit: mysql: %s - ret=%d\n", query, result);
  return result;
}

bool check_ratelimit(MYSQL *mysql)
{
  char query[SQLCMDSIZE];
  bool ratelimited = false;

  char *user_esc = malloc(strlen(auth_user)*2 + 1);
  mysql_real_escape_string(mysql, user_esc, auth_user, strlen(auth_user));

  sprintf(query,
    "SELECT `tokens`, UNIX_TIMESTAMP(`last_refill`) "
    "FROM `smtp_ratelimit` "
    "WHERE `user` = '%s'", user_esc);

  MYSQL_RES *res;
  if (mysql_query_wrapper(mysql, query) ||
      !(res = mysql_store_result(mysql)))
  {
    rllog(LOGLEVEL_ERROR, "ratelimit: mysql: %s\n", mysql_error(mysql));
    goto _cleanup;
  }

  MYSQL_ROW row;
  time_t last_refill, now = time(NULL);
  unsigned int tokens = max_tokens;
  bool found = false;
  if ((row = mysql_fetch_row(res)))
  {
    found = true;
    last_refill = atol(row[1]);
    tokens = atoi(row[0]);

    while (last_refill + refill_time < now && tokens < max_tokens)
    {
      tokens += refill_tokens;
      last_refill += refill_time;
    }

    if (tokens > max_tokens)
      tokens = max_tokens;
    if (tokens == max_tokens)
      last_refill = now;
  }
  mysql_free_result(res);

  if (rcpt_count > tokens)
  {
    rllog(LOGLEVEL_INFO, "ratelimit(%s): Mail rejected: "
      "rcpt_count=%u, rcpt_left=%u\n",
      auth_user, rcpt_count, tokens);
    ratelimited = true;
    goto _cleanup;
  }

  tokens -= rcpt_count;
  rllog(LOGLEVEL_DEBUG, "ratelimit(%s): Mail accepted: "
      "rcpt_count=%u, rcpt_left=%u\n",
      auth_user, rcpt_count, tokens);

  if (found)
  {
    sprintf(query,
      "UPDATE `smtp_ratelimit` SET `tokens` = %u, `last_refill` = FROM_UNIXTIME(%lu) "
      "WHERE `user` = '%s'",
      tokens, last_refill, user_esc);
  }
  else
  {
    sprintf(query,
      "INSERT INTO `smtp_ratelimit` VALUES ('%s', %u, FROM_UNIXTIME(%lu))",
      user_esc, tokens, now);
  }

  if (mysql_query_wrapper(mysql, query))
  {
    rllog(LOGLEVEL_ERROR, "ratelimit: mysql: %s\n", mysql_error(mysql));
    ratelimited = false;
    goto _cleanup;
  }

_cleanup:
  free(user_esc);
  return ratelimited;
}

int main()
{
  /* load config */
  if (!load_config())
    goto _end;

  /* initialize mysql library */
  mysql_library_init(-1, NULL, NULL);
  MYSQL *mysql = mysql_init(NULL);
  if (!mysql)
  {
    rllog(LOGLEVEL_FATAL, "ratelimit: mysql: %s\n", mysql_error(mysql));
    goto _cleanup;
  }

  if (mysql_default_file)
    mysql_options(mysql, MYSQL_READ_DEFAULT_FILE, mysql_default_file);

  /* connect to mysql */
  if (!mysql_real_connect(mysql, NULL, NULL, NULL, NULL, 0, NULL, 0))
  {
    rllog(LOGLEVEL_FATAL, "ratelimit: mysql: %s\n", mysql_error(mysql));
    goto _cleanup;
  }

  /* ratelimit */
  if (check_ratelimit(mysql))
    printf(CMD_REJECT);

  /* cleanup stuff */
_cleanup:
  rllog(LOGLEVEL_DEBUG, "ratelimit: exiting\n");
  if (mysql)
    mysql_close(mysql);
  mysql_library_end();
_end:
  cleanup();
  return 0;
}
