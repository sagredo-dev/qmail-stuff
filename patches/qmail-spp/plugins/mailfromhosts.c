/*
 * Copyright (c) 2016 Manuel Mausz
 */

/* uncomment the line below to use nbdm or gdbm instead of BerkDB */
//#define USE_NDBM

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>

#if defined(USE_NDBM)
# include <ndbm.h>
#else
# define DB_DBM_HSEARCH 1  /* use the dbm interface */
# define HAVE_DBM          /* for BerkDB 5.0 and later */
# include <db.h>
#endif

#define MAX_DOMAIN_LEN 253
int match_me(const char *mail_from, size_t mail_from_len)
{
  if (mail_from_len > MAX_DOMAIN_LEN)
    return 0;

  FILE *fpme;
  if ((fpme = fopen("control/me", "r")) == NULL)
    return 0;

  int match = 0;
  char me[MAX_DOMAIN_LEN + 1];
  if (fgets(me, sizeof(me), fpme) != NULL)
    match = (strncmp(mail_from, me, mail_from_len) == 0);

  (void)fclose(fpme);
  return match;
}

int match_hosts_db(char *mail_from, size_t mail_from_len,
    const char *user, size_t user_len)
{
  const char *dbfile = getenv("MAILFROMHOSTSDB");
  if (dbfile == NULL)
    dbfile = "control/mailfromhosts";

  DBM *dbm = dbm_open(dbfile, O_RDONLY, 0600);
  if (dbm == NULL)
  {
    perror("Unable to open database");
    return 0;
  }

  /* domain match */
  datum key = {
    .dptr  = mail_from,
    .dsize = mail_from_len,
  };
  datum data = dbm_fetch(dbm, key);

#ifdef ALLOW_SUBDOMAINS
  char *p;
  while (data.dptr == NULL && (p = strchr(key.dptr, '.')) != NULL)
  {
    /* parent domain match */
    p++;
    if (*p == '\0')
      break;
    key.dsize = mail_from_len - (p - mail_from);
    key.dptr  = p;
    data = dbm_fetch(dbm, key);
  }
#endif

  /*
   * check auth user and data.dptr relation
   *   auth user is <account>p<num>
   *   data.dptr is <account> (without \0)
   */
  int match = (data.dptr != NULL && user_len >= data.dsize + 2
      && strncmp(data.dptr, user, data.dsize) == 0 && user[data.dsize] == 'p');

  (void)dbm_close(dbm);
  return match;
}

int main()
{
  const char *user = getenv("SMTPAUTHUSER");
  size_t user_len;
  if (user == NULL || (user_len = strlen(user)) == 0)
    return 0;

  const char *env_mail_from = getenv("SMTPMAILFROM");
  if (env_mail_from == NULL)
    return 0;

  /* allow rfc 2298 */
  if (*env_mail_from == '\0')
    return 0;

  char *domain = strrchr(env_mail_from, '@');
  if (domain == NULL)
  {
    fprintf(stderr, "mailfromhosts: %s %s\n", user, env_mail_from);
    puts("E553 5.1.7 Sender domain not allowed");
    return 0;
  }

  size_t mail_from_len = strlen(domain + 1);
  if (mail_from_len > 0)
  {
    char *mail_from = strdup(domain + 1);
    for (char *p = mail_from; *p; ++p)
      *p = tolower(*p);

    if (!match_hosts_db(mail_from, mail_from_len, user, user_len)
        && !match_me(mail_from, mail_from_len))
    {
      fprintf(stderr, "mailfromhosts: %s %s\n", user, env_mail_from);
      puts("E553 5.1.8 Sender domain not allowed");
    }

    (void)free(mail_from);
  }

  return 0;
}
