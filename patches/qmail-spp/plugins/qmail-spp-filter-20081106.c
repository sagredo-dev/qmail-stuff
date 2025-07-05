/*
 * Copyright (C) 2008 Chris Caputo <ccaputo@alt.net>
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
 *
 */

/*
   This program enables qmail-spp commands to be issued based on matches of
   TCPREMOTEIP, SMTPMAILFROM or SMTPRCPTTO with records in text files.

   The TinyCDB library (http://www.corpit.ru/mjt/tinycdb.html) is used.  Or if
   is not available, the standard CDB library is used
   (http://cr.yp.to/cdb/install.html).

   Compile plugin using something like this for TinyCDB:

     gcc -g -Wall qmail-spp-filter.c -o qmail-spp-filter -lcdb

   Or this for standard CDB:

     gcc -g -Wall qmail-spp-filter.c -o qmail-spp-filter /usr/lib/cdb.a \
       /usr/lib/unix.a /usr/lib/buffer.a /usr/lib/alloc.a /usr/lib/byte.a

   Put qmail-spp-filter in the qmail plugins directory
   (ex. "/var/qmail/plugins") and add to smtpplugins file
   (ex. "/var/qmail/control/smtpplugins") after [rcpt]
   section:

     [rcpt]
     plugins/qmail-spp-filter

   If the "RELAYCLIENT" environment variable (envar) is set, this module
   exits without doing anything, since the client has permission to relay.

   IPv6 is supported if TCPREMOTEIP contains an IPv6 address or if
   TCP6REMOTEIP envar is set.

   Filters are specified by setting the following envars.

     SPP_FILTER_#_DEF
     SPP_FILTER_#_CMD

   '#' starts at 1 and increments numerically (base 10, no leading zeros) until
   there is no matching envar.  For each DEF envar, there must be a matching
   CMD envar.

   DEF envars are defined as:

     "type:pathname"

   where "type" is one of:

      ip         list of IP addresses
      from       list of from/sender email addresses
      regexfrom  list of regular expressions to match with from/sender addrs
      rcpt       list of destination/rcptto email addresses
      regexrcpt  list of regular expressions to match with dest/rcptto addrs

   and pathname is the full filename of a text file with one record per line.
   Comments start with '#' in the text files.  CDB hash files
   (http://cr.yp.to/cdb.html) are automatically generated for all but regular
   expression files.  CDB generation is triggered if it appears that the
   source text file is newer than the accompanying CDB file or if a CDB file
   does not exist.  The "qmaild" user must have write access to the directory
   containing the file.

   The regular expressions are of the POSIX Extended Regular Expression
   regex(3) format and are case-insensitive.

   Possible settings of CMD envars are taken from
   http://qmail-spp.sourceforge.net/doc/ :

     Command       Description
     -----------------------------------------------------------------------
     A             accept mail - turn off qmail-spp in this session
     N             next - accept current SMTP command (do not execute
                   remaining plugins for this command)
     O             ok - like N, but omits qmail checks in MAIL and RCPT
     Emsg          error - do not accept this SMTP command and immediately
                   send msg to the client
     LMmsg         later, mail - like E, but shows error after MAIL command
     LRmsg         later, rcpt - like E, but shows error after RCPT command
     LDmsg         later, data - like E, but shows error after DATA command
     Rmsg          reject mail - send msg to the client and drop connection
     D             drop connection immediately, without printing anything
     Svar=value    set environmental variable var to value
     Uvar          unset var variable
     Hcontent      header - add header content (eg. X-Spam-Flag: YES)
     Cfoo@bar.com  change last address provided by the client to foo@bar.com
                   (MAIL FROM or RCPT TO address)
     Pmsg          print - send msg to the client

   Separate commands are separated by a comma or a carriage return.  Be
   careful not to include a comma for any other reason.

   Once a match is found and a CMD is processed, the plugin exits.

   An optional SPP_FILTER_NOMATCH_CMD envar can be set if you want the program
   to issue a qmail-spp command (or commands) if there is a failure to find
   any match.

   Except for the SPP_FILTER_NOMATCH_CMD envar, if any CMDs include the
   special string "send-filter-def" then "send-filter-def" will
   be replaced by the content of the SPP_FILTER_#_DEF envar that matched.

   Example envars:

     SPP_FILTER_1_DEF="ip:/var/qmail/control/whitelist_ips"
     SPP_FILTER_1_CMD="A,SSPP_FILTER_WHITELISTEDIP_MATCHED=1"
     SPP_FILTER_2_DEF="regexrcpt:/var/qmail/control/whitelist_regex_rcpts"
     SPP_FILTER_2_CMD="A,HSPP-Filter-Match: send-filter-def"
     SPP_FILTER_3_DEF="regexfrom:/var/qmail/control/blacklist_regex_senders"
     SPP_FILTER_3_CMD="E550 Blacklisted!"
     SPP_FILTER_4_DEF="rcpt:/var/qmail/control/whitelist_rcpts"
     SPP_FILTER_4_CMD="A"
     SPP_FILTER_5_DEF="from:/var/qmail/control/whitelist_senders"
     SPP_FILTER_5_CMD="A"
     SPP_FILTER_6_DEF="from:/var/qmail/control/blacklist_senders"
     SPP_FILTER_6_CMD="E550 Blacklisted!"
     SPP_FILTER_NOMATCH_CMD="SSPP_FILTER_FOUND_NO_MATCH=1"

   Example "ip" text file:

     127.0.0.1  # full IP address, with no leading zeros
     192.168.2  # partial IP address
     192.168    # partial IP address
     10         # partial IP address
     2001:0db8:0000:0000:0000:0000  # invariant part of IPv6 addresses need to
                                    # be explicit (no "::" or ":0:" compression
                                    # since simple text matching is used.

   Example "from" or "rcpt" text file:

     # list of email addresses to whitelist
     foo@bar.com   # comment
     bar@foo.com

   Example "regexfrom" or "regexrcpt" regex text file:

     # ^ and $ operators are automatically added by the plugin.
     .*@bar.com       # match any email from bar.com
     john-.*@doe.com
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <regex.h>
#include <ctype.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>

#include <cdb.h>
#ifndef TINYCDB_VERSION
#include <cdb_make.h>
#endif // TINYCDB_VERSION

#define LOG "qmail-spp-filter: "
#define LOGR "qmail-spp-filter:%s: "
#define SEND_FILTER_DEF "send-filter-def"
#define SEND_FILTER_DEF_LEN 15

char *g_remote;


void envcmd(char *envstr,
            char *def)
{
  char *p;

  if (NULL == envstr || 0 == *envstr)
    {
      return;
    }

  p = envstr;
  while (*p)
    {
      if (NULL != def &&
          !strncmp(p, SEND_FILTER_DEF, SEND_FILTER_DEF_LEN))
        {
          printf("%s", def);
          p += SEND_FILTER_DEF_LEN;
        }
      else
        {
          printf("%c", ',' == *p ? '\n' : *p);
          p++;
        }
    }

  // don't print extra carriage return if we already ended with one
  if (p > envstr       &&
      ','  != *(p - 1) &&
      '\n' != *(p - 1))
    printf("\n");
}


void cleanse(char *szLine)
{
  char *p;

  if (NULL != (p = strchr(szLine, '#')))  *p = 0;  // remove comments

  // remove whitespace
  p = szLine;
  while (*p)
    {
      if (isspace(*p))
	{
	  *p = 0;
	  break;
	}
      p++;
    }
}


// Return 1 if there was a match.  0 otherwise (including on error).
int matchregex(char *filename,
	       char *key)
{
  FILE *fp = fopen(filename, "r");
  char szLine[256];
  regex_t re;
  int re_error;
  char szError[256];
  int fMatch = 0;

  if (NULL == fp)
    {
      fprintf(stderr,
	      LOGR "ERROR: fopen(\"%s\") failed: %m\n",
	      g_remote,
	      filename);
      goto done;
    }

  *szLine = '^';  // every line starts with a '^' regex beginning of line

  // Read in after '^' character and leave room for a '$' at the end.
  while (NULL != fgets(szLine + 1, sizeof(szLine) - 2, fp) && 0 == fMatch)
    {
      cleanse(szLine);
      if (0 == szLine[1]) continue;  // skip blank lines

      strcat(szLine, "$");  // every line ends with a '$' regex end of line

      // fprintf(stderr, LOGR "regex: '%s'\n", g_remote, szLine);
      
      re_error = regcomp(&re, szLine, REG_EXTENDED | REG_ICASE | REG_NOSUB);
      if (0 != re_error)
	{
	  regerror(re_error, &re, szError, sizeof(szError));
	  fprintf(stderr,
		  LOGR "ERROR: regcomp(\"%s\") failed: %s\n",
		  g_remote,
		  szLine,
		  szError);
	  regfree(&re);
	  goto done;
	}

      if (0 == regexec(&re, key, 0, NULL, 0))
	{
	  fMatch = 1;
	}

      regfree(&re);
    }

 done:
  if (NULL != fp) fclose(fp);
  return fMatch;
}


// Returns 1 on success, 0 on failure.
int cdbmake(char *textfilename,
            char *cdbfilename)
{
  struct cdb_make cdbm;
  int cdbinited = 0;
  int fdcdb = -1;
  char cdbtempfilename[PATH_MAX];
  FILE *fptxt = NULL;
  char szLine[256];
  int ret = 0;

  if (NULL == (fptxt = fopen(textfilename, "r")))
    {
      fprintf(stderr,
	      LOGR "ERROR: fopen(\"%s\") failed: %m\n",
	      g_remote,
	      textfilename);
      goto done;
    }

  snprintf(cdbtempfilename,
	   sizeof(cdbtempfilename),
	   "%s.%u",
	   cdbfilename,
	   getpid());
  fprintf(stderr, LOGR "cdbmake: Making '%s'\n", g_remote, cdbtempfilename);

  if (-1 == (fdcdb = open(cdbtempfilename, O_RDWR | O_CREAT | O_TRUNC, 0666)))
    {
      fprintf(stderr,
	      LOGR "ERROR: open(\"%s\") failed: %m\n",
	      g_remote,
	      cdbtempfilename);
      goto done;
    }

  if (0 != cdb_make_start(&cdbm, fdcdb))
    {
      fprintf(stderr,
	      LOGR "ERROR: cdb_make_start() failed: %m\n",
	      g_remote);
      goto done;
    }
  cdbinited = 1;

  while (NULL != fgets(szLine, sizeof(szLine), fptxt))
    {
      cleanse(szLine);
      if (0 == *szLine) continue;  // skip blank lines

      // fprintf(stderr, LOGR "cdbmake: '%s'\n", g_remote, szLine);

      // we don't worry about duplicates
      if (0 != cdb_make_add(&cdbm, szLine, strlen(szLine), NULL, 0))
	{
	  fprintf(stderr,
		  LOGR "ERROR: cdb_make_add(\"%s\") failed: %m\n",
		  g_remote,
		  szLine);
	  goto done;
	}
    }

  // Success!
  ret = 1;

 done:
  if (1 == cdbinited)
    {
      if (0 != cdb_make_finish(&cdbm))
	{
	  fprintf(stderr,
		  LOGR "ERROR: cdb_make_finish() failed: %m\n",
		  g_remote);
	}
      cdbinited = 0;
    }

  if (-1 != fdcdb && -1 == close(fdcdb))
    {
      fprintf(stderr,
	      LOGR "ERROR: close(\"%s\") failed: %m\n",
	      g_remote,
	      cdbtempfilename);
      ret = 0;
    }
  fdcdb = -1;

  if (1 == ret && -1 == rename(cdbtempfilename, cdbfilename))
    {
      fprintf(stderr,
	      LOGR "ERROR: rename(\"%s\",\"%s\") failed: %m\n",
	      g_remote,
	      cdbtempfilename,
	      cdbfilename);
      ret = 0;
    }

  if (NULL != fptxt)
    fclose(fptxt);
  fptxt = NULL;

  return ret;
}


// Returns fd or -1 on failure.
int cdbopen(char *textfilename,
	    char *cdbfilename)
{
  struct stat stattxt, statcdb;
  int fd = -1;

  // fprintf(stderr, LOGR "cdbopen: '%s'\n", g_remote, textfilename);

  if (-1 == stat(textfilename, &stattxt))
    {
      fprintf(stderr,
	      LOGR "ERROR: stat(\"%s\") failed: %m\n",
	      g_remote,
	      textfilename);
      return -1;
    }

  if (-1 == stat(cdbfilename, &statcdb) ||
      stattxt.st_mtime > statcdb.st_mtime)
    {
      if (!cdbmake(textfilename, cdbfilename))
	{
	  return -1;
	}
    }

  if (-1 == (fd = open(cdbfilename, O_RDONLY)))
    {
      fprintf(stderr,
	      LOGR "ERROR: open(\"%s\") failed: %m\n",
	      g_remote,
	      cdbfilename);
      return -1;
    }

  return fd;
}


// Return 1 if there was a match.  0 otherwise (including on error).
int matchtxt(struct cdb *pcdb,
	     char *key)
{
  int result = cdb_find(pcdb, key, strlen(key));

  if (result > 0)
    {
      return 1;
    }

  if (result < 0)
    {
      fprintf(stderr,
	      LOGR "ERROR: cdb_seek(\"%s\") failed: %m\n",
	      g_remote,
	      key);
    }

  return 0;
}


// Return 1 if there was a match.  0 otherwise (including on error).
int matchip(struct cdb *pcdb)
{
  char ipstr[INET6_ADDRSTRLEN + 1];
  int fIPv6;
  char *divider;

  // we'll work with a copy since we alter it
  strncpy(ipstr, g_remote, sizeof(ipstr));

  fIPv6 = (NULL != strchr(ipstr, ':'));
  
  for (;;)
    {
      if (1 == matchtxt(pcdb, ipstr))
	return 1;

      // trim off to next divider with each iteration
      if (NULL == (divider = strrchr(ipstr, fIPv6 ? ':' : '.')))
	break;
      else
	*divider = 0;
    }

  return 0;
}


// Return 1 if there was a match.  0 otherwise (including on error).
int match(char *def,
	  char *cmd,
	  char *mailfrom,
	  char *rcptto)
{
  int fIP = 0;
  int fFrom = 0;
  int fRcptto = 0;
  int fRegex = 0;
  char *textfilename;
  int fMatch = 0;

  if (!strncasecmp(def, "ip:", 3)) fIP = 1;
  if (!strncasecmp(def, "regex", 5))
    {
      fRegex = 1;
      if (!strncasecmp(def, "regexfrom:", 10)) fFrom = 1;
      if (!strncasecmp(def, "regexrcpt:", 10)) fRcptto = 1;
    }
  else
    {
      if (!strncasecmp(def, "from:", 5)) fFrom = 1;
      if (!strncasecmp(def, "rcpt:", 5)) fRcptto = 1;
    }

  if (!fIP && !fFrom && !fRcptto)
    {
      fprintf(stderr,
	      LOGR "ERROR: Filter definition \"%s\" is not of format "
	      "\"type:pathname\" where type is one of \"ip\", \"from\", "
	      "\"regexfrom\", \"rcpt\" or \"regexrcpt\"!\n",
	      g_remote,
              def);
      return 0;
    }

  textfilename = strchr(def, ':');
  if (NULL == textfilename || 0 == textfilename[1])
    {
      fprintf(stderr,
	      LOGR "ERROR: Filter definition \"%s\" is not of format "
	      "\"type:pathname\"!\n",
	      g_remote,
	      def);
      return 0;
    }
  textfilename++;

#if 0
  fprintf(stderr,
	  LOGR "regex=%d, ip=%d, from=%d, rcptto=%d, textfilename='%s'\n",
	  g_remote, fRegex, fIP, fFrom, fRcptto, textfilename);
#endif

  if (fRegex)
    {
      fMatch = matchregex(textfilename, fFrom ? mailfrom : rcptto);
    }
  else
    {
      char cdbfilename[PATH_MAX];
      int cdbfd = -1;
      struct cdb cdb;

      snprintf(cdbfilename,
	       sizeof(cdbfilename),
	       "%s.cdb",
	       textfilename);
      if (-1 == (cdbfd = cdbopen(textfilename, cdbfilename)))
	return 0;
      cdb_init(&cdb, cdbfd);

      if (fIP)
	fMatch = matchip(&cdb);  // uses global g_remote variable
      else
	fMatch = matchtxt(&cdb, fFrom ? mailfrom : rcptto);

      cdb_free(&cdb);
      if (-1 == close(cdbfd))
	{
	  fprintf(stderr,
		  LOGR "ERROR: close(\"%s\") failed: %m\n",
		  g_remote,
		  cdbfilename);
	}
    }

  if (fMatch)
    {
      envcmd(cmd, def);
      return 1;
    }
  else
    {
      return 0;
    }
}


int main()
{
  char *mailfrom = NULL;
  char *rcptto   = NULL;
  char *nomatch  = NULL;
  int i;
#define MAX_FILTER_COUNT 9999
  char defname[20];  // "SPP_FILTER_####_DEF"
  char cmdname[20];  // "SPP_FILTER_####_CMD"
  char *def, *cmd;
  int fMatch = 0;

  if (getenv("RELAYCLIENT"))
    return 0;

  g_remote = getenv("TCPREMOTEIP");
  if (!g_remote)
    g_remote = getenv("TCP6REMOTEIP");
  if (!g_remote)
    {
      fprintf(stderr, LOG "ERROR: can't read TCPREMOTEIP or TCP6REMOTEIP\n");
      return 0;
    }
  if (!(mailfrom = getenv("SMTPMAILFROM")))
    {
      fprintf(stderr,
	      LOGR "can't read SMTPMAILFROM\n",
	      g_remote);
      return 0;
    }
  if (!(rcptto = getenv("SMTPRCPTTO")))
    {
      fprintf(stderr,
	      LOGR "can't read SMTPRCPTTO\n",
	      g_remote);
      return 0;
    }

  for (i = 1; i <= MAX_FILTER_COUNT; i++)
    {
      snprintf(defname, sizeof(defname), "SPP_FILTER_%d_DEF", i);
      snprintf(cmdname, sizeof(cmdname), "SPP_FILTER_%d_CMD", i);
      def = getenv(defname);
      cmd = getenv(cmdname);
      if (!(def && cmd))
	{
	  if (def || cmd)
	    {
	      fprintf(stderr,
		      LOGR "ERROR: %s envar defined, but %s was not!\n",
		      g_remote,
		      def == NULL ? cmdname : defname,
		      cmd == NULL ? cmdname : defname);
	    }
	  break;
	}

      if (match(def, cmd, mailfrom, rcptto))
	{
	  fprintf(stderr,
		  LOGR "match: def #%d ('%s').  mailfrom='%s', rcptto='%s'\n",
		  g_remote,
		  i,
		  def,
		  mailfrom,
		  rcptto);
	  fMatch = 1;
	  break;
	}
    }

  if (0 == fMatch)
    {
      fprintf(stderr,
	      LOGR "nomatch: mailfrom='%s', rcptto='%s'\n",
	      g_remote,
	      mailfrom,
	      rcptto);
      if (NULL != (nomatch = getenv("SPP_FILTER_NOMATCH_CMD")))
	envcmd(nomatch, NULL);
    }
      
  return 0;
}
