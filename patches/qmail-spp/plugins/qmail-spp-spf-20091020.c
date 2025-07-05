/*
 * Copyright (C) 2003-2005 Pawel Foremski <pjf@asn.pl>
 *   - Original imported from dirqmail.
 *
 * Copyright (C) 2008 Chris Caputo <ccaputo@alt.net>
 *   - Oct 2008: Adapted to work with libspf2-1.2.8.
 *               Added support for IPv6 via TCP6REMOTEIP.
 *               Altered configuration methodology to use envars.
 *   - Nov 2008: Added SPP_SPF_DONT_ALLOW_RANDOM_IP_PASS.
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
   This is an implementation of SPF as a qmail-spp module.  It requires
   libspf2.  For more information, consult:

     http://www.openspf.org/
     http://qmail-spp.sourceforge.net/
     http://www.libspf2.org/

   If an SPF record is not found or doesn't process, a fallback SPF record
   of "v=spf1 mx -all" can be used to test if the client is listed in the MX
   records of the envelope domain.
   
   Compile plugin using something like:

     gcc -Wall -o qmail-spp-spf qmail-spp-spf.c -lspf2 -I/usr/include/spf2

   Put this in the qmail plugins directory (ex. "/var/qmail/plugins") and add
   to smtpplugins file (ex. "/var/qmail/control/smtpplugins") after [mail]
   section:

     [mail]
     plugins/qmail-spp-spf

   If the "RELAYCLIENT" environment variable (envar) is set, this module
   exits without doing anything, since the client has permission to relay.

   IPv6 is supported if TCPREMOTEIP contains an IPv6 address or if
   TCP6REMOTEIP envar is set.

   Set these envars as desired to instruct the module how to handle each SPF
   result.  Only envars defined will be used.

     SPP_SPF_NO_RESULT          - Used if both SPF and MX checks can't be done.

     SPP_SPF_RESULT_NEUTRAL    \
     SPP_SPF_RESULT_PASS       |
     SPP_SPF_RESULT_FAIL       |- Refer to http://www.openspf.org/ for
     SPP_SPF_RESULT_SOFTFAIL   |  definitions.
     SPP_SPF_RESULT_NONE       |
     SPP_SPF_RESULT_TEMPERROR  |
     SPP_SPF_RESULT_PERMERROR  /

     SPP_SPF_MX_RESULT_PASS    \  If any set, MX check of sender is done when
     SPP_SPF_MX_RESULT_FAIL    |- SPF record doesn't exist or SPF check result
     SPP_SPF_MX_RESULT_UNKNOWN /  is None, PermError, TempError or invalid.

   Possible settings of the above envars are taken from
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

   Except for the SPP_SPF_NO_RESULT and SPP_SPF_MX_RESULT_xx envars, if any
   envars include the special string "spf_smtp_msg" then "spf_smtp_msg" will
   be replaced by the output of libspf2's SPF_response_get_smtp_comment()
   function.  For example:

     SPP_SPF_RESULT_FAIL="E550 spf_smtp_msg"

   If the actual SPF query is able to be done, this module also sets the
   environmental variable SPP_SPF_RESULT to one of the following (via the
   qmail-spp 'S' command):

     pass
     fail
     softfail
     neutral
     none
     permerror
     temperror

   In addition, a "Received-SPF:" header is added to the message via the
   qmail-spp 'H' command when the SPF query is able to be done.

   It is okay to not set a particular SPP_SPF_xxx envar.  If that particular
   case is hit the module will only return the "SSPP_SPF_RESULT=<result>" and
   "HReceived-SPF:" commands if the SPF query is done.

   If the SPP_SPF_DONT_ALLOW_RANDOM_IP_PASS envar is set, then when an SPF pass
   result is obtained, two random IP addresses will also be tried to see if the
   SPF definition is passing everything as if "+all" is declared.  If the two
   random IP addresses also receive a pass from the SPF library, then the
   original pass is ignored.

   Example:

      In /etc/tcprules.d/tcp.qmail-smtp change ":allow" line to be as follows:

         :allow,SPP_SPF_RESULT_PASS="HX-Spam-Flag: No,A",SPP_SPF_RESULT_FAIL="E550 spf_smtp_msg",SPP_SPF_NO_RESULT="SSPF_MODULE_FAILED=1"

      or

         :allow,SPP_SPF_RESULT_PASS="A",SPP_SPF_MX_RESULT_PASS="A"

      (Be sure to rebuild tcp.qmail-smtp.cdb after modification, such as with
      "make" or "tcprules" commands.)
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <time.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "spf.h"

#define LOG "qmail-spp-spf: "
#define LOGR "qmail-spp-spf:%s: "
#define SPF_SMTP_MSG "spf_smtp_msg"
#define SPF_SMTP_MSG_LEN 12


void envcmd(char *envstr,
	    SPF_response_t *spf_response)
{
  char *p;

  /* Always issue these when there is a response, regardless of whether envar
     was passed in.  Also, these need to issue first since an envar can include
     a qmail-spp processing termination command. */
  if (NULL != spf_response)
    {
      printf("SSPP_SPF_RESULT=%s\n",
	     SPF_strresult(SPF_response_result(spf_response)));
      printf("H%s\n", SPF_response_get_received_spf(spf_response));
    }

  if (NULL == envstr || 0 == *envstr)
    {
      return;
    }

  p = envstr;
  while (*p)
    {
      if (NULL != spf_response &&
	  !strncmp(p, SPF_SMTP_MSG, SPF_SMTP_MSG_LEN))
	{
	  printf("%s", SPF_response_get_smtp_comment(spf_response));
	  p += SPF_SMTP_MSG_LEN;
	}
      else
	{
	  printf("%c", ',' == *p ? '\n' : *p);
	  p++;
	}
    }

  /* don't print extra carriage return if envstr already ends with one */
  if (p > envstr       &&
      ','  != *(p - 1) &&
      '\n' != *(p - 1))
    printf("\n");
}


/* Returns 1 on success, 0 on failure. */
int set_spf_ip(SPF_request_t *spf_request,
	       int fIPv4,
	       char *remote)
{
  if (fIPv4)
    {
      if (SPF_request_set_ipv4_str(spf_request, remote))
	{
	  fprintf(stderr,
		  LOGR "SPF_request_set_ipv4_str('%s') failed.\n",
		  remote,
		  remote);
	  return 0;
	}
    }
  else
    {
      if (SPF_request_set_ipv6_str(spf_request, remote))
	{
	  fprintf(stderr,
		  LOGR "SPF_request_set_ipv6_str('%s') failed.\n",
		  remote,
		  remote);
	  return 0;
	}
    }

  return 1;
}


/* Returns 1 if a random IP address also results in an SPF pass.
   0 otherwise (or on error).
*/
int random_ip_passes(SPF_request_t *spf_request,
		     int fIPv4,
		     char *remote)
{
  int ret = 0;
  struct in_addr addr4;
  struct in6_addr addr6;
  char szIP[INET6_ADDRSTRLEN];
  SPF_response_t *spf_response = NULL;
  SPF_errcode_t spf_err;

  if (fIPv4)
    {
      addr4.s_addr = random();

      if (SPF_request_set_ipv4(spf_request, addr4))
	{
	  fprintf(stderr,
		  LOGR "SPF_request_set_ipv4('%s') failed.\n",
		  remote,
		  inet_ntop(AF_INET, &addr4, szIP, sizeof(szIP)));
	  goto done;
	}
    }
  else
    {
      addr6.s6_addr32[0] = random();
      addr6.s6_addr32[1] = random();
      addr6.s6_addr32[2] = random();
      addr6.s6_addr32[3] = random();

      if (SPF_request_set_ipv6(spf_request, addr6))
	{
	  fprintf(stderr,
		  LOGR "SPF_request_set_ipv6('%s') failed.\n",
		  remote,
		  inet_ntop(AF_INET6, &addr6, szIP, sizeof(szIP)));
	  goto done;
	}
    }

  if (SPF_E_SUCCESS ==
      (spf_err = SPF_request_query_mailfrom(spf_request, &spf_response)))
    {
      if (SPF_RESULT_PASS == SPF_response_result(spf_response))
	ret = 1;
    }
  else
    {
      fprintf(stderr,
	      LOGR "SPF_request_query_mailfrom (random remote='%s'): "
	      "surprisingly failed since first test succeeded: %s\n",
	      remote,
	      inet_ntop(fIPv4 ? AF_INET : AF_INET6,
			fIPv4 ? (const void *)&addr4 : &addr6,
			szIP,
			sizeof(szIP)),
	      SPF_strerror(spf_err));
    }

 done:
  /* restore original IP settings.  no need to check result since this worked
     already */
  set_spf_ip(spf_request, fIPv4, remote);

  if (NULL != spf_response) SPF_response_free(spf_response);
  return ret;
}


int main()
{
  char *remote   = NULL;
  char *helo     = NULL;
  char *sender   = NULL;
  char *mxpass   = NULL;
  char *mxfail   = NULL;
  char *mxunk    = NULL;
  SPF_server_t   *spf_server     = NULL;
  SPF_request_t  *spf_request    = NULL;
  SPF_response_t *spf_response   = NULL;
  SPF_response_t *spf_responsemx = NULL;
  SPF_errcode_t spf_err;
  int fQuerySuccessful = 0;
  int fConsiderMXCheck = 0;
  int fIPv4 = 0;

  /**
   * env variables
   **/
  if (getenv("RELAYCLIENT")) /* known user, don't do anything */
    return 0;

  remote = getenv("TCPREMOTEIP");
  if (!remote)
    remote = getenv("TCP6REMOTEIP");
  if (!remote) /* should never happen */
    {
      fprintf(stderr, LOG "ERROR: can't read TCPREMOTEIP or TCP6REMOTEIP\n");
      goto done;
    }
  fIPv4 = (NULL == strchr(remote, ':'));

  sender = getenv("SMTPMAILFROM");
  helo   = getenv("SMTPHELOHOST");
  if (!sender && !helo) /* should never happen */
    {
      fprintf(stderr,
	      LOGR "can't read SMTPMAILFROM or SMTPHELOHOST\n",
	      remote);
      goto done;
    }

  /**
   * SPF
   **/
  if (NULL == (spf_server = SPF_server_new(SPF_DNS_RESOLV, 0)))
    {
      fprintf(stderr, LOGR "SPF_server_new failed.\n", remote);
      goto done;
    }
  if (NULL == (spf_request = SPF_request_new(spf_server)))
    {
      fprintf(stderr, LOGR "SPF_request_new failed.\n", remote);
      goto done;
    }
  if (!set_spf_ip(spf_request, fIPv4, remote))
    goto done;
  if (helo && SPF_request_set_helo_dom(spf_request, helo))
    {
      fprintf(stderr,
	      LOGR "SPF_request_set_helo_dom('%s') failed.\n",
	      remote,
	      helo);
      goto done;
    }
  if (sender && SPF_request_set_env_from(spf_request, sender))
    {
      fprintf(stderr,
	      LOGR "SPF_request_set_env_from('%s') failed.\n",
	      remote,
	      sender);
      goto done;
    }
  if (SPF_E_SUCCESS ==
      (spf_err = SPF_request_query_mailfrom(spf_request, &spf_response)))
    {
      fQuerySuccessful = 1;
      fprintf(stderr,
	      LOGR "%s\n",
	      remote,
	      SPF_response_get_received_spf(spf_response));
      switch (SPF_response_result(spf_response))
	{
	case SPF_RESULT_NEUTRAL:
	  envcmd(getenv("SPP_SPF_RESULT_NEUTRAL"), spf_response);
	  break;
	case SPF_RESULT_PASS:
	  if (getenv("SPP_SPF_DONT_ALLOW_RANDOM_IP_PASS"))
	    {
	      /* not intended to be cryptographically secure */
	      srandom(time(NULL) * getpid());

	      /* test twice.  if both pass, something is odd. */
	      if (random_ip_passes(spf_request, fIPv4, remote) &&
		  random_ip_passes(spf_request, fIPv4, remote))
		{
		  fConsiderMXCheck = 1;
		  fprintf(stderr,
			  LOGR "Two random IP addresses also passed SPF "
			  "check, so ignoring this result.  Seems like SPF "
			  "record may contain \"+all\"!\n",
			  remote);
		  break;
		}
	    }
	  envcmd(getenv("SPP_SPF_RESULT_PASS"), spf_response);
	  break;
	case SPF_RESULT_FAIL:
	  envcmd(getenv("SPP_SPF_RESULT_FAIL"), spf_response);
	  break;
	case SPF_RESULT_SOFTFAIL:
	  envcmd(getenv("SPP_SPF_RESULT_SOFTFAIL"), spf_response);
	  break;
	case SPF_RESULT_NONE:
	  envcmd(getenv("SPP_SPF_RESULT_NONE"), spf_response);
	  fConsiderMXCheck = 1;
	  break;
	case SPF_RESULT_TEMPERROR:
	  envcmd(getenv("SPP_SPF_RESULT_TEMPERROR"), spf_response);
	  fConsiderMXCheck = 1;
	  break;
	case SPF_RESULT_PERMERROR:
	  envcmd(getenv("SPP_SPF_RESULT_PERMERROR"), spf_response);
	  fConsiderMXCheck = 1;
	  break;
	case SPF_RESULT_INVALID:
	default:
	  fConsiderMXCheck = 1;
	  fprintf(stderr,
		  LOGR "SPF_request_query_mailfrom: invalid or unknown "
		  "result.\n",
		  remote);
	  break;
	}
    }
  else
    {
      fConsiderMXCheck = 1;
      fprintf(stderr,
	      LOGR "SPF_request_query_mailfrom (helo='%s', mailfrom='%s'): "
	      "failed: %s\n",
	      remote,
	      helo ? helo : "",
	      sender ? sender : "",
	      SPF_strerror(spf_err));
    }

  /**
   * Fallback MX check
   **/
  if (fConsiderMXCheck)
    {
#define SPF_MX_STR "v=spf1 mx -all"
      mxpass = getenv("SPP_SPF_MX_RESULT_PASS");
      mxfail = getenv("SPP_SPF_MX_RESULT_FAIL");
      mxunk  = getenv("SPP_SPF_MX_RESULT_UNKNOWN");
      if (mxpass || mxfail || mxunk)
	{
	  if (SPF_E_SUCCESS ==
	      (spf_err = SPF_request_query_fallback(spf_request,
						    &spf_responsemx,
						    SPF_MX_STR)))
	    {
	      fQuerySuccessful = 1;
	      fprintf(stderr,
		      LOGR "Fallback MX check \"" SPF_MX_STR "\" "
		      "(helo='%s', mailfrom='%s'): %s\n",
		      remote,
		      helo ? helo : "",
		      sender ? sender : "",
		      SPF_strresult(SPF_response_result(spf_responsemx)));
	      switch (SPF_response_result(spf_responsemx))
		{
		case SPF_RESULT_PASS:
		  envcmd(mxpass, NULL);
		  break;
		case SPF_RESULT_FAIL:
		  envcmd(mxfail, NULL);
		  break;
		default:
		  envcmd(mxunk, NULL);
		  break;
		}
	    }
	  else
	    {
	      fprintf(stderr,
		      LOGR "SPF_request_query_fallback \"" SPF_MX_STR "\" "
		      "(helo='%s', mailfrom='%s') failed: %s\n",
		      remote,
		      helo ? helo : "",
		      sender ? sender : "",
		      SPF_strerror(spf_err));
	    }
	}
    }

 done:
  if (NULL != spf_responsemx) SPF_response_free(spf_responsemx);
  if (NULL != spf_response) SPF_response_free(spf_response);
  if (NULL != spf_request) SPF_request_free(spf_request);
  if (NULL != spf_server) SPF_server_free(spf_server);

  if (0 == fQuerySuccessful)
    {
      envcmd(getenv("SPP_SPF_NO_RESULT"), NULL);
    }
      
  return 0;
}
