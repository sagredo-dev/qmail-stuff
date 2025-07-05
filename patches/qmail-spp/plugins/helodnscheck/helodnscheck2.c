/*
* Copyright (C) 2007 Jason Frisvold <friz@godshell.com>
* Original Copyright (C) 2003-2004 Perolo Silantico <per.sil@gmx.it>
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
***
* 1/16 Modified original version to check helo/ehlo instead of mail from
***
*
* $Id$
*
*/

/* (2008) modifyed by Bing Ren <bingtimren (at) gmail.com> to further check
   if the TCPREMOTEIP variable (mostly set by tcpserver) match
   any of the IP addresses the HELO resolves to.
   Depending on the environment variable HELO_DNS_CHECK, deny, log and/or
   add a header if HELO doesn't solve to an address or the addresses don't
   contain the TCPREMOTEIP

	[default] - deny if HELO doesn't solve to a record
        P - passthrough, don't deny even HELO don't solve to A record
            (of course, use with L and/or H)
        D - deny if TCPREMOTEIP not contained in the addresses solved
        L - log
        H - add header "X-Helo-Check"
        R - if "RELAYCLIENT" is set, don't do anything

   the above can be combined, so DL means deny & log
   if TCPREMOTEIP is not set, log but allow

   Compile as follows: gcc -o helodnscheck helodnscheck2.c -lresolv

   Note: If there is no HELO/EHLO argument, it defaults to a permanent block.
*/


#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <netdb.h>

void block_permanent(const char* message) {

/* Bing Ren: the original helodnscheck print command "E",
   however, if the spam connection ignore the 553 error and 
   continue send further commands, qmail-spp simply accept
   message and deliver it! */

  printf("R553 sorry, %s (#5.7.1)\n", message);
  fprintf(stderr, "helo-dns-check: blocked with: %s\n", message);  
}

void block_temporary(const char* message) {
  printf("E451 %s (#4.3.0)\n", message);
  fprintf(stderr, "helo-dns-check: temporary failure: %s\n", message);  
}

int main(void) {
 unsigned char dns_answer[1023];
 unsigned char print_address[1023];
 char *helo_domain = getenv("SMTPHELOHOST");
 char *no_helo_check = getenv("NOHELODNSCHECK");
 char *remote_ip = getenv("TCPREMOTEIP");
 char *action = getenv("HELO_DNS_CHECK");
 struct hostent* result;

  if (!action) {
    action = "";
  };

  if (!remote_ip) {
    remote_ip = "";
  };

  if (strpbrk(action,"R") && getenv("RELAYCLIENT"))
     return 0;

  if (no_helo_check) {
     return 0;
  }

  if (!helo_domain) {
    block_permanent("no HELO/EHLO hostname has been sent.");
    return 0;
  }


  /* init DNS library */
  res_init();

  /* check A record */
  result = gethostbyname(helo_domain);

  /* check if there is any result */
  if (!result) {
    if (h_errno == HOST_NOT_FOUND) {

       if (strpbrk(action,"H")) 
          printf("HX-Helo-Check: HELO [%s] from [%s] doesn't solve\n", helo_domain, remote_ip);

       if (strpbrk(action,"L")) 
          fprintf(stderr, "helo-dns-check: HELO [%s] from [%s] doesn't solve\n", helo_domain, remote_ip);

       if (!strpbrk(action,"P"))
          block_permanent("invalid host name in HELO/EHLO command.");
    }
    else {
       fprintf(stderr, "HELO DNS CHECK temporary failed, but let it go.\n");
    };
    return 0;
  };

  int count=0;
  char* addr;

  /* print debug information */
  /*
  fprintf(stderr, "dbg: result->h_name %s\n", result->h_name);
  fprintf(stderr, "dbg: result->h_aliases:\n");
  char* alias;
  while (result->h_aliases[count]) {
    alias=result->h_aliases[count];
    fprintf(stderr, "dbg: [%d] %s\n", count, alias);
    count++;
  };

  fprintf(stderr, "dbg: result->h_addrtype %d\n", result->h_addrtype);
  fprintf(stderr, "dbg: result->h_length %d\n", result->h_length);
  fprintf(stderr, "dbg: result->h_addr_list:\n");

  count=0;
  while (result->h_addr_list[count]) {
     addr=result->h_addr_list[count];
     inet_ntop(AF_INET, addr, print_address, 1000);
     fprintf(stderr, "dbg: [%d] %s\n", count, print_address);
     count++;
  };
    
  if (*remote_ip) { 
     fprintf(stderr, "dbg: remote host %s\n", remote_ip);
  } else {
     fprintf(stderr, "dbg: no remote ip $TCPREMOTEIP\n");
  };

  */

  /* check A record of host */ 

  if (!strpbrk(action,"DLH"))
     return 0;

  if (!(*remote_ip)) {
     fprintf(stderr, "helo-dns-check: TCPREMOTEIP not set, let it go.\n");
     return 0;
  };

  int found=0;
  count=0;
  while (result->h_addr_list[count] && (found==0)) {
     addr=result->h_addr_list[count];
     inet_ntop(AF_INET, addr, print_address, 1000);
     if (strcmp(print_address, remote_ip) == 0) {
	found = 1;
     };
     count++;
  };

  /* fprintf(stderr, "dbg: found = %d\n", found);  */

  if (found == 1)
     return 0;

  if (strpbrk(action,"H")) 
     printf("HX-Helo-Check: HELO [%s] doesn't match IP [%s]\n", helo_domain, remote_ip);

  if (strpbrk(action,"L")) 
     fprintf(stderr, "helo-dns-check: HELO [%s] doesn't match IP [%s]\n", helo_domain, remote_ip);

  if (strpbrk(action,"D") && (!strpbrk(action,"P"))) 
     block_permanent("HELO/EHLO command must provide FQDN that match your IP address.");

  return 0;

}

