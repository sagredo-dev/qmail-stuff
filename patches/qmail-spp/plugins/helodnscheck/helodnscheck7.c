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
*/

/*
	(2008) modifyed by Bing Ren <bingtimren (at) gmail.com> to further check
	if the TCPREMOTEIP variable (mostly set by tcpserver) match
	any of the IP addresses the HELO resolves to.

	(2022) modified by Roberto Puzzanghera <roberto dot puzzanghera at sagredo dot eu>
	to deny HELOs containing one of our domains, when RELAYCLIENT is
	not defined. In addition, it is now possible to deny only not solving
	hosts in HELO/EHLO.

	Depending on the environment variable HELO_DNS_CHECK, deny, log and/or
	add a header if HELO doesn't solve to an address or the addresses don't
	contain the TCPREMOTEIP

	[default] - deny if HELO doesn't solve to a record
		P - passthrough, don't deny even HELO don't solve to A record
		    (of course, use with L and/or H)
		B - Block if TCPREMOTEIP not contained in the addresses solved
		L - Log
		H - add Header "X-Helo-Check"
		R - if "RELAYCLIENT" is set, don't do anything
		D - Debug mode (use with L)
		V - deny if "RELAYCLIENT" is NOT set and the HELO is one of our IPs
			contained in control/moreipme. "localhost" will be denied as well.
			You don't want to use it together with B.
		I - Invalid hostname in HELO/EHLO (not solving) are denied.
			Using this one together with B is redundant.

	The above can be combined, so BL means block & log
	if TCPREMOTEIP is not set.

	Use in your tcprules like this
	111.222.333.444:allow, NOHELODNSCHECK="" // whitelist IP
	:allow,HELO_DNS_CHECK="PLRIV"

	Compile as follows:
	gcc -o /var/qmail/plugins/helodnscheck helodnscheck7.c -lresolv

	Note: If there is no HELO/EHLO argument, it defaults to a permanent block.
*/

#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>

char *qmaildir = "/var/qmail";

void block_permanent(const char* message, char *remote_ip) {
/*
    Bing Ren: the original helodnscheck print command "E",
    however, if the spam connection ignore the 553 error and
    continue send further commands, qmail-spp simply accept
    message and deliver it!
*/
	printf("R553 sorry, %s (#5.7.1)\n", message);
	fprintf(stderr, "helo-dns-check: blocked with: %s [%s]\n", message, remote_ip);
}

void block_temporary(const char* message) {
	printf("E451 %s (#4.3.0)\n", message);
	fprintf(stderr, "helo-dns-check: temporary failure: %s\n", message);
}

int my_exit(int fail, FILE *fp)
{
    // Close the file if still open
    if ( fp ) fclose (fp);

	return fail;
}

int search_in_file(char *str) {
	/*  @return  0: match not found
		         1: match found
				-1: file does not exist
	*/
	FILE *fp;
	int line_num = 1;
	char temp [512];
	char my_file[256];

	snprintf(my_file, 256, "%s/control/moreipme", qmaildir);
	if ( (fp = fopen(my_file, "r") ) == NULL) return my_exit(-1, fp);

	while ( fgets(temp, sizeof(temp), fp) != NULL ) {
		if ( (strstr(temp, str) ) != NULL ) return my_exit(1, fp);
		line_num++;
	}

	return my_exit(0, fp);
}

int main (void) {
	unsigned char dns_answer[1023];
	unsigned char rDNS[1023];
	char *helo_domain = getenv("SMTPHELOHOST");
	char *no_helo_check = getenv("NOHELODNSCHECK");
	char *remote_ip = getenv("TCPREMOTEIP");
	char *action = getenv("HELO_DNS_CHECK");
	struct hostent* result;

	/* skip if HELO_DNS_CHECK is not defined (submission service) */
    if ( !action ) return 0;

	/* debug active */
	if ( strpbrk(action,"D") ) {
		fprintf(stderr, "helo-dns-check: dbg: debug is active\n");
		fprintf(stderr, "helo-dns-check: dbg: action is %s\n", action);
	}

	if ( !remote_ip ) remote_ip = "";

	// skip if it's RELAYCLIENT
	if ( strpbrk(action,"R") && getenv("RELAYCLIENT") ) return 0;

	// skip if it's whitelisted (NOHELODNSCHECK defined)
	if ( no_helo_check ) return 0;

	if ( !helo_domain ) {
		block_permanent("no HELO/EHLO hostname has been sent.", remote_ip);
		return 0;
	}

    /* init DNS library */
	res_init();

	/* check A record */
	result = gethostbyname(helo_domain);

	/* check if there is any result */
	if ( !result ) {
		if ( h_errno == HOST_NOT_FOUND ) {

			if ( strpbrk(action,"H") )  printf("HX-Helo-Check: HELO [%s] from [%s] doesn't solve\n", helo_domain, remote_ip);

			if ( strpbrk(action,"L") )  fprintf(stderr, "helo-dns-check: HELO [%s] from [%s] doesn't solve\n", helo_domain, remote_ip);

			if ( strpbrk(action,"I") || !strpbrk(action,"P") ) block_permanent("invalid host name in HELO/EHLO command.", remote_ip);
		}

		else fprintf(stderr, "HELO DNS CHECK temporary failed, but let it go.\n");

		return 0;
	};

	int count=0;
	char* addr;

	/* print debug information */
	if ( strpbrk(action,"D") ) {
		fprintf(stderr, "helo-dns-check: dbg: result->h_name %s\n", result->h_name);
		fprintf(stderr, "helo-dns-check: dbg: result->h_aliases:\n");
		char* alias;
		while ( result->h_aliases[count] ) {
			alias=result->h_aliases[count];
			fprintf(stderr, "helo-dns-check: dbg: [%d] %s\n", count, alias);
			count++;
		};

		fprintf(stderr, "helo-dns-check: dbg: result->h_addrtype %d\n", result->h_addrtype);
		fprintf(stderr, "helo-dns-check: dbg: result->h_length %d\n", result->h_length);
		fprintf(stderr, "helo-dns-check: dbg: result->h_addr_list:\n");

		count=0;
		while ( result->h_addr_list[count] ) {
			addr=result->h_addr_list[count];
			inet_ntop(AF_INET, addr, rDNS, 1000);
			fprintf(stderr, "helo-dns-check: dbg: [%d] %s\n", count, rDNS);
			count++;
		};

		if ( *remote_ip ) fprintf(stderr, "helo-dns-check: dbg: remote host %s\n", remote_ip);
		else fprintf(stderr, "helo-dns-check: dbg: no remote ip $TCPREMOTEIP\n");
	}
	/* end debug */

	if ( !strpbrk(action,"DLHV") ) return 0;

	if ( !(*remote_ip) ) {
		fprintf(stderr, "helo-dns-check: TCPREMOTEIP not set, let it go.\n");
		return 0;
	};

    /***********************************************************************
        Check if the HELO/EHLO has one of our IPs as rDNS.
        Skip if RELAYCLIENT
     ***********************************************************************/
    if ( strpbrk(action,"V") && !getenv("RELAYCLIENT") ) {
	    char moreipme[256];
    	int result2;

		// deny localhost as HELO/EHLO
		if ( strpbrk(action,"D") ) fprintf(stderr, "helo-dns-check: dbg: helo_domain is %s\n", helo_domain);
		if ( strcmp(helo_domain,"localhost")==0 ) {
			if ( strpbrk(action,"L") ) fprintf(stderr, "helo-dns-check: invalid HELO/EHLO [%s]\n", helo_domain);
			block_permanent("HELO doesn't match IP", remote_ip);
			return 0;
		}

        // look for rDNS of remote IP
        count=0;
        while ( result->h_addr_list[count] ) {
            addr=result->h_addr_list[count];
            inet_ntop(AF_INET, addr, rDNS, 1000);

			// check it matches one of our own IPs listed in control/moreipme
            result2 = search_in_file(rDNS);
	        if( result2 == 1 ) {
    	        if ( strpbrk(action,"L") )
					fprintf(stderr, "helo-dns-check: HELO [%s] is a local domain but IP [%s] is not a RELAYCLIENT\n", helo_domain, remote_ip);
		            block_permanent("HELO doesn't match IP", remote_ip);
        		    return 0;
	        }
    	    else if( result2 == -1 ) {
        	    snprintf(moreipme, 256, "%s/control/moreipme", qmaildir);
            	if ( strpbrk(action,"L") ) fprintf(stderr, "helo-dns-check: file %s not found\n", moreipme);
        	}

            count++;
        };
    }

    /* check A record of host */

	int found=0;
	count=0;
	while ( result->h_addr_list[count] && (found==0) ) {
		addr=result->h_addr_list[count];
		inet_ntop(AF_INET, addr, rDNS, 1000);
		if ( strcmp(rDNS, remote_ip) == 0 ) found = 1;
		count++;
	};

	if ( strpbrk(action,"D") ) fprintf(stderr, "helo-dns-check: dbg: found = %d\n", found);

	if ( found == 1 ) return 0;

	if ( strpbrk(action,"H") ) printf("HX-Helo-Check: HELO [%s] doesn't match IP [%s]\n", helo_domain, remote_ip);

	if ( strpbrk(action,"L") ) fprintf(stderr, "helo-dns-check: HELO [%s] doesn't match IP [%s]\n", helo_domain, remote_ip);

	if ( strpbrk(action,"B") && (!strpbrk(action,"P")) ) block_permanent("HELO/EHLO command must provide FQDN that match your IP address.", remote_ip);

	return 0;
}

