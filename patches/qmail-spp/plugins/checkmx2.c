/*
 * Sample C code to check A/MX/SPF records for an address (on linux).
 *
 * compile with:    gcc checkmx.c -o checkmx -lresolv
 * usage: use this as a plugin for qmail see http://qmail-spp.sourceforge.net/
 *
 * The code is based on mfdnscheck.c plugin by Perolo Silantico
 * and getmx.c program Copyright (C) 2004 by HL Combrinck
 * This code is distributed under the terms of the GNU General Public License.
 *
 *
 *
 * revision By Iulian Stan (iulian@sphere.ro) and Andrei Pancu (mouseman@sphere.ro) 
 *
 * 1) added support for SPF check ( We DON'T use any SPF library, just match some IPs after digging after a TXT record)
 * Please NOTE that out SPF check is not supporting SPF redirect style, like:  TXT     "v=spf1 redirect=_spf.google.com". 
 * Maybe will be in a future release.
 *
 * 2) philosophy changed:
 * If A/MX/SFP is ok, checkmx will exit with A (accept mail - turn off qmail-spp in this session)
 * Else will not send 500 MSG and run remaining plugins(greylist in my case)
 *
 * common usage:
 * (script is now moved to [rcpt] for better logging purposes)
 *
 * [mail]
 * plugins/skip-if-relayclient
 * plugins/skip-if-smtpauthuser
 *
 * [rcpt]
 * plugins/checkmx
 * plugins/greylisting
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>

struct mx 
{
    int pref;
    char host[1024];
};

#ifndef HFIXEDSZ
# define HFIXEDSZ 12
#endif
#ifndef INT16SZ
# define INT16SZ sizeof(cit_int16_t)
#endif
#ifndef INT32SZ
# define INT32SZ sizeof(cit_int32_t)
#endif

#define OK 0
#define ERR_TEMPORARY -1
#define ERR_NOEXIST -2
#define ERR_PERMANENT -3

void block_permanent(const char* message,const char* ip,const char* from, const char* rcptto) {
/*  printf("E553 sorry, %s (#5.7.1)\n", message); */
  fprintf(stderr, "IP: %s, FROM: %s, RCPT: %s   ::: %s ::: - activating remaining plugins\n", ip, from, rcptto, message);  
}


void sender_checked(const char* message,const char* ip,const char* from, const char* rcptto) {
fprintf(stderr, "IP: %s, FROM: %s, RCPT: %s   ::: %s ::: \n", ip, from, rcptto, message);  
printf ("A\n");
}

void block_temporary(const char* message, const char* ip, const char* from, const char* rcptto) {
/*  printf("E451 %s (#4.3.0)\n", message); */
  fprintf(stderr, "IP: %s, FROM: %s , RCPT: %s  ::: %s ::: - activating remaining plugins\n", ip, from,rcptto, message);  
}

int ip_match(char *s1, char*s2)
{
  char *token,ip[16],mask[3];
  struct in_addr network1, network2;
  token = strstr(s1,"/");
  if (token)
    {
      strncpy(ip,s1,token-s1);
      ip[token-s1]=0;
      strcpy(mask,token+1);
      if (!inet_aton(ip,&network1)) return 0;
      if (!inet_aton(s2,&network2)) return 0;
      network1.s_addr=ntohl(network1.s_addr);
      network2.s_addr=ntohl(network2.s_addr);
      if((network1.s_addr & (0xffffffff<<(32-atoi(mask)))) == (network2.s_addr & (0xffffffff<<(32-atoi(mask))))) 
	{
	  return 1;
	}
      else return 0;
    }
  else
    {
      return !strcmp(s1,s2);
    }

}

int checkmx(char *dest, char* ip, int req_type)
{
	union
	{
		u_char bytes[1024];
		HEADER header;
    } ans;
	short TYPEFLAG=0;
	int ret;
	unsigned char *startptr, *endptr, *ptr;
	char expanded_buf[1024];
	unsigned short pref, type;
	int n = 0;
	int qdcount;
	struct hostent* h;
	unsigned char *token, *startip, *endip, *foundip;
	
	ret = res_query (dest, C_IN, req_type, (unsigned char *)ans.bytes, 
		sizeof(ans));

	if (ret < 0 && ((errno == ECONNREFUSED) || (errno == TRY_AGAIN)))
		return ERR_TEMPORARY;

	if ((ret<0)&&(req_type!=T_TXT)) {
		TYPEFLAG=1;
		ret = res_query (dest, C_IN, T_A, (unsigned char *)ans.bytes, 
			sizeof(ans));
		if (ret<0)
			if ((errno == ECONNREFUSED) || (errno == TRY_AGAIN))
				return ERR_TEMPORARY;
			else
				return ERR_NOEXIST;
	}

	if (ret > sizeof(ans)) ret = sizeof(ans);

	startptr = &ans.bytes[0];
	endptr = &ans.bytes[ret];
	ptr = startptr + HFIXEDSZ;	/* skip header */

	for (qdcount = ntohs(ans.header.qdcount); qdcount--; 
			ptr += ret + QFIXEDSZ)
	{
		if ((ret = dn_skipname(ptr, endptr)) < 0) return ERR_PERMANENT;
	}

	while(1)
	{
		memset (expanded_buf, 0, sizeof(expanded_buf));
		ret = dn_expand (startptr, endptr, ptr, expanded_buf,
				sizeof(expanded_buf));
		if (ret < 0) break;
		ptr += ret;

		GETSHORT (type, ptr);
		ptr += INT16SZ + INT32SZ;
		GETSHORT (n, ptr);

		if(!TYPEFLAG && type== T_MX) 
		  {
		    int i;
		    GETSHORT(pref, ptr);
		    ret = dn_expand(startptr, endptr, ptr, expanded_buf,
				    sizeof(expanded_buf));
		    ptr += ret;
		    h = gethostbyname(expanded_buf);
		    if (h==NULL) break;
		    for (i=0; h->h_addr_list[i]!=NULL; i++)
		      if (! strcmp(inet_ntoa(*(struct in_addr *)(h->h_addr_list[i])), ip) )
			return OK;
		  }
		else if (!TYPEFLAG && type == T_TXT) 
		  {
		    /*    
		    char testip[]="ip4:10.1.1.2/30";
		    ptr=testip;
		    */
		    token = ptr;
		    foundip = NULL;
		    while(token!=NULL)
		      {
			
			token = strstr(token,"ip4:");
			if (token) 
			  {
			    startip = token+4;
			    endip = strstr(startip," ");
			    if(!endip) endip= token+strlen(token)+1;
			    foundip = malloc(endip-startip+1);
			    strncpy(foundip,startip,endip-startip);
			    foundip[endip-startip]=0;
			    token = endip;
			  }
			if (foundip) 
			  {
			    
			    if(ip_match(foundip,ip))
			      {
				return OK;
			      };     	   
			  }
			free(foundip);
			foundip=NULL;
		      }
		  }
		else if (TYPEFLAG && type != T_A) ptr+=n;
		
	}

	return ERR_PERMANENT;
}


int main(argc, argv)
	int argc;
	char *argv[];
{

	char *ip=getenv("TCPREMOTEIP");
	char *from = getenv("SMTPMAILFROM");
	char *rcptto = getenv("SMTPRCPTTO");
	char *auth = getenv("RELAYCLIENT");
	char *from_domain;
/*
	char *ip="198.24.6.1";
	char *from = "iulian@ericsson.com";
	char *rcptto = "iulian@vipnet.ro";
	char *auth = NULL;
	char *from_domain;
*/

	/* If user is Authorised using SMTP AUTH then we skip MX checks */
	if (auth) return 0;

	if (!from) {
	
		block_permanent("no MAIL FROM envelope header has been sent.", ip, from, rcptto);

		return 0;
	}

	if (!ip) {
		block_permanent("no remote address present.", ip, from, rcptto);
		return 0;
	}

	from_domain = strrchr(from, '@');
	if (!from_domain || (strlen(from_domain) <= 1)) {
		block_permanent("invalid mail address in MAIL FROM envelope header.", ip, from, rcptto);
		return 0;
	}
	from_domain++;
	/*schimba mai jos*/
	int mx_result,txt_result;
	mx_result = checkmx(from_domain, ip, T_MX);

	if(OK == mx_result) 
	  {
	    sender_checked("A/MX checked, mail ACCEPTED, all remaining plugins disabled", ip, from, rcptto);
	    return 0;
	  }
	else
	  {
	    txt_result = checkmx(from_domain, ip, T_TXT);
	    if(OK == txt_result)
	      {
		sender_checked("SPF checked, mail ACCEPTED, all remaining plugins disabled", ip, from, rcptto);
		return 0;	
	      }
	    else 
	      {
		/*eroare la ambele...*/
		switch (mx_result){
		case ERR_TEMPORARY:
		  block_temporary("DNS temporary failure.", ip, from, rcptto);
		  break;
		case ERR_NOEXIST:
		  if (ERR_TEMPORARY == txt_result)
		    {
		     block_temporary("DNS temporary failure.", ip, from, rcptto);
		     break;  
		    }
		  block_permanent("your envelope sender domain must exist.", ip, from, rcptto);
		  break;
		case ERR_PERMANENT:
		  if (ERR_TEMPORARY == txt_result)
		    {
		      block_temporary("DNS temporary failure.", ip, from, rcptto);
		      break;  
		    }
		  block_permanent("550 No SPF/MX record for sender's domain!", ip, from, rcptto);
		  break;
		case OK: default:
		  return 0;
		}
	      }
	  }
	return 0;
}
