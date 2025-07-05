/*
 * $Id: qmail-spp_rcptcheck.c 2021-12-19
 * Roberto Puzzanghera - https://notes.sagredo.eu
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

/*
 * Recipient check for qmail/vpopmail patched with qmail-spp.
 * Compile with: gcc -Wall -O2 -o qmail-spp_rcptcheck qmail-spp_rcptcheck.c -lcrypt -lmysqlclient -lvpopmail -L/home/vpopmail/lib -I/home/vpopmail/include
 *
 * Just call this program within /var/qmail/control/smtpplugins as follows:
 * [rcpt]
 * plugins/qmail-spp_rcptcheck
 *
 * @file qmail-spp_rcptcheck.c
   @return 0: virtual user exists
           1: virtual user does not exist
           111: temporary problem
 */

#include <dirent.h>
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "vpopmail.h"

void my_exit(int fail, DIR *dir)
{
	if (dir != NULL) closedir(dir);
	if (fail == 1) printf("E550 sorry, no mailbox by that name (#5.7.1)\n");
	exit(fail);
}

int main()
{
	char path[MAX_BUFF], *rcpt;
	DIR *dir = NULL;

	if (!(rcpt = getenv("SMTPRCPTTO"))) my_exit(111, dir);

        /* retrieve username/domain (assuming that MAV has already been done) */
        int i = 0;
        char *p = strtok (rcpt, "@");
        char *recipient[2];
        while (p != NULL)
        {
                recipient[i++] = p;
                p = strtok (NULL, "@");
        }

	/* recipient check */
	snprintf(path, MAX_BUFF, "%s/%s", vget_assign(recipient[1], NULL, 0, NULL, NULL), recipient[0]);

	dir = opendir(path);
	if (dir) my_exit(0, dir);
	else my_exit(1, dir);
}
