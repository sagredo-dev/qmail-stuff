/*
 * Copyright (C) 2004 Pawel Foremski <pjf@asn.pl>
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
 ***
 *
 * Implements tarpitting
 *
 * Compile with: gcc -O2 -s -o tarpit ./tarpit.c
 * Set in tcprules: TARPITCOUNT=n,TARPITDELAY={n, NORMAL, MEDIUM, HARD}
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

int main()
{
  char *tcount, *tdelay, *rcount, *sender;
  int tc, rc;

  if (!(tcount = getenv("TARPITCOUNT")) ||
      !(tdelay = getenv("TARPITDELAY"))) return 0;

  if (!(rcount = getenv("SMTPRCPTCOUNT")))
    { fprintf(stderr, "tarpit: error: can't get number of envelope recipients\n"); return 0; }

  tc = atoi(tcount); rc = atoi(rcount);
  if (rc < tc) return 0; /* under limit */

  if (!(sender = getenv("SMTPMAILFROM")) || !*sender) sender = "unknown";

  if (rc == tc)
    fprintf(stderr, "tarpit: started tarpitting mail from <%s>\n", sender);

  switch (*tdelay) {
    case 'N': /* NORMAL */
        sleep((rc - tc + 1) * 2);
        break;
    case 'M': /* MEDIUM */
        sleep((rc - tc + 1) * 5);
        break;
    case 'H': /* HARD */
        sleep((rc - tc + 1) * (rc - tc + 1));
        break;
    default:
        sleep(atoi(tdelay));
        break;
  }

  return 0;
}
