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
 * This plugin allows max. $MAXBOUNCERCPTS recipients per message with
 * no envelope sender (bounce messages usually have no envelope sender).
 *
 * Compile with: gcc -O2 -s -o maxbouncercpts ./maxbouncercpts.c
 * Set in tcprules: MAXBOUNCERCPTS=1, 4, 0, etc...
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

int main()
{
  char *maxbr, *rcount, *sender;
  int mbr, rc;

  if (!(maxbr = getenv("MAXBOUNCERCPTS"))) return 0;

  if (!(sender = getenv("SMTPMAILFROM")))
    { fprintf(stderr, "maxbouncercpts: error: can't get SMTPMAILFROM env var\n"); return 0; }
  if (*sender) return 0; /* envelope sender address given */

  if (!(rcount = getenv("SMTPRCPTCOUNT")))
    { fprintf(stderr, "maxbouncercpts: error: can't get number of envelope recipients\n"); return 0; }

  rc = atoi(rcount); mbr = atoi(maxbr);
  if (rc < mbr) return 0; /* under limit */

  printf("E550 sorry, too many bounce recipients (#5.7.1)\n");
  fprintf(stderr, "maxbouncercpts: null sender mail to too many (%d) recipients\n", rc + 1);

  return 0;
}
