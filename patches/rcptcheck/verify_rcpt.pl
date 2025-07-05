#!/usr/bin/perl

#########################################################################
# Qmail RCPTTO Verification Program for a backup MX Server
# (C) Ryan A. Brown, Base 16 Consulting, Inc., 2006 [http://www.b16c.com]
# Released under GNU Public License: http://www.gnu.org/copyleft/gpl.html
#########################################################################
# This script works with the RCPTTO patch:
#   http://www.soffian.org/downloads/qmail/qmail-smtpd-doc.html
# .. for qmail:
#   http://www.qmail.org
# .. and is meant to run on a backup MX server.  This script queries the
# primary MX server to see if the address is valid.  If it can't reach
# the primary MX server, it assumes the address is valid, allowing qmail
# to hold the message until the primary MX server comes up.  If it can
# reach the primary MX server, it can weed out bogus addresses before they
# are accepted and bounced or double-bounced.
#
# Just set the following variables:
my $hostname = 'backupmx.domain.com';  # name of this host
my $remote = 'primarymx.domain.com';   # name of primary MX server
my $port = 25;                      # port on which primary MX server listens

# Then put this script in your /var/qmail/bin directory, and add the following
# line to the end of your /etc/tcp.smtp file:
# :allow,RCPTCHECK="/var/qmail/bin/verify_rcpt.pl"
# .. and then run:
# tcprules /etc/tcp.smtp.cdb /etc/tcp.smtp.tmp < /etc/tcp.smtp
#########################################################################

use strict;
use Socket;

my $recipient = $ENV{RECIPIENT};

print STDERR "Check: $recipient\n";

$SIG{ALRM} = \&timeout;
alarm (15); # after 15 seconds if we can't reach primary MX, time out.

my $iaddr = inet_aton($remote) || exit (0);
my $paddr = sockaddr_in($port, $iaddr);
my $proto = getprotobyname ('tcp');
socket (SOCK, PF_INET, SOCK_STREAM, $proto) || exit (0);
print STDERR "Connecting to $remote port $port. . .\n";
connect (SOCK, $paddr) || exit (0);
select SOCK;
$| = 1;
select STDOUT;
print STDERR "Connected to $remote port $port.\n";
my $greeting = <SOCK> || exit (0);
print STDERR $greeting;
print STDERR "HELO $hostname\n";
print SOCK "HELO $hostname\r\n";
my $ok = <SOCK> || exit (0);
print STDERR $ok;
print STDERR "MAIL FROM:<" . $ENV{SENDER} . ">\n";
print SOCK "MAIL FROM:<" . $ENV{SENDER} . ">\r\n";
$ok = <SOCK> || exit (0);
print STDERR $ok;
if ($ok !~ /^250/) {
    # sender invalid!
    print STDERR "Sender invalid!  Exiting 100.\n";
    exit (100);
}
print STDERR "RCPT TO:<" . $ENV{RECIPIENT} . ">\n";
print SOCK "RCPT TO:<" . $ENV{RECIPIENT} . ">\r\n";
$ok = <SOCK> || exit (0);
print STDERR $ok;
if ($ok !~ /^250/) {
    # recipient invalid!
    print STDERR "Recipient, $recipient, invalid!  Exiting 100.\n";
    exit (100);
}
print STDERR "QUIT\n";
print SOCK "QUIT\r\n";
close (SOCK) || exit (0);

exit (0);

sub timeout {
    print STDERR "Timeout!  Accepting address as valid.\n";
    exit (0);
}
