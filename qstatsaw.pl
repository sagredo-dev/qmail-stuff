#!/usr/bin/perl
#
# Thanks Bai Borko

use strict;
use warnings;

my $sendlog="/var/log/qmail/send/current";
my $smtpdlog="/var/log/qmail/smtpd/current";

my ($id,$from,$to,$size,$date,$shost,$rhost,$rip,$code,@tmps,@tmpl,%tmph);

#-------------------------------------------------------
# Functions
#-------------------------------------------------------
sub parsesend (){
  open my $fh, '<', $sendlog or die "Can't open file $sendlog";
  while (<$fh>) {
    $id //= 0; 
    if (/^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}.\d+) new msg (\d+)/) {
      $date=$1;
      $id=$2;
    }
    elsif (/info msg .* from/) {
      ($size,$from)=m/info msg $id: bytes (\d+) from <(.*)>/; 
      $from =~ s/-@\[\]$//g;
      if ($from =~ /@(.*)/) {
        $shost=$1; 
      }
    }
    elsif (/starting delivery (\d+): msg $id to local (.*)/) {
      $tmps[$1]=$1;
      $tmpl[$1]=$2;
    }
    elsif (/delivery (\d+): success:/) {
      my $t = $1;
      if (defined ($tmps[$t])) {
        if ($tmps[$t] eq $t) {
          if ($from eq "") { $from="unknown"; } # Accept null sender
          $tmpl[$t] =~ /(.*)-(.*)/;
          if ($shost eq $1) {
            $tmph{$date} = "$from $2 $shost $1 SMTP 250 $size";
          }
        }
      }
    }

    if(/Remote_host_said:/) {
      my ($date,$from,$to,$rip,$code) = ($_ =~ /^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}.\d+) .* <From:(.*)_To:(.*)>_(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})_\w+.\/Remote_host_said:_(\d{3})_?-?/);
      if ($to =~ /@(.*)/) {
        $rhost= $1;
      }
      if ($from =~ /@(.*)/) {
        $shost= $1;
      }
      $size //= 0;
      $tmph{$date} = "$from $to $shost $rhost SMTP $code $size";
    }
  }
}

sub parsesmtpd () {
  open my $fh, '<', $smtpdlog or die "Can't open file $smtpdlog";
  while (<$fh>) {
    if (/qlogreceived:/) {
      ($date,$code,$from,$to,$size,$rip,$rhost) = ($_ =~ /^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}.\d+) .* code=(\d{3}) .* mailfrom=(\S+)? rcptto=(\S+) .* size=(\d+) .* remoteip=(\S+) .* remotehost=(\S+) /);

      $size //= 0;
      $from //= "unknown"; # Accept null sender
      # IF is local sender with no SMTP AUTH remotehost= is not defined 
      if (defined($rhost)) {
        $tmph{$date} = "$from $to $rhost $rip SMTP $code $size";
      }
    }
  }
  close $fh;
}

#--------------------------------
# Main
#--------------------------------
parsesend;
parsesmtpd;

foreach my $fdate (sort keys %tmph) {
  print $fdate =~ s/.\d+$/ /r, $tmph{$fdate}."\n";
}
