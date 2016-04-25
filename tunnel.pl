#! /usr/bin/perl
use strict;

my $protip = shift;
my $targip = shift;
my $tun = "";
my $flag = "";
my ($client, $pip, $tun, $tip, $ports, $expr) ;

## Date replace module
sub repldate {
  my $how = shift;
  my $exp = shift;
  my ($y,$m,$d) = split("-", $exp);
  if ( $how eq "d" ) { $d++ ; }
  elsif ( $how eq "m" ) { $m++ ; }
  else { print("$how - $exp - How days?\n");exit;};
  if ( $d >= 31 ) { $d = 1; $m++ ;};
  if ( $m >= 13 ) { $m = 1; $y++ ;};
  $exp = "$y-$m-$d" ;
  return $exp;
}

unless ($targip && $protip) {
  print ("Usage: tunnel.pl <ProtectedIP> <NewTargetIP> or tunnel.sh <ProtectedIP> <day/month>\n\n"); exit;
};
unless ($protip=~/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/ &&(($1<=255 && $2<=255 && $3<=255 &&$4<=255 ))) {
  print ("$protip is not valid address\n"); exit
};

unless (($targip  =~ /^[dDmM]$/) || $targip eq "day" || $targip eq "month" || ( $targip=~/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/ &&($1<=255 && $2<=255 && $3<=255 &&$4<=255 ))) {
  print ("$targip is not valid value\n"); exit
};

my $file = "/ddguard/common/firewall/system/clients.pl";
my $cmd = `cp $file $file.bak`;

open(FH, "<" , $file) or die $!;
my @f = <FH>;
my @torepl = grep(/$protip\"/, @f);
my @repl = grep (!/^#/,@torepl);
if (defined $repl[1]) { print ("Many lines:\n",@repl); exit} ;

unless (defined $repl[0]) { print ("Cant find $protip in $file\n"); exit} ;
my ($type) = $repl[0] =~ m/^(\S+)\(/;
if ($targip eq "d" || $targip eq "D"||$targip eq "day") {
  $flag = "d";
}
elsif ($targip eq "m" ||$targip eq "M"|| $targip eq "month") {
  $flag = "m";
};

  if ($type eq "proxy_tunnel_new") {
    ($client, $pip, $tun, $tip, $ports, $expr) = $repl[0] =~ m/^\S+\(\"(\S+)\"\,\s\"(\S+)\"\,\s(\S+)\,\s\"(\S+)\"\,\s\[(.*)\]\,\s\"(\S+)\"\)\;/ ;
    print ("Replace\t: $repl[0]");
    if ($flag eq "d" || $flag eq "m") {
      $expr = repldate($flag,$expr);
      print ("To\t: $type\(\"$client\"\, \"$pip\"\, $tun\, \"$tip\", \[$ports\], \"$expr\"\)\n");
      for (@f) {
        if ($_ =~ /$protip\"\,\s$tun\,\ \"$tip/) {
          s/\"\d+\-\d+\-\d+\"\)\;/\"$expr"\)\;/ ;
        };
      };
    }
    else {
      print ("To\t: $type\(\"$client\"\, \"$pip\"\, $tun\, \"$targip\", \[$ports\], \"$expr\"\)\n");
      if ( $targip eq $tip ) { print ("Already changed\n"); exit };
      for (@f) {
        s/$protip\"\,\s$tun\,\ \"$tip/$protip\"\,\ $tun\,\ \"$targip/ ;
      };
    };
  }
  elsif ($type eq "proxy") {
    ($client, $pip, $tip, $ports, $expr) = $repl[0] =~      m/^\S+\(\"(\S+)\"\,\s\"(\S+)\"\,\s\"(\S+)\"\,\s\[(.*)\]\,\s\"(\S+)\"\)\;/ ;
    print ("Replace\t: $repl[0]");
    if ($flag eq "d"| $flag eq "m") {
      $expr = repldate($flag,$expr);
      print ("To\t: $type\(\"$client\"\, \"$pip\"\, \"$tip\", \[$ports\], \"$expr\"\)\n");
      for (@f) {
        if ($_ =~ /$protip\"\,\s\"$tip/) {
          s/\"\d+\-\d+\-\d+\"\)\;/\"$expr"\)\;/ ;
        };
      };
    }
    else {
      print ("To\t: $type\(\"$client\"\, \"$pip\"\, \"$targip\", \[$ports\], \"$expr\"\)\n");
      if ( $targip eq $tip ) { print ("Already changed\n"); exit };
      for (@f) { s/$protip\"\,\s\"$tip/$protip\"\,\ \"$targip/ ; } ;
    };
  }
  else { print ("Unknown service: $type"); exit; };

open(FHO, ">" , "$file.out");
print FHO (@f);
close FHO;
close FH;

my @diff = `diff $file $file.out`;
print ("\n========================================= Diff ==============================================\n",@diff,"\n=============================================================================================\n\n");
if ($flag ne "") {
  print ("Press enter to save.\n");
  my $case = (<STDIN>);
  chomp($case);
  unless ($case eq "") {print("Aborting\n"); exit;};
  my $cmd = `cp $file.out $file`;
  print "\n\"cp $file.out $file\" Success!\n\n";
}
else {
  print ("Diff is correct? (yes/No): ");
  my $case = (<STDIN>);
  chomp($case);
  if ($case eq "yes") {
    my $cmd = `cp $file.out $file`;
    print "\n\"cp $file.out $file\" Success!\n\n";

    if ($type eq "proxy_tunnel_new") {
        print ("Tunnel script:\n\n");
        print ("#!/bin/bash\n\nREMOTE_IP='$protip'\t# DDoS-Guard.NET tunnel server\nLOCAL_IP='$targip'\t\t\t# Client endpoint\nN=$tun\t\t\t\t# tunnel\n");
        print ("TUN_DEV=\"ddosguard\$N\"\n\ncase \"\$1\" in\n\tstart)\n\t\tip tunnel add \$TUN_DEV mode ipip remote \$REMOTE_IP local \$LOCAL_IP ttl 250\n\n\t\tip link set \$TUN_DEV up\n\t\tip addr add 10.0.\$N.2/32 peer 10.0.\$N.1 dev \$TUN_DEV\n\n\t\tip route add default via 10.0.\$N.1 dev \$TUN_DEV tab \$N\n\t\tip rule add from 10.0.\$N.2/32 tab \$N prio 5\n\n\t\t;;\n\n\tstop)\n\t\tip route del default via 10.0.\$N.1 dev \$TUN_DEV tab \$N\n\t\tip link set \$TUN_DEV down\n\t\tip rule del from 10.0.\$N.2/32 tab \$N\n\n\t\tip tunnel  del \$TUN_DEV\n\t\t;;\n\n\t*)\n\t\techo \"Usage: \$0 {start|stop}\"\n\t\t;;\nesac\n\n");
    };
    print ("Start apply script on echo2:\n");
    $cmd = `cd /ddguard/common/firewall/ && ./apply.sh` ;
    print ("Start apply script on echo4:\n");
    $cmd = `ssh \$SUDO_USER\@10.0.4.35 'sudo sh -c "cd /ddguard/common/firewall/ && ./apply.sh"'` ;
  }
  else { print ("Not copied\n"); };
}
