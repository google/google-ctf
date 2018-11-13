#!/usr/bin/perl
#
# Splits the list of files and outputs for makefile type files
# wrapped at 80 chars
#
# Tom St Denis
use strict;
use warnings;

my @a = split ' ', $ARGV[1];
my $b = $ARGV[0] . '=';
my $len = length $b;
print $b;
foreach my $obj (@a) {
   $len = $len + length $obj;
   $obj =~ s/\*/\$/;
   if ($len > 100) {
      printf "\\\n";
      $len = length $obj;
   }
   print $obj . ' ';
}

print "\n\n";

# ref:         HEAD -> develop
# git commit:  8b9f98baa16b21e1612ac6746273febb74150a6f
# commit time: 2018-09-23 21:37:58 +0200
