#!/usr/bin/perl 
#
# Walk through source, add labels and make classes
#
use strict;
use warnings;

my %deplist;

#open class file and write preamble 
open(my $class, '>', 'tommath_class.h') or die "Couldn't open tommath_class.h for writing\n";
print {$class} << 'EOS';
#if !(defined(LTM1) && defined(LTM2) && defined(LTM3))
#if defined(LTM2)
#   define LTM3
#endif
#if defined(LTM1)
#   define LTM2
#endif
#define LTM1

#if defined(LTM_ALL)
EOS

foreach my $filename (glob 'bn*.c') {
   my $define = $filename;

   print "Processing $filename\n";

   # convert filename to upper case so we can use it as a define
   $define =~ tr/[a-z]/[A-Z]/;
   $define =~ tr/\./_/;
   print {$class} << "EOS";
#   define $define
EOS

   # now copy text and apply #ifdef as required 
   my $apply = 0;
   open(my $src, '<', $filename);
   open(my $out, '>', 'tmp');

   # first line will be the #ifdef
   my $line = <$src>;
   if ($line =~ /include/) {
      print {$out} $line;
   } else {
      print {$out} << "EOS";
#include "tommath_private.h"
#ifdef $define
$line
EOS
      $apply = 1;
   }
   while (<$src>) {
      if (!($_ =~ /tommath\.h/)) {
         print {$out} $_;
      }
   }
   if ($apply == 1) {
      print {$out} << 'EOS';
#endif
EOS
   }
   close $src;
   close $out;

   unlink $filename;
   rename 'tmp', $filename;
}
print {$class} << 'EOS';
#endif

EOS

# now do classes 

foreach my $filename (glob 'bn*.c') {
   open(my $src, '<', $filename) or die "Can't open source file!\n";

   # convert filename to upper case so we can use it as a define 
   $filename =~ tr/[a-z]/[A-Z]/;
   $filename =~ tr/\./_/;

   print {$class} << "EOS";
#if defined($filename)
EOS
   my $list = $filename;

   # scan for mp_* and make classes
   while (<$src>) {
      my $line = $_;
      while ($line =~ m/(fast_)*(s_)*mp\_[a-z_0-9]*/) {
          $line = $';
          # now $& is the match, we want to skip over LTM keywords like
          # mp_int, mp_word, mp_digit
          if (!($& eq 'mp_digit') && !($& eq 'mp_word') && !($& eq 'mp_int') && !($& eq 'mp_min_u32')) {
             my $a = $&;
             $a =~ tr/[a-z]/[A-Z]/;
             $a = 'BN_' . $a . '_C';
             if (!($list =~ /$a/)) {
                print {$class} << "EOS";
#   define $a
EOS
             }
             $list = $list . ',' . $a;
          }
      }
   }
   $deplist{$filename} = $list;

   print {$class} << 'EOS';
#endif

EOS
   close $src;
}

print {$class} << 'EOS';
#ifdef LTM3
#   define LTM_LAST
#endif

#include <tommath_superclass.h>
#include <tommath_class.h>
#else
#   define LTM_LAST
#endif
EOS
close $class;

#now let's make a cool call graph... 

open(my $out, '>', 'callgraph.txt');
my $indent = 0;
my $list;
foreach (sort keys %deplist) {
   $list = '';
   draw_func($deplist{$_});
   print {$out} "\n\n";
}
close $out;

sub draw_func
{
   my @funcs = split ',', $_[0];
   if ($list =~ /$funcs[0]/) {
      return;
   } else {
      $list = $list . $funcs[0];
   }
   if ($indent == 0) {
   } elsif ($indent >= 1) {
      print {$out} '|   ' x ($indent - 1) . '+--->';
   }
   print {$out} $funcs[0] . "\n";
   shift @funcs;
   my $temp = $list;
   foreach my $i (@funcs) {
      ++$indent;
      draw_func($deplist{$i}) if exists $deplist{$i};
      --$indent;
   }
   $list = $temp;
   return;
}

