#!/usr/bin/perl
#
# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

use JSON qw/to_json from_json/;
use List::Util qw/shuffle/;
use Digest::HMAC_SHA1 qw/hmac_sha1_hex/;
use strict;
use warnings;
use utf8;
$| = 1;

# TODO(rjamet):
# - better randomness (/dev/rand ?)
# - more tuning of the basic params
# - limits on accounts/cards/linking ? for now it's just unhex
# - final answer seems to accept '0' or '' instead of '00'

my $DIFFICULTY = 1; # 0: dumb, 1: easy (200-300-ish ?), 2: hard (slightly more?)
my $EMOJIS = 0;

open(my $flagfile, "flag.txt") or die("no flag file?");
my $FLAG = join "", <$flagfile>; chomp $FLAG;
my $KEY = join "", map chr(rand 1 << 8), 1 .. 16;

sub unhex {
 my $d = shift; return sprintf("0x%x", ($d < 10e6) ? $d : die("too big"));
}

# The obfuscation function. Doesn't have to be fancy: I think this one couldn't
# even be decrypted.
sub OBFUSCATOR {
   if ($DIFFICULTY == 0) { #Test mode, don't crypt
     return shift;
   } else {
     my $r = hmac_sha1_hex(shift, $KEY);
     $r =~ s/^(.{16}).+/$1/;
     # That should probably be disabled if it causes issues
     if ($EMOJIS) {
       $r =~ tr/0123456789abcdef/🚵🌹💕👌🎩⛹👻❄💩💉☣🌵💯☠🐵☢/;
     }
     return $r;
   }
}

sub difficultyBasedSelection {
  my @v = (shift, shift, shift);
  return $v[$DIFFICULTY];
}

# Repos of cards and accounts. Each point to a list of names for the other.
my %ALL_ACCOUNTS;
my %ALL_CARDS;

# The various settings for difficulty.
# For these, I think higher is harder (more noise), but not significantly so.
# If you're writing nearly-deterministic solutions, it's probably just a matter
# of tuning your parameters to have slightly more distinctive patterns.
my $NB_CARDS = difficultyBasedSelection(10, 300, 1000);
my $NB_ACC = difficultyBasedSelection(10, 300, 1000);

# More complex here: higher gets much easier very fast. With 5, it's likely
# trivial to find a specific node (attach a star of degree 5 nodes, for
# instance, as they get common). 2 or 3 is likely right.
my $NB_CARDS_PER_ACCOUNT_MAX = difficultyBasedSelection(5, 3, 3);
my $NB_ACCOUNTS_PER_CARD_MAX = difficultyBasedSelection(5, 3, 3);

# Higher is harder. 0 makes it more predictible for deanonymization, but keep in
# mind that solving the puzzle requires being able to link to the target nodes.
# I've got good solutions in mind if there's at least 2 attacker-controlled
# edges per target card, and I think it's possible to work something out with
# a single edge too.
my $NB_ACCOUNTS_PER_CHALLENGE_CARD_STARTUP = difficultyBasedSelection(0, 0, 1);

# How many target cards (good protection against brute forcing). My solutions
# are O(x^2) in this, so too high isn't a good idea, 128 should be enough for
# all purposes. Should be lower than $NB_CARDS.
my $CHALLENGE_BITS = difficultyBasedSelection(1, 64, 64);

# The chall itself: a list of special cards that can either be tagged or not.
my $challengeAnswer = "";
my %flaggedChallengeCards;
my %flaggedRegularCards;

# Run the challenge cards generation.
for my $specialCard (map {"ccard".(unhex $_)} 1..$CHALLENGE_BITS) {
  my $bit = int rand(2);
  $challengeAnswer .= $bit;
  $flaggedChallengeCards{$specialCard} = $bit ? '🚨' : '';

  $ALL_CARDS{$specialCard} = [];
}

# Generate the regular cards.
for my $regularCard (map {"*rcard".(unhex $_)} $CHALLENGE_BITS+1..$NB_CARDS) {
  $ALL_CARDS{$regularCard } = [];
  if (rand(5) < 1) {
    # Add some noise to show the flagged field even if the user doesn't link it
    $flaggedRegularCards{$regularCard} = '🚨';
  }
}

# And regular accounts.
for my $n (1..$NB_CARDS) {
  $ALL_ACCOUNTS{"*raccount" . (unhex $n)} = [];
}

# Associate cards and accounts.
for my $regularCard (map {"*rcard".(unhex $_)} $CHALLENGE_BITS+1..$NB_CARDS) {
  my $nbAssociations = int rand($NB_ACCOUNTS_PER_CARD_MAX + 1); # 0 to x
  my @okAccounts =
      shuffle
      grep {@{$ALL_ACCOUNTS{$_}} < $NB_CARDS_PER_ACCOUNT_MAX}
      keys %ALL_ACCOUNTS;
  for (0..$nbAssociations - 1) {
    my $acc = pop @okAccounts or die(
        "No account can satisfy the constraints. ".
        " Tell the organizers if that pops too often.");
    push (@{$ALL_CARDS{$regularCard}}, $acc);
    push (@{$ALL_ACCOUNTS{$acc}}, $regularCard);
  }
}

# Same for target cards, but associate less accounts.
for my $specialCard (map {"ccard".(unhex $_)} 1..$CHALLENGE_BITS) {
  my $nbAssociations = int rand($NB_ACCOUNTS_PER_CHALLENGE_CARD_STARTUP + 1);
  my @okAccounts =
      shuffle
      grep {@{$ALL_ACCOUNTS{$_}} < $NB_CARDS_PER_ACCOUNT_MAX}
      keys %ALL_ACCOUNTS;
  for (0..$nbAssociations - 1) {
    my $acc = pop @okAccounts or die(
        "No account can satisfy the constraints. ".
        "Tell the organizers if that pops too often.");
    push (@{$ALL_CARDS{$specialCard}}, $acc);
    push (@{$ALL_ACCOUNTS{$acc}}, $specialCard);
  }
}

print "".
  "Hey. ".
  "Could you tell me if my cards ccard0x1 through ccard".
  (unhex($CHALLENGE_BITS))." have attracted the wrong type of attention? ".
  "Flagged cards are displayed in their dumps, and their encryption is ".
  "deterministic. I seem to have the wrong encoding on my terminal, so I'll ".
  "need help there.\n".
  "I'll patch you into a management interface in a few seconds.\n\n\n";

# outside of test mode, sleep to avoid bruteforces
sleep(difficultyBasedSelection(0,3,3));

print "".
  "Welcome to our telnet dogecoin exchange !.\n".
  "We've currently frozen most of the operations pending ".
  "an investigation into potential credit card fraud with law enforcement.\n".
  " - NEWACC to create an account.\n".
  " - NEWCARD to create a test credit card.\n".
  " - ASSOC <cardx> <accounty> to associate cardx to accounty.\n".
  " - BACKUP to generate a anonymized encrypted jsonified maybe-emojified backup.\n";

my $userCardCounter = 1;
my $userAccountCounter = 1;

# The interactive part. Simple input loop, but that's enough to work.
while(1) {
  my $line = lc <>;
  if (!$line) {die("No input.");}
  chomp $line;
  if ($line =~ /^NEWACC/i) { # TODO(rjamet): limit this ?
    if(!exists $ALL_ACCOUNTS{"uaccount".(unhex $userAccountCounter)}) {
      print "OK: Account uaccount".(unhex $userAccountCounter)." created.\n";
      $ALL_ACCOUNTS{"uaccount".(unhex $userAccountCounter)} = [];
      $userAccountCounter++;
    }
  } elsif ($line =~ /^NEWCARD/i) { # TODO(rjamet): limit this ?
    if(!exists $ALL_CARDS{"ucard".unhex $userCardCounter}) {
      print "OK: Card ucard".(unhex $userCardCounter)." created.\n";
      $ALL_CARDS{"ucard".(unhex $userCardCounter)} = [];
      $userCardCounter++;
    }
  # WARNING: that [\w\d]+ is important, since it ensures the solver can't touch
  # regular accounts and regular cards (i.e. noise). User accounts, user cards,
  # and target cards are fair game and are meant to be accessed.
  } elsif ($line =~ /^ASSOC ([\w\d]+) ([\w\d]+)/i) {
    if (!exists $ALL_CARDS{$1}) {
      print "KO: No card named ".$1.".\n"; next;
    } elsif (!exists $ALL_ACCOUNTS{$2}) {
      print "KO: No account named ".$2.".\n"; next;
    } elsif (@{$ALL_CARDS{$1}} >=  $NB_ACCOUNTS_PER_CARD_MAX) {
      print "KO: Too many accounts already use this card.\n"; next;
    } elsif (@{$ALL_ACCOUNTS{$2}} >= $NB_CARDS_PER_ACCOUNT_MAX) {
      print "KO: Too many cards used by this account.\n"; next;
    } elsif (grep {$_ eq $2} @{$ALL_CARDS{$1}}) {
      print "KO: Those are already associated.\n"; next;
    } else {
      push (@{$ALL_CARDS{$1}}, $2);
      push (@{$ALL_ACCOUNTS{$2}}, $1);
      print "OK: Card $1 associated with account $2.\n"; next;
    }
  } elsif ($line =~ /^BACKUP/i) {
    last;
  } elsif ($line =~ /^EMOJIS/i) {
    $EMOJIS = 1;
  } else {
    print "KO: Wait, what?\n";
  }
}

# Dump the DB.
my @data;

# The shuffles are important
for my $account (shuffle keys %ALL_ACCOUNTS) {
  my %accDb;
  $accDb{$EMOJIS ? '📒' : 'account'} = OBFUSCATOR $account;
  $accDb{$EMOJIS ? '💳💳💳' : 'cards'} = [];
  for my $card (shuffle @{$ALL_ACCOUNTS{$account}}) {
    my %cardDb;
    $cardDb{$EMOJIS ? '💳' : 'card'} = OBFUSCATOR $card;
    if( $flaggedChallengeCards{$card} ){
      $cardDb{$EMOJIS ? '👮' : 'flagged'} = $EMOJIS ? '🚨' : '1';
    } elsif ($flaggedRegularCards{$card} ){
      $cardDb{$EMOJIS ? '👮' : 'flagged'} = $EMOJIS ? '🚨' : '1';
    }
    push @{$accDb{$EMOJIS ? '💳💳💳' : 'cards'}}, \%cardDb;
  }
  push @data, \%accDb;
}

# At this point, things are weirdly ordered. Part of it is Perl's own hashtable
# weirdness, that runs depending on hash keys. I don't think it matters here:
# we're inserting in a random order, due to the shuffles above, and the values
# are encrypted crap.
print to_json(\@data, {utf8 => 1})."\n";

print "\n\n".
  "So, which cards are burnt?\n".
  "Answer with a string of zeroes and ones, no spaces.\n";

my $line = <>;
if (!$line) {die("No input.");}
chomp $line;

if ($line eq sprintf("%0".$CHALLENGE_BITS."s", $challengeAnswer)) {
  print "$FLAG\n";
} else {
  print "Wait, that's not right. I expected " .
      sprintf("%0".$CHALLENGE_BITS."s",$challengeAnswer) . "...\n";
}
