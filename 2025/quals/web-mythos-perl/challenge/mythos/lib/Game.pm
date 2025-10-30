#!/usr/bin/perl
use lib '.';

package Game;

use Exporter qw(import);
@EXPORT = qw(new, events, addEv, currEv);

sub new {
    my $class = shift;
    my $self = {
        events           =>     [0]
    };
    bless $self, $class;
    return $self;
}

sub events {
    my $self = shift;
    return $self->{events};
}

sub addEv {
    my ($game) = shift;
    my ($event) = shift;
    push @{$game->{events}}, $event;
}

sub currEv {
    my ($game) = shift;
    return $game->{events}[-1];
}

1;