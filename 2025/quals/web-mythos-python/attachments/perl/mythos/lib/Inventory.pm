#!/usr/bin/perl
use lib '.';

package Inventory;

use Exporter qw(import);
@EXPORT = qw(new);

sub new {
    my $class = shift;
    my $self = {
        Game => "",
        Inventory => $class
    };

    bless $self, $class;
    return $self;
}

sub hasAllItems {
    my $inv = shift;
    my $game_artifacts = shift;
    foreach my $key (keys %$game_artifacts) {
        if (!exists $inv->{$key} and $key ne 'item_delegate') {
            return 0;
        }
        if ($key ne 'item_delegate') {
            $inv->{$key} = $game_artifacts->{item_delegate}($game_artifacts->{$key});
        }
        
    }
    return 1;
}

1;