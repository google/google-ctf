#!/usr/bin/perl
package Mythos;
use warnings;
use strict;

use JSON;
use MIME::Base64;

use Dancer2;
set serializer => 'JSON';

use File::Slurp;

use lib '.';
use Game;
use Inventory;

use constant FILENAME => './data/events.json';

my $game_artifacts = {
    item_delegate    => sub {
                            my $obj = shift; 
                            if (defined $obj->{desc_filename}) {
                                $obj->{desc} = read_file($obj->{desc_filename});
                                return {
                                    name=>$obj->{name},
                                    desc=>$obj->{desc}
                                    };
                                } return $obj;
                            },
    mermaid_scale     => {
        name=>"Mermaid Scale",
        desc_filename=>"./data/mermaid_scale.txt"
    },
    angels_scarf      => {
        name=>"Angel Scarf",
        desc_filename=>"./data/angels_scarf.txt"
    },
    mew_plaque      => {
        name=>"Mew Plaque",
        desc_filename=>"./data/mew_plaque.txt"
    },
    mimic_gem      => {
        name=>"Mimic Gem",
        desc_filename=>"./data/mimic_gem.txt"
    }
};
my $all_events = {};

my %curr_games;

BEGIN {
    sub initEvents {
        my $json_text = read_file('./data/events.json');
        my $event_data = decode_json($json_text);
        my $event_ptr = $event_data->{"events"};
        my @events = @{$event_ptr};
        for my $i (0 .. $#events) {
            my $id = $event_data->{events}[$i]->{ev_id};
            $all_events->{$id} =  $event_data->{events}[$i];
        }
    }

    sub setAttribute {
        my $dst = shift;
        my $key_name = shift;
        my $value_ref = shift;
        if (!defined $key_name || $key_name eq '' || !defined $value_ref) {
            return 0;
        }
        no strict 'refs';
        *{"$dst"."::$key_name"} = $value_ref;
        use strict 'refs';
        return 1;
    }

    sub copyItems {
        my $dst = shift;
        my $src = shift;
        foreach my $key (keys %$src) {
            if (defined $dst->{$key} && ref $dst->{$key} eq 'HASH' && ref $src->{$key} eq 'HASH') {
                copyItems($dst->{$key}, $src->{$key});
            } elsif (!defined $dst->{$key}) {
                if (ref $src->{$key} ne 'HASH') {
                    $dst->{$key} = $src->{$key};
                } else {
                    foreach my $inner_key (keys %{$src->{$key}}) {
                        my $index = $src->{$key}->{$inner_key};
                        setAttribute($key, $inner_key, $game_artifacts->{$index});
                    }
                }
            } elsif (defined $dst->{$key} && ref $dst->{$key} ne 'HASH') {
                $dst->{$key} = $src->{$key};
            }
        }
        return $dst;
    }

    sub deserialize {
        my $items = shift;
        my $inv = new Inventory();
        my $final_score = copyItems($inv, $items);
        return $final_score;
    }

}

initEvents();

post '/game' => sub {
    my $player_name = (body_parameters->get('name'));
    my $game = new Game();
    $curr_games{$player_name} = $game;
    my $ev = $all_events->{$game->currEv()};
    return {
        success => 1,
        player => $player_name,
        ev_title => $ev->{ev_name},
        ev_desc => $ev->{ev_content},
        ev_choice => $ev->{ev_choice}
    };
};

post '/event' => sub { 
    my $choice = (body_parameters->get('choice'));
    my $player_name = (body_parameters->get('name'));
    if (!exists $curr_games{$player_name}) {
        return {
            success => 0
        };
    }
    my $game = $curr_games{$player_name};
    my $next = $all_events->{$game->currEv()}->{ev_choice}[$choice]{"goto"};
    $game->addEv($next);
    my $next_ev = $all_events->{$next};
    if ($game->currEv() == 20) {
        my $stats = deserialize(decode_json(decode_base64(body_parameters->get('items'))));
        $stats->{Game} = $player_name;
        $game->{inventory} = $stats;
        if ($game->{inventory}->can("hasAllItems")) {
            if ($game->{inventory}->hasAllItems($game_artifacts) == 1) {
                $next_ev = $all_events->{21};
            } else {
                $next_ev = $all_events->{22};
            }
        }
    }
    my $results = {
            success => 1,
            player => $player_name,
            ev_title => $next_ev->{ev_name},
            ev_desc => $next_ev->{ev_content},
            ev_choice => $next_ev->{ev_choice}
        };
        if (defined $next_ev->{ev_item}) {
            $results->{ev_item} = $next_ev->{ev_item};
        }
        if (defined $game->{inventory}) {
            foreach my $key (keys %{$game->{inventory}}) {
                $results->{items}->{$key} = $game->{inventory}->{$key};
            }
        }
        return $results;
};

1;
