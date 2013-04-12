#!/usr/bin/perl
use strict;
use warnings;

use Switch;
use CGI;
use JSON;
use Monitoring::Livestatus;

my $q = CGI->new;
my $output;

my $ml = Monitoring::Livestatus->new(
    socket => "/var/lib/icinga/rw/live",
    errors_are_fatal => 1,
    warnings => 0,
);

print $q->header('application/json');
switch ($q->param('action')) {
    case "mapdata" {
        my $name  = $q->param('id');
        if ($name) {
            $output = $ml->selectall_arrayref("GET hosts\n".
                "Filter: name = ".$name, { Slice => {} });
        } else {
            $output = $ml->selectall_arrayref("GET hosts", { Slice => {} });
        }
    }
    else {
        $output = {};
    }
}
print encode_json $output;
