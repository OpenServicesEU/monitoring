#!/usr/bin/perl -w
# Copyright 2013 Michael Fladischer
# OpenServices e.U.
# office@openservices.at
#
# Perform timed DNS queries of various record types.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

use strict;
use lib "/usr/lib/nagios/plugins/";

use Net::DNS::Resolver;
use Net::DNS::Packet;
use Time::HiRes qw(gettimeofday tv_interval);
use List::Util qw(min max);
use Log::Message::Simple qw[:STD :CARP];

use Nagios::Plugin;
use Nagios::Plugin::Performance use_die => 1;

my $nagios = Nagios::Plugin->new(
    shortname => "DNS",
    version => "0.1",
    url => "http://openservices.at/services/infrastructure-monitoring/dns",
    usage => "Usage: %s ".
        "[-v|--verbose] ".
        "[-t <timeout>] ".
        "-H <host> ".
        "-p <port> ".
        "-q <query> ".
        "[-e <expected>] ".
        "-w <threshold> ".
        "-c <threshold> ",
);

# add valid command line options and build them into your usage/help documentation.
$nagios->add_arg(
    spec => 'host|H=s',
    help => "-H, --host=STRING\n".
        "The DNS server to send queries to.",
    required => 1,
);
$nagios->add_arg(
    spec => 'warning|w=i',
    help => "-w, --warning=INTEGER:INTEGER\n".
        "See http://nagiosplug.sourceforge.net/developer-guidelines.html#THRESHOLDFORMAT for the threshold format.",
    required => 1,
);
$nagios->add_arg(
    spec => 'critical|c=i',
    help => "-c, --critical=INTEGER:INTEGER\n".
        "See http://nagiosplug.sourceforge.net/developer-guidelines.html#THRESHOLDFORMAT for the threshold format.",
    required => 1,
);
$nagios->add_arg(
    spec => 'port|p=i',
    help => "-p, --port=INTEGER\n".
        "Port on the DNS server (default: 53).",
    required => 0,
    default => 53,
);
$nagios->add_arg(
    spec => 'query|q=s',
    help => "-q, --query=STRING\n".
        "The DNS record to query (e.g. www.example.com:A:IN).",
    required => 1,
);
$nagios->add_arg(
    spec => 'expected|e=s',
    help => "-e, --expected=STRING\n".
        "The expected DNS response to the query (e.g. 127.0.0.1:A:IN).",
    required => 0,
);

my %mapping = (
    'CNAME' => 'cname',
    'A' => 'address',
    'AAAA' => 'address',
    'MX' => 'exchange',
);

# Parse @ARGV and process arguments.
$nagios->getopts;

# Parse query string and set default values if necessary.
my %query;
($query{record}, $query{type}, $query{class}) = split /:/,$nagios->opts->get('query');
$query{type} ||= "A";
$query{class} ||= "IN";

# Parse expected string and set default values taken from the query string if necessary.
my %expected;
($expected{record}, $expected{type}, $expected{class}) = split /:/,$nagios->opts->get('expected');
$expected{type} ||= $query{type};
$expected{class} ||= $query{class};

# Create resolver using hostname and port.
my $res = Net::DNS::Resolver->new;
$res->nameservers($nagios->opts->get('host'));
$res->port($nagios->opts->get('port'));

# Create DNS request packet.
my $req = new Net::DNS::Packet($query{record}, $query{type}, $query{class});

msg("Sending DNS query:\n".$req->string, $nagios->opts->get('verbose'));
my $timer = [gettimeofday];
# Send DNS request packet using the resolver.
my $answer = $res->send($req);
# Calculate the time it took for the resolver to answer our request.
my $elapsed = tv_interval($timer) * 1000;
msg("Received DNS response:\n".$answer->string, $nagios->opts->get('verbose'));

my @result;

# Perfdata
$nagios->add_perfdata(
    label => "Latency",
    value => $elapsed,
    threshold => $nagios->threshold,
    uom => 'ms',
);

# Threshold check for the roundtrip time of the query.
if ($nagios->check_threshold(check => $elapsed) != OK) {
    push @result, {
        'code' => $nagios->check_threshold(check => $elapsed),
        'message' => "Check took to long: ${elapsed}ms",
    };
} else {
    push @result, {
        'code' => OK,
        'message' => "Check finished in: ${elapsed}ms",
    };
}

# I f a record is expected in as an anser to our query, iterate over the answer
# member and filter out results based on the expected record.
if ($nagios->opts->get('expected')) {
    if (grep {
        $_->type eq $expected{type} &&
        $_->class eq $expected{class} &&
        $_->{$mapping{$expected{type}}} eq $expected{record}
        } $answer->answer) {
        # We found at least one matching record.
        push @result, {
            'code' => OK,
            'message' => sprintf(
                "Expected answer found: %s:%s:%s",
                $expected{record},
                $expected{type},
                $expected{class}),
        };
    } else {
        # No matching record found, go CRITICAL.
        push @result, {
            'code' => CRITICAL,
            'message' => sprintf(
                "Could not find expected answer: %s:%s:%s",
                $expected{record},
                $expected{type},
                $expected{class}),
        };
    }
}

# Pick higher code from results and join messages
$nagios->nagios_exit(max(map { $_->{code} } @result), join "; ",map { $_->{message} } @result);
