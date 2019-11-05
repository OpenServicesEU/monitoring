#!/usr/bin/perl -w
# Copyright 2015 Michael Fladischer
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

use Net::DNS::Resolver;
use Net::DNS::Packet;
use Time::HiRes qw(gettimeofday tv_interval);
use List::Util qw(min max);
use Log::Message::Simple qw[:STD :CARP];

use Monitoring::Plugin;
use Monitoring::Plugin::Performance use_die => 1;

my $monitor = Monitoring::Plugin->new(
    shortname => "DNS",
    version => "0.3",
    url => "http://openservices.at/services/infrastructure-monitoring/dns",
    usage => "Usage: %s ".
        "-H <host> ".
        "-q <query> ".
        "-w <threshold> ".
        "-c <threshold> ".
        "[-e <expected>] ".
        "[-p <port>] ".
        "[-t <timeout>] ".
        "[-v|--verbose]",
);

# add valid command line options and build them into your usage/help documentation.
$monitor->add_arg(
    spec => 'host|H=s',
    help => "-H, --host=STRING\n".
        "The DNS server to send queries to.",
    required => 1,
);
$monitor->add_arg(
    spec => 'warning|w=i',
    help => "-w, --warning=INTEGER:INTEGER\n".
        "Time in milliseconds that the query is allowed to take before this check returns WARNING.\n".
        "See http://nagiosplug.sourceforge.net/developer-guidelines.html#THRESHOLDFORMAT for the threshold format.",
    required => 1,
);
$monitor->add_arg(
    spec => 'critical|c=i',
    help => "-c, --critical=INTEGER:INTEGER\n".
        "Time in milliseconds that the query is allowed to take before this check returns CRITICAL.\n".
        "See http://nagiosplug.sourceforge.net/developer-guidelines.html#THRESHOLDFORMAT for the threshold format.",
    required => 1,
);
$monitor->add_arg(
    spec => 'port|p=i',
    help => "-p, --port=INTEGER\n".
        "Port on the DNS server (default: 53).",
    required => 0,
    default => 53,
);
$monitor->add_arg(
    spec => 'query|q=s',
    help => "-q, --query=STRING\n".
        "The DNS record to query (e.g. www.example.com:A:IN).",
    required => 1,
);
$monitor->add_arg(
    spec => 'expected|e=s@',
    help => "-e, --expected=STRING\n".
        "The expected DNS response to the query (e.g. 127.0.0.1:A:IN).",
    required => 0,
);

my %mapping = (
    'CNAME' => sub { return shift->{cname}->{name} },
    'A' => sub { return shift->address },
    'AAAA' => sub { return shift->address },
    'MX' => sub {return shift->{exchange}->{name} },
);

# Parse @ARGV and process arguments.
$monitor->getopts;

# Parse query string and set default values if necessary.
my %query;
($query{record}, $query{type}, $query{class}) = split /:/,$monitor->opts->get('query');
$query{type} ||= "A";
$query{class} ||= "IN";

# Parse expected string and set default values taken from the query string if necessary.
my @expected = ();
if ($monitor->opts->get('expected')) {
    foreach my $expected (@{$monitor->opts->get('expected')}) {
        my %variant;
        ($variant{record}, $variant{type}, $variant{class}) = split /:/ , $expected;
        $variant{type} ||= $query{type};
        $variant{class} ||= $query{class};
        push @expected, \%variant;
    }
}

# Create resolver using hostname and port.
my $res = Net::DNS::Resolver->new;
$res->nameservers($monitor->opts->get('host'));
$res->port($monitor->opts->get('port'));

# Set timeout for both TCP and UDP if one was specified.
if ($monitor->opts->get('timeout')) {
  $res->tcp_timeout($monitor->opts->get('timeout'));
  $res->udp_timeout($monitor->opts->get('timeout'));
}

# Create DNS request packet.
my $req = new Net::DNS::Packet($query{record}, $query{type}, $query{class});

msg("Sending DNS query:\n".$req->string, $monitor->opts->get('verbose'));
my $timer = [gettimeofday];
# Send DNS request packet using the resolver.
my $answer = $res->send($req);
# Calculate the time it took for the resolver to answer our request.
my $elapsed = tv_interval($timer) * 1000;
msg("Received DNS response:\n".$answer->string, $monitor->opts->get('verbose'));

my @result;

# Perfdata
$monitor->add_perfdata(
    label => "Latency",
    value => $elapsed,
    threshold => $monitor->threshold,
    uom => 'ms',
);

# Threshold check for the roundtrip time of the query.
if ($monitor->check_threshold(check => $elapsed) != OK) {
    push @result, {
        'code' => $monitor->check_threshold(check => $elapsed),
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
foreach my $variant (@expected) {
    if (grep {
        $_->type eq $variant->{type} &&
        $_->class eq $variant->{class} &&
        $mapping{$variant->{type}}($_) eq $variant->{record}
        } $answer->answer) {
        # We found at least one matching record.
        push @result, {
            'code' => OK,
            'message' => sprintf(
                "Expected answer found: %s:%s:%s",
                $variant->{record},
                $variant->{type},
                $variant->{class}),
        };
    } else {
        # No matching record found, go CRITICAL.
        push @result, {
            'code' => CRITICAL,
            'message' => sprintf(
                "Could not find expected answer: %s:%s:%s",
                $variant->{record},
                $variant->{type},
                $variant->{class}),
        };
    }
}

# Pick higher code from results and join messages
$monitor->plugin_exit(max(map { $_->{code} } @result), join "; ",map { $_->{message} } @result);
