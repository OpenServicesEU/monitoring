#!/usr/bin/perl -w
# Copyright 2014 Michael Fladischer
# OpenServices e.U.
# office@openservices.at
#
# This is a optimized check for the OpenServices::SNMP::Plugin::Updates agent
# extension. It uses warning and critical thresholds to check if the time an
# update has been in the pending state should trigger a WARNING or CRITICAL
# status. If there are pending updates but none of them is pending more than the
# warning or critical threshold, then a status of OK is returned.
#
# If the OID is not found, then UNKNOWN is returned.
#
# This check uses Berkeley DB files to memorize the names and timestamps of
# pending updates.
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
use lib "/usr/local/nagios/libexec/";

use Log::Message::Simple qw[:STD :CARP];

use Nagios::Plugin::SNMP;
use Nagios::Plugin::Performance use_die => 1;

use DB_File;

my $nagios = Nagios::Plugin::SNMP->new(
    shortname => "SECURITY UPDATES",
    version => "0.1",
    url => "http://openservices.at/services/infrastructure-monitoring/security_updates",
    usage => "Usage: %s ".
        "[-v|--verbose] ".
        "[-t <timeout>] ".
        "-H <host> ".
        "-l <login> ".
        "-p <password> ".
        "-o <port> ".
        "-u <ups> ".
        "-q <query> ".
        "[-o <oid>] ".
        "[-w <threshold>] ".
        "[-c <threshold>] ",
);

# add valid command line options and build them into your usage/help documentation.
$nagios->add_arg(
    spec => 'oid|o=s',
    help => "-o, --oid=OID\n".
        "   Base OID at which package updates are found (default: .1.3.6.1.4.1.36425.256.2).",
    required => 0,
    default => ".1.3.6.1.4.1.36425.256.2",
);
$nagios->add_arg(
    spec => 'store|s=s',
    help => "-s, --store=PATH\n".
        "   Path to the file where package tracing information can be stored.",
    required => 0,
    default => "/var/lib/snmp/security_updates",
);

# Parse @ARGV and process arguments.
$nagios->getopts;

my $filename = sprintf(
    "%s/%s-%d-SNMP%s.db",
    $nagios->opts->get("store"),
    $nagios->opts->get("hostname"),
    $nagios->opts->get("port"),
    $nagios->opts->get("snmp-version")
);

my %h;

msg(
    sprintf(
        "Persistent store: %s",
        $filename
    ),
    $nagios->opts->get('verbose')
);

my $count = $nagios->get($nagios->opts->get("oid"));
if (!exists $count->{$nagios->opts->get("oid")}) {
    $nagios->nagios_exit(UNKNOWN, sprintf("No security update information found at %s", $nagios->opts->get("oid")));
}
$nagios->add_perfdata(
    label => "updates",
    value => $count->{$nagios->opts->get("oid")},
);
if ($count->{$nagios->opts->get("oid")} == 0) {
    unlink $filename;
    $nagios->nagios_exit(OK, "No security updates pending");
}

msg(
    sprintf(
        "Connecting to %s:%d with SNMP%s",
        $nagios->opts->get("hostname"),
        $nagios->opts->get("port"),
        $nagios->opts->get("snmp-version")
    ),
    $nagios->opts->get('verbose')
);

my $packages = $nagios->walk($nagios->opts->get("oid"));

my @packagenames = map { $packages->{$nagios->opts->get("oid")}->{$_} } keys %{$packages->{$nagios->opts->get("oid")}};

# Tie persistent storage to keep track of pending updates over time.
tie %h, "DB_File", $filename, O_RDWR|O_CREAT, 0640, $DB_HASH or
    $nagios->nagios_exit(UNKNOWN, sprintf("Cannot open file %s (%s)", $filename, $!));

foreach my $key (keys %h) {
    msg(
        sprintf(
            "Previously seen update: %s (%s)",
            $key,
            scalar localtime $h{$key}
        ),
        $nagios->opts->get('verbose')
    );
    if (!grep { $key eq $_ } @packagenames) {
        msg(
            sprintf(
                "Forgetting update: %s",
                $key
            ),
            $nagios->opts->get('verbose')
        );
        delete $h{$key};
    }
}
foreach my $key (@packagenames) {
    if (!grep { $key eq $_ } keys %h) {
        msg(
            sprintf(
                "Remembering update: %s",
                $key
            ),
            $nagios->opts->get('verbose')
        );
        $h{$key} = time();
    }
}

my @critical = grep { $h{$_} < time() - $nagios->opts->get("critical") * 86400 } keys %h;
my @warning = grep { $h{$_} < time() - $nagios->opts->get("warning") * 86400 } keys %h;

untie %h;

my $status = @warning ? @critical ? CRITICAL : WARNING : OK;

$nagios->nagios_exit(
    $status,
    sprintf(
        "Pending updates: %d\n%s",
        $count->{$nagios->opts->get("oid")},
        join ",\n", sort @packagenames
    )
);
