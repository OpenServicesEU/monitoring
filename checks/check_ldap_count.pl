#!/usr/bin/perl -w
# Copyright 2013 Michael Fladischer
# OpenServices e.U.
# office@openservices.at
#
# Perform read/write/delete tests on a remote WebDAV enabled webserver.
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
use warnings;
use lib "/usr/lib/nagios/plugins/";

use Net::LDAP;
use Log::Message::Simple qw[:STD :CARP];

use Nagios::Plugin;
use Nagios::Plugin::Performance use_die => 1;

my $nagios = Nagios::Plugin->new(
    shortname => "LDAP Count",
    version => "0.1",
    url => "http://openservices.at/services/infrastructure-monitoring/ldap",
    usage => "Usage: %s ".
        "[-v|--verbose] ".
        "[-t <timeout>] ".
        "-H <host> ".
        "[-t <port>] ".
        "-l <login> ".
        "-p <password> ".
        "-b <base> ".
        "-f <filter> ".
        "[-s] ".
        "-w <threshold> ".
        "-c <threshold> ",
);

# add valid command line options and build them into your usage/help documentation.
$nagios->add_arg(
    spec => 'host|H=s',
    help => "-H, --host=STRING\n".
        "The host to connect to.",
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
    spec => 'login|l=s',
    help => "-l, --login=STRING\n".
        "DN to login.",
    required => 0,
);
$nagios->add_arg(
    spec => 'password|p=s',
    help => "-p, --password=STRING\n".
        "Password used for authentication.",
    required => 0,
);
$nagios->add_arg(
    spec => 'port|o=i',
    help => "-o, --port=INTEGER\n".
        "Port used by the LDAP server.",
    required => 0,
    default => 389,
);
$nagios->add_arg(
    spec => 'base|b=s',
    help => "-b, --base=STRING\n".
        "Base-DN for LDAP search (e.g. dc=example,dc=com)",
    required => 1,
);
$nagios->add_arg(
    spec => 'filter|f=s',
    help => "-f, --filter=STRING\n".
        "LDAP-Filter used to search for entries (e.g. (attr='value'))",
    required => 1,
);
$nagios->add_arg(
    spec => 'ssl|s',
    help => "-s, --ssl\n".
        "Use SSL/HTTPS",
    required => 0,
);

# Parse @ARGV and process arguments.
$nagios->getopts;

my $ldap = Net::LDAP->new(
    sprintf("%s:%i", $nagios->opts->get('host'), $nagios->opts->get('port'))
) or $nagios->nagios_exit(UNKNOWN,
    sprintf("Could not connect to host %s:%i: %s",
        $nagios->opts->get('host'),
        $nagios->opts->get('port'),
        $@
    )
);
if ($nagios->opts->get('login')) {
    # Login with credentials. Make sure that this user cannot change entries in
    # the tree!
    $ldap->bind($nagios->opts->get('login'),
        password => $nagios->opts->get('password'),
        version => 3
    );
} else {
    # Use anonymous bind as we are only searching in the tree. Much safer!
    $ldap->bind(version => 3);
}

my $result = $ldap->search(
    base => $nagios->opts->get('base'),
    filter => $nagios->opts->get('filter'),
    attrs => [],
    scope => "sub"
);

# Disconnect from LDAP server
$ldap->unbind;
$ldap->disconnect;

# Threshold check.
my $code = $nagios->check_threshold(
    check => $result->count(),
);

# Perfdata
$nagios->add_perfdata(
    label => "Entries",
    value => $result->count(),
    threshold => $nagios->threshold,
);

# Exit with status
$nagios->nagios_exit($code, sprintf("Found %i entries in %s", $result->count(), $nagios->opts->get('base')));
