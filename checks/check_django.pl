#!/usr/bin/perl -w
# Copyright 2013 Michael Fladischer
# OpenServices e.U.
# office@openservices.at
#
# Monitor Django installations.
# This check requires the django_monitoring app to be installed and to be be
# accessible through the URL mapper.
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

use version;
use Thread::Pool::Simple;
use LWP::UserAgent;
use JSON;
use Time::HiRes qw(gettimeofday tv_interval);
use Log::Message::Simple qw[:STD :CARP];

use Nagios::Plugin;
use Nagios::Plugin::Performance use_die => 1;

my $nagios = Nagios::Plugin->new(
    shortname => "DJANGO",
    version => "0.1",
    url => "http://openservices.at/services/infrastructure-monitoring/django",
    usage => "Usage: %s ".
        "[-v|--verbose] ".
        "[-t <timeout>] ".
        "-H <host> ".
        "[-u <uri>] ".
        "[-l <login>] ".
        "[-p <password>] ".
        "[-I <ip>] ".
        "[-i <extension>] ".
        "[-w <threshold>] ".
        "[-c <threshold>] ",
);

# add valid command line options and build them into your usage/help documentation.
$nagios->add_arg(
    spec => 'host|H=s',
    help => "-H, --host=STRING\n".
        "The host to connect to.",
    required => 1,
);
$nagios->add_arg(
    spec => 'warning|w=s',
    help => "-w, --warning=INTEGER:INTEGER\n".
        "See http://nagiosplug.sourceforge.net/developer-guidelines.html#THRESHOLDFORMAT for the threshold format.",
    required => 1,
);
$nagios->add_arg(
    spec => 'critical|c=s',
    help => "-c, --critical=INTEGER:INTEGER\n".
        "See http://nagiosplug.sourceforge.net/developer-guidelines.html#THRESHOLDFORMAT for the threshold format.",
    required => 1,
);
$nagios->add_arg(
    spec => 'login|l=s',
    help => "-l, --login=STRING\n".
        "Username to login.",
    required => 0,
    default => "",
);
$nagios->add_arg(
    spec => 'password|p=s',
    help => "-p, --password=STRING\n".
        "   Password used for authentication.",
    required => 0,
    default => "",
);
$nagios->add_arg(
    spec => 'uri|u=i',
    help => "-u, --uri=STRING\n".
        "URI to django_monitoring (default: /monitoring).",
    required => 0,
    default => "/monitoring",
);
$nagios->add_arg(
    spec => 'ssl|s',
    help => "-s, --ssl\n".
        "Use SSL (HTTPS) when connecting to django_monitoring.",
    required => 0,
    default => 0,
);
$nagios->add_arg(
    spec => 'ip|I=s',
    help => "-I, --ip=STRING\n".
        "IPv4 address of the Django server. If this argument is used, the hostname (argument -H or --hostname) is sent as \"Host:\" in the HTTP header of the request.",
    required => 0,
);
$nagios->add_arg(
    spec => 'ignore|i=s@',
    help => "-i, --ignore=STRING\n".
        "Names of Django applications that should be ignored. Can be used multiple times to ignore more than one application.",
    required => 0,
);

# Map strings from arguments to Nagios Plugin codes.
my %codemap = (
    "ignore" => undef,
    "warning" => WARNING,
    "critical" => CRITICAL,
);

# Parse @ARGV and process arguments.
$nagios->getopts;

# Construct URL to django_monitoring view.
my $url = sprintf("http%s://%s%s",
    $nagios->opts->get("ssl") ? "s" : "",
    ($nagios->opts->get("ip") or $nagios->opts->get("host")),
    $nagios->opts->get("uri")
);

msg(
    sprintf(
        "Connecting to django_monitoring on %s with user %s",
        $url,
        $nagios->opts->get("login")
    ),
    $nagios->opts->get('verbose')
);

# Instantiate new LWP user agent for django_monitoring.
my $ua = LWP::UserAgent->new;
$ua->default_header("Host" => $nagios->opts->get("host"));
$ua->timeout($nagios->opts->get("timeout"));
$ua->cookie_jar({});

if ($nagios->opts->get("login") and $nagios->opts->get("password")) {
    msg(
        sprintf(
            "Setting credentials for realm \"TYPO3 Nagios\": %s",
            $nagios->opts->get("login")
        ),
        $nagios->opts->get('verbose')
    );
    $ua->credentials(
        sprintf(
            "%s:%i",
            $nagios->opts->get("host"),
            $nagios->opts->get("ssl") ? 443 : 80
        ),
        "TYPO3 Nagios",
        $nagios->opts->get("login"),
        $nagios->opts->get("password")
    );
}

# Retrieve TYPO3 nagios extension page and meassure required time.
my $timer = [gettimeofday];
my $response = $ua->get($url);
my $elapsed = tv_interval($timer) * 1000;

# Perfdata
$nagios->add_perfdata(
    label => "Latency",
    value => $elapsed,
    threshold => $nagios->threshold,
    uom => 'ms',
);

# See if we got a valid response from the TYPO3 nagios extension.
if ($response->code != 200) {
    $nagios->nagios_exit(
        CRITICAL,
        sprintf(
            "Django returned an HTTP error: %i",
            $response->code
        )
    );
}

# Hash that will hold the parsed response data.
my $data = decode_json $response->content;

# Models perfdata
foreach (keys %{$data->{models}}) {
    $nagios->add_perfdata(
        label => $_,
        value => $data->{models}->{$_},
    );
}

# First status derived from the time elapsed during the initial request.
my $code = $nagios->check_threshold(check => $elapsed);
my $message = sprintf("Request finished in %ims", $elapsed);

# Exit with final status and message.
$nagios->nagios_exit($code, $message);
