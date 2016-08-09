#!/usr/bin/perl -w
# Copyright 2016 Michael Fladischer
# OpenServices e.U.
# office@openservices.at
#
# Monitor OwnCloud instances.
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

use URI;
use URI::Escape;
use LWP::UserAgent;
use DB_File;
use Log::Message::Simple qw[:STD :CARP];

use Monitoring::Plugin;
use Monitoring::Plugin::Performance use_die => 1;

use Data::Dumper;

my $monitor = Monitoring::Plugin->new(
    shortname => "nginx",
    version => "0.1",
    url => "http://openservices.at/services/infrastructure-monitoring/nginx",
    usage => "Usage: %s ".
        "[-v|--verbose] ".
        "[-t <timeout>] ".
        "-H <host> ".
        "--path=<path> ".
        "-w <threshold> ".
        "-c <threshold> ".
        "-m (status) ".
        "[-S <path>] ".
        "[-P <port>] ".
        "[-l <login>] ".
        "[-p <password>] ".
        "[-r <realm>] ".
        "[-s|--ssl] ".
        "[-I <ip>] ",
);

# add valid command line options and build them into your usage/help documentation.
$monitor->add_arg(
    spec => 'host|H=s',
    help => "-H, --host=STRING\n".
        "The host to connect to.",
    required => 1,
);
$monitor->add_arg(
    spec => 'port|P=i',
    help => "-P, --port=INTEGER\n".
        "The port to connect to.",
    required => 0,
);
$monitor->add_arg(
    spec => 'warning|w=s',
    help => "-w, --warning=INTEGER:INTEGER\n".
        "See http://nagiosplug.sourceforge.net/developer-guidelines.html#THRESHOLDFORMAT for the threshold format.",
    required => 1,
);
$monitor->add_arg(
    spec => 'critical|c=s',
    help => "-c, --critical=INTEGER:INTEGER\n".
        "See http://nagiosplug.sourceforge.net/developer-guidelines.html#THRESHOLDFORMAT for the threshold format.",
    required => 1,
);
$monitor->add_arg(
    spec => 'login|l=s',
    help => "-l, --login=STRING\n".
        "Username to login.",
    required => 0,
);
$monitor->add_arg(
    spec => 'password|p=s',
    help => "-p, --password=STRING\n".
        "Password used for authentication.",
    required => 0,
);
$monitor->add_arg(
    spec => 'realm|r=s',
    help => "-r, --realm=STRING\n".
        "Realm used for authentication.",
    required => 0,
);
$monitor->add_arg(
    spec => 'path=s',
    help => "--path=STRING\n".
        "Path to nginx status page.",
    required => 1,
);
$monitor->add_arg(
    spec => 'ssl|s',
    help => "-s, --ssl\n".
        "Use SSL (HTTPS) when connecting.",
    required => 0,
);
$monitor->add_arg(
    spec => 'ip|I=s',
    help => "-I, --ip=STRING\n".
        "IPv4/6 address of the OwnCloud instance. If this argument is used, the hostname (argument -H or --hostname) is sent as \"Host:\" in the HTTP header of the request.",
    required => 0,
);
$monitor->add_arg(
    spec => 'mode|m=s',
    help => "--mode=(status)\n".
        "One of the following modes are available:\n".
        "    \"status\"       check if nginx answers on its status page",
    required => 1,
);
$monitor->add_arg(
  spec => 'store|S=s',
  help => "-S, --store=PATH\n".
    'Path to the file where package tracing information can be stored.',
  required => 0,
  default => '/var/cache/monitoring/nginx'
);
$monitor->add_arg(
    spec => 'debug|d',
    help => "-d, --debug\n".
        "Print debug information",
    required => 0,
);

# Parse @ARGV and process arguments.
$monitor->getopts;

# Construct URL
my $uri = URI->new("http://");

# Attach host and path to URL.
$uri->host($monitor->opts->get('host'));
$uri->path($monitor->opts->get('path'));

# See if we should enable SSL for HTTPS.
if ($monitor->opts->get('ssl')) {
  $uri->scheme('https');
}

# Override default port if needed.
if ($monitor->opts->get('port')) {
  $uri->port($monitor->opts->get('port'));
}

# Set up user agent to fetch data.
my $headers = HTTP::Headers->new(
  User_Agent => $monitor->shortname,
);

# See if we should use the `ip` parameter to connect to. Otherwise use the `host` parameter. This is used to query name
# based virtual hosts.
if ($monitor->opts->get('ip')) {
  $uri->host($monitor->opts->get('ip'));
  $headers->header(Host => $monitor->opts->get('host'));
}

my $ua = LWP::UserAgent->new(
  cookie_jar => {},
  default_headers => $headers,
  ssl_opts => {
    verify_hostname => 1,
    SSL_hostname => $monitor->opts->get('host'),
    SSL_verifycn_name => $monitor->opts->get('host'),
  }
);

# Register debug handlers
$ua->add_handler(
  "request_send",
  sub {
    debug(shift->dump, $monitor->opts->{debug});
    return;
  }
);
$ua->add_handler(
  "response_done",
  sub {
    debug(shift->dump, $monitor->opts->{debug});
    return;
  }
);

# Initialize authentication for HTTP basic auth. This only happens if both `username` and `password` parameters are set.
# The `realm` parameter is optional.
if ($monitor->opts->get('login') && $monitor->opts->get('password')) {
  $ua->credentials(
    $uri->authority,
    $monitor->opts->get('realm') || '*',
    $monitor->opts->get('login'),
    $monitor->opts->get('password')
  );
}

my $filename = sprintf(
  '%s/%s-%s-%s.db',
  $monitor->opts->get('store'),
  $uri->scheme,
  $uri->authority,
  uri_escape($uri->path)
);

my %h;

# Fetch the data.
my $response = $ua->get($uri->as_string);

# Fail with CRITICAL if we received any HTTP status code other than 200.
if ($response->is_error) {
  $monitor->plugin_exit(
    CRITICAL,
    'Unable to fetch nginx status response'
  );
}

$response->content =~ /^Active connections: (?<active>\d+)\s+server accepts handled requests\s+(?<accepts>\d+) (?<handled>\d+) (?<requests>\d+)/;

my $stats = \%+;

# Tie persistent storage to keep track of pending updates over time.
tie %h, 'DB_File', $filename, O_RDWR|O_CREAT, 0640, $DB_HASH or
$monitor->nagios_exit(UNKNOWN, sprintf('Cannot open file %s (%s)', $filename, $!));

my $timestamp = time();

# Check if there is histroical data. If not, fill storage file with current data.
# This enables our next round of checks to pass this.
if (!defined $h{'timestamp'}) {
  $h{'timestamp'} = $timestamp;
  $h{'active'} = $stats->{'active'};
  $h{'accepts'} = $stats->{'accepts'};
  $h{'handled'} = $stats->{'handled'};
  $h{'requests'} = $stats->{'requests'};
  untie %h;
  $monitor->nagios_exit(UNKNOWN, sprintf('No previous data found in file %s', $filename));
}

# The actual check logic map. Each key in the hash map contains a subroutine that does the actual checking of the
# response content.
my %codemap = (
  'connections' => sub {
    my ($stats, $store) = @_;
    $monitor->add_perfdata(
      label => "Connections",
      value => $stats->{'active'},
      threshold => $monitor->threshold,
      uom => 'connections',
    );
    $store->{'timestamp'} = $timestamp;
    $store->{'active'} = $stats->{'active'};
    $store->{'accepts'} = $stats->{'accepts'};
    $store->{'handled'} = $stats->{'handled'};
    $store->{'requests'} = $stats->{'requests'};
    untie %h;
    my $code = $monitor->check_threshold($stats->{'active'});
    $monitor->plugin_exit(
      $code,
      sprintf(
        '%d connections',
        $stats->{'active'}
      )
    );
  },
  'connections/sec' => sub {
    my ($stats, $store) = @_;
    my $timestamp = time();
    my $elapsed = $timestamp - $store->{'timestamp'};
    my $avg = ($stats->{'accepts'} - $store->{'accepts'}) / $elapsed;
    $store->{'timestamp'} = $timestamp;
    $store->{'active'} = $stats->{'active'};
    $store->{'accepts'} = $stats->{'accepts'};
    $store->{'handled'} = $stats->{'handled'};
    $store->{'requests'} = $stats->{'requests'};
    untie %h;
    $monitor->add_perfdata(
      label => "Connections per Second",
      value => $avg,
      threshold => $monitor->threshold,
      uom => 'c/s',
    );
    my $code = $monitor->check_threshold($avg);
    $monitor->plugin_exit(
      $code,
      sprintf(
        '%.2f connections per second',
        $avg
      )
    );
  },
  'requests/sec' => sub {
    my ($stats, $store) = @_;
    my $timestamp = time();
    my $elapsed = $timestamp - $store->{'timestamp'};
    my $avg = ($stats->{'requests'} - $store->{'requests'}) / $elapsed;
    $store->{'timestamp'} = $timestamp;
    $store->{'active'} = $stats->{'active'};
    $store->{'accepts'} = $stats->{'accepts'};
    $store->{'handled'} = $stats->{'handled'};
    $store->{'requests'} = $stats->{'requests'};
    untie %h;
    $monitor->add_perfdata(
      label => "Requests per Second",
      value => $avg,
      threshold => $monitor->threshold,
      uom => 'r/s',
    );
    my $code = $monitor->check_threshold($avg);
    $monitor->plugin_exit(
      $code,
      sprintf(
        '%.2f requests per second',
        $avg
      )
    );
  },
);

# Fetch check subroutine based on the `mode` parameter and call it with the response.
$codemap{$monitor->opts->get('mode')}($stats, \%h);
