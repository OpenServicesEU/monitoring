#!/usr/bin/perl -w
# Copyright 2015 Michael Fladischer
# OpenServices e.U.
# office@openservices.at
#
# Monitor PHP FPM instances.
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
use LWP::UserAgent;
use XML::LibXML;
use Time::HiRes qw(gettimeofday tv_interval);
use Log::Message::Simple qw[:STD :CARP];

use Monitoring::Plugin;
use Monitoring::Plugin::Performance use_die => 1;

my $monitor = Monitoring::Plugin->new(
    shortname => "PHP-FPM",
    version => "0.1",
    url => "http://openservices.at/services/infrastructure-monitoring/php-fpm",
    usage => "Usage: %s ".
        "[-v|--verbose] ".
        "[-t <timeout>] ".
        "-H <host> ".
        "--path=<path> ".
        "-w <threshold> ".
        "-c <threshold> ".
        "-m (ping|queue|processes) ".
        "[-P <port>] ".
        "[-L <login>] ".
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
    spec => 'login|L=s',
    help => "-L, --login=STRING\n".
        "Username to login.",
    required => 0,
);
$monitor->add_arg(
    spec => 'password|p=s',
    help => "-p, --password=STRING\n".
        "   Password used for authentication.",
    required => 0,
);
$monitor->add_arg(
    spec => 'realm|r=s',
    help => "-r, --realm=STRING\n".
        "   Realm used for authentication.",
    required => 0,
    default => '',
);
$monitor->add_arg(
    spec => 'path=s',
    help => "--path=STRING\n".
        "Path to PHP-FPM's ping/status page.",
    required => 1,
);
$monitor->add_arg(
    spec => 'ssl|s',
    help => "-s, --ssl\n".
        "Use SSL (HTTPS) when connecting to TYPO3.",
    required => 0,
    default => 0,
);
$monitor->add_arg(
    spec => 'ip|I=s',
    help => "-I, --ip=STRING\n".
        "IPv4/6 address of the PHP-FPM instance. If this argument is used, the hostname (argument -H or --hostname) is sent as \"Host:\" in the HTTP header of the request.",
    required => 0,
);
$monitor->add_arg(
    spec => 'mode|m=s',
    help => "--mode=(ping|queue|processes)\n".
        "   One of the following modes are available:\n".
        "       \"ping\"       check if php-fpm ansers on its ping page\n".
        "       \"queue\"      check the maximum recorded number of requests waiting in the queue\n".
        "       \"processes\"  check the maximum recorded number of active processes",
    required => 1,
);
$monitor->add_arg(
    spec => 'debug|d',
    help => "-d, --debug\n".
        "Print debug information",
    required => 0,
    default => 0,
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

# Set query to `xml` so we get back XML formated responses.
$uri->query('xml');

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

# Fetch the data.
my $response = $ua->get($uri->as_string);

# Fail with CRITICAL if we received any HTTP status code other than 200.
if ($response->is_error) {
  $monitor->nagios_exit(
    CRITICAL,
    'Unable to fetch FPM response'
  );
}

# The actual check logic map. Each key in the hash map contains a subroutine that does the actual checking of the
# response content.
my %codemap = (
  'ping' => sub {
    my ($response) = @_;
    my $timer = [gettimeofday];
    my $elapsed = tv_interval($timer) * 1000;
    if ($response->content ne "pong") {
      $monitor->nagios_exit(
        CRITICAL,
        'Invalid response to PING request'
      );
    }
    $monitor->add_perfdata(
      label => "Latency",
      value => $elapsed,
      threshold => $monitor->threshold,
      uom => 'ms',
    );
    $monitor->nagios_exit(
      OK,
      sprintf(
        'Received PING response in %d milliseconds',
        $elapsed
      )
    );
  },
  'queue' => sub {
    my ($response) = @_;
    my $status = XML::LibXML->load_xml(string => $response->content);
    my $pool = $status->findvalue('/status/pool');
    my $pending = $status->findvalue('/status/listen-queue');
    my $maximum = $status->findvalue('/status/max-listen-queue');
    $monitor->add_perfdata(
      label => 'Pending',
      value => $pending,
      uom => 'requests',
    );
    $monitor->add_perfdata(
      label => 'Maximum',
      value => $maximum,
      threshold => $monitor->threshold,
      uom => 'requests',
    );
    my $code = $monitor->check_threshold($maximum);
    $monitor->nagios_exit(
      $code,
      sprintf(
        '%s: maximum requests in queue: %d',
        $pool,
        $maximum
      )
    );
  },
  'processes' => sub {
    my ($response) = @_;
    my $status = XML::LibXML->load_xml(string => $response->content);
    my $pool = $status->findvalue('/status/pool');
    my $active = $status->findvalue('/status/active-processes');
    my $maximum = $status->findvalue('/status/max-active-processes');
    $monitor->add_perfdata(
      label => 'Active',
      value => $active,
      uom => 'processes',
    );
    $monitor->add_perfdata(
      label => 'Maximum',
      value => $maximum,
      threshold => $monitor->threshold,
      uom => 'processes',
    );
    my $code = $monitor->check_threshold($maximum);
    $monitor->nagios_exit(
      $code,
      sprintf(
        '%s: maximum active processes: %d',
        $pool,
        $maximum
      )
    );
  },
);

# Fetch check subroutine based on the `mode` parameter and call it with the response.
$codemap{$monitor->opts->get('mode')}($response);
