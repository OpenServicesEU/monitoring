#!/usr/bin/perl -w
# Copyright 2015 Michael Fladischer
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
use LWP::UserAgent;
use JSON;
use Time::HiRes qw(gettimeofday tv_interval);
use Log::Message::Simple qw[:STD :CARP];

use Monitoring::Plugin;
use Monitoring::Plugin::Performance use_die => 1;

my $monitor = Monitoring::Plugin->new(
    shortname => "OwnCloud",
    version => "0.2",
    url => "http://openservices.at/services/infrastructure-monitoring/owncloud",
    usage => "Usage: %s ".
        "[-v|--verbose] ".
        "[-t <timeout>] ".
        "-H <host> ".
        "--path=<path> ".
        "-w <threshold> ".
        "-c <threshold> ".
        "-m (status) ".
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
        "Path to OwnCloud status page.",
    required => 1,
);
$monitor->add_arg(
    spec => 'ssl|s',
    help => "-s, --ssl\n".
        "Use SSL (HTTPS) when connecting to OwnCloud.",
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
        "    \"status\"       check if OwnCloud answers on its status page",
    required => 1,
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

# Fetch the data.
my $timer = [gettimeofday];
my $response = $ua->get($uri->as_string);
my $elapsed = tv_interval($timer) * 1000;

# Fail with CRITICAL if we received any HTTP status code other than 200.
if ($response->is_error) {
  $monitor->plugin_exit(
    CRITICAL,
    'Unable to fetch OwnCloud status response'
  );
}

# The actual check logic map. Each key in the hash map contains a subroutine that does the actual checking of the
# response content.
my %codemap = (
  'status' => sub {
    my ($response, $elapsed) = @_;
    my $status = JSON->new->utf8->decode($response->content);
    $monitor->add_perfdata(
      label => "Latency",
      value => $elapsed,
      threshold => $monitor->threshold,
      uom => 'ms',
    );
    if (!$status->{'installed'}) {
      $monitor->plugin_exit(
        UNKNOWN,
        sprintf(
          'OwnCloud %s: Not installed',
          $status->{'version'}
        )
      );
    }
    if ($status->{'maintainance'}) {
      $monitor->plugin_exit(
        WARNING,
        sprintf(
          'OwnCloud %s: Maintainance active',
          $status->{'version'}
        )
      );
    }
    my $code = $monitor->check_threshold($elapsed);
    $monitor->plugin_exit(
      $code,
      sprintf(
        'OwnCloud %s: Status retrieved',
        $status->{'version'}
      )
    );
  },
);

# Fetch check subroutine based on the `mode` parameter and call it with the response.
$codemap{$monitor->opts->get('mode')}($response, $elapsed);
