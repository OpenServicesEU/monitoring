#!/usr/bin/perl -w
# Copyright 2015 Michael Fladischer
# OpenServices e.U.
# office@openservices.at
#
# Perform authentication on CAMPUSonline web interface.
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
use Time::HiRes qw( gettimeofday tv_interval );
use Log::Message::Simple qw[:STD :CARP];

use Monitoring::Plugin;
use Monitoring::Plugin::Performance use_die => 1;

my $monitor = Monitoring::Plugin->new(
    shortname => "CAMPUSonline",
    version => "0.1",
    url => "http://openservices.at/services/infrastructure-monitoring/campusonline",
    usage => "Usage: %s ".
        "[-v|--verbose] ".
        "[-t <timeout>] ".
        "-H <host> ".
        "--path=<path> ".
        "-l <login> ".
        "-p <password> ".
        "-w <threshold> ".
        "-c <threshold> ".
        "[-P <port>] ".
        "[-I <ip>] ".
        "[-s] ",
);

# add valid command line options and build them into your usage/help documentation.
$monitor->add_arg(
    spec => 'host|H=s',
    help => "-H, --host=STRING\n".
        "The host to connect to.",
    required => 1,
);
$monitor->add_arg(
    spec => 'warning|w=i',
    help => "-w, --warning=INTEGER:INTEGER\n".
        "See http://nagiosplug.sourceforge.net/developer-guidelines.html#THRESHOLDFORMAT for the threshold format.",
    required => 1,
);
$monitor->add_arg(
    spec => 'critical|c=i',
    help => "-c, --critical=INTEGER:INTEGER\n".
        "See http://nagiosplug.sourceforge.net/developer-guidelines.html#THRESHOLDFORMAT for the threshold format.",
    required => 1,
);
$monitor->add_arg(
    spec => 'login|l=s',
    help => "-l, --login=STRING\n".
        "Username to login.",
    required => 1,
);
$monitor->add_arg(
    spec => 'password|p=s',
    help => "-p, --password=STRING\n".
        "Password used for authentication.",
    required => 1,
);
$monitor->add_arg(
    spec => 'port|P=i',
    help => "-P, --port=INTEGER\n".
        "Port used by the HTTP server.",
    required => 0,
);
$monitor->add_arg(
    spec => 'path=s',
    help => "--path=STRING\n".
        "Base path for check (default: mug_online)",
    required => 0,
    default => "mug_online",
);
$monitor->add_arg(
    spec => 'ssl|s',
    help => "-s, --ssl\n".
        "Use SSL/HTTPS",
    required => 0,
);
$monitor->add_arg(
    spec => 'ip|I=s',
    help => "-I, --IP=STRING\n".
        "The IP to connect to. If this is set, the host parameter is sent in the Host HTTP header field.",
    required => 0,
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

my $path = sprintf("%s/", $uri->path);
my $host = $uri->host;

my $url;
my $response;

# Start timer
my $timer = [gettimeofday];

$url = $uri->clone;
$url->path_segments($uri->path_segments, "webnav.ini");
msg(
  sprintf(
    "Fetching %s",
    $url->as_string
  ),
  $monitor->opts->{verbose}
);
$response = $ua->get($url->as_string);
check_response($monitor, $response);

msg(
  sprintf(
    "Adding header Cookie: PSESSIONID=%s",
    $ua->cookie_jar->{COOKIES}{$host}{$path}{'PSESSIONID'}[1]
  ),
  $monitor->opts->{verbose}
);
$ua->default_header(
  "Cookie" => sprintf(
    "PSESSIONID=%s",
    $ua->cookie_jar->{COOKIES}{$host}{$path}{'PSESSIONID'}[1]
  )
);

$url = $uri->clone;
$url->path_segments($uri->path_segments, "wbanmeldung.durchfuehren");
msg(
  sprintf(
    "Fetching %s",
    $url->as_string
  ),
  $monitor->opts->{verbose}
);
$response = $ua->get($url->as_string);
check_response($monitor, $response);

msg(
  sprintf(
    "Adding header Cookie: PLOGINID=%s",
    $ua->cookie_jar->{COOKIES}{$host}{$path}{'PLOGINID'}[1]
  ),
  $monitor->opts->{verbose}
);
$ua->default_header(
  "Cookie" => sprintf(
    "PSESSIONID=%s; PLOGINID=%s",
    $ua->cookie_jar->{COOKIES}{$host}{$path}{'PSESSIONID'}[1],
    $ua->cookie_jar->{COOKIES}{$host}{$path}{'PLOGINID'}[1]
  )
);

$url = $uri->clone;
$url->path_segments($uri->path_segments, "wbanmeldung.durchfuehren");
$url->query("ctxid=check&cusergroup=&cinframe=&curl=");
msg(
  sprintf(
    "Fetching %s",
    $url->as_string
  ),
  $monitor->opts->{verbose}
);
$response = $ua->get($url->as_string);
check_response($monitor, $response);

$url = $uri->clone;
$url->path_segments($uri->path_segments, "wbAnmeldung.durchfuehren");
msg("Submitting form", $monitor->opts->{verbose});
$response = $ua->post(
  $url->as_string,
  {
    cp1 => $monitor->opts->{login},
    cp2 => $monitor->opts->{password},
    ctxid => "check",
    curl => undef,
    cinframe => undef,
    pLogonMask => undef
  }
);
check_response($monitor, $response);

my ($rpath, $rquery) = split /\?/, $response->header("Location");
$url = $uri->clone;
$url->path_segments($uri->path_segments, $rpath);
$url->query($rquery);
msg(
  sprintf(
    "Fetching %s",
    $url->as_string
  ),
  $monitor->opts->{verbose}
);
$response = $ua->get($url->as_string);
check_response($monitor, $response);

my $content = $response->content;
my ($lastName, $firstName) = ($content =~ /Visitenkarte von (\w+), (\w+)/);
if (!defined $lastName or !defined $firstName) {
  $monitor->nagios_exit(
    CRITICAL,
    sprintf(
      "Could not authenticate as %s",
      $monitor->opts->{login}
    )
  );
}

# End timer
my $elapsed = tv_interval($timer) * 1000;

# Threshold check.
my $code = $monitor->check_threshold(
  check => $elapsed,
);

# Perfdata
$monitor->add_perfdata(
  label => "Latency",
  value => $elapsed,
  threshold => $monitor->threshold,
  uom => 'ms',
);

# Exit if WARNING or CRITICAL.
if ($code != OK) {
  $monitor->nagios_exit(
    $code,
    sprintf(
      "Check took to long with %dms for %s %s",
      $elapsed,
      $firstName,
      $lastName
    )
  );
}

# Exit OK.
$monitor->nagios_exit(
  OK,
  sprintf(
    "Check finished in %dms for %s %s",
    $elapsed,
    $firstName,
    $lastName
  )
);

sub check_response {
  my ($monitor, $response) = @_;
  if ($response->is_error) {
    $monitor->nagios_exit(
      CRITICAL,
      sprintf(
        "Could not fetch %s: %s",
        $response->request->uri,
        $response->status_line
      )
    );
  }
}
