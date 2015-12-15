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
use lib "/usr/lib/nagios/plugins/";

# Disable hostname verification for LWP::SSL because the CN of most
# certificates does not match their internal hostname.
BEGIN { $ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0 }

use URI;
use WWW::Mechanize;
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

# See if we should use the `ip` parameter to connect to. Otherwise use the `host` parameter. This is used to query name
# based virtual hosts.
if ($monitor->opts->get('ip')) {
  $uri->host($monitor->opts->get('ip'));
} else {
  $uri->host($monitor->opts->get('host'));
}

# Attach path to URL.
$uri->path($monitor->opts->get('path'));

# See if we should enable SSL for HTTPS.
if ($monitor->opts->get('ssl')) {
  $uri->scheme('https');
}

# Override default port if needed.
if ($monitor->opts->get('port')) {
  $uri->port($monitor->opts->get('port'));
}

my $path = sprintf("%s/", $uri->path);
my $host = $uri->host;

my $headers = HTTP::Headers->new(
  User_Agent => $monitor->shortname,
);

if ($monitor->opts->get('ip')) {
  $headers->header(Host => $monitor->opts->get('host'));
}

my $m = WWW::Mechanize->new(
    cookie_jar => {},
    autocheck => 0,
    default_headers => $headers,
);

# Register debug handlers
$m->add_handler("request_send", sub { debug(shift->dump, $monitor->opts->{debug}); return });
$m->add_handler("response_done", sub { debug(shift->dump, $monitor->opts->{debug}); return });

my $url;

# Start timer
my $timer = [gettimeofday];

$url = $uri->clone;
$url->path_segments($uri->path_segments, "webnav.ini");
msg("Fetching ".$url->as_string, $monitor->opts->{verbose});
$m->get($url->as_string);
check_response($monitor, $m);

msg("Adding header Cookie: PSESSIONID=".$m->cookie_jar->{COOKIES}{$host}{$path}{'PSESSIONID'}[1], $monitor->opts->{verbose});
$m->add_header("Cookie" => "PSESSIONID=".$m->cookie_jar->{COOKIES}{$host}{$path}{'PSESSIONID'}[1]);

$url = $uri->clone;
$url->path_segments($uri->path_segments, "wbanmeldung.durchfuehren");
msg("Fetching ".$url->as_string, $monitor->opts->{verbose});
$m->get($url->as_string);
check_response($monitor, $m);

msg("Adding header Cookie: PLOGINID=".$m->cookie_jar->{COOKIES}{$host}{$path}{'PLOGINID'}[1], $monitor->opts->{verbose});
$m->add_header("Cookie" => "PSESSIONID=" . $m->cookie_jar->{COOKIES}{$host}{$path}{'PSESSIONID'}[1]."; PLOGINID=".$m->cookie_jar->{COOKIES}{$host}{$path}{'PLOGINID'}[1]);

$url = $uri->clone;
$url->path_segments($uri->path_segments, "wbanmeldung.durchfuehren");
$url->query("ctxid=check&cusergroup=&cinframe=&curl=");
msg("Fetching ".$url->as_string, $monitor->opts->{verbose});
$m->get($url->as_string);
check_response($monitor, $m);

msg("Submitting form", $monitor->opts->{verbose});
$m->submit_form(
  form_name => "dia",
  fields => {
    cp1 => $monitor->opts->{login},
    cp2 => $monitor->opts->{password}
  }
);
check_response($monitor, $m);

my $content = $m->content;
my ($lastName, $firstName) = ($content =~ /Visitenkarte von (\w+), (\w+)/);
$monitor->nagios_exit(CRITICAL, "Could not authenticate as ".$monitor->opts->{login}) unless (defined $lastName and defined $firstName);

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
$monitor->nagios_exit($code, "Check took to long with ${elapsed}ms for $firstName $lastName") if $code != OK;
# Exit OK.
$monitor->nagios_exit(OK, "Check finished in ${elapsed}ms for $firstName $lastName");

sub check_response {
    my ($monitor, $m) = @_;
    if (!$m->success()) {
        $monitor->nagios_exit(CRITICAL, "Could not fetch ".$m->uri().": ".$m->status())
    }
}
