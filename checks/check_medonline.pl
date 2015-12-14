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
        "-l <login> ".
        "-p <password> ".
        "[-t <port>] ".
        "-u <uri> ".
        "[-s] ".
        "-w <threshold> ".
        "-c <threshold> ",
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
    spec => 'port|o=i',
    help => "-o, --port=INTEGER\n".
        "Port used by the HTTP server.",
    required => 0,
    default => 80,
);
$monitor->add_arg(
    spec => 'url|u=s',
    help => "-u, --url=STRING\n".
        "Base URL path for check (default: mug_online/)",
    required => 0,
    default => "mug_online/",
);
$monitor->add_arg(
    spec => 'ssl|s',
    help => "-s, --ssl\n".
        "Use SSL/HTTPS",
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

my $url = sprintf("%s://%s:%i/%s", $monitor->opts->get('ssl') ? "https" : "http", $monitor->opts->get('host'), $monitor->opts->get('port'), $monitor->opts->get('url'));
my $path = '/'.$monitor->opts->{url};
my $host = $monitor->opts->get('host');

my $m = WWW::Mechanize->new(
    cookie_jar => {},
    ssl_opts => {SSL_version => 'SSLv3'}, # Oracle decided to mess with Apache mod_ssl up to a point where it breaks :-(
    autocheck => 0,
);

# Register debug handlers
$m->add_handler("request_send", sub { debug(shift->dump, $monitor->opts->{debug}); return });
$m->add_handler("response_done", sub { debug(shift->dump, $monitor->opts->{debug}); return });

# Start timer
my $timer = [gettimeofday];

msg("Fetching ".$url."webnav.ini", $monitor->opts->{verbose});
$m->get($url."webnav.ini");
check_response($monitor, $m);

msg("Adding header Cookie: PSESSIONID=".$m->cookie_jar->{COOKIES}{$host}{$path}{'PSESSIONID'}[1], $monitor->opts->{verbose});
$m->add_header("Cookie" => "PSESSIONID=".$m->cookie_jar->{COOKIES}{$host}{$path}{'PSESSIONID'}[1]);

msg("Fetching ".$url."wbanmeldung.durchfuehren", $monitor->opts->{verbose});
$m->get($url."wbanmeldung.durchfuehren");
check_response($monitor, $m);

msg("Adding header Cookie: PLOGINID=".$m->cookie_jar->{COOKIES}{$host}{$path}{'PLOGINID'}[1], $monitor->opts->{verbose});
$m->add_header("Cookie" => "PSESSIONID=" . $m->cookie_jar->{COOKIES}{$host}{$path}{'PSESSIONID'}[1]."; PLOGINID=".$m->cookie_jar->{COOKIES}{$host}{$path}{'PLOGINID'}[1]);

msg("Fetching ".$url."wbanmeldung.durchfuehren?ctxid=check&cusergroup=&cinframe=&curl=", $monitor->opts->{verbose});
$m->get($url."wbanmeldung.durchfuehren?ctxid=check&cusergroup=&cinframe=&curl=");
check_response($monitor, $m);

msg("Submitting form", $monitor->opts->{verbose});
$m->submit_form(form_name => "dia", fields => {cp1 => $monitor->opts->{login}, cp2 => $monitor->opts->{password}});
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
