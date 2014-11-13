#!/usr/bin/perl -w
# Copyright 2013 Michael Fladischer
# OpenServices e.U.
# office@openservices.at
#
# Perform authentication on GroupWise 2012 web mail interface.
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

use Nagios::Plugin;
use Nagios::Plugin::Performance use_die => 1;

my $nagios = Nagios::Plugin->new(
    shortname => "GROUPWISE 2012 WEBMAIL",
    version => "0.1",
    url => "http://openservices.at/services/infrastructure-monitoring/groupwise-2012-webmail",
    usage => "Usage: %s ".
        "[-v|--verbose] ".
        "[-t <timeout>] ".
        "-H <host> ".
        "-l <login> ".
        "-p <password> ".
        "[-t <port>] ".
        "[-u <uri>] ".
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
        "Username to login.",
    required => 1,
);
$nagios->add_arg(
    spec => 'password|p=s',
    help => "-p, --password=STRING\n".
        "Password used for authentication.",
    required => 1,
);
$nagios->add_arg(
    spec => 'port|o=i',
    help => "-o, --port=INTEGER\n".
        "Port used by the HTTP(S) server.",
    required => 0,
    default => 0,
);
$nagios->add_arg(
    spec => 'url|u=s',
    help => "-u, --url=STRING\n".
        "Base URL path for check (default: gw/webacc)",
    required => 0,
    default => "gw/webacc",
);
$nagios->add_arg(
    spec => 'ssl|s',
    help => "-s, --ssl\n".
        "Use SSL/HTTPS",
    required => 0,
);
$nagios->add_arg(
    spec => 'debug|d',
    help => "-d, --debug\n".
        "Print debug information",
    required => 0,
    default => 0,
);

# Parse @ARGV and process arguments.
$nagios->getopts;

my $port;
if ($nagios->opts->get('port') == 0) {
    $port = $nagios->opts->get('ssl') ? 443 : 80;
} else {
    $port = $nagios->opts->get('port');
}
my $path = '/'.$nagios->opts->{url};
my $host = $nagios->opts->get('host');
my $url = sprintf("%s://%s:%i%s", $nagios->opts->get('ssl') ? "https" : "http", $host, $port, $path);

my $m = WWW::Mechanize->new(
    cookie_jar => {},
    #ssl_opts => {SSL_version => 'SSLv3'}, # Oracle decided to mess with Apache mod_ssl up to a point where it breaks :-(
    agent => 'Mozilla/5.0 (X11; Linux x86_64; rv:24.0) Gecko/20100101 Firefox/24.0 Iceweasel/24.0',
    autocheck => 0,
);

# Register debug handlers
$m->add_handler("request_send", sub { debug(shift->dump, $nagios->opts->{debug}); return });
$m->add_handler("response_done", sub { debug(shift->dump, $nagios->opts->{debug}); return });

# Start timer
my $timer = [gettimeofday];

msg("Fetching ".$url, $nagios->opts->{verbose});
$m->get($url);
check_response($nagios, $m);

#msg("Adding header Cookie: PSESSIONID=".$m->cookie_jar->{COOKIES}{$host}{$path}{'PSESSIONID'}[1], $nagios->opts->{verbose});
#$m->add_header("Cookie" => "PSESSIONID=".$m->cookie_jar->{COOKIES}{$host}{$path}{'PSESSIONID'}[1]);

#msg("Fetching ".$url."wbanmeldung.durchfuehren", $nagios->opts->{verbose});
#$m->get($url."wbanmeldung.durchfuehren");
#check_response($nagios, $m);
#
#msg("Adding header Cookie: PLOGINID=".$m->cookie_jar->{COOKIES}{$host}{$path}{'PLOGINID'}[1], $nagios->opts->{verbose});
#$m->add_header("Cookie" => "PSESSIONID=" . $m->cookie_jar->{COOKIES}{$host}{$path}{'PSESSIONID'}[1]."; PLOGINID=".$m->cookie_jar->{COOKIES}{$host}{$path}{'PLOGINID'}[1]);

#msg("Fetching ".$url."wbanmeldung.durchfuehren?ctxid=check&cusergroup=&cinframe=&curl=", $nagios->opts->{verbose});
#$m->get($url."wbanmeldung.durchfuehren?ctxid=check&cusergroup=&cinframe=&curl=");
#check_response($nagios, $m);

msg("Submitting form", $nagios->opts->{verbose});
$m->submit_form(form_name => "loginForm", fields => {"User.id" => $nagios->opts->{login}, "User.password" => $nagios->opts->{password}});
check_response($nagios, $m);

my $content = $m->content;
my ($userid) = ($content =~ /var userId = \"([\w\_]+)\";/);
$nagios->nagios_exit(CRITICAL, "Could not authenticate as ".$nagios->opts->{login}) unless ($userid eq $nagios->opts->{login});
my ($firstName, $lastName) = ($content =~ /<TITLE>Novell GroupWise \((\w+) (\w+)\)<\/TITLE>/);
$nagios->nagios_exit(CRITICAL, "Could not authenticate as ".$nagios->opts->{login}) unless (defined $lastName and defined $firstName);

# End timer
my $elapsed = tv_interval($timer) * 1000;

# Threshold check.
my $code = $nagios->check_threshold(
    check => $elapsed,
);

# Perfdata
$nagios->add_perfdata(
    label => "Latency",
    value => $elapsed,
    threshold => $nagios->threshold,
    uom => 'ms',
);

# Exit if WARNING or CRITICAL.
$nagios->nagios_exit($code, "Check took to long with ${elapsed}ms for $firstName $lastName") if $code != OK;
# Exit OK.
$nagios->nagios_exit(OK, "Check finished in ${elapsed}ms for $firstName $lastName");

sub check_response {
    my ($nagios, $m) = @_;
    if (!$m->success()) {
        $nagios->nagios_exit(CRITICAL, "Could not fetch ".$m->uri().": ".$m->status())
    }
}
