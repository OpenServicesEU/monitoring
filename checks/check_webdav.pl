#!/usr/bin/perl -w
# Copyright 2011 Michael Fladischer
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

# Disable hostname verification for LWP::SSL because the CN of most
# certificates does not match their internal hostname.
BEGIN { $ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0 }

use IO::Handle;
use HTTP::DAV;
require File::Temp;
use File::Compare;
use Time::HiRes qw( gettimeofday tv_interval );
use Log::Message::Simple qw[:STD :CARP];

use Monitoring::Plugin;
use Monitoring::Plugin::Performance use_die => 1;

my $monitor = Monitoring::Plugin->new(
    shortname => "WebDAV",
    version => "0.2",
    url => "http://openservices.at/services/infrastructure-monitoring/webdav",
    usage => "Usage: %s ".
        "[-v|--verbose] ".
        "[-t <timeout>] ".
        "-H <host> ".
        "-l <login> ".
        "-p <password> ".
        "[-t <port>] ".
        "-u <uri> ".
        "-r <realm> ".
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
        "Port used by the WebDAV server.",
    required => 0,
    default => 80,
);
$monitor->add_arg(
    spec => 'url|u=s',
    help => "-u, --url=STRING\n".
        "URL path for check (e.g. /user/test)",
    required => 1,
);
$monitor->add_arg(
    spec => 'realm|r=s',
    help => "-r, --realm=STRING\n".
        "Realm used in authentication",
    required => 1,
);
$monitor->add_arg(
    spec => 'ssl|s',
    help => "-s, --ssl\n".
        "Use SSL/HTTPS",
    required => 0,
);

# Parse @ARGV and process arguments.
$monitor->getopts;

my $timer = [gettimeofday];

my $d = HTTP::DAV->new();
my $url = sprintf("%s://%s:%i/%s", $monitor->opts->get('ssl') ? "https" : "http", $monitor->opts->get('host'), $monitor->opts->get('port'), $monitor->opts->get('url'));

$d->credentials(
  -user  => $monitor->opts->get('login'),
  -pass  => $monitor->opts->get('password'),
  -url   => $url,
  -realm => $monitor->opts->get('realm'),
);

msg("Connecting to $url", $monitor->opts->get('verbose'));
$d->open( -url => $url )
    or $monitor->nagios_exit(CRITICAL, "Couldn't open $url: ".$d->message);

# Make a new directory
msg("Creating directory $url/nagios", $monitor->opts->get('verbose'));
$d->mkcol( -url => "$url/nagios" )
    or $monitor->nagios_exit(CRITICAL, "Could not create directory $url/nagios: ".$d->message);

# Change to the newly created directory
msg("Changing directory to $url/nagios", $monitor->opts->get('verbose'));
$d->cwd("nagios")
    or $monitor->nagios_exit(CRITICAL, "Could not change to directory $url/nagios: ".$d->message);

my $fhup = File::Temp->new(SUFFIX => '.nagios');
msg("Using local file $fhup for upload", $monitor->opts->get('verbose'));
$fhup->autoflush(1);
open RANDOM, "</dev/urandom"
    or $monitor->nagios_exit(UNKNOWN, "Internal check error at opening /dev/urandom: ".$!);
my $data;
read RANDOM, $data, 128;
print $fhup $data;
close RANDOM;
# Upload file to newly created directory
msg("Uploading file to $url/nagios", $monitor->opts->get('verbose'));
$d->put( -local => $fhup->filename, -url => "$url/nagios/testfile.nagios" )
    or $monitor->nagios_exit(CRITICAL, "Could not upload file to directory $url/nagios/testfile.nagios: ".$d->message);

my $fhdown = File::Temp->new(SUFFIX => '.nagios');
msg("Using local file $fhdown for download", $monitor->opts->get('verbose'));
msg("Downloading file from $url/nagios", $monitor->opts->get('verbose'));
$d->get( -url => "$url/nagios/testfile.nagios", -to => $fhdown->filename )
    or $monitor->nagios_exit(CRITICAL, "Could not download file to directory $url/nagios/testfile.nagios: ".$d->message);

msg("Comparing $fhdown with $fhup", $monitor->opts->get('verbose'));
(compare($fhdown->filename, $fhup->filename) == 0)
    or $monitor->nagios_exit(CRITICAL, "Downloaded file differs from uploaded one");

# Remove uploaded file
msg("Removing file $url/nagios/testfile.nagios", $monitor->opts->get('verbose'));
$d->delete("testfile.nagios")
    or $monitor->nagios_exit(CRITICAL, "Could not remove testfile.nagios from directory $url/nagios: ".$d->message);

# Change to the parent directory before removing the previously created directory
msg("Changing directory to $url", $monitor->opts->get('verbose'));
$d->cwd("..")
  or $monitor->nagios_exit(CRITICAL, "Could not change to directory $url: ".$d->message);

# Remove the previously created directory
msg("Removing directory $url/nagios", $monitor->opts->get('verbose'));
$d->delete("nagios")
  or $monitor->nagios_exit(CRITICAL, "Could not remove directory $url/nagios: ".$d->message);

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
$monitor->nagios_exit($code, "Check took to long with ${elapsed}ms") if $code != OK;
# Exit OK.
$monitor->nagios_exit(OK, "Check finished in ${elapsed}ms");
