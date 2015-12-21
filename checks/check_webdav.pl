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

use URI;
use HTTP::DAV;
use File::Temp;
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
  "-r <realm> ".
  "--path=<path> ".
  "-w <threshold> ".
  "-c <threshold> ".
  "[-I <ip>] ".
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
  spec => 'realm|r=s',
  help => "-r, --realm=STRING\n".
  "Realm used in authentication",
  required => 1,
);
$monitor->add_arg(
  spec => 'path=s',
  help => "--path=STRING\n".
  "Path for check (e.g. /user/test)",
  required => 1,
);
$monitor->add_arg(
  spec => 'port|P=i',
  help => "-P, --port=INTEGER\n".
  "Port used by the WebDAV server.",
  required => 0,
);
$monitor->add_arg(
  spec => 'ip|I=s',
  help => "-I, --IP=STRING\n".
  "The IP to connect to. If this is set, the host parameter is sent in the Host HTTP header field.",
  required => 0,
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

my $headers = HTTP::Headers->new(
  User_Agent => $monitor->shortname,
);

if ($monitor->opts->get('ip')) {
  $headers->header(Host => $monitor->opts->get('host'));
}

my $ua = HTTP::DAV::UserAgent->new(
  cookie_jar => {},
  default_headers => $headers,
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
my $timer = [gettimeofday];

my $d = HTTP::DAV->new(-useragent=>$ua);

$d->credentials(
  -url   => $uri->as_string,
  -user  => $monitor->opts->get('login'),
  -pass  => $monitor->opts->get('password'),
  -realm => $monitor->opts->get('realm'),
);

msg(
  sprintf(
    "Connecting to %s",
    $uri->as_string
  ),
  $monitor->opts->get('verbose')
);
if (!$d->open(-url => $uri->as_string)) {
  $monitor->plugin_exit(
    CRITICAL,
    sprintf(
      "Couldn't open %s: %s",
      $uri->as_string,
      $d->message
    )
  );
}

my $url;

# Make a new directory
$url = $uri->clone;
$url->path_segments($uri->path_segments, "nagios");
msg(
  sprintf(
    "Creating directory %s",
    $url->as_string
  ),
  $monitor->opts->get('verbose')
);
if (!$d->mkcol(-url => $url->as_string)) {
  $monitor->plugin_exit(
    CRITICAL,
    sprintf(
      "Could not create directory %s: %s",
      $url->as_string,
      $d->message
    )
  );
}

# Change to the newly created directory
msg(
  sprintf(
    "Changing directory to %s",
    $url->as_string
  ),
  $monitor->opts->get('verbose')
);
if (!$d->cwd("nagios")) {
  $monitor->plugin_exit(
    CRITICAL,
    sprintf(
      "Could not change to directory %s :%s",
      $url->as_string,
      $d->message
    )
  );
}

my $fhup = File::Temp->new(SUFFIX => '.nagios');
msg(
  sprintf(
    "Using local file for upload: %s",
    $fhup
  ),
  $monitor->opts->get('verbose')
);
$fhup->autoflush(1);
if (!open RANDOM, "</dev/urandom") {
  $monitor->plugin_exit(
    UNKNOWN,
    sprintf(
      "Internal check error at opening /dev/urandom: %s",
      $!
    )
  );
}

my $data;
read RANDOM, $data, 128;
print $fhup $data;
close RANDOM;

# Upload file to newly created directory
$url = $uri->clone;
$url->path_segments($uri->path_segments, "nagios", "testfile.nagios");
msg(
  sprintf(
    "Uploading file to %s",
    $url->as_string
  ),
  $monitor->opts->get('verbose')
);
if (!$d->put(-local => $fhup->filename, -url => $url->as_string)) {
  $monitor->plugin_exit(
    CRITICAL,
    sprintf(
      "Could not upload file to directory %s: %s",
      $url->as_string,
      $d->message
    )
  );
}

my $fhdown = File::Temp->new(SUFFIX => '.nagios');
msg(
  sprintf(
    "Using local file for download: %s",
    $fhdown
  ),
  $monitor->opts->get('verbose')
);
msg(
  sprintf(
    "Downloading file from %s",
    $url->as_string
  ),
  $monitor->opts->get('verbose')
);
if (!$d->get(-url => $url->as_string, -to => $fhdown->filename)) {
  $monitor->plugin_exit(
    CRITICAL,
    sprintf(
      "Could not download file to directory %s: %s",
      $url->as_string,
      $d->message
    )
  );
}

msg(
  sprintf(
    "Comparing %s with %s",
    $fhdown,
    $fhup
  ),
  $monitor->opts->get('verbose')
);
if (compare($fhdown->filename, $fhup->filename) != 0) {
  $monitor->plugin_exit(
    CRITICAL,
    "Downloaded file differs from uploaded one"
  );
}

# Remove uploaded file
msg(
  sprintf(
    "Removing file %s",
    $url->as_string
  ),
  $monitor->opts->get('verbose')
);
if (!$d->delete("testfile.nagios")) {
  $monitor->plugin_exit(
    CRITICAL,
    sprintf(
      "Could not remove %s: %s",
      $url->as_string,
      $d->message
    )
  );
}

# Change to the parent directory before removing the previously created directory
msg(
  sprintf(
    "Changing directory to %s",
    $url->as_string
  ),
  $monitor->opts->get('verbose')
);
if (!$d->cwd("..")) {
  $monitor->plugin_exit(
    CRITICAL,
    sprintf(
      "Could not change to directory %s: %s",
      $url->as_string,
      $d->message
    )
  );
}

# Remove the previously created directory
$url = $uri->clone;
$url->path_segments($uri->path_segments, "nagios");
msg(
  sprintf(
    "Removing directory %s",
    $url->as_string
  ),
  $monitor->opts->get('verbose')
);
if (!$d->delete("nagios")) {
  $monitor->plugin_exit(
    CRITICAL,
    sprintf(
      "Could not remove directory %s: %s",
      $url->as_string,
      $d->message
    )
  );
}

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
  $monitor->plugin_exit(
    $code,
    sprintf(
      "Check took to long with %dms",
      $elapsed
    )
  );
}
# Exit OK.
$monitor->plugin_exit(
  OK,
  sprintf(
    "Check finished in %dms",
    $elapsed
  )
);
