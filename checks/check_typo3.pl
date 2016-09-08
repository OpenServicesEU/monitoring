#!/usr/bin/perl -w
# Copyright 2015 Michael Fladischer
# OpenServices e.U.
# office@openservices.at
#
# Monitor Typo3 instances.
# This check is a rewrite of Michael Schams <michael@schams.net> script
# check_typo3.sh available at http://schams.net/nagios/.
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

use version;
use URI;
use LWP::UserAgent;
use File::Spec;
use File::Slurp;
use XML::LibXML;
use Time::HiRes qw(gettimeofday tv_interval);
use Compress::Zlib;
use Digest::MD5;
use Log::Message::Simple qw[:STD :CARP];

use Monitoring::Plugin;
use Monitoring::Plugin::Performance use_die => 1;

use Data::Dumper;

my $monitor = Monitoring::Plugin->new(
  shortname => "TYPO3",
  version => "0.2",
  url => "http://openservices.at/services/infrastructure-monitoring/typo3",
  usage => "Usage: %s ".
  "[-v|--verbose] ".
  "[-t <timeout>] ".
  "-H <host> ".
  "-path=<path> ".
  "[-l <login>] ".
  "[-p <password>] ".
  "[-I <ip>] ".
  "[-i <extension>] ".
  "[-C <cachepath>] ".
  "[-M <mirror>] ".
  "[--update-action=<update-action>] ".
  "[--conflict-action=<conflict-action>] ".
  "[--deprecationlog-action=<deprecation-action>] ".
  "[-w <threshold>] ".
  "[-c <threshold>] ",
);

# add valid command line options and build them into your usage/help documentation.
$monitor->add_arg(
  spec => 'cache|C=s',
  help => "-C, --cache=STRING\n".
  "Path where the downloaded mirrors and extensions XML files can be stored.",
  required => 0,
  default => File::Spec->tmpdir(),
);
$monitor->add_arg(
  spec => 'mirror|M=s',
  help => "-M, --mirror=STRING\n".
  "The prefered mirror URL from which the extensions metadata XML file should be downloaded.",
  required => 0,
  default => "https://typo3.org/fileadmin/ter",
),
$monitor->add_arg(
  spec => 'host|H=s',
  help => "-H, --host=STRING\n".
  "The host to connect to.",
  required => 1,
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
  "   Password used for authentication.",
  required => 0,
);
$monitor->add_arg(
  spec => 'path=i',
  help => "--path=STRING\n".
  "Path of TYPO3 server's Nagios extension output (default: /index.php?eID=nagios).",
  required => 0,
  default => "/index.php?eID=nagios",
);
$monitor->add_arg(
  spec => 'ssl|s',
  help => "-s, --ssl\n".
  "Use SSL (HTTPS) when connecting to TYPO3.",
  required => 0,
);
$monitor->add_arg(
  spec => 'ip|I=s',
  help => "-I, --ip=STRING\n".
  "IPv4 address of the TYPO3 server. If this argument is used, the hostname (argument -H or --hostname) is sent as \"Host:\" in the HTTP header of the request.",
  required => 0,
);
$monitor->add_arg(
  spec => 'ignore|i=s@',
  help => "-i, --ignore=STRING\n".
  "Names of TYPO3 extensions that should be ignored. Can be used multiple times to ignore more than one extension.",
  required => 0,
);
$monitor->add_arg(
  spec => 'conflict-action=s',
  help => "--conflict-action=(ignore|warning|critical)\n".
  "   One of the following actions, if a conflict with an extension has been detected (default: warning):\n".
  "       \"ignore\"    do nothing, ignore conflict\n".
  "       \"warning\"   generate a warning condition in Nagios\n".
  "       \"critical\"  generate a critical condition in Nagios",
  required => 0,
  default => "warning",
);
$monitor->add_arg(
  spec => 'update-action=s',
  help => "--update-action=(ignore|warning|critical)\n".
  "   One of the following actions, if an update for an extension has been detected (default: warning):\n".
  "       \"ignore\"    do nothing, ignore available updates\n".
  "       \"warning\"   generate a warning condition in Nagios\n".
  "       \"critical\"  generate a critical condition in Nagios",
  required => 0,
  default => "warning",
);
$monitor->add_arg(
  spec => 'deprecationlog-action=s',
  help => "--deprecationlog-action=(ignore|warning|critical)\n".
  "   One of the following actions, if an enabled deprecation log has been detected (default: warning):\n".
  "       \"ignore\"    do nothing, ignore enabled deprecation logs\n".
  "       \"warning\"   generate a warning condition in Nagios\n".
  "       \"critical\"  generate a critical condition in Nagios",
  required => 0,
  default => "warning",
);
$monitor->add_arg(
  spec => 'debug|d',
  help => "-d, --debug\n".
  "Print debug information",
  required => 0,
);

# Map strings from arguments to Nagios Plugin codes.
my %codemap = (
  "ignore" => undef,
  "warning" => WARNING,
  "critical" => CRITICAL,
);

# Parse @ARGV and process arguments.
$monitor->getopts;

# Set up user agent to fetch data.
my $headers = HTTP::Headers->new(
  User_Agent => $monitor->shortname,
);


my $uri = URI->new("http://");

# Attach host and path to URL.
$uri->host($monitor->opts->get('host'));
$uri->path_query($monitor->opts->get('path'));

# See if we should enable SSL for HTTPS.
if ($monitor->opts->get('ssl')) {
  $uri->scheme('https');
}

# Override default port if needed.
if ($monitor->opts->get('port')) {
  $uri->port($monitor->opts->get('port'));
}

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

msg(
  sprintf(
    "Connecting to TYPO3 on %s with user %s",
    $uri->as_string,
    $monitor->opts->get("login") || ''
  ),
  $monitor->opts->get('verbose')
);

# Retrieve TYPO3 nagios extension page and meassure required time.
my $timer = [gettimeofday];
my $response = $ua->get($uri->as_string);
my $elapsed = tv_interval($timer) * 1000;

# Perfdata
$monitor->add_perfdata(
  label => "Latency",
  value => $elapsed,
  threshold => $monitor->threshold,
  uom => 'ms',
);

# See if we got a valid response from the TYPO3 nagios extension.
if ($response->is_error) {
  $monitor->plugin_exit(
    CRITICAL,
    sprintf(
      "TYPO3 returned a HTTP error: %s",
      $response->status_line
    )
  );
}

my $uat = LWP::UserAgent->new(
  cookie_jar => undef,
  default_headers => $headers,
);


my $mirror_url = URI->new($monitor->opts->get("mirror"));

msg(
  sprintf(
    "Using mirror: %s",
    $mirror_url->as_string
  ),
  $monitor->opts->get('verbose')
);

my $cache = File::Spec->catfile(
  $monitor->opts->get("cache"),
  "extensions.xml.gz"
);

my $ext_bin;

# Check if a caching file already exists.
if (-e $cache) {
  my $md5_url = $mirror_url->clone;
  $md5_url->path_segments($mirror_url->path_segments, "extensions.md5");
  msg(
    sprintf(
      "Downloading extensions.md5: %s",
      $md5_url->as_string
    ),
    $monitor->opts->get('verbose')
  );
  my $md5_resp= $uat->get($md5_url->as_string);
  if ($md5_resp->is_error) {
    $monitor->plugin_exit(
      UNKNOWN,
      sprintf(
        "Could not fetch remote MD5 checksum: %s",
        $md5_url->as_string
      )
    );
  }
  msg(
    sprintf(
      "Remote extensions.md5: %s",
      $md5_resp->content
    ),
    $monitor->opts->get('verbose')
  );
  my $ctx = Digest::MD5->new;
  open my $fh, '<', $cache;
  binmode ($fh);
  $ctx->addfile($fh);
  my $md5_local = $ctx->hexdigest;
  close $fh;
  msg(
    sprintf(
      "Local MD5 for extensions.xml.gz: %s",
      $ctx->hexdigest
    ),
    $monitor->opts->get('verbose')
  );
  if ($md5_resp->content eq $md5_local) {
    msg(
      "Local extensions.xml.gz is up to date.",
      $monitor->opts->get('verbose')
    );
    $ext_bin = read_file($cache, binmode => ':raw');
  } else {
    msg(
      "Local extensions.xml.gz is out of date, purging from cache.",
      $monitor->opts->get('verbose')
    );
    unlink $cache;
  }
}

# See if we got some content from caching, if not, fetch the whole extension archive.
if (!defined $ext_bin) {
  my $ext_url = $mirror_url->clone;
  $ext_url->path_segments(
    $mirror_url->path_segments,
    "extensions.xml.gz"
  );
  msg(
    sprintf(
      "Download extensions.xml.gz: %s",
      $ext_url->as_string
    ),
    $monitor->opts->get('verbose')
  );
  my $ext_resp = $uat->get($ext_url->as_string);
  if ($ext_resp->is_error) {
    $monitor->plugin_exit(
      UNKNOWN,
      sprintf(
        "Could not fetch remote extension archive: %s",
        $ext_url->as_string
      )
    );
  }
  if ($monitor->opts->get("cache")) {
    open my $fh, ">", $cache;
    binmode ($fh);
    print $fh $ext_resp->content;
    close $fh;
  }
  $ext_bin = $ext_resp->content;
}

my $extensions = XML::LibXML->load_xml(
  string => Compress::Zlib::memGunzip($ext_bin)
);
# Hash that will hold the parsed response data.
my %data;

# Parse response content and populate data hash.
foreach (grep { !/^#|^$/ } split /\n/, $response->content) {
  print $_;
  my @matches = $_ =~ /^(\w+):(.*?)((-version)?-(([\d\.]+)(-dev|-([\d\.]+))?))?$/g;

  # Ignore extensions from arguments.
  next if (grep { /$matches[1]/ } @{$monitor->opts->get("ignore") || []});

  if (!exists $data{$matches[0]}) {
    $data{$matches[0]} = {};
  }
  if ($matches[0] =~ /^TYPO3|PHP$/) {
    $data{$matches[0]} = version->parse($matches[4]);
  } elsif ($matches[0] =~ /^EXT$/) {
    $data{$matches[0]}->{$matches[1]} = version->parse($matches[5]);
  } elsif ($matches[0] =~ /^EXTDEPTYPO3$/) {
    $data{$matches[0]}->{$matches[1]} = {
      "from" => version->parse($matches[5]),
      "to" => version->parse($matches[7])
    }
  } else {
    $data{$matches[0]} = $matches[1];
  }

}

# Perfdata
$monitor->add_perfdata(
  label => "Database tables",
  value => $data{DBTABLES},
);

my @updates;
foreach my $name (keys %{$data{EXT}}) {
  my $ext = $data{EXT}->{$name};
  my $extension = ($extensions->findnodes(sprintf("/extensions/extension[\@extensionkey='%s']", $name)))[0];
  if (!defined $extension) {
    msg(
      sprintf(
        "Extension not found in data file: %s",
        $name
      ),
      $monitor->opts->get('verbose')
    );
    next;
  }
  if (grep { $ext < $_ } map { version->parse($_->to_literal) } $extension->findnodes("version/\@version")) {
    push @updates, $name;
  }
}

# Perfdata
$monitor->add_perfdata(
  label => "Updates pending",
  value => scalar @updates,
);

# Filter all conflicts.
my @conflicts = grep { $data{TYPO3} < $data{EXTDEPTYPO3}->{$_}->{from} or $data{TYPO3} > $data{EXTDEPTYPO3}->{$_}->{to} } grep { $data{EXTDEPTYPO3}->{$_}->{to} > 0 } keys %{$data{EXTDEPTYPO3}};

# Perfdata
$monitor->add_perfdata(
  label => "Version conflicts",
  value => scalar @conflicts,
);

# First status derived from the time elapsed during the initial request.
my $code = $monitor->check_threshold(check => $elapsed);
my $message = sprintf("Request finished in %ims", $elapsed);

# Check for deprecation log.
if (defined $codemap{$monitor->opts->get('deprecationlog-action')} and $data{DEPRECATIONLOG} eq "enabled") {
  if ($codemap{$monitor->opts->get('deprecationlog-action')} > $code) {
    $code = $codemap{$monitor->opts->get('deprecationlog-action')};
  }
  $message .= "; Deprecation log enabled!";
}

# Process conflicts.
if (scalar @conflicts > 0) {
  my $action = $codemap{$monitor->opts->get('conflict-action')};
  if (defined $action && $action > $code) {
    $code = $action;
  }
  $message .= sprintf("; TYPO3 %s conflicts: %s", $data{TYPO3}, join(", ", map { sprintf ("%s[%s-%s]", $_, $data{EXTDEPTYPO3}->{$_}->{from}, $data{EXTDEPTYPO3}->{$_}->{to}) } @conflicts));
}

# Process updates.
if (scalar @updates > 0) {
  my $action = $codemap{$monitor->opts->get('update-action')};
  if (defined $action && $action > $code) {
    $code = $action;
  }
  $message .= sprintf("; Updates available: %s", join(", ", @updates));
}

# Exit with final status and message.
$monitor->plugin_exit($code, $message);
