#!/usr/bin/perl -w
# Copyright 2015 Michael Fladischer
# OpenServices e.U.
# office@openservices.at
#
# Count the number of messages inside a IMAP folder with support for filters.
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

use Net::IMAP::Simple;
use IO::Socket::SSL;
use Log::Message::Simple qw[:STD :CARP];

use Monitoring::Plugin;
use Monitoring::Plugin::Performance use_die => 1;

my $monitor = Monitoring::Plugin->new(
  shortname => "IMAP/FOLDER",
  version => "0.1",
  url => "http://openservices.at/services/infrastructure-monitoring/imap-folder",
  usage => "Usage: %s ".
  "-H <host> ".
  "-l <login> ".
  "-p <password> ".
  "-w <warning> ".
  "-c <threshold> ".
  "[-f <folder>] ".
  "[-F <filter>] ".
  "[-P <port>] ".
  "[-s] ".
  "[-t <timeout>] ".
  "[-v] ".
  "[-d] ",
);

# add valid command line options and build them into your usage/help documentation.
$monitor->add_arg(
  spec => 'host|H=s',
  help => "-H, --host=STRING\n".
  "The IMAP server to connect to.",
  required => 1,
);
$monitor->add_arg(
  spec => 'warning|w=i',
  help => "-w, --warning=INTEGER:INTEGER\n".
  "The number of messages inside the folder for which the check will return WARNING.\n".
  "See http://nagiosplug.sourceforge.net/developer-guidelines.html#THRESHOLDFORMAT for the threshold format.",
  required => 1,
);
$monitor->add_arg(
  spec => 'critical|c=i',
  help => "-c, --critical=INTEGER:INTEGER\n".
  "The number of messages inside the folder for which the check will return CRITICAL.\n".
  "See http://nagiosplug.sourceforge.net/developer-guidelines.html#THRESHOLDFORMAT for the threshold format.",
  required => 1,
);
$monitor->add_arg(
  spec => 'login|l=s',
  help => "-l, --login=STRING\n".
  "Username on IMAP server.",
  required => 1,
);
$monitor->add_arg(
  spec => 'password|p=s',
  help => "-p, --password=STRING\n".
  "Password on IMAP server.",
  required => 1,
);
$monitor->add_arg(
  spec => 'folder|f=s',
  help => "-f, --folder=STRING\n".
  "Folder to check on IMAP server.",
  required => 0,
  default => "INBOX",
);
$monitor->add_arg(
  spec => 'filter|F=s',
  help => "-F, --filter=INTEGER\n".
  "IMAP SEARCH filter that is applied to the folder.",
  required => 0,
);
$monitor->add_arg(
  spec => 'port|P=i',
  help => "-P, --port=INTEGER\n".
  "Port on the IMAP server (default: 143).",
  required => 0,
  default => 143,
);
$monitor->add_arg(
  spec => 'ca-file|C=s',
  help => "-C, --ca-file=STRING\n".
  "PAth to CA file (default: /etc/ssl/certs/ca-certificates.crt).",
  required => 0,
  default => "/etc/ssl/certs/ca-certificates.crt",
);
$monitor->add_arg(
  spec => 'ssl|s',
  help => "-s, --ssl\n".
  "Enable SSL.",
  required => 0,
);
$monitor->add_arg(
  spec => 'starttls|S',
  help => "-S, --starttls\n".
  "Enable STARTTLS.",
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

my %options = (
  port => $monitor->opts->get('port'),
);

if ($monitor->opts->get('timeout')) {
  $options{timeout} = $monitor->opts->get('timeout');
}

if ($monitor->opts->get('ssl')) {
  $options{use_ssl} = 1;
  $options{ssl_version} = "SSLv23:!SSLv3:!SSLv2";
  $options{ssl_options} = [
    SSL_ca_file => $monitor->opts->get('ca-file'),
    SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_PEER(),
    SSL_version => "SSLv23:!SSLv3:!SSLv2",
  ];
}


msg(
  sprintf(
    "Connecting to %s on port %d",
    $monitor->opts->get('host'),
    $monitor->opts->get('port')
  ),
  $monitor->opts->get('verbose')
);
my $imap = Net::IMAP::Simple->new(
  $monitor->opts->get('host'),
  %options
);

if (!$imap) {
  $monitor->plugin_exit(
    UNKNOWN,
    sprintf(
      "Connection failed: %s",
      $Net::IMAP::Simple::errstr
    )
  );
}

if ($monitor->opts->get('starttls')) {
  msg(
    "Enabling STARTTLS",
    $monitor->opts->get('verbose')
  );
  $imap->starttls;
}

msg(
  sprintf(
    "Logging in as user %s",
    $monitor->opts->get('login')
  ),
  $monitor->opts->get('verbose')
);
if(!$imap->login($monitor->opts->get('login'), $monitor->opts->get('password'))){
  $monitor->plugin_exit(
    UNKNOWN,
    sprintf(
      "Login failed: %s",
      $imap->errstr
    )
  );
}

msg(
  sprintf(
    "Selecting folder %s",
    $monitor->opts->get('folder')
  ),
  $monitor->opts->get('verbose')
);

my @mailboxes = $imap->mailboxes;
if ($monitor->opts->get('debug')) {
  foreach my $mailbox (@mailboxes) {
    msg(
      sprintf(
        "Found mailbox: %s",
        $mailbox
      ),
      $monitor->opts->get('debug')
    );
  }
}

if (!grep {$_ eq $monitor->opts->get('folder')} @mailboxes) {
  $monitor->plugin_exit(
    UNKNOWN,
    sprintf(
      "Could not select folder: %s",
      $monitor->opts->get('folder')
    )
  );
}

my $count;
if ($monitor->opts->get('filter')) {
  msg(
    sprintf(
      "Counting messages matching '%s'",
      $monitor->opts->get('filter')
    ),
    $monitor->opts->get('verbose')
  );
  $count = $imap->search($monitor->opts->get('filter'));
} else {
  msg(
    "Counting unseen messages",
    $monitor->opts->get('verbose')
  );
  $count = $imap->unseen($monitor->opts->get('folder'));
}

# Perfdata
$monitor->add_perfdata(
  label => "Unseen",
  value => $count,
  threshold => $monitor->threshold,
  uom => 'messages',
);
$monitor->plugin_exit(
  $monitor->check_threshold(check => $count),
  sprintf(
    "%d messages found in %s",
    $count,
    $monitor->opts->get('folder')
  )
);
