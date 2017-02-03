#!/usr/bin/perl -w
# Copyright 2017 Michael Fladischer
# OpenServices e.U.
# office@openservices.at
#
# Grade HTTPs configurations using the Qualys SSLLabs webservice.
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

use List::MoreUtils qw(first_index);
use WebService::SSLLabs;
use Log::Message::Simple qw[:STD :CARP];

use Monitoring::Plugin;
use Monitoring::Plugin::Performance use_die => 1;

my $monitor = Monitoring::Plugin->new(
  shortname => "SSLLABS",
  version => "0.1",
  url => "http://openservices.at/services/infrastructure-monitoring/ssllabs",
  usage => "Usage: %s ".
  "[-v|--verbose] ".
  "[-t <timeout>] ".
  "-H <host> ".
  "-w <grade> ".
  "-c <grade> ".
  "[-C] ".
  "[-m <hours>] ".
  "[-p] ",
);

# add valid command line options and build them into your usage/help documentation.
$monitor->add_arg(
  spec => 'host|H=s',
  help => "-H, --host=STRING\n".
  "   The host to test.",
  required => 1,
);
$monitor->add_arg(
  spec => 'warning|w=s',
  help => "-w, --warning=GRADE\n".
  "   See https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide for the grading system.",
  required => 1,
);
$monitor->add_arg(
  spec => 'critical|c=s',
  help => "-c, --critical=GRADE\n".
  "   See https://github.com/ssllabs/research/wiki/SSL-Server-Rating-Guide for the grading system.",
  required => 1,
);
$monitor->add_arg(
  spec => 'cache|C',
  help => "-C, --cache\n".
  "    Always deliver cached assessment reports if available.",
  required => 0,
);
$monitor->add_arg(
  spec => 'max-age|m=i',
  help => "-m, --max-age=HOURS\n".
  "   Maximum report age, in hours, if retrieving from cache.",
  required => 0,
  default => 48,
);
$monitor->add_arg(
  spec => 'publish|p',
  help => "-p, --publish\n".
  "    Publish assessment results on the public results boards.",
  required => 0,
);

# Parse @ARGV and process arguments.
$monitor->getopts;

msg(
  sprintf(
    "Connecting to Qualys SSLLabs to test %s",
    $monitor->opts->get("host")
  ),
  $monitor->opts->get("verbose")
);
my $labs = WebService::SSLLabs->new();

my $info = $labs->info();

if (!defined $info) {
  $monitor->plugin_exit(
    UNKNOWN,
    "SSLLabs system not available."
  );
}
msg(
  sprintf(
    "Using rating criteria %s",
    $info->criteria_version
  ),
  $monitor->opts->get("verbose")
);

if ($info->current_assessments >= $info->max_assessments) {
  $monitor->plugin_exit(
    UNKNOWN,
    sprintf(
      "Maximum concurrent assessments reached: %d.",
      $info->max_assessments
    )
  );
}

my @grades = ('A+', 'A', 'A-', 'B', 'C', 'D', 'E', 'F', 'T', 'M');
my $warning = first_index { $_ eq $monitor->opts->get("warning") } @grades;
my $critical = first_index { $_ eq $monitor->opts->get("critical") } @grades;

if ($critical < $warning) {
  $monitor->plugin_exit(
    UNKNOWN,
    sprintf(
      "Critical grade (%s) must be worse of equal to warning grade (%s).",
      $monitor->opts->get("critical"),
      $monitor->opts->get("warning")
    )
  );
}

$monitor->set_thresholds(warning => $warning, critical => $critical);

my $host;
my @errors;
my %options = (
  host => $monitor->opts->get("host"),
  publish => $monitor->opts->get("publish") ? "on" : "off",
  from_cache => $monitor->opts->get("cache") ? "on" : "off",
  max_age => $monitor->opts->get("max-age"),
);
while(not $host = $labs->analyze(%options)->complete()) {
  msg(
    sprintf(
      "Sleeping for %d seconds",
      $labs->previous_eta()
    ),
    $monitor->opts->get("verbose")
  );
  sleep $labs->previous_eta();
}
if ($host->ready()) {
  foreach my $endpoint ($host->endpoints()) {
    if ($endpoint->ready()) {
      msg(
        sprintf(
          "Endpoint %s rated: %s",
          $endpoint->ip_address(),
          $endpoint->grade()
        ),
        $monitor->opts->get("verbose")
      );
      my $index = first_index { $_ eq $endpoint->grade() } @grades;
      $monitor->add_message(
        $monitor->check_threshold($index),
        sprintf("%s: %s", $endpoint->ip_address(), $endpoint->grade())
      );
    } else {
      msg(
        sprintf(
          "Endpoint %s failed: %s",
          $endpoint->ip_address(),
          $endpoint->status_message()
        ),
        $monitor->opts->get("verbose")
      );
      push @errors, sprintf("%s: %s", $endpoint->ip_address(), $endpoint->status_message());
    }
  }
} else {
  $monitor->plugin_exit(
    UNKNOWN,
    sprintf(
      "%s failed to test: %s",
      $host->host(),
      $host->status_message()
    )
  );
}

if (@errors) {
  $monitor->plugin_exit(
    UNKNOWN,
    sprintf(
      "One of more endpoints could not be tested:\n - %s",
      join("\n - ", @errors)
    )
  );
}

my ($code, $message) = $monitor->check_messages(join => "\n - ");
$monitor->plugin_exit(
  $code,
  sprintf(
    "SSLLabs test results:\n - %s",
    $message
  )
);
