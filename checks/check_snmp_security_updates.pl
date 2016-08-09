#!/usr/bin/perl -w
# Copyright 2014 Michael Fladischer
# OpenServices e.U.
# office@openservices.at
#
# This is a optimized check for the OpenServices::SNMP::Plugin::Updates agent
# extension. It uses warning and critical thresholds to check if the time an
# update has been in the pending state should trigger a WARNING or CRITICAL
# status. If there are pending updates but none of them is pending more than the
# warning or critical threshold, then a status of OK is returned.
#
# If the OID is not found, then UNKNOWN is returned.
#
# This check uses Berkeley DB files to memorize the names and timestamps of
# pending updates.
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

use POSIX;
use Log::Message::Simple qw[:STD :CARP];

use Monitoring::Plugin;
use Monitoring::Plugin::Performance use_die => 1;

use DB_File;
use Net::SNMP;

my $monitor = Monitoring::Plugin->new(
  shortname => 'SECURITY UPDATES',
  version => '0.3',
  url => 'http://openservices.at/services/infrastructure-monitoring/security_updates',
  usage => 'Usage: %s '.
    '[-v|--verbose] '.
    '[-t <timeout>] '.
    '-H <host> '.
    '-C <community> '.
    '[-o <oid>] '.
    '[-s <path>] '.
    '[-P <port>] '.
    '[-w <threshold>] '.
    '[-c <threshold>] ',
);

# add valid command line options and build them into your usage/help documentation.
$monitor->add_arg(
  spec => 'warning|w=i',
  help => "-w, --warning=INTEGER:INTEGER\n".
    'See http://nagiosplug.sourceforge.net/developer-guidelines.html#THRESHOLDFORMAT for the threshold format.',
  required => 1
);
$monitor->add_arg(
  spec => 'critical|c=i',
  help => "-c, --critical=INTEGER:INTEGER\n".
    'See http://nagiosplug.sourceforge.net/developer-guidelines.html#THRESHOLDFORMAT for the threshold format.',
  required => 1
);
$monitor->add_arg(
  spec => 'hostname|H=s',
  help => "-H, --hostname=hostname\n".
    'Hostname of SNMP agent.',
  required => 1
);
$monitor->add_arg(
  spec => 'community|C=s',
  help => "-C, --community=secret\n".
    'SNMP community string.',
  required => 1
);
$monitor->add_arg(
  spec => 'oid|o=s',
  help => "-o, --oid=OID\n".
    'Base OID at which package updates are found (default: .1.3.6.1.4.1.36425.256.2).',
  required => 0,
  default => '.1.3.6.1.4.1.36425.256.2'
);
$monitor->add_arg(
  spec => 'store|s=s',
  help => "-s, --store=PATH\n".
    'Path to the file where package tracing information can be stored.',
  required => 0,
  default => '/var/cache/monitoring/security_updates'
);
$monitor->add_arg(
  spec => 'port|P=i',
  help => "-P, --port=INT\n".
    'SNMP port.',
  required => 0,
  default => 161
);

# Parse @ARGV and process arguments.
$monitor->getopts;

my $filename = sprintf(
  '%s/%s-%d.db',
  $monitor->opts->get('store'),
  $monitor->opts->get('hostname'),
  $monitor->opts->get('port')
);

my %h;

msg(
  sprintf(
    'Persistent store: %s',
    $filename
  ),
  $monitor->opts->get('verbose')
);

msg(
  sprintf(
    'Connecting to %s:%d',
    $monitor->opts->get('hostname'),
    $monitor->opts->get('port')
  ),
  $monitor->opts->get('verbose')
);

my ($snmp, $error) = Net::SNMP->session(
  -hostname => $monitor->opts->get('hostname'),
  -community => $monitor->opts->get('community'),
  -port => $monitor->opts->get('port')
);

if (!defined($snmp)) {
  $monitor->nagios_exit(UNKNOWN, sprintf('Could not connect: %s', $error));
}

my $count = $snmp->get_request($monitor->opts->get('oid'));
if (!exists $count->{$monitor->opts->get('oid')}) {
  $monitor->nagios_exit(UNKNOWN, sprintf('No security update information found at %s', $monitor->opts->get('oid')));
}
$monitor->add_perfdata(
  label => 'updates',
  value => $count->{$monitor->opts->get('oid')},
);
if ($count->{$monitor->opts->get('oid')} == 0) {
  unlink $filename;
  $monitor->nagios_exit(OK, 'No security updates pending');
}

my $packages = {};
my $oid = $monitor->opts->get('oid');

while (my $response = $snmp->get_next_request($oid)) {
  $oid = (keys %$response)[0];
  if (substr($oid, 0, length $monitor->opts->get('oid')) ne $monitor->opts->get('oid')) {
    last;
  }
  msg(
    sprintf(
      'Walking OID %s: %s',
      $oid,
      $response->{$oid}
    ),
    $monitor->opts->get('verbose')
  );
  $packages->{$oid} = $response->{$oid}

};

my @packagenames = values %{$packages};

# Tie persistent storage to keep track of pending updates over time.
tie %h, 'DB_File', $filename, O_RDWR|O_CREAT, 0640, $DB_HASH or
$monitor->nagios_exit(UNKNOWN, sprintf('Cannot open file %s (%s)', $filename, $!));

foreach my $key (keys %h) {
  msg(
    sprintf(
      'Previously seen update: %s (%s)',
      $key,
      scalar localtime $h{$key}
    ),
    $monitor->opts->get('verbose')
  );
  if (!grep { $key eq $_ } @packagenames) {
    msg(
      sprintf(
        'Forgetting update: %s',
        $key
      ),
      $monitor->opts->get('verbose')
    );
    delete $h{$key};
  }
}
foreach my $key (@packagenames) {
  if (!grep { $key eq $_ } keys %h) {
    msg(
      sprintf(
        'Remembering update: %s',
        $key
      ),
      $monitor->opts->get('verbose')
    );
    $h{$key} = time();
  }
}

my @critical = grep { $h{$_} < time() - $monitor->opts->get('critical') * 86400 } keys %h;
my @warning = grep { $h{$_} < time() - $monitor->opts->get('warning') * 86400 } keys %h;

my $status = @warning ? @critical ? CRITICAL : WARNING : OK;

my $message = sprintf(
  "Pending updates: %d\n%s",
  $count->{$monitor->opts->get('oid')},
  join ",\n", sort map { sprintf("%s: %s", $_, scalar localtime $h{$_}) } keys %h
);

untie %h;

$monitor->nagios_exit($status, $message);
