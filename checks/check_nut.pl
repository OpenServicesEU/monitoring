#!/usr/bin/perl -w
# Copyright 2013 Michael Fladischer
# OpenServices e.U.
# office@openservices.at
#
# Monitor UPS connected through NUT.
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
use lib "/usr/local/nagios/libexec/";

use UPS::Nut;
use Log::Message::Simple qw[:STD :CARP];

use Monitoring::Plugin;
use Monitoring::Plugin::Performance use_die => 1;

my $monitor = Monitoring::Plugin->new(
    shortname => "NUT",
    version => "0.2",
    url => "http://openservices.at/services/infrastructure-monitoring/nut",
    usage => "Usage: %s ".
        "[-v|--verbose] ".
        "[-t <timeout>] ".
        "-H <host> ".
        "-l <login> ".
        "-p <password> ".
        "-o <port> ".
        "-u <ups> ".
        "-q <query> ".
        "[-n <context>] ".
        "[-w <threshold>] ".
        "[-c <threshold>] ",
);

# add valid command line options and build them into your usage/help documentation.
$monitor->add_arg(
    spec => 'host|H=s',
    help => "-H, --host=STRING\n".
        "   The host to connect to.",
    required => 1,
);
$monitor->add_arg(
    spec => 'warning|w=s',
    help => "-w, --warning=INTEGER:INTEGER\n".
        "   See http://nagiosplug.sourceforge.net/developer-guidelines.html#THRESHOLDFORMAT for the threshold format.",
    required => 1,
);
$monitor->add_arg(
    spec => 'critical|c=s',
    help => "-c, --critical=INTEGER:INTEGER\n".
        "   See http://nagiosplug.sourceforge.net/developer-guidelines.html#THRESHOLDFORMAT for the threshold format.",
    required => 1,
);
$monitor->add_arg(
    spec => 'login|l=s',
    help => "-l, --login=STRING\n".
        "   Username to login.",
    required => 1,
);
$monitor->add_arg(
    spec => 'password|p=s',
    help => "-p, --password=STRING\n".
        "   Password used for authentication.",
    required => 1,
);
$monitor->add_arg(
    spec => 'port|o=i',
    help => "-o, --port=INTEGER\n".
        "   Port used by the remote NUT server.",
    required => 0,
    default => 3493,
);
$monitor->add_arg(
    spec => 'ups|u=s',
    help => "-u, --ups=STRING\n".
        "   Name of remote UPS.",
    required => 1,
);
$monitor->add_arg(
    spec => 'query|q=s',
    help => "-q, --query=(state|battery|load|voltage|temperature)\n".
        "   Type of information to query from NUT.",
    required => 1,
);
$monitor->add_arg(
    spec => 'context|n=s',
    help => "-n, --context=STRING\n".
        "   Optional context for query type (e.g. 1,2 or 3 for load/voltage).",
    required => 0,
    default => 1,
);

# Parse @ARGV and process arguments.
$monitor->getopts;

msg("Connecting to NUT on ".$monitor->opts->get("host").":".$monitor->opts->get("port")." with user ".$monitor->opts->get("login"), $monitor->opts->get('verbose'));
my $ups = new UPS::Nut(
    NAME => $monitor->opts->get("ups"),
    HOST => $monitor->opts->get("host"),
    PORT => $monitor->opts->get("port"),
    USERNAME => $monitor->opts->get("login"),
    PASSWORD => $monitor->opts->get("password"),
    TIMEOUT => $monitor->opts->get("timeout"),
);

my %querymap = (
    "state" => sub {
        my ($ups, $monitor) = @_;
        if ($ups->Status() =~ /FSD/) {
            $monitor->nagios_exit(CRITICAL, "UPS ".$monitor->opts->get("ups")." is in Forced Shutdown (FSD) state.");
        } elsif ($ups->Status() =~ /OB/) {
            $monitor->nagios_exit(CRITICAL, "UPS ".$monitor->opts->get("ups")." is running on battery.");
        } else {
            $monitor->nagios_exit(OK, "UPS ".$monitor->opts->get("ups")." is doing fine.");
        }
    },
    "battery" => sub {
        my ($ups, $monitor) = @_;
        my $code = $monitor->check_threshold(
            check => $ups->BattPercent(),
        );
        $monitor->add_perfdata(
            label => "Battery",
            value => $ups->BattPercent(),
            threshold => $monitor->threshold,
            uom => "%",
        );
        $monitor->nagios_exit($code, "UPS ".$monitor->opts->get("ups")." is running low on battery (".$ups->BattPercent()."%).") if $code != OK;
        # Exit OK.
        $monitor->nagios_exit(OK, "UPS ".$monitor->opts->get("ups")." is charged (".$ups->BattPercent()."%).");
    },
    "load" => sub {
        my ($ups, $monitor) = @_;
        my $code = $monitor->check_threshold(
            check => $ups->LoadPercent($monitor->opts->get("context")),
        );
        $monitor->add_perfdata(
            label => "Load",
            value => $ups->LoadPercent($monitor->opts->get("context")),
            threshold => $monitor->threshold,
            uom => "%",
        );
        $monitor->nagios_exit($code, "UPS ".$monitor->opts->get("ups")." is on high load (".$ups->LoadPercent($monitor->opts->get("context"))."%).") if $code != OK;
        # Exit OK.
        $monitor->nagios_exit(OK, "UPS ".$monitor->opts->get("ups")." is on normal load (".$ups->LoadPercent($monitor->opts->get("context"))."%).");
    },
    "voltage" => sub {
        my ($ups, $monitor) = @_;
        my $code = $monitor->check_threshold(
            check => $ups->LineVoltage($monitor->opts->get("context")),
        );
        $monitor->add_perfdata(
            label => "Voltage",
            value => $ups->LineVoltage($monitor->opts->get("context")),
            threshold => $monitor->threshold,
            uom => "V",
        );
        $monitor->nagios_exit($code, "UPS ".$monitor->opts->get("ups")." is on out-of-bounds line voltage (".$ups->LineVoltage($monitor->opts->get("context"))."V).") if $code != OK;
        # Exit OK.
        $monitor->nagios_exit(OK, "UPS ".$monitor->opts->get("ups")." is on normal line voltage (".$ups->LineVoltage($monitor->opts->get("context"))."V).");
    },
    "temperature" => sub {
        my ($ups, $monitor) = @_;
        my $code = $monitor->check_threshold(
            check => $ups->Temperature(),
        );
        $monitor->add_perfdata(
            label => "Temperature",
            value => $ups->Temperature(),
            threshold => $monitor->threshold,
            uom => "DegC",
        );
        $monitor->nagios_exit($code, "UPS ".$monitor->opts->get("ups")." is on out-of-bounds temperature (".$ups->Temperature()."DegC).") if $code != OK;
        # Exit OK.
        $monitor->nagios_exit(OK, "UPS ".$monitor->opts->get("ups")." is on normal temperature (".$ups->Temperature()."DegC).");
    }
);

if (exists $querymap{$monitor->opts->get("query")}) {
    $querymap{$monitor->opts->get("query")}($ups, $monitor);
} else {
    $monitor->nagios_exit(UNKNOWN, "Unknown query type: ".$monitor->opts->get("query"));
}
