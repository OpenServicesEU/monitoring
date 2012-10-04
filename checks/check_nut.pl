#!/usr/bin/perl -w
# Copyright 2012 Michael Fladischer
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
use Switch;
use Log::Message::Simple qw[:STD :CARP];
use Data::Dumper;

use Nagios::Plugin;
use Nagios::Plugin::Performance use_die => 1;

my $nagios = Nagios::Plugin->new(  
    shortname => "NUT",
    version => "0.1",
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
$nagios->add_arg(
    spec => 'host|H=s',
    help => "-H, --host=STRING\n".
        "   The host to connect to.",
    required => 1,
);
$nagios->add_arg(
    spec => 'warning|w=s',
    help => "-w, --warning=INTEGER:INTEGER\n".
        "   See http://nagiosplug.sourceforge.net/developer-guidelines.html#THRESHOLDFORMAT for the threshold format.",
    required => 1,
);
$nagios->add_arg(
    spec => 'critical|c=s',
    help => "-c, --critical=INTEGER:INTEGER\n".
        "   See http://nagiosplug.sourceforge.net/developer-guidelines.html#THRESHOLDFORMAT for the threshold format.",
    required => 1,
);
$nagios->add_arg(
    spec => 'login|l=s',
    help => "-l, --login=STRING\n".
        "   Username to login.",
    required => 1,
);
$nagios->add_arg(
    spec => 'password|p=s',
    help => "-p, --password=STRING\n".
        "   Password used for authentication.",
    required => 1,
);
$nagios->add_arg(
    spec => 'port|o=i',
    help => "-o, --port=INTEGER\n".
        "   Port used by the remote NUT server.",
    required => 0,
    default => 3493,
);
$nagios->add_arg(
    spec => 'ups|u=s',
    help => "-u, --ups=STRING\n".
        "   Name of remote UPS.",
    required => 1,
);
$nagios->add_arg(
    spec => 'query|q=s',
    help => "-q, --query=(state|battery|load|voltage|temperature)\n".
        "   Type of information to query from NUT.",
    required => 1,
);
$nagios->add_arg(
    spec => 'context|n=s',
    help => "-n, --context=STRING\n".
        "   Optional context for query type (e.g. 1,2 or 3 for load/voltage).",
    required => 0,
    default => 1,
);

# Parse @ARGV and process arguments.
$nagios->getopts;

msg("Connecting to NUT on ".$nagios->opts->get("host").":".$nagios->opts->get("port")." with user ".$nagios->opts->get("login"), $nagios->opts->get('verbose'));
my $ups = new UPS::Nut(
	NAME => $nagios->opts->get("ups"),
	HOST => $nagios->opts->get("host"),
	PORT => $nagios->opts->get("port"),
	USERNAME => $nagios->opts->get("login"),
	PASSWORD => $nagios->opts->get("password"),
	TIMEOUT => $nagios->opts->get("timeout"),
);

switch ($nagios->opts->get("query")) {
    case "state" {
        if ($ups->Status() =~ /FSD/) {
            $nagios->nagios_exit(CRITICAL, "UPS ".$nagios->opts->get("ups")." is in Forced Shutdown (FSD) state.");
        } elsif ($ups->Status() =~ /OB/) {
            $nagios->nagios_exit(CRITICAL, "UPS ".$nagios->opts->get("ups")." is running on battery.");
        } else {
            $nagios->nagios_exit(OK, "UPS ".$nagios->opts->get("ups")." is doing fine.");
        }
    }
    case "battery" {
        my $code = $nagios->check_threshold(
            check => $ups->BattPercent(),
        );
        $nagios->add_perfdata( 
            label => "Battery",
            value => $ups->BattPercent(),
            threshold => $nagios->threshold,
            uom => "%",
        );
        $nagios->nagios_exit($code, "UPS ".$nagios->opts->get("ups")." is running low on battery (".$ups->BattPercent()."%).") if $code != OK;
        # Exit OK.
        $nagios->nagios_exit(OK, "UPS ".$nagios->opts->get("ups")." is charged (".$ups->BattPercent()."%).");
    }
    case "load" {
        my $code = $nagios->check_threshold(
            check => $ups->LoadPercent($nagios->opts->get("context")),
        );
        $nagios->add_perfdata( 
            label => "Load",
            value => $ups->LoadPercent($nagios->opts->get("context")),
            threshold => $nagios->threshold,
            uom => "%",
        );
        $nagios->nagios_exit($code, "UPS ".$nagios->opts->get("ups")." is on high load (".$ups->LoadPercent($nagios->opts->get("context"))."%).") if $code != OK;
        # Exit OK.
        $nagios->nagios_exit(OK, "UPS ".$nagios->opts->get("ups")." is on normal load (".$ups->LoadPercent($nagios->opts->get("context"))."%).");
    }
    case "voltage" {
        my $code = $nagios->check_threshold(
            check => $ups->LineVoltage($nagios->opts->get("context")),
        );
        $nagios->add_perfdata( 
            label => "Voltage",
            value => $ups->LineVoltage($nagios->opts->get("context")),
            threshold => $nagios->threshold,
            uom => "V",
        );
        $nagios->nagios_exit($code, "UPS ".$nagios->opts->get("ups")." is on out-of-bounds line voltage (".$ups->LineVoltage($nagios->opts->get("context"))."V).") if $code != OK;
        # Exit OK.
        $nagios->nagios_exit(OK, "UPS ".$nagios->opts->get("ups")." is on normal line voltage (".$ups->LineVoltage($nagios->opts->get("context"))."V).");
    }
    case "temperature" {
        my $code = $nagios->check_threshold(
            check => $ups->Temperature(),
        );
        $nagios->add_perfdata( 
            label => "Temperature",
            value => $ups->Temperature(),
            threshold => $nagios->threshold,
            uom => "DegC",
        );
        $nagios->nagios_exit($code, "UPS ".$nagios->opts->get("ups")." is on out-of-bounds temperature (".$ups->Temperature()."DegC).") if $code != OK;
        # Exit OK.
        $nagios->nagios_exit(OK, "UPS ".$nagios->opts->get("ups")." is on normal temperature (".$ups->Temperature()."DegC).");
    }
    else {
        $nagios->nagios_exit(UNKNOWN, "Unknown query type: ".$nagios->opts->get("query"));
    }
}
