#!/usr/bin/perl -w
# Copyright 2012 Michael Fladischer
# OpenServices e.U.
# office@openservices.at
#
# Monitor various aspects of Groupwise MTA, IA, WEBACC and POA.
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

use WWW::Mechanize;
use HTML::TreeBuilder::XPath;
use Switch;
use List::MoreUtils qw[first_index];
use Log::Message::Simple qw[:STD :CARP];

use Nagios::Plugin;
use Nagios::Plugin::Performance use_die => 1;

my $map = {
    'mta' => {
        'domains' => {main => {name => 'closed', index => 2}, extra => [{name => 'total', index => 1},], anchor => 'Domains'},
        'post-offices' => {main => {name => 'closed', index => 2}, extra => [{name => 'total', index => 1},], anchor => 'Post Offices'},
        'gateways' => {main => {name => 'closed', index => 2}, extra => [{name => 'total', index => 1},], anchor => 'Gateways'},
        'routed' => {main => {name => '10m', index => 2}, extra => [{name => 'total', index => 1},], anchor => 'Routed'},
        'undeliverable' => {main => {name => '10m', index => 2}, extra => [{name => 'total', index => 1},], anchor => 'Undeliverable'},
        'errors' => {main => {name => '10m', index => 2}, extra => [{name => 'total', index => 1},], anchor => 'Errors'},
    },
    'ia' => {
        'message-conversion-threads' => {main => {name => 'busy', index => 1}, extra => [{name => 'idle', index => 2},], anchor => 'Message Conversion Threads'},
        'smtp-threads' => {main => {name => 'busy', index => 1}, extra => [{name => 'idle', index => 2},], anchor => 'SMTP Threads'},
        'pop-threads' => {main => {name => 'busy', index => 1}, extra => [{name => 'idle', index => 2},], anchor => 'Standard POP Threads'},
        'pops-threads' => {main => {name => 'busy', index => 1}, extra => [{name => 'idle', index => 2},], anchor => 'Secure POP Threads'},
        'imap-threads' => {main => {name => 'busy', index => 1}, extra => [{name => 'idle', index => 2},], anchor => 'Standard IMAP Threads'},
        'imaps-threads' => {main => {name => 'busy', index => 1}, extra => [{name => 'idle', index => 2},], anchor => 'Secure IMAP Threads'},
        'ldap-threads' => {main => {name => 'busy', index => 1}, extra => [{name => 'idle', index => 2},], anchor => 'LDAP Threads'},
        'outbound-message-queues' => {main => {name => 'queued', index => 1}, anchor => 'Outbound Message Queues'},
        'inbound-message-queues' => {main => {name => 'queued', index => 1}, anchor => 'Inbound Message Queues'},
        'smtp-send-queue' => {main => {name => 'queued', index => 1}, anchor => 'SMTP Send Queue'},
        'smtp-receive-queue' => {main => {name => 'queued', index => 1}, anchor => 'SMTP Receive Queue'},
        'delayed-message-queue' => {main => {name => 'queued', index => 1}, anchor => 'Delayed Message Queue'},
        'message-normal-out' => {main => {name => '10m', index => 2}, extra => [{name => 'total', index => 1},], anchor => 'Normal'},
        'message-normal-in' => {main => {name => '10m', index => 4}, extra => [{name => 'total', index => 3},], anchor => 'Normal'},
        'message-status-out' => {main => {name => '10m', index => 2}, extra => [{name => 'total', index => 1},], anchor => 'Status'},
        'message-status-in' => {main => {name => '10m', index => 4}, extra => [{name => 'total', index => 3},], anchor => 'Status'},
        'message-passthrough-out' => {main => {name => '10m', index => 2}, extra => [{name => 'total', index => 1},], anchor => 'Passthrough'},
        'message-passthrough-in' => {main => {name => '10m', index => 4}, extra => [{name => 'total', index => 3},], anchor => 'Passthrough'},
        'message-conversion-errors-out' => {main => {name => '10m', index => 2}, extra => [{name => 'total', index => 1},], anchor => 'Conversion Errors'},
        'message-conversion-errors-in' => {main => {name => '10m', index => 4}, extra => [{name => 'total', index => 3},], anchor => 'Conversion Errors'},
        'message-communication-errors-out' => {main => {name => '10m', index => 2}, extra => [{name => 'total', index => 1},], anchor => 'Communication Errors'},
        'message-communication-errors-in' => {main => {name => '10m', index => 4}, extra => [{name => 'total', index => 3},], anchor => 'Communication Errors'},
        'total-bytes-out' => {main => {name => 'bytes', index => 1, conversion => \&traffic}, anchor => 'Total Bytes'},
        'total-bytes-in' => {main => {name => 'bytes', index => 2, conversion => \&traffic}, anchor => 'Total Bytes'},
    },
    'webacc' => {
        'client/server-users' => {main => {name => 'busy', index => 2}, extra => [{name => 'total', index => 1},], anchor => 'C/S Users'},
        'client/server-handler-threads' => {main => {name => 'busy', index => 2}, extra => [{name => 'total', index => 1},], anchor => 'C/S Handler Threads'},
        'client/server-requests' => {main => {name => 'requests', index => 1}, anchor => 'C/S Requests'},
        'client/server-requests-failed' => {main => {name => 'requests', index => 1}, anchor => 'C/S Requests Failed'},
    },
    'poa' => {
        'client/server-users' => {main => {name => 'users', index => 1}, anchor => 'C/S Users'},
        'remote/caching-users' => {main => {name => 'users', index => 1}, anchor => 'Remote/Caching Users Users'},
        'application-connections' => {main => {name => 'connections', index => 1}, anchor => 'Application Connections'},
        'physical-connections' => {main => {name => 'connections', index => 1}, anchor => 'Physical Connections'},
        'priority-queues' => {main => {name => 'queues', index => 1}, anchor => 'Priority Queues'},
        'normal-queues' => {main => {name => 'queues', index => 1}, anchor => 'Normal Queues'},
        'gwcheck-auto-queues' => {main => {name => 'queues', index => 1}, anchor => 'GWCheck Auto Queues'},
        'gwcheck-scheduled-queues' => {main => {name => 'queues', index => 1}, anchor => 'GWCheck Scheduled Queues'},
        'client/server-handler-threads' => {main => {name => 'busy', index => 2}, extra => [{name => 'total', index => 1},], anchor => 'C/S Handler Threads'},
        'message-worker-threads' => {main => {name => 'busy', index => 2}, extra => [{name => 'total', index => 1},], anchor => 'Message Worker Threads'},
        'gwcheck-worker-threads' => {main => {name => 'busy', index => 2}, extra => [{name => 'total', index => 1},], anchor => 'GWCheck Worker Threads'},
        'calendar-publishing-threads' => {main => {name => 'busy', index => 2}, extra => [{name => 'total', index => 1},], anchor => 'Calendar Publishing Threads'},
        'client/server-requests' => {main => {name => 'requests', index => 1}, anchor => 'C/S Requests'},
        'client/server-requests-pending' => {main => {name => 'requests', index => 2}, anchor => 'C/S Requests Pending'},
        'users-timed-out' => {main => {name => 'users', index => 1}, anchor => 'Users Timed Out'},
        'calendar-publishing-requests' => {main => {name => 'requests', index => 1}, anchor => 'Calendar Publishing Requests'},
        'rules-executed' => {main => {name => 'rules', index => 1}, anchor => ' Rules Executed'},
        'users-delivered' => {main => {name => 'users', index => 1}, anchor => 'Users Delivered'},
        'message-files-processed' => {main => {name => 'message-files', index => 1}, anchor => 'Message Files Processed'},
        'messages-undelivered' => {main => {name => 'messages', index => 1}, anchor => 'Messages Undelivered'},
        'problem-messages' => {main => {name => 'messages', index => 1}, anchor => 'Problem Messages'},
        'users-deleted' => {main => {name => 'users', index => 1}, anchor => 'Users Deleted'},
        'statuses-processed' => {main => {name => 'statuses', index => 1}, anchor => 'Statuses Processed'},
        'databases-recovered' => {main => {name => 'databases', index => 1}, anchor => 'Databases Recovered'},
        'gwcheck-messages-processed' => {main => {name => 'messages', index => 1}, anchor => 'GWCheck Messages Processed'},
        'gwcheck-problem-messages' => {main => {name => 'messages', index => 1}, anchor => 'GWCheck Problem Messages'},
        'caching-requests' => {main => {name => 'requests', index => 1}, anchor => 'Caching Requests'},
        'caching-primings' => {main => {name => 'primings', index => 1}, anchor => 'Caching Primings'},
        'rejected-caching-requests' => {main => {name => 'requests', index => 1}, anchor => 'Rejected Caching Requests'},
        'rejected-caching-primings' => {main => {name => 'primings', index => 1}, anchor => 'Rejected Caching Primings'},
        'mass-purge-jobs' => {main => {name => 'jobs', index => 1}, anchor => 'Number of Mass Purge Jobs'},
        'mass-purge-items' => {main => {name => 'items', index => 1}, anchor => 'Number of Items under Mass Purge'},
    },
};

my $nagios = Nagios::Plugin->new(  
    shortname => "Groupwise-8",
    version => "0.1",
    url => "http://openservices.at/services/infrastructure-monitoring/groupwise-8",
    usage => "Usage: %s ".
        "[-v|--verbose] ".
        "[-t <timeout>] ".
        "-H <host> ".
        "-l <login> ".
        "-p <password> ".
        "-o <port> ".
        "-a <agent> ".
        "-f <field> ".
        "-w <threshold> ".
        "-c <threshold> ",
    blurb => list(),
);

sub list {
    my $output = "Agents and associated fields:\n";
    foreach my $agent (keys %{$map}) {
        $output .= " - ".uc($agent)."\n";
        foreach my $field (keys %{$map->{$agent}}) {
            $output .= "   + ".$field." (".$map->{$agent}->{$field}->{anchor}.")\n";
        }
    }
    return $output;
}

# add valid command line options and build them into your usage/help documentation.
$nagios->add_arg(
    spec => 'host|H=s',
    help => "-H, --host=STRING\n".
        "   The host to connect to.",
    required => 1,
);
$nagios->add_arg(
    spec => 'warning|w=i',
    help => "-w, --warning=INTEGER:INTEGER\n".
        "   See http://nagiosplug.sourceforge.net/developer-guidelines.html#THRESHOLDFORMAT for the threshold format.",
    required => 1,
);
$nagios->add_arg(
    spec => 'critical|c=i',
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
        "   Port used by the HTTP server.",
    required => 0,
    default => 80,
);
$nagios->add_arg(
    spec => 'agent|a=s',
    help => "-a, --agent=(mta|ia|webacc|poa)\n".
        "   Type of agent to check (mta|ia|webacc|poa)\n".
        "   See above for a complete listing of possible values!",
    required => 1,
);
$nagios->add_arg(
    spec => 'field|f=s',
    help => "-f, --field=STRING\n".
        "   Field to fetch from status information page\n".
        "   See above for a complete listing of possible values!",
    required => 1,
);
$nagios->add_arg(
    spec => 'debug|d',
    help => "-d, --debug\n".
        "   Print debug information",
    required => 0,
    default => 0,
);

# Parse @ARGV and process arguments.
$nagios->getopts;

msg("Checking presence of requested agent->field mapping", $nagios->opts->get('verbose'));
$nagios->nagios_exit(UNKNOWN, "Unknown agent type: ".$nagios->opts->get('agent')) if !exists $map->{lc($nagios->opts->get('agent'))};
$nagios->nagios_exit(UNKNOWN, "Unknown field for agent ".$nagios->opts->get('agent').": ".$nagios->opts->get('field')) if !exists $map->{lc($nagios->opts->get('agent'))}->{lc($nagios->opts->get('field'))};

my $field = $map->{lc($nagios->opts->get('agent'))}->{lc($nagios->opts->get('field'))};

my $url = sprintf("http://%s:%i/", $nagios->opts->get('host'), $nagios->opts->get('port'));
my $host = $nagios->opts->get('host');

my $m = WWW::Mechanize->new(
    cookie_jar => {},
    ssl_opts => {SSL_version => 'SSLv3'}, # Oracle decided to mess with Apache mod_ssl up to a point where it breaks :-(
    autocheck => 0,
);

# Register debug handlers
$m->add_handler("request_send", sub { debug(shift->dump, $nagios->opts->get('debug')); return });
$m->add_handler("response_done", sub { debug(shift->dump, $nagios->opts->get('debug')); return });

# Set credentials for HTTP basic auth
$m->credentials($nagios->opts->{login}, $nagios->opts->get('password'));

msg("Fetching ".$url, $nagios->opts->get('verbose'));
$m->get($url);
check_response($nagios, $m);
my $tree = HTML::TreeBuilder::XPath->new;
$tree->parse_content($m->content);
my @lines = $tree->findvalues('//td[translate(@align,"ABCDEFGHIJKLMNOPQRSTUVWXYZ","abcdefghijklmnopqrstuvwxyz")="center"]/..//font[@size="-1"]');

msg("Extracting primary value: Anchor=>'".$field->{anchor}."', Index=>".$field->{main}->{index}, $nagios->opts->get('verbose'));
my $value = get_field($field->{anchor}, $field->{main}->{index}, @lines);
$nagios->nagios_exit(UNKNOWN, uc($nagios->opts->{agent})." provides no information on field: ".lc($nagios->opts->get('field'))) if $value < 0;

# Threshold check.
my $code = $nagios->check_threshold(
    check => $value,
);

# Perfdata
$nagios->add_perfdata( 
    label => $field->{main}->{name},
    value => $value,
    threshold => $nagios->threshold,
);

if (exists $field->{extra}) {
    foreach (@{$field->{extra}}) {
        $nagios->add_perfdata( 
            label => $_->{name},
            value => get_field($field->{anchor}, $_->{index}, @lines),
        );
    }
}

# Exit if WARNING or CRITICAL.
$nagios->nagios_exit($code, uc($nagios->opts->{agent})." aspect '".$nagios->opts->{field}."' is out of bounds with ".$value) if $code != OK;
# Exit OK.
$nagios->nagios_exit(OK, uc($nagios->opts->{agent})." acpect '".$nagios->opts->{field}."' is within bounds");

sub check_response {
    my ($nagios, $m) = @_;
    if (!$m->success()) {
        $nagios->nagios_exit(UNKNOWN, "Could not fetch ".$m->uri().": ".$m->status());
    }
}

sub get_field {
    my ($anchor, $index, @lines) = @_;
    my $start = first_index { $_ eq $anchor } @lines;
    if ($start < 0) {
        return -1;
    }
    return $lines[$start + $index];
}
