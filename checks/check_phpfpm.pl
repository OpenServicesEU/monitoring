#!/usr/bin/perl -w
# Copyright 2015 Michael Fladischer
# OpenServices e.U.
# office@openservices.at
#
# Monitor PHP FPM instances.
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

use version;
use URI;
use LWP::UserAgent;
use File::Slurp;
use XML::LibXML;
use Time::HiRes qw(gettimeofday tv_interval);
use Compress::Zlib;
use Digest::MD5;
use Log::Message::Simple qw[:STD :CARP];

use Nagios::Plugin;
use Nagios::Plugin::Performance use_die => 1;

my $nagios = Nagios::Plugin->new(
    shortname => "PHP-FPM",
    version => "0.1",
    url => "http://openservices.at/services/infrastructure-monitoring/php-fpm",
    usage => "Usage: %s ".
        "[-v|--verbose] ".
        "[-t <timeout>] ".
        "-H <host> ".
        "--path=<path> ".
        "-w <threshold> ".
        "-c <threshold> ".
        "-m (ping|queue|processes) ".
        "[-P <port>] ".
        "[-L <login>] ".
        "[-p <password>] ".
        "[-r <realm>] ".
        "[-s|--ssl] ".
        "[-I <ip>] ",
);

# add valid command line options and build them into your usage/help documentation.
$nagios->add_arg(
    spec => 'host|H=s',
    help => "-H, --host=STRING\n".
        "The host to connect to.",
    required => 1,
);
$nagios->add_arg(
    spec => 'port|P=i',
    help => "-P, --port=INTEGER\n".
        "The port to connect to.",
    required => 0,
);
$nagios->add_arg(
    spec => 'warning|w=s',
    help => "-w, --warning=INTEGER:INTEGER\n".
        "See http://nagiosplug.sourceforge.net/developer-guidelines.html#THRESHOLDFORMAT for the threshold format.",
    required => 1,
);
$nagios->add_arg(
    spec => 'critical|c=s',
    help => "-c, --critical=INTEGER:INTEGER\n".
        "See http://nagiosplug.sourceforge.net/developer-guidelines.html#THRESHOLDFORMAT for the threshold format.",
    required => 1,
);
$nagios->add_arg(
    spec => 'login|L=s',
    help => "-L, --login=STRING\n".
        "Username to login.",
    required => 0,
);
$nagios->add_arg(
    spec => 'password|p=s',
    help => "-p, --password=STRING\n".
        "   Password used for authentication.",
    required => 0,
);
$nagios->add_arg(
    spec => 'realm|r=s',
    help => "-r, --realm=STRING\n".
        "   Realm used for authentication.",
    required => 0,
    default => '',
);
$nagios->add_arg(
    spec => 'path=s',
    help => "--path=STRING\n".
        "Path to PHP-FPM's ping/status page.",
    required => 1,
);
$nagios->add_arg(
    spec => 'ssl|s',
    help => "-s, --ssl\n".
        "Use SSL (HTTPS) when connecting to TYPO3.",
    required => 0,
    default => 0,
);
$nagios->add_arg(
    spec => 'ip|I=s',
    help => "-I, --ip=STRING\n".
        "IPv4/6 address of the PHP-FPM instance. If this argument is used, the hostname (argument -H or --hostname) is sent as \"Host:\" in the HTTP header of the request.",
    required => 0,
);
$nagios->add_arg(
    spec => 'mode|m=s',
    help => "--mode=(ping|queue|processes)\n".
        "   One of the following modes are available:\n".
        "       \"ping\"       check if php-fpm ansers on its ping page\n".
        "       \"queue\"      check the maximum recorded number of requests waiting in the queue\n".
        "       \"processes\"  check the maximum recorded number of active processes",
    required => 1,
);

# Parse @ARGV and process arguments.
$nagios->getopts;


my $uri = URI->new("http://");
$uri->host($nagios->opts->get('host'));
$uri->path($nagios->opts->get('path'));
if ($nagios->opts->get('ssl')) {
  $uri->scheme('https');
}
if ($nagios->opts->get('port')) {
  $uri->port($nagios->opts->get('port'));
}

sub get_remote {
    my ($uri) =  @_;
    my $ua = LWP::UserAgent->new;
    if ($nagios->opts->get('login') && $nagios->opts->get('password')) {
        $ua->credentials(
          $uri->authority,
          $nagios->opts->get('realm'),
          $nagios->opts->get('login'),
          $nagios->opts->get('password')
        );
    }
    my $response = $ua->get($uri->as_string);
    if ($response->code == 200) {
        return $response->content;
    } else {
        $nagios->nagios_exit(
            UNKNOWN,
            sprintf(
                'Could not fetch %s',
                $uri->as_string
            )
        );
    }
}
sub get_remote_xpath {
    return XML::LibXML->load_xml(string => get_remote(@_));
}

my %codemap = (
    'ping' => sub {
        my $timer = [gettimeofday];
        my $content = get_remote($uri);
        my $elapsed = tv_interval($timer) * 1000;
        if ($content eq "pong") {
            $nagios->add_perfdata(
                label => "Latency",
                value => $elapsed,
                threshold => $nagios->threshold,
                uom => 'ms',
            );
            $nagios->nagios_exit(
                OK,
                sprintf(
                    'Received PING response in %d milliseconds',
                    $elapsed
                )
            );
        }
        $nagios->nagios_exit(
            CRITICAL,
            'Invalid response to PING request'
        );
    },
    'queue' => sub {
        $uri->query('xml');
        my $status = get_remote_xpath($uri);
        my $pool = $status->findvalue('/status/pool');
        my $pending = $status->findvalue('/status/listen-queue');
        my $maximum = $status->findvalue('/status/max-listen-queue');
        $nagios->add_perfdata(
            label => 'Pending',
            value => $pending,
            uom => 'requests',
        );
        $nagios->add_perfdata(
            label => 'Maximum',
            value => $maximum,
            threshold => $nagios->threshold,
            uom => 'requests',
        );
        my $code = $nagios->check_threshold($maximum);
        $nagios->nagios_exit(
            $code,
            sprintf(
                '%s: maximum requests in queue: %d',
                $pool,
                $maximum
            )
        );
    },
    'processes' => sub {
        $uri->query('xml');
        my $status = get_remote_xpath($uri);
        my $pool = $status->findvalue('/status/pool');
        my $active = $status->findvalue('/status/active-processes');
        my $maximum = $status->findvalue('/status/max-active-processes');
        $nagios->add_perfdata(
            label => 'Active',
            value => $active,
            uom => 'processes',
        );
        $nagios->add_perfdata(
            label => 'Maximum',
            value => $maximum,
            threshold => $nagios->threshold,
            uom => 'processes',
        );
        my $code = $nagios->check_threshold($maximum);
        $nagios->nagios_exit(
            $code,
            sprintf(
                '%s: maximum active processes: %d',
                $pool,
                $maximum
            )
        );
    },
);

$codemap{$nagios->opts->get('mode')}();
