#!/usr/bin/perl -w
# Copyright 2013 Michael Fladischer
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
use lib "/usr/local/nagios/libexec/";

use version;
use Thread::Pool::Simple;
use LWP;
use HTML::TreeBuilder::XPath;
use Time::HiRes qw(gettimeofday tv_interval);
use Log::Message::Simple qw[:STD :CARP];

use Nagios::Plugin;
use Nagios::Plugin::Performance use_die => 1;

my $nagios = Nagios::Plugin->new(
    shortname => "TYPO3",
    version => "0.1",
    url => "http://openservices.at/services/infrastructure-monitoring/typo3",
    usage => "Usage: %s ".
        "[-v|--verbose] ".
        "[-t <timeout>] ".
        "-H <host> ".
        "[-u <uri>] ".
        "[-l <login>] ".
        "[-p <password>] ".
        "[-I <ip>] ".
        "[-i <extension>] ".
        "[--update-action=<update-action>] ".
        "[--conflict-action=<conflict-action>] ".
        "[--deprecationlog-action=<deprecation-action>] ".
        "[-T <threads>] ".
        "[-w <threshold>] ".
        "[-c <threshold>] ",
);

# add valid command line options and build them into your usage/help documentation.
$nagios->add_arg(
    spec => 'host|H=s',
    help => "-H, --host=STRING\n".
        "The host to connect to.",
    required => 1,
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
    spec => 'login|l=s',
    help => "-l, --login=STRING\n".
        "Username to login.",
    required => 0,
    default => "",
);
$nagios->add_arg(
    spec => 'password|p=s',
    help => "-p, --password=STRING\n".
        "   Password used for authentication.",
    required => 0,
    default => "",
);
$nagios->add_arg(
    spec => 'uri|u=i',
    help => "-u, --uri=STRING\n".
        "URI of TYPO3 server's Nagios extension output (default: /index.php?eID=nagios).",
    required => 0,
    default => "/index.php?eID=nagios",
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
        "IPv4 address of the TYPO3 server. If this argument is used, the hostname (argument -H or --hostname) is sent as \"Host:\" in the HTTP header of the request.",
    required => 0,
);
$nagios->add_arg(
    spec => 'ignore|i=s@',
    help => "-i, --ignore=STRING\n".
        "Names of TYPO3 extensions that should be ignored. Can be used multiple times to ignore more than one extension.",
    required => 0,
);
$nagios->add_arg(
    spec => 'conflict-action=s',
    help => "--conflict-action=(ignore|warning|critical)\n".
        "   One of the following actions, if a conflict with an extension has been detected (default: warning):\n".
        "       \"ignore\"    do nothing, ignore conflict\n".
        "       \"warning\"   generate a warning condition in Nagios\n".
        "       \"critical\"  generate a critical condition in Nagios",
    required => 0,
    default => "warning",
);
$nagios->add_arg(
    spec => 'update-action=s',
    help => "--update-action=(ignore|warning|critical)\n".
        "   One of the following actions, if an update for an extension has been detected (default: warning):\n".
        "       \"ignore\"    do nothing, ignore available updates\n".
        "       \"warning\"   generate a warning condition in Nagios\n".
        "       \"critical\"  generate a critical condition in Nagios",
    required => 0,
    default => "warning",
);
$nagios->add_arg(
    spec => 'deprecationlog-action=s',
    help => "--deprecationlog-action=(ignore|warning|critical)\n".
        "   One of the following actions, if an enabled deprecation log has been detected (default: warning):\n".
        "       \"ignore\"    do nothing, ignore enabled deprecation logs\n".
        "       \"warning\"   generate a warning condition in Nagios\n".
        "       \"critical\"  generate a critical condition in Nagios",
    required => 0,
    default => "warning",
);
$nagios->add_arg(
    spec => 'threads|T=i',
    help => "-T, --threads=INTEGER\n".
        "The number of threads to use for gathering version information from typo3.org (default: 4).",
    required => 0,
    default => 4,
);

# Map strings from arguments to Nagios Plugin codes.
my %codemap = (
    "ignore" => undef,
    "warning" => WARNING,
    "critical" => CRITICAL,
);

# Parse @ARGV and process arguments.
$nagios->getopts;

# Construct URL to TYPO3 nagios extension page.
my $url = sprintf("http%s://%s%s",
    $nagios->opts->get("ssl") ? "s" : "",
    ($nagios->opts->get("ip") or $nagios->opts->get("host")),
    $nagios->opts->get("uri")
);

msg(
    sprintf(
        "Connecting to TYPO3 on %s with user %s",
        $url,
        $nagios->opts->get("login")
    ),
    $nagios->opts->get('verbose')
);

# Instantiate new LWP user agent for TYPO3 nagios extension page.
my $ua = LWP::UserAgent->new;
$ua->default_header("Host" => $nagios->opts->get("host"));
$ua->timeout($nagios->opts->get("timeout"));
$ua->cookie_jar({});

if ($nagios->opts->get("login") and $nagios->opts->get("password")) {
    msg(
        sprintf(
            "Setting credentials for realm \"TYPO3 Nagios\": %s",
            $nagios->opts->get("login")
        ),
        $nagios->opts->get('verbose')
    );
    $ua->credentials(
        sprintf(
            "%s:%i",
            $nagios->opts->get("host"),
            $nagios->opts->get("ssl") ? 443 : 80
        ),
        "TYPO3 Nagios",
        $nagios->opts->get("login"),
        $nagios->opts->get("password")
    );
}

# Retrieve TYPO3 nagios extension page and meassure required time.
my $timer = [gettimeofday];
my $response = $ua->get($url);
my $elapsed = tv_interval($timer) * 1000;

# Perfdata
$nagios->add_perfdata(
    label => "Latency",
    value => $elapsed,
    threshold => $nagios->threshold,
    uom => 'ms',
);

# See if we got a valid response from the TYPO3 nagios extension.
if ($response->code != 200) {
    $nagios->nagios_exit(
        CRITICAL,
        sprintf(
            "TYPO3 returned an HTTP error: %i",
            $response->code
        )
    );
}

# Hash that will hold the paresd response data.
my %data;

# Parse response content and populate data hash.
foreach (grep { !/^#|^$/ } split /\n/, $response->content) {
    my @matches = $_ =~ /^(\w+):(.*?)((-version)?-(([\d\.]+)(-dev|-([\d\.]+))?))?$/g;

    # Ignore extensions from arguments.
    next if (grep { /$matches[1]/ } @{$nagios->opts->get("ignore") || []});

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
$nagios->add_perfdata(
    label => "Database tables",
    value => $data{DBTABLES},
);

# Check for latest version of installed extensions from typo3.org.
sub update {
    my ($extension) = @_;

    # Instantiate new LWP user agent for typo3.org to avoid leaking credentials.
    $ua = LWP::UserAgent->new;
    $ua->timeout($nagios->opts->get("timeout"));
    $ua->cookie_jar( {} );
    msg(
        sprintf(
            "Checking for latest version of %s on TYPO3.org",
            $extension
        ),
        $nagios->opts->get('verbose')
    );
    my $url = sprintf("http://typo3.org/extensions/repository/view/%s", $extension);
    my $response = $ua->get($url);
    if ($response->code != 200) {
        error(
            sprintf(
                "Could not fetch version information from %s: %i",
                $url,
                $response->code
            )
        );
        next;
    }

    my $tree = HTML::TreeBuilder::XPath->new;
    $tree->utf8_mode(1);
    $tree->parse($response->content);
    $tree->eof();
    my $key = $tree->findvalue('//tr/th[text()="Extension key"]/../td/strong/text()');
    if ($key ne $extension) {
        error(
            sprintf(
                "Could not fetch remote version information for %s from %s",
                $extension,
                $url
            )
        );
        return undef;
    }
    my $new = $tree->findvalue('//div[@class="download-button"]/a/text()');
    $new =~ s/^Download version //;
    msg(
        sprintf(
            "Version of %s found on typo3.org: %s",
            $extension,
            $new
        ),
        $nagios->opts->get('verbose')
    );
    return version->parse($new);
}

# Instantiate a thread pool which will look up version information on typo.org.
msg(
    sprintf(
        "Starting thread pool with %i threads...",
        $nagios->opts->get('threads')
    ),
    $nagios->opts->get('verbose')
);
my $pool = Thread::Pool::Simple->new(
    do => [\&update],
    min => $nagios->opts->get('threads')
);

# Queue jobs to thread pool by passing the extension key.
# Job IDs are stored for later retrieval of the results.
my %jobs = map { $_ => $pool->add(($_)) } keys %{$data{EXT}};

# Wait for thread pool to run out of jobs.
msg("Waiting for thread pool to finish...", $nagios->opts->get('verbose'));
$pool->join();

# Retrieve results from thread pool.
my %results = map { $_ => $pool->remove($jobs{$_}) } keys %jobs;

# Filter all updates.
my @updates = grep { $results{$_} > $data{EXT}->{$_} } grep { defined $results{$_} } keys %results;

# Perfdata
$nagios->add_perfdata(
    label => "Updates pending",
    value => scalar @updates,
);

# Filter all conflicts.
my @conflicts = grep { $data{TYPO3} < $data{EXTDEPTYPO3}->{$_}->{from} or $data{TYPO3} > $data{EXTDEPTYPO3}->{$_}->{to} } grep { $data{EXTDEPTYPO3}->{$_}->{to} > 0 } keys %{$data{EXTDEPTYPO3}};

# Perfdata
$nagios->add_perfdata(
    label => "Version conflicts",
    value => scalar @conflicts,
);

# First status derived from the time elapsed during the initial request.
my $code = $nagios->check_threshold(check => $elapsed);
my $message = sprintf("Request finished in %ims", $elapsed);

# Check for deprecation log.
if (defined $codemap{$nagios->opts->get('deprecationlog-action')} and $data{DEPRECATIONLOG} eq "enabled") {
    if ($codemap{$nagios->opts->get('deprecationlog-action')} > $code) {
        $code = $codemap{$nagios->opts->get('deprecationlog-action')};
    }
    $message .= "; Deprecation log enabled!";
}

# Process conflicts.
if (defined $codemap{$nagios->opts->get('conflict-action')} and scalar @conflicts > 0) {
    if ($codemap{$nagios->opts->get('conflict-action')} > $code) {
        $code = $codemap{$nagios->opts->get('conflict-action')};
    }
    $message .= sprintf("; TYPO3 %s conflicts: %s", $data{TYPO3}, join(", ", map { sprintf ("%s[%s-%s]", $_, $data{EXTDEPTYPO3}->{$_}->{from}, $data{EXTDEPTYPO3}->{$_}->{to}) } @conflicts));
}

# Process updates.
if (defined $codemap{$nagios->opts->get('update-action')} and scalar @updates > 0) {
    if ($codemap{$nagios->opts->get('update-action')} > $code) {
        $code = $codemap{$nagios->opts->get('update-action')};
    }
    $message .= sprintf("; Updates available: %s", join(", ", map { sprintf ("%s[%s->%s]", $_, $data{EXT}->{$_}, $results{$_}) } @updates));
}

# Exit with final status and message.
$nagios->nagios_exit($code, $message);
