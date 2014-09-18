#!/usr/bin/perl -w
# Copyright 2014 Michael Fladischer
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
        "[-C <cachepath>] ".
        "[-M <mirror>] ".
        "[--update-action=<update-action>] ".
        "[--conflict-action=<conflict-action>] ".
        "[--deprecationlog-action=<deprecation-action>] ".
        "[-w <threshold>] ".
        "[-c <threshold>] ",
);

# add valid command line options and build them into your usage/help documentation.
$nagios->add_arg(
    spec => 'cache|C=s',
    help => "-C, --cache=STRING\n".
        "Path where the downloaded mirrors and extensions XML files can be stored.",
    required => 0,
    default => 0,
);
$nagios->add_arg(
    spec => 'mirror|M=s',
    help => "-M, --mirror=STRING\n".
        "The prefered mirror from whcih the extensions metadata XML file should be downloaded. A random mirror is choosen if this option is omitted.",
    required => 0,
    default => 0,
),
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

# Map strings from arguments to Nagios Plugin codes.
my %codemap = (
    "ignore" => undef,
    "warning" => WARNING,
    "critical" => CRITICAL,
);

# Parse @ARGV and process arguments.
$nagios->getopts;

sub get_remote {
    my ($baseurl, $filename) =  @_;
    my $ua = LWP::UserAgent->new;
    my $response = $ua->get(sprintf("%s/%s", $baseurl, $filename));
    if ($response->code == 200) {
        return $response->content;
    } else {
        return;
    }
}
sub get_remote_cached {
    my ($baseurl, $filename, $cache) =  @_;
    my $path = sprintf("%s/%s", $cache, $filename);
    if ($cache && -e $path) {
        return read_file($path, binmode => ':raw');
    } else {
        my $content = get_remote(@_);
        if (defined $content && -d $cache) {
            open my $fh, ">", $path;
            binmode ($fh);
            print $fh $content;
            close $fh;
        }
        return $content;
    }
}
sub get_remote_cached_uncompressed {
    return Compress::Zlib::memGunzip(get_remote_cached(@_));
}
sub get_remote_cached_uncompressed_xpath {
    return XML::LibXML->load_xml(string => get_remote_cached_uncompressed(@_));
}

my $mirrors = get_remote_cached_uncompressed_xpath("http://repositories.typo3.org", "mirrors.xml.gz", $nagios->opts->get("cache"));
my $mirror;

# Select random mirror
if ($nagios->opts->get("mirror")) {
    $mirror = ($mirrors->findnodes(sprintf("/mirrors/mirror/host[text()='%s']/..", $nagios->opts->get("mirror"))))[0];
}
if (!defined($mirror)) {
    my @mirror_candidates = $mirrors->findnodes('/mirrors/mirror');
    msg(
        sprintf(
            "Selecting random mirror from candidates: %d",
            $#mirror_candidates
        ),
        $nagios->opts->get('verbose')
    );
    $mirror = $mirror_candidates[rand @mirror_candidates];
}

my $mirror_url = sprintf("http://%s%s", $mirror->findvalue("host"), $mirror->findvalue("path"));
msg(
    sprintf(
        "Using mirror: %s",
        $mirror_url
    ),
    $nagios->opts->get('verbose')
);

my $path = sprintf("%s/%s", $nagios->opts->get("cache"), "extensions.xml.gz");
if (-e $path) {
    my $remote_md5 = get_remote($mirror_url, "extensions.md5", $nagios->opts->get("cache"));
    msg(
        sprintf(
            "Remote extensions.md5: %s",
            $remote_md5
        ),
        $nagios->opts->get('verbose')
    );
    my $ctx = Digest::MD5->new;
    open my $fh, '<', $path;
    binmode ($fh);
    $ctx->addfile($fh);
    my $local_md5 = $ctx->hexdigest;
    msg(
        sprintf(
            "Local MD5 for extensions.xml.gz: %s",
            $local_md5
        ),
        $nagios->opts->get('verbose')
    );
    if ($remote_md5 eq $local_md5) {
        msg("Local extensions.xml.gz is up to date.", $nagios->opts->get('verbose'));
    } else {
        msg("Local extensions.xml.gz is out of date, purging from cache.", $nagios->opts->get('verbose'));
        unlink $path;
    }

}

my $extensions = get_remote_cached_uncompressed_xpath($mirror_url, "extensions.xml.gz", $nagios->opts->get("cache"));

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

# Hash that will hold the parsed response data.
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
            $nagios->opts->get('verbose')
        );
        next;
    }
    if (grep { $ext < $_ } map { version->parse($_->to_literal) } $extension->findnodes("version/\@version")) {
        push @updates, $name;
    }
}

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
if (scalar @conflicts > 0) {
    my $action = $codemap{$nagios->opts->get('conflict-action')};
    if (defined $action && $action > $code) {
        $code = $action;
    }
    $message .= sprintf("; TYPO3 %s conflicts: %s", $data{TYPO3}, join(", ", map { sprintf ("%s[%s-%s]", $_, $data{EXTDEPTYPO3}->{$_}->{from}, $data{EXTDEPTYPO3}->{$_}->{to}) } @conflicts));
}

# Process updates.
if (scalar @updates > 0) {
    my $action = $codemap{$nagios->opts->get('update-action')};
    if (defined $action && $action > $code) {
        $code = $action;
    }
    $message .= sprintf("; Updates available: %s", join(", ", @updates));
}

# Exit with final status and message.
$nagios->nagios_exit($code, $message);
