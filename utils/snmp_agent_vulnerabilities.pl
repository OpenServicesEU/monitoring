#!/usr/bin/perl -w
# Copyright 2014 Michael Fladischer
# OpenServices e.U.
# office@openservices.at
#
# Extend net-snmp agent to test and report know vulnerabilities.
# Currently supports:
#  * ShellShock (Bash environment execution)
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

use NetSNMP::agent qw(:all);
use NetSNMP::ASN qw(:all);

my $vulnerabilities_oid = new NetSNMP::OID(".1.3.6.1.4.1.36425.256.1");

# Extend this hash map with future vulnerabilities_checks.
# Each new chack should increment
my %vulnerabilities_checks = (
    '.2014.6271' => sub {
        return qx/env x='() { :;}; echo vulnerable' bash -c 'true'/ =~ /^vulnerable$/ ? 0xFF : 0x00;
    },
    '.2014.6278' => sub {
        return qx/env X='() { (a)=>\' sh -c 'echo safe'; cat echo/ !~ /^safe$/ ? 0xFF : 0x00;

    },
);

sub vulnerabilities_handler {
    my ($handler, $registration_info, $request_info, $requests) = @_;
    my $request;

    if (!keys %vulnerabilities_checks) {
        return;
    }

    for($request = $requests; $request; $request = $request->next()) {
        my $oid = $request->getOID();
        if ($request_info->getMode() == MODE_GET) {
            if ($oid == $vulnerabilities_oid) {
                $request->setValue(ASN_INTEGER, scalar keys %vulnerabilities_checks);
            } else {
                foreach my $check_oid (sort keys %vulnerabilities_checks) {
                    if ($oid == $vulnerabilities_oid + $check_oid) {
                        $request->setValue(ASN_INTEGER, $vulnerabilities_checks{$check_oid}->());
                    }
                }
            }
        } elsif ($request_info->getMode() == MODE_GETNEXT) {
            if ($oid < $vulnerabilities_oid) {
                $request->setOID($vulnerabilities_oid);
                $request->setValue(ASN_INTEGER, scalar keys %vulnerabilities_checks);
            } else {
                foreach my $check_oid (sort keys %vulnerabilities_checks) {
                    if ($oid < $vulnerabilities_oid + $check_oid) {
                        $request->setOID($vulnerabilities_oid + $check_oid);
                        $request->setValue(ASN_INTEGER, $vulnerabilities_checks{$check_oid}->());
                        last;
                    }
                }
            }
        }
    }
}

{
    if (!$agent) {
        print STDERR "No \$agent defined\n";
        print STDERR "Please check your snmp_perl.pl that should be included in you net-snmp distribution.\n";
        exit 1;
    }

    $agent->register("Vulnerabilities", $vulnerabilities_oid, \&vulnerabilities_handler);
}
