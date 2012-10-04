#!/usr/bin/perl -w

use Getopt::Long;
use Nagios::Plugin::WWW::Mechanize;
$np = Nagios::Plugin::WWW::Mechanize->new( 
  usage => "Checks number of mailing list users",
);
my $user;
my $password;

# Process options.
if ( @ARGV > 0 ) {
    GetOptions(
         'user|u=s'      => \$user,
         'password|p=s'      => \$password,
         'host|H=s'      => \$host,
         'debug|d'      => \$debug)
      or pod2usage(2);
}

if (defined $debug) {
  $np->mech->add_handler("request_send", sub { shift->dump; return });
  $np->mech->add_handler("response_done", sub { shift->dump; return });
}

$np->get( "http://$host/gw/webacc" );
$np->submit_form( form_name => "loginForm", fields => { "User.id" => $user, "User.password" => $password });
$content = $np->content;
($firstName, $lastName) = ($content =~ /<TITLE>Novell WebAccess \((\w+) (\w+)\)<\/TITLE>/);
$np->nagios_exit( CRITICAL, "Could not login as $user" ) unless (defined $lastName and defined $firstName);

#$np->add_perfdata(
#  label => "users",
#  value => $number_of_users,
#);
$np->nagios_exit(
  OK,
  "User found: $firstName $lastName"
);
