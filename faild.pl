#!/usr/bin/perl -w
# Script to monitor gateways for uptime and downtime, and adjust routing and
# packet filters accordingly when gateways go down and come back up.  Gateways
# should be listed in order of priority, so that failback can occur properly.

# For each gateway, specify its IP address, an IP address that is remote from
# the local network (these may be the same, e.g., for a cable modem setup, or
# distinct, for a T1 with a local router as the gateway), and its type
# (dedicated or on-demand).

# Current implementation only allows one ppp-on-demand gateway since
# there is only a single option for PPP_SYSTEM and PPP_IF, though this
# could be added to a per-gateway array like other options.
#
# Config file /etc/faild.conf format:
# # Comment format
# page_source: email-addr (where alerts are sent from)
# page_destination: email-addr (where alerts are sent to)
# # Then as many of these triplets as you want:
# gateway: <ip>
# ping_ip: <ip>
# type: <dedicated|on-demand|host>

# Issues/To Do:
# 1. PPP on-demand needs completion, need to handle failback/modem hangup.
#    Need to do appropriate NAT.  (Note that ppp already adds a default
#    route.)
# 2. Need to implement failover for pf rules.  Use tables?  I don't think
#    that will work for NAT rules.
# 3. Need to do an ifconfig $PPP_IF down/ifconfig $PPP_IF delete at
#    failback.
# 4. IPv6 support.
# Alternative:
# ppp -auto.  When failover occurs, just change the default route,
#   send some traffic (to where?), and sleep for $PPP_WAIT_TIME
#   seconds, then check for IP assignments to tun0.

# 2003-04-29 by Jim Lippard, from original written 2002-04-12.
# 1.1: 6 May 2003
# 1.2: 11 August 2004: Added third ping when gateway is down.  This
#      should probably be configurable.
# 1.3: 11 November 2005: Made number of pings for gateway down configurable,
#      added ability to set when failed pings log, reports number of failed
#      pings on a transition back to an "up" state.
# 1.4: 22 September 2021: Added support for identifying if specified cloud
#      hosts are unpingable, in addition to gateway.
# 1.5: 24 October 2021: Moved configurable items to a separate config file.
# 1.6: 12 July 2022: Add configurable option in code to disable failover
#      actions.
# 1.7: 19 December 2022: Use constant for FAILD_PID file. Fix uninitialized
#      pings_down variable bug.
# 1.8: 11 May 2023: Report failover steps even if not performing failover;
#      fix bug where it reports all gateways down when current gateway goes
#      down and we're not performing failover here.
# 1.9: 3 January 2024: Converted to newer perl open format. Don't exit if
#      current gateway is not in config.
# 1.9a: 20 July 2024: Change error message when starting up and current gateway
#      is not in config.

### Required packages.

use strict;
use Net::Ping;
use Sys::Syslog;

### Constants.

# Probably shouldn't touch.
my $VERSION = 'faild.pl 1.9a of 20 July 2024';

my $DEDICATED = 1;
my $ON_DEMAND = 2;
my $HOST_CHECK = 3;
my @GATE_TYPE_NAME = ('', 'Gateway', 'On-demand gateway', 'Host');

my $UP = 1;
my $DOWN = 0;

# User-configurable.
my $DEBUG = 0;

my $PERFORM_FAILOVER = 0;

# Number of seconds to wait between gateway checks.
my $SLEEP_TIME = 60;
# Number of seconds to wait for on-demand PPP connections.
my $PPP_WAIT_TIME = 15;
# Number of times to ping gateways before counting them as genuinely down.
my $N_PINGS_DOWN = 5;
# Number of times to ping before logging individual ping failures.
my $N_PINGS_TO_NOTIFY = 3;

my %PING_NAME = (1, 'first',
		 2, 'second',
		 3, 'third',
		 4, 'fourth',
		 5, 'fifth',
		 6, 'sixth',
		 7, 'seventh',
		 8, 'eighth',
		 9, 'ninth',
		 10, 'tenth');

my (@GATEWAYS, @PING_IPS, @GATE_TYPE);

# Name of PPP system to use in /etc/ppp/ppp.conf.
my $PPP_SYSTEM = 'pmdemand';
# Name of interface PPP connection is over (tun0 for ppp,
# would be ppp0 for pppd).
my $PPP_IF = 'tun0';

my $FAILD_CONF = '/etc/faild.conf';
my $FAILD_INFO = '/var/run/faild.info';
my $FAILD_PID = '/var/run/faild.pid';

my $IFCONFIG = '/usr/sbin/ifconfig';
my $PPP = '/usr/sbin/ppp';
my $ROUTE = '/sbin/route';
my $SENDMAIL = '/usr/sbin/sendmail';

my $SYSLOG_FACILITY = 'daemon';

my ($PAGE_SOURCE, $PAGE_DESTINATION);

### Variables.

my ($current_gateway, @ping_obj, @current_state, @new_state, @state_time, @pings_down, $n_pings);
my ($gate_type_name, $more_gateways_than_recorded);

### Main program.

if ($#ARGV == 0) {
    if ($ARGV[0] eq '-v') {
	print "$VERSION\n";
	exit;
    }
    else {
	die "Usage: faild.pl [-v]\n";
    }
}

&parse_config;
&initialize_states;
Sys::Syslog::setlogsock('unix');
&read_faild_info;

# Infinite loop.
while (1) {
    &ping_gateways;
    &report_and_failover;

    print "Sleeping for $SLEEP_TIME seconds.\n" if ($DEBUG);
    sleep $SLEEP_TIME;
}

&logmsg ('alert', 'Process has exited from infinite loop.');
exit;

### Subroutines.

# Parse config file.
sub parse_config {
    my ($have_page_source, $have_page_destination, $gateway_idx, $have_ping_ip, $have_type);
    $have_page_source = 0;
    $have_page_destination = 0;
    $gateway_idx = -1;
    $have_ping_ip = 0;
    $have_type = 0;

die "Config file does not exist. $! $FAILD_CONF\n" if (!-e $FAILD_CONF);
    open (CONFIG, '<', $FAILD_CONF) || die "Cannot open config file for reading. $! $FAILD_CONF\n";
    while (<CONFIG>) {
	chop;
	if (/^\s*#|^\s*$/) {
	    # comment or blank
	}
	elsif (/^\s*page_source:\s*(.*)$/) {
	    if (&is_email ($1)) {
		$PAGE_SOURCE = $1;
		$have_page_source = 1;
	    }
	    else {
		die "page_source must be an email address. $1\n";
	    }
	}
	elsif (/^\s*page_destination:\s*(.*)$/) {
	    if (&is_email ($1)) {
		$PAGE_DESTINATION = $1;
		$have_page_destination = 1;
	    }
	    else {
		die "page_destination must be an email address. $_\n";
	    }	    
	}
	elsif (/^\s*gateway:\s*(.*)$/) {
	    if ($gateway_idx > -1 &&
		(!$have_ping_ip || !$have_type)) {
		die "New gateway line when no ping_ip or type specified for previous gateway. $_\n";
	    }
	    if (&is_ipaddr ($1)) {
		push (@GATEWAYS, $1);
		$gateway_idx++;
		$have_ping_ip = 0;
		$have_type = 0;
	    }
	    else {
		die "gateway must be an IPv4 address. $_\n";
	    }
	}
	elsif (/^\s*ping_ip:\s*(.*)$/) {
	    if ($have_ping_ip) {
		die "Already have a ping IP for gateway. $_\n";
	    }
	    if (&is_ipaddr ($1)) {
		push (@PING_IPS, $1);
		$have_ping_ip = 1;
	    }
	}
	elsif (/\s*type:\s*(.*)$/) {
	    if ($have_type) {
		die "Already have a type for gateway. $_\n";
	    }
	    if ($1 eq 'dedicated') {
		push (@GATE_TYPE, $DEDICATED);
	    }
	    elsif ($1 eq 'on-demand') {
		push (@GATE_TYPE, $ON_DEMAND);
	    }
	    elsif ($1 eq 'host') {
		push (@GATE_TYPE, $HOST_CHECK);
	    }
	    else {
		die "Unrecognized type \"$1\". $_\n";
	    }
	    $have_type = 1;
	}
	else {
	    die "Unrecognized line in config. $_\n";
	}
    }
    close (CONFIG);

    if (!$have_page_source) {
	die "No page_source in config. $FAILD_CONF\n";
    }
    if (!$have_page_destination) {
	die "No page_destination in config. $FAILD_CONF\n";
    }
    if ($gateway_idx == -1) {
	die "No gateway in config. $FAILD_CONF\n";
    }
    if (!$have_ping_ip) {
	die "Missing ping_ip in config. $FAILD_CONF\n";
    }
    if (!$have_type) {
	die "Missing type in config. $FAILD_CONF\n";
    }
}

# Subroutine to do rudimentary email address check.
sub is_email {
    my ($addr) = @_;

    if ($addr =~ /^[\w.+-]+\@[\w.+-]+$/) {
	return 1;
    }
    else {
	return 0;
    }
}

# Subroutine to do rudimentary IP address check.
sub is_ipaddr {
    my ($ipaddr) = @_;

    if ($ipaddr =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/) {
	if (&is_octet ($1) &&
	    &is_octet ($2) &&
	    &is_octet ($3) &&
	    &is_octet ($4) &&
	    $1 > 0) {
	    return 1;
	}
	else {
	    # Bad octet.
	    return 0;
	}
    }
    else {
	# Not even close to an IP.
	return 0;
    }
}

# Subroutine to check numeric range of octet.
sub is_octet {
    my ($octet) = @_;

    if ($octet >= 0 && $octet <= 255) {
	return 1;
    }
    else {
	return 0;
    }
}

# Initialize states with up, since current moment, create ping objects.
sub initialize_states {
    my ($ip, $idx);

    print "Entering sub initialize_states.\n" if ($DEBUG);
    $ip = &gateway_ip;
    $current_gateway = &gate_index ($ip);
    print "Current gateway is $current_gateway ($ip).\n" if ($DEBUG);

    if ($current_gateway == -1) {
	&logmsg ('alert', "Current gateway ($ip) is not in faild.pl configuration.");
	&send_page ("faild.pl: Current gateway ($ip) is not in faild.pl configuration.");
    }

    for ($idx = 0; $idx <= $#GATEWAYS; $idx++) {
	$ping_obj[$idx] = Net::Ping -> new("icmp", 5);
	$current_state[$idx] = $UP;
	$state_time[$idx] = time();
	$pings_down[$idx] = 0;
    }

    if (open (PID, '>', $FAILD_PID)) {
	print PID "$$\n";
	close (PID);
    }

    &logmsg ("info", "started");
}

sub read_faild_info {
    my ($ip, $state, $state_time, $idx, $gateway_count);

    print "Entering sub read_faild_info.\n" if ($DEBUG);

    $gateway_count = 0;
    $more_gateways_than_recorded = 0;

    if (open (FAILD_INFO, '<', $FAILD_INFO)) {
	while (<FAILD_INFO>) {
	    chop;
	    $gateway_count++;
	    ($ip, $state, $state_time) = split (/,\s+/);
	    $idx = &gate_index ($ip);
	    if ($idx >= 0) {
		$current_state[$idx] = $state;
		$state_time[$idx] = $state_time;
	    }
	}
	close (FAILD_INFO);
    }
    $more_gateways_than_recorded = 1 if ($gateway_count < $#GATEWAYS);
}

sub write_faild_info {
    my ($idx);

    print "Entering sub write_faild_info.\n" if ($DEBUG);

    if (open (FAILD_INFO, '>', $FAILD_INFO)) {
	for ($idx = 0; $idx <= $#GATEWAYS; $idx++) {
	    print FAILD_INFO "$GATEWAYS[$idx], $current_state[$idx], $state_time[$idx]\n";
	}
	close (FAILD_INFO);
    }
}

# Set new_state for all gateways as up or down.  No test is performed
# for on-demand gateways not in use but believed to be up.
sub ping_gateways {
    my ($idx);

    print "Entering sub ping_gateways.\n" if ($DEBUG);

    for ($idx = 0; $idx <= $#GATEWAYS; $idx++) {
	$gate_type_name = $GATE_TYPE_NAME[$GATE_TYPE[$idx]];
	if ($GATE_TYPE[$idx] == $ON_DEMAND &&
	    $current_gateway != $idx &&
	    $current_state[$idx] == $UP) {
	    $new_state[$idx] = $UP;
	    print "$gate_type_name $idx ($GATEWAYS[$idx]) assumed to be up.\n" if ($DEBUG);
	}
	elsif ($ping_obj[$idx] -> ping ($PING_IPS[$idx])) {
	    $new_state[$idx] = $UP;
	    print "$gate_type_name $idx ($GATEWAYS[$idx]) is up on the first ping.\n" if ($DEBUG);
	}
	else {
	    $new_state[$idx] = $DOWN;
	    print "$gate_type_name $idx ($GATEWAYS[$idx]) is down on the first ping.\n" if ($DEBUG);
	    $pings_down[$idx] = 1;
	}
    }

    # Ping anything marked as down again N_PINGS_DOWN-1 times, just to be sure.  ($n_pings is total number of pings
    # including the first)
    for ($idx = 0; $idx <= $#GATEWAYS; $idx++) {
	$gate_type_name = $GATE_TYPE_NAME[$GATE_TYPE[$idx]];
	if ($new_state[$idx] == $DOWN) {
	    for ($n_pings = 2; $n_pings < $N_PINGS_DOWN+1; $n_pings++) {
		if ($ping_obj[$idx] -> ping ($PING_IPS[$idx])) {
		    $new_state[$idx] = $UP;
		    print "$gate_type_name $idx ($GATEWAYS[$idx]) is up on the $PING_NAME{$n_pings} ping.\n" if ($DEBUG);
		    &logmsg ('alert', "$gate_type_name $idx ($GATEWAYS[$idx]) is up on the $PING_NAME{$n_pings} ping.") if ($n_pings > $N_PINGS_TO_NOTIFY);
		    last;
		}
		else {
		    print "$gate_type_name $idx ($GATEWAYS[$idx]) is down on the $PING_NAME{$n_pings} ping.\n" if ($DEBUG);
		    &logmsg ('alert', "$gate_type_name $idx ($GATEWAYS[$idx]) is down on the $PING_NAME{$n_pings} ping.") if ($n_pings > $N_PINGS_TO_NOTIFY);
		    $pings_down[$idx] = $n_pings;
		}
	    }
	}
    }
}

# Subroutine to report any state changes and failover to another
# gateway if necessary and possible.
sub report_and_failover {
    my ($changes_occurred, $idx, $duration, $plural);

    print "Entering sub report_and_failover.\n" if ($DEBUG);

    # Report changes that have occurred.
    $changes_occurred = 0;
    for ($idx = 0; $idx <= $#GATEWAYS; $idx++) {
	$gate_type_name = $GATE_TYPE_NAME[$GATE_TYPE[$idx]];
	if ($current_state[$idx] != $new_state[$idx]) {
	    $changes_occurred = 1;
	    $duration = time() - $state_time[$idx];
	    $duration = int ($duration / 60);
	    $plural = 's';
	    $plural = '' if ($duration == 1);
	    if ($new_state[$idx] == $UP) {
		&logmsg ('alert', "$gate_type_name $idx ($GATEWAYS[$idx]) is again reachable (down $duration minute$plural), $pings_down[$idx] failed pings.");
		print "$gate_type_name $idx ($GATEWAYS[$idx]) is again reachable (down $duration minute$plural).\n" if ($DEBUG);
		if ($duration > 15) {
		    &send_page ("faild.pl: $gate_type_name $idx ($GATEWAYS[$idx]) is again reachable (down $duration minute$plural).");
		}
	    }
	    else {
		&logmsg ('alert', "$gate_type_name $idx ($GATEWAYS[$idx]) has gone down (up $duration minute$plural).");
		print "$gate_type_name $idx ($GATEWAYS[$idx]) has gone down (up $duration minute$plural).\n" if ($DEBUG);
	    }
	    $current_state[$idx] = $new_state[$idx];
	    $state_time[$idx] = time();
	}
	elsif ($new_state[$idx] == $DOWN) {
	    $duration = time() - $state_time[$idx];
	    $duration = int ($duration / 60);
	    $plural = 's';
	    $plural = '' if ($duration == 1);
	    &logmsg ('alert', "$gate_type_name $idx ($GATEWAYS[$idx]) has been down for $duration minute$plural.");
	    print "$gate_type_name $idx ($GATEWAYS[$idx]) has been down for $duration minute$plural.\n" if ($DEBUG);
	    if ($duration % 15 == 0 && $duration < 61) {
		&send_page ("faild.pl: $gate_type_name $idx ($GATEWAYS[$idx]) has been down for $duration minutes.");
	    }
	}
    }

    # If changes occurred or states haven't been written out before,
    # or if there are some new gateways not already recorded,
    # write out new states.
    if ($changes_occurred || !-e $FAILD_INFO || $more_gateways_than_recorded) {
	&write_faild_info;
    }

    # If current gateway is down, look for one to failover to.
    # If current gateway is not the primary, look for a higher-priority
    # gateway to fail back to.
    $changes_occurred = 0;
    if ($new_state[$current_gateway] == $DOWN || $current_gateway != 0) {
	for ($idx = 0; $idx <= $#GATEWAYS; $idx++) {
	    $gate_type_name = $GATE_TYPE_NAME[$GATE_TYPE[$idx]];
	    # If we're trying to fail back, give up when we get to the
	    # current gateway--no higher-priority gateway is up.
	    if ($idx == $current_gateway && $new_state[$current_gateway] == $UP) {
		last;
	    }
	    # If we find a gateway that's up, we can switch to it.
	    # If there's more than one gateway but we're not performing
	    # failover here, report the failover steps even though we aren't
	    # doing it.
	    elsif ($new_state[$idx] == $UP && $GATE_TYPE[$idx] != $HOST_CHECK) {
		if ($idx < $current_gateway) {
		    &logmsg ('alert', "Failing back from gateway $current_gateway ($GATEWAYS[$current_gateway]) to gateway $idx ($GATEWAYS[$idx]).");
		    print "Failing back from gateway $current_gateway ($GATEWAYS[$current_gateway]) to gateway $idx ($GATEWAYS[$idx]).\n" if ($DEBUG);
		    &send_page ("faild.pl: Failing back from gateway $current_gateway ($GATEWAYS[$current_gateway]) to gateway $idx ($GATEWAYS[$idx]).");
		    $current_gateway = $idx;
		}
		elsif ($idx > $current_gateway) {
		    if ($current_gateway == -1) {
			&logmsg ('alert', "Starting up with gateway $idx ($GATEWAYS[$idx]).");
			print "Starting up with gateway $idx ($GATEWAYS[$idx]).\n";
		    }
		    else {
			&logmsg ('alert', "Failing over from gateway $current_gateway ($GATEWAYS[$current_gateway]) to gateway $idx ($GATEWAYS[$idx]).");
			print "Failing over from gateway $current_gateway ($GATEWAYS[$current_gateway]) to gateway $idx ($GATEWAYS[$idx]).\n" if ($DEBUG);
			&send_page ("faild.pl: Failing over from gateway $current_gateway ($GATEWAYS[$current_gateway]) to gateway $idx ($GATEWAYS[$idx]).");
		    }
		    $current_gateway = $idx;
		}
		else {
		    &logmsg ('alert', "Primary and current gateway $current_gateway ($GATEWAYS[$current_gateway]) is back up.");
		    print "Primary and current gateway $current_gateway ($GATEWAYS[$current_gateway]) is back up.\n" if ($DEBUG);
		    &send_page ("faild.pl: Primary and current gateway $current_gateway ($GATEWAYS[$current_gateway]) is back up.");
		}

		# We found something to switch to.
		$changes_occurred = 1;

		# Change routing to new gateway.
		if ($PERFORM_FAILOVER && $GATE_TYPE[$idx] == $DEDICATED) {
		    system ("$ROUTE change default $GATEWAYS[$idx]");
		}
		elsif ($PERFORM_FAILOVER) {
		    # Bring up on-demand dialup PPP gateway.
		    system ("$PPP -ddial $PPP_SYSTEM");
		    sleep $PPP_WAIT_TIME;

		    if (open (IFCONF, '-|', "$IFCONFIG $PPP_IF")) {
			while (<IFCONF>) {
			    if (/inet (\d+\.\d+\.\d+\.\d+) --> (\d+\.\d+\.\d+\.\d+)/) {
				# ADD: check to make sure we get something,
				#  record my IP, so we can send it out.
				$GATEWAYS[$idx] = $2;
				$PING_IPS[$idx] = $2;
			    }
			} # while
			close (IFCONF);
		    } #ifconfig
		    # Routing change for on-demand gateway.
		    system ("$ROUTE change default $GATEWAYS[$idx]");
		} # dialup PPP
		# ADD: Change pf config/NAT.  No, should be in place already.
		last;
	    } # found up gateway
	} # for loop
    } # current gateway down or not on primary gateway

    # If there is more than one gateway and all are down, note that.
    if ($#GATEWAYS > 0 &&
	!$changes_occurred &&
	$new_state[$current_gateway] == $DOWN) {
	&logmsg ('alert', "All available gateways are down.");
	print "All available gateways are down.\n" if ($DEBUG);
    }
}

# Subroutine to return IP address of current gateway.
sub gateway_ip {
    my ($ip);

    open (ROUTE, '-|', "$ROUTE -n show");
    while (<ROUTE>) {
        if (/^default\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+UG/) {
	    $ip = $1;
        }
    }
    close (ROUTE);
    return $ip;
}

# Subroutine to return index of gateway as specified by IP address.
sub gate_index {
    my ($ip) = @_;
    my ($idx, $found);

    for ($idx = 0; $idx <= $#GATEWAYS; $idx++) {
	if ($GATEWAYS[$idx] eq $ip) {
	    $found = 1;
	    last;
	}
    }

    return $idx if ($found);
    return -1;
}

# Log a message to syslog.
sub logmsg {
    my ($level, $msg) = @_;

    print "Sending syslog message.\n" if ($DEBUG);
    openlog ('faild.pl', 'pid', $SYSLOG_FACILITY);
    syslog ($level, $msg);
    closelog();
}

# Send a page.
sub send_page {
    my ($msg) = @_;

    print "Sending page.\n" if ($DEBUG);
    open (MAIL, '|-', "$SENDMAIL -t");
    print MAIL "From: $PAGE_SOURCE\n";
    print MAIL "To: $PAGE_DESTINATION\n\n";
    print MAIL "$msg\n";
    close (MAIL);
}
