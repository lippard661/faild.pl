#!/usr/bin/perl -w
# Script to monitor gateways for uptime and downtime, and adjust routing and
# packet filters accordingly when gateways go down and come back up.  Gateways
# should be listed in order of priority, so that failback can occur properly.

# For each gateway, specify its IP address, an IP address that is remote from
# the local network (these may be the same, e.g., for a cable modem setup, or
# distinct, for a T1 with a local router as the gateway), and its type
# (dedicated or on-demand).
#
# Config file /etc/faild.conf format:
# # Comment format
# page_source: email-addr (where alerts are sent from)
# page_destination: email-addr (where alerts are sent to)
# perform_failover: [yes|no] (optional, default no)
# # Then as many of these triplets as you want:
# gateway: <ip>
# interface: <interface name> [optional, but needed for dhcplease]
# routes: <cidr>, <cidr>, <cidr> [optional only for dhcplease, use "P" after
#    cidr for permanent route that should not be removed if gateway goes down
# ping_ip: <ip>
# type: <dedicated|dedicated-dhcplease-primary|dedicated-dhcplease-backup|on-demand|host>

# Issues/To Do:
# (reworked)
# 1. Allow specifying an amount of downtime before failover (e.g., to avoid
#    a one-minute downtime change). Default should be 2 min. (DONE)
# 1a.  Command line and/or config file option for whether failover should
#      occur. (DONE, config)
# 2. Allow more control over what failover actions occur -- e.g.,
#    checking dhcpleasectl info on gateways, making additional
#    routing changes, error checking. (DONE, sort of)
# 3. IPv6 support. (currently using tunnel on one interface)

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
# 1.9b: 15 June 2025: Modified to flush pf states and source tracking for
#      current gateway when it goes down as part of failover to new gateway.
# 1.10: 16-17 June 2025: Modified to not failover until 2 minutes of downtime.
#      Add dedicated-dhcplease-(primary/backup) types and renew leases before they expire.
#      Use pledge and unveil.
# 1.11 3 July 2025: Modified to allow adding specific routes to a gateway.
# 1.12 23 August 2025: While an interface is down, check for permanent routes
#      and re-add them if missing, which sometimes occurs after a reboot,
#      e.g., after power failure.
# 1.13 8 November 2025: Modified for some cleanup.
# 1.14 4 January 2026: Modified to remove & from subroutine calls.
# 1.15 1 March 2026: Modified (with Claude assistance at identifying issues
#      based on my description) to fix failover delay bug and some other
#      minor issues.
# 1.16 17 March 2026: Modified to fix bug in host monitoring downtime duration
#      tracking and bug where "All available gateways are down" when a monitored
#      host (not gateway) is down.
# 1.17 3 May 2026: Modified to avoid shell in opening pipes for commands. Umask
#      for file permissions. Flock for PID file, eliminate race condition.
#      Better error checking and reporting.
# 1.18 5 May 2026: Modified to fix bug in failback.
# 1.19 14 May 2026: Replace Net::Ping with use of OS ping command as part
#      of preparation for privilege separation, properly daemonize. Remove
#      netstart call and unveil for /bin/sh to do it. Improve forced lease
#      renewing. Remove PPP support.
# 1.20 15 May 2026: Added privilege separation, state_dir: for config file,
#      can run as nonpriv user, in monitor-only mode with no priv process,
#      will drop privs and restrict pledges.

# ToDo: Some former "constants" are now variables from the config and should
# consider moving them to the variables section and making them all
# lowercase names.

### Required packages.

use strict;
use warnings;
use base; # required by Privileges::Drop;
use English; # required by Privileges::Drop;
use Fcntl qw( :DEFAULT :flock );
use IO::Handle;
use JSON::PP;
use POSIX;
use Privileges::Drop;
use Socket qw( AF_UNIX SOCK_STREAM PF_UNSPEC );
use Sys::Syslog;

use if $^O eq "openbsd", "OpenBSD::Pledge";
use if $^O eq "openbsd", "OpenBSD::Unveil";

### Constants.

my $VERSION = 'faild.pl 1.20 of 15 May 2026';

# Pledge promise groups - stdio is added automatically by OpenBSD::Pledge
my @READONLY_PROMISES     = ('rpath');
my @READWRITE_PROMISES    = ('wpath', 'cpath');
my @EXEC_PROMISES         = ('proc', 'exec');
my @FLOCK_PROMISE         = ('flock');
my @UNVEIL_PROMISE        = ('unveil');
my @UNIX_PROMISE          = ('unix');
my @PRIVSEP_DROP_PROMISES = ('id', 'prot_exec');
my @CHOWN_PROMISES        = ('chown', 'fattr');

my @RUNTIME_PROMISES = (@READONLY_PROMISES, @READWRITE_PROMISES,
                        @EXEC_PROMISES, @FLOCK_PROMISE, @UNIX_PROMISE);
my @HELPER_PROMISES = (@EXEC_PROMISES);
my @STARTUP_PROMISES = (@RUNTIME_PROMISES, @UNVEIL_PROMISE, @PRIVSEP_DROP_PROMISES,
    @CHOWN_PROMISES);

my $DEDICATED = 1;
my $DEDICATED_DHCPLEASE_PRIMARY = 2;
my $DEDICATED_DHCPLEASE_BACKUP = 3;
my $HOST_CHECK = 4;
my @GATE_TYPE_NAME = ('',
		      'Gateway',
		      'Gateway (DHCP primary)',
		      'Gateway (DHCP backup)',
		      'Host');

my $UP = 1;
my $DOWN = 0;

# User-configurable.
my $DEBUG = 0;

my $PERFORM_FAILOVER = 0;

# Number of minutes of downtime before failover.
my $FAILOVER_DELAY_MINUTES = 2;

# Number of seconds to wait between gateway checks.
my $SLEEP_TIME = 60;
# Number of times to ping gateways before counting them as genuinely down.
my $N_PINGS_DOWN = 5;
# Number of times to ping before logging individual ping failures.
my $N_PINGS_TO_NOTIFY = 3;
# Number of seconds to wait for each ping to succeed or fail.
my $PING_TIMEOUT = 1;

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

my (@GATEWAYS, @INTERFACES, @ROUTES, @PING_IPS, @GATE_TYPE);

my $FAILD_CONF = '/etc/faild.conf';
my $STATE_DIR = '/var/run';; # default
my $FAILD_INFO; # default = '/var/run/faild.info';
my $FAILD_PID; # default = '/var/run/faild.pid';

my $DHCPLEASECTL = '/usr/sbin/dhcpleasectl';
my $PFCTL = '/sbin/pfctl';
my $PING = '/sbin/ping';
$PING = '/usr/bin/ping' if ($^O eq 'linux'); # Linux not supported for routing
my $ROUTE = '/sbin/route';
my $SENDMAIL = '/usr/sbin/sendmail';

my $SYSLOG_FACILITY = 'daemon';

my ($PAGE_SOURCE, $PAGE_DESTINATION);

### Variables.

my ($current_gateway, @current_state, @new_state, @state_time, @pings_down, $n_pings);
my ($gate_type_name, $more_gateways_than_recorded);
my (@last_interface_ip, @last_netmask, @last_gateway_ip);
my ($faild_uid, $faild_gid);
my $helper_sock; # for privilege separation


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

umask 022; # rw-r-r-

# Pledge, Unveil.
if ($^O eq "openbsd") {
    pledge (@STARTUP_PROMISES) || die "Cannot pledge promises. $!\n";
    unveil ($FAILD_CONF, 'r');
    unveil ('/etc', 'r');
    unveil ('/var/run', 'rwc');
    unveil ('/dev/log', 'rw');
    unveil ('/dev/null', 'rw');
    unveil ($DHCPLEASECTL, 'x');
    unveil ($PFCTL, 'x');
    unveil ($PING, 'x');
    unveil ($ROUTE, 'x');
    unveil ($SENDMAIL, 'x');
    # don't lock yet.
}

parse_config();
$FAILD_INFO = "$STATE_DIR/faild.info";
$FAILD_PID = "$STATE_DIR/faild.pid";
if ($^O eq 'openbsd') {
    unveil ($STATE_DIR, 'rwc');
    unveil (); # done unveiling, lock it
}

if ($PERFORM_FAILOVER && $^O ne 'openbsd') {
    die "Failover is only supported on OpenBSD.\n";
}

my ($running_as_root, $need_helper) = determine_privilege_mode();

# Check that state_dir is writable for the eventual runtime user
# (root always can; non-root must be writable as the current user)
if (!$running_as_root) {
    if (!-w $STATE_DIR) {
        die "Cannot use state_dir '$STATE_DIR' - not writable by current user.\n" .
            "Set state_dir in $FAILD_CONF to a directory writable by your user, " .
            "e.g., '\$HOME/.faild'.\n";
    }
}
# When running as root, the directory will be made accessible to _faild
# in setup_privsep (file chown). The /var/run default is root-writable.

acquire_pid_lock();
initialize_states();
Sys::Syslog::setlogsock('unix');
read_faild_info();

daemonize() unless ($DEBUG);

if ($need_helper) {
    setup_privsep();
}
# monitor-only mode, don't need privileged helper
elsif ($running_as_root) {
    prepare_state_files_for_user ($faild_uid, $faild_gid);
    Privileges::Drop::drop_uidgid ($faild_uid, $faild_gid);
    $0 = 'faild monitor';
}
# already running as non-root
else {
    $0 = 'faild monitor';
}

# Tighten pledge.
pledge (@RUNTIME_PROMISES) if ($^O eq 'openbsd');

# Set up signal handlers in child
$SIG{TERM} = sub {
    logmsg('info', 'Received SIGTERM, exiting cleanly');
    exit(0);
};
$SIG{INT} = $SIG{TERM};

write_pid();

# Infinite loop.
while (1) {
    ping_gateways();
    report_and_failover();

    print "Sleeping for $SLEEP_TIME seconds.\n" if ($DEBUG);
    sleep $SLEEP_TIME;
}

logmsg ('alert', 'Process has exited from infinite loop.');
exit;

### Subroutines.

# Parse config file.
sub parse_config {
    my ($have_page_source, $have_page_destination, $gateway_idx, $have_interface, $have_routes, $have_ping_ip, $have_type);
    $have_page_source = 0;
    $have_page_destination = 0;
    $gateway_idx = -1;
    $have_interface = 0;
    $have_routes = 0;
    $have_ping_ip = 0;
    $have_type = 0;

    die "Config file does not exist. $! $FAILD_CONF\n" if (!-e $FAILD_CONF);
    open (CONFIG, '<', $FAILD_CONF) || die "Cannot open config file for reading. $! $FAILD_CONF\n";
    while (<CONFIG>) {
	chomp;
	if (/^\s*#|^\s*$/) {
	    # comment or blank
	}
	elsif (/^\s*state_dir:\s*(.*)$/) {
	    $STATE_DIR = $1;
	    $STATE_DIR =~ s|/+$||; # remove any trailing slashes
	    die "Invalid state_dir path: $STATE_DIR\n"
		unless ($STATE_DIR =~ m{^/[\w/.-]+$} && length ($STATE_DIR) < 256);
	    die "state_dir $STATE_DIR does not exist.\n" unless (-d $STATE_DIR);
	}
	elsif (/^\s*page_source:\s*(.*)$/) {
	    if (is_email ($1)) {
		$PAGE_SOURCE = $1;
		$have_page_source = 1;
	    }
	    else {
		die "page_source must be an email address. $1\n";
	    }
	}
	elsif (/^\s*page_destination:\s*(.*)$/) {
	    if (is_email ($1)) {
		$PAGE_DESTINATION = $1;
		$have_page_destination = 1;
	    }
	    else {
		die "page_destination must be an email address. $_\n";
	    }	    
	}
	elsif (/^\s*perform_failover:\s*(.*)$/) {
	    if ($1 eq 'yes') {
		$PERFORM_FAILOVER = 1;
	    }
	    elsif ($1 eq 'no') {
		$PERFORM_FAILOVER = 0;
	    }
	    else {
		die "perform_failover must be \"yes\" or \"no\", not \"$1\".\n";
	    }
	}
	elsif (/^\s*gateway:\s*(.*)$/) {
	    if ($gateway_idx > -1) {
		die "New gateway line when no ping_ip specified for previous gateway. $_\n" if (!$have_ping_ip);
		die "New gateway line when no type specified for previous gateway. $_\n" if (!$have_type);
		die "New gateway line when no interface specified for previous dedicated-dhcplease gateway. $_\n" if (!$have_interface && ($GATE_TYPE[$gateway_idx] == $DEDICATED_DHCPLEASE_PRIMARY ||
																	   $GATE_TYPE[$gateway_idx] == $DEDICATED_DHCPLEASE_BACKUP));
	    }
	    if (is_ipaddr ($1)) {
		push (@GATEWAYS, $1);
		$gateway_idx++;
		$have_interface = 0;
		$have_routes = 0;
		$have_ping_ip = 0;
		$have_type = 0;
	    }
	    else {
		die "gateway must be an IPv4 address. $_\n";
	    }
	}
	# Optional except for dedicated-dhcplease types.
	elsif (/^\s*interface:\s*(.*)$/) {
	    if ($have_interface) {
		die "Already have an interface for gateway. $_\n";
	    }
	    $INTERFACES[$gateway_idx] = $1;
	    die "Invalid interface name. $INTERFACES[$gateway_idx]\n" unless ($INTERFACES[$gateway_idx] =~ /^[\w\._]+$/ &&
		length ($INTERFACES[$gateway_idx]) < 16);
	    if ($^O eq 'openbsd') {
		# no need to unveil specifically since /etc is unveiled with r
		die "No /etc/hostname.$INTERFACES[$gateway_idx].\n" if (!-e "/etc/hostname.$INTERFACES[$gateway_idx]");
	    }
	    elsif ($^O eq 'linux') {
		die "No /sys/class/net/$INTERFACES[$gateway_idx]\n" if (!-e "/sys/class/net/$INTERFACES[$gateway_idx]");
	    }
	    $have_interface = 1;
	}
	# Optional, only for dedicated-dhcplease types.
	elsif (/^\s*routes:\s*(.*)$/) {
	    if ($have_routes) {
		die "Already have specific routes for gateway. $_\n";
	    }
	    $ROUTES[$gateway_idx] = $1;
	    # remove any whitespace
	    $ROUTES[$gateway_idx] =~ s/\s//g;
	    if (!valid_routes ($ROUTES[$gateway_idx])) {
		die "Invalid specific routes. $ROUTES[$gateway_idx]\n";
	    }
	    $have_routes = 1;
	}
	elsif (/^\s*ping_ip:\s*(.*)$/) {
	    if ($have_ping_ip) {
		die "Already have a ping IP for gateway. $_\n";
	    }
	    if (is_ipaddr ($1)) {
		push (@PING_IPS, $1);
		$have_ping_ip = 1;
	    }
	    else {
		die "Invalid ping IP address. $1\n";
	    }
	}
	elsif (/\s*type:\s*(.*)$/) {
	    if ($have_type) {
		die "Already have a type for gateway. $_\n";
	    }
	    if ($1 eq 'dedicated') {
		push (@GATE_TYPE, $DEDICATED);
	    }
	    elsif ($1 eq 'dedicated-dhcplease-primary') {
		push (@GATE_TYPE, $DEDICATED_DHCPLEASE_PRIMARY);
	    }
	    elsif ($1 eq 'dedicated-dhcplease-backup') {
		push (@GATE_TYPE, $DEDICATED_DHCPLEASE_BACKUP);
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
    # These checks need to occur for each gateway.
    if (!$have_interface) {
	die "Missing interface in config for dedicated-dhcplease gateway. $FAILD_CONF\n" if ($have_type &&
											     ($GATE_TYPE[$gateway_idx] == $DEDICATED_DHCPLEASE_PRIMARY ||
											      $GATE_TYPE[$gateway_idx] == $DEDICATED_DHCPLEASE_BACKUP));
    }
    if (!$have_ping_ip) {
	die "Missing ping_ip in config. $FAILD_CONF\n";
    }
    if (!$have_type) {
	die "Missing type in config. $FAILD_CONF\n";
    }
    if ($have_routes && $GATE_TYPE[$gateway_idx] != $DEDICATED_DHCPLEASE_PRIMARY &&
	$GATE_TYPE[$gateway_idx] != $DEDICATED_DHCPLEASE_BACKUP) {
	die "Specific routes specified for non-dedicated DHCP gateway.\n";
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

# Validation functions
sub is_ipaddr {
    my ($ip) = @_;
    return 0 unless defined ($ip);
    return 0 unless ($ip =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    return 0 if ($1 == 0); # First octet must be non-zero
    foreach my $octet ($1, $2, $3, $4) {
        return 0 if ($octet > 255);
    }
    return 1;
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

# Subroutine to check format of CIDR block.
sub is_cidr {
    my ($cidr) = @_;
    return 0 unless defined ($cidr);
    return 0 unless ($cidr =~ m{^([\d.]+)/(\d+)$});
    my ($ip, $bits) = ($1, $2);
    return is_ipaddr ($ip) && $bits >= 1 && $bits <= 32;
}

# Subroutine to validate an interface.
sub is_interface {
    my ($if) = @_;
    return 0 unless defined ($if);
    return 0 unless ($if =~ /^[a-z]+\d+(\.\d+)?$/);
    return 0 if (length ($if) >= 16);
    return 1;
}

# Subroutine to check format of specific routes list. IPv4 only.
sub valid_routes {
    my ($routes) = @_;
    my @route_array = split (/,/, $routes);
    foreach my $route (@route_array) {
        my $clean = $route;
        $clean =~ s/P$//;  # strip permanent marker
        return 0 unless is_cidr ($clean);
    }
    return 1;
}

### Privilege separation subroutines.

# Subroutine to determine privilege mode for this invocation.
sub determine_privilege_mode {
    my $running_as_root = ($> == 0);
    
    my $need_helper = $PERFORM_FAILOVER;
    if (!$need_helper) {
        for (my $i = 0; $i <= $#GATEWAYS; $i++) {
            if ($GATE_TYPE[$i] == $DEDICATED_DHCPLEASE_PRIMARY ||
                $GATE_TYPE[$i] == $DEDICATED_DHCPLEASE_BACKUP) {
                $need_helper = 1;
                last;
            }
        }
    }

    # Validate we have the privileges and users we need.
    if ($need_helper && !$running_as_root) {
        die "faild.pl needs to run as root for failover or DHCP gateway types.\n";
    }

    # If running as root, we'll drop privileges - verify _faild exists
    if ($running_as_root) {
        $faild_uid = getpwnam('_faild');
        $faild_gid = getgrnam('_faild');
        if (!defined($faild_uid) || !defined($faild_gid)) {
            die "Cannot drop privileges: _faild user and group must exist.\n" .
                "Create with: useradd -L daemon -d /var/empty -s /sbin/nologin _faild\n";
        }
    }
    
    return ($running_as_root, $need_helper);
}

# Subroutine to set up privilege separation.
sub setup_privsep {
    prepare_state_files_for_user ($faild_uid, $faild_gid);
    
    my ($parent_sock, $child_sock);
    socketpair($parent_sock, $child_sock, AF_UNIX, SOCK_STREAM, PF_UNSPEC)
        or die "socketpair: $!";
    
    $parent_sock->autoflush(1);
    $child_sock->autoflush(1);
    
    my $pid = fork();
    die "Cannot fork for privsep: $!\n" if (!defined $pid);
    
    if ($pid != 0) {
        # Parent: become the helper
        close($child_sock);
        $0 = 'faild [priv]';

	# Close the PID file, let the child/worker keep it open.
	close (PID);

	# Setup signal handlers.
	$SIG{TERM} = sub { exit(0); };
	$SIG{INT} = sub { exit(0); };
        
        # Helper-specific pledge - more restrictive than child
	pledge (@HELPER_PROMISES) || die "Cannot pledge promises. $!\n" if ($^O eq 'openbsd');
        
        helper_loop($parent_sock);
        
        # When helper_loop returns, child has disconnected
        exit(0);
    }
    
    # Child: continue with privilege drop
    close($parent_sock);
    $helper_sock = $child_sock;

    Privileges::Drop::drop_uidgid ($faild_uid, $faild_gid);

    # Pledges are tightened right after this in main program, for multiple code paths,
    # otherwise it would have been done here.

    $0 = 'faild monitor';
}

## Privileged (helper) side, executes privileged operations.

# Privileged listener.
sub helper_loop {
    my ($sock) = @_;
    
    while (my $line = <$sock>) {
        chomp $line;
        my $req;
        eval { $req = decode_json($line); };
        if ($@) {
            print $sock encode_json({status => 'err', reason => 'invalid JSON'}) . "\n";
            next;
        }
        my $resp = dispatch_command($req);
        print $sock encode_json($resp) . "\n";
    }
}

# Helper command dispatch - runs in the privileged process (or same process in Step 2)
sub dispatch_command {
    my ($req) = @_;
    my $cmd = $req->{cmd} || '';
    
    if ($cmd eq 'ROUTE_CHANGE_DEFAULT') {
        return {status => 'err', reason => 'bad ip'} 
            unless (defined ($req->{ip}) && is_ipaddr ($req->{ip}));
        return run_helper_cmd ($ROUTE, '-n', 'change', 'default', $req->{ip});
    }
    elsif ($cmd eq 'ROUTE_ADD_DEFAULT') {
        return {status => 'err', reason => 'bad ip'} 
            unless (defined ($req->{ip}) && is_ipaddr ($req->{ip}));
        return run_helper_cmd ($ROUTE, '-n', 'add', 'default', $req->{ip});
    }
    elsif ($cmd eq 'ROUTE_DELETE_DEFAULT') {
        return {status => 'err', reason => 'bad ip'} 
            unless (defined ($req->{ip}) && is_ipaddr ($req->{ip}));
        return run_helper_cmd ($ROUTE, '-n', 'delete', 'default', $req->{ip});
    }
    elsif ($cmd eq 'ROUTE_ADD') {
        return {status => 'err', reason => 'bad cidr'} 
            unless (defined ($req->{cidr}) && is_cidr ($req->{cidr}));
        return {status => 'err', reason => 'bad gateway'} 
            unless (defined ($req->{gateway}) && is_ipaddr ($req->{gateway}));
        return run_helper_cmd ($ROUTE, '-n', 'add', '-inet', $req->{cidr}, $req->{gateway});
    }
    elsif ($cmd eq 'ROUTE_DELETE') {
        return {status => 'err', reason => 'bad cidr'} 
            unless (defined ($req->{cidr}) && is_cidr ($req->{cidr}));
        return run_helper_cmd ($ROUTE, '-n', 'delete', '-inet', $req->{cidr});
    }
    elsif ($cmd eq 'ROUTE_FLUSH_IFACE') {
        return {status => 'err', reason => 'bad interface'} 
            unless (defined ($req->{interface}) && is_interface ($req->{interface}));
        return run_helper_cmd ($ROUTE, 'flush', '-iface', $req->{interface});
    }
    elsif ($cmd eq 'PFCTL_FLUSH_STATES') {
        return {status => 'err', reason => 'bad ip'} 
            unless (defined ($req->{ip}) && is_ipaddr ($req->{ip}));
        return run_helper_cmd ($PFCTL, '-F', 'states', '-k', $req->{ip});
    }
    elsif ($cmd eq 'DHCPLEASECTL_RENEW') {
        return {status => 'err', reason => 'bad interface'} 
            unless (defined ($req->{interface}) && is_interface ($req->{interface}));
        return run_helper_cmd ($DHCPLEASECTL, $req->{interface});
    }
    elsif ($cmd eq 'DHCPLEASECTL_INFO') {
        return {status => 'err', reason => 'bad interface'} 
            unless (defined ($req->{interface}) && is_interface ($req->{interface}));
        return get_dhcp_info ($req->{interface});
    }
    else {
        return {status => 'err', reason => 'unknown command'};
    }
}

# Run a privileged system command, return JSON-encodable result
sub run_helper_cmd {
    my (@cmd) = @_;
    my $rc = system (@cmd);
    if ($rc == 0) {
        return {status => 'ok'};
    }
    elsif ($rc == -1) {
	return {status => 'err', reason => "exec failed: $!"};
    }
    elsif ($? & 127) {
        my $sig = $? & 127;
        return {status => 'err', reason => "killed by signal $sig"};
    }
    else {
        my $exit = $? >> 8;
        return {status => 'err', reason => "exit $exit"};
    }
}

# Get DHCP lease info - returns structured data
sub get_dhcp_info {
    my ($interface) = @_;
    my $fh;
    if (!open ($fh, '-|', $DHCPLEASECTL, '-l', $interface)) {
        return {status => 'err', reason => "cannot run dhcpleasectl: $!"};
    }
    my $output = '';
    while (<$fh>) { $output .= $_; }
    close ($fh);
    
    # Match existing parsing logic from old get_dhcplease_info
    if ($output =~ /inet (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) netmask (\d+\.\d+\.\d+\.\d+).*default gateway (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*lease (\d+) (hours|minutes)/s) {
        return {
            status => 'ok',
            ip => $1,
            netmask => $2,
            gateway => $3,
            lease_time => int($4),
            units => $5,
        };
    }
    else {
	logmsg('alert', "Could not parse dhcpleasectl output - format may have changed");
        return {status => 'err', reason => 'cannot parse dhcpleasectl output'};
    }
}

## Client-side subroutines (nonprivileged side, makes requests for privileged operations).

# Subroutine to send a request.
sub helper_request {
    my (%args) = @_;
    
    if (!defined $helper_sock) {
        # No helper - either Step 2 in-process mode or monitor-only mode
        # In monitor-only mode, this shouldn't be called for state-changing ops
        # In Step 2, fall back to direct dispatch
        my $json_str = encode_json(\%args);
        return dispatch_command(decode_json($json_str));
    }

    # Ignore SIGPIPE locally; convert write failures to error returns
    local $SIG{PIPE} = 'IGNORE';
    local $SIG{ALRM} = sub { die "helper timeout\n"; };
    alarm(30);  # 30 seconds max for any helper operation

    my $line;

    eval {
	my $written = print $helper_sock encode_json(\%args) . "\n";
	if (!$written) {
	    die "helper write failed: $!\n";
	}
	$line = <$helper_sock>;
    };
    alarm(0);

    if ($@) {
        logmsg('alert', "Helper request failed, exiting: $@");
        die "Lost connection to privileged helper\n";
    }
    
    if (!defined $line) {
        logmsg('alert', 'Helper communication failed: no response, exiting.');
        die "Lost connection to privileged helper, exiting.\n";
    }
    chomp $line;
    my $resp;
    eval { $resp = decode_json($line); };
    if ($@) {
        logmsg('alert', "Invalid JSON response from helper: $line");
        return {status => 'err', reason => 'invalid JSON response'};
    }
    return $resp;
}

# Subroutine to return 1 if request returned successfully.
sub helper_ok {
    my (%args) = @_;
    my $resp = helper_request (%args);
    return $resp->{status} eq 'ok';
}

# Wrapper to mirror run_cmd interface - logs failures and returns 0/1
# Will migrate from run_cmd to helper_cmd, then get rid of run_cmd.
sub helper_cmd {
    my ($description, $log_failure, %args) = @_;
    my $resp = helper_request (%args);
    if ($resp->{status} ne 'ok') {
        my $reason = $resp->{reason} // 'unknown';
        my $msg = "Failed: $description: $reason";
        if ($log_failure) {
            logmsg ('alert', $msg);
        }
        else {
            print "$msg\n" if ($DEBUG);
        }
        return 0;
    }
    return 1;
}

# Initialize states with up, since current moment.
sub initialize_states {
    my ($ip, $idx);

    print "Entering sub initialize_states.\n" if ($DEBUG);
    $ip = gateway_ip();
    $current_gateway = gate_index ($ip);
    print "Current gateway is $current_gateway ($ip).\n" if ($DEBUG);

    if ($current_gateway == -1) {
	logmsg ('alert', "Current gateway ($ip) is not in faild.pl configuration.");
	send_page ("faild.pl: Current gateway ($ip) is not in faild.pl configuration.");
    }

    for ($idx = 0; $idx <= $#GATEWAYS; $idx++) {
	$current_state[$idx] = $UP;
	$state_time[$idx] = time();
	$pings_down[$idx] = 0;
    }

    logmsg ("info", "started");
}

sub acquire_pid_lock {
    # Open and lock the PID file. Must be called before daemonize().
    open (PID, '+>>', $FAILD_PID) || die "Cannot open PID file. $! $FAILD_PID\n";
    if (!flock (PID, 2 | 4)) {  # LOCK_EX | LOCK_NB
        die "Another instance of faild.pl is already running.\n";
    }
}


# Daemonize: detach from controlling terminal and redirect standard fds
sub daemonize {
    # Fork; parent exits
    my $pid = fork();
    die "Cannot fork: $!\n" if (!defined $pid);
    exit (0) if ($pid != 0);  # parent exits
    
    # Child: become session leader
    POSIX::setsid() || die "Cannot setsid: $!\n";
    
    # Redirect standard file descriptors to /dev/null
    open (my $devnull, '+<', '/dev/null') || die "Cannot open /dev/null: $!\n";
    POSIX::dup2 (fileno($devnull), 0);
    POSIX::dup2 (fileno($devnull), 1);
    POSIX::dup2 (fileno($devnull), 2);
    close ($devnull);
    
    # Optionally chdir to / to avoid holding the cwd
    # If you do this, you must unveil /.
    # chdir ('/');
}

sub prepare_state_files_for_user {
    my ($uid, $gid) = @_;
    foreach my $file ($FAILD_INFO, $FAILD_PID) {
        # Create if missing, using O_NOFOLLOW to prevent symlink attacks
        my $fh;
        if (!sysopen($fh, $file, O_RDWR | O_CREAT | O_NOFOLLOW, 0644)) {
            die "Cannot open $file: $!\n";
        }
        close($fh);
        # Verify it's a regular file (not a symlink, hardlink we shouldn't touch, etc.)
        my @st = lstat($file);
        if (!@st || !-f _) {
            die "$file is not a regular file\n";
        }
	if ($st[3] > 1) { # nlink > 1 means there are hard links
	    die "$file has hard links - possible attack\n";
	}
        chown($uid, $gid, $file) or die "Cannot chown $file: $!";
        chmod(0644, $file);
    }
}

sub write_pid {
    # Write our PID to the already-locked file. Must be called after daemonize()
    # so that the child's PID (not the parent's) is recorded.
    seek (PID, 0, 0);
    truncate (PID, 0);
    print PID "$$\n";
    PID->flush() if PID->can('flush');
    # Do NOT close PID - keeping it open maintains the flock
}

sub read_faild_info {
    my ($ip, $state, $saved_time, $idx, $gateway_count);

    print "Entering sub read_faild_info.\n" if ($DEBUG);

    $gateway_count = 0;
    $more_gateways_than_recorded = 0;

    if (open (FAILD_INFO, '<', $FAILD_INFO)) {
	while (<FAILD_INFO>) {
	    chomp;
	    $gateway_count++;
	    ($ip, $state, $saved_time) = split (/,\s+/);
	    $idx = gate_index ($ip);
	    if ($idx >= 0) {
		$current_state[$idx] = $state;
		$state_time[$idx] = $saved_time;
	    }
	}
	close (FAILD_INFO);
    }
    $more_gateways_than_recorded = 1 if ($gateway_count < scalar (@GATEWAYS));
}

sub write_faild_info {
    my ($idx);

    print "Entering sub write_faild_info.\n" if ($DEBUG);

    if (!open (FAILD_INFO, '>', $FAILD_INFO)) {
        logmsg ('alert', "Cannot open $FAILD_INFO for writing: $!");
        return;
    }
    for ($idx = 0; $idx <= $#GATEWAYS; $idx++) {
	print FAILD_INFO "$GATEWAYS[$idx], $current_state[$idx], $state_time[$idx]\n";
    }
    if (!close (FAILD_INFO)) {
        logmsg ('alert', "Error closing $FAILD_INFO.tmp: $!");
        return;
    }
}

# Set new_state for all gateways as up or down.  No test is performed
# for on-demand gateways not in use but believed to be up.
sub ping_gateways {
    my ($idx);

    print "Entering sub ping_gateways.\n" if ($DEBUG);

    for ($idx = 0; $idx <= $#GATEWAYS; $idx++) {
	$gate_type_name = $GATE_TYPE_NAME[$GATE_TYPE[$idx]];
	if (ping_host ($PING_IPS[$idx], $PING_TIMEOUT)) {
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
		if (ping_host ($PING_IPS[$idx], $PING_TIMEOUT)) {
		    $new_state[$idx] = $UP;
		    print "$gate_type_name $idx ($GATEWAYS[$idx]) is up on the $PING_NAME{$n_pings} ping.\n" if ($DEBUG);
		    logmsg ('alert', "$gate_type_name $idx ($GATEWAYS[$idx]) is up on the $PING_NAME{$n_pings} ping.") if ($n_pings > $N_PINGS_TO_NOTIFY);
		    last;
		}
		else {
		    print "$gate_type_name $idx ($GATEWAYS[$idx]) is down on the $PING_NAME{$n_pings} ping.\n" if ($DEBUG);
		    logmsg ('alert', "$gate_type_name $idx ($GATEWAYS[$idx]) is down on the $PING_NAME{$n_pings} ping.") if ($n_pings > $N_PINGS_TO_NOTIFY);
		    $pings_down[$idx] = $n_pings;
		}
	    }
	}
    }
}

# Subroutine to return dhcpleased information for an interface.
sub get_dhcplease_info {
    my ($interface) = @_;
    my $resp = helper_request (cmd => 'DHCPLEASECTL_INFO', interface => $interface);
    if ($resp->{status} ne 'ok') {
        return (undef, undef, undef, undef, undef);
    }
    return ($resp->{ip}, $resp->{netmask}, $resp->{gateway}, 
            $resp->{lease_time}, $resp->{units});
}

# Subroutine to report any state changes and failover to another
# gateway if necessary and possible.
sub report_and_failover {
    my ($changes_occurred, $duration, $plural);
    my ($interface_ip, $netmask, $gateway_ip, $lease_time, $units);
    my ($prior_gateway);

    print "Entering sub report_and_failover.\n" if ($DEBUG);

    # Report changes that have occurred.
    $changes_occurred = 0;
    for (my $idx = 0; $idx <= $#GATEWAYS; $idx++) {
	$gate_type_name = $GATE_TYPE_NAME[$GATE_TYPE[$idx]];

	# Check DHCP lease info for changes and expiring leases.
	if (($GATE_TYPE[$idx] == $DEDICATED_DHCPLEASE_PRIMARY
	     || $GATE_TYPE[$idx] == $DEDICATED_DHCPLEASE_BACKUP)
	    && defined ($INTERFACES[$idx])
	    && $new_state[$idx] == $UP) {
	    ($interface_ip, $netmask, $gateway_ip, $lease_time, $units) =
		get_dhcplease_info ($INTERFACES[$idx]);

	    # Renew lease first if expiration is imminent (safety net for stuck dhcpleased).
	    if (defined ($lease_time) && defined ($units)) {
		my $minutes_remaining;
		if ($units eq 'hours') {
		    $minutes_remaining = $lease_time * 60;
		}
		elsif ($units eq 'minutes') {
		    $minutes_remaining = $lease_time;
		}
		if (defined ($minutes_remaining) && $minutes_remaining <= 5) {
		    helper_cmd ("renew DHCP lease on $INTERFACES[$idx]", 1,
				cmd => 'DHCPLEASECTL_RENEW', interface => $INTERFACES[$idx]);
		    # Give dhcpleased time to process the renewal and update its info.
		    sleep 10;
		    # Re-fetch lease info after renewal.
		    ($interface_ip, $netmask, $gateway_ip, $lease_time, $units) =
			get_dhcplease_info ($INTERFACES[$idx]);
		}
	    }

	    # Check for IP/gateway changes (catches changes from dhcpleased's
	    # automatic renewals as well as our forced renewal above).
	    if (defined ($interface_ip) && defined ($gateway_ip)) {
		if (defined ($last_interface_ip[$idx]) && 
		    ($interface_ip ne $last_interface_ip[$idx] ||
		     $netmask ne $last_netmask[$idx] ||
		     $gateway_ip ne $last_gateway_ip[$idx])) {
		    # Flush states for old gateway IP.
		    helper_cmd ("flush pf states for $last_gateway_ip[$idx]", 1,
				cmd => 'PFCTL_FLUSH_STATES', ip => $last_gateway_ip[$idx]);
		    # If this is a backup gateway not currently in use, also delete
		    # the stale default route for the old IP (dhcpleased may have
		    # added a new one for the new IP, and we don't want both lingering).
		    if ($idx != $current_gateway && 
			$GATE_TYPE[$idx] == $DEDICATED_DHCPLEASE_BACKUP) {
			helper_cmd ("delete stale default route for old IP $last_gateway_ip[$idx]", 0,
				    cmd => 'ROUTE_DELETE_DEFAULT', ip => $last_gateway_ip[$idx]);
		    }
		    # If this gateway is currently in use, the default route needs to
		    # be updated to point to the new gateway IP.
		    elsif ($idx == $current_gateway) {
			helper_cmd ("change default route to new IP $gateway_ip", 1,
				    cmd => 'ROUTE_CHANGE_DEFAULT', ip => $gateway_ip);
		    }
		    # Also update the stored GATEWAYS and PING_IPS if they match the old IP.
		    # This handles the case where the config specifies the dhcp-assigned IP
		    # itself as the ping target.
		    if ($GATEWAYS[$idx] eq $last_gateway_ip[$idx]) {
			$GATEWAYS[$idx] = $gateway_ip;
		    }
		    if ($PING_IPS[$idx] eq $last_gateway_ip[$idx]) {
			$PING_IPS[$idx] = $gateway_ip;
		    }
		    my $message = "DHCP lease changed for $gate_type_name $idx: " .
			"interface IP $last_interface_ip[$idx]->$interface_ip, " .
			"netmask $last_netmask[$idx]->$netmask, " .
			"gateway $last_gateway_ip[$idx]->$gateway_ip.";
		    logmsg ('alert', $message);
		    print "$message\n" if ($DEBUG);
		    send_page ("faild.pl: $message");
		}
		# Update tracked values.
		$last_interface_ip[$idx] = $interface_ip;
		$last_netmask[$idx] = $netmask;
		$last_gateway_ip[$idx] = $gateway_ip;
	    }

	    # Remove default route if this is a backup that is not the current
	    # gateway -- dhcpleased may have added it (assuming multipath routing).
	    if (defined ($gateway_ip) &&
		$idx != $current_gateway && 
		$GATE_TYPE[$idx] == $DEDICATED_DHCPLEASE_BACKUP) {
		helper_cmd ("delete default route for $gateway_ip", 0,
			    cmd => 'ROUTE_DELETE_DEFAULT', ip => $gateway_ip);
	    }
	}

	if ($current_state[$idx] != $new_state[$idx]) {
	    $changes_occurred = 1;
	    $duration = time() - $state_time[$idx];
	    $duration = int ($duration / 60);
	    $plural = 's';
	    $plural = '' if ($duration == 1);
	    if ($new_state[$idx] == $UP) {
		logmsg ('alert', "$gate_type_name $idx ($GATEWAYS[$idx]) is again reachable (down $duration minute$plural), $pings_down[$idx] failed pings.");
		$pings_down[$idx] = 0; # reset counter
		print "$gate_type_name $idx ($GATEWAYS[$idx]) is again reachable (down $duration minute$plural).\n" if ($DEBUG);
		if ($duration > 15) {
		    send_page ("faild.pl: $gate_type_name $idx ($GATEWAYS[$idx]) is again reachable (down $duration minute$plural).");
		}
		# A newly up gateway that we may or may not be switching to,
		# depending on whether multiple were down.  We may end up
		# using it, which is handled further below.
		# If there are specific routes to add, let's do that.
		if (defined ($ROUTES[$idx])) {
		    add_routes ($ROUTES[$idx], $gateway_ip);
		    my $message = "Added routes for $gate_type_name $idx.";
		    logmsg ('alert', $message);
		    print "$message\n" if ($DEBUG);
		    send_page ("faild.pl: $message");
		}
		# We want to delete default route if it's a backup, unless we
		# need it.
		if ($idx != $current_gateway && $GATE_TYPE[$idx] == $DEDICATED_DHCPLEASE_BACKUP) {
		    helper_cmd ("delete default route for backup $gateway_ip", 0,
				cmd => 'ROUTE_DELETE_DEFAULT', ip => $gateway_ip);
		}
	    }
	    else {
		logmsg ('alert', "$gate_type_name $idx ($GATEWAYS[$idx]) has gone down (up $duration minute$plural).");
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
	    logmsg ('alert', "$gate_type_name $idx ($GATEWAYS[$idx]) has been down for $duration minute$plural.");
	    print "$gate_type_name $idx ($GATEWAYS[$idx]) has been down for $duration minute$plural.\n" if ($DEBUG);
	    if ($duration % 15 == 0 && $duration < 61) {
		send_page ("faild.pl: $gate_type_name $idx ($GATEWAYS[$idx]) has been down for $duration minutes.");
	    }
	    # Add permanent routes if missing while down -- necessary to make
	    # sure test pings still go out the right interface.
	    if (defined ($ROUTES[$idx])) {
		add_missing_perm_routes ($ROUTES[$idx], $GATEWAYS[$idx]);
	    }
	    # Delete specific routes for outage of more than five minutes if
	    # defined.
	    if ($duration == 5 && defined ($ROUTES[$idx])) {
		my $message = "Deleting routes for $gate_type_name $idx after five minutes of outage.";
		logmsg ('alert', $message);
		print "$message\n" if ($DEBUG);
		send_page ("faild.pl: $message");
		delete_routes ($ROUTES[$idx]);
	    }
	}
    }

    # If changes occurred or states haven't been written out before,
    # or if there are some new gateways not already recorded,
    # write out new states.
    if ($changes_occurred || !-e $FAILD_INFO || $more_gateways_than_recorded) {
	write_faild_info;
    }

    # Calculate how long the current gateway has been down.
    $duration = 0;
    if ($new_state[$current_gateway] == $DOWN && defined($state_time[$current_gateway])) {
	$duration = (time() - $state_time[$current_gateway]) / 60;  # minutes
    }

    # If current gateway is down, look for one to failover to.
    # If current gateway is not the primary, look for a higher-priority
    # gateway to fail back to.
    $changes_occurred = 0;
    $prior_gateway = $current_gateway;

    # Determine if failback is possible (a higher-priority gateway is up)
    my $failback_possible = 0;
    for (my $idx = 0; $idx < $current_gateway; $idx++) {
	if ($new_state[$idx] == $UP && $GATE_TYPE[$idx] != $HOST_CHECK) {
	    $failback_possible = 1;
	    last;
	}
    }

    if (($new_state[$current_gateway] == $DOWN &&
	 $duration >= $FAILOVER_DELAY_MINUTES) ||
	$failback_possible) {
	for (my $idx = 0; $idx <= $#GATEWAYS; $idx++) {
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
		    logmsg ('alert', "Failing back from gateway $current_gateway ($GATEWAYS[$current_gateway]) to gateway $idx ($GATEWAYS[$idx]).");
		    print "Failing back from gateway $current_gateway ($GATEWAYS[$current_gateway]) to gateway $idx ($GATEWAYS[$idx]).\n" if ($DEBUG);
		    send_page ("faild.pl: Failing back from gateway $current_gateway ($GATEWAYS[$current_gateway]) to gateway $idx ($GATEWAYS[$idx]).");
		    $current_gateway = $idx;
		}
		elsif ($idx > $current_gateway) {
		    if ($current_gateway == -1) {
			logmsg ('alert', "Starting up with gateway $idx ($GATEWAYS[$idx]).");
			print "Starting up with gateway $idx ($GATEWAYS[$idx]).\n";
		    }
		    else {
			logmsg ('alert', "Failing over from gateway $current_gateway ($GATEWAYS[$current_gateway]) to gateway $idx ($GATEWAYS[$idx]).");
			print "Failing over from gateway $current_gateway ($GATEWAYS[$current_gateway]) to gateway $idx ($GATEWAYS[$idx]).\n" if ($DEBUG);
			send_page ("faild.pl: Failing over from gateway $current_gateway ($GATEWAYS[$current_gateway]) to gateway $idx ($GATEWAYS[$idx]).");
		    }
		    $current_gateway = $idx;
		}
		else {
		    logmsg ('alert', "Primary and current gateway $current_gateway ($GATEWAYS[$current_gateway]) is back up.");
		    print "Primary and current gateway $current_gateway ($GATEWAYS[$current_gateway]) is back up.\n" if ($DEBUG);
		    send_page ("faild.pl: Primary and current gateway $current_gateway ($GATEWAYS[$current_gateway]) is back up.");
		}

		# We found something to switch to.
		$changes_occurred = 1;

		# Change routing to new gateway.
		if ($PERFORM_FAILOVER && ($GATE_TYPE[$idx] == $DEDICATED ||
					  $GATE_TYPE[$idx] == $DEDICATED_DHCPLEASE_PRIMARY ||
					  $GATE_TYPE[$idx] == $DEDICATED_DHCPLEASE_BACKUP)) {

		    # Change default route.  (Might need to add if there isn't one.)
		    # Try change first, then add - one of these will succeed depending on
		    # whether a default route already exists.
		    my $changed = helper_cmd ("change default route to $GATEWAYS[$idx]", 0,
					      cmd => 'ROUTE_CHANGE_DEFAULT', ip => $GATEWAYS[$idx]);
		    my $added = helper_cmd ("add default route to $GATEWAYS[$idx]", 0,
					    cmd => 'ROUTE_ADD_DEFAULT', ip => $GATEWAYS[$idx]);
		    if (!$changed && !$added) {
			logmsg ('alert', "Failed to set default route to $GATEWAYS[$idx] (both change and add failed)");
		    }

		    # Flush routes from prior gateway unless it has specific routes defined.
		    if (defined ($ROUTES[$prior_gateway])) {
			delete_routes ($ROUTES[$prior_gateway]);
		    }
		    else {
			if (defined ($INTERFACES[$prior_gateway])) {
			    helper_cmd ("flush routes for interface $INTERFACES[$prior_gateway]", 1,
					cmd => 'ROUTE_FLUSH_IFACE', interface => $INTERFACES[$prior_gateway]);
			}
		    }
		    # Flush pf states for prior gateway.
		    helper_cmd ("flush pf states for $GATEWAYS[$prior_gateway]", 1,
				cmd => 'PFCTL_FLUSH_STATES', ip => $GATEWAYS[$prior_gateway]);
		    
		}
		last;
	    } # found up gateway
	} # for loop
    } # current gateway down or not on primary gateway

    # If there is more than one gateway and all are down, note that.
    if ($#GATEWAYS > 0 &&
	!$changes_occurred &&
	$new_state[$current_gateway] == $DOWN) {
	# Check if there are actually any UP gateways (excluding HOST_CHECK)
	my $any_gateway_up = 0;
	for (my $idx = 0; $idx <= $#GATEWAYS; $idx++) {
	    if ($new_state[$idx] == $UP && $GATE_TYPE[$idx] != $HOST_CHECK) {
		$any_gateway_up = 1;
		last;
	    }
	}
	if (!$any_gateway_up) {
	    logmsg ('alert', "All available gateways are down.");
	    print "All available gateways are down.\n" if ($DEBUG);
	}
    }
}

# Subroutine to return IP address of current gateway.
sub gateway_ip {
    my ($ip);

    if (!open (ROUTE, '-|', $ROUTE, '-n', 'show')) {
        logmsg ('alert', "Cannot run $ROUTE -n show: $!");
        return undef;
    }
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

# Subroutine to add routes. IPv4 only
sub add_routes {
    my ($routes, $gateway_ip) = @_;
    my (@route_array, $route);

    @route_array = split (/,/, $routes);
    foreach $route (@route_array) {
	$route =~ s/P$//; # remove P for permanent routes
	helper_cmd ("add route $route via $gateway_ip", 0,
		    cmd => 'ROUTE_ADD', cidr => $route, gateway => $gateway_ip);
    }
}

# Subroutine to delete routes. IPv4 only
sub delete_routes {
    my ($routes) = @_;
    my (@route_array, $route);

    @route_array = split (/,/, $routes);
    foreach $route (@route_array) {
	next if $route =~ /P$/; # do not remove permanent routes
	helper_cmd ("delete route $route", 0,
		    cmd => 'ROUTE_DELETE', cidr => $route);
    }
}

# Subroutine to add permanent routes if missing. IPv4 only
sub add_missing_perm_routes {
    my ($routes, $gateway_ip) = @_;
    my (@route_array, $route);

    @route_array = split (/,/, $routes);
    foreach $route (@route_array) {
	next if $route !~ /P$/; # ignore non-permanent routes
	$route =~ s/P$//; # remove P for permanent routes
	if (!route_present ($route, $gateway_ip)) {
	    if (helper_cmd ("add missing permanent route $route via $gateway_ip", 1,
			    cmd => 'ROUTE_ADD', cidr => $route, gateway => $gateway_ip)) {
		my $message = "Added missing permanent route $route for $gateway_ip.";
		logmsg ('alert', $message);
		print "$message\n" if ($DEBUG);
		send_page ("faild.pl: $message");
	    }
	}
    }
}

# Subroutine to identify if a route is present with a given gateway.
sub route_present {
    my ($route, $gateway_ip) = @_;
    my ($route_result, $route_minus_cidr, $dest_result, $gateway_result);

    if (!open (ROUTE, '-|', $ROUTE, '-n', 'get', $route)) {
	logmsg ('alert', "Cannot run $ROUTE -n get $route: $!");
	return 0;
    }
    # could also check interface, flags (for up/down)
    while (<ROUTE>) {
	if (/destination: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/) {
	    $dest_result = $1;
	}
	elsif (/gateway: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/) {
	    $gateway_result = $1;
	}
    }
    close (ROUTE);

    $route_minus_cidr = $route;
    $route_minus_cidr =~ s/\/\d+$//;

    # is it necessary to delete the route if it's pointing to the wrong
    # gateway?
    return 1 if (defined ($dest_result) && $dest_result eq $route_minus_cidr
		 && defined ($gateway_result) && $gateway_result eq $gateway_ip);
    return 0;
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
    if (!open (MAIL, '|-', $SENDMAIL, '-t')) {
        logmsg ('alert', "Cannot run sendmail: $!");
        return;
    }
    print MAIL "From: $PAGE_SOURCE\n";
    print MAIL "To: $PAGE_DESTINATION\n\n";
    print MAIL "$msg\n";
    close (MAIL);
}

# Ping gateways or hosts.
# Send a single ICMP ping using /sbin/ping. Returns 1 on success, 0 on failure.
# This replaces Net::Ping which requires raw sockets (root privileges).
sub ping_host {
    my ($ip, $timeout) = @_;
    $timeout //= 1;
    
    # Validate IP before passing to system command (defense in depth)
    return 0 unless ($ip =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/);
    
    my $pid = fork();
    if (!defined $pid) {
        logmsg ('alert', "fork failed for ping: $!");
        return 0;
    }
    if ($pid == 0) {
        # Child: redirect stdout/stderr to /dev/null and exec ping
        open (my $devnull, '+<', '/dev/null') or exit (1);
        POSIX::dup2 (fileno($devnull), 0);
        POSIX::dup2 (fileno($devnull), 1);
        POSIX::dup2 (fileno($devnull), 2);	
	close ($devnull);
        exec ($PING, '-c', '1', '-w', $timeout, '-q', $ip);
        exit (1);  # only reached if exec fails
    }
    # Parent: wait for ping to complete
    waitpid ($pid, 0);
    return ($? == 0) ? 1 : 0;
}
