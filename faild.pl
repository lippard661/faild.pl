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
# distinctive_ping_len: [bytes] (optional, default may vary by OS)
# distinctive_ping_ttl: [hop count, default 255] (optional)
# distinctive_ping_tos: [TOS options, default none]
# distinctive_ping_frequency: [minutes]
# state_dir: <dir> (optional, default /var/db)
# pid_dir: <dir> (optional, default /var/run)
# # Then as many of these stanzas as you want, each starting with gateway:
# gateway: <ip> (IPv4, or IPv6 for the ipv6-* types; must come first)
# name: <name> (optional, unique; used in alerts and by depends_on)
# depends_on: <name>[, <name>...] (optional, alert enrichment only)
# distinctive_pings: <yes|no> (optional, type host only)
# gateway_table: <pf-table-name> (optional, populated with next-hop gateway)
# dynamic_dping_table: <pf-table-name> (optional, populated with distinctive ping destinations while the associated gateway is up, removed when it's down)
# interface: <interface name> [optional, but needed for dhcplease]
# routes: <cidr>, <cidr>, <cidr> [optional only for dhcplease, use "P" after
#    cidr for permanent route that should not be removed if gateway goes down
# ping_ip: <ip>[, <ip>[, <ip>]] (up to 3 IPs)
#         If multiple IPs are specified, the gateway is considered up if
#         a ping to ANY of them succeeds. This allows tolerating individual
#         ping target outages.
# type: <dedicated|dedicated-dhcplease-primary|dedicated-dhcplease-backup|host|ipv6-pd|ipv6-tunnel>
#    ipv6-pd requires interface: (the dhcp6leased interface) and runs as root.

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
# 1.21 16 May 2026: Issues corrected after Claude, ChatGPT, and Gemini reviews;
#      each identified different issues and some very minor (and sometimes
#      incorrect for various reasons).
# 1.22 7 June 2026: Remove logmsg call from get_dhcp_info which is on the priv
#      helper side; then went ahead and made get_dhcp_info more resilient to
#      different format lease times.
# 1.23 20 June 2026: Move state file to /var/db by default for persistence
#      over reboots, make pid_dir configurable.
# 1.24 24 June 2026: Allow multiple ping IPs.
# 1.25 30 June 2026: Fix bugs after Claude Opus 4.8 review.
# 1.26 15 July 2026: Change route handling to add missing routes at start.
# 1.27 28 July 2026: Add distinctive pinging features.
# 1.28 31 July 2026: Add name, gateway_table, dynamic_dping_table.
# 1.29 1 August 2026: Update error message when run as non-privileged
#    when pf table integration is used and add table existence check.
# 1.30 8 August 2026: Add IPv6 monitoring: type: ipv6-tunnel and ipv6-pd
#    entries (ping6 liveness, plus delegated-prefix change detection via
#    dhcp6leasectl for ipv6-pd), and the depends_on alert-enrichment field.
# 1.31 26 August 2026: Add -n config-test mode; ignore SIGHUP (no reload
#    path -- use restart for config or version changes).
# 1.32 29 August 2026: Add subject with hostname to mailed/texted notifications.
# 1.33 11 October 2026: Modified by Claude Opus 5.5 at the direction of Jim
#    Lippard after review. Security: the privileged helper now ignores SIGHUP
#    (previously only the monitor did, so a HUP to "faild [priv]" killed it
#    and took the monitor down with it); privileged-side validators anchor
#    with \z. IPv6 PD: last-seen prefix persisted in state_dir so a change
#    across a restart is paged; dhcp6leasectl failures and a delegation that
#    stays non-Bound for 15 minutes are alerted (once, plus recovery);
#    ipv6-pd now requires the privileged helper. -n now runs every startup
#    check, not just the parse. Lease-time parsing no longer turns an
#    unrecognized format into 0 (which forced a renewal every cycle). IPv6
#    entry states restored from faild.info. Pings are bounded by a watchdog;
#    Linux uses ping -6 when there is no ping6. Config: fields before the
#    first gateway: are rejected, duplicate name:/ipv6-pd interfaces
#    rejected, sendmail failures logged.
# 1.34 11 October 2026: Modified by Claude Opus 5.5 at the direction of Jim
#    Lippard. Fix 1.33's false "/sbin/ping6 is not executable" on OpenBSD:
#    Perl's -x is a stat(2), which needs unveil read permission, so ping6 and
#    dhcp6leasectl are now unveiled rx (exec alone does not allow stat).
#    -n now runs under the same pledge and unveil as startup (before, it ran
#    outside them and passed what startup then failed). A non-default
#    state_dir/pid_dir is unveiled before parse_config tests that it exists.

# ToDo: Some former "constants" are now variables from the config and should
# consider moving them to the variables section and making them all
# lowercase names.

### Required packages.

use strict;
use warnings;
use base; # required by Privileges::Drop;
use English; # required by Privileges::Drop;
use Fcntl qw( :DEFAULT :flock O_NOFOLLOW );
use IO::Handle;
use JSON::PP;
use POSIX;
use Privileges::Drop;
use Socket qw( AF_UNIX SOCK_STREAM PF_UNSPEC AF_INET6 inet_pton inet_ntop );
use Sys::Hostname;
use Sys::Syslog;

use if $^O eq "openbsd", "OpenBSD::Pledge";
use if $^O eq "openbsd", "OpenBSD::Unveil";

### Constants.

my $VERSION = 'faild.pl 1.34 of 11 October 2026';

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
my $IPV6_TUNNEL = 5;        # monitoring only: ping6 a tunnel far-side
my $IPV6_PD = 6;           # monitoring only: ping6 liveness + PD prefix watch
my @GATE_TYPE_NAME = ('',
		      'Gateway',
		      'Gateway (DHCP primary)',
		      'Gateway (DHCP backup)',
		      'Host',
		      'IPv6 tunnel',
		      'IPv6 prefix delegation');

my $HOSTNAME = hostname();
my ($SHORT_HOSTNAME, $DOMAINNAME) = split (/\./, $HOSTNAME, 2);

my $UP = 1;
my $DOWN = 0;

my $ALL_ROUTES = 1;
my $PERM_ONLY = 0;

# User-configurable.
my $DEBUG = 0;

my $PERFORM_FAILOVER = 0;

# Minutes an ipv6-pd entry may go without a usable Bound delegation (or with
# dhcp6leasectl failing) before alerting. Transient non-Bound states during a
# renewal are normal and shorter than this.
my $PD_UNBOUND_ALERT_MINUTES = 15;

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

# Map of TOS keywords to their numeric TOS-byte value (0-255). OpenBSD's ping
# accepts these keywords directly via -T, but Linux (-Q) and macOS (-z) only
# accept a number, so we use this map to translate. The AF and CS values are
# generated so the DSCP-to-byte arithmetic (DSCP << 2) can't be mistyped.
my %KEYWORD_TOS = (
    critical    => 0xa0, # 160, IPTOS_PREC_CRITIC_ECP
    inetcontrol => 0xc0, # 192, IPTOS_PREC_INTERNETCONTROL
    lowdelay    => 0x10, #  16, IPTOS_LOWDELAY
    netcontrol  => 0xe0, # 224, IPTOS_PREC_NETCONTROL
    throughput  => 0x08, #   8, IPTOS_THROUGHPUT
    reliability => 0x04, #   4, IPTOS_RELIABILITY
    ef          => 46 << 2, # 184, Expedited Forwarding (DSCP 46)
    );
# cs0..cs7: class selector, DSCP = idx*8, byte = DSCP << 2.
foreach my $idx (0 .. 7) {
    $KEYWORD_TOS{"cs$idx"} = ($idx * 8) << 2;
}
# af11..af43: DSCP = 8*class + 2*drop, byte = DSCP << 2.
foreach my $class (1 .. 4) {
    foreach my $drop (1 .. 3) {
        $KEYWORD_TOS{"af$class$drop"} = ((8 * $class + 2 * $drop) << 2);
    }
}

my (@GATEWAYS, @INTERFACES, @ROUTES, @PING_IPS, @GATE_TYPE, @DISTINCTIVE_PINGS);
my (@NAMES, @GATEWAY_TABLE, @DYNAMIC_DPING_TABLE);
# IPv6 monitoring state: @DEPENDS_ON holds an arrayref of entry names each entry
# depends on (alert enrichment only, never control flow). @LAST_PREFIX holds the
# last canonicalized delegated prefix seen for a PD entry, for change detection.
my (@DEPENDS_ON, @LAST_PREFIX);
# @LAST_PREFIX is persisted in $FAILD_PREFIX_INFO so a change that happens
# while faild is not running (e.g., a reboot after a power failure, which
# forces a fresh DHCPv6 solicit) is still detected. Per-run PD bookkeeping:
# @PD_PROBLEM_SINCE/@PD_PROBLEM_ALERTED track how long an entry has gone
# without a usable delegation; @PD_SEEN_THIS_RUN marks the first reading
# since startup; @PD_MULTI_NOTED limits the multiple-IA_PD note to once.
my (@PD_PROBLEM_SINCE, @PD_PROBLEM_ALERTED, @PD_SEEN_THIS_RUN, @PD_MULTI_NOTED);
# Whitelist of pf table names faild is allowed to manage, built in parse_config
# (which runs as root before the privsep fork), so the privileged helper can
# screen table-op requests against it independently of the monitor side.
my %MANAGED_TABLES;

my $FAILD_CONF = '/etc/faild.conf';
my $STATE_DIR = '/var/db'; # default
my $PID_DIR = '/var/run'; # default
my $FAILD_INFO; # default = '/var/db/faild.info';
my $FAILD_PID; # default = '/var/run/faild.pid';
my $FAILD_PREFIX_INFO; # default = '/var/db/faild.prefix'; used only with ipv6-pd

my $DHCPLEASECTL = '/usr/sbin/dhcpleasectl';
my $DHCP6LEASECTL = '/usr/sbin/dhcp6leasectl';
my $PFCTL = '/sbin/pfctl';
my $PING = '/sbin/ping';
$PING = '/usr/bin/ping' if ($^O eq 'linux'); # Linux not supported for routing
my $PING6 = '/sbin/ping6';
# Leading arguments for $PING6. Current iputils on many Linux distributions
# ships no separate ping6; there, use ping -6 instead.
my @PING6_PREFIX = ();
if ($^O eq 'linux') {
    $PING6 = '/usr/bin/ping6';
    if (!-x $PING6 && -x $PING) {
	$PING6 = $PING;
	@PING6_PREFIX = ('-6');
    }
}
my $ROUTE = '/sbin/route';
my $SENDMAIL = '/usr/sbin/sendmail';

my $SYSLOG_FACILITY = 'daemon';

my ($PAGE_SOURCE, $PAGE_DESTINATION);

### Variables.

my ($current_gateway, @current_state, @new_state, @state_time, @pings_down);
my ($gate_type_name, $more_gateways_than_recorded);
my (@last_interface_ip, @last_netmask, @last_gateway_ip);
my ($distinctive_ping_len, $distinctive_ping_ttl, $distinctive_ping_tos,
    $distinctive_ping_frequency);
my $distinctive_pings_enabled = 0; # set true by parse_config if any host uses it
my ($faild_uid, $faild_gid);
my $helper_sock; # for privilege separation
my $starting_up;
my $first_cycle = 1;


### Main program.

my $config_test = 0;
if ($#ARGV == 0) {
    if ($ARGV[0] eq '-v') {
	print "$VERSION\n";
	exit;
    }
    elsif ($ARGV[0] eq '-n') {
	# Config-test mode: handled below, after pledge and unveil, so that it
	# runs under exactly the same restrictions as real startup.
	$config_test = 1;
    }
    else {
	die "Usage: faild.pl [-v|-n]\n";
    }
}

umask 022; # rw-r-r-

# Pledge, Unveil. The restriction takes effect at the first unveil() call,
# not when the list is locked. Binaries that startup_checks() tests with -x
# are unveiled 'rx', not just 'x': Perl's -x is a stat(2), and on OpenBSD
# stat needs read permission on an unveiled path, so with 'x' alone -x
# returns false for a binary that execs fine (1.33's "/sbin/ping6 is not
# executable" on a host where it plainly was).
if ($^O eq "openbsd") {
    pledge (@STARTUP_PROMISES) || die "Cannot pledge promises. $!\n";
    unveil ($FAILD_CONF, 'r');
    unveil ('/etc', 'r');
    unveil ($STATE_DIR, 'rwc');
    unveil ($PID_DIR, 'rwc');
    unveil ('/dev/log', 'rw');
    unveil ('/dev/null', 'rw');
    unveil ($DHCPLEASECTL, 'x');
    unveil ($DHCP6LEASECTL, 'rx');  # -x tested in startup_checks
    unveil ($PFCTL, 'x');
    unveil ($PING, 'x');
    unveil ($PING6, 'rx');          # -x tested in startup_checks
    unveil ($ROUTE, 'x');
    unveil ($SENDMAIL, 'x');
    # don't lock yet.
}

# Config-test mode. Runs the exact same parse_config(), unveil lock and
# startup_checks() as real startup, under the same pledge and unveil (both
# die on the first error), so a pass here guarantees startup will accept the
# configuration on this host, including the privilege mode, the _faild
# user, the pf tables, the binaries and the state/pid directories. (Before
# 1.34 it ran before pledge and unveil, so it passed checks that startup
# then failed.) Run it as the user faild will start as (root, for rcctl).
# Prints the first error and exits non-zero on failure; prints OK and exits
# 0 on success. Deliberately stops at the first error rather than
# accumulating, to stay identical to the startup path and avoid cascading
# secondary errors.
if ($config_test) {
    my $ok = eval { parse_config (); lock_unveil (); startup_checks (); 1 };
    if ($ok) {
	print "faild.pl: configuration OK ($FAILD_CONF)\n";
	exit (0);
    }
    my $err = $@;
    $err =~ s/\s+\z//;
    print STDERR "faild.pl: configuration error: $err\n";
    exit (1);
}

parse_config();
lock_unveil();

# Every check that can reject the configuration runs here, before daemonize
# (so a failure reaches the terminal) and is shared with -n (so a -n pass
# guarantees this passes too).
my ($running_as_root, $need_helper) = startup_checks();

acquire_pid_lock();
initialize_states();
Sys::Syslog::setlogsock('unix');
read_faild_info();
read_prefix_info();

# faild has no SIGHUP reconfiguration path (use restart for config/version
# changes), and SIGHUP's default disposition is to terminate. Ignore it here,
# before daemonize() and the privsep fork, so the disposition is inherited by
# both the privileged helper and the monitor. (Before 1.33 this was set after
# the fork, so only the monitor ignored HUP, and a HUP to "faild [priv]"
# killed the helper and with it the monitor's next helper request.)
$SIG{HUP} = 'IGNORE';

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
    unlink ($FAILD_PID); # Best effort cleanup.
    exit(0);
};
$SIG{INT} = $SIG{TERM};

write_pid();

initialize_routes();

# distinctive_ping_frequency is in minutes. Starting at 0 makes the first
# distinctive ping go out on the first cycle (handy for verifying the feature);
# set this to time() instead to wait a full interval before the first one.
my $last_distinctive_ping_time = 0;

# Infinite loop.
while (1) {
    ping_all_gateways();
    report_and_failover();
    sync_managed_tables();
    check_ipv6_prefixes();

    if ($distinctive_pings_enabled &&
	time() - $last_distinctive_ping_time >= $distinctive_ping_frequency * 60) {
	send_distinctive_pings();
	$last_distinctive_ping_time = time();
    }

    print "Sleeping for $SLEEP_TIME seconds.\n" if ($DEBUG);
    sleep $SLEEP_TIME;
}

logmsg ('alert', 'Process has exited from infinite loop.');
exit;

### Subroutines.

# Parse config file.
sub parse_config {
    my ($have_page_source, $have_page_destination, $gateway_idx, $have_interface, $have_routes, $have_ping_ip, $have_type, $have_distinctive_pings);
    my ($have_name, $have_gateway_table, $have_dynamic_dping_table);
    my ($have_depends_on);
    $have_depends_on = 0;
    $have_name = 0;
    $have_gateway_table = 0;
    $have_dynamic_dping_table = 0;
    $have_page_source = 0;
    $have_page_destination = 0;
    $gateway_idx = -1;
    $have_interface = 0;
    $have_routes = 0;
    $have_ping_ip = 0;
    $have_type = 0;
    $have_distinctive_pings = 0;

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
	    # Unveil the configured directory before testing it: under unveil a
	    # path outside the list stats as nonexistent (only the default is
	    # unveiled before parse_config runs).
	    unveil ($STATE_DIR, 'rwc') if ($^O eq 'openbsd');
	    die "state_dir $STATE_DIR does not exist.\n" unless (-d $STATE_DIR);
	}
	elsif (/^\s*pid_dir:\s*(.*)$/) {
	    $PID_DIR = $1;
	    $PID_DIR =~ s|/+$||; # remove any trailing slashes
	    die "Invalid pid_dir path: $PID_DIR\n"
		unless ($PID_DIR =~ m{^/[\w/.-]+$} && length ($PID_DIR) < 256);
	    unveil ($PID_DIR, 'rwc') if ($^O eq 'openbsd');   # see state_dir
	    die "pid_dir $PID_DIR does not exist.\n" unless (-d $PID_DIR);
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
	elsif (/^\s*distinctive_ping_len:\s*(.*)$/) {
	    my $val = $1;
	    if ($val =~ /^\d+$/ &&
		$val >= 16 && $val <= 255) {
		$distinctive_ping_len = $val;
	    }
	    else {
		die "distinctive_ping_len must be a decimal number between 16 and 255 bytes, not \"$val\".\n";
	    }
	}
	elsif (/^\s*distinctive_ping_ttl:\s*(.*)$/) {
	    my $val = $1;
	    if ($val =~ /^\d+$/ &&
		$val > 1 && $val <= 255) {
		$distinctive_ping_ttl = $val;
	    }
	    else {
		die "distinctive_ping_ttl must be a decimal number between 2 and 255, not \"$val\".\n";
	    }
	}
	elsif (/^\s*distinctive_ping_tos:\s*(.*)$/) {
	    if (valid_ping_tos ($1)) {
		$distinctive_ping_tos = $1;
	    }
	    else {
		die "distinctive_ping_tos must be a valid ping tos value, not \"$1\".\n";
	    }
	}
	elsif (/^\s*distinctive_ping_frequency:\s*(.*)$/) {
	    my $val = $1;
	    if ($val =~ /^\d+$/ && $val > 1) {
		$distinctive_ping_frequency = $val;
	    }
	    else {
		die "distinctive_ping_frequency must be a decimal number > 1, not \"$val\".\n";
	    }
	}
	elsif (/^\s*gateway:\s*(.*)$/) {
	    if ($gateway_idx > -1) {
		die "New gateway line when no ping_ip specified for previous gateway. $_\n" if (!$have_ping_ip);
		die "New gateway line when no type specified for previous gateway. $_\n" if (!$have_type);
		die "New gateway line when no interface specified for previous dedicated-dhcplease gateway. $_\n" if (!$have_interface && ($GATE_TYPE[$gateway_idx] == $DEDICATED_DHCPLEASE_PRIMARY ||
																	   $GATE_TYPE[$gateway_idx] == $DEDICATED_DHCPLEASE_BACKUP));
	    }
	    if (is_ipaddr ($1) || is_ip6addr ($1)) {
		push (@GATEWAYS, $1);
		$gateway_idx++;
		$have_interface = 0;
		$have_routes = 0;
		$have_ping_ip = 0;
		$have_type = 0;
		$have_distinctive_pings = 0;
		$have_name = 0;
		$have_gateway_table = 0;
		$have_dynamic_dping_table = 0;
		$have_depends_on = 0;
	    }
	    else {
		die "gateway must be an IPv4 or IPv6 address. $_\n";
	    }
	}
	# Optional except for dedicated-dhcplease types.
	elsif (/^\s*interface:\s*(.*)$/) {
	    die "interface line before any gateway. $_\n" if ($gateway_idx < 0);
	    if ($have_interface) {
		die "Already have an interface for gateway. $_\n";
	    }
	    $INTERFACES[$gateway_idx] = $1;
	    die "Invalid interface name. $INTERFACES[$gateway_idx]\n" unless (is_interface ($INTERFACES[$gateway_idx]));
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
	    die "routes line before any gateway. $_\n" if ($gateway_idx < 0);
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
	    die "ping_ip line before any gateway. $_\n" if ($gateway_idx < 0);
	    if ($have_ping_ip) {
		die "Already have a ping IP for gateway. $_\n";
	    }
	    my @ips = split (/\s*,\s*/, $1);
	    if (@ips < 1 || @ips > 3) {
		die "ping_ip must specify 1-3 IPs. $_\n";
	    }
	    my %seen;
	    foreach my $ip (@ips) {
		die "Invalid ping IP address. $ip\n" unless (is_ipaddr ($ip) || is_ip6addr ($ip));
		die "Duplicate ping IP. $ip\n" if $seen{$ip}++;
	    }
	    $PING_IPS[$gateway_idx] = [@ips];
	    $have_ping_ip = 1;
	}
	elsif (/^\s*type:\s*(.*)$/) {
	    die "type line before any gateway. $_\n" if ($gateway_idx < 0);
	    if ($have_type) {
		die "Already have a type for gateway. $_\n";
	    }
	    # Assign by index rather than push, so the type can never be
	    # attributed to a different gateway than the one being parsed.
	    my %type_code = ('dedicated'                   => $DEDICATED,
			     'dedicated-dhcplease-primary' => $DEDICATED_DHCPLEASE_PRIMARY,
			     'dedicated-dhcplease-backup'  => $DEDICATED_DHCPLEASE_BACKUP,
			     'host'                        => $HOST_CHECK,
			     'ipv6-tunnel'                 => $IPV6_TUNNEL,
			     'ipv6-pd'                     => $IPV6_PD);
	    my $val = $1;
	    die "Unrecognized type \"$val\". $_\n" unless (exists ($type_code{$val}));
	    $GATE_TYPE[$gateway_idx] = $type_code{$val};
	    $have_type = 1;
	}
	# Optional, only valid for type: host. Validated against type below,
	# since type: may appear after this line for the same gateway.
	elsif (/^\s*distinctive_pings:\s*(.*)$/) {
	    die "distinctive_pings line before any gateway. $_\n" if ($gateway_idx < 0);
	    if ($have_distinctive_pings) {
		die "Already have distinctive_pings for gateway. $_\n";
	    }
	    if ($1 eq 'yes') {
		$DISTINCTIVE_PINGS[$gateway_idx] = 1;
	    }
	    elsif ($1 eq 'no') {
		$DISTINCTIVE_PINGS[$gateway_idx] = 0;
	    }
	    else {
		die "distinctive_pings must be \"yes\" or \"no\", not \"$1\".\n";
	    }
	    $have_distinctive_pings = 1;
	}
	# Optional descriptive label for any entry, inserted into alerts.
	elsif (/^\s*name:\s*(.*)$/) {
	    die "name line before any gateway. $_\n" if ($gateway_idx < 0);
	    die "Already have a name for gateway. $_\n" if ($have_name);
	    my $val = $1;
	    $val =~ s/\s+$//;
	    die "name must be non-empty. $_\n" if ($val eq '');
	    $NAMES[$gateway_idx] = $val;
	    $have_name = 1;
	}
	# Optional pf table faild keeps populated with this gateway's current
	# next-hop, for use as a route-to target. Validated against type below.
	elsif (/^\s*gateway_table:\s*(.*)$/) {
	    die "gateway_table line before any gateway. $_\n" if ($gateway_idx < 0);
	    die "Already have a gateway_table for gateway. $_\n" if ($have_gateway_table);
	    my $val = $1;
	    $val =~ s/\s+$//;
	    die "Invalid pf table name \"$val\". $_\n" unless (is_pftable_name ($val));
	    $GATEWAY_TABLE[$gateway_idx] = $val;
	    $have_gateway_table = 1;
	}
	# Optional pf table faild populates with distinctive-ping host IPs while
	# this (backup) gateway is up and flushes when it is down. Validated below.
	elsif (/^\s*dynamic_dping_table:\s*(.*)$/) {
	    die "dynamic_dping_table line before any gateway. $_\n" if ($gateway_idx < 0);
	    die "Already have a dynamic_dping_table for gateway. $_\n" if ($have_dynamic_dping_table);
	    my $val = $1;
	    $val =~ s/\s+$//;
	    die "Invalid pf table name \"$val\". $_\n" unless (is_pftable_name ($val));
	    $DYNAMIC_DPING_TABLE[$gateway_idx] = $val;
	    $have_dynamic_dping_table = 1;
	}
	# Optional: names of other entries this one depends on. Used only to
	# enrich this entry's alerts (shared-fate triage); never control flow.
	# Resolved and cycle-checked in post-parse validation below.
	elsif (/^\s*depends_on:\s*(.*)$/) {
	    die "depends_on line before any gateway. $_\n" if ($gateway_idx < 0);
	    die "Already have depends_on for gateway. $_\n" if ($have_depends_on);
	    my @deps = split (/\s*,\s*/, $1);
	    my %seen;
	    foreach my $d (@deps) {
		$d =~ s/^\s+//;
		$d =~ s/\s+$//;
		die "Empty name in depends_on. $_\n" if ($d eq '');
		die "Duplicate name in depends_on: $d\n" if ($seen{$d}++);
	    }
	    die "depends_on lists no names. $_\n" unless (@deps);
	    $DEPENDS_ON[$gateway_idx] = [@deps];
	    $have_depends_on = 1;
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

    # Per-gateway checks that can only run once every field of every gateway
    # is known (type: may follow routes:/distinctive_pings: within a stanza,
    # and these must be verified for every gateway, not just the last one).
    for (my $idx = 0; $idx <= $#GATEWAYS; $idx++) {
	if (defined ($ROUTES[$idx]) &&
	    $GATE_TYPE[$idx] != $DEDICATED_DHCPLEASE_PRIMARY &&
	    $GATE_TYPE[$idx] != $DEDICATED_DHCPLEASE_BACKUP) {
	    die "Specific routes specified for non-dedicated DHCP gateway. ($GATEWAYS[$idx])\n";
	}
	if ($DISTINCTIVE_PINGS[$idx]) {
	    $distinctive_pings_enabled = 1;
	    if ($GATE_TYPE[$idx] != $HOST_CHECK) {
		die "distinctive_pings is only valid for type: host. ($GATEWAYS[$idx])\n";
	    }
	}
	# gateway_table holds an IPv4 gateway's next-hop; only real IPv4
	# gateways (not hosts, not IPv6 monitoring entries) have one.
	if (defined ($GATEWAY_TABLE[$idx])) {
	    if (!is_failover_candidate ($idx)) {
		die "gateway_table is only valid for an IPv4 gateway. ($GATEWAYS[$idx])\n";
	    }
	    if ($MANAGED_TABLES{$GATEWAY_TABLE[$idx]}) {
		die "pf table \"$GATEWAY_TABLE[$idx]\" is managed by more than one entry.\n";
	    }
	    $MANAGED_TABLES{$GATEWAY_TABLE[$idx]} = 1;
	}
	# dynamic_dping_table gates distinctive pings onto a backup gateway.
	if (defined ($DYNAMIC_DPING_TABLE[$idx])) {
	    if ($GATE_TYPE[$idx] != $DEDICATED_DHCPLEASE_BACKUP) {
		die "dynamic_dping_table is only valid for a dedicated-dhcplease-backup gateway. ($GATEWAYS[$idx])\n";
	    }
	    if ($MANAGED_TABLES{$DYNAMIC_DPING_TABLE[$idx]}) {
		die "pf table \"$DYNAMIC_DPING_TABLE[$idx]\" is managed by more than one entry.\n";
	    }
	    $MANAGED_TABLES{$DYNAMIC_DPING_TABLE[$idx]} = 1;
	}
	# IPv6 monitoring entries: gateway and every ping_ip must be IPv6;
	# a PD entry needs an interface to read the delegated prefix from.
	# Conversely, IPv4 entries must not carry IPv6 addresses.
	if (is_ipv6_entry ($idx)) {
	    die "gateway for an IPv6 entry must be an IPv6 address. ($GATEWAYS[$idx])\n"
		unless (is_ip6addr ($GATEWAYS[$idx]));
	    if (defined ($PING_IPS[$idx])) {
		foreach my $ip (@{$PING_IPS[$idx]}) {
		    die "ping_ip for an IPv6 entry must be an IPv6 address. ($ip)\n"
			unless (is_ip6addr ($ip));
		}
	    }
	    if ($GATE_TYPE[$idx] == $IPV6_PD && !defined ($INTERFACES[$idx])) {
		die "type: ipv6-pd requires an interface (the dhcp6leased interface). ($GATEWAYS[$idx])\n";
	    }
	}
	else {
	    die "gateway for an IPv4 entry must be an IPv4 address. ($GATEWAYS[$idx])\n"
		unless (is_ipaddr ($GATEWAYS[$idx]));
	    if (defined ($PING_IPS[$idx])) {
		foreach my $ip (@{$PING_IPS[$idx]}) {
		    die "ping_ip for an IPv4 entry must be an IPv4 address. ($ip)\n"
			unless (is_ipaddr ($ip));
		}
	    }
	}
    }

    # One ipv6-pd entry per interface: the persisted last-seen prefix is keyed
    # by interface, and two entries reading the same lease would duplicate
    # every alert anyway.
    {
	my %pd_if;
	for (my $idx = 0; $idx <= $#GATEWAYS; $idx++) {
	    next unless ($GATE_TYPE[$idx] == $IPV6_PD);
	    die "More than one ipv6-pd entry for interface $INTERFACES[$idx]. ($GATEWAYS[$idx])\n"
		if ($pd_if{$INTERFACES[$idx]}++);
	}
    }

    # Resolve depends_on names to configured entries and reject dangling
    # references and cycles. This is alert-enrichment metadata only, but we
    # fail loud at parse time rather than emit confusing runtime text.
    {
	# Names must be unique: they identify entries in alerts (and to
	# downstream processing such as reportnew) and in depends_on.
	my %name_to_idx;
	for (my $idx = 0; $idx <= $#GATEWAYS; $idx++) {
	    next unless (defined ($NAMES[$idx]));
	    die "name \"$NAMES[$idx]\" is used by more than one entry. ($GATEWAYS[$idx])\n"
		if (exists ($name_to_idx{$NAMES[$idx]}));
	    $name_to_idx{$NAMES[$idx]} = $idx;
	}
	for (my $idx = 0; $idx <= $#GATEWAYS; $idx++) {
	    next unless (defined ($DEPENDS_ON[$idx]));
	    foreach my $dep (@{$DEPENDS_ON[$idx]}) {
		die "depends_on references unknown entry name \"$dep\". ($GATEWAYS[$idx])\n"
		    unless (exists ($name_to_idx{$dep}));
		die "depends_on cannot reference itself \"$dep\". ($GATEWAYS[$idx])\n"
		    if ($name_to_idx{$dep} == $idx);
	    }
	}
	# Detect cycles in the depends-on graph (harmless for the non-traversing
	# alert text, but a cycle is a config error worth catching early).
	my %color;   # 0/undef=white, 1=gray (on stack), 2=black (done)
	my $visit;
	$visit = sub {
	    my ($i) = @_;
	    return 0 if (($color{$i} // 0) == 2);
	    return 1 if (($color{$i} // 0) == 1);   # back-edge => cycle
	    $color{$i} = 1;
	    if (defined ($DEPENDS_ON[$i])) {
		foreach my $dep (@{$DEPENDS_ON[$i]}) {
		    return 1 if ($visit->($name_to_idx{$dep}));
		}
	    }
	    $color{$i} = 2;
	    return 0;
	};
	for (my $idx = 0; $idx <= $#GATEWAYS; $idx++) {
	    die "depends_on forms a cycle involving entry $idx ($GATEWAYS[$idx]).\n"
		if ($visit->($idx));
	}
    }

    # A dynamic_dping_table is only meaningful if some host actually sends
    # distinctive pings; otherwise it would forever be empty.
    if (grep { defined } @DYNAMIC_DPING_TABLE) {
	die "dynamic_dping_table requires at least one host with distinctive_pings: yes. $FAILD_CONF\n"
	    unless ($distinctive_pings_enabled);
    }

    # Enforce the "never route a gateway health-check probe" rule: no IP that
    # will populate a dynamic_dping_table (a distinctive-ping host's ping_ip)
    # may also be a gateway's ping target, or a gateway-down flush would divert
    # the very probe used to decide that gateway is up.
    if (grep { defined } @DYNAMIC_DPING_TABLE) {
	my %dping_ip = map { $_ => 1 } distinctive_ping_host_ips();
	for (my $idx = 0; $idx <= $#GATEWAYS; $idx++) {
	    next if ($GATE_TYPE[$idx] == $HOST_CHECK);
	    next unless (defined ($PING_IPS[$idx]));
	    foreach my $ip (@{$PING_IPS[$idx]}) {
		die "ping_ip $ip is both a gateway probe and a distinctive-ping " .
		    "destination; these must be disjoint.\n" if ($dping_ip{$ip});
	    }
	}
    }
    if ($distinctive_pings_enabled) {
	die "distinctive_pings requires distinctive_ping_frequency in config. $FAILD_CONF\n"
	    unless (defined ($distinctive_ping_frequency));
	# A ping with neither a distinctive TTL nor TOS is not distinguishable
	# from an ordinary echo request, so require at least one.
	die "distinctive_pings requires distinctive_ping_len, distinctive_ping_ttl, and/or distinctive_ping_tos in config. $FAILD_CONF\n"
	    unless (defined ($distinctive_ping_len) || defined ($distinctive_ping_ttl) || defined ($distinctive_ping_tos));
    }
}

# Subroutine to do rudimentary email address check.
sub is_email {
    my ($addr) = @_;

    if ($addr =~ /^[\w.+-]+\@[\w.+-]+\z/) {
	return 1;
    }
    else {
	return 0;
    }
}

# Validation functions
sub is_ipaddr {
    my ($ipaddr) = @_;
    return 0 unless defined ($ipaddr);
    return 0 unless ($ipaddr =~ /^(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\.(0|[1-9]\d{0,2})\z/);
    return 0 if ($1 == 0);
    foreach my $octet ($1, $2, $3, $4) {
        return 0 if ($octet > 255);
    }
    return 1;
}

# Subroutine to check format of CIDR block.
sub is_cidr {
    my ($cidr) = @_;
    return 0 unless defined ($cidr);
    return 0 unless ($cidr =~ m{^([\d.]+)/(\d+)\z});
    my ($ip, $bits) = ($1, $2);
    return is_ipaddr ($ip) && $bits >= 1 && $bits <= 32;
}

# Validate an IPv6 address using the system resolver's parser rather than a
# hand-rolled regex (IPv6 text form is too subtle to get right by regex).
# Note: inet_pton does not accept a zone/scope suffix (fe80::1%if0), so
# link-local targets are not accepted here by design.
sub is_ip6addr {
    my ($addr) = @_;
    return 0 unless defined ($addr);
    return 0 if ($addr =~ /%/);            # reject scoped addresses explicitly
    return defined (inet_pton (AF_INET6, $addr)) ? 1 : 0;
}

# Validate an IPv6 prefix in address/length form (e.g. 2600:8800:4901:940::/60).
sub is_ip6prefix {
    my ($prefix) = @_;
    return 0 unless defined ($prefix);
    return 0 unless ($prefix =~ m{^(.+)/(\d+)\z});
    my ($addr, $len) = ($1, $2);
    return 0 unless (is_ip6addr ($addr));
    return 0 unless ($len >= 1 && $len <= 128);
    return 1;
}

# Canonicalize an IPv6 prefix to a stable comparable string: parse to bytes,
# zero the host bits beyond the prefix length, and re-emit in canonical form.
# This makes 2600:8800:4901:0940::/60 and 2600:8800:4901:940::/60 compare equal
# and defends against cosmetic formatting differences in dhcp6leasectl output.
# Returns undef on malformed input.
sub canonical_ip6_prefix {
    my ($addr, $len) = @_;
    return undef unless (defined ($addr) && defined ($len));
    return undef unless ($len =~ /^\d+$/ && $len >= 0 && $len <= 128);
    my $bytes = inet_pton (AF_INET6, $addr);
    return undef unless (defined ($bytes) && length ($bytes) == 16);
    # Zero all bits at position >= $len across the 16-byte address.
    my @b = unpack ('C16', $bytes);
    for (my $bit = $len; $bit < 128; $bit++) {
	my $byte = $bit >> 3;
	my $mask = ~(1 << (7 - ($bit & 7))) & 0xFF;
	$b[$byte] &= $mask;
    }
    my $masked = pack ('C16', @b);
    my $canon = inet_ntop (AF_INET6, $masked);
    return undef unless (defined ($canon));
    return "$canon/$len";
}

# Subroutine to validate an interface.
sub is_interface {
    my ($if) = @_;
    return 0 unless defined ($if);
    return 0 unless ($if =~ /^[a-z]+\d+(\.\d+)?\z/);
    return 0 if (length ($if) >= 16);
    return 1;
    }

# Subroutine to validate a pf table name. pf table names are limited to
# printable non-whitespace; we restrict further to a safe, conventional set
# and forbid the leading characters pfctl treats specially. This is belt and
# suspenders: managed table names are also whitelisted from the parsed config.
sub is_pftable_name {
    my ($name) = @_;
    return 0 unless defined ($name);
    return 0 if (length ($name) < 1 || length ($name) > 31);
    return 0 unless ($name =~ /^[A-Za-z0-9][A-Za-z0-9_.:-]*\z/);
    return 1;
}

# Subroutine to validate ping TOS values.
sub valid_ping_tos {
    my ($tos) = @_;
    return 0 unless (defined ($tos));

    # Named keyword: critical, lowdelay, ef, af11..af43, cs0..cs7, etc.
    return 1 if (exists ($KEYWORD_TOS{$tos}));

    # Otherwise a numeric TOS byte, hex (0x..) or decimal, in range 0..255.
    my $tos_num;
    if ($tos =~ /^0[xX][0-9a-fA-F]+\z/) {
	$tos_num = hex ($tos);
    }
    elsif ($tos =~ /^\d+\z/) {
	$tos_num = $tos + 0;
    }
    else {
	return 0;
    }
    return ($tos_num >= 0 && $tos_num <= 255) ? 1 : 0;
}

# Convert a TOS keyword or numeric string to its decimal byte value (0-255).
# OpenBSD's ping understands the keywords natively, but Linux (-Q) and macOS
# (-z) need a number. Assumes the value already passed valid_ping_tos().
sub tos_to_number {
    my ($tos) = @_;
    return $KEYWORD_TOS{$tos} if (exists ($KEYWORD_TOS{$tos}));
    return hex ($tos) if ($tos =~ /^0[xX]/);
    return $tos + 0;
}

# Build the ping argument list for the host OS. The TTL flag, TOS flag, and
# overall-timeout flag all differ between ping implementations:
#
#              TTL   TOS   timeout
#   OpenBSD    -t    -T    -w (seconds)
#   Linux      -t    -Q    -w (seconds)   (-T is a timestamp option here!)
#   macOS      -m    -z    -t (seconds)   (-t is the timeout, not TTL; no -w)
#
# TOS keywords are OpenBSD-only, so we pass a number on the other platforms.
sub build_ping_opts {
    my ($timeout, $len, $ttl, $tos) = @_;
    my @opts = ('-c', '1', '-q');

    push (@opts, '-s', $len) if (defined ($len)); # option same for each OS

    if ($^O eq 'darwin') {
	push (@opts, '-t', $timeout);              # macOS: -t is the timeout
	push (@opts, '-m', $ttl) if (defined ($ttl));
	push (@opts, '-z', tos_to_number ($tos)) if (defined ($tos));
    }
    elsif ($^O eq 'linux') {
	push (@opts, '-w', $timeout);
	push (@opts, '-t', $ttl) if (defined ($ttl));
	push (@opts, '-Q', tos_to_number ($tos)) if (defined ($tos));
    }
    else { # openbsd and other BSDs
	push (@opts, '-w', $timeout);
	push (@opts, '-t', $ttl) if (defined ($ttl));
	push (@opts, '-T', $tos) if (defined ($tos)); # keyword passed through
    }
    return @opts;
}

# Build options for an IPv6 liveness ping (ping6, or ping -6 on Linux without
# ping6). No distinctive-ping options are used for IPv6. OpenBSD's -w is the
# maximum wait for a reply and Linux's -w is a deadline; either bounds the
# ping. macOS ping6 has no such flag (its -i is the packet interval, which the
# 1.30 version wrongly used), so there ping_host's watchdog is the bound.
sub build_ping6_opts {
    my ($timeout) = @_;
    my @opts = (@PING6_PREFIX, '-c', '1');
    push (@opts, '-w', $timeout) unless ($^O eq 'darwin');
    return @opts;
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

# Unveil the configured state and pid directories (known only after
# parse_config) and lock the unveil list. Shared by startup and -n.
sub lock_unveil {
    return unless ($^O eq 'openbsd');
    unveil ($STATE_DIR, 'rwc');
    unveil ($PID_DIR, 'rwc');
    unveil (); # done unveiling, lock it
}

# Every startup check that can reject a configuration, in one place so that
# real startup and -n run exactly the same checks. Must be called after
# parse_config() and before daemonize(), while still single-process and with
# the original privileges. Returns ($running_as_root, $need_helper).
sub startup_checks {
    $FAILD_INFO = "$STATE_DIR/faild.info";
    $FAILD_PID = "$PID_DIR/faild.pid";
    $FAILD_PREFIX_INFO = "$STATE_DIR/faild.prefix";

    if ($PERFORM_FAILOVER && $^O ne 'openbsd') {
	die "Failover is only supported on OpenBSD.\n";
    }

    my ($running_as_root, $need_helper) = determine_privilege_mode();

    # Verify declared managed pf tables exist. We are guaranteed root here
    # (determine_privilege_mode has already exited if managed tables were
    # declared by a non-root user), we still hold exec/pfctl-unveil, and no
    # privilege drop has happened -- so this runs pfctl directly, needs no
    # helper, and its die still reaches the terminal.
    verify_managed_tables_exist();

    # Commands the configured entry types will run. Without this, a missing
    # ping6 makes every IPv6 entry read as down rather than failing loudly.
    my $have_v6 = grep { is_ipv6_entry ($_) } (0 .. $#GATEWAYS);
    my $have_pd = grep { $GATE_TYPE[$_] == $IPV6_PD } (0 .. $#GATEWAYS);
    if ($have_v6 && !-x $PING6) {
	die "IPv6 entries are configured but $PING6 is not executable.\n";
    }
    if ($have_pd && !-x $DHCP6LEASECTL) {
	die "type: ipv6-pd is configured but $DHCP6LEASECTL is not executable.\n";
    }

    # Check that state_dir is writable for the eventual runtime user
    # (root always can; non-root must be writable as the current user).
    # When running as root, the files are made accessible to _faild in
    # prepare_state_files_for_user. The /var/run default is root-writable.
    if (!$running_as_root) {
	if (!-w $STATE_DIR) {
	    die "Cannot use state_dir '$STATE_DIR' - not writable by current user.\n" .
		"Set state_dir in $FAILD_CONF to a directory writable by your user, " .
		"e.g., '\$HOME/.faild'.\n";
	}
	if (!-w $PID_DIR) {
	    die "Cannot use pid_dir '$PID_DIR' - not writable by current user.\n" .
		"Set pid_dir in $FAILD_CONF to a directory writable by your user, " .
		"e.g., '\$HOME/.faild'.\n";
	}
    }

    return ($running_as_root, $need_helper);
}

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
    # Managing pf tables requires the privileged helper (pfctl needs root).
    $need_helper = 1 if (%MANAGED_TABLES);
    # Every command dispatched to the helper must be represented here.
    # ipv6-pd reads dhcp6leasectl via DHCP6LEASECTL_INFO, so it needs the
    # helper too; otherwise a monitor-only host would run it as _faild.
    for (my $i = 0; $i <= $#GATEWAYS; $i++) {
        if ($GATE_TYPE[$i] == $IPV6_PD) {
            $need_helper = 1;
            last;
        }
    }

    # Validate we have the privileges and users we need.
    if ($need_helper && !$running_as_root) {
        die "faild.pl must run as root for failover, DHCP gateway types, " .
            "IPv6 prefix-delegation monitoring, or pf table management.\n";
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
    elsif ($cmd eq 'PFCTL_TABLE_REPLACE') {
        # Table name must be one faild declared in its config (parsed as root
        # before the privsep fork), so a compromised monitor cannot touch any
        # other table. An empty address set flushes the table.
        return {status => 'err', reason => 'bad table'}
            unless (defined ($req->{table}) && $MANAGED_TABLES{$req->{table}});
        my $ips = $req->{ips};
        return {status => 'err', reason => 'bad ips'}
            unless (defined ($ips) && ref ($ips) eq 'ARRAY');
        foreach my $ip (@$ips) {
            return {status => 'err', reason => 'bad ip'} unless (is_ipaddr ($ip));
        }
        if (@$ips) {
            return run_helper_cmd ($PFCTL, '-t', $req->{table}, '-T', 'replace', @$ips);
        }
        else {
            return run_helper_cmd ($PFCTL, '-t', $req->{table}, '-T', 'flush');
        }
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
    elsif ($cmd eq 'DHCP6LEASECTL_INFO') {
        return {status => 'err', reason => 'bad interface'}
            unless (defined ($req->{interface}) && is_interface ($req->{interface}));
        return get_dhcp6_info ($req->{interface});
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

# List pf table names present in the active ruleset (one per line from
# 'pfctl -sT'). Returns { status => 'ok', tables => [...] }. Read-only: it
# never creates a table, so it is safe as an existence probe.
sub list_pf_tables {
    my $fh;
    if (!open ($fh, '-|', $PFCTL, '-sT')) {
        return {status => 'err', reason => "cannot run pfctl: $!"};
    }
    my @tables;
    while (<$fh>) {
        chomp;
        s/^\s+//;
        s/\s+$//;
        push @tables, $_ if (length ($_));
    }
    close ($fh);
    if ($? != 0) {
        return {status => 'err', reason => "pfctl -sT failed (is pf enabled?)"};
    }
    return {status => 'ok', tables => \@tables};
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
    
    # Extract each field independently
    my ($ip, $netmask, $gateway, $lease_seconds);
    
    if ($output =~ /inet (\d+\.\d+\.\d+\.\d+) netmask (\d+\.\d+\.\d+\.\d+)/) {
        $ip = $1;
        $netmask = $2;
    }
    
    if ($output =~ /default gateway (\d+\.\d+\.\d+\.\d+)/) {
        $gateway = $1;
    }
    
    # Lease remaining. undef when absent or in an unrecognized format: an
    # unknown lease must not be mistaken for an expiring one (before 1.33 an
    # unrecognized format parsed as 0, forcing a renewal every cycle).
    $lease_seconds = parse_lease_seconds ($output);

    # Validate we got the required fields. The lease is optional: without it
    # the caller skips the expiry safety net but still tracks IP changes.
    if (defined($ip) && defined($netmask) && defined($gateway)) {
        # Convert back to hours/minutes for compatibility with existing worker code
        my ($lease_time, $units);
        if (!defined ($lease_seconds)) {
            # leave both undef
        }
        elsif ($lease_seconds >= 3600 && $lease_seconds % 3600 == 0) {
            $lease_time = $lease_seconds / 3600;
            $units = 'hours';
        }
        else {
            $lease_time = int($lease_seconds / 60);
            $units = 'minutes';
        }
        return {
            status => 'ok',
            ip => $ip,
            netmask => $netmask,
            gateway => $gateway,
            lease_time => $lease_time,
            units => $units,
        };
    }
    else {
        # Build diagnostic listing what was missing
        my @missing;
        push @missing, 'ip' unless defined $ip;
        push @missing, 'netmask' unless defined $netmask;
        push @missing, 'gateway' unless defined $gateway;
        return {status => 'err', reason => 'parse failed, missing: ' . join(',', @missing)};
    }
}

# Parse the remaining lease time from dhcpleasectl/dhcp6leasectl output, in
# seconds. Accepts any run of number-unit pairs after "lease", in long or
# short form and in any combination: "24 hours", "2 days", "1 day 3 hours",
# "7h 45m 31s". Returns undef if there is no lease, no pair, or any unit it
# does not recognize -- it never guesses.
sub parse_lease_seconds {
    my ($output) = @_;
    return undef unless (defined ($output) &&
			 $output =~ /\blease\s+((?:\d+\s*[A-Za-z]+\b[\s,]*)+)/);
    my $text = $1;
    my %unit_seconds = (day => 86400, d => 86400,
			hour => 3600, hr => 3600, h => 3600,
			minute => 60, min => 60, m => 60,
			second => 1, sec => 1, s => 1);
    my ($total, $pairs) = (0, 0);
    while ($text =~ /(\d+)\s*([A-Za-z]+)/g) {
	my ($count, $unit) = ($1, lc ($2));
	$unit =~ s/s\z// if (length ($unit) > 1);   # plural: hours -> hour
	return undef unless (exists ($unit_seconds{$unit}));
	$total += $count * $unit_seconds{$unit};
	$pairs++;
    }
    return $pairs ? $total : undef;
}

# Get DHCPv6 prefix-delegation info for an interface by parsing dhcp6leasectl.
# Example output:
#   igc0 [Bound]
#   IA_PD 0: 2600:8800:4901:940::/60
#   lease 24 hours
# Returns { status, state, pds => [ {index, prefix, prefixlen}, ... ],
# lease_seconds }. A dhcp6leasectl that cannot run or exits non-zero (e.g.,
# dhcp6leased is not running) is an error. Otherwise parsing is lenient: an
# unreadable state or a missing IA_PD is not an error here -- the caller
# decides (only a Bound lease with a valid prefix is trusted).
sub get_dhcp6_info {
    my ($interface) = @_;
    my $fh;
    if (!open ($fh, '-|', $DHCP6LEASECTL, '-l', $interface)) {
        return {status => 'err', reason => "cannot run dhcp6leasectl: $!"};
    }
    my $output = '';
    while (<$fh>) { $output .= $_; }
    close ($fh);
    # Before 1.33 the exit status was ignored, so a failing dhcp6leasectl
    # looked like an ordinary non-Bound reading and was silent forever.
    if ($? != 0) {
        my $why = ($? & 127) ? "killed by signal " . ($? & 127)
                             : "exit " . ($? >> 8);
        return {status => 'err', reason => "dhcp6leasectl -l $interface failed ($why)"};
    }

    # Lease state appears in brackets on the interface line, e.g. "igc0 [Bound]".
    my $state;
    if ($output =~ /\[(\w+)\]/) {
        $state = $1;
    }

    # Collect every IA_PD delegation line, e.g. "IA_PD 0: 2600:8800:4901:940::/60".
    my @pds;
    while ($output =~ /IA_PD\s+(\d+):\s+([0-9A-Fa-f:]+)\/(\d+)/g) {
        push @pds, { index => $1, prefix => $2, prefixlen => $3 };
    }

    # Lease remaining, best-effort (same parser as the IPv4 path).
    my $lease_seconds = parse_lease_seconds ($output);

    return {
        status => 'ok',
        state => $state,
        pds => \@pds,
        lease_seconds => $lease_seconds,
    };
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

# Wrapper to mirror former run_cmd interface - logs failures and returns 0/1;
# migrated from run_cmd to helper_cmd, then removed run_cmd in transition
# to privsep model.
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
	$current_gateway = 0; # Assume primary, will be fixed up on next cycle.
	$starting_up = 1;
    }
    else {
	$starting_up = 0;
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
    if (!sysopen(PID, $FAILD_PID, O_RDWR | O_CREAT | O_NOFOLLOW, 0644)) {
	die "Cannot open PID file. $! $FAILD_PID\n";
    }
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
    my @files = ($FAILD_INFO, $FAILD_PID);
    # The monitor (running as $uid) writes the last-seen delegated prefix.
    push (@files, $FAILD_PREFIX_INFO)
	if (grep { $GATE_TYPE[$_] == $IPV6_PD } (0 .. $#GATEWAYS));
    foreach my $file (@files) {
        # Create if missing, using O_NOFOLLOW to prevent symlink attacks
        my $fh;
        if (!sysopen($fh, $file, O_RDWR | O_CREAT | O_NOFOLLOW, 0644)) {
            die "Cannot open $file: $!\n";
        }
        # Verify it's a regular file (not a symlink, hardlink we shouldn't touch, etc.)
        my @st = stat($fh);
        if (!@st || !-f _) {
	    close ($fh);
            die "$file is not a regular file\n";
        }
	if ($st[3] > 1) { # nlink > 1 means there are hard links
	    die "$file has hard links - possible attack\n";
	}
        chown($uid, $gid, $fh) or do {
	    close ($fh);
	    die "Cannot chown $file: $!\n";
	};
        chmod(0644, $fh) or do {
	    close ($fh);
	    die "Cannot chmod $file: $!\n";
	};
	close ($fh);
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
	    # IPv6 entries are written here too (since 1.30), so accept both.
	    next unless (defined $ip && (is_ipaddr ($ip) || is_ip6addr ($ip)));
	    $idx = gate_index ($ip);
	    next unless ($idx >= 0);
	    next unless (defined $state && $state =~ /^[01]$/); # UP or DOWN only
	    next unless (defined $saved_time && $saved_time =~ /^\d+$/ # plausible epoch
			 && $saved_time <= time());                    # not in the future
	    $current_state[$idx] = $state;
	    $state_time[$idx] = $saved_time;
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
        logmsg ('alert', "Error closing $FAILD_INFO: $!");
        return;
    }
}

# Set new_state for all gateways as up or down.  No test is performed
# for on-demand gateways not in use but believed to be up.
sub ping_all_gateways {
    my ($idx);
    my ($gate_type_name, $n_pings);

    print "Entering sub ping_gateways.\n" if ($DEBUG);

    for ($idx = 0; $idx <= $#GATEWAYS; $idx++) {
	$gate_type_name = $GATE_TYPE_NAME[$GATE_TYPE[$idx]];
	my $glabel = gate_label ($idx);
	if (ping_gateway_ips ($idx, $PING_TIMEOUT)) {
	    $new_state[$idx] = $UP;
	    print "$glabel is up on the first ping.\n" if ($DEBUG);
	}
	else {
	    $new_state[$idx] = $DOWN;
	    print "$glabel is down on the first ping.\n" if ($DEBUG);
	    $pings_down[$idx] = 1;
	}
    }

    # Ping anything marked as down again N_PINGS_DOWN-1 times, just to be sure.  ($n_pings is total number of pings
    # including the first)
    for ($idx = 0; $idx <= $#GATEWAYS; $idx++) {
	$gate_type_name = $GATE_TYPE_NAME[$GATE_TYPE[$idx]];
	my $glabel = gate_label ($idx);
	if ($new_state[$idx] == $DOWN) {
	    for ($n_pings = 2; $n_pings < $N_PINGS_DOWN+1; $n_pings++) {
		if (ping_gateway_ips ($idx, $PING_TIMEOUT)) {
		    $new_state[$idx] = $UP;
		    $pings_down[$idx] = 0; # prevent miscount if it goes down in next minute
		    print "$glabel is up on the $PING_NAME{$n_pings} ping.\n" if ($DEBUG);
		    logmsg ('alert', "$glabel is up on the $PING_NAME{$n_pings} ping." . depends_suffix ($idx)) if ($n_pings > $N_PINGS_TO_NOTIFY);
		    last;
		}
		else {
		    print "$glabel is down on the $PING_NAME{$n_pings} ping.\n" if ($DEBUG);
		    logmsg ('alert', "$glabel is down on the $PING_NAME{$n_pings} ping." . depends_suffix ($idx)) if ($n_pings > $N_PINGS_TO_NOTIFY);
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
        my $reason = $resp->{reason} // 'unknown';
        logmsg('alert', "DHCP info query for $interface failed: $reason");
        return (undef, undef, undef, undef, undef);
    }
    return ($resp->{ip}, $resp->{netmask}, $resp->{gateway}, 
            $resp->{lease_time}, $resp->{units});
}

# Query the privileged helper for an interface's DHCPv6 PD info. Always
# returns a hashref: the helper's response ({status => 'ok', state, pds,
# lease_seconds}) or {status => 'err', reason}. It does not log: the caller
# alerts on a failure only once it has persisted (see check_ipv6_prefixes),
# rather than once a minute. (A lost helper connection still dies in
# helper_request, as for every other helper command.)
sub get_dhcp6_prefix {
    my ($interface) = @_;
    my $resp = helper_request (cmd => 'DHCP6LEASECTL_INFO', interface => $interface);
    return {status => 'err', reason => 'no response'} if (!$resp);
    return $resp;
}

# Subroutine to report any state changes and failover to another
# gateway if necessary and possible.
sub report_and_failover {
    my ($changes_occurred, $duration, $plural);
    my ($prior_gateway);
    my ($gate_type_name);

    print "Entering sub report_and_failover.\n" if ($DEBUG);

    # Report changes that have occurred.
    $changes_occurred = 0;
    for (my $idx = 0; $idx <= $#GATEWAYS; $idx++) {
	my ($interface_ip, $netmask, $gateway_ip, $lease_time, $units);
	$gate_type_name = $GATE_TYPE_NAME[$GATE_TYPE[$idx]];
	my $glabel = gate_label ($idx);

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
		    # If any ping IP matches the old gateway IP (i.e., we were pinging the gateway 
		    # itself, possibly as the default), update it to the new gateway IP
		    for (my $jdx = 0; $jdx <= $#{$PING_IPS[$idx]}; $jdx++) {
			if ($PING_IPS[$idx]->[$jdx] eq $last_gateway_ip[$idx]) {
			    $PING_IPS[$idx]->[$jdx] = $gateway_ip;
			}
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

	# Routes are otherwise only added on a down->up transition, which never
	# happens for a gateway that has been up since boot.
	if ($first_cycle && defined ($ROUTES[$idx]) && $new_state[$idx] == $UP) {
	    add_missing_routes ($ROUTES[$idx], $gateway_ip, $ALL_ROUTES);
	}

	if ($current_state[$idx] != $new_state[$idx]) {
	    $changes_occurred = 1;
	    $duration = time() - $state_time[$idx];
	    $duration = int ($duration / 60);
	    $plural = 's';
	    $plural = '' if ($duration == 1);
	    if ($new_state[$idx] == $UP) {
		logmsg ('alert', "$glabel is again reachable (down $duration minute$plural), $pings_down[$idx] failed pings." . depends_suffix ($idx));
		$pings_down[$idx] = 0; # reset counter
		print "$glabel is again reachable (down $duration minute$plural).\n" if ($DEBUG);
		if ($duration > 15) {
		    send_page ("faild.pl: $glabel is again reachable (down $duration minute$plural)." . depends_suffix ($idx));
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
		logmsg ('alert', "$glabel has gone down (up $duration minute$plural)." . depends_suffix ($idx));
		print "$glabel has gone down (up $duration minute$plural).\n" if ($DEBUG);
	    }
	    $current_state[$idx] = $new_state[$idx];
	    $state_time[$idx] = time();
	}
	elsif ($new_state[$idx] == $DOWN) {
	    $duration = time() - $state_time[$idx];
	    $duration = int ($duration / 60);
	    $plural = 's';
	    $plural = '' if ($duration == 1);
	    logmsg ('alert', "$glabel has been down for $duration minute$plural." . depends_suffix ($idx));
	    print "$glabel has been down for $duration minute$plural.\n" if ($DEBUG);
	    if ($duration % 15 == 0 && $duration < 61) {
		send_page ("faild.pl: $glabel has been down for $duration minutes." . depends_suffix ($idx));
	    }
	    # Add permanent routes if missing while down -- necessary to make
	    # sure test pings still go out the right interface.
	    if (defined ($ROUTES[$idx])) {
		add_missing_routes ($ROUTES[$idx], $GATEWAYS[$idx], $PERM_ONLY);
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
	if ($new_state[$idx] == $UP && is_failover_candidate ($idx)) {
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
	    elsif ($new_state[$idx] == $UP && is_failover_candidate ($idx)) {
		if ($idx < $current_gateway) {
		    logmsg ('alert', "Failing back from gateway $current_gateway ${\ gname($current_gateway)} to gateway $idx ${\ gname($idx)}.");
		    print "Failing back from gateway $current_gateway ${\ gname($current_gateway)} to gateway $idx ${\ gname($idx)}.\n" if ($DEBUG);
		    send_page ("faild.pl: Failing back from gateway $current_gateway ${\ gname($current_gateway)} to gateway $idx ${\ gname($idx)}.");
		    $current_gateway = $idx;
		}
		elsif ($idx > $current_gateway) {
		    if ($starting_up) {
			logmsg ('alert', "Starting up with gateway $idx ${\ gname($idx)}.");
			print "Starting up with gateway $idx ${\ gname($idx)}.\n";
		    }
		    else {
			logmsg ('alert', "Failing over from gateway $current_gateway ${\ gname($current_gateway)} to gateway $idx ${\ gname($idx)}.");
			print "Failing over from gateway $current_gateway ${\ gname($current_gateway)} to gateway $idx ${\ gname($idx)}.\n" if ($DEBUG);
			send_page ("faild.pl: Failing over from gateway $current_gateway ${\ gname($current_gateway)} to gateway $idx ${\ gname($idx)}.");
		    }
		    $current_gateway = $idx;
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

    # Once we've settled on an up gateway, we're no longer starting up.
    $starting_up = 0 if ($new_state[$current_gateway] == $UP);
    $first_cycle = 0;

    # If there is more than one gateway and all are down, note that.
    if ($#GATEWAYS > 0 &&
	!$changes_occurred &&
	$new_state[$current_gateway] == $DOWN) {
	# Check if there are actually any UP gateways (excluding HOST_CHECK)
	my $any_gateway_up = 0;
	for (my $idx = 0; $idx <= $#GATEWAYS; $idx++) {
	    if ($new_state[$idx] == $UP && is_failover_candidate ($idx)) {
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
    my @ips;

    if (!open (ROUTE, '-|', $ROUTE, '-n', 'show')) {
        logmsg ('alert', "Cannot run $ROUTE -n show: $!");
        return undef;
    }
    while (<ROUTE>) {
        if (/^default\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+UG/) {
	    push (@ips, $1);
        }
    }
    close (ROUTE);

    return undef unless (@ips);

    # If multiple defaults exist, prefer the highest-priority (lowest-index)
    # gateway from our config. This handles multipath routing setups where
    # multiple default routes may exist temporarily.
    foreach my $cfg_idx (0 .. $#GATEWAYS) {
        foreach my $ip (@ips) {
            return $ip if ($ip eq $GATEWAYS[$cfg_idx]);
        }
    }
    
    # No configured gateway matches any current default - return first one found
    return $ips[0];
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

# Establish permanent routes before the first ping, since without them a
# gateway's test pings follow the default route out the wrong interface and
# report a false "up".  hostname.if(5) normally sets these, but may not have
# (e.g., network not ready at boot).
sub initialize_routes {
    my ($idx);

    print "Entering sub initialize_routes.\n" if ($DEBUG);
    for ($idx = 0; $idx <= $#GATEWAYS; $idx++) {
	my $gw;
        next if (!defined ($ROUTES[$idx]));
        # ROUTES imply a dhcplease type with an interface; prefer the lease's
        # gateway, fall back to the configured one.
        (undef, undef, $gw, undef, undef) = get_dhcplease_info ($INTERFACES[$idx]);
        $gw = $GATEWAYS[$idx] if (!defined ($gw));
        add_missing_routes ($ROUTES[$idx], $gw, $PERM_ONLY);
    }
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

# Subroutine to add routes if missing. IPv4 only.
# Default is just the perm routes but $all_routes
# adds all routes.
sub add_missing_routes {
    my ($routes, $gateway_ip, $all_routes) = @_;
    my (@route_array, $route);

    return if (!defined ($gateway_ip));
    @route_array = split (/,/, $routes);
    foreach $route (@route_array) {
        next if (!$all_routes && $route !~ /P$/);
        $route =~ s/P$//;
        next if (route_present ($route, $gateway_ip));
        if (helper_cmd ("add missing route $route via $gateway_ip", 1,
                        cmd => 'ROUTE_ADD', cidr => $route, gateway => $gateway_ip)) {
            my $message = "Added missing route $route for $gateway_ip.";
            logmsg ('alert', $message);
            print "$message\n" if ($DEBUG);
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
# Format an entry's identity for alerts: "TypeName idx name (IP)" when a name
# is configured, else "TypeName idx (IP)". Emitting the stable name lets
# downstream alert processing (e.g. reportnew) key on it rather than on a
# changeable IP.
sub gate_label {
    my ($idx) = @_;
    my $id = "$GATE_TYPE_NAME[$GATE_TYPE[$idx]] $idx";
    $id .= " $NAMES[$idx]" if (defined ($NAMES[$idx]));
    return "$id ($GATEWAYS[$idx])";
}

# Short identity for failover messages that name two gateways at once:
# "name (IP)" or "(IP)".
sub gname {
    my ($idx) = @_;
    return defined ($NAMES[$idx]) ? "$NAMES[$idx] ($GATEWAYS[$idx])"
	                          : "($GATEWAYS[$idx])";
}

# Is this entry one of the IPv6 monitoring-only kinds? Such entries are pinged
# for liveness but never participate in the IPv4 failover state machine.
sub is_ipv6_entry {
    my ($idx) = @_;
    return ($GATE_TYPE[$idx] == $IPV6_TUNNEL || $GATE_TYPE[$idx] == $IPV6_PD);
}

# Is this entry a candidate to be the active (failover) default gateway? Only
# real IPv4 gateways are -- not host checks and not IPv6 monitoring entries.
sub is_failover_candidate {
    my ($idx) = @_;
    return ($GATE_TYPE[$idx] != $HOST_CHECK && !is_ipv6_entry ($idx));
}

# Alert-enrichment suffix naming this entry's declared dependencies, e.g.
# " (depends on: cox)". Empty when no depends_on is configured. This affects
# only the text of an alert; it never gates a probe or a state decision.
sub depends_suffix {
    my ($idx) = @_;
    return '' unless (defined ($DEPENDS_ON[$idx]) && @{$DEPENDS_ON[$idx]});
    return ' (depends on: ' . join (', ', @{$DEPENDS_ON[$idx]}) . ')';
}

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
    # If sendmail exits before reading the message, writing to the pipe
    # raises SIGPIPE, whose default action would kill the monitor.
    local $SIG{PIPE} = 'IGNORE';
    if (!open (MAIL, '|-', $SENDMAIL, '-t')) {
        logmsg ('alert', "Cannot run sendmail: $!");
        return;
    }
    print MAIL "From: $PAGE_SOURCE\n";
    print MAIL "To: $PAGE_DESTINATION\n";
    print MAIL "Subject: $SHORT_HOSTNAME faild\n\n";
    print MAIL "$msg\n";
    # close on a pipe waits for sendmail and fails if it exited non-zero or
    # the writes failed; without this check a lost page leaves no trace.
    if (!close (MAIL)) {
	my $why = $! ? "$!"
		: ($? & 127) ? "killed by signal " . ($? & 127)
		: "exit " . ($? >> 8);
	logmsg ('alert', "sendmail failed ($why); page not sent: $msg");
    }
}

# Ping all configured IPs for a gateway in sequence. Return success if any
# of them respond. This allows tolerating individual ping target outages
# (e.g., a public DNS resolver having issues).
sub ping_gateway_ips {
    my ($idx, $timeout) = @_;
    return 0 unless defined $PING_IPS[$idx];
    my @failed;
    foreach my $ip (@{$PING_IPS[$idx]}) {
	if (ping_host ($ip, $timeout)) {
	    if (@failed) {
		my $msg = "Ping IPs failed for gateway $idx: " . join(',', @failed) . " (but $ip succeeded)\n";
		print $msg if ($DEBUG);
		logmsg ('alert', $msg);
	    }
        return 1;
	}
	push @failed, $ip;
    }
    return 0;
}

# Return the ping_ip destinations of every host entry configured to receive
# distinctive pings. Used to populate a dynamic_dping_table and, at parse time,
# to guarantee those destinations never overlap a gateway's health probe.
sub distinctive_ping_host_ips {
    my @ips;
    for (my $idx = 0; $idx <= $#GATEWAYS; $idx++) {
	next unless ($GATE_TYPE[$idx] == $HOST_CHECK);
	next unless ($DISTINCTIVE_PINGS[$idx]);
	next unless (defined ($PING_IPS[$idx]));
	push @ips, @{$PING_IPS[$idx]};
    }
    return @ips;
}

# Send distinctive pings to any host-type entries configured for them. These
# carry a distinctive TTL and/or TOS so the remote host can log them separately
# from ordinary ICMP echo requests. They are purely for remote-side logging and
# deliberately do not affect up/down state, so the ping result is ignored.
sub send_distinctive_pings {
    my ($idx, $ip);

    print "Entering sub send_distinctive_pings.\n" if ($DEBUG);
    for ($idx = 0; $idx <= $#GATEWAYS; $idx++) {
	next unless ($GATE_TYPE[$idx] == $HOST_CHECK);
	next unless ($DISTINCTIVE_PINGS[$idx]);
	next unless (defined ($PING_IPS[$idx]));
	foreach $ip (@{$PING_IPS[$idx]}) {
	    ping_host ($ip, $PING_TIMEOUT, $distinctive_ping_len,
		       $distinctive_ping_ttl, $distinctive_ping_tos);
	    if ($DEBUG) {
		my $len = defined ($distinctive_ping_len) ? $distinctive_ping_len : 'default';
		my $ttl = defined ($distinctive_ping_ttl) ? $distinctive_ping_ttl : 'default';
		my $tos = defined ($distinctive_ping_tos) ? $distinctive_ping_tos : 'default';
		print "Sent distinctive ping (len=$len, ttl=$ttl, tos=$tos) to $ip.\n";
	    }
	}
    }
}

# Reconcile every faild-managed pf table to the current gateway state. Called
# each cycle after report_and_failover. The pf 'replace' primitive is idempotent
# (pfctl computes the add/delete diff itself), so this both applies changes and
# self-heals drift or a stale table left by a restart -- the same reconcile-to-
# desired-state approach used for cold start elsewhere.
#
# A gateway_table tracks an address fact (the current next-hop) and is not gated
# on up/down. A dynamic_dping_table is gated on the gateway's state: populated
# with the distinctive-ping host IPs while up, flushed while down (so the pf
# route-to rule keyed on it stops matching and those pings fall to the default
# path -- the positive Cox-down signal the remote monitor reads).
sub sync_managed_tables {
    return unless (%MANAGED_TABLES);
    print "Entering sub sync_managed_tables.\n" if ($DEBUG);

    my (@dping_ips, $have_dping_ips);
    $have_dping_ips = 0;

    for (my $idx = 0; $idx <= $#GATEWAYS; $idx++) {
	if (defined ($GATEWAY_TABLE[$idx])) {
	    # Prefer the dhcplease-learned next-hop; fall back to the configured
	    # gateway IP for a static gateway.
	    my @want = defined ($last_gateway_ip[$idx]) ? ($last_gateway_ip[$idx])
		     : is_ipaddr ($GATEWAYS[$idx])       ? ($GATEWAYS[$idx])
		     :                                     ();
	    replace_managed_table ($GATEWAY_TABLE[$idx], @want);
	}
	if (defined ($DYNAMIC_DPING_TABLE[$idx])) {
	    if (!$have_dping_ips) {
		@dping_ips = distinctive_ping_host_ips();
		$have_dping_ips = 1;
	    }
	    my @want = ($current_state[$idx] == $UP) ? @dping_ips : ();
	    replace_managed_table ($DYNAMIC_DPING_TABLE[$idx], @want);
	}
    }
}

# Verify every faild-managed pf table already exists in the active ruleset.
# Called once at startup while still single-process and root (before daemonize
# and privsep), so it runs pfctl directly -- no helper needed. faild populates
# these tables but never creates them: they must be declared persistent in
# pf.conf (e.g. "table <cox_gw> persist"). Checking here turns a
# faild.conf/pf.conf mismatch into a clear terminal error at startup instead of
# a per-cycle table-op failure once the daemon is detached.
sub verify_managed_tables_exist {
    return unless (%MANAGED_TABLES);
    my $resp = list_pf_tables ();
    if (!$resp || ($resp->{status} // '') ne 'ok') {
	my $why = $resp ? ($resp->{reason} // 'unknown error') : 'no response';
	die "Cannot verify pf tables exist: $why\n";
    }
    my %present = map { $_ => 1 } @{$resp->{tables} || []};
    my @missing = grep { !$present{$_} } sort keys %MANAGED_TABLES;
    if (@missing) {
	die "pf table(s) not found in the active ruleset: " . join (', ', @missing) . ".\n" .
	    "Declare each as a persistent table in pf.conf, e.g.: table <NAME> persist\n";
    }
}

# Push an exact membership to a managed pf table (flushes if the set is empty).
sub replace_managed_table {
    my ($table, @ips) = @_;
    helper_cmd ("replace pf table $table", 1,
		cmd => 'PFCTL_TABLE_REPLACE', table => $table, ips => [@ips]);
}

# Detect and alert on delegated-prefix changes for every ipv6-pd entry. This is
# pure detect-and-alert: it never touches pf or routes. Discipline:
#   - Only a Bound lease with a valid IA_PD is a usable reading. Anything else
#     (dhcp6leasectl failing, a non-Bound state, no IA_PD, an unparseable
#     prefix) holds the last known prefix. A short spell of that is normal
#     during a renewal; one lasting $PD_UNBOUND_ALERT_MINUTES is alerted once,
#     and the return of a usable reading is alerted once.
#   - Prefixes are compared canonicalized (bytes + length), not as printed text.
#   - The last known prefix is persisted in $FAILD_PREFIX_INFO, so a change
#     made while faild was not running (a reboot after a power failure forces
#     a fresh solicit) is detected on the first usable reading. Only the very
#     first observation, with nothing recorded, is not treated as a change.
sub check_ipv6_prefixes {
    for (my $idx = 0; $idx <= $#GATEWAYS; $idx++) {
	next unless ($GATE_TYPE[$idx] == $IPV6_PD);

	my $info = get_dhcp6_prefix ($INTERFACES[$idx]);
	my ($canon, $problem);
	if (($info->{status} // '') ne 'ok') {
	    $problem = 'query failed: ' . ($info->{reason} // 'unknown');
	}
	elsif (($info->{state} // '') ne 'Bound') {
	    $problem = 'lease state is ' . ($info->{state} // 'unknown');
	}
	elsif (!@{$info->{pds} || []}) {
	    $problem = 'Bound but no IA_PD delegation';
	}
	else {
	    my @pds = @{$info->{pds}};
	    # faild tracks a single prefix per entry: the lowest-indexed
	    # delegation. More than one is unexpected here; note it once.
	    my ($primary) = sort { $a->{index} <=> $b->{index} } @pds;
	    if (@pds > 1 && !$PD_MULTI_NOTED[$idx]) {
		logmsg ('alert', gate_label ($idx) . ' has ' . scalar (@pds) .
			" IA_PD delegations; tracking index $primary->{index}." .
			depends_suffix ($idx));
		$PD_MULTI_NOTED[$idx] = 1;
	    }
	    $canon = canonical_ip6_prefix ($primary->{prefix}, $primary->{prefixlen});
	    $problem = "unparseable delegated prefix $primary->{prefix}/$primary->{prefixlen}"
		unless (defined ($canon));
	}

	if (defined ($problem)) {
	    pd_problem ($idx, $problem);
	    next;
	}
	pd_recovered ($idx);

	my $first_this_run = !$PD_SEEN_THIS_RUN[$idx];
	$PD_SEEN_THIS_RUN[$idx] = 1;

	if (!defined ($LAST_PREFIX[$idx])) {
	    # First observation ever: record it, do not alert as a change.
	    $LAST_PREFIX[$idx] = $canon;
	    write_prefix_info ();
	    logmsg ('info', gate_label ($idx) .
		    " initial delegated prefix $canon (no prefix previously recorded).");
	    print "PD $idx initial prefix $canon.\n" if ($DEBUG);
	}
	elsif ($LAST_PREFIX[$idx] ne $canon) {
	    my $old = $LAST_PREFIX[$idx];
	    $LAST_PREFIX[$idx] = $canon;
	    write_prefix_info ();
	    my $msg = gate_label ($idx) .
		" IPv6 delegated prefix changed from $old to $canon" .
		($first_this_run ? ' (found at startup: changed while faild was not running)' : '') .
		'.' . depends_suffix ($idx);
	    logmsg ('alert', $msg);
	    send_page ("faild.pl: $msg");
	}
	elsif ($first_this_run) {
	    logmsg ('info', gate_label ($idx) . " delegated prefix $canon unchanged since last run.");
	}
    }
}

# An ipv6-pd entry has no usable reading this cycle. Start the clock on the
# first one; alert once if it lasts $PD_UNBOUND_ALERT_MINUTES.
sub pd_problem {
    my ($idx, $problem) = @_;
    print "PD $idx ($INTERFACES[$idx]): $problem; holding last known.\n" if ($DEBUG);
    if (!defined ($PD_PROBLEM_SINCE[$idx])) {
	$PD_PROBLEM_SINCE[$idx] = time ();
	return;
    }
    return if ($PD_PROBLEM_ALERTED[$idx]);
    my $minutes = int ((time () - $PD_PROBLEM_SINCE[$idx]) / 60);
    return if ($minutes < $PD_UNBOUND_ALERT_MINUTES);
    my $held = defined ($LAST_PREFIX[$idx]) ? "holding last known prefix $LAST_PREFIX[$idx]"
	                                    : 'no prefix known';
    my $msg = gate_label ($idx) .
	" has had no usable IPv6 delegation for $minutes minutes ($problem; $held)." .
	depends_suffix ($idx);
    logmsg ('alert', $msg);
    send_page ("faild.pl: $msg");
    $PD_PROBLEM_ALERTED[$idx] = 1;
}

# An ipv6-pd entry has a usable reading. If a problem had been alerted,
# announce the recovery; either way, reset the clock.
sub pd_recovered {
    my ($idx) = @_;
    return unless (defined ($PD_PROBLEM_SINCE[$idx]));
    if ($PD_PROBLEM_ALERTED[$idx]) {
	my $minutes = int ((time () - $PD_PROBLEM_SINCE[$idx]) / 60);
	my $msg = gate_label ($idx) .
	    " has a usable IPv6 delegation again (after $minutes minutes)." .
	    depends_suffix ($idx);
	logmsg ('alert', $msg);
	send_page ("faild.pl: $msg");
    }
    $PD_PROBLEM_SINCE[$idx] = undef;
    $PD_PROBLEM_ALERTED[$idx] = 0;
}

# Restore last-seen delegated prefixes from $FAILD_PREFIX_INFO: one
# "<interface> <prefix>" line per ipv6-pd entry. Each value is validated and
# re-canonicalized rather than trusted; lines for interfaces that are not
# configured as ipv6-pd now are ignored. A missing file means nothing recorded.
sub read_prefix_info {
    return unless (grep { $GATE_TYPE[$_] == $IPV6_PD } (0 .. $#GATEWAYS));
    my $fh;
    return unless (open ($fh, '<', $FAILD_PREFIX_INFO));
    while (my $line = <$fh>) {
	my ($if, $prefix, @rest) = split (' ', $line);
	next if (@rest || !defined ($prefix));
	next unless (is_interface ($if) && is_ip6prefix ($prefix));
	my ($addr, $len) = split (m{/}, $prefix, 2);
	my $canon = canonical_ip6_prefix ($addr, $len);
	next unless (defined ($canon));
	for (my $idx = 0; $idx <= $#GATEWAYS; $idx++) {
	    $LAST_PREFIX[$idx] = $canon
		if ($GATE_TYPE[$idx] == $IPV6_PD && $INTERFACES[$idx] eq $if);
	}
    }
    close ($fh);
}

# Persist the last-seen delegated prefix of every ipv6-pd entry. Written by
# the monitor, which owns the file (prepare_state_files_for_user).
sub write_prefix_info {
    my $fh;
    if (!sysopen ($fh, $FAILD_PREFIX_INFO, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0644)) {
	logmsg ('alert', "Cannot open $FAILD_PREFIX_INFO for writing: $!");
	return;
    }
    for (my $idx = 0; $idx <= $#GATEWAYS; $idx++) {
	next unless ($GATE_TYPE[$idx] == $IPV6_PD && defined ($LAST_PREFIX[$idx]));
	print $fh "$INTERFACES[$idx] $LAST_PREFIX[$idx]\n";
    }
    if (!close ($fh)) {
	logmsg ('alert', "Error closing $FAILD_PREFIX_INFO: $!");
    }
}

# Ping gateways or hosts.
# Send a single ICMP ping using /sbin/ping. Returns 1 on success, 0 on failure.
# This replaces Net::Ping which requires raw sockets (root privileges).
sub ping_host {
    my ($ip, $timeout, $len, $ttl, $tos) = @_;
    $timeout //= 1;

    # An IPv6 target (contains a colon) is pinged with ping6. Distinctive-ping
    # options (len/ttl/tos) are IPv4-only and are ignored for IPv6 liveness.
    my $v6 = ($ip =~ /:/) ? 1 : 0;

    if ($v6) {
	return 0 unless (is_ip6addr ($ip));
    }
    else {
	return 0 unless (!defined ($len) || ($len =~ /^\d+$/ &&
					     $len >= 16 && $len <= 255));

	return 0 unless (!defined ($ttl) || ($ttl =~ /^\d+$/ &&
					     $ttl > 1 &&
					     $ttl <= 255));

	return 0 unless (!defined ($tos) || valid_ping_tos ($tos));

	# Validate IP before passing to system command (defense in depth)
	return 0 unless ($ip =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/);
    }

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
	my ($cmd, @ping_opts);
	if ($v6) {
	    $cmd = $PING6;
	    @ping_opts = build_ping6_opts ($timeout);
	}
	else {
	    $cmd = $PING;
	    @ping_opts = build_ping_opts ($timeout, $len, $ttl, $tos);
	}
        exec ($cmd, @ping_opts, $ip);
        exit (1);  # only reached if exec fails
    }
    # Parent: wait for ping to complete, but never longer than the timeout
    # plus a margin. Every ping is issued with its own wait/deadline flag
    # where the platform has one, but a ping that ignores it (macOS ping6
    # has no deadline flag) or hangs must not stall the monitoring loop.
    my $timed_out = 0;
    eval {
	local $SIG{ALRM} = sub { die "ping watchdog\n"; };
	alarm ($timeout + 2);
	waitpid ($pid, 0);
	alarm (0);
	1;
    } or do {
	alarm (0);
	$timed_out = 1;
    };
    if ($timed_out) {
	kill ('KILL', $pid);
	waitpid ($pid, 0);
	print "Ping of $ip killed by watchdog after " . ($timeout + 2) . "s.\n" if ($DEBUG);
	return 0;
    }
    return ($? == 0) ? 1 : 0;
}
