# faild.pl
Script to monitor Internet connections and remote hosts for uptime and generate alerts when they go down.
Also can make routing changes and pf table changes to facilitate failover.

Also found at https://www.discord.org/lippard/software/

faild.pl 1.34 of 11 October 2026

1.31 adds faild OpenBSD rc.d script and -n config test.
1.20 does privilege separation.
1.19 replaces Net::Ping with system call to ping as preparation
for privilege separation; properly daemonizes.

Config file format (/etc/faild.conf):
<PRE>
 # Comment format
 #state_dir: /var/db
 #pid_dir: /var/run
 #perform_failover: [yes|no] no = monitor mode, no privs*; yes = priv mode
 #  * exception: dhcplease interfaces require priv mode
 page_source: email-addr (where alerts are sent from)
 page_destination: email-addr (where alerts are sent to)
 # can periodically send distinctive pings for various purposes
 #distinctive_ping_len: [16-255]
 #distinctive_ping_ttl: [2-255]
 #distinctive_ping_tos: [tos value]
 #distinctive_ping_frequency: [2+] (minutes)
 # Then as many of these triplets as you want:
 gateway: &lt;ip&gt; [for type ipv6-pd this must be a valid IPv6 IP but is just an identifier]
 #name: &lt;descriptive name&gt; # optional
# gateway_table: &ltpf-table-name&gt; # optional (will add current next-hop gateway IP to pf table and keep it updated over IP address changes) - not valid on type: host
 interface: &lt;interface&gt; # optional, used by dhcplease-primary/backup [required for ipv6-pd]
 routes: &lt;cidr&gt;,&ltcidr&gt,... # optional, only for dhcplease-primary/backup
 ping_ip: &lt;ip-list&gt; (1-3 comma-separated IPs) [IPv6 for types ipv6-tunnel and ipv6-pd]
 type: &lt;dedicated|dedicated-dhcplease-primary|dedicated-dhcplease-backup|host|ipv6-tunnel|ipv6-pd&gt;
 #dynamic_dping_table: &lt;pf-table-name&gt; # optional, only for dhcplease-backup, populated with IPs of hosts receiving distinctive pings and flushed if the backup interface goes down - use to force distinctive pings out backup interface in pf rules unless it's down
 #distinctive_pings: [yes|no] (valid only for host type)
 #depends_on: &ltinterface-name&gt; # optional, used for reporting purposes for ipv6-tunnel or ipv6-pd
 </PRE>
