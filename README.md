# faild.pl
Script to monitor Internet connections and remote hosts for uptime and generate alerts when they go down. Also can make routing changes to facilitate failover.

Also found at https://www.discord.org/lippard/software/

faild.pl 1.27 of 28 July 2026

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
 gateway: &lt;ip&gt;
 interface: &lt;interface&gt; # optional, used by dhcplease-primary/backup
 routes: &lt;cidr&gt;,&ltcidr&gt,... # optional, only for dhcplease-primary/backup
 ping_ip: &lt;ip-list&gt; (1-3 comma-separated IPs)
 type: &lt;dedicated|dedicated-dhcplease-primary|dedicated-dhcplease-backup|on-demand|host&gt;
 #distinctive_pings: [yes|no] (valid only for host type)
  </PRE>
