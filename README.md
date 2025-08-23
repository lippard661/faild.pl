# faild.pl
Script to monitor Internet connections and remote hosts for uptime and generate alerts when they go down.

Also found at https://www.discord.org/lippard/software/

faild.pl 1.12 of 23 August 2025

Config file format (/etc/faild.conf):
<PRE>
 # Comment format
 page_source: email-addr (where alerts are sent from)
 page_destination: email-addr (where alerts are sent to)
 # Then as many of these triplets as you want:
 gateway: &lt;ip&gt;
 interface: &lt;interface&gt; # optional, used by dhcplease-primary/backup
 routes: &lt;cidr&gt;,&ltcidr&gt,... # optional, only for dhcplease-primary/backup
 ping_ip: &lt;ip&gt;
 type: &lt;dedicated|dedicated-dhcplease-primary|dedicated-dhcplease-backup|on-demand|host&gt;
  </PRE>
