# faild.pl
Script to monitor Internet connections and remote hosts for uptime and generate alerts when they go down.

Also found at https://www.discord.org/lippard/software/

faild.pl 1.7 of 19 December 2022

Config file format (/etc/faild.conf):
<PRE>
 # Comment format
 page_source: email-addr (where alerts are sent from)
 page_destination: email-addr (where alerts are sent to)
 # Then as many of these triplets as you want:
 gateway: <ip>
 ping_ip: <ip>
 type: <dedicated|on-demand|host>
  </PRE>
