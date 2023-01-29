## Packet Filter Firewall (iptables)

In this lab, I used the [netplan](https://netplan.io) tool to configure network settings in virtual machines and I used the [iptables](https://help.ubuntu.com/community/IptablesHowTo) tool on Linux systems (Ubuntu) to implement a packet filter firewall.

Our goal in this lab was to set up iptables to block all traffic and only allow specific traffic to pass between clientVM and gateway/serverVM (Webserver), based on the protocol, the source, and the destination IP addresses.
